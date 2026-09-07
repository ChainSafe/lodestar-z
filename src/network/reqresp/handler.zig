const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const types = @import("../types.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const TransportEvent = engine_mod.Event;
const Now = types.Now;
const Protocol = protocol.Protocol;
const ReqResp = reqresp.ReqResp;
const RequestHandle = reqresp.RequestHandle;

pub const outcomes_per_pump: usize = 16;

pub const InitError = reqresp.InitError;

pub const Active = struct { outbound: u16, inbound: u16 };

pub const Handler = struct {
    allocator: std.mem.Allocator,
    inner: ReqResp,
    sink_arena: []u8,
    sink_size: usize,

    pub fn init(allocator: std.mem.Allocator, options: reqresp.Options) InitError!Handler {
        const inbound_max = options.inbound_max;
        var inner = try ReqResp.init(allocator, options);
        errdefer inner.deinit();

        const sink_size = protocol.requestMaxAll();
        const bulk_bytes = std.math.mul(usize, inbound_max - options.inbound_control_reserved, sink_size) catch return error.InvalidOptions;
        const control_bytes = std.math.mul(usize, options.inbound_control_reserved, protocol.requestMaxControl()) catch return error.InvalidOptions;
        const sink_bytes = std.math.add(usize, bulk_bytes, control_bytes) catch return error.InvalidOptions;
        const sink_arena = try allocator.alloc(u8, sink_bytes);
        errdefer allocator.free(sink_arena);

        return .{
            .allocator = allocator,
            .inner = inner,
            .sink_arena = sink_arena,
            .sink_size = sink_size,
        };
    }

    pub fn deinit(self: *Handler) void {
        self.allocator.free(self.sink_arena);
        self.inner.deinit();
        self.* = undefined;
    }

    pub fn request(
        self: *Handler,
        router: *routing.Router,
        engine: *Engine,
        conn: Handle,
        which: Protocol,
        request_ssz: []const u8,
        sink: []u8,
        options: reqresp.RequestOptions,
        now: Now,
    ) reqresp.RequestError!RequestHandle {
        return self.inner.request(
            engine,
            router,
            conn,
            which,
            request_ssz,
            sink,
            options,
            now,
        );
    }

    pub fn respond(
        self: *Handler,
        handle: RequestHandle,
        ssz: []const u8,
        context: ?reqresp.ForkEntry,
        now: Now,
    ) reqresp.RespondError!void {
        return self.inner.respond(handle, ssz, context, now);
    }

    pub fn respondError(
        self: *Handler,
        handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) reqresp.RespondError!void {
        return self.inner.respondError(handle, code, message, now);
    }

    pub fn finish(self: *Handler, handle: RequestHandle, now: Now) bool {
        return self.inner.finish(handle, now);
    }

    pub fn consume(self: *Handler, handle: RequestHandle, now: Now) bool {
        return self.inner.consume(handle, now);
    }

    pub fn errorMessage(self: *const Handler, handle: RequestHandle) []const u8 {
        return self.inner.errorMessage(handle);
    }

    pub fn nextWakeup(
        self: *Handler,
        router: *const routing.Router,
        now: Now,
        event_capacity: usize,
    ) ?u64 {
        return self.nextWakeupPartitioned(router, now, event_capacity, event_capacity);
    }

    pub fn nextWakeupPartitioned(
        self: *Handler,
        router: *const routing.Router,
        now: Now,
        application_capacity: usize,
        control_capacity: usize,
    ) ?u64 {
        const request_due = self.inner.nextWakeupPartitioned(
            now,
            application_capacity,
            control_capacity,
        );
        const negotiation_due = router.nextWakeup(now, outcomes_per_pump);
        if (request_due) |due| return if (negotiation_due) |other| @min(due, other) else due;
        return negotiation_due;
    }

    /// Includes the fixed sink slab; canonical Router storage is separate.
    pub fn memoryPlan(self: *const Handler) reqresp.MemoryPlan {
        var plan = self.inner.memoryPlan();
        plan.facade_bytes = @sizeOf(Handler);
        plan.request_sink_bytes = self.sink_arena.len;
        plan.total_bytes = plan.facade_bytes + plan.slot_bytes + plan.io_bytes +
            plan.limiter_bytes + plan.request_sink_bytes;
        return plan;
    }

    pub fn active(self: *const Handler) Active {
        const counts = self.inner.active();
        return .{ .outbound = counts.outbound, .inbound = counts.inbound };
    }

    pub fn counters(self: *const Handler) reqresp.Counters {
        return self.inner.counters;
    }

    pub fn acceptNegotiated(
        self: *Handler,
        engine: *Engine,
        stream: StreamHandle,
        selection: routing.Selection,
        now: Now,
    ) ?RequestHandle {
        const which = switch (selection.protocol) {
            .reqresp => |which| which,
            else => return null,
        };
        const index = self.inner.availableInboundFor(which) orelse return null;
        const sink = self.inboundSink(index);
        return self.inner.accept(engine, stream, selection, sink, now) catch null;
    }

    pub fn inboundSink(self: *Handler, index: u16) []u8 {
        std.debug.assert(index < self.inner.inbound.len);
        const reserved = self.inner.options.inbound_control_reserved;
        const control_size = protocol.requestMaxControl();
        const offset = if (index < reserved) @as(usize, index) * control_size else @as(usize, reserved) * control_size + @as(usize, index - reserved) * self.sink_size;
        const size = if (index < reserved) control_size else self.sink_size;
        return self.sink_arena[offset..][0..size];
    }

    pub fn transportEvents(self: *Handler, events: []const TransportEvent) void {
        for (events) |event| switch (event) {
            .closed => |closed| self.inner.connectionClosed(closed.conn),
            else => {},
        };
    }

    pub fn negotiationResult(
        self: *Handler,
        engine: *Engine,
        outcome: routing.Outcome,
        now: Now,
    ) void {
        if (outcome.direction == .outbound) {
            if (!self.inner.negotiated(outcome, now)) engine.closeStream(outcome.stream, 0);
        } else switch (outcome.result) {
            .ready => |selection| {
                if (self.acceptNegotiated(engine, outcome.stream, selection, now) == null) {
                    engine.closeStream(outcome.stream, 0);
                }
            },
            else => {},
        }
    }

    pub fn pump(
        self: *Handler,
        router: *routing.Router,
        engine: *Engine,
        now: Now,
        out: []reqresp.Event,
    ) usize {
        return self.inner.pump(engine, router, now, out);
    }

    pub fn pumpPartitioned(
        self: *Handler,
        router: *routing.Router,
        engine: *Engine,
        now: Now,
        application: []reqresp.Event,
        control: []reqresp.Event,
    ) reqresp.PartitionedCounts {
        return self.inner.pumpPartitioned(engine, router, now, application, control);
    }

    pub fn cancel(self: *Handler, handle: RequestHandle) bool {
        return self.inner.cancel(handle);
    }

    pub fn shutdown(self: *Handler, router: *routing.Router, engine: *Engine) void {
        self.inner.shutdown(engine, router);
    }
};

test "reqresp typed reserved sinks keep full control waves and exclude bulk" {
    var service = try Handler.init(std.testing.allocator, .{ .forks = &.{}, .inbound_max = 4, .inbound_control_reserved = 2, .inbound_per_peer_max = 4 });
    defer service.deinit();
    try std.testing.expectEqual(2 * protocol.requestMaxAll() + 2 * protocol.requestMaxControl(), service.sink_arena.len);
    try std.testing.expectEqual(@as(?u16, 2), service.inner.availableInboundFor(.blocks_by_range_v2));
    for (0..4) |i| {
        const index = service.inner.availableInboundFor(.ping_v1).?;
        try std.testing.expectEqual(@as(u16, @intCast(i)), index);
        service.inner.inbound[index].state = .receiving_request;
        service.inner.inbound[index].protocol = .ping_v1;
    }
    try std.testing.expectEqual(@as(?u16, null), service.inner.availableInboundFor(.ping_v1));
    service.inner.inbound[0].state = .free;
    try std.testing.expectEqual(@as(?u16, null), service.inner.availableInboundFor(.blocks_by_range_v2));
    try std.testing.expectEqual(@as(?u16, 0), service.inner.availableInboundFor(.ping_v1));
    for (service.inner.inbound) |*slot| slot.state = .free;
}
