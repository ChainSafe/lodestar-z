const std = @import("std");
const config = @import("config");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../negotiate.zig");
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

pub const Options = struct {
    reqresp: reqresp.Options,
    negotiations_max: ?u16 = null,
};

pub const InitError = negotiate.Error || reqresp.InitError;

pub const Active = struct { outbound: u16, inbound: u16 };

pub const Service = struct {
    allocator: std.mem.Allocator,
    router: ?routing.Router,
    inner: ReqResp,
    sink_arena: []u8,
    sink_size: usize,

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Service {
        var service = try initHandler(allocator, options.reqresp);
        errdefer service.deinit();
        const default_neg = @as(u32, options.reqresp.outbound_max) + options.reqresp.inbound_max;
        service.router = try routing.Router.init(allocator, .{
            .negotiations_max = options.negotiations_max orelse
                @intCast(@min(default_neg, std.math.maxInt(u16))),
            .meshsub = false,
        });
        return service;
    }

    pub fn initHandler(allocator: std.mem.Allocator, options: reqresp.Options) InitError!Service {
        const inbound_max = options.inbound_max;
        var inner = try ReqResp.init(allocator, options);
        errdefer inner.deinit();

        const sink_size = protocol.requestMaxAll();
        const sink_bytes = std.math.mul(usize, inbound_max, sink_size) catch
            return error.InvalidOptions;
        const sink_arena = try allocator.alloc(u8, sink_bytes);
        errdefer allocator.free(sink_arena);

        return .{
            .allocator = allocator,
            .router = null,
            .inner = inner,
            .sink_arena = sink_arena,
            .sink_size = sink_size,
        };
    }

    pub fn deinit(self: *Service) void {
        self.allocator.free(self.sink_arena);
        self.inner.deinit();
        if (self.router) |*router| router.deinit();
        self.* = undefined;
    }

    pub fn request(
        self: *Service,
        engine: *Engine,
        conn: Handle,
        which: Protocol,
        request_ssz: []const u8,
        sink: []u8,
        options: reqresp.RequestOptions,
        now: Now,
    ) reqresp.RequestError!RequestHandle {
        return self.requestRouted(
            &self.router.?,
            engine,
            conn,
            which,
            request_ssz,
            sink,
            options,
            now,
        );
    }

    pub fn requestRouted(
        self: *Service,
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
        self: *Service,
        handle: RequestHandle,
        ssz: []const u8,
        fork: ?config.ForkSeq,
        now: Now,
    ) reqresp.RespondError!void {
        return self.inner.respond(handle, ssz, fork, now);
    }

    pub fn respondError(
        self: *Service,
        handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) reqresp.RespondError!void {
        return self.inner.respondError(handle, code, message, now);
    }

    pub fn finish(self: *Service, handle: RequestHandle, now: Now) bool {
        return self.inner.finish(handle, now);
    }

    pub fn consume(self: *Service, handle: RequestHandle, now: Now) bool {
        return self.inner.consume(handle, now);
    }

    pub fn errorMessage(self: *const Service, handle: RequestHandle) []const u8 {
        return self.inner.errorMessage(handle);
    }

    pub fn nextWakeup(self: *Service, now: Now, event_capacity: usize) ?u64 {
        return self.nextWakeupRouted(&self.router.?, now, event_capacity);
    }

    pub fn nextWakeupRouted(
        self: *Service,
        router: *const routing.Router,
        now: Now,
        event_capacity: usize,
    ) ?u64 {
        const request_due = self.inner.nextWakeup(now, event_capacity);
        const negotiation_due = router.nextWakeup(now, outcomes_per_pump);
        if (request_due) |due| return if (negotiation_due) |other| @min(due, other) else due;
        return negotiation_due;
    }

    /// Includes the fixed sink slab; canonical Router storage is separate.
    pub fn memoryPlan(self: *const Service) reqresp.MemoryPlan {
        var plan = self.inner.memoryPlan();
        plan.facade_bytes = @sizeOf(Service);
        plan.request_sink_bytes = self.sink_arena.len;
        plan.total_bytes = plan.facade_bytes + plan.slot_bytes + plan.io_bytes +
            plan.limiter_bytes + plan.request_sink_bytes;
        return plan;
    }

    pub fn active(self: *const Service) Active {
        const counts = self.inner.active();
        return .{ .outbound = counts.outbound, .inbound = counts.inbound };
    }

    pub fn counters(self: *const Service) reqresp.Counters {
        return self.inner.counters;
    }

    pub fn acceptNegotiated(
        self: *Service,
        engine: *Engine,
        stream: StreamHandle,
        selection: routing.Selection,
        now: Now,
    ) ?RequestHandle {
        const index = self.inner.availableInbound() orelse return null;
        const sink = self.sink_arena[@as(usize, index) * self.sink_size ..][0..self.sink_size];
        return self.inner.accept(engine, stream, selection, sink, now) catch null;
    }

    pub fn process(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        now: Now,
        out: []reqresp.Event,
    ) usize {
        const router = &self.router.?;
        self.inner.cleanupPending(engine, router);
        router.transportEvents(engine, events, now);
        self.transportEvents(events);
        var outcomes: [outcomes_per_pump]routing.Outcome = undefined;
        const count = router.pump(engine, now, &outcomes);
        for (outcomes[0..count]) |outcome| self.negotiationResult(engine, outcome, now);
        return self.pump(engine, now, out);
    }

    pub fn transportEvents(self: *Service, events: []const TransportEvent) void {
        for (events) |event| switch (event) {
            .closed => |closed| self.inner.connectionClosed(closed.conn),
            else => {},
        };
    }

    pub fn negotiationResult(
        self: *Service,
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

    pub fn pump(self: *Service, engine: *Engine, now: Now, out: []reqresp.Event) usize {
        return self.pumpRouted(&self.router.?, engine, now, out);
    }

    pub fn pumpRouted(
        self: *Service,
        router: *routing.Router,
        engine: *Engine,
        now: Now,
        out: []reqresp.Event,
    ) usize {
        return self.inner.pump(engine, router, now, out);
    }

    pub fn cancel(self: *Service, handle: RequestHandle) bool {
        return self.inner.cancel(handle);
    }

    pub fn shutdown(self: *Service, engine: *Engine) void {
        self.shutdownRouted(&self.router.?, engine);
    }

    pub fn shutdownRouted(self: *Service, router: *routing.Router, engine: *Engine) void {
        self.inner.shutdown(engine, router);
    }
};
