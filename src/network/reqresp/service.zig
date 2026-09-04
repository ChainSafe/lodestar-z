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
    free_sinks: []u16,
    free_len: usize,
    slot_sink: []u16,

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
        const sink_arena = try allocator.alloc(u8, @as(usize, inbound_max) * sink_size);
        errdefer allocator.free(sink_arena);
        const free_sinks = try allocator.alloc(u16, inbound_max);
        errdefer allocator.free(free_sinks);
        const slot_sink = try allocator.alloc(u16, inbound_max);
        errdefer allocator.free(slot_sink);
        for (free_sinks, 0..) |*slot, index| slot.* = @intCast(index);

        return .{
            .allocator = allocator,
            .router = null,
            .inner = inner,
            .sink_arena = sink_arena,
            .sink_size = sink_size,
            .free_sinks = free_sinks,
            .free_len = inbound_max,
            .slot_sink = slot_sink,
        };
    }

    pub fn deinit(self: *Service) void {
        self.allocator.free(self.slot_sink);
        self.allocator.free(self.free_sinks);
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
            &router.negotiator,
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

    pub fn finish(self: *Service, handle: RequestHandle) bool {
        return self.inner.finish(handle);
    }

    pub fn consume(self: *Service, handle: RequestHandle) bool {
        return self.inner.consume(handle);
    }

    pub fn errorMessage(self: *const Service, handle: RequestHandle) []const u8 {
        return self.inner.errorMessage(handle);
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
        stream: StreamHandle,
        selection: routing.Selection,
        now: Now,
    ) ?RequestHandle {
        const which = switch (selection.protocol) {
            .reqresp => |which| which,
            else => return null,
        };
        const ready: negotiate.Ready = .{
            .protocol_index = @intFromEnum(which),
            .leftover = selection.leftover,
            .fin = selection.fin,
        };
        if (self.free_len == 0) return null;
        const index = self.free_sinks[self.free_len - 1];
        const sink = self.sink_arena[@as(usize, index) * self.sink_size ..][0..self.sink_size];
        const handle = self.inner.accept(stream, ready, sink, now) catch return null;
        self.free_len -= 1;
        assert(handle.direction == .inbound);
        assert(handle.index < self.slot_sink.len);
        self.slot_sink[handle.index] = index;
        return handle;
    }

    pub fn process(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        now: Now,
        out: []reqresp.Event,
    ) usize {
        const router = &self.router.?;
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
            const raw: negotiate.Outcome = .{
                .stream = outcome.stream,
                .result = switch (outcome.result) {
                    .ready => |selection| .{ .ready = .{
                        .protocol_index = @intFromEnum(selection.protocol.reqresp),
                        .leftover = selection.leftover,
                        .fin = selection.fin,
                    } },
                    .rejected => .rejected,
                    .failed => |failure| .{ .failed = failure },
                },
            };
            if (!self.inner.negotiated(raw)) engine.closeStream(outcome.stream, 0);
        } else switch (outcome.result) {
            .ready => |selection| {
                if (self.acceptNegotiated(outcome.stream, selection, now) == null) {
                    engine.closeStream(outcome.stream, 0);
                }
            },
            else => {},
        }
    }

    pub fn pump(self: *Service, engine: *Engine, now: Now, out: []reqresp.Event) usize {
        const count = self.inner.pump(engine, now, out);
        for (out[0..count]) |event| self.release(event);
        return count;
    }

    fn release(self: *Service, event: reqresp.Event) void {
        const handle = switch (event) {
            .served => |served| served.request,
            .failed => |failed| failed.request,
            else => return,
        };
        if (handle.direction != .inbound) return;
        assert(self.free_len < self.free_sinks.len);
        assert(handle.index < self.slot_sink.len);
        self.free_sinks[self.free_len] = self.slot_sink[handle.index];
        self.free_len += 1;
    }
};
