const std = @import("std");
const config = @import("config");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../negotiate.zig");
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

/// Composes the multistream negotiator with the req/resp slot machine so a host
/// pumps transport events straight to req/resp events without hand-wiring the two.
/// The negotiator ownership lives here today; when a second protocol needs it, a
/// shared router hoists it up and calls `acceptNegotiated` per handler.
pub const Service = struct {
    allocator: std.mem.Allocator,
    negotiator: negotiate.Negotiator,
    inner: ReqResp,
    sink_arena: []u8,
    sink_size: usize,
    free_sinks: []u16,
    free_len: usize,
    slot_sink: []u16,

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Service {
        const inbound_max = options.reqresp.inbound_max;
        const default_neg = @as(u32, options.reqresp.outbound_max) + inbound_max;
        const negotiations_max = options.negotiations_max orelse
            @as(u16, @intCast(@min(default_neg, std.math.maxInt(u16))));

        var negotiator = try negotiate.Negotiator.init(allocator, negotiations_max);
        errdefer negotiator.deinit();
        var inner = try ReqResp.init(allocator, options.reqresp);
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
            .negotiator = negotiator,
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
        self.negotiator.deinit();
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
        const negotiator = &self.negotiator;
        return self.inner.request(engine, negotiator, conn, which, request_ssz, sink, options, now);
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

    /// Hands one ready inbound negotiation to req/resp with a pooled request sink.
    /// Returns null when the protocol is not ours or no sink is free, so a future
    /// shared router can try the next handler and close the stream if none claim it.
    pub fn acceptNegotiated(
        self: *Service,
        stream: StreamHandle,
        ready: negotiate.Ready,
        now: Now,
    ) ?RequestHandle {
        if (ready.protocol_index >= Protocol.count) return null;
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
        for (events) |event| switch (event) {
            .stream_opened => |stream| self.listen(engine, stream, now),
            .closed => |closed| self.inner.connectionClosed(closed.conn),
            else => {},
        };
        var outcomes: [outcomes_per_pump]negotiate.Outcome = undefined;
        const ready = self.negotiator.pump(engine, now, &outcomes);
        for (outcomes[0..ready]) |outcome| {
            if (self.inner.negotiated(outcome)) continue;
            switch (outcome.result) {
                .ready => |accepted| self.route(engine, outcome.stream, accepted, now),
                else => {},
            }
        }
        const count = self.inner.pump(engine, now, out);
        for (out[0..count]) |event| self.release(event);
        return count;
    }

    fn listen(self: *Service, engine: *Engine, stream: StreamHandle, now: Now) void {
        self.negotiator.acceptInbound(stream, &protocol.ids, now) catch {
            engine.closeStream(stream, 0);
        };
    }

    fn route(
        self: *Service,
        engine: *Engine,
        stream: StreamHandle,
        ready: negotiate.Ready,
        now: Now,
    ) void {
        if (self.acceptNegotiated(stream, ready, now) == null) engine.closeStream(stream, 0);
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
