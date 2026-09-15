const std = @import("std");
const reqresp = @import("reqresp.zig");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const RequestIO = @import("request_io.zig").RequestIO;
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const Event = reqresp.Event;
const Failure = reqresp.Failure;
const Engine = engine_mod.Engine;

pub const FailurePhase = union(enum) {
    outbound: reqresp.RequestPhase,
    inbound: @import("server.zig").State,
};

/// Terminal delivery ends application borrows; the following pump recycles the slot.
/// A queued response chunk survives termination until the host receives both events.
pub const Lifecycle = struct {
    completion: union(enum) { free, active, terminal: Event, reported } = .free,
    notification: union(enum) { none, pending: Event, borrowed_chunk } = .none,
    stream_owner: enum { router, protocol, closed } = .protocol,
    close_code: ?u64 = null,
    direction: types.Direction = .outbound,
    generation: u32 = 0,
    conn: engine_mod.Handle = undefined,
    stream: engine_mod.StreamHandle = undefined,
    protocol: @import("protocol.zig").Protocol = .status_v1,
    progress_ms: u64 = 0,
    started_ms: u64 = 0,
    needs_service: bool = false,
    timeout_ms: u64 = 0,
    chunks: u32 = 0,
    chunks_max: u32 = 1,
    io: RequestIO = .{},
    error_message: [codec.error_message_max]u8 = undefined,
    error_len: u16 = 0,

    pub fn occupied(self: *const Lifecycle) bool {
        return self.completion != .free;
    }

    pub fn active(self: *const Lifecycle) bool {
        return self.completion == .active or self.completion == .terminal;
    }

    pub fn running(self: *const Lifecycle) bool {
        return self.completion == .active;
    }

    pub fn available(self: *const Lifecycle) bool {
        return !self.occupied() and self.generation < std.math.maxInt(u32);
    }

    pub fn handle(self: *const Lifecycle, index: u16) reqresp.RequestHandle {
        return .{ .index = index, .generation = self.generation, .direction = self.direction };
    }

    pub fn pendingEvent(self: *const Lifecycle) ?Event {
        return if (self.notification == .pending) self.notification.pending else null;
    }

    pub fn terminalEvent(self: *const Lifecycle) ?Event {
        return if (self.completion == .terminal) self.completion.terminal else null;
    }

    pub fn waitingHost(self: *const Lifecycle) bool {
        return self.notification != .none;
    }

    pub fn queue(self: *Lifecycle, event: Event) void {
        assert(self.running() and self.notification == .none);
        assert(event == .chunk or event == .request or event == .chunk_sent);
        self.notification = .{ .pending = event };
    }

    pub fn deliver(self: *Lifecycle, control: bool) ?Event {
        if (self.protocol.isControl() != control) return null;
        if (self.pendingEvent()) |event| {
            self.notification = if (event == .chunk) .borrowed_chunk else .none;
            return event;
        }
        if (self.terminalEvent()) |event| {
            self.completion = .reported;
            self.notification = .none;
            return event;
        }
        return null;
    }

    pub fn consume(self: *Lifecycle) bool {
        if (self.notification != .borrowed_chunk) return false;
        self.notification = .none;
        return true;
    }

    pub fn cleanup(self: *Lifecycle, engine: *Engine, router: *routing.Router, recycle: bool) void {
        if (self.close_code) |code| {
            switch (self.stream_owner) {
                .router => router.cancel(engine, self.stream),
                .protocol => engine.closeStream(self.stream, code),
                .closed => unreachable,
            }
            self.stream_owner = .closed;
            self.close_code = null;
        }
        if (recycle and self.completion == .reported) {
            assert(self.stream_owner == .closed and self.notification == .none);
            self.completion = .free;
            self.io.sink = &.{};
        }
    }

    pub fn wakeup(self: *const Lifecycle, capacity: usize) bool {
        return self.needs_service or self.close_code != null or self.completion == .reported or
            (capacity > 0 and (self.notification == .pending or self.completion == .terminal));
    }

    pub fn complete(self: *Lifecycle, owner: *reqresp.ReqResp, index: u16, event: Event, engine: ?*Engine) void {
        if (!self.running()) return;
        assert(event == .done or event == .served or event == .failed);
        const counts = &owner.protocol_counters[@intFromEnum(self.protocol)];
        const duration_ms = owner.last_now_ms -| self.started_ms;
        if (event != .failed) std.log.scoped(.network_reqresp).debug("request_completed direction={s} request={d}:{d} connection={d}:{d} method={s} chunks={d} elapsed_ms={d}", .{ @tagName(self.direction), index, self.generation, self.conn.index, self.conn.generation, @tagName(self.protocol), self.chunks, duration_ms });
        if (self.direction == .outbound) counts.outgoing_time.observe(duration_ms) else counts.incoming_time.observe(duration_ms);
        self.completion = .{ .terminal = event };
        self.io.clear();
        self.needs_service = false;
        if (self.pendingEvent()) |pending| if (pending == .request) {
            self.notification = .none;
        };
        self.close_code = if (event == .failed) switch (event.failed.reason) {
            .timeout => constants.app_error_timeout,
            .invalid_response, .too_many_chunks, .unknown_context => constants.app_error_invalid_response,
            else => types.app_error_normal,
        } else types.app_error_normal;
        if (engine) |live| if (self.stream_owner == .protocol) {
            live.closeStream(self.stream, self.close_code.?);
            self.stream_owner = .closed;
            self.close_code = null;
        };
    }

    pub fn fail(self: *Lifecycle, owner: *reqresp.ReqResp, index: u16, reason: Failure, phase: FailurePhase, engine: ?*Engine) void {
        if (!self.running()) return;
        assert((self.direction == .outbound) == (phase == .outbound));
        const request_phase: ?reqresp.RequestPhase = if (phase == .outbound) phase.outbound else null;
        const phase_name = switch (phase) {
            .outbound => |value| @tagName(value),
            .inbound => |value| @tagName(value),
        };
        const counts = &owner.protocol_counters[@intFromEnum(self.protocol)];
        const duration_ms = owner.last_now_ms -| self.started_ms;
        if (reason == .cancelled) {
            if (self.direction == .outbound) counts.outgoing_cancelled +|= 1 else counts.incoming_cancelled +|= 1;
            std.log.scoped(.network_reqresp).debug("request_cancelled direction={s} request={d}:{d} connection={d}:{d} method={s} chunks={d} elapsed_ms={d}", .{ @tagName(self.direction), index, self.generation, self.conn.index, self.conn.generation, @tagName(self.protocol), self.chunks, duration_ms });
        } else {
            const detail: []const u8 = switch (reason) {
                .invalid_response => |err| @errorName(err),
                .invalid_request => |err| @errorName(err),
                .negotiation_failed => |failure| @tagName(failure),
                else => self.io.failure_detail,
            };
            const peer_code: u16 = if (reason == .peer_error) reason.peer_error.code else 0;
            std.log.scoped(.network_reqresp_errors).debug("request_failed direction={s} request={d}:{d} connection={d}:{d} method={s} phase={s} reason={s} detail={s} peer_code={d} chunks={d} elapsed_ms={d}", .{ @tagName(self.direction), index, self.generation, self.conn.index, self.conn.generation, @tagName(self.protocol), phase_name, @tagName(reason), detail, peer_code, self.chunks, duration_ms });
            owner.counters.failures += 1;
            if (self.direction == .outbound) {
                counts.outgoing_errors +|= 1;
                owner.outgoing_error_reasons[@intFromEnum(reqresp.metrics.ErrorReason.fromFailure(reason, phase.outbound))] +|= 1;
            } else counts.incoming_errors +|= 1;
        }
        self.complete(owner, index, .{ .failed = .{ .request = self.handle(index), .reason = reason, .phase = request_phase } }, engine);
    }

    pub fn failStream(self: *Lifecycle, owner: *reqresp.ReqResp, index: u16, err: engine_mod.StreamError, phase: FailurePhase, engine: *Engine) void {
        self.io.failure_detail = @errorName(err);
        self.fail(owner, index, switch (err) {
            error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
            else => .transport,
        }, phase, engine);
    }
};
