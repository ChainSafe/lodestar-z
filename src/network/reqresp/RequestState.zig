//! Terminal delivery ends application borrows; the following pump recycles the slot.
//! A queued response chunk survives termination until the host receives both events.
const std = @import("std");
const events = @import("events.zig");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const RequestIO = @import("RequestIO.zig");
const Engine = @import("../quic/Engine.zig");
const routing = @import("../router.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const Event = events.Event;

const RequestState = @This();

completion: union(enum) { free, running, terminal: Event, reported } = .free,
notification: union(enum) { none, pending: Event, borrowed_chunk } = .none,
stream_owner: enum { router, protocol, closed } = .protocol,
close_code: ?u64 = null,
direction: types.Direction = .outbound,
generation: u32 = 0,
conn: Engine.Handle = undefined,
stream: Engine.StreamHandle = undefined,
protocol: @import("protocol.zig").Protocol = .status_v1,
started_ms: u64 = 0,
chunks: u32 = 0,
chunks_max: u32 = 1,
io: RequestIO = .{},
error_message: [codec.error_message_max]u8 = undefined,
error_len: u16 = 0,
failure_detail: []const u8 = "none",
peer_fault: ?PeerFault = null,

pub const PeerFault = enum { protocol, non_completion };

pub fn occupied(self: *const RequestState) bool {
    return self.completion != .free;
}

pub fn awaitingTerminal(self: *const RequestState) bool {
    return self.completion == .running or self.completion == .terminal;
}

pub fn running(self: *const RequestState) bool {
    return self.completion == .running;
}

pub fn available(self: *const RequestState) bool {
    return !self.occupied() and self.generation < std.math.maxInt(u32);
}

pub fn handle(self: *const RequestState, index: u16) events.RequestHandle {
    return .{ .index = index, .generation = self.generation, .direction = self.direction };
}

pub fn pendingEvent(self: *const RequestState) ?Event {
    return if (self.notification == .pending) self.notification.pending else null;
}

pub fn terminalEvent(self: *const RequestState) ?Event {
    return if (self.completion == .terminal) self.completion.terminal else null;
}

pub fn waitingHost(self: *const RequestState) bool {
    return self.notification != .none;
}

pub fn queue(self: *RequestState, event: Event) void {
    assert(self.running() and self.notification == .none);
    assert(event == .chunk or event == .request or event == .chunk_sent);
    self.notification = .{ .pending = event };
}

pub fn deliver(self: *RequestState, control: bool) ?Event {
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

pub fn consume(self: *RequestState) bool {
    if (self.notification != .borrowed_chunk) return false;
    self.notification = .none;
    return true;
}

pub fn closePending(self: *RequestState, engine: *Engine, router: *routing.Router) void {
    if (self.close_code) |code| {
        switch (self.stream_owner) {
            .router => router.cancel(engine, self.stream),
            .protocol => engine.closeStream(self.stream, code),
            .closed => unreachable,
        }
        self.stream_owner = .closed;
        self.close_code = null;
    }
}

pub fn recycleDelivered(self: *RequestState) void {
    assert(self.completion == .reported);
    assert(self.stream_owner == .closed and self.notification == .none);
    self.completion = .free;
    self.io.sink = &.{};
}

/// A pending notification or an undelivered terminal event.
pub fn deliverable(self: *const RequestState) bool {
    return self.notification == .pending or self.completion == .terminal;
}

pub fn terminate(self: *RequestState, event: Event) bool {
    if (!self.running()) return false;
    assert(event == .done or event == .served or event == .failed);
    self.completion = .{ .terminal = event };
    self.io.clear();
    if (self.pendingEvent()) |pending| if (pending == .request) {
        self.notification = .none;
    };
    self.close_code = if (event == .failed) switch (event.failed.reason) {
        .timeout => constants.app_error_timeout,
        .invalid_response, .too_many_chunks, .unknown_context => constants.app_error_invalid_response,
        else => types.app_error_normal,
    } else types.app_error_normal;
    return true;
}
