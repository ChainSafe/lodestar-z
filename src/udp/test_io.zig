const std = @import("std");

pub const FaultIo = struct {
    base: std.Io = undefined,
    vtable: std.Io.VTable = undefined,
    receive: ?Trigger = null,
    send: ?Trigger = null,
    clock: ?Trigger = null,
    entropy: ?Trigger = null,
    receive_calls: usize = 0,
    send_calls: usize = 0,
    clock_calls: usize = 0,
    entropy_calls: usize = 0,
    longest_wait_ms: i64 = 0,

    pub const Trigger = struct {
        at: usize = 1,
        socket: ?std.Io.net.Socket.Handle = null,

        fn matches(self: Trigger, calls: usize, socket: ?std.Io.net.Socket.Handle) bool {
            return calls >= self.at and (self.socket == null or self.socket == socket);
        }
    };

    threadlocal var active: ?*FaultIo = null;

    /// Initialize at a stable address and issue faulted calls on this thread.
    pub fn init(self: *FaultIo, base: std.Io) void {
        std.debug.assert(active == null);
        self.base = base;
        self.vtable = base.vtable.*;
        self.vtable.batchAwaitConcurrent = receiveHook;
        self.vtable.netSend = sendHook;
        self.vtable.now = clockHook;
        self.vtable.randomSecure = entropyHook;
        active = self;
    }

    pub fn deinit(self: *FaultIo) void {
        std.debug.assert(active == self);
        active = null;
    }

    pub fn io(self: *FaultIo) std.Io {
        std.debug.assert(active == self);
        return .{ .userdata = self.base.userdata, .vtable = &self.vtable };
    }

    fn receiveHook(_: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self = active.?;
        if (batch.submitted.head != .none) {
            const operation = batch.storage[batch.submitted.head.toIndex()].submission.operation;
            if (operation == .net_receive) {
                self.receive_calls += 1;
                if (timeout == .duration) self.longest_wait_ms = @max(self.longest_wait_ms, timeout.duration.raw.toMilliseconds());
                if (self.receive) |trigger| if (trigger.matches(self.receive_calls, operation.net_receive.socket_handle)) return error.Canceled;
            }
        }
        return self.base.vtable.batchAwaitConcurrent(self.base.userdata, batch, timeout);
    }

    fn sendHook(_: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self = active.?;
        self.send_calls += 1;
        if (self.send) |trigger| if (trigger.matches(self.send_calls, socket)) return .{ error.AddressFamilyUnsupported, 0 };
        return self.base.vtable.netSend(self.base.userdata, socket, messages, flags);
    }

    fn clockHook(_: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = active.?;
        self.clock_calls += 1;
        if (self.clock) |trigger| if (trigger.matches(self.clock_calls, null)) return .{ .nanoseconds = -1 };
        return self.base.vtable.now(self.base.userdata, clock);
    }

    fn entropyHook(_: ?*anyopaque, bytes: []u8) std.Io.RandomSecureError!void {
        const self = active.?;
        self.entropy_calls += 1;
        if (self.entropy) |trigger| if (trigger.matches(self.entropy_calls, null)) return error.EntropyUnavailable;
        return self.base.vtable.randomSecure(self.base.userdata, bytes);
    }
};
