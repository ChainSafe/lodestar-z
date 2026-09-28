const std = @import("std");

/// A seccomp filter that fails sendto and sendmmsg on chosen sockets with a real errno.
pub const SendFilter = struct {
    pub const Instruction = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
    pub const Program = extern struct { len: c_ushort, filter: [*]const Instruction };

    pub const Rule = struct {
        socket: std.Io.net.Socket.Handle,
        errno: std.os.linux.E,
        /// Fails only sends that ask not to wait, as a full send buffer does.
        nonblocking_only: bool = false,
    };

    const rules_max = 4;

    /// Filters the calling thread's sends until the thread ends, one rule per socket. Threads it
    /// starts afterwards inherit the filter, so the caller must not start any, including Io tasks.
    /// Returns false where the kernel refuses seccomp filters.
    pub fn install(rules: []const Rule) bool {
        const linux = std.os.linux;
        const bpf = linux.BPF;
        std.debug.assert(rules.len > 0 and rules.len <= rules_max);
        const little = comptime @import("builtin").cpu.arch.endian() == .little;
        const descriptor: u32 = @offsetOf(linux.SECCOMP.data, "arg0") + if (little) 0 else 4;
        const flags: u32 = @offsetOf(linux.SECCOMP.data, "arg3") + if (little) 0 else 4;
        var length: usize = 5;
        for (rules) |rule| length += if (rule.nonblocking_only) 4 else 2;
        const allow = length - 1;
        var filter: [5 + 4 * rules_max]Instruction = undefined;
        filter[0] = .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = @offsetOf(linux.SECCOMP.data, "nr") };
        filter[1] = .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 1, .jf = 0, .k = @intFromEnum(linux.SYS.sendto) };
        filter[2] = .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = @intCast(allow - 3), .k = @intFromEnum(linux.SYS.sendmmsg) };
        filter[3] = .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = descriptor };
        var at: usize = 4;
        for (rules) |rule| {
            const block: u8 = if (rule.nonblocking_only) 4 else 2;
            filter[at] = .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = block - 1, .k = @intCast(rule.socket) };
            if (rule.nonblocking_only) {
                filter[at + 1] = .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = flags };
                filter[at + 2] = .{ .code = bpf.JMP | bpf.JSET | bpf.K, .jt = 0, .jf = @intCast(allow - at - 3), .k = linux.MSG.DONTWAIT };
            }
            filter[at + block - 1] = .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ERRNO | @as(u32, @intFromEnum(rule.errno)) };
            at += block;
        }
        std.debug.assert(at == allow);
        filter[allow] = .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ALLOW };
        const program: Program = .{ .len = @intCast(length), .filter = &filter };
        if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS) return false;
        return linux.errno(linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &program)) == .SUCCESS;
    }
};

pub const FaultIo = struct {
    base: std.Io = undefined,
    vtable: std.Io.VTable = undefined,
    receive: ?Trigger = null,
    send: ?Trigger = null,
    send_failure: std.Io.net.Socket.SendError = error.AddressFamilyUnsupported,
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
        if (self.send) |trigger| if (trigger.matches(self.send_calls, socket)) return .{ self.send_failure, 0 };
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
