const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;
/// A backstop only: an owner computes its wait from its deadlines and wakes on readiness.
pub const native_wait_max_ms: u32 = 1_000;
pub const Error = error{ UnsupportedWait, InvalidWakeSource, WaitFailed, WaitSourceClosed, Canceled };
pub const Sources = struct { quic: [2]?i32, discovery: [2]?i32 = .{ null, null }, host: ?i32 = null };
pub const Result = struct {
    /// Per family, indexed like `Sources.quic`.
    quic: [2]bool = .{ false, false },
    discovery: [2]bool = .{ false, false },
    host: bool = false,
    failure: ?Error = null,

    pub fn discoveryReady(self: *const Result) bool {
        return self.discovery[0] or self.discovery[1];
    }

    pub fn quicReady(self: *const Result) bool {
        return self.quic[0] or self.quic[1];
    }
};

/// Requires real OS descriptors from an Io provider with the OS awake clock.
/// Cancellation is checked around one poll, bounded to 1 s. Host readiness and
/// signals can wake it sooner; arbitrary Io cancellation cannot interrupt libc.
/// Only observes readiness. Descriptor owners retain all bytes and close duties.
pub fn poll(io: std.Io, sources: Sources, timeout_ms: u32) Result {
    return pollWith(io, sources, timeout_ms, std.c.poll);
}

fn pollWith(io: std.Io, sources: Sources, timeout_ms: u32, comptime pollFn: anytype) Result {
    if (!supported) return .{ .failure = error.UnsupportedWait };
    const handles = sources.quic ++ sources.discovery ++ [_]?i32{sources.host};
    if (sources.quic[0] == null and sources.quic[1] == null) return .{ .failure = error.InvalidWakeSource };
    for (handles) |fd| if (fd) |value| if (value < 0) return .{ .failure = error.InvalidWakeSource };
    io.checkCancel() catch |err| return .{ .failure = err };
    var descriptors: [5]std.c.pollfd = undefined;
    for (handles, &descriptors) |fd, *descriptor| descriptor.* = .{ .fd = fd orelse -1, .events = std.c.POLL.IN, .revents = 0 };
    var result: Result = .{};
    const count = pollFn(&descriptors, descriptors.len, @intCast(@min(timeout_ms, native_wait_max_ms)));
    if (count < 0) {
        switch (std.c.errno(count)) {
            .INTR => {},
            else => |errno| {
                std.log.scoped(.network_runtime).debug("owner_poll_failed errno={s}", .{@tagName(errno)});
                result.failure = error.WaitFailed;
            },
        }
    } else {
        for (&result.quic, descriptors[0..2]) |*ready, descriptor| ready.* = descriptor.revents & std.c.POLL.IN != 0;
        for (&result.discovery, descriptors[2..4]) |*ready, descriptor| ready.* = descriptor.revents & std.c.POLL.IN != 0;
        result.host = descriptors[4].revents & std.c.POLL.IN != 0;
        for (descriptors, 0..) |descriptor, index| {
            if (descriptor.revents & (std.c.POLL.ERR | std.c.POLL.HUP | std.c.POLL.NVAL) != 0) {
                const role: []const u8 = if (index < 2) "quic" else if (index < 4) "discovery" else "host";
                const family: []const u8 = if (index == 4) "none" else if (index % 2 == 0) "ip4" else "ip6";
                std.log.scoped(.network_runtime).debug("owner_poll_source_failed role={s} family={s} descriptor={d} revents={x}", .{ role, family, descriptor.fd, descriptor.revents });
                result.failure = error.WaitSourceClosed;
            }
        }
    }
    io.checkCancel() catch |err| {
        result.failure = result.failure orelse err;
    };
    return result;
}

test "native wait handles interruption once and bounds the poll timeout" {
    _ = @import("wait_test.zig");
    if (!supported) return error.SkipZigTest;
    const Interrupted = struct {
        var calls: usize = 0;
        fn poll(_: [*]std.c.pollfd, _: std.c.nfds_t, timeout: c_int) c_int {
            calls += 1;
            std.debug.assert(timeout == native_wait_max_ms);
            std.c._errno().* = @intFromEnum(std.posix.E.INTR);
            return -1;
        }
    };
    const result = pollWith(std.testing.io, .{ .quic = .{ 0, null } }, 5000, Interrupted.poll);
    try std.testing.expectEqual(@as(usize, 1), Interrupted.calls);
    try std.testing.expect(result.failure == null);
    try std.testing.expect(!result.quicReady() and !result.discoveryReady() and !result.host);
}
