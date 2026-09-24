const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;
/// A backstop only: an owner computes its wait from its deadlines and wakes on readiness.
pub const native_wait_max_ms: u32 = 1_000;
pub const Error = error{ UnsupportedWait, InvalidWakeSource, WaitFailed, WaitSourceClosed, Canceled };
pub const Sources = struct { quic: [2]?i32, discovery: [2]?i32 = .{ null, null }, host: ?i32 = null };
pub const Result = struct {
    quic: bool = false,
    discovery: bool = false,
    host: bool = false,
    interrupted: bool = false,
    timeout_ms: u32 = 0,
    failure: ?Error = null,
};

/// Requires real OS descriptors from an Io provider with the OS awake clock.
/// Cancellation is checked around one poll, bounded to 1 s. Host readiness and
/// signals can wake it sooner; arbitrary Io cancellation cannot interrupt libc.
/// Only observes readiness. Descriptor owners retain all bytes and close duties.
pub fn poll(io: std.Io, sources: Sources, timeout_ms: u32) Result {
    if (!supported) return .{ .failure = error.UnsupportedWait };
    const handles = sources.quic ++ sources.discovery ++ [_]?i32{sources.host};
    if (sources.quic[0] == null and sources.quic[1] == null) return .{ .failure = error.InvalidWakeSource };
    for (handles) |fd| if (fd) |value| if (value < 0) return .{ .failure = error.InvalidWakeSource };
    io.checkCancel() catch |err| return .{ .failure = err };
    var descriptors: [5]std.c.pollfd = undefined;
    for (handles, &descriptors) |fd, *descriptor| descriptor.* = .{ .fd = fd orelse -1, .events = std.c.POLL.IN, .revents = 0 };
    var result: Result = .{ .timeout_ms = @min(timeout_ms, native_wait_max_ms) };
    const count = std.c.poll(&descriptors, descriptors.len, @intCast(result.timeout_ms));
    if (count < 0) {
        switch (std.c.errno(count)) {
            .INTR => result.interrupted = true,
            else => result.failure = error.WaitFailed,
        }
    } else {
        result.quic = (descriptors[0].revents | descriptors[1].revents) & std.c.POLL.IN != 0;
        result.discovery = (descriptors[2].revents | descriptors[3].revents) & std.c.POLL.IN != 0;
        result.host = descriptors[4].revents & std.c.POLL.IN != 0;
        for (descriptors) |descriptor| {
            if (descriptor.revents & (std.c.POLL.ERR | std.c.POLL.HUP | std.c.POLL.NVAL) != 0)
                result.failure = error.WaitSourceClosed;
        }
    }
    io.checkCancel() catch |err| {
        result.failure = result.failure orelse err;
    };
    return result;
}

test {
    _ = @import("wait_test.zig");
}
