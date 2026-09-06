const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;
pub const native_wait_max_ms: u32 = 100;
pub const Mode = enum { portable, native_poll };
pub const Error = error{ UnsupportedWait, InvalidWakeSource, WaitFailed, WaitSourceClosed, Canceled };
pub const Sources = struct { quic: i32, discovery: ?i32 = null, host: ?i32 = null };
pub const Result = struct {
    quic: bool = false,
    discovery: bool = false,
    host: bool = false,
    interrupted: bool = false,
    timeout_ms: u32 = 0,
    failure: ?Error = null,
};

/// Requires real OS descriptors from an Io provider with the OS awake clock.
/// Cancellation is checked around one poll, bounded to 100ms. Host readiness and
/// signals can wake it sooner; arbitrary Io cancellation cannot interrupt libc.
/// Only observes readiness. Descriptor owners retain all bytes and close duties.
pub fn poll(io: std.Io, sources: Sources, timeout_ms: u32) Result {
    if (!supported) return .{ .failure = error.UnsupportedWait };
    if (sources.quic < 0 or (sources.discovery != null and sources.discovery.? < 0) or
        (sources.host != null and sources.host.? < 0)) return .{ .failure = error.InvalidWakeSource };
    io.checkCancel() catch |err| return .{ .failure = err };
    var descriptors = [_]std.c.pollfd{
        .{ .fd = sources.quic, .events = std.c.POLL.IN, .revents = 0 },
        .{ .fd = sources.discovery orelse -1, .events = std.c.POLL.IN, .revents = 0 },
        .{ .fd = sources.host orelse -1, .events = std.c.POLL.IN, .revents = 0 },
    };
    var result: Result = .{ .timeout_ms = @min(timeout_ms, native_wait_max_ms) };
    const count = std.c.poll(&descriptors, descriptors.len, @intCast(result.timeout_ms));
    if (count < 0) {
        switch (std.c.errno(count)) {
            .INTR => result.interrupted = true,
            else => result.failure = error.WaitFailed,
        }
    } else {
        result.quic = descriptors[0].revents & std.c.POLL.IN != 0;
        result.discovery = descriptors[1].revents & std.c.POLL.IN != 0;
        result.host = descriptors[2].revents & std.c.POLL.IN != 0;
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
