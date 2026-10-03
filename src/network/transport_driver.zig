const std = @import("std");
const Transport = @import("transport.zig").Transport;
const Engine = @import("quic/Engine.zig");
const wait = @import("wait.zig");

pub const Options = struct { wait_max_ms: u32 = @import("constants.zig").poll_interval_ms };
pub const Error = Transport.StepError || wait.Error || error{ClockOutOfRange};
pub const Result = struct { progress: Transport.StepResult, failure: ?Error = null };

/// Standalone driver for a transport without NetworkCore. Requires OS sockets and the OS clock,
/// like the network driver. The caller consumes event borrows before another turn or teardown.
pub fn step(transport: *Transport, io: std.Io, events: []Engine.Event, options: Options) Result {
    const before = Transport.currentTime(io) catch |err| return .{
        .progress = .{ .now = .{ .mono_ms = 0, .unix_s = 0 } },
        .failure = err,
    };
    const timeout = transport.schedule().waitMs(before.mono_ms, @min(options.wait_max_ms, wait.native_wait_max_ms));
    const ready = wait.poll(io, .{ .quic = transport.sockets.handles() }, timeout);
    var failure: ?Error = ready.failure;
    const read = Transport.currentTime(io) catch |err| blk: {
        failure = failure orelse err;
        break :blk before;
    };
    const now = if (read.mono_ms >= before.mono_ms) read else before;
    const advanced = transport.advance(io, .{
        .now = now,
        .ready = if (ready.failure != null) @splat(true) else ready.quic,
        .cancelled = if (ready.failure) |err| err == error.Canceled else false,
    }, events);
    if (advanced.failure) |err| failure = if (err == error.Canceled) err else failure orelse err;
    return .{ .progress = advanced.progress, .failure = failure };
}

test {
    _ = @import("transport_driver_test.zig");
}
