const std = @import("std");
const Transport = @import("Transport.zig");
const CallTable = @import("CallTable.zig");

pub const Options = struct {
    wait_max_ms: u32 = 100,
    deadline_ms: u64 = std.math.maxInt(u64),
};

/// Standalone std.Io driver. Waiting receives at most one datagram; protocol advancement uses
/// the clock read after that wait. Dual-family sockets require Io concurrency support.
pub fn step(transport: *Transport, io: std.Io, expired: []CallTable.Expired, options: Options) Transport.Error!Transport.StepResult {
    if (expired.len == 0) return error.MissingExpiryStorage;
    const before = Transport.monotonicMilliseconds(io) catch |err| return .{ .failure = err, .failure_stage = .clock };
    const deadline = @min(options.deadline_ms, transport.engine.nextDeadlineMs() orelse options.deadline_ms);
    const wait_ms = @min(options.wait_max_ms, 1_000, deadline -| before);
    var ready: [2]bool = @splat(true);
    const input: Transport.Input = if (wait_ms == 0)
        transport.receive(io, &ready)
    else if (transport.sockets.receiveDatagram(io, &transport.receive_buffer, .{ .duration = .{
        .raw = .fromMilliseconds(wait_ms),
        .clock = .awake,
    } })) |packet| packet else |err| err;
    var clock_failure: ?error{ClockOutOfRange} = null;
    const read = Transport.monotonicMilliseconds(io) catch |err| blk: {
        clock_failure = err;
        break :blk before;
    };
    var result = try transport.advance(io, @max(before, read), expired, input);
    if (result.failure == null) if (clock_failure) |err| {
        result.failure = err;
        result.failure_stage = .clock;
    };
    return result;
}

test {
    _ = @import("driver_test.zig");
}
