const std = @import("std");
const NetworkCore = @import("network_core.zig").NetworkCore;
const Transport = @import("transport.zig").Transport;
const Now = @import("types.zig").Now;
const wait = @import("wait.zig");
const timing = @import("metrics/timing.zig");

/// Waits for socket/host readiness or scheduled work, then advances the core with a fresh clock.
/// The core and its borrowed descriptors must remain owned by this thread throughout the call.
pub fn step(core: *NetworkCore, io: std.Io, now: Now, outputs: NetworkCore.Outputs, host: NetworkCore.Host) NetworkCore.Result {
    var wakeups = core.wakeups(now, outputs);
    wakeups.note(.host, .{ .deadline_ms = host.deadline_ms });
    const timeout_ms = if (core.peer_manager.stopped) 0 else wakeups.schedule().waitMs(now.mono_ms, wait.native_wait_max_ms);
    if (!core.peer_manager.stopped and timeout_ms == 0) {
        for (wakeups.sources, &core.due_now_turns) |source, *turns| {
            turns.* +|= @intFromBool(source.due(now.mono_ms));
        }
    }
    const readiness: wait.Result = if (comptime wait.supported) wait.poll(io, .{
        .quic = core.transport.sockets.handles(),
        .discovery = if (!core.peer_manager.quiescing and !core.peer_manager.stopped and core.discovery != null)
            core.discovery.?.transport.sockets.handles()
        else
            .{ null, null },
        .host = core.host_wake,
    }, timeout_ms) else .{ .failure = error.UnsupportedWait };
    core.counters.readiness_failures +|= @intFromBool(readiness.failure != null);
    const start = timing.now(io);
    defer core.step_duration.observe(timing.now(io) -| start);
    var clock_failure: ?error{ClockOutOfRange} = null;
    const read = Transport.currentTime(io) catch |err| blk: {
        clock_failure = err;
        core.counters.transport_failures +|= 1;
        break :blk now;
    };
    const tick = if (read.mono_ms >= now.mono_ms) read else now;
    var result = core.advance(io, tick, readiness, outputs, host);
    if (result.failure == null or result.failure.? != error.Canceled) {
        if (clock_failure) |err| result.failure = readiness.failure orelse err;
    }
    return result;
}

test {
    _ = @import("driver_test.zig");
}
