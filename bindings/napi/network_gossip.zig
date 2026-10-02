const std = @import("std");
const n = @import("network");
const native = n.gossipsub;
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const assert = std.debug.assert;
const processor = n.gossip_processor;
pub const batch_max = processor.GossipProcessor.batch_max;
pub const batch_bytes = processor.GossipProcessor.batch_bytes;
pub const payload_max = processor.GossipProcessor.payload_max;
pub const topic_max = processor.GossipProcessor.topic_max;
pub const Token = processor.GossipProcessor.Token;
pub const Cell = processor.GossipProcessor.Cell;
pub const Diagnostics = processor.GossipProcessor.Diagnostics;
pub const Batch = processor.GossipProcessor.Batch;
pub const Table = processor.GossipProcessor;
pub const Clock = struct { mono_ms: u64, unix_ms: u64 };
pub fn sample(io: std.Io) !Clock {
    const mono = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const wall = std.Io.Timestamp.now(io, .real).toMilliseconds();
    if (mono < 0 or mono > std.math.maxInt(u64) or wall < 0 or wall > 9007199254740991) return error.InvalidNetworkClock;
    return .{ .mono_ms = @intCast(mono), .unix_ms = @intCast(wall) };
}
pub fn monotonic() !u64 {
    const value = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .awake).toMilliseconds();
    if (value < 0 or value > std.math.maxInt(u64)) return error.InvalidNetworkClock;
    return @intCast(value);
}
pub fn projectWall(admitted: u64, clock: Clock) !u64 {
    if (admitted > clock.mono_ms) return error.InvalidNetworkClock;
    const elapsed = clock.mono_ms - admitted;
    if (elapsed > clock.unix_ms or clock.unix_ms > 9007199254740991) return error.InvalidNetworkClock;
    return clock.unix_ms - elapsed;
}
/// Runs processor maintenance and applies queued verdicts, unless the host holds them. Each message the host was
/// handed then awaits acknowledgement of its disposition. Returns whether bounded carry-over work remains for the
/// next turn.
pub fn flags(runtime: *Runtime, io: std.Io) !bool {
    runtime.lock();
    defer runtime.unlock();
    const table = if (runtime.gossip) |*table| table else return false;
    const clock = try sample(io);
    const now: n.Now = .{ .mono_ms = clock.mono_ms, .unix_s = @intCast(clock.unix_ms / 1000) };
    table.maintain(now.mono_ms, runtime.slot);
    var retired_bytes: usize = 0;
    for (0..if (runtime.verdicts_held) 0 else batch_max) |_| {
        const token = table.nextVerdict() orelse break;
        const cell = table.get(token).?;
        if (retired_bytes > 0 and cell.input.len > batch_bytes -| retired_bytes) break;
        retired_bytes += cell.input.len;
        const result = runtime.heavy.?.core.reportValidation(cell.handle, cell.verdict, now);
        table.outcome(result);
        table.retire(token);
    }
    runtime.recomputeLocked(.completions);
    runtime.recomputeLocked(.checks);
    runtime.recomputeLocked(.gossip);
    return table.pending(!runtime.verdicts_held);
}
pub const Ingress = struct {
    runtime: *Runtime,
    io: std.Io,
    failure: ?anyerror = null,

    pub fn sink(self: *Ingress) native.Gossipsub.MessageSink {
        return .{ .context = self, .has_capacity = hasCapacity, .admit = admit };
    }

    fn hasCapacity(context: *anyopaque, kind: native.topic.Kind, len: usize) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        if (self.failure != null) return false;
        const runtime = self.runtime;
        runtime.lock();
        defer runtime.unlock();
        if (runtime.stop) return false;
        const table = if (runtime.gossip) |*table| table else return false;
        return table.admissible(kind, len);
    }

    fn admit(context: *anyopaque, candidate: *native.Gossipsub.MessageAdmission) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        return self.capture(candidate) catch |err| {
            self.failure = err;
            return false;
        };
    }

    fn capture(self: *Ingress, candidate: *native.Gossipsub.MessageAdmission) !bool {
        const runtime = self.runtime;
        const clock = try sample(self.io);
        const received_at = try projectWall(candidate.event.admitted_ms, clock);
        runtime.lock();
        defer runtime.unlock();
        if (runtime.stop or self.failure != null) return false;
        const accepted = runtime.gossip.?.admit(runtime.heavy.?.core.service.gossipsub, candidate, clock.mono_ms, received_at, runtime.slot);
        runtime.recomputeLocked(.checks);
        runtime.recomputeLocked(.gossip);
        return accepted;
    }
};
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.gossip) |*table| table.close();
}
test {
    _ = @import("network_gossip_test.zig");
}
