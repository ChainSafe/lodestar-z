const std = @import("std");
const n = @import("network");
const native = n.gossipsub;
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const assert = std.debug.assert;
const processor = n.gossip_processor;
pub const batch_max = processor.batch_max;
pub const batch_bytes = processor.batch_bytes;
pub const payload_max = processor.payload_max;
pub const topic_max = processor.topic_max;
pub const Token = processor.Token;
pub const Cell = processor.Cell;
pub const Diagnostics = processor.Diagnostics;
pub const Batch = processor.Batch;
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
/// Runs processor maintenance and applies queued verdicts. Returns whether bounded carry-over
/// work remains for the next turn.
pub fn flags(runtime: *Runtime, io: std.Io) !bool {
    runtime.lock();
    defer runtime.unlock();
    const table = if (runtime.gossip) |*table| table else return false;
    const clock = try sample(io);
    const now: n.Now = .{ .mono_ms = clock.mono_ms, .unix_s = @intCast(clock.unix_ms / 1000) };
    table.maintain(now.mono_ms, runtime.slot);
    var retired_bytes: usize = 0;
    for (0..batch_max) |_| {
        const token = table.nextVerdict() orelse break;
        const cell = table.get(token).?;
        if (retired_bytes > 0 and cell.input.len > batch_bytes -| retired_bytes) break;
        retired_bytes += cell.input.len;
        const result = runtime.heavy.?.core.reportValidation(cell.handle, cell.verdict, now);
        table.outcome(result);
        table.retire(token);
    }
    if (table.hasWork()) runtime.pingLocked();
    return table.pending();
}
pub const Ingress = struct {
    runtime: *Runtime,
    io: std.Io,
    failure: ?anyerror = null,

    pub fn sink(self: *Ingress) native.MessageSink {
        return .{ .context = self, .has_capacity = hasCapacity, .admit = admit };
    }

    fn hasCapacity(context: *anyopaque, kind: native.topic.Kind, len: usize) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        if (self.failure != null) return false;
        const previous = r.phase(.gossip_ingress);
        defer r.restore(previous);
        const runtime = self.runtime;
        runtime.lock();
        defer runtime.unlock();
        if (runtime.stop) return false;
        const table = if (runtime.gossip) |*table| table else return false;
        if (table.hasCapacity(kind, len) or table.freshnessVictim(kind) != null) return true;
        if (!table.closed) table.refuseCapacity(kind, len);
        return false;
    }

    fn admit(context: *anyopaque, candidate: *native.Admission) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        return self.capture(candidate) catch |err| {
            self.failure = err;
            return false;
        };
    }

    fn capture(self: *Ingress, candidate: *native.Admission) !bool {
        const previous = r.phase(.gossip_ingress);
        defer r.restore(previous);
        const runtime = self.runtime;
        const clock = try sample(self.io);
        const received_at = try projectWall(candidate.event.admitted_ms, clock);
        runtime.lock();
        defer runtime.unlock();
        const admitted_ns = r.bridge.now();
        if (runtime.stop or self.failure != null) return false;
        const table = &runtime.gossip.?;
        const empty = !table.hasWork();
        const accepted = table.admit(runtime.heavy.?.core.service.gossipsub, candidate, clock.mono_ms, received_at, runtime.slot);
        if (accepted) {
            const kind = native.topic.parseCanonical(candidate.event.topic).?.name.kind;
            runtime.bridge.admission_lag[@intFromEnum(r.bridge.admissionKind(kind))].observe(admitted_ns -| runtime.heavy.?.core.tick_ns);
        }
        if (empty and table.hasWork()) runtime.pingLocked();
        return accepted;
    }
};
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.gossip) |*table| table.close();
}
test {
    _ = @import("network_gossip_test.zig");
}
