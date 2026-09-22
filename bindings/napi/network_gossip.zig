const std = @import("std");
const n = @import("network");
const native = n.gossipsub;
const Runtime = @import("network_runtime.zig").Runtime;
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
pub fn flags(runtime: *Runtime, io: std.Io) !void {
    runtime.lock();
    defer runtime.unlock();
    const table = if (runtime.gossip) |*table| table else return;
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
}
pub const Ingress = struct {
    runtime: *Runtime,
    io: std.Io,
    failure: ?anyerror = null,

    pub fn sink(self: *Ingress) native.MessageSink {
        return .{ .context = self, .has_capacity = hasCapacity, .make_room = makeRoom, .deliver = deliver };
    }

    fn hasCapacity(context: *anyopaque, kind: native.topic.Kind, len: usize) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        if (self.failure != null) return false;
        const runtime = self.runtime;
        runtime.lock();
        defer runtime.unlock();
        if (runtime.stop) return false;
        const table = if (runtime.gossip) |*table| table else return false;
        return table.hasCapacity(kind, len) or table.freshnessVictim(kind) != null;
    }

    fn makeRoom(context: *anyopaque, source: processor.Source, kind: native.topic.Kind, len: usize) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        const runtime = self.runtime;
        runtime.lock();
        defer runtime.unlock();
        if (runtime.stop or self.failure != null) return false;
        const table = &runtime.gossip.?;
        if (!table.sourceRoom(source, kind, len)) {
            table.diag.sourceRefusals +|= 1;
            return false;
        }
        const now = monotonic() catch |err| {
            self.failure = err;
            return false;
        };
        var bytes: usize = 0;
        for (0..batch_max) |_| {
            if (table.hasCapacity(kind, len)) return true;
            const token = table.freshnessVictim(kind) orelse return false;
            const cell = table.get(token).?;
            if (bytes > 0 and cell.input.len > batch_bytes -| bytes) return false;
            bytes += cell.input.len;
            table.outcome(runtime.heavy.?.core.reportValidation(cell.handle, .ignore, .{ .mono_ms = now, .unix_s = 0 }));
            table.retire(token);
            table.diag.freshnessReplacements +|= 1;
        }
        return table.hasCapacity(kind, len);
    }

    fn deliver(context: *anyopaque, message: *const native.MessageEvent) bool {
        const self: *Ingress = @ptrCast(@alignCast(context));
        return self.capture(message) catch |err| {
            self.failure = err;
            return false;
        };
    }

    fn capture(self: *Ingress, message: *const native.MessageEvent) !bool {
        const runtime = self.runtime;
        const clock = try sample(self.io);
        const now: n.Now = .{ .mono_ms = clock.mono_ms, .unix_s = @intCast(clock.unix_ms / 1000) };
        const received_at = try projectWall(message.admitted_ms, clock);
        runtime.lock();
        defer runtime.unlock();
        const table = &runtime.gossip.?;
        if (runtime.stop or table.closed or now.mono_ms >= message.deadline) {
            return false;
        }
        const parsed = native.topic.parseCanonical(message.topic).?;
        const kind = parsed.name.kind;
        var electra = false;
        var deneb = false;
        if (table.limits != null) {
            const config = &runtime.heavy.?.config;
            for (config.chain.forks[0..config.chain.supported_count]) |fork| if (std.mem.eql(u8, &fork.digest, &parsed.digest)) {
                electra = @intFromEnum(fork.fork) >= @intFromEnum(@as(@TypeOf(fork.fork), .electra));
                deneb = @intFromEnum(fork.fork) >= @intFromEnum(@as(@TypeOf(fork.fork), .deneb));
                break;
            };
        }
        const metadata: processor.metadata_mod.Metadata = if (table.limits != null) processor.metadata_mod.extract(kind, electra, message.bytes) else .{};
        if (table.limits != null and !processor.metadata_mod.eligible(&metadata, kind, deneb, runtime.slot)) {
            table.diag.slotRefusals +|= 1;
            return false;
        }
        const empty = !table.hasWork();
        table.capture(message, &metadata, deneb, received_at) catch |err| switch (err) {
            error.NetworkGossipFull, error.NetworkBridgeFull => return false,
            else => return err,
        };
        if (empty and table.hasWork()) runtime.pingLocked();
        return true;
    }
};
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.gossip) |*table| table.close();
}
test {
    _ = @import("network_gossip_test.zig");
}
