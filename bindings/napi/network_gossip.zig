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
    table.slot = runtime.slot;
    if (table.batch_due) |due| if (now.mono_ms >= due) {
        table.batch_due = null;
        if (table.hasWork()) runtime.pingLocked();
    };
    if (table.limits != null) for (table.cells) |*cell| {
        if (cell.state != .queued and cell.state != .waiting and cell.state != .needs_check and cell.state != .checking) continue;
        if (!processor.metadata_mod.eligible(&cell.metadata, cell.kind, cell.deneb, table.slot)) {
            table.ignore(cell);
            table.diag.slotRefusals +|= 1;
        }
    };
    var applied: usize = 0;
    for (0..table.cells.len) |_| {
        const i = table.cursor;
        table.cursor = (i + 1) % table.cells.len;
        const cell = &table.cells[i];
        if (cell.state != .verdict_pending) continue;
        const result = runtime.heavy.?.core.reportValidation(cell.handle, cell.verdict, now);
        table.outcome(result);
        if (now.mono_ms >= cell.deadline) table.diag.deliveredExpired +|= 1;
        table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        applied += 1;
        if (applied == batch_max) break;
    }
    table.expire(now.mono_ms);
    if (applied > 0 and table.hasWork()) {
        runtime.readable_rearm = true;
        runtime.signalLocked();
    }
}
pub fn capture(runtime: *Runtime, events: []const native.Event, clock: Clock) !void {
    const table = if (runtime.gossip) |*table| table else return;
    const now: n.Now = .{ .mono_ms = clock.mono_ms, .unix_s = @intCast(clock.unix_ms / 1000) };
    for (events) |event| {
        if (event != .message) continue;
        const message = event.message;
        const received_at = try projectWall(message.admitted_ms, clock);
        runtime.lock();
        const kind = native.topic.parseCanonical(message.topic).?.name.kind;
        var electra = false;
        var deneb = false;
        if (table.limits != null) {
            const digest = native.topic.parseCanonical(message.topic).?.digest;
            const config = &runtime.heavy.?.config;
            for (config.chain.forks[0..config.chain.supported_count]) |fork| if (std.mem.eql(u8, &fork.digest, &digest)) {
                electra = @intFromEnum(fork.fork) >= @intFromEnum(@as(@TypeOf(fork.fork), .electra));
                deneb = @intFromEnum(fork.fork) >= @intFromEnum(@as(@TypeOf(fork.fork), .deneb));
                break;
            };
        }
        const metadata: processor.metadata_mod.Metadata = if (table.limits != null) processor.metadata_mod.extract(kind, electra, message.bytes) else .{};
        if (table.limits != null and !processor.metadata_mod.eligible(&metadata, kind, deneb, runtime.slot)) {
            table.diag.slotRefusals +|= 1;
            table.outcome(runtime.heavy.?.core.reportValidation(message.handle, .ignore, now));
            runtime.unlock();
            continue;
        }
        const token = table.reserveKind(kind, message.bytes.len) catch |err| {
            switch (err) {
                error.NetworkGossipFull, error.NetworkBridgeFull => {},
                else => {
                    runtime.unlock();
                    return err;
                },
            }
            table.outcome(runtime.heavy.?.core.reportValidation(message.handle, .ignore, now));
            runtime.unlock();
            continue;
        };
        const cell = table.get(token).?;
        cell.metadata = metadata;
        cell.deneb = deneb;
        cell.handle = message.handle;
        cell.identity = message.identity;
        cell.source = message.source;
        cell.connection = message.peer;
        cell.id = message.id;
        assert(message.topic.len <= topic_max);
        @memcpy(cell.topic[0..message.topic.len], message.topic);
        cell.topic_len = @intCast(message.topic.len);
        cell.deadline = message.deadline;
        cell.received_at = received_at;
        cell.admitted_ms = message.admitted_ms;
        const empty = !table.hasWork();
        table.install(token, message.bytes);
        if (runtime.stop) table.retire(token) else {
            table.expire(clock.mono_ms);
            if (empty and table.hasWork()) runtime.pingLocked();
        }
        runtime.unlock();
    }
}
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.gossip) |*table| table.close();
}
pub fn releasePublicationLocked(runtime: *Runtime, input: *@import("network_commands.zig").Input) void {
    if (input.command != .publishGossip) return;
    @import("network_runtime.zig").allocator.free(input.publication);
    input.publication = &.{};
    runtime.gossip.?.releasePublication(input.publication_reservation);
    input.publication_reservation = 0;
}
pub fn published(runtime: *Runtime, result: native.Gossipsub.PublishOutcome) void {
    const diag = &runtime.gossip.?.diag;
    diag.publicationQueued +|= result.queued;
    diag.publicationPressured +|= result.pressured;
    diag.publicationSelected +|= result.selected;
    diag.publicationUnavailable +|= result.unavailable;
    diag.publicationDuplicates +|= @intFromBool(result.duplicate);
}
test {
    _ = @import("network_gossip_test.zig");
}
