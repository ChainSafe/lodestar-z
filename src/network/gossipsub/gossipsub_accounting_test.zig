const std = @import("std");
const support = @import("test_support.zig");
const topic_mod = @import("topic.zig");
const session_io = @import("session_io.zig");
const slots = @import("../slot_clock.zig");
const Gossipsub = @import("gossipsub.zig").Gossipsub;
const Apply = @import("metrics.zig").Apply;
const IwantOutcome = @import("metrics.zig").IwantOutcome;
const GraftOutcome = @import("mesh_metrics.zig").GraftOutcome;
const Removal = @import("mesh_metrics.zig").Removal;
const MessageId = topic_mod.MessageId;

const name = "/eth2/01020304/beacon_block/ssz_snappy";

fn drain(g: *Gossipsub, peer: u16, now_ms: u64) void {
    const tx = &g.sessions.rows[peer].io.tx;
    for (0..64) |_| {
        const segment = tx.segment(&g.messages.store);
        if (segment.len == 0) break;
        g.advanceWrite(g.sessions.ref(peer), segment.len, now_ms);
    }
}

fn ids(out: []u8, field: u32, list: []const MessageId) []const u8 {
    var writer = @import("protobuf.zig").Writer.init(out);
    for (list) |*id| writer.bytesField(field, id);
    return writer.written();
}

test "owner applies record verdict bursts, forward admissions and the service between them" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const source = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    var destinations: [2]u16 = undefined;
    try support.subscribe(&g, name);
    for (&destinations, 1..) |*destination, index| {
        destination.* = support.addPeer(&g, .{ .index = @intCast(index), .generation = 1 }, .v1_2).?.index;
        g.overlay.rows[g.overlay.findTopic(name).?].mesh.set(destination.*);
        g.sessions.rows[destination.*].io.tx.cancelStream(&g.messages.store);
    }
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var handles: [3]@import("validation.zig").Handle = undefined;
    var len: u64 = 0;
    for (&handles, 0..) |*handle, i| {
        var text: [16]u8 = undefined;
        try std.testing.expectEqual(@as(?usize, 1), try support.message(&g, source.index, try std.fmt.bufPrint(&text, "verdict {d}", .{i}), 1));
        handle.* = inbox.last().handle;
        len = g.messages.store.get(g.messages.validation.entries[handle.index].state.pending.message).?.len;
    }
    // One host apply reports two verdicts, each forwarded to both mesh peers.
    for (handles[0..2]) |handle| _ = g.report(handle, .accept, .{ .mono_ms = 10, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 0), g.apply_metrics.verdicts.count);
    for (destinations) |destination| drain(&g, destination, 12);
    _ = session_io.beginPump(&g, .{ .mono_ms = 12, .unix_s = 0 });
    const metrics = &g.apply_metrics;
    try std.testing.expectEqual(@as(u64, 1), metrics.verdicts.count);
    try std.testing.expectEqual(@as(u128, 2), metrics.verdicts.sum);
    try std.testing.expectEqual(@as(u128, 4), metrics.recipients[@intFromEnum(Apply.Recipient.selected)].sum);
    try std.testing.expectEqual(@as(u128, 4), metrics.recipients[@intFromEnum(Apply.Recipient.queued)].sum);
    try std.testing.expectEqual(@as(u128, 0), metrics.recipients[@intFromEnum(Apply.Recipient.refused)].sum);
    try std.testing.expectEqual(@as(u128, 4 * len), metrics.bytes.sum);
    try std.testing.expectEqual(@as(u64, 0), metrics.spacing.count);
    // Each destination was empty for the first admission and held one frame for the second.
    const queued = &g.delivery_metrics.queued;
    try std.testing.expectEqual(@as(u64, 4), queued.count);
    try std.testing.expectEqual(@as(u64, 2), queued.buckets[0]);
    try std.testing.expectEqual(@as(u64, 2), queued.buckets[1]);
    try std.testing.expectEqual(@as(u64, 2), g.delivery_metrics.oldest_age.count);
    // The next apply starts 20 ms after the first and follows the four frames QUIC took.
    _ = g.report(handles[2], .ignore, .{ .mono_ms = 30, .unix_s = 0 });
    _ = session_io.beginPump(&g, .{ .mono_ms = 31, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 2), metrics.verdicts.count);
    try std.testing.expectEqual(@as(u128, 20), metrics.spacing.sum);
    try std.testing.expectEqual(@as(u128, 4), metrics.service.sum);
    try std.testing.expectEqual(@as(u128, 4), metrics.recipients[@intFromEnum(Apply.Recipient.selected)].sum);
    // A pump without verdicts records no apply.
    _ = session_io.beginPump(&g, .{ .mono_ms = 40, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 2), metrics.verdicts.count);
}

test "occupancy integrates queued frames and full peers by slot phase across idle intervals" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, name, true);
    g.markDirect(g.sessions.rows[peer.index].conn);
    g.sessions.rows[peer.index].io.tx.cancelStream(&g.messages.store);
    // Monotonic zero is the start of a 12 s slot: each phase bucket lasts 750 ms.
    var clock: slots.SlotClock = .{ .genesis_unix_ms = 1_000_000, .slot_duration_ms = 12_000 };
    clock.observe(.{ .mono_ms = 0, .unix_s = 0, .unix_ms = 1_000_000 + 12_000 });
    g.slot_clock = &clock;
    _ = session_io.beginPump(&g, .{ .mono_ms = 100, .unix_s = 0 });
    _ = try g.publish(name, "queued", .{ .mono_ms = 100, .unix_s = 0 });
    const occupancy = &g.occupancy;
    // No change for 700 ms: the queued frame is credited to the buckets the interval crossed.
    _ = session_io.beginPump(&g, .{ .mono_ms = 800, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 700), occupancy.observed_ms[0] + occupancy.observed_ms[1]);
    try std.testing.expectEqual(@as(u64, 650), occupancy.descriptor_ms[0]);
    try std.testing.expectEqual(@as(u64, 50), occupancy.descriptor_ms[1]);
    try std.testing.expectEqual(@as(u64, 0), occupancy.full_ms[1]);
    // Fill the ordinary allowance; the peer counts as full until a frame leaves.
    const h = g.messages.history.message(g.messages.history.get(&g.messages.store, topic_mod.validMessageId(name, "queued", .{})).?);
    const tx = &g.sessions.rows[peer.index].io.tx;
    for (0..@import("delivery.zig").per_peer_limit) |_| {
        if (tx.data.full()) break;
        try std.testing.expectEqual(.queued, tx.queueData(&g.messages.store, h, .forward, .{ .bytes = g.options.tx_peer_bytes }, 800));
    }
    try std.testing.expectEqual(@as(usize, 1), g.sessions.deliveries.full_queues);
    const queued = tx.data.count;
    _ = session_io.beginPump(&g, .{ .mono_ms = 1_600, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 700), occupancy.full_ms[1]);
    try std.testing.expectEqual(@as(u64, 100), occupancy.full_ms[2]);
    try std.testing.expectEqual(@as(u64, 50 + 700 * queued), occupancy.descriptor_ms[1]);
    g.cancelWrites(g.sessions.ref(peer.index));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.deliveries.full_queues);
    // Without a slot clock the time is kept, under an unknown phase.
    g.slot_clock = null;
    _ = session_io.beginPump(&g, .{ .mono_ms = 2_000, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 400), occupancy.observed_ms[slots.phase_buckets]);
    try std.testing.expectEqual(@as(u64, 0), occupancy.descriptor_ms[slots.phase_buckets]);
}

test "IWANT outcomes separate misses, suppression, the retransmission limit, queued and refused responses" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    g.sessions.rows[peer.index].io.tx.cancelStream(&g.messages.store);
    var known: [3]MessageId = undefined;
    for (&known, 0..) |*id, i| {
        var text: [8]u8 = undefined;
        const payload = try std.fmt.bufPrint(&text, "iwant {d}", .{i});
        _ = try g.publish(name, payload, .{ .mono_ms = 1, .unix_s = 0 });
        id.* = topic_mod.validMessageId(name, payload, .{});
    }
    var body: [256]u8 = undefined;
    const now: @import("../types.zig").Now = .{ .mono_ms = 2, .unix_s = 0 };
    support.control(&g, peer.index, .{ .idontwant = .{ .body = ids(&body, 1, &.{known[2]}) } }, now);
    const unknown: MessageId = @splat(9);
    support.control(&g, peer.index, .{ .iwant = .{ .body = ids(&body, 1, &.{ unknown, known[2], known[0], known[0], known[0], known[0] }) } }, now);
    const tx = &g.sessions.rows[peer.index].io.tx;
    const h = g.messages.history.message(g.messages.history.get(&g.messages.store, known[0]).?);
    for (0..@import("delivery.zig").per_peer_limit) |_| {
        if (tx.data.full()) break;
        _ = tx.queueData(&g.messages.store, h, .forward, .{ .bytes = g.options.tx_peer_bytes }, 2);
    }
    support.control(&g, peer.index, .{ .iwant = .{ .body = ids(&body, 1, &.{known[1]}) } }, now);
    const outcomes = g.rpc_metrics.iwant;
    for ([_]IwantOutcome{ .miss, .suppressed, .limited, .queued, .refused }, [_]u64{ 1, 1, 1, 3, 1 }) |outcome, count| {
        try std.testing.expectEqual(count, outcomes[@intFromEnum(outcome)]);
    }
    try std.testing.expectEqual(@as(u64, 1), g.rpc_metrics.iwant_unknown);
    g.cancelWrites(g.sessions.ref(peer.index));
}

test "GRAFT outcomes, PRUNE reasons and mesh peer-time" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const direct = support.addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    g.markDirect(g.sessions.rows[direct.index].conn);
    try support.subscribe(&g, name);
    const now: @import("../types.zig").Now = .{ .mono_ms = 1, .unix_s = 0 };
    support.control(&g, peer.index, .{ .graft = "/eth2/01020304/voluntary_exit/ssz_snappy" }, now);
    support.control(&g, peer.index, .{ .graft = name }, now);
    support.control(&g, peer.index, .{ .graft = name }, now);
    support.control(&g, direct.index, .{ .graft = name }, now);
    const metrics = &g.overlay.metrics;
    for ([_]GraftOutcome{ .unknown_topic, .accepted, .member, .direct, .backoff }, [_]u64{ 1, 1, 1, 1, 0 }) |outcome, count| {
        try std.testing.expectEqual(count, metrics.graft_received[@intFromEnum(outcome)]);
    }
    try std.testing.expectEqual(@as(u64, 1), metrics.prune_sent[@intFromEnum(Removal.direct)]);
    // One mesh member for 700 ms between heartbeat samples.
    metrics.sampleMesh(&g.overlay.rows, 1_000);
    metrics.sampleMesh(&g.overlay.rows, 1_700);
    try std.testing.expectEqual(@as(u64, 700), metrics.peer_ms[@intFromEnum(topic_mod.Kind.beacon_block)]);
    for (g.sessions.rows) |*row| if (row.active) row.io.tx.cancelStream(&g.messages.store);
}
