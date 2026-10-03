const Now = @import("../types.zig").Now;
const support = @import("test_support.zig");
const std = @import("std");
const Gossipsub = @import("Gossipsub.zig");
const topic_mod = @import("topic.zig");
const constants = @import("constants.zig");
const receiveForTest = support.receiveMessage;
const testMessage = support.message;
const storage = @import("message_store.zig");

fn requestOne(g: *Gossipsub, peer: u16, id: *const @import("topic.zig").MessageId) void {
    var body: [32]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&body);
    writer.bytesField(1, id);
    support.control(g, peer, .{ .iwant = .{ .body = writer.written() } }, Now.fromMilliseconds(.{ .mono_ms = g.last_now_ms, .unix_s = 0 }));
}

test "gossipsub duplicate invalid bytes do not evict useful history" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    _ = try g.publish(topic, "useful", Now.fromMilliseconds(.{ .mono_ms = 1, .unix_s = 1 }));
    const useful = topic_mod.validMessageId(topic, "useful", .{});
    const retained = g.messages.history.message(g.messages.history.get(&g.messages.store, useful).?);
    for (0..20) |_| {
        try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "useful", 2));
        _ = receiveForTest(&g, peer.index, .{ .topic = topic, .data = &.{ 5, 0 } }, Now.fromMilliseconds(.{ .mono_ms = 2, .unix_s = 1 }));
        try std.testing.expectEqual(retained, g.messages.history.message(g.messages.history.get(&g.messages.store, useful).?));
    }
}

test "gossip history covers the processor retention allowance and the memory plan accounts for it" {
    const limits: @import("../gossip_limits.zig").Limits = @splat(.{ .items = 4, .bytes = 4096 });
    const total = @import("../gossip_limits.zig").items(&limits);
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(topic_mod.Kind.beacon_block)] = .{ .count = 1, .ssz_max = 1024 };
    for ([_]usize{ 16, total + 1 }, [_]usize{ total, total + 1 }) |floor, expected| {
        var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var g = try support.init(ledger.allocator(), .{ .random_seed = 1, .topic_policy = &.{boundary}, .mcache_capacity = floor, .validation_capacity = total, .payload_limits = limits });
        try std.testing.expectEqual(expected, g.messages.history.entries.len);
        try std.testing.expectEqual(expected + total, g.messages.store.entries.len);
        try std.testing.expectEqual(ledger.bytes, g.memoryPlan().total_bytes - @sizeOf(Gossipsub));
        g.deinit();
    }
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 16, .validation_capacity = total });
    defer g.deinit();
    try std.testing.expectEqual(@as(usize, 16), g.messages.history.entries.len);
}

test "gossip history at capacity serves IWANT until each message's sixth heartbeat boundary" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 2 * constants.mcache_len });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const history = &g.messages.history;
    var ids: [constants.mcache_len][2]@import("topic.zig").MessageId = undefined;
    for (&ids, 0..) |*window, epoch| {
        if (epoch > 0) support.ageHistory(&g);
        for (window, 0..) |*id, i| {
            var payload: [2]u8 = .{ @intCast(epoch), @intCast(i) };
            _ = try g.publish(name, &payload, Now.fromMilliseconds(.{ .mono_ms = 1 + epoch, .unix_s = 0 }));
            id.* = topic_mod.validMessageId(name, &payload, .{});
        }
    }
    try std.testing.expectEqual(history.entries.len, history.count);
    // A full history evicts its oldest message while that message still has a window left.
    _ = try g.publish(name, "one more", Now.fromMilliseconds(.{ .mono_ms = 10, .unix_s = 0 }));
    try std.testing.expectEqual(history.entries.len, history.count);
    try std.testing.expect(history.get(&g.messages.store, ids[0][0]) == null);
    const misses = &g.iwant_outcomes[@intFromEnum(@import("metrics.zig").IwantOutcome.miss)];
    const unknown = misses.*;
    requestOne(&g, peer.index, &ids[0][0]);
    try std.testing.expectEqual(unknown + 1, misses.*);
    requestOne(&g, peer.index, &ids[0][1]);
    try std.testing.expectEqual(unknown + 1, misses.*);
    // Each heartbeat boundary retires exactly the window that reached six; the next stays servable.
    for (1..constants.mcache_len) |window| {
        support.ageHistory(&g);
        try std.testing.expect(history.get(&g.messages.store, ids[window - 1][1]) == null);
        requestOne(&g, peer.index, &ids[window - 1][1]);
        try std.testing.expectEqual(unknown + window + 1, misses.*);
        requestOne(&g, peer.index, &ids[window][0]);
        requestOne(&g, peer.index, &ids[window][1]);
        try std.testing.expectEqual(unknown + window + 1, misses.*);
    }
    g.cancelWrites(g.sessions.ref(peer.index));
}

test "gossip retention makes room from its own kind's oldest copy and refuses when queues hold it" {
    const limits: @import("../gossip_limits.zig").Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(topic_mod.Kind.beacon_block)] = .{ .count = 1, .ssz_max = 1024 };
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &.{boundary}, .validation_capacity = @import("../gossip_limits.zig").items(&limits), .payload_limits = limits });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const kind = @intFromEnum(topic_mod.Kind.beacon_block);
    for (0..4) |i| _ = try g.publish(name, &[_]u8{@intCast(i)}, Now.fromMilliseconds(.{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectEqual(@as(usize, 4), g.messages.store.retained_entries_by_kind[kind]);
    _ = try g.publish(name, "fifth", Now.fromMilliseconds(.{ .mono_ms = 2, .unix_s = 0 }));
    try std.testing.expect(g.messages.history.get(&g.messages.store, topic_mod.validMessageId(name, &[_]u8{0}, .{})) == null);
    try std.testing.expectEqual(@as(usize, 4), g.messages.history.count);
    // Copies queued to a peer stay retained, so a full allowance refuses the next message.
    var slot = g.messages.history.head;
    for (0..g.messages.history.count) |_| {
        try std.testing.expectEqual(.queued, g.sessions.rows[peer.index].io.tx.queueData(&g.messages.store, g.messages.history.message(slot), .forward, .{ .bytes = g.options.tx_peer_bytes }, 2));
        slot = g.messages.history.entries[slot].next;
    }
    try std.testing.expectError(error.ResourceExhausted, g.publish(name, "sixth", Now.fromMilliseconds(.{ .mono_ms = 3, .unix_s = 0 })));
    try std.testing.expectEqual(@as(u64, 1), g.messages.retention_refusals[kind]);
    try std.testing.expectEqual(@as(usize, 4), g.messages.history.count);
    g.cancelWrites(g.sessions.ref(peer.index));
}

test "gossip refused retention leaves the history unchanged" {
    const limits_mod = @import("../gossip_limits.zig");
    const block = topic_mod.Kind.beacon_block;
    const exit = topic_mod.Kind.voluntary_exit;
    var limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = storage.page_bytes });
    limits[@intFromEnum(block)].bytes = 2 * storage.page_bytes;
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(block)] = .{ .count = 1, .ssz_max = 6000 };
    boundary.rules[@intFromEnum(exit)] = .{ .count = 1, .ssz_max = 3000 };
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &.{boundary}, .validation_capacity = limits_mod.items(&limits), .payload_limits = limits });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const history = &g.messages.history;
    var random = std.Random.DefaultPrng.init(3);
    var payloads: [3][5000]u8 = undefined;
    for (&payloads) |*payload| random.random().bytes(payload);
    const cases = [_]struct { name: []const u8, kept: [3][]const u8, queued: usize, refused: []const u8 }{
        // Two one-page blocks fill the two-page allowance; the queued one cannot be reclaimed,
        // so a two-page block must not evict the other.
        .{ .name = "/eth2/01020304/beacon_block/ssz_snappy", .kept = .{ payloads[0][0..1000], payloads[1][0..1000], "" }, .queued = 1, .refused = &payloads[2] },
        // A queued one-page exit fills the one-page allowance; inline exits free no page.
        .{ .name = "/eth2/01020304/voluntary_exit/ssz_snappy", .kept = .{ "inline one", "inline two", payloads[0][1000..2000] }, .queued = 2, .refused = payloads[1][1000..2000] },
    };
    for (cases) |case| {
        var handles: [3]storage.Handle = undefined;
        var kept: usize = 0;
        for (case.kept) |payload| {
            if (payload.len == 0) continue;
            _ = try g.publish(case.name, payload, Now.fromMilliseconds(.{ .mono_ms = 1, .unix_s = 0 }));
            handles[kept] = history.message(history.get(&g.messages.store, topic_mod.validMessageId(case.name, payload, .{})).?);
            kept += 1;
        }
        try std.testing.expectEqual(.queued, g.sessions.rows[peer.index].io.tx.queueData(&g.messages.store, handles[case.queued], .forward, .{ .bytes = g.options.tx_peer_bytes }, 1));
        const count = history.count;
        try std.testing.expectError(error.ResourceExhausted, g.publish(case.name, case.refused, Now.fromMilliseconds(.{ .mono_ms = 2, .unix_s = 0 })));
        try std.testing.expectEqual(count, history.count);
        for (handles[0..kept]) |h| try std.testing.expect(history.get(&g.messages.store, g.messages.store.get(h).?.id) != null);
    }
    try std.testing.expectEqual(@as(u64, 1), g.messages.retention_refusals[@intFromEnum(block)]);
    try std.testing.expectEqual(@as(u64, 1), g.messages.retention_refusals[@intFromEnum(exit)]);
    g.cancelWrites(g.sessions.ref(peer.index));
}
