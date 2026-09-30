const Admission = @import("peer_book.zig").Admission;
const Handle = @import("../quic/engine.zig").Handle;
const Metadata = @import("peer_book.zig").Metadata;
const PeerBook = @import("peer_book.zig").PeerBook;
const Ref = @import("peer_book.zig").Ref;
fn allocateBook(a: std.mem.Allocator) !void {
    var book = try PeerBook.init(a, &.{ .retained_score_ms = 10, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer book.deinit(a);
}
const capacity = @import("peer_book.zig").capacity;
const normalize = @import("peer_book.zig").normalize;
const outbound_reserve = @import("peer_book.zig").outbound_reserve;
const std = @import("std");

/// Retained identities still carrying a penalty; an admission that reclaims one lowers it.
fn penalized(peers: *const PeerBook, now: u64) usize {
    var count: usize = 0;
    for (peers.rows) |*row| count += @intFromBool(row.occupied and row.negative and now < row.retain_until);
    return count;
}

test "gossip policy peers retain identity and reserve outbound recovery under negative churn" {
    var peers = try PeerBook.init(std.testing.allocator, &.{ .retained_score_ms = 10_000 });
    defer peers.deinit(std.testing.allocator);
    var metadata: Metadata = .{ .identity = undefined, .address = .unspecified, .direction = .inbound };
    for (0..capacity) |i| {
        metadata.identity.bytes = [_]u8{0} ** @import("../wire/peer_id.zig").length;
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        if (i == capacity - outbound_reserve) {
            metadata.direction = .outbound;
        }
        const result = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, i).admitted;
        peers.scores.penalize(result.peer.index, 7);
        peers.disconnect(result.peer, i);
    }
    metadata.identity.bytes[2] = 1;
    metadata.direction = .inbound;
    const inbound = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, 1000).admitted;
    try std.testing.expectEqual(@as(usize, capacity - 1), penalized(&peers, 1000));
    try std.testing.expect(inbound.peer.index < capacity - outbound_reserve);
    peers.disconnect(inbound.peer, 1000);
    metadata.identity.bytes[2] = 2;
    const pinned: Ref = .{ .index = 0, .generation = peers.rows[0].generation };
    peers.retain(pinned);
    metadata.direction = .outbound;
    const fallback = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, 1000).admitted;
    try std.testing.expectEqual(@as(usize, capacity - 2), penalized(&peers, 1000));
    try std.testing.expectEqual(@as(u16, 1), fallback.peer.index);
    try std.testing.expectEqual(Admission.duplicate, peers.admit(.{ .index = 1, .generation = 1 }, &metadata, 1001));
    peers.scores.penalize(fallback.peer.index, 7);
    peers.disconnect(fallback.peer, 1001);
    const resumed = peers.admit(.{ .index = 2, .generation = 1 }, &metadata, 1002).admitted;
    try std.testing.expect(!resumed.fresh);
    try std.testing.expectEqual(fallback.peer, resumed.peer);
    peers.release(pinned);
}

test "gossip policy IP colocation normalizes ports mapping and current path generation" {
    var peers = try PeerBook.init(std.testing.allocator, &.{ .retained_score_ms = 100 });
    defer peers.deinit(std.testing.allocator);
    const first_conn: Handle = .{ .index = 0, .generation = 1 };
    const first: Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } }, .direction = .inbound };
    var second = first;
    second.identity.bytes[0] = 2;
    second.address = .{ .ip6 = .{ .octets = normalize(first.address), .port = 2 } };
    const a = peers.admit(first_conn, &first, 0).admitted.peer;
    const b = peers.admit(.{ .index = 1, .generation = 1 }, &second, 0).admitted.peer;
    try std.testing.expectEqual(@as(u16, 2), peers.ipCount(a, &.{}));
    try std.testing.expectEqual(@as(u16, 2), peers.ipCount(b, &.{}));
    try std.testing.expectEqual(@as(u16, 0), peers.ipCount(a, &.{normalize(first.address)}));
    try std.testing.expectEqual(Admission.duplicate, peers.admit(.{ .index = 2, .generation = 1 }, &first, 0));
    peers.migrate(.{ .index = 0, .generation = 2 }, .unspecified);
    try std.testing.expectEqual(@as(u16, 2), peers.ipCount(a, &.{}));
    peers.migrate(first_conn, .unspecified);
    try std.testing.expectEqual(@as(u16, 1), peers.ipCount(a, &.{}));
    try std.testing.expectEqual(@as(u16, 1), peers.ipCount(b, &.{}));
}

test "gossip policy identity generation exhaustion cannot revive stale references" {
    var peers = try PeerBook.init(std.testing.allocator, &.{ .retained_score_ms = 100 });
    defer peers.deinit(std.testing.allocator);
    peers.rows[0].generation = std.math.maxInt(u64);
    const metadata: Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
    const first = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, 0).admitted.peer;
    try std.testing.expectEqual(@as(u16, 1), first.index);
    peers.scores.penalize(first.index, 7);
    peers.disconnect(first, 0);
    const next = peers.admit(.{ .index = 0, .generation = 2 }, &metadata, 100).admitted.peer;
    try std.testing.expectEqual(first.index, next.index);
    try std.testing.expectEqual(first.generation + 1, next.generation);
    try std.testing.expect(!peers.matches(first));
}

test "gossip pinned backoff survives identity churn" {
    var peers = try PeerBook.init(std.testing.allocator, &.{ .retained_score_ms = 100_000 });
    defer peers.deinit(std.testing.allocator);
    var metadata: Metadata = .{ .identity = .{ .bytes = [_]u8{0} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
    const connection: Handle = .{ .index = 0, .generation = 1 };
    for (0..capacity - outbound_reserve) |i| {
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        const ref = peers.admit(connection, &metadata, i).admitted.peer;
        if (i == 0) peers.addBackoff(ref, 0, 1, 0, 60_000);
        if (i != 0) peers.scores.penalize(ref.index, 7);
        peers.disconnect(ref, i);
    }
    const original: Ref = .{ .index = 0, .generation = peers.rows[0].generation };
    metadata.identity.bytes[2] = 1;
    peers.retain(original);
    defer peers.release(original);
    const retained = penalized(&peers, 1000);
    const churn = peers.admit(connection, &metadata, 1000).admitted;
    try std.testing.expectEqual(retained - 1, penalized(&peers, 1000));
    try std.testing.expect(churn.peer.index != original.index);
    peers.disconnect(churn.peer, 1000);
    try std.testing.expect(peers.backedOff(original, 0, 1, 1000));
    metadata.identity = peers.rows[0].identity;
    const resumed = peers.admit(connection, &metadata, 1000).admitted;
    try std.testing.expect(!resumed.fresh);
    try std.testing.expectEqual(original, resumed.peer);
    try std.testing.expect(peers.backedOff(original, 0, 1, 1000));
    peers.disconnect(resumed.peer, 1000);
    metadata.direction = .outbound;
    metadata.identity.bytes[2] = 1;
    for (0..outbound_reserve) |i| {
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        const ref = peers.admit(connection, &metadata, 1001 + i).admitted.peer;
        peers.scores.penalize(ref.index, 7);
        peers.disconnect(ref, 1001 + i);
    }
    metadata.identity.bytes[2] = 2;
    const before = penalized(&peers, 1100);
    const fallback = peers.admit(connection, &metadata, 1100).admitted;
    try std.testing.expectEqual(before, penalized(&peers, 1100));
    try std.testing.expect(fallback.peer.index != 0);
    try std.testing.expect(peers.backedOff(original, 0, 1, 1100));
}

test "peer book retains reputation across pinned reconnect and clears it on expiry" {
    var book = try PeerBook.init(std.testing.allocator, &.{ .retained_score_ms = 10, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer book.deinit(std.testing.allocator);
    const metadata: Metadata = .{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound };
    const first = book.admit(.{ .index = 0, .generation = 1 }, &metadata, 0).admitted.peer;
    book.invalid(first, 0);
    book.retain(first);
    book.disconnect(first, 1);
    const score = book.snapshot(first, 1);
    try std.testing.expect(score < 0);
    book.refresh(20);
    try std.testing.expect(book.matches(first));
    const reconnected = book.admit(.{ .index = 0, .generation = 2 }, &metadata, 20).admitted;
    try std.testing.expectEqualDeep(first, reconnected.peer);
    try std.testing.expect(!reconnected.fresh);
    try std.testing.expectEqual(score, book.snapshot(first, 20));
    try std.testing.expect(book.scores.rows[first.index].connected);
    book.release(first);
    book.disconnect(first, 21);
    book.refresh(31);
    try std.testing.expect(!book.matches(first));
    try std.testing.expect(!book.scores.rows[first.index].connected);
    const fresh = book.admit(.{ .index = 0, .generation = 3 }, &metadata, 31).admitted;
    try std.testing.expect(fresh.fresh);
    try std.testing.expect(fresh.peer.generation > first.generation);
    try std.testing.expectEqual(@as(f64, 0), book.score(fresh.peer, 31));
}

test "peer book releases identity and reputation allocations on partial initialization" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocateBook, .{});
}

test "gossip score snapshots follow population migration and identity reuse without policy reads" {
    var book = try PeerBook.init(std.testing.allocator, &.{ .retained_capacity = 2, .retained_outbound_reserve = 0, .retained_score_ms = 10, .score_params = .{ .ip_colocation_weight = -5, .ip_colocation_threshold = 1 } });
    defer book.deinit(std.testing.allocator);
    var metadata: Metadata = .{ .identity = .{ .bytes = @splat(1) }, .address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } }, .direction = .inbound };
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = book.admit(conn, &metadata, 0).admitted.peer;
    try std.testing.expectEqual(@as(f64, 0), book.score(first, 0));
    metadata.identity.bytes[0] = 2;
    const second = book.admit(.{ .index = 1, .generation = 1 }, &metadata, 1).admitted.peer;
    try std.testing.expectEqual(@as(f64, -5), book.snapshot(first, 1));
    try std.testing.expectEqual(@as(f64, -5), book.score(first, 1));
    book.migrate(conn, .{ .ip4 = .{ .octets = .{ 192, 0, 2, 2 }, .port = 1 } });
    try std.testing.expectEqual(@as(f64, 0), book.snapshot(first, 2));
    try std.testing.expectEqual(@as(f64, 0), book.snapshot(second, 2));
    book.disconnect(first, 3);
    metadata.identity.bytes[0] = 3;
    metadata.address = .unspecified;
    const fresh = book.admit(.{ .index = 0, .generation = 2 }, &metadata, 13).admitted.peer;
    try std.testing.expectEqual(first.index, fresh.index);
    try std.testing.expect(fresh.generation > first.generation);
    try std.testing.expectEqual(@as(f64, 0), book.snapshot(fresh, 13));
}

test "gossip reconnect resets positive scores and retains nonpositive evidence without first delivery credit" {
    const topics_cap = @import("constants.zig").topics_cap;
    const TopicCounters = @import("score.zig").TopicCounters;
    for ([_]u8{ 7, 6, 5 }) |credits| {
        var book = try PeerBook.init(std.testing.allocator, &.{
            .retained_capacity = 2,
            .retained_outbound_reserve = 0,
            .retained_score_ms = 100,
            .score_params = .{
                .behaviour_weight = -1,
                .behaviour_threshold = 0,
                .behaviour_decay = 0.5,
                .decay_interval_ms = 10,
                .topic = .{
                    .time_in_mesh_weight = 0,
                    .mesh_delivery_threshold = 2,
                    .mesh_delivery_activation_ms = 0,
                    .mesh_delivery_decay = 0.5,
                    .mesh_failure_decay = 0.5,
                    .invalid_weight = -4,
                    .invalid_decay = 0.5,
                },
            },
        });
        defer book.deinit(std.testing.allocator);
        const metadata: Metadata = .{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound };
        const first = book.admit(.{ .index = 0, .generation = 1 }, &metadata, 0).admitted.peer;
        book.scores.graft(first.index, 0, 0);
        book.scores.creditMesh(first.index, 0);
        book.scores.prune(first.index, 0, 1);
        for (1..credits) |_| book.scores.deliverEligible(first.index, 0, false);
        book.scores.deliverEligible(first.index, topics_cap - 1, false);
        book.invalid(first, 0);
        book.scores.penalize(first.index, 1);
        book.addBackoff(first, 0, 1, 1, 50);
        book.retain(first);
        defer book.release(first);
        try std.testing.expectEqual(@as(f64, @floatFromInt(credits)) - 6, book.score(first, 1));
        const revision = book.scores.revision;
        book.disconnect(first, 2);
        try std.testing.expect(book.scores.revision > revision);
        try std.testing.expect(!book.scores.rows[first.index].connected);
        const expected: f64 = if (credits > 6) 0 else -6;
        try std.testing.expectEqual(expected, book.snapshot(first, 2));
        const base = @as(usize, first.index) * topics_cap;
        const counters: TopicCounters = if (credits > 6) .{} else .{ .mesh_deliveries = 1, .mesh_failures = 1, .invalid = 1 };
        try std.testing.expectEqualDeep(counters, book.scores.topics[base]);
        try std.testing.expectEqualDeep(TopicCounters{}, book.scores.topics[base + topics_cap - 1]);
        try std.testing.expectEqual(@as(f64, if (credits > 6) 0 else 1), book.scores.rows[first.index].behaviour);
        book.refresh(20);
        try std.testing.expectEqual(expected, book.score(first, 20));
        book.scores.deliverEligible(first.index, 0, false);
        book.scores.deliverEligible(first.index, topics_cap - 1, false);
        try std.testing.expectEqual(expected + 2, book.score(first, 20));
        const reconnected = book.admit(.{ .index = 0, .generation = 2 }, &metadata, 20).admitted;
        try std.testing.expectEqual(first, reconnected.peer);
        try std.testing.expect(!reconnected.fresh);
        try std.testing.expect(book.backedOff(first, 0, 1, 20));
        try std.testing.expectEqual(@as(u32, 1), book.rows[first.index].pins);
        try std.testing.expectEqual(expected, book.score(first, 20));
        book.refresh(30);
        try std.testing.expectEqual(@as(f64, if (credits > 6) 0 else -1.75), book.score(first, 30));
    }
}

test "gossip disconnect classifies score before removing IP contribution" {
    var book = try PeerBook.init(std.testing.allocator, &.{
        .retained_capacity = 2,
        .retained_outbound_reserve = 0,
        .score_params = .{ .ip_colocation_weight = -2, .ip_colocation_threshold = 1, .topic = .{ .invalid_weight = -1 } },
    });
    defer book.deinit(std.testing.allocator);
    var metadata: Metadata = .{ .identity = .{ .bytes = @splat(1) }, .address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } }, .direction = .inbound };
    const first = book.admit(.{ .index = 0, .generation = 1 }, &metadata, 0).admitted.peer;
    metadata.identity.bytes[0] = 2;
    _ = book.admit(.{ .index = 1, .generation = 1 }, &metadata, 0).admitted;
    book.scores.deliverEligible(first.index, 0, false);
    book.scores.deliverEligible(first.index, 0, false);
    book.invalid(first, 0);
    try std.testing.expectEqual(@as(f64, -1), book.score(first, 1));
    book.disconnect(first, 1);
    try std.testing.expectEqual(@as(f64, -1), book.score(first, 1));
    metadata.identity.bytes[0] = 1;
    const reconnected = book.admit(.{ .index = 0, .generation = 2 }, &metadata, 2).admitted;
    try std.testing.expectEqual(first, reconnected.peer);
    try std.testing.expectEqual(@as(f64, -3), book.score(first, 2));
}
