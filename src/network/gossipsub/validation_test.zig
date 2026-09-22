const Outcome = @import("validation.zig").Outcome;
const PeerRef = @import("validation.zig").PeerRef;
const Peers = @import("peer_book.zig").PeerBook;
const Validation = @import("validation.zig").Validation;
const Verdict = @import("validation.zig").Verdict;
const std = @import("std");
const storage = @import("message_store.zig");
const topic_mod = @import("topic.zig");

test "gossip validation expires without pump and resolves exactly once" {
    var peers = try Peers.init(std.testing.allocator, &.{ .retained_score_ms = 100 });
    defer peers.deinit(std.testing.allocator);
    peers.rows[0] = .{ .occupied = true, .generation = 1 };
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var v = try Validation.init(std.testing.allocator, 1, 10, 20);
    defer v.deinit(std.testing.allocator, &store, &peers);
    const m = store.put([_]u8{1} ** 20, "t", "body").?;
    var h_reservation = v.reserve(store.get(m).?.id).?;
    const h = h_reservation.commit(&store, &peers, m, .{ .index = 0, .generation = 1 }, .{ .index = 0, .generation = 1 }, 100);
    store.seal(m);
    try std.testing.expect(v.inspect(&store, &peers, h, 109) == null);
    try std.testing.expectEqual(Outcome.expired, v.inspect(&store, &peers, h, 110).?);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(Outcome.stale_handle, v.inspect(&store, &peers, h, 130).?);
    const m2 = store.put([_]u8{2} ** 20, "t", "body").?;
    peers.rows[0].generation = 2;
    var h2_reservation = v.reserve(store.get(m2).?.id).?;
    const h2 = h2_reservation.commit(&store, &peers, m2, .{ .index = 0, .generation = 2 }, .{ .index = 0, .generation = 1 }, 130);
    store.seal(m2);
    try std.testing.expectEqual(Outcome.stale_handle, v.inspect(&store, &peers, h, 130).?);
    v.finish(&store, h2, .ignore, 131);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, h2, 132).?);
}

test "gossip validation readmission skips exhausted generation without hiding pending ID" {
    var peers = try Peers.init(std.testing.allocator, &.{ .retained_score_ms = 100 });
    defer peers.deinit(std.testing.allocator);
    peers.rows[0] = .{ .occupied = true, .generation = 1 };
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var v = try Validation.init(std.testing.allocator, 2, 10, 20);
    defer v.deinit(std.testing.allocator, &store, &peers);
    v.entries[0].generation = std.math.maxInt(u64) - 1;
    const id = [_]u8{1} ** 20;
    const source: PeerRef = .{ .index = 0, .generation = 1 };
    const first = store.put(id, "t", "body").?;
    var old_reservation = v.reserve(store.get(first).?.id).?;
    const old = old_reservation.commit(&store, &peers, first, source, .{ .index = 0, .generation = 1 }, 100);
    store.seal(first);
    v.finish(&store, old, .ignore, 101);
    const second = store.put(id, "t", "body").?;
    var current_reservation = v.reserve(store.get(second).?.id).?;
    const current = current_reservation.commit(&store, &peers, second, source, .{ .index = 0, .generation = 1 }, 102);
    store.seal(second);
    try std.testing.expectEqual(std.math.maxInt(u64), old.generation);
    try std.testing.expectEqual(@as(u64, 1), current.generation);
    try std.testing.expect(old.index != current.index);
    try std.testing.expectEqual(v.attribution(current), v.find(id, 103).?);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, old, 103).?);
    try std.testing.expectEqual(@as(usize, 1), store.used_entries);
    v.finish(&store, current, .reject, 104);
    try std.testing.expectEqual(Verdict.reject, v.find(id, 105).?.verdict);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, old, 105).?);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(store.next.len, store.free_pages);
}

test "gossip validation reservation rollback preserves attribution and prior outcome" {
    const a = std.testing.allocator;
    var peers = try Peers.init(a, &.{ .retained_score_ms = 100, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(a);
    peers.rows[0] = .{ .occupied = true, .generation = 1 };
    const source: PeerRef = .{ .index = 0, .generation = 1 };
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    var v = try Validation.init(a, 1, 10, 20);
    defer v.deinit(a, &store, &peers);
    const id = [_]u8{1} ** 20;
    const message = store.put(id, "topic", "payload").?;
    var handle_reservation = v.reserve(store.get(message).?.id).?;
    const handle = handle_reservation.commit(&store, &peers, message, source, .{ .index = 0, .generation = 1 }, 0);
    store.seal(message);
    v.finish(&store, handle, .reject, 1);
    const indexed = v.index.find(id).?;
    var reservation = v.reserve(id).?;
    try std.testing.expectEqual(indexed, v.index.find(id).?);
    try std.testing.expectEqual(Verdict.reject, v.find(id, 2).?.verdict);
    try std.testing.expect(!v.available());
    try std.testing.expect(v.reserve(@splat(2)) == null);
    reservation.cancel();
    reservation.cancel();
    try std.testing.expect(v.available());
    try std.testing.expectEqual(indexed, v.index.find(id).?);
    try std.testing.expectEqual(Verdict.reject, v.find(id, 2).?.verdict);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, handle, 2).?);
    try std.testing.expectEqual(@as(u64, 0), v.delivery_evictions);
    try std.testing.expectEqual(@as(u32, 1), peers.rows[0].pins);
}

test "gossip validation destruction releases pending payloads and resolved attribution pins" {
    const a = std.testing.allocator;
    var peers = try Peers.init(a, &.{ .retained_score_ms = 100, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(a);
    const source = peers.admit(.{ .index = 0, .generation = 1 }, &.{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound }, 0).admitted.peer;
    var store = try storage.Store.init(a, 2, 8192);
    defer store.deinit(a);
    {
        var v = try Validation.init(a, 2, 10, 20);
        defer v.deinit(a, &store, &peers);
        for (0..2) |i| {
            const message = store.put(@splat(@intCast(i)), "topic", "payload").?;
            var handle_reservation = v.reserve(store.get(message).?.id).?;
            const handle = handle_reservation.commit(&store, &peers, message, source, .{ .index = 0, .generation = 1 }, 0);
            store.seal(message);
            if (i == 0) v.finish(&store, handle, .accept, 1);
        }
        try std.testing.expectEqual(@as(u32, 2), peers.rows[source.index].pins);
        try std.testing.expectEqual(@as(usize, 1), store.used_entries);
    }
    try std.testing.expectEqual(@as(u32, 0), peers.rows[source.index].pins);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(store.next.len, store.free_pages);
}

test "gossip validation index bounds sparse lookups and follows replacement expiry and clear" {
    const a = std.testing.allocator;
    var peers = try Peers.init(a, &.{ .retained_score_ms = 100, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(a);
    peers.rows[0] = .{ .occupied = true, .generation = 1 };
    const source: PeerRef = .{ .index = 0, .generation = 1 };
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    var v = try Validation.init(a, 8192, 10, 20);
    defer v.deinit(a, &store, &peers);
    try std.testing.expectEqual(@as(usize, 32768), v.recent.len);
    try std.testing.expectEqual(@as(usize, 0), v.index.probe_limit);
    const first: topic_mod.MessageId = @splat(0);
    var second = first;
    second[19] = 1;
    for ([_]topic_mod.MessageId{ first, second }) |id| {
        const message = store.put(id, "topic", "payload").?;
        var reservation = v.reserve(id).?;
        try std.testing.expect(v.index.find(id) == null);
        const handle = reservation.commit(&store, &peers, message, source, .{ .index = 0, .generation = 1 }, 0);
        store.seal(message);
        v.finish(&store, handle, .reject, 1);
        try std.testing.expectEqual(@as(usize, 1), v.index.probe_limit);
        try std.testing.expectEqual(Verdict.reject, v.find(id, 2).?.verdict);
    }
    try std.testing.expect(v.find(first, 2) != null);
    try std.testing.expectEqual(@as(u64, 0), v.delivery_evictions);
    try std.testing.expect(v.find(second, 21) == null);
    try std.testing.expect(v.index.find(second) != null);
    var retry = v.reserve(second).?;
    retry.cancel();
    try std.testing.expect(v.index.find(second) != null);
    v.expire(&store, &peers, 21);
    try std.testing.expect(v.index.find(second) == null);
    try std.testing.expectEqual(@as(u32, 0), peers.rows[0].pins);
    for (0..2) |i| {
        const message = store.put(first, "topic", "payload").?;
        var reservation = v.reserve(first).?;
        const handle = reservation.commit(&store, &peers, message, source, .{ .index = 0, .generation = 1 }, 30);
        store.seal(message);
        try std.testing.expectEqual(handle, v.find(first, 30).?.handle);
        if (i == 0) {
            v.expire(&store, &peers, 40);
            try std.testing.expect(v.index.find(first) == null);
        } else v.clear(&store, &peers);
    }
    try std.testing.expectEqual(@as(usize, 0), v.index.probe_limit);
    try std.testing.expect(v.find(first, 40) == null);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(@as(u32, 0), peers.rows[0].pins);
}
