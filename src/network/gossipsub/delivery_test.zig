const Pool = @import("delivery.zig").Pool;
const per_peer_limit = @import("delivery.zig").per_peer_limit;
const Queue = @import("delivery.zig").Queue;
const Receipt = @import("delivery.zig").Receipt;
const Limits = @import("delivery.zig").Limits;
const Origin = @import("delivery.zig").Origin;
const per_peer_reserve = @import("delivery.zig").per_peer_reserve;
const std = @import("std");
const storage = @import("message_store.zig");

test "gossip shared deliveries preserve every peer reserve under global pressure" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 3, Pool.capacity(3, 1));
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    const message = store.put(@splat(1), "topic", "payload").?;
    store.retainHistory(message);
    store.seal(message);
    var queues: [3]Queue = @splat(.{ .pool = &pool });
    for (0..per_peer_limit) |_| try queues[0].append(&store, message, .forward, .{ .bytes = 8192 }, 1);
    try std.testing.expectError(error.Descriptors, queues[0].append(&store, message, .forward, .{ .bytes = 8192 }, 2));
    for (queues[1..]) |*queue| {
        for (0..per_peer_reserve) |_| try queue.append(&store, message, .forward, .{ .bytes = 8192 }, 3);
        try std.testing.expectError(error.PoolFull, queue.append(&store, message, .forward, .{ .bytes = 8192 }, 4));
    }
    try std.testing.expectEqual(@as(usize, 0), pool.available);
    try std.testing.expectEqual(@as(usize, 0), pool.protected);
    queues[1].reset(&store);
    try std.testing.expectError(error.PoolFull, queues[2].append(&store, message, .forward, .{ .bytes = 8192 }, 5));
    for (0..per_peer_reserve) |_| try queues[1].append(&store, message, .forward, .{ .bytes = 8192 }, 6);
    store.releaseHistory(message);
    for (&queues) |*queue| queue.reset(&store);
    try std.testing.expectEqual(@as(usize, 3 * per_peer_reserve), pool.protected);
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip delivery byte refusal acquires no descriptor or payload retain" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 1, Pool.capacity(1, 1));
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    const message = store.put(@splat(1), "topic", "payload").?;
    store.retainHistory(message);
    store.seal(message);
    var queue: Queue = .{ .pool = &pool };
    try std.testing.expectError(error.Bytes, queue.append(&store, message, .forward, .{ .bytes = 6 }, 0));
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(u32, 0), store.get(message).?.tx);
    store.releaseHistory(message);
}

test "gossip delivery resumes a frame cut by a short write and releases a cut frame on reset" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 1, Pool.capacity(1, 1));
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 2, storage.page_bytes);
    defer store.deinit(a);
    const first = store.put(@splat(1), "topic", "first payload").?;
    const second = store.put(@splat(2), "topic", "second").?;
    for ([_]storage.Handle{ first, second }) |h| {
        store.retainHistory(h);
        store.seal(h);
    }
    var queue: Queue = .{ .pool = &pool };
    try queue.append(&store, first, .publication, .{ .bytes = 8192 }, 5);
    try queue.append(&store, second, .iwant, .{ .bytes = 8192 }, 6);
    const frame_len = queue.next(&store).?.segment(&store).len;
    try std.testing.expectEqual(store.get(first).?.frameLen(), frame_len);
    try std.testing.expect(queue.advance(&store, 3) == null);
    try std.testing.expectEqual(first, queue.next(&store).?.message);
    try std.testing.expectEqual(frame_len - 3, queue.next(&store).?.segment(&store).len);
    try std.testing.expectEqual(Receipt{ .origin = .publication }, queue.advance(&store, frame_len - 3).?);
    try std.testing.expectEqual(@as(u32, 0), store.get(first).?.tx);
    try std.testing.expectEqual(second, queue.next(&store).?.message);
    try std.testing.expect(queue.advance(&store, 1) == null);
    queue.reset(&store);
    try std.testing.expectEqual(@as(u32, 0), store.get(second).?.tx);
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(usize, per_peer_reserve), pool.protected);
    for ([_]storage.Handle{ first, second }) |h| store.releaseHistory(h);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip delivery keeps the local reserve from ordinary frames and pressures a full reserve" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 1, Pool.capacity(1, 1));
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    const message = store.put(@splat(1), "topic", "payload").?;
    store.retainHistory(message);
    store.seal(message);
    var queue: Queue = .{ .pool = &pool };
    pool.local_descriptors = 4;
    const descriptors: Limits = .{ .bytes = 1 << 20 };
    for (0..per_peer_limit - 5) |_| try queue.append(&store, message, .forward, descriptors, 1);
    try std.testing.expect(!queue.full());
    try queue.append(&store, message, .forward, descriptors, 1);
    try std.testing.expect(queue.full());
    try std.testing.expectError(error.Descriptors, queue.append(&store, message, .iwant, descriptors, 1));
    for (0..4) |_| try queue.append(&store, message, .publication, descriptors, 2);
    try std.testing.expectError(error.Descriptors, queue.append(&store, message, .publication, descriptors, 3));
    try std.testing.expectEqual(@as(usize, 4), queue.classCount(.local));
    // Sending a local frame frees no ordinary room; sending an ordinary one does.
    try std.testing.expectEqual(Origin.publication, queue.advance(&store, queue.next(&store).?.segment(&store).len).?.origin);
    try std.testing.expect(queue.full());
    queue.current = .ordinary;
    try std.testing.expectEqual(Origin.forward, queue.advance(&store, queue.next(&store).?.segment(&store).len).?.origin);
    try std.testing.expect(!queue.full());
    queue.reset(&store);
    pool.local_descriptors = 0;

    // Seven-byte frames: ordinary ones stop 14 bytes short of the limit, which two local ones fill.
    const bytes: Limits = .{ .bytes = 70, .local_bytes = 14 };
    for (0..8) |_| try queue.append(&store, message, .forward, bytes, 4);
    try std.testing.expectError(error.Bytes, queue.append(&store, message, .forward, bytes, 4));
    for (0..2) |_| try queue.append(&store, message, .publication, bytes, 5);
    try std.testing.expectError(error.Bytes, queue.append(&store, message, .publication, bytes, 5));
    queue.reset(&store);
    // Without ordinary frames, local publications may use all the room.
    for (0..10) |_| try queue.append(&store, message, .publication, bytes, 6);
    try std.testing.expectError(error.Bytes, queue.append(&store, message, .publication, bytes, 6));
    queue.reset(&store);
    try std.testing.expectEqual(pool.slots.len, pool.available);
    store.releaseHistory(message);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip delivery prefers local frames for a bounded run and never interleaves a started frame" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 1, Pool.capacity(1, 1));
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 3, 64 * storage.page_bytes);
    defer store.deinit(a);
    const small = store.put(@splat(1), "topic", "local").?;
    const other = store.put(@splat(2), "topic", "ordinary").?;
    // Larger than the 64 KiB byte run.
    const large = store.put(@splat(3), "topic", &([_]u8{9} ** (70 * 1024))).?;
    for ([_]storage.Handle{ small, other, large }) |h| {
        store.retainHistory(h);
        store.seal(h);
    }
    var queue: Queue = .{ .pool = &pool };
    const limits: Limits = .{ .bytes = 1 << 20 };
    for (0..2) |_| try queue.append(&store, other, .forward, limits, 1);
    try queue.append(&store, other, .iwant, limits, 1);
    for (0..10) |_| try queue.append(&store, small, .publication, limits, 2);
    // Four local frames go ahead of each waiting ordinary frame; the run state lives in the
    // queue, so it spans any number of turns.
    const expected = [_]Origin{ .publication, .publication, .publication, .publication, .forward, .publication, .publication, .publication, .publication, .forward, .publication, .publication, .iwant };
    for (expected, 0..) |origin, i| {
        const segment = queue.next(&store).?.segment(&store);
        // A frame cut by a short write stays chosen even when the other class has frames waiting.
        if (i == 5) {
            try std.testing.expect(queue.advance(&store, 1) == null);
            try queue.append(&store, other, .forward, limits, 3);
            try std.testing.expectEqual(small, queue.next(&store).?.message);
            try std.testing.expectEqual(origin, queue.advance(&store, segment.len - 1).?.origin);
        } else try std.testing.expectEqual(origin, queue.advance(&store, segment.len).?.origin);
    }
    try std.testing.expectEqual(Origin.forward, queue.advance(&store, queue.next(&store).?.segment(&store).len).?.origin);
    try std.testing.expectEqual(@as(usize, 0), queue.count);

    // One local frame at or above the byte run hands the next turn to a waiting ordinary frame.
    try queue.append(&store, large, .publication, limits, 4);
    try queue.append(&store, small, .publication, limits, 4);
    try queue.append(&store, other, .forward, limits, 4);
    for ([_]Origin{ .publication, .forward, .publication }) |origin| {
        for (0..32) |_| {
            const segment = queue.next(&store).?.segment(&store);
            if (queue.advance(&store, segment.len)) |receipt| {
                try std.testing.expectEqual(origin, receipt.origin);
                break;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), queue.count);
    for ([_]storage.Handle{ small, other, large }) |h| store.releaseHistory(h);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip pool protects each peer's first descriptors by the combined count of both classes" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 2, Pool.capacity(2, 1));
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    const message = store.put(@splat(1), "topic", "payload").?;
    store.retainHistory(message);
    store.seal(message);
    var queues: [2]Queue = @splat(.{ .pool = &pool });
    pool.local_descriptors = 8;
    const limits: Limits = .{ .bytes = 1 << 20 };
    for (0..40) |_| try queues[0].append(&store, message, .publication, limits, 1);
    for (0..30) |_| try queues[0].append(&store, message, .forward, limits, 1);
    try std.testing.expectEqual(@as(usize, per_peer_reserve), pool.protected);
    try std.testing.expectEqual(pool.slots.len - 70, pool.available);
    // The first peer takes every unprotected descriptor; the second still gets its protected
    // share across both classes, and no more.
    for (70..per_peer_limit) |_| try queues[0].append(&store, message, .publication, limits, 2);
    for (0..per_peer_reserve / 2) |_| try queues[1].append(&store, message, .publication, limits, 3);
    for (0..per_peer_reserve / 2) |_| try queues[1].append(&store, message, .forward, limits, 3);
    try std.testing.expectEqual(@as(usize, 0), pool.available);
    try std.testing.expectError(error.PoolFull, queues[1].append(&store, message, .publication, limits, 4));
    try std.testing.expectError(error.PoolFull, queues[1].append(&store, message, .forward, limits, 4));
    // Draining in class order returns every descriptor and protected unit.
    for (&queues) |*queue| {
        for (0..per_peer_limit) |_| {
            const segment = (queue.next(&store) orelse break).segment(&store);
            _ = queue.advance(&store, segment.len).?;
        }
        try std.testing.expectEqual(@as(usize, 0), queue.count);
    }
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(usize, 2 * per_peer_reserve), pool.protected);
    store.releaseHistory(message);
}
