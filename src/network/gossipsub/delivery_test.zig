const Pool = @import("delivery.zig").Pool;
const per_peer_limit = @import("delivery.zig").per_peer_limit;
const Queue = @import("delivery.zig").Queue;
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
    for (0..per_peer_limit) |_| try queues[0].append(&store, message, 8192, 1);
    try std.testing.expectError(error.Descriptors, queues[0].append(&store, message, 8192, 2));
    for (queues[1..]) |*queue| {
        for (0..per_peer_reserve) |_| try queue.append(&store, message, 8192, 3);
        try std.testing.expectError(error.PoolFull, queue.append(&store, message, 8192, 4));
    }
    try std.testing.expectEqual(@as(usize, 0), pool.available);
    try std.testing.expectEqual(@as(usize, 0), pool.protected);
    queues[1].reset(&store);
    try std.testing.expectError(error.PoolFull, queues[2].append(&store, message, 8192, 5));
    for (0..per_peer_reserve) |_| try queues[1].append(&store, message, 8192, 6);
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
    try std.testing.expectError(error.Bytes, queue.append(&store, message, 6, 0));
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(u32, 0), store.get(message).?.tx);
    store.releaseHistory(message);
}
