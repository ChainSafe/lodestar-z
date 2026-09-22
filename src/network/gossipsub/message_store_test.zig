const Handle = @import("message_store.zig").Handle;
const Store = @import("message_store.zig").Store;
fn allocationProbe(a: std.mem.Allocator) !void {
    var store = try Store.init(a, 8, 8 * page_bytes);
    defer store.deinit(a);
}
const inline_bytes = @import("message_store.zig").inline_bytes;
const page_bytes = @import("message_store.zig").page_bytes;
const std = @import("std");

test "gossip store independent retains pages and stale handles" {
    var store = try Store.init(std.testing.allocator, 1, 3 * page_bytes);
    defer store.deinit(std.testing.allocator);
    const h = store.put([_]u8{1} ** 20, "topic", &([_]u8{9} ** (page_bytes + 1))).?;
    store.retainValidation(h);
    store.retainHistory(h);
    store.seal(h);
    store.retainTx(h);
    store.releaseHistory(h);
    store.releaseValidation(h);
    try std.testing.expectEqual(@as(usize, 1), store.free_pages);
    var c = store.cursor(h);
    try std.testing.expectEqual(page_bytes, store.segment(h, c).len);
    store.advance(&c, page_bytes);
    try std.testing.expectEqualSlices(u8, &.{9}, store.segment(h, c));
    store.releaseTx(h);
    try std.testing.expectEqual(@as(usize, 3), store.free_pages);
    const replacement = store.put([_]u8{2} ** 20, "next", "x").?;
    try std.testing.expect(store.get(h) == null);
    try std.testing.expect(replacement.generation != h.generation);
    store.seal(replacement);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip store small messages use startup inline storage and roll back allocation failures" {
    const a = std.testing.allocator;
    var store = try Store.init(a, 2048, page_bytes);
    defer store.deinit(a);
    for (0..2048) |i| {
        var id = [_]u8{0} ** 20;
        std.mem.writeInt(u64, id[0..8], i, .little);
        const h = store.put(id, "t", &([_]u8{1} ** 200)).?;
        store.retainValidation(h);
        store.seal(h);
    }
    try std.testing.expectEqual(@as(usize, 1), store.free_pages);
    try std.testing.expectEqual(@as(usize, 2048), store.used_entries);
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{});
}

test "gossip retained pages and inline descriptors preserve fresh capacity by kind" {
    const limits_mod = @import("../gossip_limits.zig");
    const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = page_bytes });
    var store = try Store.init(std.testing.allocator, 2 * limits_mod.items(&limits), 2 * limits_mod.bytes(&limits));
    defer store.deinit(std.testing.allocator);
    store.limits = limits;
    const name = "/eth2/01020304/beacon_attestation_0/ssz_snappy";
    var retained: [4]Handle = undefined;
    for (&retained) |*handle| {
        handle.* = store.put(@splat(1), name, "small").?;
        store.retainHistory(handle.*);
        store.seal(handle.*);
        store.retainTx(handle.*);
        store.releaseHistory(handle.*);
    }
    var pending: [4]Handle = undefined;
    for (&pending) |*handle| {
        handle.* = store.put(@splat(2), name, "fresh").?;
        store.retainValidation(handle.*);
        store.seal(handle.*);
        try std.testing.expect(!store.canRetain(handle.*));
    }
    try std.testing.expect(store.put(@splat(3), name, "over") == null);
    const block = store.put(@splat(4), "/eth2/01020304/beacon_block/ssz_snappy", "block").?;
    store.seal(block);
    for (retained) |handle| store.releaseTx(handle);
    for (pending) |handle| store.releaseValidation(handle);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(store.next.len, store.free_pages);
}

test "gossip retained page allowance cannot consume pending or other kind pages" {
    const limits_mod = @import("../gossip_limits.zig");
    const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = page_bytes });
    var store = try Store.init(std.testing.allocator, 2 * limits_mod.items(&limits), 2 * limits_mod.bytes(&limits));
    defer store.deinit(std.testing.allocator);
    store.limits = limits;
    const name = "/eth2/01020304/beacon_attestation_0/ssz_snappy";
    const payload: [inline_bytes + 1]u8 = @splat(9);
    const retained = store.put(@splat(1), name, &payload).?;
    store.retainHistory(retained);
    store.seal(retained);
    store.retainTx(retained);
    store.releaseHistory(retained);
    const pending = store.put(@splat(2), name, &payload).?;
    store.retainValidation(pending);
    store.seal(pending);
    try std.testing.expect(!store.canRetain(pending));
    try std.testing.expect(store.put(@splat(3), name, &payload) == null);
    const block = store.put(@splat(4), "/eth2/01020304/beacon_block/ssz_snappy", &payload).?;
    store.seal(block);
    store.releaseTx(retained);
    try std.testing.expect(store.canRetain(pending));
    store.releaseValidation(pending);
    try std.testing.expectEqual(store.next.len, store.free_pages);
}
