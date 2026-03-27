//! Tests for MemoryKVStore: CRUD, batch writes, named database isolation.

const std = @import("std");
const MemoryKVStore = @import("memory_kv_store.zig").MemoryKVStore;
const BatchOp = @import("kv_store.zig").BatchOp;
const DatabaseId = @import("buckets.zig").DatabaseId;

test "MemoryKVStore: basic put and get" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("key1", "value1");
    const result = try db.get("key1");
    defer if (result) |r| allocator.free(r);

    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "value1", result.?);
}

test "MemoryKVStore: get missing key returns null" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    const result = try db.get("nonexistent");
    try std.testing.expect(result == null);
}

test "MemoryKVStore: overwrite existing key" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("key1", "first");
    try db.put("key1", "second");

    const result = try db.get("key1");
    defer if (result) |r| allocator.free(r);
    try std.testing.expectEqualSlices(u8, "second", result.?);
    try std.testing.expectEqual(@as(usize, 1), store.countIn(.block));
}

test "MemoryKVStore: delete existing key" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("key1", "value1");
    try db.delete("key1");

    const result = try db.get("key1");
    try std.testing.expect(result == null);
    try std.testing.expectEqual(@as(usize, 0), store.countIn(.block));
}

test "MemoryKVStore: delete missing key is no-op" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.delete("nonexistent");
    try std.testing.expectEqual(@as(usize, 0), store.countIn(.block));
}

test "MemoryKVStore: writeBatch applies all ops" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("a", "old_a");
    try db.put("b", "old_b");

    const ops = [_]BatchOp{
        .{ .put = .{ .db = .block, .key = "a", .value = "new_a" } },
        .{ .put = .{ .db = .block, .key = "c", .value = "new_c" } },
        .{ .delete = .{ .db = .block, .key = "b" } },
    };
    try kv.writeBatch(&ops);

    const a = try db.get("a");
    defer if (a) |r| allocator.free(r);
    try std.testing.expectEqualSlices(u8, "new_a", a.?);

    const b = try db.get("b");
    try std.testing.expect(b == null);

    const c_val = try db.get("c");
    defer if (c_val) |r| allocator.free(r);
    try std.testing.expectEqualSlices(u8, "new_c", c_val.?);

    try std.testing.expectEqual(@as(usize, 2), store.countIn(.block));
}

test "MemoryKVStore: named databases are isolated" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const block_db = kv.getDatabase(.block);
    const state_db = kv.getDatabase(.state_archive);

    try block_db.put("key", "block_value");
    try state_db.put("key", "state_value");

    const bv = try block_db.get("key");
    defer if (bv) |r| allocator.free(r);
    const sv = try state_db.get("key");
    defer if (sv) |r| allocator.free(r);

    try std.testing.expectEqualSlices(u8, "block_value", bv.?);
    try std.testing.expectEqualSlices(u8, "state_value", sv.?);
}

test "MemoryKVStore: allKeys returns all keys in database" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("key_a", "val_a");
    try db.put("key_b", "val_b");

    // Put something in a different database
    const other = kv.getDatabase(.state_archive);
    try other.put("key_c", "val_c");

    const keys = try db.allKeys();
    defer {
        for (keys) |k| allocator.free(k);
        allocator.free(keys);
    }

    try std.testing.expectEqual(@as(usize, 2), keys.len);
}

test "MemoryKVStore: close prevents further operations" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("key", "value");
    kv.close();

    try std.testing.expectError(error.StoreClosed, db.get("key"));
    try std.testing.expectError(error.StoreClosed, db.put("key2", "val"));
    try std.testing.expectError(error.StoreClosed, db.delete("key"));
}

test "MemoryKVStore: binary keys work correctly" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    const key1 = "\x00\x01\x02\xff";
    const key2 = "\x00\x01\x02\xfe";

    try db.put(key1, "val1");
    try db.put(key2, "val2");

    const r1 = try db.get(key1);
    defer if (r1) |r| allocator.free(r);
    const r2 = try db.get(key2);
    defer if (r2) |r| allocator.free(r);

    try std.testing.expectEqualSlices(u8, "val1", r1.?);
    try std.testing.expectEqualSlices(u8, "val2", r2.?);
}

test "MemoryKVStore: empty value" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const db = kv.getDatabase(.block);
    try db.put("key", "");
    const result = try db.get("key");
    defer if (result) |r| allocator.free(r);

    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 0), result.?.len);
}

test "MemoryKVStore: cross-database batch writes" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const ops = [_]BatchOp{
        .{ .put = .{ .db = .block, .key = "root1", .value = "block_data" } },
        .{ .put = .{ .db = .idx_block_root, .key = "root1", .value = "slot_bytes" } },
        .{ .put = .{ .db = .idx_main_chain, .key = "slot1", .value = "root1" } },
    };
    try kv.writeBatch(&ops);

    const block = try kv.getDatabase(.block).get("root1");
    defer if (block) |b| allocator.free(b);
    try std.testing.expectEqualSlices(u8, "block_data", block.?);

    const idx = try kv.getDatabase(.idx_block_root).get("root1");
    defer if (idx) |i| allocator.free(i);
    try std.testing.expectEqualSlices(u8, "slot_bytes", idx.?);
}
