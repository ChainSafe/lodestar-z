//! Tests for MemoryKVStore: CRUD, batch writes, prefix scans, close behavior.

const std = @import("std");
const MemoryKVStore = @import("memory_kv_store.zig").MemoryKVStore;
const BatchOp = @import("kv_store.zig").BatchOp;

test "MemoryKVStore: basic put and get" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("key1", "value1");
    const result = try kv.get("key1");
    defer if (result) |r| allocator.free(r);

    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "value1", result.?);
}

test "MemoryKVStore: get missing key returns null" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    const result = try kv.get("nonexistent");
    try std.testing.expect(result == null);
}

test "MemoryKVStore: overwrite existing key" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("key1", "first");
    try kv.put("key1", "second");

    const result = try kv.get("key1");
    defer if (result) |r| allocator.free(r);
    try std.testing.expectEqualSlices(u8, "second", result.?);
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "MemoryKVStore: delete existing key" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("key1", "value1");
    try kv.delete("key1");

    const result = try kv.get("key1");
    try std.testing.expect(result == null);
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "MemoryKVStore: delete missing key is no-op" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.delete("nonexistent");
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "MemoryKVStore: writeBatch applies all ops atomically" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    // Pre-populate
    try kv.put("a", "old_a");
    try kv.put("b", "old_b");

    const ops = [_]BatchOp{
        .{ .put = .{ .key = "a", .value = "new_a" } },
        .{ .put = .{ .key = "c", .value = "new_c" } },
        .{ .delete = .{ .key = "b" } },
    };
    try kv.writeBatch(&ops);

    const a = try kv.get("a");
    defer if (a) |r| allocator.free(r);
    try std.testing.expectEqualSlices(u8, "new_a", a.?);

    const b = try kv.get("b");
    try std.testing.expect(b == null);

    const c = try kv.get("c");
    defer if (c) |r| allocator.free(r);
    try std.testing.expectEqualSlices(u8, "new_c", c.?);

    try std.testing.expectEqual(@as(usize, 2), store.count());
}

test "MemoryKVStore: keysWithPrefix" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("\x01key_a", "val_a");
    try kv.put("\x01key_b", "val_b");
    try kv.put("\x02key_c", "val_c");

    const keys = try kv.keysWithPrefix("\x01");
    defer {
        for (keys) |k| allocator.free(k);
        allocator.free(keys);
    }

    try std.testing.expectEqual(@as(usize, 2), keys.len);
}

test "MemoryKVStore: entriesWithPrefix" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("\x03data_1", "val_1");
    try kv.put("\x03data_2", "val_2");
    try kv.put("\x04data_3", "val_3");

    const entries = try kv.entriesWithPrefix("\x03");
    defer entries.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), entries.keys.len);
    try std.testing.expectEqual(@as(usize, 2), entries.values.len);
}

test "MemoryKVStore: keysWithPrefix empty prefix matches all" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("a", "1");
    try kv.put("b", "2");

    const keys = try kv.keysWithPrefix("");
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

    try kv.put("key", "value");
    kv.close();

    try std.testing.expectError(error.StoreClosed, kv.get("key"));
    try std.testing.expectError(error.StoreClosed, kv.put("key2", "val"));
    try std.testing.expectError(error.StoreClosed, kv.delete("key"));
}

test "MemoryKVStore: binary keys work correctly" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    // Keys with null bytes and high bytes
    const key1 = "\x00\x01\x02\xff";
    const key2 = "\x00\x01\x02\xfe";

    try kv.put(key1, "val1");
    try kv.put(key2, "val2");

    const r1 = try kv.get(key1);
    defer if (r1) |r| allocator.free(r);
    const r2 = try kv.get(key2);
    defer if (r2) |r| allocator.free(r);

    try std.testing.expectEqualSlices(u8, "val1", r1.?);
    try std.testing.expectEqualSlices(u8, "val2", r2.?);
}

test "MemoryKVStore: empty value" {
    const allocator = std.testing.allocator;
    var store = MemoryKVStore.init(allocator);
    defer store.deinit();
    var kv = store.kvStore();

    try kv.put("key", "");
    const result = try kv.get("key");
    defer if (result) |r| allocator.free(r);

    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 0), result.?.len);
}
