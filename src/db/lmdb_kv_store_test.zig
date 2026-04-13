//! Tests for LmdbKVStore: LMDB-backed KVStore with named database support.

const std = @import("std");
const testing = std.testing;
const KVStore = @import("kv_store.zig").KVStore;
const BatchOp = @import("kv_store.zig").BatchOp;
const LmdbKVStore = @import("lmdb_kv_store.zig").LmdbKVStore;
const DatabaseId = @import("buckets.zig").DatabaseId;

fn openTestStore() !struct { store: *LmdbKVStore, path: [:0]u8 } {
    const tmp_dir = testing.tmpDir(.{});
    const path = try tmp_dir.dir.realPathFileAlloc(testing.io, ".", testing.allocator);

    const store = try testing.allocator.create(LmdbKVStore);
    store.* = try LmdbKVStore.open(testing.allocator, testing.io, path, .{ .map_size = 10 * 1024 * 1024 });
    return .{ .store = store, .path = path };
}

fn cleanupTestStore(store: *LmdbKVStore, path: [:0]u8) void {
    store.deinit();
    testing.allocator.destroy(store);
    testing.allocator.free(path);
}

test "LmdbKVStore: put and get in named database" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    try db.put("key1", "value1");

    const val = try db.get("key1");
    try testing.expect(val != null);
    try testing.expectEqualStrings("value1", val.?);
    testing.allocator.free(val.?);
}

test "LmdbKVStore: named databases are isolated" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const block_db = kv.getDatabase(.block);
    const state_db = kv.getDatabase(.state_archive);

    try block_db.put("key", "block_val");
    try state_db.put("key", "state_val");

    const bv = try block_db.get("key");
    try testing.expectEqualStrings("block_val", bv.?);
    testing.allocator.free(bv.?);

    const sv = try state_db.get("key");
    try testing.expectEqualStrings("state_val", sv.?);
    testing.allocator.free(sv.?);
}

test "LmdbKVStore: get nonexistent returns null" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    const val = try db.get("nonexistent");
    try testing.expect(val == null);
}

test "LmdbKVStore: delete" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    try db.put("key1", "value1");
    try db.delete("key1");

    const val = try db.get("key1");
    try testing.expect(val == null);
}

test "LmdbKVStore: delete nonexistent is no-op" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    try db.delete("nonexistent");
}

test "LmdbKVStore: overwrite value" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    try db.put("key", "v1");
    try db.put("key", "v2");

    const val = try db.get("key");
    try testing.expectEqualStrings("v2", val.?);
    testing.allocator.free(val.?);
}

test "LmdbKVStore: writeBatch atomic across databases" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const block_db = kv.getDatabase(.block);
    try block_db.put("del_me", "gone");

    const ops = [_]BatchOp{
        .{ .put = .{ .db = .block, .key = "batch1", .value = "b1" } },
        .{ .put = .{ .db = .state_archive, .key = "batch2", .value = "b2" } },
        .{ .delete = .{ .db = .block, .key = "del_me" } },
    };
    try kv.writeBatch(&ops);

    const v1 = try block_db.get("batch1");
    try testing.expectEqualStrings("b1", v1.?);
    testing.allocator.free(v1.?);

    const v2 = try kv.getDatabase(.state_archive).get("batch2");
    try testing.expectEqualStrings("b2", v2.?);
    testing.allocator.free(v2.?);

    const vd = try block_db.get("del_me");
    try testing.expect(vd == null);
}

test "LmdbKVStore: allKeys" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    try db.put("a", "v1");
    try db.put("b", "v2");
    try db.put("c", "v3");

    // Different database — should not appear
    try kv.getDatabase(.state_archive).put("x", "v4");

    const keys = try db.allKeys();
    defer {
        for (keys) |k| testing.allocator.free(k);
        testing.allocator.free(keys);
    }

    try testing.expectEqual(@as(usize, 3), keys.len);
}

test "LmdbKVStore: allEntries" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);
    try db.put("a", "v1");
    try db.put("b", "v2");

    try kv.getDatabase(.state_archive).put("x", "v3");

    const entries = try db.allEntries();
    defer entries.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), entries.keys.len);
    try testing.expectEqual(@as(usize, 2), entries.values.len);
}

test "LmdbKVStore: close then operations fail" {
    var result = try openTestStore();
    defer {
        testing.allocator.destroy(result.store);
        testing.allocator.free(result.path);
    }

    const kv = result.store.kvStore();
    kv.close();

    const db = kv.getDatabase(.block);
    const get_result = db.get("key");
    try testing.expectError(error.StoreClosed, get_result);
}

test "LmdbKVStore: persistence across reopen" {
    const tmp_dir = testing.tmpDir(.{});
    const z_path = try tmp_dir.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(z_path);

    // Write phase
    {
        var store = try LmdbKVStore.open(testing.allocator, testing.io, z_path, .{ .map_size = 10 * 1024 * 1024 });
        const kv = store.kvStore();
        try kv.getDatabase(.block).put("persist_key", "persist_value");
        kv.close();
    }

    // Read phase — reopen same path
    {
        var store = try LmdbKVStore.open(testing.allocator, testing.io, z_path, .{ .map_size = 10 * 1024 * 1024 });
        defer store.deinit();
        const kv = store.kvStore();

        const val = try kv.getDatabase(.block).get("persist_key");
        try testing.expect(val != null);
        try testing.expectEqualStrings("persist_value", val.?);
        testing.allocator.free(val.?);
    }
}

test "LmdbKVStore: large values" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.state_archive);

    const large = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(large);
    @memset(large, 0xAB);

    try db.put("large_key", large);

    const val = try db.get("large_key");
    try testing.expect(val != null);
    try testing.expectEqual(large.len, val.?.len);
    try testing.expect(std.mem.eql(u8, large, val.?));
    testing.allocator.free(val.?);
}

test "LmdbKVStore: many keys" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const db = kv.getDatabase(.block);

    var buf: [16]u8 = undefined;
    for (0..1000) |i| {
        const key_str = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
        try db.put(key_str, "val");
    }

    const v = try db.get("500");
    try testing.expect(v != null);
    try testing.expectEqualStrings("val", v.?);
    testing.allocator.free(v.?);
}
