//! Tests for LmdbKVStore: LMDB-backed KVStore implementation.
//!
//! Covers the full KVStore interface exercised through the vtable,
//! plus LMDB-specific behaviors like persistence across reopen and
//! large value handling (beacon states can be 100 MB+).

const std = @import("std");
const testing = std.testing;
const KVStore = @import("kv_store.zig").KVStore;
const BatchOp = @import("kv_store.zig").BatchOp;
const LmdbKVStore = @import("lmdb_kv_store.zig").LmdbKVStore;

/// Helper: open an LmdbKVStore in a temporary directory.
fn openTestStore() !struct { store: *LmdbKVStore, path: [:0]u8 } {
    const tmp_dir = testing.tmpDir(.{});
    const path = try tmp_dir.dir.realPathFileAlloc(testing.io, ".", testing.allocator);

    const store = try testing.allocator.create(LmdbKVStore);
    store.* = try LmdbKVStore.open(testing.allocator, path, .{ .map_size = 10 * 1024 * 1024 }); // 10 MB
    return .{ .store = store, .path = path };
}

fn cleanupTestStore(store: *LmdbKVStore, path: [:0]u8) void {
    store.deinit();
    testing.allocator.destroy(store);
    testing.allocator.free(path);
}

// -- KVStore vtable tests --

test "LmdbKVStore: put and get through vtable" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    try kv.put("key1", "value1");

    const val = try kv.get("key1");
    try testing.expect(val != null);
    try testing.expectEqualStrings("value1", val.?);
    testing.allocator.free(val.?);
}

test "LmdbKVStore: get nonexistent returns null" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    const val = try kv.get("nonexistent");
    try testing.expect(val == null);
}

test "LmdbKVStore: delete" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    try kv.put("key1", "value1");
    try kv.delete("key1");

    const val = try kv.get("key1");
    try testing.expect(val == null);
}

test "LmdbKVStore: delete nonexistent is no-op" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    try kv.delete("nonexistent"); // should not error
}

test "LmdbKVStore: overwrite value" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    try kv.put("key", "v1");
    try kv.put("key", "v2");

    const val = try kv.get("key");
    try testing.expectEqualStrings("v2", val.?);
    testing.allocator.free(val.?);
}

test "LmdbKVStore: writeBatch atomic" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();

    // Pre-populate a key that will be deleted in the batch
    try kv.put("del_me", "gone");

    const ops = [_]BatchOp{
        .{ .put = .{ .key = "batch1", .value = "b1" } },
        .{ .put = .{ .key = "batch2", .value = "b2" } },
        .{ .delete = .{ .key = "del_me" } },
    };
    try kv.writeBatch(&ops);

    const v1 = try kv.get("batch1");
    try testing.expectEqualStrings("b1", v1.?);
    testing.allocator.free(v1.?);

    const v2 = try kv.get("batch2");
    try testing.expectEqualStrings("b2", v2.?);
    testing.allocator.free(v2.?);

    const vd = try kv.get("del_me");
    try testing.expect(vd == null);
}

test "LmdbKVStore: keysWithPrefix" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    try kv.put(&[_]u8{ 0x01, 'a' }, "v1");
    try kv.put(&[_]u8{ 0x01, 'b' }, "v2");
    try kv.put(&[_]u8{ 0x01, 'c' }, "v3");
    try kv.put(&[_]u8{ 0x02, 'x' }, "v4");

    const keys = try kv.keysWithPrefix(&[_]u8{0x01});
    defer {
        for (keys) |k| testing.allocator.free(k);
        testing.allocator.free(keys);
    }

    try testing.expectEqual(@as(usize, 3), keys.len);
}

test "LmdbKVStore: entriesWithPrefix" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();
    try kv.put(&[_]u8{ 0x01, 'a' }, "v1");
    try kv.put(&[_]u8{ 0x01, 'b' }, "v2");
    try kv.put(&[_]u8{ 0x02, 'x' }, "v3");

    const entries = try kv.entriesWithPrefix(&[_]u8{0x01});
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

    // Operations after close should fail
    const get_result = kv.get("key");
    try testing.expectError(error.StoreClosed, get_result);
}

test "LmdbKVStore: persistence across reopen" {
    const tmp_dir = testing.tmpDir(.{});
    const z_path = try tmp_dir.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(z_path);

    // Write phase
    {
        var store = try LmdbKVStore.open(testing.allocator, z_path, .{ .map_size = 10 * 1024 * 1024 });
        const kv = store.kvStore();
        try kv.put("persist_key", "persist_value");
        kv.close();
    }

    // Read phase — reopen same path
    {
        var store = try LmdbKVStore.open(testing.allocator, z_path, .{ .map_size = 10 * 1024 * 1024 });
        defer store.deinit();
        const kv = store.kvStore();

        const val = try kv.get("persist_key");
        try testing.expect(val != null);
        try testing.expectEqualStrings("persist_value", val.?);
        testing.allocator.free(val.?);
    }
}

test "LmdbKVStore: large values" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();

    // 1 MB value (beacon states can be 100 MB+, but 1 MB is enough to test)
    const large = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(large);
    @memset(large, 0xAB);

    try kv.put("large_key", large);

    const val = try kv.get("large_key");
    try testing.expect(val != null);
    try testing.expectEqual(large.len, val.?.len);
    try testing.expect(std.mem.eql(u8, large, val.?));
    testing.allocator.free(val.?);
}

test "LmdbKVStore: many keys" {
    var result = try openTestStore();
    defer cleanupTestStore(result.store, result.path);

    const kv = result.store.kvStore();

    // Write 1000 keys
    var buf: [16]u8 = undefined;
    for (0..1000) |i| {
        const key_str = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
        try kv.put(key_str, "val");
    }

    // Verify random reads
    const v = try kv.get("500");
    try testing.expect(v != null);
    try testing.expectEqualStrings("val", v.?);
    testing.allocator.free(v.?);
}
