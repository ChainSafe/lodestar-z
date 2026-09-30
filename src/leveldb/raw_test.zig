const std = @import("std");
const leveldb = @import("raw.zig");
const DB = leveldb.DB;
const Options = leveldb.Options;
const ReadOptions = leveldb.ReadOptions;
const WriteOptions = leveldb.WriteOptions;
const WriteBatch = leveldb.WriteBatch;
const Error = leveldb.Error;
const destroyDB = leveldb.destroyDB;
const free = leveldb.free;

fn tmpDbPath(allocator: std.mem.Allocator, tmp_dir: std.testing.TmpDir) ![:0]const u8 {
    const tmp_dir_path = try tmp_dir.parent_dir.realPathFileAlloc(
        std.testing.io,
        &tmp_dir.sub_path,
        allocator,
    );
    defer allocator.free(tmp_dir_path);

    return try std.fs.path.joinZ(allocator, &[_][]const u8{ tmp_dir_path, "test.db" });
}

test "basic put and get" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    const key = "test_key";
    const value = "test_value";
    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, key, value);

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = try db.get(&read_options, key) orelse return error.KeyNotFound;
    defer free(retrieved.ptr);
    try std.testing.expectEqualStrings(value, retrieved);
}

test "delete key" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    const key = "test_key";
    const value = "test_value";
    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, key, value);
    try db.delete(&write_options, key);

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = db.get(&read_options, key);
    try std.testing.expectEqual(null, retrieved);
}

test "non-existent key" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = db.get(&read_options, "nonexistent");
    try std.testing.expectEqual(null, retrieved);
}

test "invalid argument error - missing createIfMissing" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    defer options.destroy();
    const result = DB.open(&options, db_path);
    try std.testing.expectError(Error.InvalidArgument, result);
}

test "iterator seek and next" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, "key1", "value1");
    try db.put(&write_options, "key2", "value2");

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    var iter = try db.createIterator(&read_options);
    defer iter.destroy();

    iter.seekToFirst();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("key1", iter.key());
    try std.testing.expectEqualStrings("value1", iter.value());

    iter.next();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("key2", iter.key());
    try std.testing.expectEqualStrings("value2", iter.value());
}

test "write batch put and delete" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var batch = try WriteBatch.create();
    defer batch.destroy();
    batch.put("batch_key", "batch_value");
    batch.delete("batch_key");

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.write(&write_options, &batch);

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = db.get(&read_options, "batch_key");
    try std.testing.expectEqual(null, retrieved);
}

test "options setters" {
    var options = try Options.create();
    defer options.destroy();

    options.setCreateIfMissing(true);
    options.setWriteBufferSize(1024 * 1024);
    options.setCompression(0);
}

test "destroy db" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    db.close();

    try destroyDB(&options, db_path);
    options.setCreateIfMissing(false);
    const result = DB.open(&options, db_path);
    try std.testing.expectError(Error.InvalidArgument, result);
}

test "empty key and value" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, "", "");

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = try db.get(&read_options, "") orelse return error.KeyNotFound;
    defer free(retrieved.ptr);
    try std.testing.expectEqualStrings("", retrieved);
}

test "overwrite key" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    const key = "test_key";
    const value1 = "value1";
    const value2 = "value2";
    var write_options = try WriteOptions.create();
    defer write_options.destroy();

    try db.put(&write_options, key, value1);

    try db.put(&write_options, key, value2);

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = try db.get(&read_options, key) orelse return error.KeyNotFound;
    defer free(retrieved.ptr);
    try std.testing.expectEqualStrings(value2, retrieved);
}

test "iterator seek to last and prev" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, "key1", "value1");
    try db.put(&write_options, "key2", "value2");
    try db.put(&write_options, "key3", "value3");

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    var iter = try db.createIterator(&read_options);
    defer iter.destroy();

    iter.seekToLast();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("key3", iter.key());
    try std.testing.expectEqualStrings("value3", iter.value());

    iter.prev();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("key2", iter.key());
    try std.testing.expectEqualStrings("value2", iter.value());

    iter.prev();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("key1", iter.key());
    try std.testing.expectEqualStrings("value1", iter.value());
}

test "iterator seek to specific key" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, "key1", "value1");
    try db.put(&write_options, "key2", "value2");
    try db.put(&write_options, "key3", "value3");

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    var iter = try db.createIterator(&read_options);
    defer iter.destroy();

    iter.seek("key2");
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("key2", iter.key());
    try std.testing.expectEqualStrings("value2", iter.value());
}

test "iterator validity past end" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, "key1", "value1");

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    var iter = try db.createIterator(&read_options);
    defer iter.destroy();

    iter.seekToFirst();
    try std.testing.expect(iter.valid());

    iter.next();
    try std.testing.expect(!iter.valid()); // Past end
}

test "iterator get error" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    options.setCreateIfMissing(true);
    defer options.destroy();
    var db = try DB.open(&options, db_path);
    defer db.close();

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    var iter = try db.createIterator(&read_options);
    defer iter.destroy();

    try iter.getError();
}

test "snapshot preserves overwritten and deleted values" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    defer options.destroy();
    options.setCreateIfMissing(true);

    var db = try DB.open(&options, db_path);
    defer db.close();

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    try db.put(&write_options, "a", "before");
    try db.put(&write_options, "b", "deleted");

    var snapshot = try db.createSnapshot();
    defer db.releaseSnapshot(&snapshot);

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    read_options.setSnapshot(&snapshot);
    read_options.setVerifyChecksums(true);
    read_options.setFillCache(false);

    try db.put(&write_options, "a", "after");
    try db.delete(&write_options, "b");
    try db.put(&write_options, "c", "new");

    const value = (try db.get(&read_options, "a")).?;
    defer free(value.ptr);
    try std.testing.expectEqualStrings("before", value);
    try std.testing.expectEqual(null, try db.get(&read_options, "c"));

    var iter = try db.createIterator(&read_options);
    defer iter.destroy();
    iter.seekToFirst();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("a", iter.key());
    try std.testing.expectEqualStrings("before", iter.value());
    iter.next();
    try std.testing.expect(iter.valid());
    try std.testing.expectEqualStrings("b", iter.key());
    try std.testing.expectEqualStrings("deleted", iter.value());
    iter.next();
    try std.testing.expect(!iter.valid());
    try iter.getError();
}

test "sync batch persists binary keys and values through reopen" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var cache = try leveldb.Cache.createLru(1024 * 1024);
    defer cache.destroy();

    var options = try Options.create();
    defer options.destroy();
    options.setCreateIfMissing(true);
    options.setCache(&cache);
    options.setWriteBufferSize(64 * 1024);
    options.setMaxOpenFiles(64);
    options.setBlockSize(1024);
    options.setBlockRestartInterval(8);
    options.setMaxFileSize(1024 * 1024);
    options.setCompression(1);
    options.setParanoidChecks(true);

    var write_options = try WriteOptions.create();
    defer write_options.destroy();
    write_options.setSync(true);

    var batch = try WriteBatch.create();
    defer batch.destroy();
    batch.put("ignored", "discarded");
    batch.clear();
    const key = "\x00\xff\x00";
    const value = [_]u8{0xff} ** (16 * 1024);
    batch.put(key, "superseded");
    batch.delete(key);
    batch.put(key, &value);
    batch.put("empty", "");

    {
        var db = try DB.open(&options, db_path);
        defer db.close();
        try db.write(&write_options, &batch);
        db.compactRange(null, null);
        batch.clear();
        try db.write(&write_options, &batch);
    }

    options.setCreateIfMissing(false);
    var db = try DB.open(&options, db_path);
    defer db.close();

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    const retrieved = (try db.get(&read_options, key)).?;
    defer free(retrieved.ptr);
    try std.testing.expectEqualSlices(u8, &value, retrieved);
    try std.testing.expectEqual(null, try db.get(&read_options, "ignored"));
    const empty = (try db.get(&read_options, "empty")).?;
    defer free(empty.ptr);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "open propagates lock and existing database errors" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    defer options.destroy();
    options.setCreateIfMissing(true);

    {
        var db = try DB.open(&options, db_path);
        defer db.close();
        try std.testing.expectError(error.IOError, DB.open(&options, db_path));
    }
    options.setErrorIfExists(true);
    try std.testing.expectError(error.InvalidArgument, DB.open(&options, db_path));
}

fn corruptTable(tmp_dir: *std.testing.TmpDir) !void {
    const io = std.testing.io;
    var directory = try tmp_dir.dir.openDir(io, "test.db", .{ .iterate = true });
    defer directory.close(io);

    var entries = directory.iterate();
    var corrupted: usize = 0;
    for (0..64) |_| {
        const entry = try entries.next(io) orelse break;
        if (!std.mem.endsWith(u8, entry.name, ".ldb")) continue;

        const file = try directory.openFile(io, entry.name, .{ .mode = .read_write });
        defer file.close(io);

        const size = (try file.stat(io)).size;
        try std.testing.expect(size >= 8);
        try file.writePositionalAll(io, &([_]u8{0} ** 8), size - 8);
        corrupted += 1;
    } else return error.TooManyDatabaseFiles;
    try std.testing.expectEqual(@as(usize, 1), corrupted);
}

test "get and iterator propagate corrupt table errors instead of missing keys" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmpDbPath(std.testing.allocator, tmp_dir);
    defer std.testing.allocator.free(db_path);

    var options = try Options.create();
    defer options.destroy();
    options.setCreateIfMissing(true);

    {
        var db = try DB.open(&options, db_path);
        defer db.close();

        var write_options = try WriteOptions.create();
        defer write_options.destroy();
        try db.put(&write_options, "key", "value");
        db.compactRange(null, null);
    }
    try corruptTable(&tmp_dir);

    var db = try DB.open(&options, db_path);
    defer db.close();

    var read_options = try ReadOptions.create();
    defer read_options.destroy();
    read_options.setVerifyChecksums(true);
    try std.testing.expectError(error.Corruption, db.get(&read_options, "key"));

    var iter = try db.createIterator(&read_options);
    defer iter.destroy();
    iter.seek("key");
    try std.testing.expect(!iter.valid());
    try std.testing.expectError(error.Corruption, iter.getError());
}
