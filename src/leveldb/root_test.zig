const std = @import("std");
const leveldb = @import("root.zig");
const testing = std.testing;
const allocator = testing.allocator;

const Fixture = struct {
    tmp: testing.TmpDir,
    path: [:0]u8,
    db: leveldb.Database,
    closed: bool = false,

    fn init(self: *Fixture) !void {
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();

        const directory = try self.tmp.dir.realPathFileAlloc(testing.io, ".", allocator);
        defer allocator.free(directory);

        self.path = try std.fmt.allocPrintSentinel(allocator, "{s}/database", .{directory}, 0);
        errdefer allocator.free(self.path);

        self.db = try leveldb.Database.open(allocator, self.path, .{});
        self.closed = false;
    }

    fn close(self: *Fixture) !void {
        try self.db.close();
        self.closed = true;
    }

    fn reopen(self: *Fixture) !void {
        try self.close();
        self.db = try leveldb.Database.open(allocator, self.path, .{
            .create_if_missing = false,
        });
        self.closed = false;
    }

    fn deinit(self: *Fixture) void {
        if (!self.closed) self.db.close() catch unreachable;
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

fn expectValue(db: *leveldb.Database, key: []const u8, expected: ?[]const u8) !void {
    var destination: [128]u8 = @splat(0xa5);
    const actual = try db.getInto(key, &destination);
    if (expected) |value| {
        try testing.expect(actual != null);
        try testing.expectEqualSlices(u8, value, actual.?);
        try testing.expectEqual(@intFromPtr(&destination), @intFromPtr(actual.?.ptr));
        for (destination[value.len..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    } else {
        try testing.expectEqual(null, actual);
        try testing.expectEqualSlices(u8, &(@as([128]u8, @splat(0xa5))), &destination);
    }
}

fn expectEntry(entry: *const leveldb.Entry, key: []const u8, value: []const u8) !void {
    try testing.expectEqualSlices(u8, key, entry.key);
    try testing.expectEqualSlices(u8, value, entry.value);
}

test "getInto distinguishes exact binary keys, empty values, and missing keys" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("", "empty key", false);
    try fixture.db.put("ab", "prefix", false);
    try fixture.db.put("ab\x00", "nul", false);
    try fixture.db.put("ab\xff", "binary", false);
    try fixture.db.put("empty", "", false);

    try expectValue(&fixture.db, "", "empty key");
    try expectValue(&fixture.db, "a", null);
    try expectValue(&fixture.db, "ab", "prefix");
    try expectValue(&fixture.db, "ab\x00", "nul");
    try expectValue(&fixture.db, "ab\x01", null);
    try expectValue(&fixture.db, "ab\xff", "binary");
    try expectValue(&fixture.db, "empty", "");
    try expectValue(&fixture.db, "z", null);

    var empty: [0]u8 = .{};
    try testing.expectEqual(@as(usize, 0), (try fixture.db.getInto("empty", &empty)).?.len);
    try testing.expectEqual(null, try fixture.db.getInto("missing", &empty));
    try fixture.db.delete("empty", false);
    try fixture.db.delete("missing", false);
    try expectValue(&fixture.db, "empty", null);
}

test "memory_safety: getInto rejects oversized values without touching destination" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("key", "12345", false);
    var guarded: [8]u8 = @splat(0xa5);
    try testing.expectError(error.ValueTooLarge, fixture.db.getInto("key", guarded[2..6]));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &guarded);
    try testing.expectError(error.ValueTooLarge, fixture.db.getInto("key", guarded[2..2]));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &guarded);

    const value = (try fixture.db.getInto("key", guarded[1..6])).?;
    try testing.expectEqualStrings("12345", value);
    try testing.expectEqualSlices(u8, &.{ 0xa5, '1', '2', '3', '4', '5', 0xa5, 0xa5 }, &guarded);
}

test "getManyInto preserves mixed missing empty duplicate and unsorted key order" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.write(&.{
        .{ .key = "", .value = "E" },
        .{ .key = "a", .value = "A" },
        .{ .key = "a\x00", .value = "N" },
        .{ .key = "b", .value = "BB" },
        .{ .key = "empty", .value = "" },
    }, false);
    const keys = [_][]const u8{ "zz", "b", "a", "ab", "b", "empty", "", "a\x00", "a" };
    const expected = [_]?[]const u8{ null, "BB", "A", null, "BB", "", "E", "N", "A" };
    var destination: [16]u8 = @splat(0xa5);
    var results: [keys.len]?[]const u8 = undefined;
    try fixture.db.getManyInto(&keys, &destination, &results, 2);

    var offset: usize = 0;
    for (expected, results) |value, result| {
        if (value) |bytes| {
            try testing.expect(result != null);
            try testing.expectEqualSlices(u8, bytes, result.?);
            try testing.expectEqual(
                @intFromPtr(destination[offset..].ptr),
                @intFromPtr(result.?.ptr),
            );
            offset += bytes.len;
        } else {
            try testing.expectEqual(null, result);
        }
    }
    try testing.expectEqual(@as(usize, 8), offset);
    try testing.expectEqualStrings("BBABBENA", destination[0..offset]);
    for (destination[offset..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);

    try fixture.db.put("b", "changed", false);
    try testing.expectEqualStrings("BB", results[1].?);
    try testing.expectEqualStrings("BB", results[4].?);
}

test "getManyInto permits zero byte limits for empty and missing values" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("empty", "", false);
    try fixture.db.put("full", "v", false);
    const keys = [_][]const u8{ "missing", "empty", "", "empty" };
    var destination: [0]u8 = .{};
    var results: [keys.len]?[]const u8 = undefined;
    try fixture.db.getManyInto(&keys, &destination, &results, 0);
    try testing.expectEqual(null, results[0]);
    try testing.expect(results[1] != null);
    try testing.expectEqual(@as(usize, 0), results[1].?.len);
    try testing.expectEqual(null, results[2]);
    try testing.expect(results[3] != null);
    try testing.expectEqual(@as(usize, 0), results[3].?.len);
    try fixture.db.getManyInto(&.{}, &destination, results[0..0], 0);

    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{"full"},
        &destination,
        results[0..1],
        0,
    ));
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
        &.{"full"},
        &destination,
        results[0..1],
        1,
    ));
    try fixture.close();
}

test "memory_safety: getManyInto enforces per value limits before copying oversized row" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("large", "12345", false);
    try fixture.db.put("small", "v", false);
    var destination: [16]u8 = @splat(0xa5);
    var results: [2]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{ "large", "small" },
        destination[1..15],
        &results,
        4,
    ));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{ "small", "large" },
        destination[1..15],
        &results,
        4,
    ));
    try testing.expectEqual(@as(u8, 0xa5), destination[0]);
    try testing.expectEqual(@as(u8, 0xa5), destination[15]);

    try fixture.db.getManyInto(&.{ "large", "small" }, destination[1..15], &results, 5);
    try testing.expectEqualStrings("12345", results[0].?);
    try testing.expectEqualStrings("v", results[1].?);
    try fixture.close();
}

test "memory_safety: getManyInto counts duplicate values against exact aggregate capacity" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("a", "123", false);
    try fixture.db.put("b", "45", false);
    try fixture.db.put("empty", "", false);
    const keys = [_][]const u8{ "a", "b", "a", "empty", "missing" };
    var destination: [10]u8 = @splat(0xa5);
    var results: [keys.len]?[]const u8 = undefined;
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
        &keys,
        destination[1..8],
        &results,
        3,
    ));
    try testing.expectEqual(@as(u8, 0xa5), destination[0]);
    try testing.expectEqualSlices(u8, &.{ 0xa5, 0xa5 }, destination[8..]);

    try fixture.db.getManyInto(&keys, destination[1..9], &results, 3);
    try testing.expectEqualStrings("12345123", destination[1..9]);
    try testing.expectEqualStrings("123", results[0].?);
    try testing.expectEqualStrings("45", results[1].?);
    try testing.expectEqualStrings("123", results[2].?);
    try testing.expect(results[3] != null);
    try testing.expectEqual(@as(usize, 0), results[3].?.len);
    try testing.expectEqual(null, results[4]);
    try testing.expectEqual(@as(u8, 0xa5), destination[0]);
    try testing.expectEqual(@as(u8, 0xa5), destination[9]);
}

test "getManyInto reports per value overflow before aggregate overflow" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("large", "12345", false);
    var destination: [3]u8 = @splat(0xa5);
    var results: [1]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{"large"},
        &destination,
        &results,
        4,
    ));
    try testing.expectEqualSlices(u8, &(@as([3]u8, @splat(0xa5))), &destination);
}

test "getManyInto validates key counts result lengths keys and value limits" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("key", "v", false);
    const keys: [leveldb.max_batch_entries + 1][]const u8 = @splat("missing");
    var results: [keys.len]?[]const u8 = undefined;
    var destination: [8]u8 = @splat(0xa5);
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
        &keys,
        &destination,
        &results,
        1,
    ));
    for ([_]usize{ 0, 2 }) |result_count| {
        try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
            &.{"key"},
            &destination,
            results[0..result_count],
            1,
        ));
    }
    const oversized_key: [leveldb.max_key_bytes + 1]u8 = @splat('k');
    try testing.expectError(error.KeyTooLarge, fixture.db.getManyInto(
        &.{ "key", &oversized_key },
        &destination,
        results[0..2],
        1,
    ));
    try testing.expectError(error.InvalidReadLimit, fixture.db.getManyInto(
        &.{"key"},
        &destination,
        results[0..1],
        leveldb.max_value_bytes + 1,
    ));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);

    try fixture.db.getManyInto(
        keys[0..leveldb.max_batch_entries],
        destination[0..0],
        results[0..leveldb.max_batch_entries],
        0,
    );
    for (results[0..leveldb.max_batch_entries]) |result| try testing.expectEqual(null, result);
    try fixture.close();
    try testing.expectError(error.DatabaseClosed, fixture.db.getManyInto(
        &.{"key"},
        &destination,
        results[0..1],
        1,
    ));
}

test "write applies ordered puts and deletes and persists after reopening" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("remove", "old", false);
    try fixture.db.write(&.{
        .{ .key = "same", .value = "first" },
        .{ .key = "remove", .value = null },
        .{ .key = "same", .value = null },
        .{ .key = "same", .value = "last" },
        .{ .key = "empty", .value = "" },
    }, true);
    try fixture.db.write(&.{}, false);
    try fixture.close();
    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    });
    fixture.closed = false;

    try expectValue(&fixture.db, "same", "last");
    try expectValue(&fixture.db, "remove", null);
    try expectValue(&fixture.db, "empty", "");
}

test "write validates every key before applying any operation" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("keep", "original", false);
    const oversized_key: [leveldb.max_key_bytes + 1]u8 = @splat('k');
    try testing.expectError(error.KeyTooLarge, fixture.db.write(&.{
        .{ .key = "new", .value = "must not appear" },
        .{ .key = "keep", .value = null },
        .{ .key = &oversized_key, .value = "invalid" },
    }, false));
    try expectValue(&fixture.db, "new", null);
    try expectValue(&fixture.db, "keep", "original");

    try testing.expectError(error.KeyTooLarge, fixture.db.write(&.{
        .{ .key = "keep", .value = "changed" },
        .{ .key = &oversized_key, .value = null },
    }, false));
    try expectValue(&fixture.db, "keep", "original");
}

test "write bounds operation count and counts keys in its aggregate byte limit" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("k", "original", false);
    var operations: [leveldb.max_batch_entries + 1]leveldb.Operation = @splat(.{
        .key = "k",
        .value = null,
    });
    try testing.expectError(error.BatchTooLarge, fixture.db.write(&operations, false));
    try expectValue(&fixture.db, "k", "original");

    const value = try allocator.alloc(u8, leveldb.max_batch_bytes / leveldb.max_batch_entries);
    defer allocator.free(value);
    @memset(value, 'v');
    for (operations[0..leveldb.max_batch_entries]) |*operation| {
        operation.* = .{ .key = "k", .value = value };
    }
    try testing.expectError(error.BatchTooLarge, fixture.db.write(
        operations[0..leveldb.max_batch_entries],
        false,
    ));
    try expectValue(&fixture.db, "k", "original");

    @memset(&operations, .{ .key = "absent", .value = null });
    try fixture.db.write(operations[0..leveldb.max_batch_entries], false);
}

test "cursor keeps its creation snapshot across updates deletes and inserts" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.write(&.{
        .{ .key = "a", .value = "old a" },
        .{ .key = "c", .value = "old c" },
        .{ .key = "e", .value = "old e" },
    }, false);
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();

    try fixture.db.put("a", "new a", false);
    try fixture.db.put("b", "new b", false);
    var destination: [32]u8 = undefined;
    var entries: [1]leveldb.Entry = undefined;
    var page = try cursor.readInto(&destination, &entries, 16);
    try testing.expectEqual(@as(usize, 1), page.count);
    try expectEntry(&entries[0], "a", "old a");

    try fixture.db.delete("c", false);
    try fixture.db.put("d", "new d", false);
    try fixture.db.put("e", "new e", false);
    page = try cursor.readInto(&destination, &entries, 16);
    try testing.expectEqual(@as(usize, 1), page.count);
    try expectEntry(&entries[0], "c", "old c");
    page = try cursor.readInto(&destination, &entries, 16);
    try testing.expectEqual(@as(usize, 1), page.count);
    try expectEntry(&entries[0], "e", "old e");
    try testing.expect(page.done);
    try testing.expectError(error.CursorClosed, cursor.readInto(&destination, &entries, 16));
    try expectValue(&fixture.db, "a", "new a");
    try expectValue(&fixture.db, "c", null);
    try expectValue(&fixture.db, "e", "new e");
}

test "cursor owns range bounds and applies inclusive gte exclusive lt and total limit" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    for ([_][]const u8{ "a", "b", "c", "d", "e" }) |key| {
        try fixture.db.put(key, key, false);
    }
    var lower = [_]u8{'b'};
    var upper = [_]u8{'e'};
    var cursor = try fixture.db.cursor(.{ .gte = &lower, .lt = &upper, .limit = 2 });
    defer cursor.close();
    lower[0] = 'z';
    upper[0] = 'a';

    var destination: [16]u8 = undefined;
    var entries: [1]leveldb.Entry = undefined;
    var page = try cursor.readInto(&destination, &entries, 1);
    try testing.expectEqual(@as(usize, 1), page.count);
    try testing.expect(!page.done);
    try expectEntry(&entries[0], "b", "b");
    page = try cursor.readInto(&destination, &entries, 1);
    try testing.expectEqual(@as(usize, 1), page.count);
    try testing.expect(page.done);
    try expectEntry(&entries[0], "c", "c");

    var range = try fixture.db.cursor(.{ .gte = "bb", .lt = "e" });
    defer range.close();
    var range_entries: [4]leveldb.Entry = undefined;
    page = try range.readInto(&destination, &range_entries, 1);
    try testing.expectEqual(@as(usize, 2), page.count);
    try testing.expect(page.done);
    try expectEntry(&range_entries[0], "c", "c");
    try expectEntry(&range_entries[1], "d", "d");
}

test "cursor handles empty database zero limit and empty ranges" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    var destination: [8]u8 = @splat(0xa5);
    var entries: [1]leveldb.Entry = undefined;
    var empty = try fixture.db.cursor(.{});
    defer empty.close();
    const empty_page = try empty.readInto(&destination, &entries, 1);
    try testing.expectEqual(@as(usize, 0), empty_page.count);
    try testing.expectEqual(@as(usize, 0), empty_page.bytes);
    try testing.expect(empty_page.done);

    try fixture.db.put("b", "v", false);
    for ([_]leveldb.RangeOptions{
        .{ .limit = 0 },
        .{ .gte = "b", .lt = "b" },
        .{ .gte = "z", .lt = "a" },
        .{ .gte = "z" },
        .{ .lt = "b" },
    }) |options| {
        var cursor = try fixture.db.cursor(options);
        defer cursor.close();
        const page = try cursor.readInto(&destination, &entries, 1);
        try testing.expectEqual(@as(usize, 0), page.count);
        try testing.expectEqual(@as(usize, 0), page.bytes);
        try testing.expect(page.done);
    }
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);
}

test "cursor counts keys and defers a row that does not fit without advancing" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.write(&.{
        .{ .key = "aa", .value = "123" },
        .{ .key = "bbb", .value = "45" },
        .{ .key = "c", .value = "" },
    }, false);
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();

    var guarded: [12]u8 = @splat(0xa5);
    var entries: [3]leveldb.Entry = undefined;
    const first = try cursor.readInto(guarded[1..10], &entries, 3);
    try testing.expectEqual(@as(usize, 1), first.count);
    try testing.expectEqual(@as(usize, 5), first.bytes);
    try testing.expect(!first.done);
    try expectEntry(&entries[0], "aa", "123");
    try testing.expectEqual(@intFromPtr(&guarded[1]), @intFromPtr(entries[0].key.ptr));
    try testing.expectEqual(@intFromPtr(&guarded[3]), @intFromPtr(entries[0].value.ptr));
    try testing.expectEqual(@as(u8, 0xa5), guarded[0]);
    for (guarded[6..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);

    var second_destination: [6]u8 = undefined;
    var second_entries: [3]leveldb.Entry = undefined;
    const second = try cursor.readInto(&second_destination, &second_entries, 3);
    try testing.expectEqual(@as(usize, 2), second.count);
    try testing.expectEqual(@as(usize, 6), second.bytes);
    try testing.expect(second.done);
    try expectEntry(&second_entries[0], "bbb", "45");
    try expectEntry(&second_entries[1], "c", "");
    try expectEntry(&entries[0], "aa", "123");
    try testing.expectEqualStrings("bbb45c", &second_destination);
}

test "memory_safety: cursor oversized row errors are terminal and release database" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("key", "12345", false);
    var destination: [16]u8 = @splat(0xa5);
    var entries: [1]leveldb.Entry = undefined;
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();

    try testing.expectError(error.ValueTooLarge, cursor.readInto(&destination, &entries, 4));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.CursorClosed, cursor.readInto(&destination, &entries, 5));
    try fixture.close();
    cursor.close();
    cursor.close();
}

test "memory_safety: cursor rejects first row when key and value exceed page capacity" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("long-key", "v", false);
    var destination: [8]u8 = @splat(0xa5);
    var entries: [1]leveldb.Entry = undefined;
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();

    try testing.expectError(error.BatchTooLarge, cursor.readInto(&destination, &entries, 1));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.CursorClosed, cursor.readInto(&destination, &entries, 1));
    try fixture.close();
    cursor.close();
}

test "cursor oversized later row fails the entire page and releases snapshot" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("a", "v", false);
    try fixture.db.put("b", "too big", false);
    var cursor = try fixture.db.cursor(.{ .lt = "z" });
    defer cursor.close();

    var destination: [32]u8 = undefined;
    var entries: [2]leveldb.Entry = undefined;
    try testing.expectError(error.ValueTooLarge, cursor.readInto(&destination, &entries, 1));
    try testing.expectError(error.CursorClosed, cursor.readInto(&destination, &entries, 7));
    try fixture.close();
}

test "cursor advances an empty key and value even when its byte count is zero" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("", "", false);
    try fixture.db.put("a", "", false);
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();

    var destination: [1]u8 = .{0xa5};
    var entries: [1]leveldb.Entry = undefined;
    const first = try cursor.readInto(&destination, &entries, 1);
    try testing.expectEqual(@as(usize, 1), first.count);
    try testing.expectEqual(@as(usize, 0), first.bytes);
    try testing.expect(!first.done);
    try expectEntry(&entries[0], "", "");
    try testing.expectEqual(@as(u8, 0xa5), destination[0]);

    const second = try cursor.readInto(&destination, &entries, 1);
    try testing.expectEqual(@as(usize, 1), second.count);
    try testing.expectEqual(@as(usize, 1), second.bytes);
    try testing.expect(second.done);
    try expectEntry(&entries[0], "a", "");
    try fixture.close();
}

test "close rejects live cursors and remains usable until all cursors close" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("key", "value", false);
    var first = try fixture.db.cursor(.{});
    defer first.close();
    var second = try fixture.db.cursor(.{});
    defer second.close();

    try testing.expectError(error.CursorsOpen, fixture.db.close());
    try expectValue(&fixture.db, "key", "value");
    first.close();
    first.close();
    try testing.expectError(error.CursorsOpen, fixture.db.close());

    var destination: [16]u8 = undefined;
    var entries: [1]leveldb.Entry = undefined;
    const page = try second.readInto(&destination, &entries, 5);
    try testing.expect(page.done);
    try testing.expectEqual(@as(usize, 1), page.count);
    try expectEntry(&entries[0], "key", "value");
    try fixture.close();
    try fixture.db.close();
    try testing.expectError(error.CursorClosed, second.readInto(&destination, &entries, 5));
    try testing.expectError(error.DatabaseClosed, fixture.db.getInto("key", &destination));
    try testing.expectError(error.DatabaseClosed, fixture.db.put("key", "new", false));
    try testing.expectError(error.DatabaseClosed, fixture.db.delete("key", false));
    try testing.expectError(error.DatabaseClosed, fixture.db.write(&.{}, false));
    try testing.expectError(error.DatabaseClosed, fixture.db.cursor(.{}));
}

test "cursor capacity is exact and closing one cursor permits replacement" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    var cursors: [leveldb.max_cursors]leveldb.Cursor = undefined;
    var initialized: usize = 0;
    defer for (cursors[0..initialized]) |*cursor| cursor.close();
    for (&cursors) |*cursor| {
        cursor.* = try fixture.db.cursor(.{});
        initialized += 1;
    }
    try testing.expectError(error.CursorCapacity, fixture.db.cursor(.{}));
    cursors[0].close();
    cursors[0] = try fixture.db.cursor(.{});
    try testing.expectError(error.CursorCapacity, fixture.db.cursor(.{}));
    for (&cursors) |*cursor| cursor.close();
    try fixture.close();
}

test "cursor allocation failure leaves database usable without retaining a live cursor" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    try fixture.db.put("key", "value", false);
    try fixture.close();

    var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    fixture.db = try leveldb.Database.open(failing.allocator(), fixture.path, .{
        .create_if_missing = false,
    });
    fixture.closed = false;
    try testing.expectError(error.OutOfMemory, fixture.db.cursor(.{ .lt = "z" }));
    try testing.expect(failing.has_induced_failure);
    try expectValue(&fixture.db, "key", "value");

    failing.fail_index = std.math.maxInt(usize);
    var cursor = try fixture.db.cursor(.{ .lt = "z" });
    defer cursor.close();
    var destination: [8]u8 = undefined;
    var entries: [1]leveldb.Entry = undefined;
    const page = try cursor.readInto(&destination, &entries, 5);
    try testing.expectEqual(@as(usize, 1), page.count);
    try testing.expect(page.done);
    try expectEntry(&entries[0], "key", "value");
    try testing.expect(failing.allocated_bytes > 0);
    try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    try fixture.close();
}

test "maximum length keys work and oversized keys fail at every public boundary" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const key: [leveldb.max_key_bytes + 1]u8 = @splat('k');
    const maximum = key[0..leveldb.max_key_bytes];
    try fixture.db.put(maximum, "v", false);
    try expectValue(&fixture.db, maximum, "v");

    var destination: [8]u8 = @splat(0xa5);
    try testing.expectError(error.KeyTooLarge, fixture.db.getInto(&key, &destination));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.KeyTooLarge, fixture.db.put(&key, "v", false));
    try testing.expectError(error.KeyTooLarge, fixture.db.delete(&key, false));
    try testing.expectError(error.KeyTooLarge, fixture.db.cursor(.{ .gte = &key }));
    try testing.expectError(error.KeyTooLarge, fixture.db.cursor(.{ .lt = &key }));
    try expectValue(&fixture.db, maximum, "v");
    try fixture.db.delete(maximum, false);
    try expectValue(&fixture.db, maximum, null);
    try fixture.close();
}

test "invalid cursor read limits close the cursor without writing output" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("key", "value", false);
    var destination: [16]u8 = @splat(0xa5);
    var entries: [leveldb.max_batch_entries + 1]leveldb.Entry = undefined;
    const Case = struct { bytes: usize, entries: usize, value_limit: usize };
    for ([_]Case{
        .{ .bytes = 0, .entries = 1, .value_limit = 5 },
        .{ .bytes = 16, .entries = 0, .value_limit = 5 },
        .{ .bytes = 16, .entries = entries.len, .value_limit = 5 },
        .{ .bytes = 16, .entries = 1, .value_limit = 0 },
        .{ .bytes = 16, .entries = 1, .value_limit = leveldb.max_value_bytes + 1 },
    }) |case| {
        var cursor = try fixture.db.cursor(.{});
        defer cursor.close();
        try testing.expectError(error.InvalidReadLimit, cursor.readInto(
            destination[0..case.bytes],
            entries[0..case.entries],
            case.value_limit,
        ));
        try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &destination);
        try testing.expectError(error.CursorClosed, cursor.readInto(
            &destination,
            entries[0..1],
            5,
        ));
    }
    try fixture.close();
}

test "open rejects invalid paths and options before creating database" {
    const long_path: [4097:0]u8 = @splat('p');
    for ([_][:0]const u8{ "", "embedded\x00nul", &long_path }) |path| {
        try testing.expectError(error.InvalidPath, leveldb.Database.open(allocator, path, .{}));
    }

    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    try fixture.close();

    for ([_]leveldb.Options{
        .{ .cache_bytes = 1024 * 1024 * 1024 + 1 },
        .{ .write_buffer_bytes = 64 * 1024 - 1 },
        .{ .write_buffer_bytes = 1024 * 1024 * 1024 + 1 },
        .{ .max_open_files = 19 },
        .{ .max_open_files = 4097 },
    }) |options| {
        try testing.expectError(error.InvalidOptions, leveldb.Database.open(
            allocator,
            fixture.path,
            options,
        ));
    }
    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
        .cache_bytes = 0,
        .write_buffer_bytes = 64 * 1024,
        .max_open_files = 20,
    });
    fixture.closed = false;
    try fixture.db.put("key", "value", false);
    try expectValue(&fixture.db, "key", "value");
}

test "memory_safety: cold compressed SSTable reads enforce destination and row limits" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const value = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(value);
    @memset(value, 's');
    try fixture.db.put("compressed", value, true);
    try fixture.close();

    // Reopening flushes the recovered log to an SSTable; reopen again to discard engine caches.
    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    });
    fixture.closed = false;
    try fixture.close();
    try expectCompressedTable(&fixture, value.len);

    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    });
    fixture.closed = false;
    var small: [16]u8 = @splat(0xa5);
    try testing.expectError(error.ValueTooLarge, fixture.db.getInto("compressed", &small));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &small);

    try fixture.reopen();
    var results: [1]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{"compressed"},
        &small,
        &results,
        small.len,
    ));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &small);

    try fixture.reopen();
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();
    var entries: [1]leveldb.Entry = undefined;
    try testing.expectError(error.ValueTooLarge, cursor.readInto(&small, &entries, small.len));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &small);
    try testing.expectError(error.CursorClosed, cursor.readInto(&small, &entries, value.len));

    const destination = try allocator.alloc(u8, "compressed".len + value.len);
    defer allocator.free(destination);
    try testing.expectEqualSlices(u8, value, (try fixture.db.getInto("compressed", destination)).?);
    var full_cursor = try fixture.db.cursor(.{});
    defer full_cursor.close();
    const page = try full_cursor.readInto(destination, &entries, value.len);
    try testing.expectEqual(@as(usize, 1), page.count);
    try testing.expectEqual(destination.len, page.bytes);
    try testing.expect(page.done);
    try expectEntry(&entries[0], "compressed", value);
    try fixture.close();
}

test "SSTable corruption propagates through reads and failed cursor creation cleans up" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    try fixture.db.put("key", "value", true);
    try fixture.reopen();
    try fixture.close();
    try corruptFirstTableBlock(&fixture);
    try fixture.reopen();

    var destination: [8]u8 = @splat(0xa5);
    var results: [1]?[]const u8 = undefined;
    try testing.expectError(error.Corruption, fixture.db.getInto("key", &destination));
    try testing.expectError(error.Corruption, fixture.db.getManyInto(
        &.{"key"},
        &destination,
        &results,
        destination.len,
    ));
    try testing.expectError(error.Corruption, fixture.db.getManyOwned(
        &.{"key"},
        &results,
        destination.len,
        destination.len,
        false,
    ));
    try testing.expectEqual(null, results[0]);
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.Corruption, fixture.db.cursor(.{ .gte = "key", .lt = "z" }));
    try fixture.close();
}

fn corruptFirstTableBlock(fixture: *const Fixture) !void {
    var directory = try fixture.tmp.dir.openDir(testing.io, "database", .{ .iterate = true });
    defer directory.close(testing.io);

    var iterator = directory.iterate();
    for (0..32) |_| {
        const entry = try iterator.next(testing.io) orelse return error.MissingTable;
        if (!std.mem.endsWith(u8, entry.name, ".ldb") and
            !std.mem.endsWith(u8, entry.name, ".sst")) continue;
        const file = try directory.openFile(testing.io, entry.name, .{ .mode = .read_write });
        defer file.close(testing.io);

        var byte: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try file.readPositionalAll(testing.io, &byte, 0));
        byte[0] ^= 0xff;
        try file.writePositionalAll(testing.io, &byte, 0);
        return;
    }
    return error.TooManyDatabaseFiles;
}

fn expectCompressedTable(fixture: *const Fixture, uncompressed_bytes: usize) !void {
    var directory = try fixture.tmp.dir.openDir(testing.io, "database", .{ .iterate = true });
    defer directory.close(testing.io);

    var iterator = directory.iterate();
    var table_count: usize = 0;
    var table_bytes: u64 = 0;
    for (0..32) |_| {
        const entry = try iterator.next(testing.io) orelse break;
        if (!std.mem.endsWith(u8, entry.name, ".ldb") and
            !std.mem.endsWith(u8, entry.name, ".sst")) continue;
        const stat = try directory.statFile(testing.io, entry.name, .{});
        table_count += 1;
        table_bytes += stat.size;
    } else return error.TooManyDatabaseFiles;
    try testing.expectEqual(@as(usize, 1), table_count);
    try testing.expect(table_bytes > 0);
    try testing.expect(table_bytes < uncompressed_bytes);
}
