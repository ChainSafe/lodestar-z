const std = @import("std");
const leveldb = @import("root.zig");
const testing = std.testing;
const allocator = testing.allocator;
const helpers = @import("test_utils.zig");

fn expectKeys(db: *leveldb.Database, options: leveldb.RangeOptions, expected: []const []const u8) !void {
    var cursor = try db.cursor(options);
    defer cursor.close();
    var entries: [8]leveldb.Entry = undefined;
    var buffer: [128]u8 = undefined;
    const page = try cursor.readInto(&buffer, &entries, 16);
    try testing.expectEqual(expected.len, page.count);
    try testing.expect(page.done);
    for (entries[0..page.count], expected) |entry, key| try testing.expectEqualStrings(key, entry.key);
    var owned_cursor = try db.cursor(options);
    defer owned_cursor.close();
    const owned_page = try owned_cursor.readOwned(&entries, 16, buffer.len);
    defer helpers.freeEntries(allocator, entries[0..owned_page.count]);
    try testing.expectEqual(expected.len, owned_page.count);
    try testing.expect(owned_page.done);
    for (entries[0..owned_page.count], expected) |entry, key| try testing.expectEqualStrings(key, entry.key);
}

test "four range bounds match inclusive precedence in both directions" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    for ([_][]const u8{ "", "a", "b", "c", "d" }) |key| try fixture.db.put(key, "v", false);
    const Case = struct { options: leveldb.RangeOptions, keys: []const []const u8 };
    const cases = [_]Case{
        .{ .options = .{}, .keys = &.{ "", "a", "b", "c", "d" } },
        .{ .options = .{ .gt = "a", .lt = "d" }, .keys = &.{ "b", "c" } },
        .{ .options = .{ .gte = "a", .lte = "c" }, .keys = &.{ "a", "b", "c" } },
        .{ .options = .{ .gt = "a", .lte = "c" }, .keys = &.{ "b", "c" } },
        .{ .options = .{ .gte = "a", .lt = "c" }, .keys = &.{ "a", "b" } },
        .{ .options = .{ .gt = "z", .gte = "b", .lt = "a", .lte = "c" }, .keys = &.{ "b", "c" } },
        .{ .options = .{ .gt = "ab", .lte = "cz" }, .keys = &.{ "b", "c" } },
        .{ .options = .{ .gte = "c", .lte = "c" }, .keys = &.{"c"} },
        .{ .options = .{ .gt = "c", .lte = "c" }, .keys = &.{} },
        .{ .options = .{ .gte = "c", .lt = "c" }, .keys = &.{} },
        .{ .options = .{ .gte = "d", .lte = "a" }, .keys = &.{} },
        .{ .options = .{ .lt = "" }, .keys = &.{} },
        .{ .options = .{ .lte = "" }, .keys = &.{""} },
        .{ .options = .{ .gte = "z" }, .keys = &.{} },
        .{ .options = .{ .gte = "a", .lte = "z" }, .keys = &.{ "a", "b", "c", "d" } },
    };
    for (cases) |case| {
        try expectKeys(&fixture.db, case.options, case.keys);
        var reverse = case.options;
        reverse.reverse = true;
        var keys: [8][]const u8 = undefined;
        for (case.keys, 0..) |key, index| keys[case.keys.len - index - 1] = key;
        try expectKeys(&fixture.db, reverse, keys[0..case.keys.len]);
    }
}

test "reverse range owns bounds and keeps its snapshot across pages" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    for ([_][]const u8{ "a\x00", "a\xff", "b" }) |key| try fixture.db.put(key, key, false);
    var lower = [_]u8{ 'a', 0 };
    var upper = [_]u8{'b'};
    var cursor = try fixture.db.cursor(.{ .gte = &lower, .lte = &upper, .reverse = true, .limit = 2 });
    defer cursor.close();
    @memset(&lower, 'z');
    @memset(&upper, 0);
    try fixture.db.delete("b", false);
    try fixture.db.put("a\xff", "changed", false);
    var entries: [1]leveldb.Entry = undefined;
    var buffer: [16]u8 = undefined;
    const first = try cursor.readInto(&buffer, &entries, 16);
    try testing.expect(!first.done);
    try testing.expectEqualStrings("b", entries[0].key);
    const second = try cursor.readInto(&buffer, &entries, 16);
    try testing.expect(second.done);
    try testing.expectEqualStrings("a\xff", entries[0].key);
    try testing.expectEqualStrings("a\xff", entries[0].value);
}

test "projection charges only requested bytes and ignores omitted value limits" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("key", "1234567890", false);
    for ([_]bool{ false, true }) |reverse| {
        var keys = try fixture.db.cursor(.{ .values = false, .reverse = reverse, .fill_cache = true });
        defer keys.close();
        var entries: [1]leveldb.Entry = undefined;
        const key_page = try keys.readOwned(&entries, 0, 3);
        defer helpers.freeEntries(allocator, entries[0..key_page.count]);
        try testing.expectEqual(@as(usize, 3), key_page.bytes);
        try testing.expectEqualStrings("key", entries[0].key);
        try testing.expectEqualStrings("", entries[0].value);
    }
    var values = try fixture.db.cursor(.{ .keys = false });
    defer values.close();
    var value_entries: [1]leveldb.Entry = undefined;
    const value_page = try values.readOwned(&value_entries, 10, 10);
    defer helpers.freeEntries(allocator, value_entries[0..value_page.count]);
    try testing.expectEqual(@as(usize, 10), value_page.bytes);
    try testing.expectEqualStrings("", value_entries[0].key);
    try testing.expectEqualStrings("1234567890", value_entries[0].value);
    var neither = try fixture.db.cursor(.{ .keys = false, .values = false });
    defer neither.close();
    var empty_entries: [1]leveldb.Entry = undefined;
    const empty_page = try neither.readOwned(&empty_entries, 0, 0);
    defer helpers.freeEntries(allocator, empty_entries[0..empty_page.count]);
    try testing.expectEqual(@as(usize, 1), empty_page.count);
    try testing.expectEqual(@as(usize, 0), empty_page.bytes);
    try testing.expect(empty_page.done);
}

test "range allocation failures release both copied bounds" {
    for (0..2) |fail_index| {
        var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var fixture: helpers.Fixture = undefined;
        try fixture.init(failing.allocator());
        defer fixture.deinit();
        try testing.expectError(error.OutOfMemory, fixture.db.cursor(.{ .gte = "a", .lte = "z" }));
        try testing.expectEqual(@as(u32, 0), fixture.db.cursors.load(.monotonic));
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
