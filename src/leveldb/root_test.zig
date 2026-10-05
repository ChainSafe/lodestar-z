const std = @import("std");
const leveldb = @import("root.zig");
const testing = std.testing;
const allocator = testing.allocator;
const helpers = @import("test_utils.zig");
const Fixture = helpers.Fixture;
const expectValue = helpers.expectValue;
const expectEntry = helpers.expectEntry;

test "getInto distinguishes exact binary keys, empty values, and missing keys" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("", "empty key", false, null);
    try fixture.db.put("ab", "prefix", false, null);
    try fixture.db.put("ab\x00", "nul", false, null);
    try fixture.db.put("ab\xff", "binary", false, null);
    try fixture.db.put("empty", "", false, null);

    try expectValue(&fixture.db, "", "empty key");
    try expectValue(&fixture.db, "a", null);
    try expectValue(&fixture.db, "ab", "prefix");
    try expectValue(&fixture.db, "ab\x00", "nul");
    try expectValue(&fixture.db, "ab\x01", null);
    try expectValue(&fixture.db, "ab\xff", "binary");
    try expectValue(&fixture.db, "empty", "");
    try expectValue(&fixture.db, "z", null);

    var empty: [0]u8 = .{};
    try testing.expectEqual(@as(usize, 0), (try fixture.db.getInto("empty", &empty, null)).?.len);
    try testing.expectEqual(null, try fixture.db.getInto("missing", &empty, null));
    try fixture.db.delete("empty", false, null);
    try fixture.db.delete("missing", false, null);
    try expectValue(&fixture.db, "empty", null);
}

test "memory_safety: getInto rejects oversized values without touching destination" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("key", "12345", false, null);
    var guarded: [8]u8 = @splat(0xa5);
    try testing.expectError(error.ValueTooLarge, fixture.db.getInto("key", guarded[2..6], null));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &guarded);
    try testing.expectError(error.ValueTooLarge, fixture.db.getInto("key", guarded[2..2], null));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &guarded);

    const value = (try fixture.db.getInto("key", guarded[1..6], null)).?;
    try testing.expectEqualStrings("12345", value);
    try testing.expectEqualSlices(u8, &.{ 0xa5, '1', '2', '3', '4', '5', 0xa5, 0xa5 }, &guarded);
}

test "getManyInto preserves mixed missing empty duplicate and unsorted key order" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.write(&.{
        .{ .key = "", .value = "E" },
        .{ .key = "a", .value = "A" },
        .{ .key = "a\x00", .value = "N" },
        .{ .key = "b", .value = "BB" },
        .{ .key = "empty", .value = "" },
    }, false, null);
    const keys = [_][]const u8{ "zz", "b", "a", "ab", "b", "empty", "", "a\x00", "a" };
    const expected = [_]?[]const u8{ null, "BB", "A", null, "BB", "", "E", "N", "A" };
    var destination: [16]u8 = @splat(0xa5);
    var results: [keys.len]?[]const u8 = undefined;
    try fixture.db.getManyInto(&keys, &destination, &results, 2, null);

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

    try fixture.db.put("b", "changed", false, null);
    try testing.expectEqualStrings("BB", results[1].?);
    try testing.expectEqualStrings("BB", results[4].?);
}

test "getManyInto permits zero byte limits for empty and missing values" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("empty", "", false, null);
    try fixture.db.put("full", "v", false, null);
    const keys = [_][]const u8{ "missing", "empty", "", "empty" };
    var destination: [0]u8 = .{};
    var results: [keys.len]?[]const u8 = undefined;
    try fixture.db.getManyInto(&keys, &destination, &results, 0, null);
    try testing.expectEqual(null, results[0]);
    try testing.expect(results[1] != null);
    try testing.expectEqual(@as(usize, 0), results[1].?.len);
    try testing.expectEqual(null, results[2]);
    try testing.expect(results[3] != null);
    try testing.expectEqual(@as(usize, 0), results[3].?.len);
    try fixture.db.getManyInto(&.{}, &destination, results[0..0], 0, null);

    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{"full"},
        &destination,
        results[0..1],
        0,
        null,
    ));
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
        &.{"full"},
        &destination,
        results[0..1],
        1,
        null,
    ));
    try fixture.close();
}

test "memory_safety: getManyInto enforces per value limits before copying oversized row" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("large", "12345", false, null);
    try fixture.db.put("small", "v", false, null);
    var destination: [16]u8 = @splat(0xa5);
    var results: [2]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{ "large", "small" },
        destination[1..15],
        &results,
        4,
        null,
    ));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{ "small", "large" },
        destination[1..15],
        &results,
        4,
        null,
    ));
    try testing.expectEqual(@as(u8, 0xa5), destination[0]);
    try testing.expectEqual(@as(u8, 0xa5), destination[15]);

    try fixture.db.getManyInto(&.{ "large", "small" }, destination[1..15], &results, 5, null);
    try testing.expectEqualStrings("12345", results[0].?);
    try testing.expectEqualStrings("v", results[1].?);
    try fixture.close();
}

test "memory_safety: getManyInto counts duplicate values against exact aggregate capacity" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("a", "123", false, null);
    try fixture.db.put("b", "45", false, null);
    try fixture.db.put("empty", "", false, null);
    const keys = [_][]const u8{ "a", "b", "a", "empty", "missing" };
    var destination: [10]u8 = @splat(0xa5);
    var results: [keys.len]?[]const u8 = undefined;
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
        &keys,
        destination[1..8],
        &results,
        3,
        null,
    ));
    try testing.expectEqual(@as(u8, 0xa5), destination[0]);
    try testing.expectEqualSlices(u8, &.{ 0xa5, 0xa5 }, destination[8..]);

    try fixture.db.getManyInto(&keys, destination[1..9], &results, 3, null);
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
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("large", "12345", false, null);
    var destination: [3]u8 = @splat(0xa5);
    var results: [1]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{"large"},
        &destination,
        &results,
        4,
        null,
    ));
    try testing.expectEqualSlices(u8, &(@as([3]u8, @splat(0xa5))), &destination);
}

test "getManyInto validates key counts result lengths keys and value limits" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("key", "v", false, null);
    const keys: [leveldb.max_batch_entries + 1][]const u8 = @splat("missing");
    var results: [keys.len]?[]const u8 = undefined;
    var destination: [8]u8 = @splat(0xa5);
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
        &keys,
        &destination,
        &results,
        1,
        null,
    ));
    for ([_]usize{ 0, 2 }) |result_count| {
        try testing.expectError(error.BatchTooLarge, fixture.db.getManyInto(
            &.{"key"},
            &destination,
            results[0..result_count],
            1,
            null,
        ));
    }
    const oversized_key: [leveldb.max_key_bytes + 1]u8 = @splat('k');
    try testing.expectError(error.KeyTooLarge, fixture.db.getManyInto(
        &.{ "key", &oversized_key },
        &destination,
        results[0..2],
        1,
        null,
    ));
    try testing.expectError(error.InvalidReadLimit, fixture.db.getManyInto(
        &.{"key"},
        &destination,
        results[0..1],
        leveldb.max_value_bytes + 1,
        null,
    ));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);

    try fixture.db.getManyInto(
        keys[0..leveldb.max_batch_entries],
        destination[0..0],
        results[0..leveldb.max_batch_entries],
        0,
        null,
    );
    for (results[0..leveldb.max_batch_entries]) |result| try testing.expectEqual(null, result);
    try fixture.close();
    try testing.expectError(error.DatabaseClosed, fixture.db.getManyInto(
        &.{"key"},
        &destination,
        results[0..1],
        1,
        null,
    ));
}

test "write applies ordered puts and deletes and persists after reopening" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("remove", "old", false, null);
    try fixture.db.write(&.{
        .{ .key = "same", .value = "first" },
        .{ .key = "remove", .value = null },
        .{ .key = "same", .value = null },
        .{ .key = "same", .value = "last" },
        .{ .key = "empty", .value = "" },
    }, true, null);
    try fixture.db.write(&.{}, false, null);
    try fixture.close();
    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    }, null);
    fixture.closed = false;

    try expectValue(&fixture.db, "same", "last");
    try expectValue(&fixture.db, "remove", null);
    try expectValue(&fixture.db, "empty", "");
}

test "write validates every key before applying any operation" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("keep", "original", false, null);
    const oversized_key: [leveldb.max_key_bytes + 1]u8 = @splat('k');
    try testing.expectError(error.KeyTooLarge, fixture.db.write(&.{
        .{ .key = "new", .value = "must not appear" },
        .{ .key = "keep", .value = null },
        .{ .key = &oversized_key, .value = "invalid" },
    }, false, null));
    try expectValue(&fixture.db, "new", null);
    try expectValue(&fixture.db, "keep", "original");

    try testing.expectError(error.KeyTooLarge, fixture.db.write(&.{
        .{ .key = "keep", .value = "changed" },
        .{ .key = &oversized_key, .value = null },
    }, false, null));
    try expectValue(&fixture.db, "keep", "original");
}

test "write bounds operation count and counts keys in its aggregate byte limit" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("k", "original", false, null);
    var operations: [leveldb.max_batch_entries + 1]leveldb.Operation = @splat(.{
        .key = "k",
        .value = null,
    });
    try testing.expectError(error.BatchTooLarge, fixture.db.write(&operations, false, null));
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
        null,
    ));
    try expectValue(&fixture.db, "k", "original");

    @memset(&operations, .{ .key = "absent", .value = null });
    try fixture.db.write(operations[0..leveldb.max_batch_entries], false, null);
}

test "maximum length keys work and oversized keys fail at every public boundary" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const key: [leveldb.max_key_bytes + 1]u8 = @splat('k');
    const maximum = key[0..leveldb.max_key_bytes];
    try fixture.db.put(maximum, "v", false, null);
    try expectValue(&fixture.db, maximum, "v");

    var destination: [8]u8 = @splat(0xa5);
    try testing.expectError(error.KeyTooLarge, fixture.db.getInto(&key, &destination, null));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.KeyTooLarge, fixture.db.put(&key, "v", false, null));
    try testing.expectError(error.KeyTooLarge, fixture.db.delete(&key, false, null));
    try testing.expectError(error.KeyTooLarge, fixture.db.cursor(.{ .gte = &key }, null));
    try testing.expectError(error.KeyTooLarge, fixture.db.cursor(.{ .lt = &key }, null));
    try expectValue(&fixture.db, maximum, "v");
    try fixture.db.delete(maximum, false, null);
    try expectValue(&fixture.db, maximum, null);
    try fixture.close();
}

test "open rejects invalid paths and options before creating database" {
    const long_path: [4097:0]u8 = @splat('p');
    for ([_][:0]const u8{ "", "embedded\x00nul", &long_path }) |path| {
        try testing.expectError(error.InvalidPath, leveldb.Database.open(allocator, path, .{}, null));
    }

    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.close();

    for ([_]leveldb.Options{
        .{ .cache_bytes = 1024 * 1024 * 1024 + 1 },
        .{ .write_buffer_bytes = 64 * 1024 - 1 },
        .{ .write_buffer_bytes = 1024 * 1024 * 1024 + 1 },
        .{ .max_open_files = 73 },
        .{ .max_open_files = 4097 },
    }) |options| {
        try testing.expectError(error.InvalidOptions, leveldb.Database.open(
            allocator,
            fixture.path,
            options,
            null,
        ));
    }
    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
        .cache_bytes = 0,
        .write_buffer_bytes = 64 * 1024,
        .max_open_files = 74,
    }, null);
    fixture.closed = false;
    try fixture.db.put("key", "value", false, null);
    try expectValue(&fixture.db, "key", "value");
}

test "memory_safety: cold compressed SSTable reads enforce destination and row limits" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const value = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(value);
    @memset(value, 's');
    try fixture.db.put("compressed", value, true, null);
    try fixture.close();

    // Reopening flushes the recovered log to an SSTable; reopen again to discard engine caches.
    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    }, null);
    fixture.closed = false;
    try fixture.close();
    try expectCompressedTable(&fixture, value.len);

    fixture.db = try leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    }, null);
    fixture.closed = false;
    var small: [16]u8 = @splat(0xa5);
    try testing.expectError(error.ValueTooLarge, fixture.db.getInto("compressed", &small, null));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &small);

    try fixture.reopen();
    var results: [1]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyInto(
        &.{"compressed"},
        &small,
        &results,
        small.len,
        null,
    ));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &small);

    try fixture.reopen();
    var cursor = try fixture.db.cursor(.{}, null);
    defer cursor.close();
    var entries: [1]leveldb.Entry = undefined;
    try testing.expectError(error.ValueTooLarge, cursor.readInto(&small, &entries, small.len, null));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &small);
    try testing.expectError(error.CursorClosed, cursor.readInto(&small, &entries, value.len, null));

    const destination = try allocator.alloc(u8, "compressed".len + value.len);
    defer allocator.free(destination);
    try testing.expectEqualSlices(u8, value, (try fixture.db.getInto("compressed", destination, null)).?);
    var full_cursor = try fixture.db.cursor(.{}, null);
    defer full_cursor.close();
    const page = try full_cursor.readInto(destination, &entries, value.len, null);
    try testing.expectEqual(@as(usize, 1), page.count);
    try testing.expectEqual(destination.len, page.bytes);
    try testing.expect(page.done);
    try expectEntry(&entries[0], "compressed", value);
    full_cursor.close();
    try fixture.close();
}

test "SSTable corruption propagates through reads and failed cursor creation cleans up" {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    try fixture.db.put("key", "value", true, null);
    try fixture.reopen();
    try fixture.close();
    try corruptFirstTableBlock(&fixture);
    try fixture.reopen();

    var diagnostics: leveldb.Diagnostics = .{};
    defer diagnostics.deinit();
    var destination: [8]u8 = @splat(0xa5);
    var results: [1]?[]const u8 = undefined;
    try testing.expectError(error.Corruption, fixture.db.getInto("key", &destination, &diagnostics));
    try testing.expect(std.mem.startsWith(u8, diagnostics.message.?, "Corruption"));
    diagnostics.deinit();
    try testing.expectError(error.Corruption, fixture.db.getManyInto(
        &.{"key"},
        &destination,
        &results,
        destination.len,
        &diagnostics,
    ));
    try testing.expectError(error.Corruption, fixture.db.getManyOwned(
        &.{"key"},
        &results,
        destination.len,
        destination.len,
        false,
        &diagnostics,
    ));
    try testing.expect(std.mem.startsWith(u8, diagnostics.message.?, "Corruption"));
    diagnostics.deinit();
    try testing.expectEqual(null, results[0]);
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xa5))), &destination);
    try testing.expectError(error.Corruption, fixture.db.cursor(.{ .gte = "key", .lt = "z" }, &diagnostics));
    try fixture.close();
    try testing.expect(std.mem.startsWith(u8, diagnostics.message.?, "Corruption"));
}

test "owned getMany returns independent exact allocations with caller byte limits" {
    var failing = testing.FailingAllocator.init(allocator, .{});
    var fixture: helpers.Fixture = undefined;
    try fixture.init(failing.allocator());
    defer fixture.deinit();
    try fixture.db.put("a", "one", false, null);
    try fixture.db.put("empty", "", false, null);
    const keys = [_][]const u8{ "a", "missing", "empty", "a" };
    var results: [keys.len]?[]const u8 = undefined;
    const before = failing.allocated_bytes;
    try fixture.db.getManyOwned(&keys, &results, 1024 * 1024 * 1024, 1024 * 1024 * 1024, false, null);
    defer helpers.freeValues(failing.allocator(), &results);
    try testing.expectEqualStrings("one", results[0].?);
    try testing.expectEqual(null, results[1]);
    try testing.expectEqualStrings("", results[2].?);
    try testing.expectEqualStrings("one", results[3].?);
    try testing.expect(results[0].?.ptr != results[3].?.ptr);
    try testing.expect(failing.allocated_bytes - before < 1024);
    try fixture.close();
    try testing.expectEqualStrings("one", results[0].?);
}

test "owned getMany enforces value and total limits and releases partial results" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "12345", false, null);
    try fixture.db.put("empty", "", false, null);
    var results: [2]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyOwned(&.{ "a", "a" }, &results, 4, 1, true, null));
    for (results) |value| try testing.expectEqual(null, value);
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyOwned(&.{ "a", "a" }, &results, 5, 9, false, null));
    for (results) |value| try testing.expectEqual(null, value);
    try fixture.db.getManyOwned(&.{ "missing", "empty" }, &results, 0, 0, true, null);
    defer helpers.freeValues(allocator, &results);
    try testing.expectEqual(null, results[0]);
    try testing.expectEqualStrings("", results[1].?);
}

test "memory_safety: owned getMany frees every partial allocation and nulls outputs" {
    for (0..3) |fail_index| {
        var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var fixture: helpers.Fixture = undefined;
        try fixture.init(failing.allocator());
        defer fixture.deinit();
        try fixture.db.put("a", "value", false, null);
        var results: [3]?[]const u8 = undefined;
        try testing.expectError(error.OutOfMemory, fixture.db.getManyOwned(
            &.{ "a", "a", "a" },
            &results,
            5,
            15,
            true,
            null,
        ));
        for (results) |value| try testing.expectEqual(null, value);
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "owned reads and atomic writes accept more than 1024 entries" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    const count = leveldb.max_batch_entries + 1;
    const operations = try allocator.alloc(leveldb.Operation, count);
    defer allocator.free(operations);
    @memset(operations, .{ .key = "a", .value = "v" });
    try fixture.db.writeWithLimits(operations, false, .{
        .max_entries = count,
        .max_total_bytes = count * 2,
        .max_value_bytes = 1,
    }, null);
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    @memset(keys, "a");
    const results = try allocator.alloc(?[]const u8, count);
    defer allocator.free(results);
    try fixture.db.getManyOwned(keys, results, 1, count, true, null);
    defer helpers.freeValues(allocator, results);
    for (results) |value| try testing.expectEqualStrings("v", value.?);
    operations[count - 1].value = "too large";
    operations[0] = .{ .key = "new", .value = "v" };
    try testing.expectError(error.ValueTooLarge, fixture.db.writeWithLimits(operations, false, .{
        .max_entries = count,
        .max_total_bytes = count * 4,
        .max_value_bytes = 1,
    }, null));
    var buffer: [1]u8 = undefined;
    try testing.expectEqual(null, try fixture.db.getInto("new", &buffer, null));
}

test "owned read limits reject oversized budgets and clear output metadata" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "A", false, null);
    const budgets = [_][2]usize{
        .{ leveldb.max_owned_value_bytes + 1, leveldb.max_owned_batch_bytes },
        .{ leveldb.max_owned_value_bytes, leveldb.max_owned_batch_bytes + 1 },
    };
    for (budgets) |budget| {
        var results = [_]?[]const u8{"sentinel"};
        try testing.expectError(error.InvalidReadLimit, fixture.db.getManyOwned(
            &.{"a"},
            &results,
            budget[0],
            budget[1],
            false,
            null,
        ));
        try testing.expectEqual(null, results[0]);
    }
    var results: [1]?[]const u8 = undefined;
    try fixture.db.getManyOwned(&.{"a"}, &results, leveldb.max_owned_value_bytes, leveldb.max_owned_batch_bytes, true, null);
    helpers.freeValues(allocator, &results);
    try fixture.close();
    try testing.expectError(error.DatabaseClosed, fixture.db.getManyOwned(&.{"a"}, &results, 1, 1, true, null));
    try testing.expectEqual(null, results[0]);
}

test "owned getMany validation failures null all bounded result slots" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    var results = [_]?[]const u8{ "sentinel", "sentinel" };
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyOwned(&.{"a"}, &results, 1, 1, true, null));
    for (results) |value| try testing.expectEqual(null, value);
    const oversized_key = [_]u8{'k'} ** (leveldb.max_key_bytes + 1);
    try testing.expectError(error.KeyTooLarge, fixture.db.getManyOwned(&.{ "a", &oversized_key }, &results, 1, 1, true, null));
    for (results) |value| try testing.expectEqual(null, value);
}

test "write limits enforce value bytes total bytes and entry counts" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try testing.expectError(error.ValueTooLarge, fixture.db.writeWithLimits(&.{}, false, .{
        .max_value_bytes = leveldb.max_owned_value_bytes + 1,
        .max_total_bytes = leveldb.max_owned_batch_bytes,
        .max_entries = leveldb.max_bulk_entries,
    }, null));
    try testing.expectError(error.BatchTooLarge, fixture.db.writeWithLimits(&.{}, false, .{
        .max_value_bytes = leveldb.max_owned_value_bytes,
        .max_total_bytes = leveldb.max_owned_batch_bytes + 1,
        .max_entries = leveldb.max_bulk_entries,
    }, null));
    try fixture.db.writeWithLimits(&.{}, false, .{
        .max_value_bytes = leveldb.max_owned_value_bytes,
        .max_total_bytes = leveldb.max_owned_batch_bytes,
        .max_entries = leveldb.max_bulk_entries,
    }, null);
    var operations: [leveldb.max_batch_entries + 1]leveldb.Operation = undefined;
    @memset(&operations, .{ .key = "a", .value = "A" });
    try testing.expectError(error.BatchTooLarge, fixture.db.write(&operations, false, null));
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

test "clear deletes multiple chunks and preserves existing cursor snapshot" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    for (0..1100) |index| {
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, @intCast(index), .big);
        try fixture.db.put(&key, "value", false, null);
    }
    var snapshot = try fixture.db.cursor(.{ .limit = 1 }, null);
    defer snapshot.close();
    try fixture.db.clear(null);
    var entries: [1]leveldb.Entry = undefined;
    var buffer: [16]u8 = undefined;
    const old = try snapshot.readInto(&buffer, &entries, 5, null);
    try testing.expect(old.done);
    try testing.expectEqualStrings("value", entries[0].value);
    var empty = try fixture.db.cursor(.{}, null);
    defer empty.close();
    const page = try empty.readInto(&buffer, &entries, 5, null);
    try testing.expectEqual(@as(usize, 0), page.count);
    try fixture.db.put("new", "new", false, null);
    try testing.expectEqualStrings("new", (try fixture.db.getInto("new", &buffer, null)).?);
}

test "clear preflight bounds fail without partial deletion and empty clear permits zero budget" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    fixture.db.clear_max_entries = 0;
    try fixture.db.clear(null);
    try fixture.db.put("a", "A", false, null);
    try fixture.db.put("b", "B", false, null);
    fixture.db.clear_max_entries = 1;
    try testing.expectError(error.ClearLimitExceeded, fixture.db.clear(null));
    var buffer: [1]u8 = undefined;
    try testing.expectEqualStrings("A", (try fixture.db.getInto("a", &buffer, null)).?);
    try testing.expectEqualStrings("B", (try fixture.db.getInto("b", &buffer, null)).?);
    fixture.db.clear_max_entries = 2;
    try fixture.db.clear(null);
    try testing.expectEqual(null, try fixture.db.getInto("a", &buffer, null));
}

test "maintenance compact estimate property and destroy operate on real disk" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("key", &([_]u8{'x'} ** 8192), true, null);
    try fixture.db.compactRange(null, null);
    try testing.expect(try fixture.db.approximateSize("", "z") > 0);
    try testing.expectEqual(@as(u64, 0), try fixture.db.approximateSize("key", "key"));
    try testing.expectEqual(null, try fixture.db.propertyValue("unknown-property"));
    const property = (try fixture.db.propertyValue("leveldb.stats")).?;
    defer allocator.free(property);
    try testing.expect(property.len > 0);
    try testing.expectError(error.InvalidProperty, fixture.db.propertyValue("leveldb.stats\x00suffix"));
    try fixture.close();
    try testing.expect(property.len > 0);
    try leveldb.destroy(fixture.path, null);
    try testing.expectError(error.InvalidArgument, leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    }, null));
    try testing.expectError(error.InvalidPath, leveldb.destroy("", null));
    try testing.expectError(error.InvalidPath, leveldb.destroy("not\x00a-path", null));
    try testing.expectError(error.DatabaseClosed, fixture.db.clear(null));
    try testing.expectError(error.DatabaseClosed, fixture.db.approximateSize("", "z"));
    try testing.expectError(error.DatabaseClosed, fixture.db.compactRange(null, null));
    try testing.expectError(error.DatabaseClosed, fixture.db.propertyValue("leveldb.stats"));
}

test "property copy allocation failure leaves database usable" {
    var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var fixture: helpers.Fixture = undefined;
    try fixture.init(failing.allocator());
    defer fixture.deinit();
    try testing.expectError(error.OutOfMemory, fixture.db.propertyValue("leveldb.stats"));
    try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    try fixture.db.put("a", "A", false, null);
    var buffer: [1]u8 = undefined;
    try testing.expectEqualStrings("A", (try fixture.db.getInto("a", &buffer, null)).?);
}

test "clear rejects budgets above u32 before mutation" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "A", false, null);
    fixture.db.clear_max_entries = @as(u64, std.math.maxInt(u32)) + 1;
    try testing.expectError(error.InvalidOptions, fixture.db.clear(null));
    var buffer: [1]u8 = undefined;
    try testing.expectEqualStrings("A", (try fixture.db.getInto("a", &buffer, null)).?);
    try testing.expectError(error.InvalidOptions, leveldb.Database.open(allocator, fixture.path, .{
        .clear_max_entries = fixture.db.clear_max_entries,
    }, null));
}
