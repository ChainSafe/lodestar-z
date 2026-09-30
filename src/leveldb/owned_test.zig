const std = @import("std");
const leveldb = @import("root.zig");
const testing = std.testing;
const allocator = testing.allocator;
const helpers = @import("test_utils.zig");

test "owned getMany returns independent exact allocations with caller byte limits" {
    var failing = testing.FailingAllocator.init(allocator, .{});
    var fixture: helpers.Fixture = undefined;
    try fixture.init(failing.allocator());
    defer fixture.deinit();
    try fixture.db.put("a", "one", false);
    try fixture.db.put("empty", "", false);
    const keys = [_][]const u8{ "a", "missing", "empty", "a" };
    var results: [keys.len]?[]const u8 = undefined;
    const before = failing.allocated_bytes;
    try fixture.db.getManyOwned(&keys, &results, 1024 * 1024 * 1024, 1024 * 1024 * 1024, false);
    defer helpers.freeValues(failing.allocator(), &results);
    try testing.expectEqualStrings("one", results[0].?);
    try testing.expectEqual(null, results[1]);
    try testing.expectEqualStrings("", results[2].?);
    try testing.expectEqualStrings("one", results[3].?);
    try testing.expect(results[0].?.ptr != results[3].?.ptr);
    try testing.expectEqual(keys.len * @sizeOf(?usize) + 6, failing.allocated_bytes - before);
    try fixture.close();
    try testing.expectEqualStrings("one", results[0].?);
}

test "owned getMany enforces value and total limits before allocating result bytes" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "12345", false);
    try fixture.db.put("empty", "", false);
    var results: [2]?[]const u8 = undefined;
    try testing.expectError(error.ValueTooLarge, fixture.db.getManyOwned(&.{ "a", "a" }, &results, 4, 1, true));
    for (results) |value| try testing.expectEqual(null, value);
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyOwned(&.{ "a", "a" }, &results, 5, 9, false));
    for (results) |value| try testing.expectEqual(null, value);
    try fixture.db.getManyOwned(&.{ "missing", "empty" }, &results, 0, 0, true);
    defer helpers.freeValues(allocator, &results);
    try testing.expectEqual(null, results[0]);
    try testing.expectEqualStrings("", results[1].?);
}

test "memory_safety: owned getMany frees every partial allocation and nulls outputs" {
    for (0..4) |fail_index| {
        var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var fixture: helpers.Fixture = undefined;
        try fixture.init(failing.allocator());
        defer fixture.deinit();
        try fixture.db.put("a", "value", false);
        var results: [3]?[]const u8 = undefined;
        try testing.expectError(error.OutOfMemory, fixture.db.getManyOwned(
            &.{ "a", "a", "a" },
            &results,
            5,
            15,
            true,
        ));
        for (results) |value| try testing.expectEqual(null, value);
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "owned reads and atomic writes accept bulk counts above legacy count limit" {
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
    });
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    @memset(keys, "a");
    const results = try allocator.alloc(?[]const u8, count);
    defer allocator.free(results);
    try fixture.db.getManyOwned(keys, results, 1, count, true);
    defer helpers.freeValues(allocator, results);
    for (results) |value| try testing.expectEqualStrings("v", value.?);
    operations[count - 1].value = "too large";
    operations[0] = .{ .key = "new", .value = "v" };
    try testing.expectError(error.ValueTooLarge, fixture.db.writeWithLimits(operations, false, .{
        .max_entries = count,
        .max_total_bytes = count * 4,
        .max_value_bytes = 1,
    }));
    var buffer: [1]u8 = undefined;
    try testing.expectEqual(null, try fixture.db.getInto("new", &buffer));
}

test "owned pages allocate actual bytes and defer rows without losing iterator position" {
    var failing = testing.FailingAllocator.init(allocator, .{});
    var fixture: helpers.Fixture = undefined;
    try fixture.init(failing.allocator());
    defer fixture.deinit();
    try fixture.db.put("a", "AA", false);
    try fixture.db.put("b", "BB", false);
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();
    var entries: [2]leveldb.Entry = undefined;
    const first = try cursor.readOwned(&entries, 1024 * 1024 * 1024, 3);
    try testing.expectEqual(@as(usize, 1), first.count);
    try testing.expect(!first.done);
    try testing.expectEqualStrings("a", entries[0].key);
    helpers.freeEntries(failing.allocator(), entries[0..first.count]);
    const second = try cursor.readOwned(&entries, 1024 * 1024 * 1024, 1024 * 1024 * 1024);
    defer helpers.freeEntries(failing.allocator(), entries[0..second.count]);
    try testing.expectEqual(@as(usize, 1), second.count);
    try testing.expect(second.done);
    try testing.expectEqualStrings("b", entries[0].key);
    try testing.expectEqualStrings("BB", entries[0].value);
    try testing.expectEqual(@as(usize, 6), failing.allocated_bytes);
    try fixture.close();
    try testing.expectEqualStrings("BB", entries[0].value);
}

test "memory_safety: owned pages clean up partial copies on allocation or row limit failure" {
    for (0..4) |fail_index| {
        var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var fixture: helpers.Fixture = undefined;
        try fixture.init(failing.allocator());
        defer fixture.deinit();
        try fixture.db.put("a", "A", false);
        try fixture.db.put("b", "B", false);
        var cursor = try fixture.db.cursor(.{});
        defer cursor.close();
        var entries: [2]leveldb.Entry = undefined;
        try testing.expectError(error.OutOfMemory, cursor.readOwned(&entries, 1, 4));
        try testing.expectEqual(@as(u32, 0), fixture.db.cursors);
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        for (entries) |entry| {
            try testing.expectEqual(@as(usize, 0), entry.key.len);
            try testing.expectEqual(@as(usize, 0), entry.value.len);
        }
    }
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "A", false);
    try fixture.db.put("b", "BB", false);
    var cursor = try fixture.db.cursor(.{});
    defer cursor.close();
    var entries: [2]leveldb.Entry = undefined;
    try testing.expectError(error.ValueTooLarge, cursor.readOwned(&entries, 1, 10));
    for (entries) |entry| try testing.expectEqual(@as(usize, 0), entry.value.len);
    try fixture.close();
}

test "owned pages reject first row aggregate overflow and invalid metadata counts" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("key", "value", false);
    var entries: [leveldb.max_batch_entries + 1]leveldb.Entry = undefined;
    var first = try fixture.db.cursor(.{});
    defer first.close();
    try testing.expectError(error.BatchTooLarge, first.readOwned(entries[0..1], 5, 7));
    var invalid = try fixture.db.cursor(.{});
    defer invalid.close();
    try testing.expectError(error.InvalidReadLimit, invalid.readOwned(&entries, 5, 8));
    try testing.expectEqual(@as(u32, 0), fixture.db.cursors);
}

test "owned read limits reject oversized budgets and clear output metadata" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "A", false);
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
        ));
        try testing.expectEqual(null, results[0]);
        var cursor = try fixture.db.cursor(.{});
        defer cursor.close();
        var entries = [_]leveldb.Entry{.{ .key = "sentinel", .value = "sentinel" }};
        try testing.expectError(error.InvalidReadLimit, cursor.readOwned(&entries, budget[0], budget[1]));
        try testing.expectEqual(@as(usize, 0), entries[0].key.len);
        try testing.expectEqual(@as(usize, 0), entries[0].value.len);
        try testing.expectEqual(@as(u32, 0), fixture.db.cursors);
    }
    var results: [1]?[]const u8 = undefined;
    try fixture.db.getManyOwned(&.{"a"}, &results, leveldb.max_owned_value_bytes, leveldb.max_owned_batch_bytes, true);
    helpers.freeValues(allocator, &results);
    try fixture.close();
    try testing.expectError(error.DatabaseClosed, fixture.db.getManyOwned(&.{"a"}, &results, 1, 1, true));
    try testing.expectEqual(null, results[0]);
}

test "owned getMany validation failures null all bounded result slots" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    var results = [_]?[]const u8{ "sentinel", "sentinel" };
    try testing.expectError(error.BatchTooLarge, fixture.db.getManyOwned(&.{"a"}, &results, 1, 1, true));
    for (results) |value| try testing.expectEqual(null, value);
    const oversized_key = [_]u8{'k'} ** (leveldb.max_key_bytes + 1);
    try testing.expectError(error.KeyTooLarge, fixture.db.getManyOwned(&.{ "a", &oversized_key }, &results, 1, 1, true));
    for (results) |value| try testing.expectEqual(null, value);
}

test "extended write budgets retain hard ceilings and legacy entry limits" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try testing.expectError(error.ValueTooLarge, fixture.db.writeWithLimits(&.{}, false, .{
        .max_value_bytes = leveldb.max_owned_value_bytes + 1,
        .max_total_bytes = leveldb.max_owned_batch_bytes,
        .max_entries = leveldb.max_bulk_entries,
    }));
    try testing.expectError(error.BatchTooLarge, fixture.db.writeWithLimits(&.{}, false, .{
        .max_value_bytes = leveldb.max_owned_value_bytes,
        .max_total_bytes = leveldb.max_owned_batch_bytes + 1,
        .max_entries = leveldb.max_bulk_entries,
    }));
    try fixture.db.writeWithLimits(&.{}, false, .{
        .max_value_bytes = leveldb.max_owned_value_bytes,
        .max_total_bytes = leveldb.max_owned_batch_bytes,
        .max_entries = leveldb.max_bulk_entries,
    });
    var operations: [leveldb.max_batch_entries + 1]leveldb.Operation = undefined;
    @memset(&operations, .{ .key = "a", .value = "A" });
    try testing.expectError(error.BatchTooLarge, fixture.db.write(&operations, false));
}
