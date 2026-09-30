const std = @import("std");
const leveldb = @import("root.zig");
const testing = std.testing;
const allocator = testing.allocator;
const helpers = @import("test_utils.zig");

test "clear deletes multiple chunks and preserves existing cursor snapshot" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    for (0..1100) |index| {
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, @intCast(index), .big);
        try fixture.db.put(&key, "value", false);
    }
    var snapshot = try fixture.db.cursor(.{ .limit = 1 });
    defer snapshot.close();
    try fixture.db.clear();
    var entries: [1]leveldb.Entry = undefined;
    var buffer: [16]u8 = undefined;
    const old = try snapshot.readInto(&buffer, &entries, 5);
    try testing.expect(old.done);
    try testing.expectEqualStrings("value", entries[0].value);
    var empty = try fixture.db.cursor(.{});
    defer empty.close();
    const page = try empty.readInto(&buffer, &entries, 5);
    try testing.expectEqual(@as(usize, 0), page.count);
    try fixture.db.put("new", "new", false);
    try testing.expectEqualStrings("new", (try fixture.db.getInto("new", &buffer)).?);
}

test "clear preflight bounds fail without partial deletion and empty clear permits zero budget" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    fixture.db.clear_max_entries = 0;
    try fixture.db.clear();
    try fixture.db.put("a", "A", false);
    try fixture.db.put("b", "B", false);
    fixture.db.clear_max_entries = 1;
    try testing.expectError(error.ClearLimitExceeded, fixture.db.clear());
    var buffer: [1]u8 = undefined;
    try testing.expectEqualStrings("A", (try fixture.db.getInto("a", &buffer)).?);
    try testing.expectEqualStrings("B", (try fixture.db.getInto("b", &buffer)).?);
    fixture.db.clear_max_entries = 2;
    try fixture.db.clear();
    try testing.expectEqual(null, try fixture.db.getInto("a", &buffer));
}

test "maintenance compact estimate property and destroy operate on real disk" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("key", &([_]u8{'x'} ** 8192), true);
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
    try leveldb.destroy(fixture.path);
    try testing.expectError(error.InvalidArgument, leveldb.Database.open(allocator, fixture.path, .{
        .create_if_missing = false,
    }));
    try testing.expectError(error.InvalidPath, leveldb.destroy(""));
    try testing.expectError(error.InvalidPath, leveldb.destroy("not\x00a-path"));
    try testing.expectError(error.DatabaseClosed, fixture.db.clear());
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
    try fixture.db.put("a", "A", false);
    var buffer: [1]u8 = undefined;
    try testing.expectEqualStrings("A", (try fixture.db.getInto("a", &buffer)).?);
}

test "property copy admits one MiB and rejects larger output before allocation" {
    const maintenance = @import("maintenance.zig");
    const value = try allocator.alloc(u8, 1024 * 1024 + 1);
    defer allocator.free(value);
    @memset(value, 'x');
    var failing = testing.FailingAllocator.init(allocator, .{});
    const copy = try maintenance.copyProperty(failing.allocator(), value[0 .. value.len - 1]);
    try testing.expectEqualSlices(u8, value[0 .. value.len - 1], copy);
    failing.allocator().free(copy);
    const allocated = failing.allocated_bytes;
    try testing.expectError(error.ValueTooLarge, maintenance.copyProperty(failing.allocator(), value));
    try testing.expectEqual(allocated, failing.allocated_bytes);
    try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "clear rejects budgets above u32 before mutation" {
    var fixture: helpers.Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try fixture.db.put("a", "A", false);
    fixture.db.clear_max_entries = @as(u64, std.math.maxInt(u32)) + 1;
    try testing.expectError(error.InvalidOptions, fixture.db.clear());
    var buffer: [1]u8 = undefined;
    try testing.expectEqualStrings("A", (try fixture.db.getInto("a", &buffer)).?);
    try testing.expectError(error.InvalidOptions, leveldb.Database.open(allocator, fixture.path, .{
        .clear_max_entries = fixture.db.clear_max_entries,
    }));
}
