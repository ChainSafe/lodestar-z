const std = @import("std");
const leveldb = @import("root.zig");
const testing = std.testing;
const allocator = testing.allocator;

pub const Fixture = struct {
    tmp: std.testing.TmpDir,
    path: [:0]u8,
    db: leveldb.Database,
    closed: bool = false,

    pub fn init(self: *Fixture, db_allocator: std.mem.Allocator) !void {
        self.tmp = std.testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        const directory = try self.tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
        defer allocator.free(directory);
        self.path = try std.fmt.allocPrintSentinel(allocator, "{s}/database", .{directory}, 0);
        errdefer allocator.free(self.path);
        self.db = try leveldb.Database.open(db_allocator, self.path, .{}, null);
        self.closed = false;
    }

    pub fn close(self: *Fixture) !void {
        try self.db.close();
        self.closed = true;
    }

    pub fn reopen(self: *Fixture) !void {
        try self.close();
        self.db = try leveldb.Database.open(self.db.allocator, self.path, .{ .create_if_missing = false }, null);
        self.closed = false;
    }

    pub fn deinit(self: *Fixture) void {
        if (!self.closed) self.db.close() catch unreachable;
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

pub fn freeEntries(db_allocator: std.mem.Allocator, entries: []const leveldb.Entry) void {
    for (entries) |entry| {
        db_allocator.free(entry.key);
        db_allocator.free(entry.value);
    }
}

pub fn freeValues(db_allocator: std.mem.Allocator, values: []const ?[]const u8) void {
    for (values) |value| if (value) |bytes| db_allocator.free(bytes);
}

pub fn expectValue(db: *leveldb.Database, key: []const u8, expected: ?[]const u8) !void {
    var destination: [128]u8 = @splat(0xa5);
    const actual = try db.getInto(key, &destination, null);
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

pub fn expectEntry(entry: *const leveldb.Entry, key: []const u8, value: []const u8) !void {
    try testing.expectEqualSlices(u8, key, entry.key);
    try testing.expectEqualSlices(u8, value, entry.value);
}
