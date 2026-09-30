const std = @import("std");
const leveldb = @import("root.zig");
const allocator = std.testing.allocator;

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
        self.db = try leveldb.Database.open(db_allocator, self.path, .{});
        self.closed = false;
    }

    pub fn close(self: *Fixture) !void {
        try self.db.close();
        self.closed = true;
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
