const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const fs = @import("fs.zig");

pub const KeystoreLock = struct {
    allocator: Allocator,
    path: []const u8,
    file: Io.File,

    pub fn acquire(io: Io, allocator: Allocator, keystore_path: []const u8) !KeystoreLock {
        const abs_path = try fs.resolvePath(allocator, keystore_path);
        defer allocator.free(abs_path);

        const file = Io.Dir.openFileAbsolute(io, abs_path, .{
            .mode = .read_only,
            .allow_directory = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
        }) catch |err| switch (err) {
            error.WouldBlock => return error.KeystoreLocked,
            else => return err,
        };
        errdefer file.close(io);

        return .{
            .allocator = allocator,
            .path = try allocator.dupe(u8, keystore_path),
            .file = file,
        };
    }

    pub fn deinit(self: *KeystoreLock, io: Io) void {
        self.file.close(io);
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

const testing = std.testing;

test "KeystoreLock acquires and releases a keystore file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("0x" ++ "11" ** 48);
    try tmp.dir.writeFile(.{
        .sub_path = "0x" ++ "11" ** 48 ++ "/voting-keystore.json",
        .data = "{\"version\":4}",
    });

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const keystore_path = try std.fs.path.join(testing.allocator, &.{
        root,
        "0x" ++ "11" ** 48,
        "voting-keystore.json",
    });
    defer testing.allocator.free(keystore_path);

    var lock = try KeystoreLock.acquire(testing.io, testing.allocator, keystore_path);
    defer lock.deinit(testing.io);

    try testing.expectEqualStrings(keystore_path, lock.path);
}
