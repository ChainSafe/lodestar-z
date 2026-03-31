const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn resolvePath(allocator: Allocator, path: []const u8) ![]u8 {
    return std.fs.path.resolve(allocator, &.{ ".", path });
}

pub fn readFileAlloc(io: Io, allocator: Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const abs_path = try resolvePath(allocator, path);
    defer allocator.free(abs_path);

    const file = try Io.Dir.openFileAbsolute(io, abs_path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    const len: usize = @intCast(@min(stat.size, max_bytes));
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    return buf[0..n];
}
