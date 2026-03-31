const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

var rc_config_map: ?std.StringHashMap([]const u8) = null;
var rc_config_arena: ?std.heap.ArenaAllocator = null;

pub fn resolver(name: []const u8) ?[]const u8 {
    const map = rc_config_map orelse return null;
    return map.get(name);
}

pub fn hasLoadedConfig() bool {
    return rc_config_map != null;
}

pub fn load(allocator: Allocator, io: Io, path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    const arena_alloc = arena.allocator();

    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    const content = try arena_alloc.alloc(u8, stat.size);
    const n = try file.readPositionalAll(io, content, 0);
    if (n != stat.size) return error.ShortRead;

    var map = std.StringHashMap([]const u8).init(arena_alloc);
    var lines = std.mem.splitScalar(u8, content[0..n], '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const key = std.mem.trim(u8, trimmed[0..colon], " \t");
            const val = std.mem.trim(u8, trimmed[colon + 1 ..], " \t\"'");
            if (key.len > 0 and val.len > 0) {
                try map.put(key, val);
            }
        }
    }

    rc_config_arena = arena;
    rc_config_map = map;
}

pub fn deinit() void {
    if (rc_config_arena) |*arena| {
        arena.deinit();
    }
    rc_config_arena = null;
    rc_config_map = null;
}
