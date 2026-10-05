const std = @import("std");
const raw = @import("raw.zig");
const Allocator = std.mem.Allocator;

pub const max_entries = 16_777_216;
pub const Entry = struct { key: []const u8, value: []const u8 };

pub const ReadOptions = struct {
    max_value_bytes: usize,
    max_total_bytes: usize,
    fill_cache: bool,
};

pub fn freeEntry(allocator: Allocator, entry: *const Entry) void {
    allocator.free(entry.key);
    allocator.free(entry.value);
}

pub fn copyEntry(allocator: Allocator, key: []const u8, value: []const u8) !Entry {
    const key_copy = try allocator.dupe(u8, key);
    errdefer allocator.free(key_copy);

    const value_copy = try allocator.dupe(u8, value);
    errdefer allocator.free(value_copy);

    return .{ .key = key_copy, .value = value_copy };
}

/// One iterator keeps a consistent view. Copy each value before moving it.
pub fn getMany(
    db: *raw.DB,
    allocator: Allocator,
    keys: []const []const u8,
    results: []?[]const u8,
    options: *const ReadOptions,
    key_limit: usize,
    diagnostics: ?*raw.Diagnostics,
) !void {
    if (results.len > max_entries) return error.BatchTooLarge;
    @memset(results, null);
    if (keys.len > max_entries or keys.len != results.len) return error.BatchTooLarge;
    for (keys) |key| if (key.len > key_limit) return error.KeyTooLarge;

    var read_options = try raw.ReadOptions.create();
    defer read_options.destroy();
    read_options.setFillCache(options.fill_cache);
    read_options.setVerifyChecksums(true);

    var iterator = try db.createIterator(&read_options);
    defer iterator.destroy();

    errdefer {
        for (results) |value| if (value) |bytes| allocator.free(bytes);
        @memset(results, null);
    }

    var total: usize = 0;
    for (keys, results) |key, *output| {
        if (try lookup(&iterator, key, diagnostics)) |value| {
            if (value.len > options.max_value_bytes) return error.ValueTooLarge;
            if (value.len > options.max_total_bytes - total) return error.BatchTooLarge;
            output.* = try allocator.dupe(u8, value);
            total += value.len;
        }
    }
}

fn lookup(iterator: *raw.Iterator, key: []const u8, diagnostics: ?*raw.Diagnostics) !?[]const u8 {
    iterator.seek(key);
    try iterator.getError(diagnostics);
    if (!iterator.valid() or !std.mem.eql(u8, iterator.key(), key)) return null;
    return iterator.value();
}
