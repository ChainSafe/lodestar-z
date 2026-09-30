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

/// Both passes use one iterator's consistent view. No borrowed bytes survive an iterator move.
pub fn getMany(
    db: *raw.DB,
    allocator: Allocator,
    keys: []const []const u8,
    results: []?[]const u8,
    options: *const ReadOptions,
    key_limit: usize,
) !void {
    if (results.len > max_entries) return error.BatchTooLarge;
    @memset(results, null);
    if (keys.len > max_entries or keys.len != results.len) return error.BatchTooLarge;
    for (keys) |key| if (key.len > key_limit) return error.KeyTooLarge;

    const lengths = try allocator.alloc(?usize, keys.len);
    defer allocator.free(lengths);

    var read_options = try raw.ReadOptions.create();
    defer read_options.destroy();
    read_options.setFillCache(options.fill_cache);
    read_options.setVerifyChecksums(true);

    var iterator = try db.createIterator(&read_options);
    defer iterator.destroy();

    var total: usize = 0;
    for (keys, lengths) |key, *length| {
        const value = try lookup(&iterator, key);
        length.* = if (value) |bytes| bytes.len else null;
        if (value) |bytes| {
            if (bytes.len > options.max_value_bytes) return error.ValueTooLarge;
            if (bytes.len > options.max_total_bytes - total) return error.BatchTooLarge;
            total += bytes.len;
        }
    }

    errdefer {
        for (results) |value| if (value) |bytes| allocator.free(bytes);
        @memset(results, null);
    }

    for (keys, lengths, results) |key, length, *output| {
        if (length) |expected| {
            const value = (try lookup(&iterator, key)) orelse return error.InconsistentRead;
            if (value.len != expected) return error.InconsistentRead;
            output.* = try allocator.dupe(u8, value);
        }
    }
}

fn lookup(iterator: *raw.Iterator, key: []const u8) !?[]const u8 {
    iterator.seek(key);
    try iterator.getError();
    if (!iterator.valid() or !std.mem.eql(u8, iterator.key(), key)) return null;
    return iterator.value();
}

test {
    _ = @import("owned_test.zig");
}
