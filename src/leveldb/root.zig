//! Bounded result materialization over LevelDB. Database operations may run concurrently; callers serialize each
//! cursor, keep Database addresses stable and close only after all users retire. Engine reads, decompression,
//! cache and compaction are outside these result bounds.
const std = @import("std");
const raw = @import("raw.zig");
const ranges = @import("range.zig");
const owned = @import("owned.zig");
const maintenance = @import("maintenance.zig");
const Allocator = std.mem.Allocator;

pub const max_key_bytes = 4096;
pub const max_path_bytes = 4096;
pub const max_value_bytes = 64 * 1024 * 1024;
pub const max_batch_bytes = 64 * 1024 * 1024;
pub const max_batch_entries = 1024;
pub const max_cursors = 64;
pub const max_bulk_entries = owned.max_entries;
pub const max_owned_value_bytes: usize = 1024 * 1024 * 1024;
pub const max_owned_batch_bytes: usize = 4 * 1024 * 1024 * 1024;

pub const Options = struct {
    create_if_missing: bool = true,
    error_if_exists: bool = false,
    cache_bytes: usize = 8 * 1024 * 1024,
    write_buffer_bytes: usize = 4 * 1024 * 1024,
    max_open_files: u32 = 64,
    clear_max_entries: u64 = std.math.maxInt(u32),
};
pub const Operation = struct { key: []const u8, value: ?[]const u8 };
pub const RangeOptions = ranges.Options;
/// readInto borrows destination; readOwned allocates each selected key and value separately.
pub const Entry = owned.Entry;
pub const WriteLimits = struct {
    max_value_bytes: usize,
    max_total_bytes: usize,
    max_entries: usize,
};
pub const Page = struct { count: usize, bytes: usize, done: bool };

pub const Database = struct {
    allocator: Allocator,
    inner: ?raw.DB,
    cache: raw.Cache,
    cursors: std.atomic.Value(u32) = .init(0),
    clear_max_entries: u64 = std.math.maxInt(u32),

    /// The host ensures one owner per physical directory, across path aliases, workers and other storage engines.
    /// POSIX process-scoped engine locks do not enforce this obligation between independent library copies.
    pub fn open(allocator: Allocator, path: [:0]const u8, options: Options) !Database {
        try checkPath(path);
        if (options.cache_bytes > 1024 * 1024 * 1024 or
            options.write_buffer_bytes < 64 * 1024 or options.write_buffer_bytes > 1024 * 1024 * 1024 or
            options.max_open_files < 20 or options.max_open_files > 4096 or
            options.clear_max_entries > std.math.maxInt(u32)) return error.InvalidOptions;
        var raw_options = try raw.Options.create();
        defer raw_options.destroy();
        var cache = try raw.Cache.createLru(options.cache_bytes);
        errdefer cache.destroy();

        raw_options.setCache(&cache);
        raw_options.setCreateIfMissing(options.create_if_missing);
        raw_options.setErrorIfExists(options.error_if_exists);
        raw_options.setParanoidChecks(true);
        raw_options.setWriteBufferSize(options.write_buffer_bytes);
        raw_options.setMaxOpenFiles(@intCast(options.max_open_files));
        const db = try raw.DB.open(&raw_options, path);
        return .{
            .allocator = allocator,
            .inner = db,
            .cache = cache,
            .clear_max_entries = options.clear_max_entries,
        };
    }

    pub fn close(self: *Database) !void {
        if (self.inner == null) return;
        if (self.cursors.load(.monotonic) != 0) return error.CursorsOpen;
        self.inner.?.close();
        self.inner = null;
        self.cache.destroy();
    }

    /// Copies only after exact-key lookup and length validation. Oversize and missing values leave destination alone.
    pub fn getInto(self: *Database, key: []const u8, destination: []u8) !?[]u8 {
        try checkKey(key);
        if (destination.len > max_value_bytes) return error.InvalidReadLimit;
        const db = try self.handle();
        var options = try readOptions(true);
        defer options.destroy();
        var iterator = try db.createIterator(&options);
        defer iterator.destroy();

        return lookupInto(&iterator, key, destination, destination.len);
    }

    /// Reuses one iterator and its consistent view for the whole batch. Keys and result metadata must not alias
    /// destination. On error, disregard all results.
    pub fn getManyInto(self: *Database, keys: []const []const u8, destination: []u8, results: []?[]const u8, value_limit: usize) !void {
        if (keys.len > max_batch_entries or results.len != keys.len) return error.BatchTooLarge;
        if (destination.len > max_batch_bytes or value_limit > max_value_bytes) return error.InvalidReadLimit;
        for (keys) |key| try checkKey(key);
        const db = try self.handle();
        var options = try readOptions(true);
        defer options.destroy();
        var iterator = try db.createIterator(&options);
        defer iterator.destroy();

        var offset: usize = 0;
        for (keys, results) |key, *result| {
            const available = @min(value_limit, destination.len - offset);
            result.* = try lookupInto(&iterator, key, destination[offset..][0..available], value_limit);
            if (result.*) |value| offset += value.len;
        }
        std.debug.assert(offset <= destination.len);
    }

    /// Results must contain no live allocations. Caller frees non-null results with Database.allocator.
    /// On error, all initialized result slots are null and no result allocations remain.
    pub fn getManyOwned(
        self: *Database,
        keys: []const []const u8,
        results: []?[]const u8,
        value_limit: usize,
        total_limit: usize,
        fill_cache: bool,
    ) !void {
        if (results.len > max_bulk_entries) return error.BatchTooLarge;
        @memset(results, null);
        if (value_limit > max_owned_value_bytes or total_limit > max_owned_batch_bytes)
            return error.InvalidReadLimit;
        const db = try self.handle();
        try owned.getMany(db, self.allocator, keys, results, &.{
            .max_value_bytes = value_limit,
            .max_total_bytes = total_limit,
            .fill_cache = fill_cache,
        }, max_key_bytes);
    }

    pub fn put(self: *Database, key: []const u8, value: []const u8, sync: bool) !void {
        try self.write(&.{.{ .key = key, .value = value }}, sync);
    }

    pub fn delete(self: *Database, key: []const u8, sync: bool) !void {
        try self.write(&.{.{ .key = key, .value = null }}, sync);
    }

    /// Validates the complete batch before creating its C backing or changing the database.
    pub fn write(self: *Database, operations: []const Operation, sync: bool) !void {
        return self.writeWithLimits(operations, sync, .{
            .max_value_bytes = max_value_bytes,
            .max_total_bytes = max_batch_bytes,
            .max_entries = max_batch_entries,
        });
    }

    /// The complete operation remains one atomic LevelDB batch, regardless of its configured limits.
    pub fn writeWithLimits(
        self: *Database,
        operations: []const Operation,
        sync: bool,
        limits: WriteLimits,
    ) !void {
        const db = try self.handle();
        if (limits.max_entries > max_bulk_entries or operations.len > limits.max_entries)
            return error.BatchTooLarge;
        if (limits.max_value_bytes > max_owned_value_bytes) return error.ValueTooLarge;
        if (limits.max_total_bytes > max_owned_batch_bytes) return error.BatchTooLarge;
        var total: usize = 0;
        for (operations) |operation| {
            try checkKey(operation.key);
            const value_len = if (operation.value) |value| value.len else 0;
            // LevelDB encodes each value length as a varint32.
            if (value_len > limits.max_value_bytes or value_len > std.math.maxInt(u32))
                return error.ValueTooLarge;
            const bytes = std.math.add(usize, operation.key.len, value_len) catch
                return error.BatchTooLarge;
            if (bytes > limits.max_total_bytes - total) return error.BatchTooLarge;
            total += bytes;
        }
        if (operations.len == 0) return;
        var batch = try raw.WriteBatch.create();
        defer batch.destroy();
        var options = try raw.WriteOptions.create();
        defer options.destroy();

        options.setSync(sync);
        for (operations) |operation| {
            if (operation.value) |value| batch.put(operation.key, value) else batch.delete(operation.key);
        }
        try db.write(&options, &batch);
    }

    /// Rejects the total entry bound before mutation. Engine errors may leave earlier chunks deleted.
    pub fn clear(self: *Database) !void {
        try maintenance.clear(try self.handle(), self.clear_max_entries, max_key_bytes);
    }

    /// Estimates persisted bytes in [start, end); recent writes may not be included.
    pub fn approximateSize(self: *Database, start: []const u8, end: []const u8) !u64 {
        try checkKey(start);
        try checkKey(end);
        return (try self.handle()).approximateSize(start, end);
    }

    /// The C API does not report compaction errors. Null endpoints request an unbounded endpoint.
    pub fn compactRange(self: *Database, start: ?[]const u8, end: ?[]const u8) !void {
        if (start) |key| try checkKey(key);
        if (end) |key| try checkKey(key);
        (try self.handle()).compactRange(start, end);
    }

    /// Caller frees a non-null result with Database.allocator.
    pub fn propertyValue(self: *Database, name: [:0]const u8) !?[]u8 {
        if (name.len > max_path_bytes or std.mem.indexOfScalar(u8, name, 0) != null)
            return error.InvalidProperty;
        const value = (try (try self.handle()).propertyValue(name)) orelse return null;
        defer raw.free(value.ptr);
        return try maintenance.copyProperty(self.allocator, value);
    }

    /// Takes a snapshot now. The cursor must close before the database; its address need not be stable.
    pub fn cursor(self: *Database, range: RangeOptions) !Cursor {
        const db = try self.handle();
        const previous = self.cursors.fetchAdd(1, .monotonic);
        if (previous >= max_cursors) {
            _ = self.cursors.fetchSub(1, .monotonic);
            return error.CursorCapacity;
        }
        errdefer _ = self.cursors.fetchSub(1, .monotonic);
        var bounds = try ranges.Range.init(self.allocator, &range, max_key_bytes);
        errdefer bounds.deinit(self.allocator);
        var snapshot = try db.createSnapshot();
        errdefer db.releaseSnapshot(&snapshot);
        var options = try readOptions(range.fill_cache);
        defer options.destroy();
        options.setSnapshot(&snapshot);
        var iterator = try db.createIterator(&options);
        errdefer iterator.destroy();

        if (range.limit != 0) try bounds.seek(&iterator);
        return .{
            .db = self,
            .iterator = iterator,
            .snapshot = snapshot,
            .bounds = bounds,
            .remaining = range.limit,
            .keys = range.keys,
            .values = range.values,
        };
    }

    fn handle(self: *Database) !*raw.DB {
        return if (self.inner) |*db| db else error.DatabaseClosed;
    }
};

pub const Cursor = struct {
    db: *Database,
    iterator: raw.Iterator,
    snapshot: raw.Snapshot,
    bounds: ranges.Range,
    keys: bool,
    values: bool,
    remaining: u32,
    closed: bool = false,
    positioned: bool = true,

    pub fn close(self: *Cursor) void {
        if (self.closed) return;
        self.closed = true;
        self.iterator.destroy();
        self.db.inner.?.releaseSnapshot(&self.snapshot);
        self.bounds.deinit(self.db.allocator);
        const previous = self.db.cursors.fetchSub(1, .monotonic);
        std.debug.assert(previous > 0);
    }

    /// Repositions within the original snapshot and bounds without resetting the consumed row limit.
    pub fn seek(self: *Cursor, target: []const u8) !void {
        if (self.closed) return error.CursorClosed;
        errdefer self.close();
        try checkKey(target);
        self.positioned = try self.bounds.seekTarget(&self.iterator, target);
    }

    /// Keys and values share the byte budget. A row deferred for lack of remaining room is not consumed. Any error
    /// closes the cursor; earlier rows copied during a failing call are not returned as a successful page.
    pub fn readInto(self: *Cursor, destination: []u8, entries: []Entry, value_limit: usize) !Page {
        if (self.closed) return error.CursorClosed;
        errdefer self.close();
        if (destination.len == 0 or destination.len > max_batch_bytes or
            entries.len == 0 or entries.len > max_batch_entries or
            value_limit == 0 or value_limit > max_value_bytes) return error.InvalidReadLimit;
        var page: Page = .{ .count = 0, .bytes = 0, .done = false };
        for (0..entries.len) |_| {
            if (!try self.hasNext()) {
                page.done = true;
                break;
            }
            try checkKey(self.iterator.key());
            const key = if (self.keys) self.iterator.key() else "";
            const value = if (self.values) self.iterator.value() else "";
            if (value.len > value_limit) return error.ValueTooLarge;
            const bytes = key.len + value.len;
            if (bytes > destination.len - page.bytes) {
                if (page.count == 0) return error.BatchTooLarge;
                break;
            }
            const key_copy = destination[page.bytes..][0..key.len];
            @memcpy(key_copy, key);
            const value_copy = destination[page.bytes + key.len ..][0..value.len];
            @memcpy(value_copy, value);
            entries[page.count] = .{ .key = key_copy, .value = value_copy };
            page.count += 1;
            page.bytes += bytes;
            self.remaining -= 1;
            if (self.remaining > 0) try self.bounds.advance(&self.iterator);
        }
        if (!page.done) page.done = !try self.hasNext();
        if (page.done) self.close();
        return page;
    }

    /// Caller frees each selected slice in entries[0..page.count] with Database.allocator.
    /// Entries must contain no live allocations. Errors free partial entries and close the cursor.
    pub fn readOwned(
        self: *Cursor,
        entries: []Entry,
        value_limit: usize,
        total_limit: usize,
    ) !Page {
        if (entries.len > max_batch_entries) {
            self.close();
            return error.InvalidReadLimit;
        }
        return self.readOwnedPage(entries, value_limit, total_limit, null);
    }

    /// A soft watermark ends a batch AFTER the row that exceeds it. Hard limits still refuse oversized rows.
    /// Unlike readOwned, natural exhaustion retains the snapshot for seek; callers must close it explicitly.
    pub fn readOwnedBatch(self: *Cursor, entries: []Entry, value_limit: usize, total_limit: usize, high_water_mark_bytes: u32) !Page {
        return self.readOwnedPage(entries, value_limit, total_limit, high_water_mark_bytes);
    }

    fn readOwnedPage(self: *Cursor, entries: []Entry, value_limit: usize, total_limit: usize, high_water_mark_bytes: ?u32) !Page {
        if (entries.len > max_bulk_entries) {
            self.close();
            return error.InvalidReadLimit;
        }
        @memset(entries, .{ .key = "", .value = "" });
        if (self.closed) return error.CursorClosed;
        errdefer self.close();
        if (entries.len == 0 or value_limit > max_owned_value_bytes or
            total_limit > max_owned_batch_bytes) return error.InvalidReadLimit;
        var page: Page = .{ .count = 0, .bytes = 0, .done = false };
        errdefer {
            for (entries[0..page.count]) |*entry| owned.freeEntry(self.db.allocator, entry);
            @memset(entries[0..page.count], .{ .key = "", .value = "" });
        }
        for (entries) |*entry| {
            if (!try self.hasNext()) {
                page.done = true;
                break;
            }
            try checkKey(self.iterator.key());
            const key = if (self.keys) self.iterator.key() else "";
            const value = if (self.values) self.iterator.value() else "";
            if (value.len > value_limit) return error.ValueTooLarge;
            const bytes = std.math.add(usize, key.len, value.len) catch
                return error.BatchTooLarge;
            if (bytes > total_limit - page.bytes) {
                if (page.count == 0) return error.BatchTooLarge;
                break;
            }
            entry.* = try owned.copyEntry(self.db.allocator, key, value);
            page.count += 1;
            page.bytes += bytes;
            self.remaining -= 1;
            if (self.remaining > 0) try self.bounds.advance(&self.iterator);
            if (high_water_mark_bytes) |watermark| if (page.bytes > watermark) break;
        }
        if (!page.done) page.done = !try self.hasNext();
        if (page.done and high_water_mark_bytes == null) self.close();
        return page;
    }

    fn hasNext(self: *Cursor) !bool {
        try self.iterator.getError();
        if (!self.positioned or self.remaining == 0 or !self.iterator.valid()) return false;
        return self.bounds.contains(self.iterator.key());
    }
};

/// All controllers for this physical directory must be closed, including other engine copies.
pub fn destroy(path: [:0]const u8) !void {
    try checkPath(path);
    var options = try raw.Options.create();
    defer options.destroy();
    try raw.destroyDB(&options, path);
}

fn checkPath(path: [:0]const u8) !void {
    if (path.len == 0 or path.len > max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
}

fn checkKey(key: []const u8) !void {
    if (key.len > max_key_bytes) return error.KeyTooLarge;
}

fn lookupInto(iterator: *raw.Iterator, key: []const u8, destination: []u8, value_limit: usize) !?[]u8 {
    iterator.seek(key);
    try iterator.getError();
    if (!iterator.valid() or !std.mem.eql(u8, iterator.key(), key)) return null;
    const value = iterator.value();
    if (value.len > value_limit) return error.ValueTooLarge;
    if (value.len > destination.len) return error.BatchTooLarge;
    @memcpy(destination[0..value.len], value);
    return destination[0..value.len];
}

fn readOptions(fill_cache: bool) !raw.ReadOptions {
    var options = try raw.ReadOptions.create();
    options.setFillCache(fill_cache);
    options.setVerifyChecksums(true);
    return options;
}

test {
    _ = @import("root_test.zig");
}
