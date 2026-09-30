const std = @import("std");
const napi = @import("zapi:zapi").napi;
const leveldb = @import("leveldb");
const shared = @import("leveldb_shared.zig");
const runtime = @import("leveldb_runtime.zig");
const values = @import("leveldb_values.zig");
const allocator = std.heap.c_allocator;

pub const Kind = enum { open, destroy, get_many, write, cursor, read_cursor, close_cursor, clear, approximate_size, compact_range, property };

pub const Job = struct {
    owner: *runtime.Runtime,
    kind: Kind,
    work: napi.AsyncWork(Job),
    callback: napi.Ref,
    retire_work: ?napi.AsyncWork(Job) = null,
    publication_error: ?napi.Ref = null,
    cursor_retired: bool = false,
    input: []u8,
    output: []u8,
    operations: []leveldb.Operation,
    results: []?[]const u8,
    entries: []leveldb.Entry,
    reservation: usize,
    output_limit: usize,
    fill_cache: bool = true,
    number_result: u64 = 0,
    property_found: bool = false,
    options: leveldb.Options = .{},
    multithreading: bool = false,
    range: leveldb.RangeOptions = .{},
    sync: bool = false,
    cursor_id: u32 = 0,
    value_limit: usize = 0,
    page: leveldb.Page = .{ .count = 0, .bytes = 0, .done = false },
    failure: ?anyerror = null,

    pub fn create(owner: *runtime.Runtime, kind: Kind, input_bytes: usize, output_bytes: usize, count: usize, callback_value: napi.Value) !*Job {
        std.debug.assert(count <= leveldb.max_bulk_entries);
        const operation_count = if (kind == .write or kind == .get_many) count else 0;
        const result_count = if (kind == .get_many) count else 0;
        const entry_count = if (kind == .read_cursor) count else 0;
        const reservation = input_bytes + operation_count * @sizeOf(leveldb.Operation) +
            result_count * (@sizeOf(?[]const u8) + @sizeOf([]const u8) + @sizeOf(?usize)) + entry_count * @sizeOf(leveldb.Entry);
        try owner.reserve(reservation, kind == .close_cursor);
        errdefer owner.release(reservation, kind == .close_cursor);

        const self = try allocator.create(Job);
        errdefer allocator.destroy(self);
        const input = try allocator.alloc(u8, input_bytes);
        errdefer allocator.free(input);
        const output = try allocator.alloc(u8, 0);
        errdefer allocator.free(output);
        const operations = try allocator.alloc(leveldb.Operation, operation_count);
        errdefer allocator.free(operations);
        const results = try allocator.alloc(?[]const u8, result_count);
        errdefer allocator.free(results);
        @memset(results, null);
        const entries = try allocator.alloc(leveldb.Entry, entry_count);
        errdefer allocator.free(entries);

        const callback = try values.callback(callback_value);
        errdefer callback.delete() catch {};

        self.* = .{
            .owner = owner,
            .kind = kind,
            .work = undefined,
            .callback = callback,
            .input = input,
            .output = output,
            .operations = operations,
            .results = results,
            .entries = entries,
            .reservation = reservation,
            .output_limit = output_bytes,
        };
        const name = try owner.env.createStringUtf8("LevelDb");
        self.work = try napi.AsyncWork(Job).create(owner.env, null, name, execute, complete, self);
        errdefer self.work.delete() catch {};
        if (kind == .cursor or kind == .read_cursor) {
            self.retire_work = try napi.AsyncWork(Job).create(owner.env, null, name, retireExecute, retireComplete, self);
        }
        return self;
    }

    pub fn destroy(self: *Job) void {
        self.work.delete() catch {};
        self.callback.delete() catch {};
        if (self.retire_work) |work| work.delete() catch {};
        if (self.publication_error) |reference| reference.delete() catch {};
        self.owner.release(self.reservation, self.kind == .close_cursor);
        for (self.entries[0..self.page.count]) |entry| {
            allocator.free(entry.key);
            allocator.free(entry.value);
        }
        for (self.results) |result| if (result) |bytes| allocator.free(bytes);
        allocator.free(self.entries);
        allocator.free(self.results);
        allocator.free(self.operations);
        allocator.free(self.output);
        allocator.free(self.input);
        allocator.destroy(self);
    }

    fn execute(_: napi.Env, self: *Job) void {
        self.run() catch |err| {
            self.failure = err;
        };
    }

    fn run(self: *Job) !void {
        const owner = self.owner;
        if (self.kind == .open) {
            std.debug.assert(owner.database == null);
            owner.database = try shared.Database.open(self.input[0 .. self.input.len - 1 :0], self.options, self.multithreading);
            return;
        }
        if (self.kind == .destroy) {
            try shared.destroy(self.input[0 .. self.input.len - 1 :0]);
            return;
        }
        const database = if (owner.database) |db| &db.database else return error.DatabaseClosed;
        switch (self.kind) {
            .open, .destroy => unreachable,
            .clear => try database.clear(),
            .approximate_size => self.number_result = try database.approximateSize(self.range.gte.?, self.range.lt.?),
            .compact_range => try database.compactRange(self.range.gte.?, self.range.lt.?),
            .property => {
                if (try database.propertyValue(self.input[0 .. self.input.len - 1 :0])) |text| {
                    allocator.free(self.output);
                    self.output = text;
                    self.property_found = true;
                }
            },
            .get_many => try self.readMany(database),
            .write => try database.writeWithLimits(self.operations, self.sync, .{ .max_value_bytes = leveldb.max_owned_value_bytes, .max_total_bytes = leveldb.max_owned_batch_bytes, .max_entries = leveldb.max_bulk_entries }),
            .cursor => try self.openCursor(database),
            .read_cursor => try self.readCursor(),
            .close_cursor => {
                self.cursor_retired = true;
                if (owner.findCursor(self.cursor_id)) |slot| {
                    slot.cursor.?.close();
                    slot.cursor = null;
                }
            },
        }
    }

    fn readMany(self: *Job, database: *leveldb.Database) !void {
        const keys = try allocator.alloc([]const u8, self.operations.len);
        defer allocator.free(keys);
        for (self.operations, keys) |operation, *key| key.* = operation.key;
        try database.getManyOwned(keys, self.results, self.value_limit, self.output_limit, self.fill_cache);
    }

    fn openCursor(self: *Job, database: *leveldb.Database) !void {
        if (self.owner.next_cursor_id == std.math.maxInt(u32)) return error.CursorCapacity;
        for (&self.owner.cursors) |*slot| {
            if (slot.cursor != null) continue;
            slot.cursor = try database.cursor(self.range);
            self.owner.next_cursor_id += 1;
            slot.id = self.owner.next_cursor_id;
            self.cursor_id = slot.id;
            return;
        }
        return error.CursorCapacity;
    }

    fn readCursor(self: *Job) !void {
        const slot = self.owner.findCursor(self.cursor_id) orelse {
            self.cursor_retired = true;
            return error.CursorClosed;
        };
        self.page = slot.cursor.?.readOwned(self.entries, self.value_limit, self.output_limit) catch |err| {
            slot.cursor.?.close();
            slot.cursor = null;
            self.cursor_retired = true;
            return err;
        };
        if (self.page.done) {
            self.cursor_retired = true;
            slot.cursor.?.close();
            slot.cursor = null;
        }
    }

    fn complete(env: napi.Env, status: napi.status.Status, self: *Job) void {
        const owner = self.owner;
        if (status != .ok and self.failure == null) self.failure = error.Cancelled;
        owner.syncCursor(self);
        if (owner.env_alive) {
            const finished = self.settle(env) catch |err| blk: {
                owner.deliveryFailure(err);
                break :blk true;
            };
            if (!finished) return;
        }
        owner.finish(self);
    }

    pub fn settle(self: *Job, env: napi.Env) !bool {
        if (self.failure) |err| {
            try self.reject(env, err);
            return true;
        }
        const result = self.buildResult(env) catch |err| {
            if ((self.kind == .cursor or self.kind == .read_cursor) and !self.cursor_retired) {
                return self.retireUnpublished(env, err);
            }
            try self.reject(env, err);
            return true;
        };
        try values.notify(env, self.callback, null, result);
        return true;
    }

    fn retireUnpublished(self: *Job, env: napi.Env, err: anyerror) !bool {
        const reason = try values.failureReason(env, self.owner.fallback_error.?, err);
        self.publication_error = env.createReference(reason, 1) catch blk: {
            if (try env.isExceptionPending()) _ = try env.getAndClearLastException();
            break :blk null;
        };
        self.retire_work.?.queue() catch {
            const thread = std.Thread.spawn(.{}, retireExecute, .{ env, self }) catch
                env.fatalError("LevelDb cursor", "Cannot retire an unpublished cursor");
            thread.join();
            self.owner.syncCursor(self);
            try self.rejectPublication(env);
            return true;
        };
        return false;
    }

    fn retireExecute(_: napi.Env, self: *Job) void {
        if (self.owner.findCursor(self.cursor_id)) |slot| {
            slot.cursor.?.close();
            slot.cursor = null;
        }
        self.cursor_retired = true;
    }

    fn retireComplete(env: napi.Env, status: napi.status.Status, self: *Job) void {
        const owner = self.owner;
        if (status != .ok) {
            const thread = std.Thread.spawn(.{}, retireExecute, .{ env, self }) catch
                env.fatalError("LevelDb cursor", "Cannot finish cursor retirement");
            thread.join();
        }
        owner.syncCursor(self);
        if (owner.env_alive) self.rejectPublication(env) catch |err| owner.deliveryFailure(err);
        owner.finish(self);
    }

    fn rejectPublication(self: *Job, env: napi.Env) !void {
        const reference = self.publication_error orelse self.owner.fallback_error.?;
        try values.notify(env, self.callback, try reference.getValue(), try env.getUndefined());
    }

    fn reject(self: *Job, env: napi.Env, err: anyerror) !void {
        const reason = try values.failureReason(env, self.owner.fallback_error.?, err);
        try values.notify(env, self.callback, reason, try env.getUndefined());
    }

    fn buildResult(self: *const Job, env: napi.Env) !napi.Value {
        return switch (self.kind) {
            .open, .destroy, .write, .close_cursor, .clear, .compact_range => env.getUndefined(),
            .approximate_size => env.createDouble(@floatFromInt(self.number_result)),
            .property => if (self.property_found) env.createStringUtf8(self.output) else env.getNull(),
            .cursor => env.createUint32(self.cursor_id),
            .get_many => blk: {
                const result = try env.createArrayWithLength(self.results.len);
                for (self.results, 0..) |item, index| {
                    const value = if (item) |data| try copyBytes(env, data) else try env.getNull();
                    try result.setElement(@intCast(index), value);
                }
                break :blk result;
            },
            .read_cursor => self.pageResult(env),
        };
    }

    fn pageResult(self: *const Job, env: napi.Env) !napi.Value {
        const result = try env.createObject();
        const entries = try env.createArrayWithLength(self.page.count);
        for (self.entries[0..self.page.count], 0..) |entry, index| {
            const item = try env.createObject();
            try item.setNamedProperty("key", try copyBytes(env, entry.key));
            try item.setNamedProperty("value", try copyBytes(env, entry.value));
            try entries.setElement(@intCast(index), item);
        }
        try result.setNamedProperty("entries", entries);
        try result.setNamedProperty("done", try env.getBoolean(self.page.done));
        return result;
    }
};

fn copyBytes(env: napi.Env, bytes: []const u8) !napi.Value {
    const buffer = try env.createArrayBufferCopy(bytes, null);
    return env.createTypedarray(.uint8, bytes.len, buffer, 0);
}
