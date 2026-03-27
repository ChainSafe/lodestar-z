//! MemoryKVStore: in-memory KVStore implementation with named database support.
//!
//! Uses a separate StringArrayHashMap per DatabaseId. Suitable for:
//! - Unit tests
//! - Deterministic simulation testing (DST)
//! - Development without external dependencies
//!
//! Thread-safety: NOT thread-safe. Callers must synchronize externally.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv_store = @import("kv_store.zig");
const KVStore = kv_store.KVStore;
const BatchOp = kv_store.BatchOp;
const DatabaseId = @import("buckets.zig").DatabaseId;

const DataMap = std.StringArrayHashMap([]const u8);

pub const MemoryKVStore = struct {
    allocator: Allocator,
    /// One HashMap per named database.
    databases: [DatabaseId.count]DataMap,
    closed: bool,

    pub fn init(allocator: Allocator) MemoryKVStore {
        var databases: [DatabaseId.count]DataMap = undefined;
        for (&databases) |*db| {
            db.* = DataMap.init(allocator);
        }
        return .{
            .allocator = allocator,
            .databases = databases,
            .closed = false,
        };
    }

    pub fn deinit(self: *MemoryKVStore) void {
        for (&self.databases) |*db| {
            var it = db.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
                self.allocator.free(entry.key_ptr.*);
            }
            db.deinit();
        }
    }

    pub fn kvStore(self: *MemoryKVStore) KVStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Number of entries across all databases.
    pub fn count(self: *const MemoryKVStore) usize {
        var total: usize = 0;
        for (self.databases) |db| {
            total += db.count();
        }
        return total;
    }

    /// Number of entries in a specific database.
    pub fn countIn(self: *const MemoryKVStore, db_id: DatabaseId) usize {
        return self.databases[@intFromEnum(db_id)].count();
    }

    fn getDb(self: *MemoryKVStore, db_id: DatabaseId) *DataMap {
        return &self.databases[@intFromEnum(db_id)];
    }

    // ---- VTable implementation ----

    const vtable = KVStore.VTable{
        .get = memGet,
        .put = memPut,
        .delete = memDelete,
        .writeBatch = memWriteBatch,
        .allKeys = memAllKeys,
        .allEntries = memAllEntries,
        .close = memClose,
    };

    fn memGet(ptr: *anyopaque, db_id: DatabaseId, key: []const u8) anyerror!?[]const u8 {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const db = self.getDb(db_id);
        const value = db.get(key) orelse return null;
        return try self.allocator.dupe(u8, value);
    }

    fn memPut(ptr: *anyopaque, db_id: DatabaseId, key: []const u8, value: []const u8) anyerror!void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const db = self.getDb(db_id);

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        const result = try db.getOrPut(owned_key);
        if (result.found_existing) {
            self.allocator.free(result.value_ptr.*);
            self.allocator.free(owned_key);
        }
        result.value_ptr.* = owned_value;
    }

    fn memDelete(ptr: *anyopaque, db_id: DatabaseId, key: []const u8) anyerror!void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const db = self.getDb(db_id);
        if (db.fetchOrderedRemove(key)) |old| {
            self.allocator.free(old.value);
            self.allocator.free(old.key);
        }
    }

    fn memWriteBatch(ptr: *anyopaque, ops: []const BatchOp) anyerror!void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        for (ops) |op| {
            switch (op) {
                .put => |p| try memPut(@ptrCast(self), p.db, p.key, p.value),
                .delete => |d| try memDelete(@ptrCast(self), d.db, d.key),
            }
        }
    }

    fn memAllKeys(ptr: *anyopaque, db_id: DatabaseId) anyerror![]const []const u8 {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const db = self.getDb(db_id);

        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |k| self.allocator.free(k);
            result.deinit(self.allocator);
        }

        var it = db.iterator();
        while (it.next()) |entry| {
            try result.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
        }

        return try result.toOwnedSlice(self.allocator);
    }

    fn memAllEntries(ptr: *anyopaque, db_id: DatabaseId) anyerror!KVStore.EntryList {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const db = self.getDb(db_id);

        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        var values: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (keys.items) |k| self.allocator.free(k);
            keys.deinit(self.allocator);
            for (values.items) |v| self.allocator.free(v);
            values.deinit(self.allocator);
        }

        var it = db.iterator();
        while (it.next()) |entry| {
            try keys.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
            try values.append(self.allocator, try self.allocator.dupe(u8, entry.value_ptr.*));
        }

        return .{
            .keys = try keys.toOwnedSlice(self.allocator),
            .values = try values.toOwnedSlice(self.allocator),
        };
    }

    fn memClose(ptr: *anyopaque) void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        self.closed = true;
    }
};
