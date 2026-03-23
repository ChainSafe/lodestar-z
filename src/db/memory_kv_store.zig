//! MemoryKVStore: in-memory KVStore implementation.
//!
//! Uses a sorted StringHashMap for storage. Suitable for:
//! - Unit tests
//! - Deterministic simulation testing (DST)
//! - Development without external dependencies
//!
//! Thread-safety: NOT thread-safe. Callers must synchronize externally.
//! This matches the beacon chain's single-threaded block processing model.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv_store = @import("kv_store.zig");
const KVStore = kv_store.KVStore;
const BatchOp = kv_store.BatchOp;

pub const MemoryKVStore = struct {
    allocator: Allocator,
    /// Stored data: keys and values are both owned by this map.
    data: std.StringArrayHashMap([]const u8),
    closed: bool,

    pub fn init(allocator: Allocator) MemoryKVStore {
        return .{
            .allocator = allocator,
            .data = std.StringArrayHashMap([]const u8).init(allocator),
            .closed = false,
        };
    }

    pub fn deinit(self: *MemoryKVStore) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.data.deinit();
    }

    pub fn kvStore(self: *MemoryKVStore) KVStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Number of entries in the store.
    pub fn count(self: *const MemoryKVStore) usize {
        return self.data.count();
    }

    // ---- VTable implementation ----

    const vtable = KVStore.VTable{
        .get = memGet,
        .put = memPut,
        .delete = memDelete,
        .writeBatch = memWriteBatch,
        .keysWithPrefix = memKeysWithPrefix,
        .entriesWithPrefix = memEntriesWithPrefix,
        .close = memClose,
    };

    fn memGet(ptr: *anyopaque, key: []const u8) anyerror!?[]const u8 {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const value = self.data.get(key) orelse return null;
        return try self.allocator.dupe(u8, value);
    }

    fn memPut(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        const result = try self.data.getOrPut(owned_key);
        if (result.found_existing) {
            // Free old value and the new duplicate key (map already has a key)
            self.allocator.free(result.value_ptr.*);
            self.allocator.free(owned_key);
        }
        result.value_ptr.* = owned_value;
    }

    fn memDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        if (self.data.fetchOrderedRemove(key)) |old| {
            self.allocator.free(old.value);
            self.allocator.free(old.key);
        }
    }

    fn memWriteBatch(ptr: *anyopaque, ops: []const BatchOp) anyerror!void {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        // Apply all operations. On error, partial writes may have occurred
        // (same as real DB behavior for non-transactional batch writes).
        for (ops) |op| {
            switch (op) {
                .put => |p| try memPut(@ptrCast(self), p.key, p.value),
                .delete => |d| try memDelete(@ptrCast(self), d.key),
            }
        }
    }

    fn memKeysWithPrefix(ptr: *anyopaque, prefix: []const u8) anyerror![]const []const u8 {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |k| self.allocator.free(k);
            result.deinit(self.allocator);
        }

        var it = self.data.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.*.len >= prefix.len and
                std.mem.eql(u8, entry.key_ptr.*[0..prefix.len], prefix))
            {
                try result.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }

    fn memEntriesWithPrefix(ptr: *anyopaque, prefix: []const u8) anyerror!KVStore.EntryList {
        const self: *MemoryKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        var values: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (keys.items) |k| self.allocator.free(k);
            keys.deinit(self.allocator);
            for (values.items) |v| self.allocator.free(v);
            values.deinit(self.allocator);
        }

        var it = self.data.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.*.len >= prefix.len and
                std.mem.eql(u8, entry.key_ptr.*[0..prefix.len], prefix))
            {
                try keys.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
                try values.append(self.allocator, try self.allocator.dupe(u8, entry.value_ptr.*));
            }
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
