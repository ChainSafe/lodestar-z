//! KVStore: vtable-based key-value store interface with named database support.
//!
//! Provides a backend-agnostic abstraction for persistent storage.
//! Implementations: MemoryKVStore (testing), LmdbKVStore (production).
//!
//! Key design uses named databases for namespace isolation:
//!   Each logical bucket maps to a separate named database (DBI).
//!   Keys contain only the actual key bytes — no prefix overhead.
//!
//! All returned slices from `get` are owned by the caller and must be freed
//! with the allocator that was used to create the store.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DatabaseId = @import("buckets.zig").DatabaseId;

/// A single batch operation for atomic writes.
pub const BatchOp = union(enum) {
    put: struct {
        db: DatabaseId,
        key: []const u8,
        value: []const u8,
    },
    delete: struct {
        db: DatabaseId,
        key: []const u8,
    },
};

/// Database provides operations scoped to a single named database.
///
/// Obtained via KVStore.getDatabase(). All operations target only
/// the specified database, with no key prefix overhead.
pub const Database = struct {
    store: KVStore,
    db_id: DatabaseId,

    /// Get the value for a key. Returns owned slice or null if not found.
    pub fn get(self: Database, key: []const u8) anyerror!?[]const u8 {
        return self.store.vtable.get(self.store.ptr, self.db_id, key);
    }

    /// Store a key-value pair. Overwrites any existing value.
    pub fn put(self: Database, key: []const u8, value: []const u8) anyerror!void {
        return self.store.vtable.put(self.store.ptr, self.db_id, key, value);
    }

    /// Delete a key. No-op if the key does not exist.
    pub fn delete(self: Database, key: []const u8) anyerror!void {
        return self.store.vtable.delete(self.store.ptr, self.db_id, key);
    }

    /// Get all keys in this database. Returns owned slice of owned key slices.
    pub fn allKeys(self: Database) anyerror![]const []const u8 {
        return self.store.vtable.allKeys(self.store.ptr, self.db_id);
    }

    /// Get all key-value pairs in this database. Returns owned entries.
    pub fn allEntries(self: Database) anyerror!KVStore.EntryList {
        return self.store.vtable.allEntries(self.store.ptr, self.db_id);
    }

    /// Get the last key in this database (highest in sort order). O(1) via cursor.
    /// Returns an owned slice or null if the database is empty. Caller frees.
    pub fn firstKey(self: Database) anyerror!?[]const u8 {
        return self.store.vtable.firstKey(self.store.ptr, self.db_id);
    }

    /// Get the last key in this database (highest in sort order). O(1) via cursor.
    /// Returns an owned slice or null if the database is empty. Caller frees.
    pub fn lastKey(self: Database) anyerror!?[]const u8 {
        return self.store.vtable.lastKey(self.store.ptr, self.db_id);
    }
};

/// KVStore provides a generic key-value store interface via vtable dispatch.
///
/// All implementations must be thread-safe for concurrent reads.
/// Write operations may be serialized by the implementation.
pub const KVStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Get the value for a key in a named database. Returns owned slice or null.
        get: *const fn (ptr: *anyopaque, db: DatabaseId, key: []const u8) anyerror!?[]const u8,
        /// Store a key-value pair in a named database.
        put: *const fn (ptr: *anyopaque, db: DatabaseId, key: []const u8, value: []const u8) anyerror!void,
        /// Delete a key from a named database.
        delete: *const fn (ptr: *anyopaque, db: DatabaseId, key: []const u8) anyerror!void,
        /// Atomically apply a batch of put/delete operations across databases.
        writeBatch: *const fn (ptr: *anyopaque, ops: []const BatchOp) anyerror!void,
        /// Get all keys in a named database.
        allKeys: *const fn (ptr: *anyopaque, db: DatabaseId) anyerror![]const []const u8,
        /// Get all key-value pairs in a named database.
        allEntries: *const fn (ptr: *anyopaque, db: DatabaseId) anyerror!EntryList,
        /// Get the first (lowest) key in a named database. O(1). Returns owned slice or null.
        firstKey: *const fn (ptr: *anyopaque, db: DatabaseId) anyerror!?[]const u8,
        /// Get the last (highest) key in a named database. O(1). Returns owned slice or null.
        lastKey: *const fn (ptr: *anyopaque, db: DatabaseId) anyerror!?[]const u8,
        /// Close the store and release resources.
        close: *const fn (ptr: *anyopaque) void,
    };

    /// A list of key-value entries returned by database scans.
    pub const EntryList = struct {
        keys: []const []const u8,
        values: []const []const u8,

        /// Free all owned memory.
        pub fn deinit(self: EntryList, allocator: Allocator) void {
            for (self.keys) |k| allocator.free(k);
            for (self.values) |v| allocator.free(v);
            allocator.free(self.keys);
            allocator.free(self.values);
        }
    };

    // ---- Convenience methods ----

    /// Get a Database handle for the given named database.
    pub fn getDatabase(self: KVStore, db_id: DatabaseId) Database {
        return .{ .store = self, .db_id = db_id };
    }

    /// Atomically apply a batch of operations across databases.
    pub fn writeBatch(self: KVStore, ops: []const BatchOp) anyerror!void {
        return self.vtable.writeBatch(self.ptr, ops);
    }

    /// Close the store and release resources.
    pub fn close(self: KVStore) void {
        return self.vtable.close(self.ptr);
    }
};
