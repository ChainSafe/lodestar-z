//! KVStore: vtable-based key-value store interface.
//!
//! Provides a backend-agnostic abstraction for persistent storage.
//! Implementations: MemoryKVStore (testing), future LMDB/RocksDB backends.
//!
//! Key design follows Lodestar's bucket prefix scheme:
//!   key = [1-byte bucket prefix] ++ [key_bytes...]
//!
//! All returned slices from `get` are owned by the caller and must be freed
//! with the allocator that was used to create the store.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A single batch operation for atomic writes.
pub const BatchOp = union(enum) {
    put: struct {
        key: []const u8,
        value: []const u8,
    },
    delete: struct {
        key: []const u8,
    },
};

/// KVStore provides a generic key-value store interface via vtable dispatch.
///
/// All implementations must be thread-safe for concurrent reads.
/// Write operations may be serialized by the implementation.
pub const KVStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Get the value for a key. Returns owned slice or null if not found.
        get: *const fn (ptr: *anyopaque, key: []const u8) anyerror!?[]const u8,
        /// Store a key-value pair. Overwrites any existing value.
        put: *const fn (ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void,
        /// Delete a key. No-op if the key does not exist.
        delete: *const fn (ptr: *anyopaque, key: []const u8) anyerror!void,
        /// Atomically apply a batch of put/delete operations.
        writeBatch: *const fn (ptr: *anyopaque, ops: []const BatchOp) anyerror!void,
        /// Get all keys matching a prefix. Returns owned slice of owned key slices.
        keysWithPrefix: *const fn (ptr: *anyopaque, prefix: []const u8) anyerror![]const []const u8,
        /// Get all key-value pairs matching a prefix. Returns owned entries.
        entriesWithPrefix: *const fn (ptr: *anyopaque, prefix: []const u8) anyerror!EntryList,
        /// Close the store and release resources.
        close: *const fn (ptr: *anyopaque) void,
    };

    /// A list of key-value entries returned by prefix scans.
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

    // ---- Forwarding methods ----

    pub fn get(self: KVStore, key: []const u8) anyerror!?[]const u8 {
        return self.vtable.get(self.ptr, key);
    }

    pub fn put(self: KVStore, key: []const u8, value: []const u8) anyerror!void {
        return self.vtable.put(self.ptr, key, value);
    }

    pub fn delete(self: KVStore, key: []const u8) anyerror!void {
        return self.vtable.delete(self.ptr, key);
    }

    pub fn writeBatch(self: KVStore, ops: []const BatchOp) anyerror!void {
        return self.vtable.writeBatch(self.ptr, ops);
    }

    pub fn keysWithPrefix(self: KVStore, prefix: []const u8) anyerror![]const []const u8 {
        return self.vtable.keysWithPrefix(self.ptr, prefix);
    }

    pub fn entriesWithPrefix(self: KVStore, prefix: []const u8) anyerror!EntryList {
        return self.vtable.entriesWithPrefix(self.ptr, prefix);
    }

    pub fn close(self: KVStore) void {
        return self.vtable.close(self.ptr);
    }
};
