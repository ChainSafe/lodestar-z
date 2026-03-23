//! Beacon chain database layer.
//!
//! Provides persistent storage for the beacon chain node:
//! - KVStore: generic key-value store interface (vtable-based)
//! - MemoryKVStore: in-memory implementation for testing/DST
//! - BeaconDB: high-level typed accessors for beacon chain data
//! - Buckets: key namespacing matching Lodestar's bucket scheme
//!
//! Future backends: LMDB (recommended), RocksDB (alternative).
//! See docs/db-research.md for storage engine analysis.

pub const kv_store = @import("kv_store.zig");
pub const KVStore = kv_store.KVStore;
pub const BatchOp = kv_store.BatchOp;

pub const memory_kv_store = @import("memory_kv_store.zig");
pub const MemoryKVStore = memory_kv_store.MemoryKVStore;

pub const beacon_db = @import("beacon_db.zig");
pub const BeaconDB = beacon_db.BeaconDB;

pub const buckets = @import("buckets.zig");
pub const Bucket = buckets.Bucket;

// Re-export key construction helpers
pub const bucketKey = buckets.bucketKey;
pub const bucketRootKey = buckets.bucketRootKey;
pub const bucketSlotKey = buckets.bucketSlotKey;
pub const bucketPrefix = buckets.bucketPrefix;

pub const memory_kv_store_test = @import("memory_kv_store_test.zig");
pub const beacon_db_test = @import("beacon_db_test.zig");

comptime {
    // Ensure all tests are discovered
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
