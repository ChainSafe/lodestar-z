//! Beacon chain database layer.
//!
//! Provides persistent storage for the beacon chain node:
//! - KVStore: generic key-value store interface (vtable-based)
//! - MemoryKVStore: in-memory implementation for testing/DST
//! - LmdbKVStore: persistent LMDB-backed implementation
//! - BeaconDB: high-level typed accessors for beacon chain data
//! - Buckets: key namespacing matching Lodestar's bucket scheme
//!
//! LMDB was chosen for:
//! - Read-heavy workload (mmap zero-copy reads)
//! - Single-writer matches beacon chain's block processing model
//! - Tiny C dependency (~10K lines, vendored)
//! - Crash-safe copy-on-write B+tree
//!
//! See docs/db-research.md for storage engine analysis.

pub const kv_store = @import("kv_store.zig");
pub const KVStore = kv_store.KVStore;
pub const BatchOp = kv_store.BatchOp;

pub const memory_kv_store = @import("memory_kv_store.zig");
pub const MemoryKVStore = memory_kv_store.MemoryKVStore;

pub const lmdb = @import("lmdb.zig");
pub const LmdbEnv = lmdb.LmdbEnv;
pub const LmdbTxn = lmdb.LmdbTxn;
pub const LmdbCursor = lmdb.LmdbCursor;

pub const lmdb_kv_store = @import("lmdb_kv_store.zig");
pub const LmdbKVStore = lmdb_kv_store.LmdbKVStore;

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
pub const lmdb_kv_store_test = @import("lmdb_kv_store_test.zig");

comptime {
    // Ensure all tests are discovered
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
