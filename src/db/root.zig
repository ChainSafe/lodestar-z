//! Beacon chain database layer.
//!
//! Provides persistent storage for the beacon chain node:
//! - KVStore: generic key-value store interface (vtable-based, named DB support)
//! - MemoryKVStore: in-memory implementation for testing/DST
//! - LmdbKVStore: persistent LMDB-backed implementation with named databases
//! - BeaconDB: high-level typed accessors for beacon chain data
//! - DatabaseId: named database identifiers (replaces bucket prefix scheme)
//!
//! LMDB was chosen for:
//! - Read-heavy workload (mmap zero-copy reads)
//! - Single-writer matches beacon chain's block processing model
//! - Tiny C dependency (~10K lines, vendored)
//! - Crash-safe copy-on-write B+tree
//! - Native named database support (up to 128 per environment)
//!
//! See DESIGN.md for the named database schema design.

pub const kv_store = @import("kv_store.zig");
pub const KVStore = kv_store.KVStore;
pub const Database = kv_store.Database;
pub const BatchOp = kv_store.BatchOp;

pub const memory_kv_store = @import("memory_kv_store.zig");
pub const MemoryKVStore = memory_kv_store.MemoryKVStore;

pub const lmdb = @import("lmdb.zig");
pub const LmdbEnv = lmdb.LmdbEnv;
pub const LmdbTxn = lmdb.LmdbTxn;
pub const LmdbCursor = lmdb.LmdbCursor;
pub const Dbi = lmdb.Dbi;

pub const lmdb_kv_store = @import("lmdb_kv_store.zig");
pub const LmdbKVStore = lmdb_kv_store.LmdbKVStore;

pub const beacon_db = @import("beacon_db.zig");
pub const BeaconDB = beacon_db.BeaconDB;

pub const buckets = @import("buckets.zig");
pub const DatabaseId = buckets.DatabaseId;
pub const slotKey = buckets.slotKey;
pub const encodeU64BE = buckets.encodeU64BE;
pub const rootColumnKey = buckets.rootColumnKey;

pub const memory_kv_store_test = @import("memory_kv_store_test.zig");
pub const beacon_db_test = @import("beacon_db_test.zig");
pub const lmdb_kv_store_test = @import("lmdb_kv_store_test.zig");

comptime {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
