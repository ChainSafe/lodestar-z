//! Shared test helpers for API handler tests.
//!
//! Provides a mock ApiContext backed by a MemoryKVStore for unit testing.

const std = @import("std");
const types = @import("types.zig");
const ctx_mod = @import("context.zig");
const ApiContext = ctx_mod.ApiContext;
const config_mod = @import("config");
const db_mod = @import("db");
const MemoryKVStore = db_mod.memory_kv_store.MemoryKVStore;

/// Create a test ApiContext backed by a MemoryKVStore.
/// Caller must call destroyTestContext when done.
pub fn makeTestContext(allocator: std.mem.Allocator) TestContext {
    const store = allocator.create(MemoryKVStore) catch @panic("OOM");
    store.* = MemoryKVStore.init(allocator);
    const db = allocator.create(db_mod.BeaconDB) catch @panic("OOM");
    db.* = db_mod.BeaconDB.init(allocator, store.kvStore());

    return .{
        .store = store,
        .db = db,
        .ctx = .{
            .head_tracker = &default_head_tracker,
            .regen = &default_regen,
            .db = db,
            .node_identity = .{
                .peer_id = "test-peer-id",
                .enr = "enr:-test",
                .p2p_addresses = &[_][]const u8{"/ip4/127.0.0.1/tcp/9000"},
                .discovery_addresses = &[_][]const u8{"/ip4/127.0.0.1/udp/9000"},
                .metadata = .{
                    .seq_number = 1,
                    .attnets = [_]u8{0} ** 8,
                    .syncnets = [_]u8{0} ** 1,
                },
            },
            .sync_status = &default_sync_status,
            .beacon_config = &default_beacon_config,
            .allocator = allocator,
        },
    };
}

pub fn destroyTestContext(allocator: std.mem.Allocator, tc: *TestContext) void {
    tc.store.deinit();
    allocator.destroy(tc.store);
    allocator.destroy(tc.db);
}

pub const TestContext = struct {
    store: *MemoryKVStore,
    db: *db_mod.BeaconDB,
    ctx: ApiContext,
};

var default_head_tracker = ctx_mod.HeadTracker{
    .head_slot = 1000,
    .head_root = [_]u8{0xaa} ** 32,
    .head_state_root = [_]u8{0xbb} ** 32,
    .finalized_slot = 900,
    .finalized_root = [_]u8{0xcc} ** 32,
    .justified_slot = 950,
    .justified_root = [_]u8{0xdd} ** 32,
};

var default_regen = ctx_mod.StateRegen{};

var default_sync_status = ctx_mod.SyncStatus{
    .head_slot = 1000,
    .sync_distance = 0,
    .is_syncing = false,
    .is_optimistic = false,
    .el_offline = false,
};

var default_beacon_config = config_mod.BeaconConfig.init(config_mod.mainnet.chain_config, [_]u8{0} ** 32);
