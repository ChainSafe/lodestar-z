//! Shared test helpers for API handler tests.
//!
//! Provides a mock ApiContext backed by a MemoryKVStore for unit testing.

const std = @import("std");
const types = @import("types.zig");
const ctx_mod = @import("context.zig");
const ApiContext = ctx_mod.ApiContext;
const CachedBeaconState = ctx_mod.CachedBeaconState;
const config_mod = @import("config");
const db_mod = @import("db");
const MemoryKVStore = db_mod.memory_kv_store.MemoryKVStore;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

fn getTestHeadTracker(ptr: *anyopaque) ctx_mod.HeadTracker {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.head_tracker.*;
}

fn getTestSyncStatus(ptr: *anyopaque) ctx_mod.SyncStatus {
    const status: *ctx_mod.SyncStatus = @ptrCast(@alignCast(ptr));
    return status.*;
}

const TestChainFixture = struct {
    allocator: std.mem.Allocator,
    db: *db_mod.BeaconDB,
    head_tracker: *ctx_mod.HeadTracker,
    sync_status: *ctx_mod.SyncStatus,
    beacon_config: *const config_mod.BeaconConfig,
    head_state: ?*CachedBeaconState = null,
    state_by_root: ?*CachedBeaconState = null,
    state_by_slot: ?*CachedBeaconState = null,
};

fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
    if (block_bytes.len < 108) return null;
    return std.mem.readInt(u64, block_bytes[100..108], .little);
}

fn getTestBlockRootBySlot(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.db.getBlockRootBySlot(slot);
}

fn getTestBlockBytesByRoot(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (try fixture.db.getBlock(root)) |block_bytes| return block_bytes;
    return fixture.db.getBlockArchiveByRoot(root);
}

fn getTestBlockExecutionOptimistic(ptr: *anyopaque, root: [32]u8) bool {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return std.mem.eql(u8, &root, &fixture.head_tracker.head_root) and fixture.sync_status.is_optimistic;
}

fn getTestBlockExecutionOptimisticAtSlot(ptr: *anyopaque, slot: u64) anyerror!bool {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return slot == fixture.head_tracker.head_slot and fixture.sync_status.is_optimistic;
}

fn getTestStateRootByBlockRoot(ptr: *anyopaque, root: [32]u8) anyerror!?[32]u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    const block_bytes = try getTestBlockBytesByRoot(ptr, root) orelse return null;
    defer fixture.allocator.free(block_bytes);

    const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
    const fork_seq = fixture.beacon_config.forkSeq(slot);
    const any_signed = try AnySignedBeaconBlock.deserialize(
        fixture.allocator,
        .full,
        fork_seq,
        block_bytes,
    );
    defer any_signed.deinit(fixture.allocator);
    return any_signed.beaconBlock().stateRoot().*;
}

fn getTestStateRootBySlot(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (slot == fixture.head_tracker.head_slot) return fixture.head_tracker.head_state_root;
    const block_root = try fixture.db.getBlockRootBySlot(slot) orelse return null;
    return getTestStateRootByBlockRoot(ptr, block_root);
}

fn getTestStateBytesBySlot(ptr: *anyopaque, slot: u64) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.db.getStateArchive(slot);
}

fn getTestStateBytesByRoot(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.db.getStateArchiveByRoot(root);
}

fn getTestStateArchiveAtSlot(ptr: *anyopaque, slot: u64) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.db.getStateArchive(slot);
}

fn getTestStateArchiveByRoot(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.db.getStateArchiveByRoot(root);
}

fn getTestHeadState(ptr: *anyopaque) ?*CachedBeaconState {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.head_state;
}

fn getTestStateByRoot(ptr: *anyopaque, root: [32]u8) anyerror!?*CachedBeaconState {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (fixture.state_by_root) |state| return state;
    if (fixture.head_state != null and std.mem.eql(u8, &root, &fixture.head_tracker.head_state_root)) {
        return fixture.head_state;
    }
    return null;
}

fn getTestStateBySlot(ptr: *anyopaque, slot: u64) anyerror!?*CachedBeaconState {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (fixture.state_by_slot) |state| return state;
    if (fixture.head_state != null and slot == fixture.head_tracker.head_slot) {
        return fixture.head_state;
    }
    return null;
}

fn getTestStateExecutionOptimisticByRoot(ptr: *anyopaque, state_root: [32]u8) bool {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return std.mem.eql(u8, &state_root, &fixture.head_tracker.head_state_root) and fixture.sync_status.is_optimistic;
}

fn getTestStateExecutionOptimisticBySlot(ptr: *anyopaque, slot: u64) anyerror!bool {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return slot == fixture.head_tracker.head_slot and fixture.sync_status.is_optimistic;
}

/// Create a test ApiContext backed by a MemoryKVStore.
/// Caller must call destroyTestContext when done.
pub fn makeTestContext(allocator: std.mem.Allocator) TestContext {
    const store = allocator.create(MemoryKVStore) catch @panic("OOM");
    store.* = MemoryKVStore.init(allocator);
    const db = allocator.create(db_mod.BeaconDB) catch @panic("OOM");
    db.* = db_mod.BeaconDB.init(allocator, store.kvStore());
    const head_tracker = allocator.create(ctx_mod.HeadTracker) catch @panic("OOM");
    head_tracker.* = default_head_tracker;
    const sync_status = allocator.create(ctx_mod.SyncStatus) catch @panic("OOM");
    sync_status.* = default_sync_status;
    const chain_fixture = allocator.create(TestChainFixture) catch @panic("OOM");
    chain_fixture.* = .{
        .allocator = allocator,
        .db = db,
        .head_tracker = head_tracker,
        .sync_status = sync_status,
        .beacon_config = &default_beacon_config,
    };

    return .{
        .store = store,
        .db = db,
        .head_tracker = head_tracker,
        .sync_status = sync_status,
        .chain_fixture = chain_fixture,
        .ctx = .{
            .node_identity = &default_node_identity,
            .beacon_config = &default_beacon_config,
            .allocator = allocator,
            .chain = .{
                .ptr = @ptrCast(chain_fixture),
                .getHeadTrackerFn = &getTestHeadTracker,
                .getBlockRootBySlotFn = &getTestBlockRootBySlot,
                .getBlockBytesByRootFn = &getTestBlockBytesByRoot,
                .getBlockExecutionOptimisticFn = &getTestBlockExecutionOptimistic,
                .getBlockExecutionOptimisticAtSlotFn = &getTestBlockExecutionOptimisticAtSlot,
                .getStateRootBySlotFn = &getTestStateRootBySlot,
                .getStateRootByBlockRootFn = &getTestStateRootByBlockRoot,
                .getStateBytesBySlotFn = &getTestStateBytesBySlot,
                .getStateBytesByRootFn = &getTestStateBytesByRoot,
                .getStateArchiveAtSlotFn = &getTestStateArchiveAtSlot,
                .getStateArchiveByRootFn = &getTestStateArchiveByRoot,
                .getHeadStateFn = &getTestHeadState,
                .getStateByRootFn = &getTestStateByRoot,
                .getStateBySlotFn = &getTestStateBySlot,
                .getStateExecutionOptimisticByRootFn = &getTestStateExecutionOptimisticByRoot,
                .getStateExecutionOptimisticBySlotFn = &getTestStateExecutionOptimisticBySlot,
            },
            .sync_status_view = .{
                .ptr = @ptrCast(sync_status),
                .getSyncStatusFn = &getTestSyncStatus,
            },
        },
    };
}

pub fn destroyTestContext(allocator: std.mem.Allocator, tc: *TestContext) void {
    allocator.destroy(tc.chain_fixture);
    allocator.destroy(tc.sync_status);
    allocator.destroy(tc.head_tracker);
    tc.store.deinit();
    allocator.destroy(tc.store);
    allocator.destroy(tc.db);
}

pub const TestContext = struct {
    store: *MemoryKVStore,
    db: *db_mod.BeaconDB,
    head_tracker: *ctx_mod.HeadTracker,
    sync_status: *ctx_mod.SyncStatus,
    chain_fixture: *TestChainFixture,
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

var default_node_identity = types.NodeIdentity{
    .peer_id = "test-peer-id",
    .enr = "enr:-test",
    .p2p_addresses = &[_][]const u8{"/ip4/127.0.0.1/tcp/9000"},
    .discovery_addresses = &[_][]const u8{"/ip4/127.0.0.1/udp/9000"},
    .metadata = .{
        .seq_number = 1,
        .attnets = [_]u8{0} ** 8,
        .syncnets = [_]u8{0} ** 1,
    },
};

var default_sync_status = ctx_mod.SyncStatus{
    .head_slot = 1000,
    .sync_distance = 0,
    .is_syncing = false,
    .is_optimistic = false,
    .el_offline = false,
};

var default_beacon_config = config_mod.BeaconConfig.init(config_mod.mainnet.chain_config, [_]u8{0} ** 32);
