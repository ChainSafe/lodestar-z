//! Shared test helpers for API handler tests.
//!
//! Provides a mock ApiContext backed by a MemoryKVStore for unit testing.

const std = @import("std");
const types = @import("types.zig");
const ctx_mod = @import("context.zig");
const ApiContext = ctx_mod.ApiContext;
const CachedBeaconState = ctx_mod.CachedBeaconState;
const config_mod = @import("config");
const preset = @import("preset").preset;
const db_mod = @import("db");
const MemoryKVStore = db_mod.memory_kv_store.MemoryKVStore;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

fn getTestHeadTracker(ptr: *anyopaque) ctx_mod.HeadTracker {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.head_tracker.*;
}

fn getTestCurrentSlot(ptr: *anyopaque) u64 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.current_slot;
}

fn getTestValidatorSeenAtEpoch(ptr: *anyopaque, validator_index: u64, epoch: u64) bool {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    return fixture.seen_liveness.contains(.{ .epoch = epoch, .validator_index = validator_index });
}

fn getTestSyncStatus(ptr: *anyopaque) ctx_mod.SyncStatus {
    const status: *ctx_mod.SyncStatus = @ptrCast(@alignCast(ptr));
    return status.*;
}

const TestChainFixture = struct {
    const LivenessKey = struct {
        epoch: u64,
        validator_index: u64,
    };

    allocator: std.mem.Allocator,
    db: *db_mod.BeaconDB,
    head_tracker: *ctx_mod.HeadTracker,
    sync_status: *ctx_mod.SyncStatus,
    beacon_config: *const config_mod.BeaconConfig,
    current_slot: u64,
    seen_liveness: std.AutoHashMap(LivenessKey, void),
    head_state: ?*CachedBeaconState = null,
    state_by_root: ?*CachedBeaconState = null,
    state_by_slot: ?*CachedBeaconState = null,
    fork_choice_heads: ?[]const types.DebugChainHead = null,
    fork_choice_nodes: ?[]types.ForkChoiceNode = null,
    block_rewards_result: ?types.BlockRewards = null,
    attestation_ideal_rewards: ?[]const types.IdealAttestationReward = null,
    attestation_total_rewards: ?[]const types.TotalAttestationReward = null,
    sync_committee_rewards: ?[]const types.SyncCommitteeReward = null,
    last_block_rewards_root: ?[32]u8 = null,
    last_attestation_rewards_epoch: ?u64 = null,
    last_attestation_reward_indices: ?[]u64 = null,
    last_sync_committee_rewards_root: ?[32]u8 = null,
    last_sync_committee_reward_indices: ?[]u64 = null,

    pub fn markValidatorSeenAtEpoch(self: *TestChainFixture, validator_index: u64, epoch: u64) !void {
        try self.seen_liveness.put(.{ .epoch = epoch, .validator_index = validator_index }, {});
    }
};

fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
    if (block_bytes.len < 108) return null;
    return std.mem.readInt(u64, block_bytes[100..108], .little);
}

fn getTestBlockRootBySlot(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (slot == fixture.head_tracker.head_slot) return fixture.head_tracker.head_root;
    return fixture.db.getFinalizedBlockRootBySlot(slot);
}

fn getTestFinalizedBlockRootByParentRoot(ptr: *anyopaque, parent_root: [32]u8) anyerror!?[32]u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    const child = try fixture.db.getArchivedCanonicalChild(parent_root) orelse return null;
    return child.root;
}

fn getTestBlockBytesByRoot(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (try fixture.db.getBlock(root)) |block_bytes| return block_bytes;
    return fixture.db.getBlockArchiveByRoot(root);
}

fn getTestBlobSidecarsByRoot(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (try fixture.db.getBlobSidecars(root)) |blob_bytes| return blob_bytes;
    return fixture.db.getBlobSidecarsArchiveByRoot(root);
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
    const block_root = try fixture.db.getFinalizedBlockRootBySlot(slot) orelse return null;
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

fn replaceCapturedIndices(
    allocator: std.mem.Allocator,
    target: *?[]u64,
    validator_indices: []const u64,
) !void {
    if (target.*) |existing| allocator.free(existing);
    target.* = try allocator.dupe(u64, validator_indices);
}

fn getTestBlockRewards(ptr: *anyopaque, _: std.mem.Allocator, block_root: [32]u8) anyerror!types.BlockRewards {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    fixture.last_block_rewards_root = block_root;
    return fixture.block_rewards_result orelse error.NotImplemented;
}

fn getTestAttestationRewards(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    epoch: u64,
    validator_indices: []const u64,
) anyerror!types.AttestationRewardsData {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    fixture.last_attestation_rewards_epoch = epoch;
    try replaceCapturedIndices(fixture.allocator, &fixture.last_attestation_reward_indices, validator_indices);
    const ideal = fixture.attestation_ideal_rewards orelse return error.NotImplemented;
    const total = fixture.attestation_total_rewards orelse return error.NotImplemented;
    return .{
        .ideal_rewards = try allocator.dupe(types.IdealAttestationReward, ideal),
        .total_rewards = try allocator.dupe(types.TotalAttestationReward, total),
    };
}

fn getTestSyncCommitteeRewards(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    block_root: [32]u8,
    validator_indices: []const u64,
) anyerror![]const types.SyncCommitteeReward {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    fixture.last_sync_committee_rewards_root = block_root;
    try replaceCapturedIndices(fixture.allocator, &fixture.last_sync_committee_reward_indices, validator_indices);
    const rewards = fixture.sync_committee_rewards orelse return error.NotImplemented;
    return allocator.dupe(types.SyncCommitteeReward, rewards);
}

fn getTestForkChoiceHeads(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]types.DebugChainHead {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    if (fixture.fork_choice_heads) |heads| return allocator.dupe(types.DebugChainHead, heads);

    const heads = try allocator.alloc(types.DebugChainHead, 1);
    heads[0] = .{
        .slot = fixture.head_tracker.head_slot,
        .root = fixture.head_tracker.head_root,
    };
    return heads;
}

fn getTestForkChoiceDump(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!types.ForkChoiceDump {
    const fixture: *TestChainFixture = @ptrCast(@alignCast(ptr));
    const nodes = if (fixture.fork_choice_nodes) |items|
        try allocator.dupe(types.ForkChoiceNode, items)
    else blk: {
        const out = try allocator.alloc(types.ForkChoiceNode, 1);
        out[0] = .{
            .slot = fixture.head_tracker.head_slot,
            .block_root = fixture.head_tracker.head_root,
            .parent_root = null,
            .justified_epoch = fixture.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
            .finalized_epoch = fixture.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
            .weight = 0,
            .validity = "valid",
            .execution_block_hash = [_]u8{0} ** 32,
        };
        break :blk out;
    };

    return .{
        .justified_checkpoint = .{
            .epoch = fixture.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
            .root = fixture.head_tracker.justified_root,
        },
        .finalized_checkpoint = .{
            .epoch = fixture.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
            .root = fixture.head_tracker.finalized_root,
        },
        .fork_choice_nodes = nodes,
    };
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
        .current_slot = default_head_tracker.head_slot,
        .seen_liveness = std.AutoHashMap(TestChainFixture.LivenessKey, void).init(allocator),
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
                .getCurrentSlotFn = &getTestCurrentSlot,
                .validatorSeenAtEpochFn = &getTestValidatorSeenAtEpoch,
                .getBlockRootBySlotFn = &getTestBlockRootBySlot,
                .getFinalizedBlockRootByParentRootFn = &getTestFinalizedBlockRootByParentRoot,
                .getBlockBytesByRootFn = &getTestBlockBytesByRoot,
                .getBlobSidecarsByRootFn = &getTestBlobSidecarsByRoot,
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
                .getBlockRewardsFn = &getTestBlockRewards,
                .getAttestationRewardsFn = &getTestAttestationRewards,
                .getSyncCommitteeRewardsFn = &getTestSyncCommitteeRewards,
            },
            .sync_status_view = .{
                .ptr = @ptrCast(sync_status),
                .getSyncStatusFn = &getTestSyncStatus,
            },
            .fork_choice_debug = .{
                .ptr = @ptrCast(chain_fixture),
                .getHeadsFn = &getTestForkChoiceHeads,
                .getForkChoiceDumpFn = &getTestForkChoiceDump,
            },
        },
    };
}

pub fn destroyTestContext(allocator: std.mem.Allocator, tc: *TestContext) void {
    if (tc.chain_fixture.fork_choice_heads) |heads| allocator.free(heads);
    if (tc.chain_fixture.fork_choice_nodes) |nodes| allocator.free(nodes);
    if (tc.chain_fixture.attestation_ideal_rewards) |items| allocator.free(items);
    if (tc.chain_fixture.attestation_total_rewards) |items| allocator.free(items);
    if (tc.chain_fixture.sync_committee_rewards) |items| allocator.free(items);
    if (tc.chain_fixture.last_attestation_reward_indices) |items| allocator.free(items);
    if (tc.chain_fixture.last_sync_committee_reward_indices) |items| allocator.free(items);
    tc.chain_fixture.seen_liveness.deinit();
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
