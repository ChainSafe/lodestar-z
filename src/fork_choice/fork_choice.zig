const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const constants = @import("constants");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;

const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const ValidatorIndex = primitives.ValidatorIndex.Type;

const proto_array_mod = @import("proto_array.zig");
const ProtoArray = proto_array_mod.ProtoArray;
const ProtoArrayError = proto_array_mod.ProtoArrayError;
const ProtoBlock = proto_array_mod.ProtoBlock;
const ProtoNode = proto_array_mod.ProtoNode;
const LVHExecResponse = proto_array_mod.LVHExecResponse;
const ForkChoiceError = proto_array_mod.ForkChoiceError;
const PayloadStatus = proto_array_mod.PayloadStatus;
const RootContext = proto_array_mod.RootContext;
const DEFAULT_PRUNE_THRESHOLD = proto_array_mod.DEFAULT_PRUNE_THRESHOLD;

const vote_tracker = @import("vote_tracker.zig");
const Votes = vote_tracker.Votes;
const NULL_VOTE_INDEX = vote_tracker.NULL_VOTE_INDEX;

const compute_deltas_mod = @import("compute_deltas.zig");
const computeDeltas = compute_deltas_mod.computeDeltas;
const DeltasCache = compute_deltas_mod.DeltasCache;

const store_mod = @import("store.zig");
pub const ForkChoiceStore = store_mod.ForkChoiceStore;
pub const Checkpoint = store_mod.Checkpoint;
pub const CheckpointWithPayloadStatus = store_mod.CheckpointWithPayloadStatus;
pub const JustifiedBalances = store_mod.JustifiedBalances;
const EffectiveBalanceIncrementsRc = store_mod.EffectiveBalanceIncrementsRc;
const JustifiedBalancesGetter = store_mod.JustifiedBalancesGetter;
const ForkChoiceStoreEvents = store_mod.ForkChoiceStoreEvents;

const interface_mod = @import("interface.zig");
const ForkChoiceOpts = interface_mod.ForkChoiceOpts;

const ZERO_HASH = constants.ZERO_HASH;

// ── Helper types ──

/// Queued attestation for deferred processing (current-slot attestations).
pub const QueuedAttestation = struct {
    validator_index: ValidatorIndex,
    payload_status: PayloadStatus,
};

/// BlockRoot -> []QueuedAttestation for a single slot's queued attestations.
pub const BlockAttestationMap = std.AutoHashMap(Root, std.ArrayListUnmanaged(QueuedAttestation));

/// Slot -> BlockAttestationMap for all queued attestations.
pub const QueuedAttestationMap = std.AutoArrayHashMap(Slot, BlockAttestationMap);

/// Set of validated attestation data roots (cleared each slot).
pub const RootSet = std.HashMapUnmanaged(Root, void, RootContext, 80);

// ── HeadResult ──

/// Result of getHead / updateHead, providing the head block and diagnostic info.
pub const HeadResult = struct {
    block_root: Root,
    slot: Slot,
    state_root: Root,
    /// Whether execution status is optimistic (syncing or payload_separated).
    execution_optimistic: bool,
    /// Payload status of the head node (Gloas ePBS). Pre-Gloas is always .full.
    payload_status: PayloadStatus = .full,
};

// ── InitOpts ──

/// Options for ForkChoice initialization.
pub const InitOpts = struct {
    config: *const BeaconConfig,
    opts: ForkChoiceOpts = .{},
    justified_checkpoint: CheckpointWithPayloadStatus,
    finalized_checkpoint: CheckpointWithPayloadStatus,
    justified_balances: []const u16,
    justified_balances_getter: JustifiedBalancesGetter,
    events: ForkChoiceStoreEvents = .{},
    prune_threshold: u32 = DEFAULT_PRUNE_THRESHOLD,
};

// ── ForkChoice ──

/// High-level fork choice struct wrapping ProtoArray, Votes, and checkpoint state.
///
/// This is the public API matching Lodestar TS IForkChoice.
/// Orchestrates: computeDeltas -> applyScoreChanges -> findHead.
pub const ForkChoice = struct {
    // ── Config & options ──
    config: *const BeaconConfig,
    opts: ForkChoiceOpts,

    // ── Core components ──
    proto_array: ProtoArray,
    votes: Votes,
    fcStore: ForkChoiceStore,
    deltas_cache: DeltasCache,

    // ── Head tracking ──
    head: ProtoBlock,

    // ── Proposer boost ──
    proposer_boost_root: ?Root,
    justified_proposer_boost_score: ?u64,

    // ── Balance tracking ──
    balances: *EffectiveBalanceIncrementsRc,

    // ── Attestation queue ──
    queued_attestations: QueuedAttestationMap,
    queued_attestations_previous_slot: u32,

    // ── Caches ──
    validated_attestation_datas: RootSet,

    // ── Error state ──
    irrecoverable_error: bool,

    /// Initialize ForkChoice from an anchor block.
    pub fn init(
        allocator: Allocator,
        opts: InitOpts,
        anchor_block: ProtoBlock,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError)!ForkChoice {
        var proto_array = try ProtoArray.initialize(
            allocator,
            anchor_block,
            current_slot,
        );
        errdefer proto_array.deinit(allocator);

        var store = try ForkChoiceStore.init(
            allocator,
            current_slot,
            opts.justified_checkpoint,
            opts.finalized_checkpoint,
            opts.justified_balances,
            opts.justified_balances_getter,
            opts.events,
        );
        errdefer store.deinit();

        // Share the store's justified balances Rc for initial balance tracking.
        const balances_rc = store.justified.balances.acquire();

        return .{
            .config = opts.config,
            .opts = opts.opts,
            .proto_array = proto_array,
            .votes = .{},
            .fcStore = store,
            .deltas_cache = .empty,
            .head = anchor_block,
            .proposer_boost_root = null,
            .justified_proposer_boost_score = null,
            .balances = balances_rc,
            .queued_attestations = QueuedAttestationMap.init(allocator),
            .queued_attestations_previous_slot = 0,
            .validated_attestation_datas = .{},
            .irrecoverable_error = false,
        };
    }

    pub fn deinit(self: *ForkChoice, allocator: Allocator) void {
        // Clean up queued attestations.
        var slot_iter = self.queued_attestations.iterator();
        while (slot_iter.next()) |entry| {
            var block_iter = entry.value_ptr.iterator();
            while (block_iter.next()) |block_entry| {
                block_entry.value_ptr.deinit(allocator);
            }
            entry.value_ptr.deinit();
        }
        self.queued_attestations.deinit();

        self.validated_attestation_datas.deinit(allocator);
        self.balances.release();
        self.deltas_cache.deinit(allocator);
        self.fcStore.deinit();
        self.votes.deinit(allocator);
        self.proto_array.deinit(allocator);
        self.* = undefined;
    }

    // ── Block processing ──

    /// Simplified onBlock that takes a pre-constructed ProtoBlock.
    /// Used by tests and for cases where block/state processing is done externally.
    /// The full onBlock (taking AnyBeaconBlock + CachedBeaconState) will be added later.
    pub fn onBlockFromProto(
        self: *ForkChoice,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError || ForkChoiceError)!void {
        if (block.slot > current_slot) return error.InvalidBlock;

        const finalized_slot = computeStartSlotAtEpoch(self.fcStore.finalized_checkpoint.epoch);
        if (block.slot <= finalized_slot) return error.InvalidBlock;

        const parent_idx = self.proto_array.getDefaultNodeIndex(block.parent_root) orelse return error.InvalidBlock;
        const parent_node = &self.proto_array.nodes.items[parent_idx];
        if (!self.proto_array.isFinalizedRootOrDescendant(parent_node)) return error.InvalidBlock;

        try self.proto_array.onBlock(allocator, block, current_slot, null);
    }

    // ── Attestation processing ──

    /// Record a validator's attestation vote for fork choice.
    /// Validates the attestation before recording.
    pub fn onAttestation(
        self: *ForkChoice,
        allocator: Allocator,
        validator_index: ValidatorIndex,
        block_root: Root,
        target_epoch: Epoch,
    ) (Allocator.Error || ForkChoiceError)!void {
        const current_epoch = computeEpochAtSlot(self.fcStore.current_slot);
        if (target_epoch > current_epoch) return error.InvalidAttestation;

        const node_index = self.proto_array.getDefaultNodeIndex(block_root) orelse
            return error.InvalidAttestation;

        try self.votes.ensureValidatorCount(allocator, @intCast(validator_index + 1));

        const fields = self.votes.fields();

        const target_slot = computeStartSlotAtEpoch(target_epoch);
        if (target_slot <= fields.next_slots[validator_index] and
            fields.next_indices[validator_index] != NULL_VOTE_INDEX)
        {
            return;
        }

        fields.next_indices[validator_index] = @intCast(node_index);
        fields.next_slots[validator_index] = target_slot;
    }

    // ── Head selection ──

    /// Compute the fork choice head: computeDeltas -> applyScoreChanges -> findHead.
    ///
    /// This is the main hot path. The deltas buffer is pre-allocated and reused.
    /// `new_balances` are the effective balance increments from the current justified state.
    pub fn getHead(
        self: *ForkChoice,
        allocator: Allocator,
        new_balances: []const u16,
    ) (Allocator.Error || ProtoArrayError || error{DeltaOverflow})!HeadResult {
        const vote_fields = self.votes.fields();

        const result = try computeDeltas(
            allocator,
            &self.deltas_cache,
            @intCast(self.proto_array.nodes.items.len),
            vote_fields.current_indices,
            vote_fields.next_indices,
            self.fcStore.justified.balances.get().items,
            new_balances,
            &self.fcStore.equivocating_indices,
        );

        try self.proto_array.applyScoreChanges(
            result.deltas,
            self.proto_array.previous_proposer_boost,
            self.fcStore.justified.checkpoint.epoch,
            self.fcStore.justified.checkpoint.root,
            self.fcStore.finalized_checkpoint.epoch,
            self.fcStore.finalized_checkpoint.root,
            self.fcStore.current_slot,
        );

        const head_node = try self.proto_array.findHead(
            self.fcStore.justified.checkpoint.root,
            self.fcStore.current_slot,
        );

        self.head = head_node.toBlock();

        const exec_status = head_node.extra_meta.executionStatus();
        const head_result: HeadResult = .{
            .block_root = head_node.block_root,
            .slot = head_node.slot,
            .state_root = head_node.state_root,
            .execution_optimistic = exec_status == .syncing or exec_status == .payload_separated,
            .payload_status = head_node.payload_status,
        };

        // Update old balances for next delta computation.
        var new_balances_list = JustifiedBalances.init(allocator);
        errdefer new_balances_list.deinit();
        try new_balances_list.appendSlice(new_balances);
        const new_balances_rc = try EffectiveBalanceIncrementsRc.init(allocator, new_balances_list);
        self.fcStore.justified.balances.release();
        self.fcStore.justified.balances = new_balances_rc;
        self.fcStore.justified.total_balance = store_mod.computeTotalBalance(new_balances);

        return head_result;
    }

    // ── Proposer boost ──

    /// Apply proposer boost for a block.
    /// Caller computes score = committee_weight * PROPOSER_SCORE_BOOST / 100
    /// (PROPOSER_SCORE_BOOST is in ChainConfig, not a comptime preset).
    pub fn setProposerBoost(
        self: *ForkChoice,
        root: Root,
        score: u64,
    ) void {
        self.proto_array.previous_proposer_boost = .{
            .root = root,
            .score = score,
        };
        self.proposer_boost_root = root;
    }

    /// Clear proposer boost (typically at start of new slot).
    pub fn clearProposerBoost(self: *ForkChoice) void {
        self.proto_array.previous_proposer_boost = null;
        self.proposer_boost_root = null;
    }

    // ── Equivocation ──

    /// Mark validators as equivocating (attester slashing).
    /// Their weight is removed in the next computeDeltas call.
    pub fn onAttesterSlashing(
        self: *ForkChoice,
        slashing_indices: []const ValidatorIndex,
    ) Allocator.Error!void {
        for (slashing_indices) |idx| {
            try self.fcStore.equivocating_indices.put(idx, {});
        }
    }

    // ── Time ──

    pub fn updateTime(self: *ForkChoice, current_slot: Slot) void {
        if (current_slot > self.fcStore.current_slot) {
            self.fcStore.current_slot = current_slot;
        }
    }

    pub fn getTime(self: *const ForkChoice) Slot {
        return self.fcStore.current_slot;
    }

    // ── Checkpoint management ──

    /// Update justified checkpoint and balances.
    /// Fires onJustified event if configured.
    pub fn updateJustifiedCheckpoint(
        self: *ForkChoice,
        allocator: Allocator,
        checkpoint: CheckpointWithPayloadStatus,
        balances: []const u16,
    ) !void {
        try self.fcStore.setJustified(allocator, checkpoint, balances);
    }

    /// Update finalized checkpoint.
    /// Delegates to ForkChoiceStore.setFinalizedCheckpoint which fires onFinalized event.
    pub fn updateFinalizedCheckpoint(self: *ForkChoice, checkpoint: CheckpointWithPayloadStatus) void {
        self.fcStore.setFinalizedCheckpoint(checkpoint);
    }

    /// Update unrealized checkpoints from pull-up FFG.
    pub fn updateUnrealizedCheckpoints(
        self: *ForkChoice,
        justified: CheckpointWithPayloadStatus,
        finalized: CheckpointWithPayloadStatus,
    ) void {
        self.fcStore.unrealized_justified = .{
            .checkpoint = justified,
            .balances = self.fcStore.unrealized_justified.balances,
            .total_balance = self.fcStore.unrealized_justified.total_balance,
        };
        self.fcStore.unrealized_finalized_checkpoint = finalized;
    }

    pub fn getJustifiedCheckpoint(self: *const ForkChoice) CheckpointWithPayloadStatus {
        return self.fcStore.justified.checkpoint;
    }

    pub fn getFinalizedCheckpoint(self: *const ForkChoice) CheckpointWithPayloadStatus {
        return self.fcStore.finalized_checkpoint;
    }

    // ── Pruning ──

    /// Prune finalized ancestors from the DAG to bound memory usage.
    /// Caller owns the returned pruned blocks slice.
    pub fn prune(
        self: *ForkChoice,
        allocator: Allocator,
        finalized_root: Root,
    ) (Allocator.Error || ProtoArrayError)![]ProtoBlock {
        return self.proto_array.maybePrune(allocator, finalized_root);
    }

    // ── Execution validation ──

    /// Propagate execution layer validity response through the DAG.
    pub fn validateLatestHash(
        self: *ForkChoice,
        allocator: Allocator,
        response: LVHExecResponse,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError)!void {
        try self.proto_array.validateLatestHash(allocator, response, current_slot);
    }

    // ── Queries ──

    /// Check if a block root exists in the DAG.
    pub fn hasBlock(self: *const ForkChoice, block_root: Root) bool {
        return self.proto_array.indices.contains(block_root);
    }

    /// Get the block node for a root, or null if not found.
    pub fn getBlock(self: *const ForkChoice, block_root: Root) ?*const ProtoNode {
        const idx = self.proto_array.getDefaultNodeIndex(block_root) orelse return null;
        return &self.proto_array.nodes.items[idx];
    }

    /// Check if one block is a descendant of another.
    /// Both root + payload status must match for identity.
    pub fn isDescendant(
        self: *const ForkChoice,
        ancestor_root: Root,
        ancestor_status: PayloadStatus,
        descendant_root: Root,
        descendant_status: PayloadStatus,
    ) ProtoArrayError!bool {
        return try self.proto_array.isDescendant(
            ancestor_root,
            ancestor_status,
            descendant_root,
            descendant_status,
        );
    }

    /// Get the canonical block matching the given root by walking the head's ancestor chain.
    /// Returns null if the root is not on the canonical chain.
    pub fn getCanonicalBlockByRoot(self: *const ForkChoice, block_root: Root) ProtoArrayError!?*const ProtoNode {
        const head_node = self.proto_array.getNode(
            self.head.block_root,
            self.head.payload_status,
        ) orelse return null;

        if (std.mem.eql(u8, &head_node.block_root, &block_root)) {
            return head_node;
        }

        var iter = self.proto_array.iterateAncestors(
            self.head.block_root,
            self.head.payload_status,
        );
        while (try iter.next()) |node| {
            if (std.mem.eql(u8, &node.block_root, &block_root)) {
                return node;
            }
        }

        return null;
    }

    /// Get the head block root (from cache, without recomputing).
    pub fn getHeadRoot(self: *const ForkChoice) Root {
        return self.head.block_root;
    }

    /// Get the number of nodes in the DAG.
    pub fn nodeCount(self: *const ForkChoice) usize {
        return self.proto_array.nodes.items.len;
    }

    /// Check if a block root is the finalized root or a descendant of it.
    pub fn isFinalizedRootOrDescendant(self: *const ForkChoice, block_root: Root) bool {
        const idx = self.proto_array.getDefaultNodeIndex(block_root) orelse return false;
        return self.proto_array.isFinalizedRootOrDescendant(&self.proto_array.nodes.items[idx]);
    }

    // ── Gloas (ePBS) ──

    /// Process an execution payload for a Gloas block (creates FULL variant).
    pub fn onExecutionPayload(
        self: *ForkChoice,
        allocator: Allocator,
        block_root: Root,
        current_slot: Slot,
        execution_payload_block_hash: Root,
        execution_payload_number: u64,
        execution_payload_state_root: Root,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        try self.proto_array.onExecutionPayload(
            allocator,
            block_root,
            current_slot,
            execution_payload_block_hash,
            execution_payload_number,
            execution_payload_state_root,
            proposer_boost_root,
        );
    }

    /// Notify PTC votes for a block.
    pub fn notifyPtcMessages(
        self: *ForkChoice,
        block_root: Root,
        ptc_indices: []const u32,
        payload_present: bool,
    ) void {
        self.proto_array.notifyPtcMessages(block_root, ptc_indices, payload_present);
    }
};

// ── Tests ──

fn makeTestCheckpoint(epoch: Epoch, root: Root) CheckpointWithPayloadStatus {
    return .{ .epoch = epoch, .root = root };
}

fn makeTestBlock(slot: Slot, root: Root, parent_root: Root) ProtoBlock {
    return .{
        .slot = slot,
        .block_root = root,
        .parent_root = parent_root,
        .state_root = ZERO_HASH,
        .target_root = root,
        .justified_epoch = 0,
        .justified_root = ZERO_HASH,
        .finalized_epoch = 0,
        .finalized_root = ZERO_HASH,
        .unrealized_justified_epoch = 0,
        .unrealized_justified_root = ZERO_HASH,
        .unrealized_finalized_epoch = 0,
        .unrealized_finalized_root = ZERO_HASH,
        .extra_meta = .{ .pre_merge = {} },
        .timeliness = true,
    };
}

fn hashFromByte(byte: u8) Root {
    var root: Root = ZERO_HASH;
    root[0] = byte;
    return root;
}

fn dummyBalancesGetter(_: ?*anyopaque, _: CheckpointWithPayloadStatus) JustifiedBalances {
    return JustifiedBalances.init(testing.allocator);
}

fn getTestConfig() *const BeaconConfig {
    return &config_mod.minimal.config;
}

const test_balances_getter: JustifiedBalancesGetter = .{ .getFn = dummyBalancesGetter };

test "init and deinit" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    try testing.expect(fc.hasBlock(genesis_root));
    try testing.expectEqual(@as(usize, 1), fc.nodeCount());
    try testing.expectEqual(genesis_root, fc.getHeadRoot());
}

test "onBlockFromProto adds block to DAG" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    const block_a = makeTestBlock(1, block_a_root, genesis_root);
    try fc.onBlockFromProto(testing.allocator, block_a, 10);

    try testing.expect(fc.hasBlock(block_a_root));
    try testing.expectEqual(@as(usize, 2), fc.nodeCount());
}

test "onBlockFromProto rejects future slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 5);
    defer fc.deinit(testing.allocator);

    const future_block = makeTestBlock(10, hashFromByte(0x02), genesis_root);
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, future_block, 5));
}

test "onBlockFromProto rejects unknown parent" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    const orphan_block = makeTestBlock(1, hashFromByte(0x02), hashFromByte(0xFF));
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, orphan_block, 10));
}

test "onAttestation records vote" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    const block_a = makeTestBlock(1, block_a_root, genesis_root);
    try fc.onBlockFromProto(testing.allocator, block_a, 10);

    try fc.onAttestation(testing.allocator, 0, block_a_root, 0);

    try testing.expectEqual(@as(u32, 1), fc.votes.len());
    const fields = fc.votes.fields();
    const expected_index = fc.proto_array.getDefaultNodeIndex(block_a_root).?;
    try testing.expectEqual(expected_index, fields.next_indices[0]);
}

test "onAttestation rejects future epoch" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, 0, genesis_root, 5));
}

test "onAttestation rejects unknown block" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, 0, hashFromByte(0xFF), 0));
}

test "getHead returns genesis when no votes" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    const head = try fc.getHead(testing.allocator, &.{});
    try testing.expectEqual(genesis_root, head.block_root);
}

test "getHead with votes shifts head" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &[_]u16{ 1, 1, 1 },
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 64);

    try fc.onAttestation(testing.allocator, 0, block_b_root, 0);
    try fc.onAttestation(testing.allocator, 1, block_b_root, 0);
    try fc.onAttestation(testing.allocator, 2, block_b_root, 0);

    const balances = [_]u16{ 1, 1, 1 };
    const head = try fc.getHead(testing.allocator, &balances);
    try testing.expectEqual(block_b_root, head.block_root);
}

test "onAttesterSlashing removes equivocating weight" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &[_]u16{ 1, 1, 1 },
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 64);

    try fc.onAttestation(testing.allocator, 0, block_b_root, 0);
    try fc.onAttestation(testing.allocator, 1, block_b_root, 0);
    try fc.onAttestation(testing.allocator, 2, block_a_root, 0);

    const balances = [_]u16{ 1, 1, 1 };

    const head1 = try fc.getHead(testing.allocator, &balances);
    try testing.expectEqual(block_b_root, head1.block_root);

    try fc.onAttesterSlashing(&[_]ValidatorIndex{ 0, 1 });

    const head2 = try fc.getHead(testing.allocator, &balances);
    try testing.expectEqual(block_a_root, head2.block_root);
}

test "updateTime advances slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    try testing.expectEqual(@as(Slot, 0), fc.getTime());
    fc.updateTime(10);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());

    fc.updateTime(5);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());
}

test "checkpoint updates" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    const new_root = hashFromByte(0x02);
    try fc.updateJustifiedCheckpoint(testing.allocator, makeTestCheckpoint(1, new_root), &[_]u16{1});
    try testing.expectEqual(@as(Epoch, 1), fc.getJustifiedCheckpoint().epoch);

    fc.updateFinalizedCheckpoint(makeTestCheckpoint(1, new_root));
    try testing.expectEqual(@as(Epoch, 1), fc.getFinalizedCheckpoint().epoch);
}

test "prune delegates to ProtoArray" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    const pruned = try fc.prune(testing.allocator, genesis_root);
    try testing.expectEqual(@as(usize, 0), pruned.len);
}

test "isDescendant checks ancestry" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, block_b_root, block_a_root), 10);

    try testing.expect(try fc.isDescendant(genesis_root, .full, block_b_root, .full));
    try testing.expect(try fc.isDescendant(block_a_root, .full, block_b_root, .full));
    try testing.expect(!try fc.isDescendant(block_b_root, .full, block_a_root, .full));
}
