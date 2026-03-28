const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const constants = @import("constants");
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

const proto_node = @import("proto_array.zig");
const ProtoBlock = proto_node.ProtoBlock;
const ProtoNode = proto_node.ProtoNode;
const LVHExecResponse = proto_node.LVHExecResponse;
const ForkChoiceError = proto_node.ForkChoiceError;
const PayloadStatus = proto_node.PayloadStatus;
const BlockExtraMeta = proto_node.BlockExtraMeta;

const vote_tracker = @import("vote_tracker.zig");
const Votes = vote_tracker.Votes;
const NULL_VOTE_INDEX = vote_tracker.NULL_VOTE_INDEX;

const compute_deltas_mod = @import("compute_deltas.zig");
const computeDeltas = compute_deltas_mod.computeDeltas;
const DeltasCache = compute_deltas_mod.DeltasCache;
const EquivocatingIndices = compute_deltas_mod.EquivocatingIndices;

const ZERO_HASH = constants.ZERO_HASH;
const preset_mod = @import("preset");
const preset = preset_mod.preset;

/// Checkpoint with root, matching Lodestar TS CheckpointWithHex.
pub const Checkpoint = struct {
    epoch: Epoch,
    root: Root,
};

/// Effective balance increments (1 increment = 1 ETH effective balance).
/// Matches Lodestar TS EffectiveBalanceIncrements = Uint16Array.
pub const EffectiveBalanceIncrements = std.ArrayListUnmanaged(u16);

/// Result of getHead, providing both the head node and diagnostic info.
pub const HeadResult = struct {
    block_root: Root,
    slot: Slot,
    state_root: Root,
    /// Whether execution status is optimistic (syncing or payload_separated).
    execution_optimistic: bool,
    /// Payload status of the head node (Gloas ePBS). Pre-Gloas is always .full.
    payload_status: PayloadStatus = .full,
};

/// Information passed to shouldOverrideForkChoiceUpdate to decide
/// whether to reorg the current head by building on its parent.
///
/// Corresponds to Lodestar TS shouldOverrideForkChoiceUpdate() parameters.
pub const ProposerHeadInfo = struct {
    /// Root of the current head block (may be weak).
    head_block_root: Root,
    /// Payload status of the current head block.
    head_payload_status: PayloadStatus,
    /// The current slot (when the proposer is preparing to produce a block).
    current_slot: Slot,
    /// Seconds elapsed since the start of current_slot.
    /// Used for timing check: reorg is only safe if proposing on time.
    sec_from_slot: f64,
    /// Total effective balance of justified validators (in ETH increments).
    /// Used to compute weight thresholds via committee fraction.
    total_justified_balance: u64,
    /// REORG_HEAD_WEIGHT_THRESHOLD from ChainConfig (default: 20).
    /// Head is "weak" if its weight < total_balance * threshold / (100 * SLOTS_PER_EPOCH).
    reorg_head_weight_threshold: u64,
    /// REORG_PARENT_WEIGHT_THRESHOLD from ChainConfig (default: 160).
    /// Parent is "strong" if its weight > total_balance * threshold / (100 * SLOTS_PER_EPOCH).
    reorg_parent_weight_threshold: u64,
    /// REORG_MAX_EPOCHS_SINCE_FINALIZATION from ChainConfig (default: 2).
    /// Reorg is only attempted if the chain has been finalizing recently.
    reorg_max_epochs_since_finalization: u64,
    /// Whether the proposer-boost reorg feature is enabled.
    /// When false, shouldOverrideForkChoiceUpdate always returns false.
    proposer_boost_reorg_enabled: bool,
};

/// Options for ForkChoice initialization.
pub const InitOpts = struct {
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    justified_balances: []const u16,
    prune_threshold: u32 = proto_array_mod.DEFAULT_PRUNE_THRESHOLD,
};

/// High-level fork choice struct wrapping ProtoArray, Votes, and checkpoint state.
///
/// This is the public API matching Lodestar TS IForkChoice.
/// Orchestrates: computeDeltas -> applyScoreChanges -> findHead.
pub const ForkChoice = struct {
    /// The core DAG maintaining block nodes and weights.
    proto_array: ProtoArray,
    /// Per-validator vote tracking (SoA for cache efficiency).
    votes: Votes,
    /// Effective balance increments at the justified checkpoint.
    /// Used as "old balances" in computeDeltas.
    justified_balances: EffectiveBalanceIncrements,
    /// Set of equivocating validator indices (from attester slashings).
    equivocating_indices: EquivocatingIndices,
    /// Pre-allocated deltas buffer reused across getHead calls.
    deltas_cache: DeltasCache,

    // ── Checkpoint state ──

    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    /// Best justified checkpoint seen (may be ahead of justified_checkpoint).
    best_justified_checkpoint: Checkpoint,
    /// Unrealized justified checkpoint from pull-up FFG.
    unrealized_justified_checkpoint: Checkpoint,
    /// Unrealized finalized checkpoint from pull-up FFG.
    unrealized_finalized_checkpoint: Checkpoint,

    // ── Time ──

    current_slot: Slot,

    // ── Head tracking ──

    /// Cached head from last getHead call.
    head: HeadResult,
    /// Whether head needs recomputation (votes/blocks changed since last getHead).
    synced: bool,

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

        var justified_balances: EffectiveBalanceIncrements = .empty;
        errdefer justified_balances.deinit(allocator);
        try justified_balances.appendSlice(allocator, opts.justified_balances);

        return .{
            .proto_array = proto_array,
            .votes = .{},
            .justified_balances = justified_balances,
            .equivocating_indices = EquivocatingIndices.init(allocator),
            .deltas_cache = .empty,
            .justified_checkpoint = opts.justified_checkpoint,
            .finalized_checkpoint = opts.finalized_checkpoint,
            .best_justified_checkpoint = opts.justified_checkpoint,
            .unrealized_justified_checkpoint = opts.justified_checkpoint,
            .unrealized_finalized_checkpoint = opts.finalized_checkpoint,
            .current_slot = current_slot,
            .head = .{
                .block_root = anchor_block.block_root,
                .slot = anchor_block.slot,
                .state_root = anchor_block.state_root,
                .execution_optimistic = false,
            },
            .synced = false,
        };
    }

    pub fn deinit(self: *ForkChoice, allocator: Allocator) void {
        self.deltas_cache.deinit(allocator);
        self.equivocating_indices.deinit();
        self.justified_balances.deinit(allocator);
        self.votes.deinit(allocator);
        self.proto_array.deinit(allocator);
        self.* = undefined;
    }

    // ── Block processing ──

    /// Add a block to the fork choice DAG.
    /// Validates the block against current state before insertion.
    pub fn onBlock(
        self: *ForkChoice,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError || ForkChoiceError)!void {
        // Reject blocks from the future.
        if (block.slot > current_slot) return error.InvalidBlock;

        // Reject blocks at or before the finalized slot.
        const finalized_slot = computeStartSlotAtEpoch(self.finalized_checkpoint.epoch);
        if (block.slot <= finalized_slot) return error.InvalidBlock;

        // Parent must be known.
        if (self.proto_array.getDefaultNodeIndex(block.parent_root) == null) {
            return error.InvalidBlock;
        }

        // Reject if parent is not a finalized descendant (block would be on a non-canonical chain).
        const parent_idx = self.proto_array.getDefaultNodeIndex(block.parent_root).?;
        const parent_node = &self.proto_array.nodes.items[parent_idx];
        if (!self.proto_array.isFinalizedRootOrDescendant(parent_node)) {
            return error.InvalidBlock;
        }

        try self.proto_array.onBlock(allocator, block, current_slot, null);
        self.synced = false;
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
        // Target epoch must not be in the future.
        const current_epoch = computeEpochAtSlot(self.current_slot);
        if (target_epoch > current_epoch) return error.InvalidAttestation;

        // The attested block must exist in the DAG.
        const node_index = self.proto_array.getDefaultNodeIndex(block_root) orelse
            return error.InvalidAttestation;

        // Ensure votes array has capacity.
        try self.votes.ensureValidatorCount(allocator, @intCast(validator_index + 1));

        // Get the SoA fields for this validator.
        const fields = self.votes.fields();

        // Reject stale attestation: slot-based monotonicity for Gloas.
        const target_slot = computeStartSlotAtEpoch(target_epoch);
        if (target_slot <= fields.next_slots[validator_index] and
            fields.next_indices[validator_index] != NULL_VOTE_INDEX)
        {
            return; // Stale vote — silently ignored (not an error).
        }

        fields.next_indices[validator_index] = @intCast(node_index);
        fields.next_slots[validator_index] = target_slot;
        self.synced = false;
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
            self.justified_balances.items,
            new_balances,
            &self.equivocating_indices,
        );

        try self.proto_array.applyScoreChanges(
            result.deltas,
            self.proto_array.previous_proposer_boost,
            self.justified_checkpoint.epoch,
            self.justified_checkpoint.root,
            self.finalized_checkpoint.epoch,
            self.finalized_checkpoint.root,
            self.current_slot,
        );

        const head_node = try self.proto_array.findHead(
            self.justified_checkpoint.root,
            self.current_slot,
        );

        const exec_status = head_node.extra_meta.executionStatus();
        self.head = .{
            .block_root = head_node.block_root,
            .slot = head_node.slot,
            .state_root = head_node.state_root,
            .execution_optimistic = exec_status == .syncing or exec_status == .payload_separated,
            .payload_status = head_node.payload_status,
        };
        self.synced = true;

        // Update old balances for next delta computation.
        self.justified_balances.clearRetainingCapacity();
        try self.justified_balances.appendSlice(allocator, new_balances);

        return self.head;
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
        self.synced = false;
    }

    /// Clear proposer boost (typically at start of new slot).
    pub fn clearProposerBoost(self: *ForkChoice) void {
        self.proto_array.previous_proposer_boost = null;
        self.synced = false;
    }

    // ── Equivocation ──

    /// Mark validators as equivocating (attester slashing).
    /// Their weight is removed in the next computeDeltas call.
    pub fn onAttesterSlashing(
        self: *ForkChoice,
        slashing_indices: []const ValidatorIndex,
    ) Allocator.Error!void {
        for (slashing_indices) |idx| {
            try self.equivocating_indices.put(idx, {});
        }
        self.synced = false;
    }

    // ── Time ──

    pub fn updateTime(self: *ForkChoice, current_slot: Slot) void {
        if (current_slot > self.current_slot) {
            self.current_slot = current_slot;
            self.synced = false;
        }
    }

    pub fn getTime(self: *const ForkChoice) Slot {
        return self.current_slot;
    }

    // ── Checkpoint management ──

    /// Update justified checkpoint and balances.
    pub fn updateJustifiedCheckpoint(
        self: *ForkChoice,
        allocator: Allocator,
        checkpoint: Checkpoint,
        balances: []const u16,
    ) Allocator.Error!void {
        self.justified_checkpoint = checkpoint;
        self.justified_balances.clearRetainingCapacity();
        try self.justified_balances.appendSlice(allocator, balances);
        self.synced = false;
    }

    /// Update finalized checkpoint.
    pub fn updateFinalizedCheckpoint(self: *ForkChoice, checkpoint: Checkpoint) void {
        self.finalized_checkpoint = checkpoint;
        self.synced = false;
    }

    /// Update best justified checkpoint (may be ahead of current justified).
    pub fn updateBestJustifiedCheckpoint(self: *ForkChoice, checkpoint: Checkpoint) void {
        if (checkpoint.epoch > self.best_justified_checkpoint.epoch) {
            self.best_justified_checkpoint = checkpoint;
        }
    }

    /// Update unrealized checkpoints from pull-up FFG.
    pub fn updateUnrealizedCheckpoints(
        self: *ForkChoice,
        justified: Checkpoint,
        finalized: Checkpoint,
    ) void {
        self.unrealized_justified_checkpoint = justified;
        self.unrealized_finalized_checkpoint = finalized;
    }

    pub fn getJustifiedCheckpoint(self: *const ForkChoice) Checkpoint {
        return self.justified_checkpoint;
    }

    pub fn getFinalizedCheckpoint(self: *const ForkChoice) Checkpoint {
        return self.finalized_checkpoint;
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
        self.synced = false;
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
        // Start from the head node in the proto array.
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

    /// Check if a block is the finalized root or a descendant of it.
    pub fn isFinalizedRootOrDescendant(self: *const ForkChoice, block_root: Root) bool {
        return self.proto_array.isFinalizedRootOrDescendant(block_root);
    }

    // ── Safe blocks (EIP-3675) ──

    /// Get the safe beacon block root.
    ///
    /// The "safe" block is the most recent block that 2/3+ of validators have
    /// attested to. Lodestar simplification:
    ///   safe = justified checkpoint block root
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.6.0/fork_choice/safe-block.md#get_safe_beacon_block_root
    pub fn getSafeBlockRoot(self: *const ForkChoice) Root {
        return self.justified_checkpoint.root;
    }

    /// Get the block node for the justified (safe) checkpoint.
    /// Returns null if the justified checkpoint block is not in the DAG.
    pub fn getJustifiedBlock(self: *const ForkChoice) ?*const ProtoNode {
        const idx = self.proto_array.getDefaultNodeIndex(self.justified_checkpoint.root) orelse return null;
        return &self.proto_array.nodes.items[idx];
    }

    /// Get the execution payload block hash for the safe block.
    ///
    /// Returns the execution payload block hash of the justified checkpoint block,
    /// or ZERO_HASH if the block is pre-merge or not found.
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.6.0/fork_choice/safe-block.md#get_safe_execution_block_hash
    pub fn getSafeExecutionBlockHash(self: *const ForkChoice) [32]u8 {
        const node = self.getJustifiedBlock() orelse return ZERO_HASH;
        return node.extra_meta.executionPayloadBlockHash() orelse ZERO_HASH;
    }

    // ── Proposer head (single-slot reorg) ──

    /// Determine whether to override the fork choice update to build on the head's
    /// parent instead of the head itself (proposer-boost reorg).
    ///
    /// Returns true if the current head is "weak" and the proposer should build
    /// on the parent to reorg it. All of the following must hold:
    ///   1. proposer_boost_reorg_enabled is true
    ///   2. Head block arrived late (timeliness == false)
    ///   3. Proposal slot is not at an epoch boundary (shuffling stable)
    ///   4. Head and parent share the same unrealized justified checkpoint (FFG competitive)
    ///   5. Chain has been finalizing recently (epochsSinceFinalization <= max)
    ///   6. Parent is exactly one slot before head
    ///   7. Head arrived in the current slot (timing check)
    ///   8. Head node weight < committee fraction (head is weak)
    ///   9. Parent node weight > parent committee fraction (parent is strong)
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/phase0/fork-choice.md#get_proposer_head
    pub fn shouldOverrideForkChoiceUpdate(
        self: *const ForkChoice,
        info: ProposerHeadInfo,
    ) bool {
        // Feature gate: proposer-boost reorg must be enabled.
        if (!info.proposer_boost_reorg_enabled) return false;

        // Head block must exist.
        const head_node = self.proto_array.getNode(
            info.head_block_root,
            info.head_payload_status,
        ) orelse return false;

        // Head must have arrived late (timeliness == false means late block).
        // is_head_late = NOT timeliness
        if (head_node.timeliness) return false; // Head is timely — no reorg

        // Proposal slot must not be at an epoch boundary (shuffling stable check).
        const proposal_slot = head_node.slot + 1;
        if (proposal_slot % preset.SLOTS_PER_EPOCH == 0) return false;

        // Parent block must exist.
        const parent_node = blk: {
            const parent_idx = self.proto_array.getDefaultNodeIndex(head_node.parent_root) orelse
                return false;
            break :blk &self.proto_array.nodes.items[parent_idx];
        };

        // FFG competitive: head and parent must share the same unrealized justified checkpoint.
        const head_j_epoch = head_node.unrealized_justified_epoch;
        const head_j_root = head_node.unrealized_justified_root;
        const parent_j_epoch = parent_node.unrealized_justified_epoch;
        const parent_j_root = parent_node.unrealized_justified_root;
        const ffg_ok = head_j_epoch == parent_j_epoch and
            std.mem.eql(u8, &head_j_root, &parent_j_root);
        if (!ffg_ok) return false;

        // Finalization check: chain must be finalizing within configured max.
        const current_epoch = computeEpochAtSlot(info.current_slot);
        const epochs_since_finalization = current_epoch -| self.finalized_checkpoint.epoch;
        if (epochs_since_finalization > info.reorg_max_epochs_since_finalization) return false;

        // Single-slot reorg: parent must be exactly one slot before head.
        if (parent_node.slot + 1 != head_node.slot) return false;

        // Timing check: head block must be in the current slot.
        if (head_node.slot != info.current_slot) return false;

        // Head weight threshold: head is "weak" if weight < reorg threshold.
        // committee_fraction = total_balance * threshold / (100 * SLOTS_PER_EPOCH)
        const head_threshold = info.total_justified_balance *
            info.reorg_head_weight_threshold /
            (100 * @as(u64, preset.SLOTS_PER_EPOCH));
        const head_weight: i64 = head_node.weight;
        if (head_weight >= @as(i64, @intCast(head_threshold))) return false; // Head is not weak

        // Parent weight threshold: parent must be "strong".
        const parent_threshold = info.total_justified_balance *
            info.reorg_parent_weight_threshold /
            (100 * @as(u64, preset.SLOTS_PER_EPOCH));
        const parent_weight: i64 = parent_node.weight;
        if (parent_weight <= @as(i64, @intCast(parent_threshold))) return false; // Parent not strong

        return true;
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
        self.synced = false;
    }

    /// Notify PTC votes for a block.
    pub fn notifyPtcMessages(
        self: *ForkChoice,
        block_root: Root,
        ptc_indices: []const u32,
        payload_present: bool,
    ) void {
        self.proto_array.notifyPtcMessages(block_root, ptc_indices, payload_present);
        self.synced = false;
    }
};

// ── Tests ──

fn makeTestCheckpoint(epoch: Epoch, root: Root) Checkpoint {
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

test "init and deinit" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    try testing.expect(fc.hasBlock(genesis_root));
    try testing.expectEqual(@as(usize, 1), fc.nodeCount());
    try testing.expectEqual(genesis_root, fc.getHeadRoot());
}

test "onBlock adds block to DAG" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    const block_a = makeTestBlock(1, block_a_root, genesis_root);
    try fc.onBlock(testing.allocator, block_a, 10);

    try testing.expect(fc.hasBlock(block_a_root));
    try testing.expectEqual(@as(usize, 2), fc.nodeCount());
}

test "onBlock rejects future slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 5);
    defer fc.deinit(testing.allocator);

    const future_block = makeTestBlock(10, hashFromByte(0x02), genesis_root);
    try testing.expectError(error.InvalidBlock, fc.onBlock(testing.allocator, future_block, 5));
}

test "onBlock rejects unknown parent" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    const orphan_block = makeTestBlock(1, hashFromByte(0x02), hashFromByte(0xFF));
    try testing.expectError(error.InvalidBlock, fc.onBlock(testing.allocator, orphan_block, 10));
}

test "onAttestation records vote" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    const block_a = makeTestBlock(1, block_a_root, genesis_root);
    try fc.onBlock(testing.allocator, block_a, 10);

    // Validator 0 attests to block_a in epoch 0.
    try fc.onAttestation(testing.allocator, 0, block_a_root, 0);

    // Votes array should have grown.
    try testing.expectEqual(@as(u32, 1), fc.votes.len());
    const fields = fc.votes.fields();
    const expected_index = fc.proto_array.getDefaultNodeIndex(block_a_root).?;
    try testing.expectEqual(expected_index, fields.next_indices[0]);
}

test "onAttestation rejects future epoch" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    // Current slot 0 → epoch 0. Attesting to epoch 5 is invalid.
    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, 0, genesis_root, 5));
}

test "onAttestation rejects unknown block" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, 0, hashFromByte(0xFF), 0));
}

test "getHead returns genesis when no votes" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
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
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &[_]u16{ 1, 1, 1 },
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

    // Create two branches: genesis -> A, genesis -> B.
    try fc.onBlock(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlock(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 64);

    // All 3 validators vote for block B.
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
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &[_]u16{ 1, 1, 1 },
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

    try fc.onBlock(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlock(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 64);

    // Validators 0, 1 vote B; validator 2 votes A.
    try fc.onAttestation(testing.allocator, 0, block_b_root, 0);
    try fc.onAttestation(testing.allocator, 1, block_b_root, 0);
    try fc.onAttestation(testing.allocator, 2, block_a_root, 0);

    const balances = [_]u16{ 1, 1, 1 };

    // Before slashing: B has 2 votes, A has 1 → head = B.
    const head1 = try fc.getHead(testing.allocator, &balances);
    try testing.expectEqual(block_b_root, head1.block_root);

    // Slash validator 0 and 1 (B voters).
    try fc.onAttesterSlashing(&[_]ValidatorIndex{ 0, 1 });

    // After slashing: B voters removed → A has 1 vote, B has 0 → head = A.
    const head2 = try fc.getHead(testing.allocator, &balances);
    try testing.expectEqual(block_a_root, head2.block_root);
}

test "updateTime advances slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    try testing.expectEqual(@as(Slot, 0), fc.getTime());
    fc.updateTime(10);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());

    // Time should not go backwards.
    fc.updateTime(5);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());
}

test "checkpoint updates" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
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
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    // Prune with genesis as finalized — should be no-op (index 0).
    const pruned = try fc.prune(testing.allocator, genesis_root);
    try testing.expectEqual(@as(usize, 0), pruned.len);
}

test "isDescendant checks ancestry" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    // genesis -> A -> B
    try fc.onBlock(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 10);
    try fc.onBlock(testing.allocator, makeTestBlock(2, block_b_root, block_a_root), 10);

    try testing.expect(try fc.isDescendant(genesis_root, .full, block_b_root, .full));
    try testing.expect(try fc.isDescendant(block_a_root, .full, block_b_root, .full));
    try testing.expect(!try fc.isDescendant(block_b_root, .full, block_a_root, .full));
}

test "getSafeBlockRoot returns justified checkpoint root" {
    const genesis_root = hashFromByte(0x01);
    const justified_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    // Initially returns genesis (justified = genesis at epoch 0).
    try testing.expectEqual(genesis_root, fc.getSafeBlockRoot());

    // After justified checkpoint update, returns the new justified root.
    try fc.updateJustifiedCheckpoint(testing.allocator, makeTestCheckpoint(1, justified_root), &.{});
    try testing.expectEqual(justified_root, fc.getSafeBlockRoot());
}

test "getSafeExecutionBlockHash returns ZERO_HASH for pre-merge block" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

    // Genesis is pre-merge → no execution payload → ZERO_HASH.
    try testing.expectEqual(ZERO_HASH, fc.getSafeExecutionBlockHash());
}

test "getSafeExecutionBlockHash returns execution block hash for post-merge justified block" {
    const genesis_root = hashFromByte(0x01);
    const justified_root = hashFromByte(0x02);
    const exec_hash = hashFromByte(0xAA);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    // Add a post-merge block as the justified checkpoint block.
    var post_merge_block = makeTestBlock(1, justified_root, genesis_root);
    post_merge_block.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(
            exec_hash,
            1,
            .valid,
            .available,
        ),
    };
    try fc.onBlock(testing.allocator, post_merge_block, 10);

    // Update justified to the post-merge block.
    try fc.updateJustifiedCheckpoint(testing.allocator, makeTestCheckpoint(1, justified_root), &.{});
    try testing.expectEqual(exec_hash, fc.getSafeExecutionBlockHash());
}

test "shouldOverrideForkChoiceUpdate disabled when feature off" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    try testing.expect(!fc.shouldOverrideForkChoiceUpdate(.{
        .head_block_root = genesis_root,
        .head_payload_status = .full,
        .current_slot = 10,
        .sec_from_slot = 0.0,
        .total_justified_balance = 1000,
        .reorg_head_weight_threshold = 20,
        .reorg_parent_weight_threshold = 160,
        .reorg_max_epochs_since_finalization = 2,
        .proposer_boost_reorg_enabled = false, // Disabled
    }));
}

test "shouldOverrideForkChoiceUpdate timely head not reorged" {
    const genesis_root = hashFromByte(0x01);
    const head_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, 10);
    defer fc.deinit(testing.allocator);

    // Add head block — timeliness = true (arrived on time).
    var head_block = makeTestBlock(10, head_root, genesis_root);
    head_block.timeliness = true;
    try fc.onBlock(testing.allocator, head_block, 10);

    try testing.expect(!fc.shouldOverrideForkChoiceUpdate(.{
        .head_block_root = head_root,
        .head_payload_status = .full,
        .current_slot = 10,
        .sec_from_slot = 0.0,
        .total_justified_balance = 1000,
        .reorg_head_weight_threshold = 20,
        .reorg_parent_weight_threshold = 160,
        .reorg_max_epochs_since_finalization = 2,
        .proposer_boost_reorg_enabled = true,
    }));
}

test "shouldOverrideForkChoiceUpdate returns true for weak late head" {
    const slots_per_epoch = preset.SLOTS_PER_EPOCH;
    const genesis_root = hashFromByte(0x01);
    const head_root = hashFromByte(0x02);
    // Use slot within an epoch (not boundary) so shuffling check passes.
    const head_slot: Slot = slots_per_epoch + 5; // Not epoch boundary
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
    }, genesis_block, head_slot);
    defer fc.deinit(testing.allocator);

    // Add head block with timeliness = false (arrived late).
    var head_block = makeTestBlock(head_slot, head_root, genesis_root);
    head_block.timeliness = false;
    // Same unrealized justified as parent (genesis) for FFG competitive check.
    head_block.unrealized_justified_epoch = 0;
    head_block.unrealized_justified_root = genesis_root;
    try fc.onBlock(testing.allocator, head_block, head_slot);

    // Also update genesis's unrealized justified to match.
    fc.proto_array.nodes.items[0].unrealized_justified_epoch = 0;
    fc.proto_array.nodes.items[0].unrealized_justified_root = genesis_root;

    // Scale total_balance so thresholds work out cleanly.
    const total_balance: u64 = 10000 * @as(u64, slots_per_epoch);

    // Set head weight to 0 (weak) and parent weight high enough to be "strong".
    fc.proto_array.nodes.items[0].weight = @intCast(total_balance); // genesis/parent = strong
    fc.proto_array.nodes.items[1].weight = 0; // head = weak (0 < threshold)

    const result = fc.shouldOverrideForkChoiceUpdate(.{
        .head_block_root = head_root,
        .head_payload_status = .full,
        .current_slot = head_slot,
        .sec_from_slot = 0.0,
        .total_justified_balance = total_balance,
        .reorg_head_weight_threshold = 20,
        .reorg_parent_weight_threshold = 0, // parent threshold = 0, so any positive weight passes
        .reorg_max_epochs_since_finalization = 10,
        .proposer_boost_reorg_enabled = true,
    });
    try testing.expect(result);
}
