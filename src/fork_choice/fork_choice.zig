const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const assert = std.debug.assert;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const constants = @import("constants");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const preset_mod = @import("preset");
const preset = preset_mod.preset;
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
const ExecutionStatus = proto_array_mod.ExecutionStatus;
const DataAvailabilityStatus = proto_array_mod.DataAvailabilityStatus;
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
const EffectiveBalanceIncrementsRc = store_mod.JustifiedBalancesRc;
const JustifiedBalancesGetter = store_mod.JustifiedBalancesGetter;
const ForkChoiceStoreEvents = store_mod.ForkChoiceStoreEvents;

/// Epoch offset for dependent root computation.
///
/// Spec: fork-choice.md (get_dependent_root)
///
///   current  = 0 (current epoch shuffling dependent root)
///   previous = 1 (previous epoch shuffling dependent root)
pub const EpochDifference = enum(u1) {
    current = 0,
    previous = 1,
};

/// Result of ancestor comparison between two blocks.
pub const AncestorStatus = enum {
    /// Blocks share a common ancestor at depth.
    common_ancestor,
    /// One block is a descendant of the other.
    descendant,
    /// No common ancestor found (should not happen in a valid chain).
    no_common_ancestor,
    /// One or both block roots are unknown to fork choice.
    block_unknown,
};

/// Result of `getCommonAncestorDepth`: ancestor status + optional depth.
pub const AncestorResult = union(AncestorStatus) {
    common_ancestor: struct { depth: u32 },
    descendant: void,
    no_common_ancestor: void,
    block_unknown: void,
};

/// Reason why proposer-boost reorging was NOT applied.
///
/// Used for metrics and debugging in `shouldOverrideForkChoiceUpdate`.
pub const NotReorgedReason = enum {
    head_block_is_timely,
    parent_block_not_available,
    proposer_boost_reorg_disabled,
    not_shuffling_stable,
    not_ffg_competitive,
    chain_long_unfinality,
    parent_block_distance_more_than_one_slot,
    reorg_more_than_one_slot,
    proposer_boost_not_worn_off,
    head_block_not_weak,
    parent_block_not_strong,
    not_proposing_on_time,
    not_proposer_of_next_slot,
    head_block_not_available,
    unknown,
};

/// Result of `shouldOverrideForkChoiceUpdate`.
pub const ShouldOverrideForkChoiceUpdateResult = union(enum) {
    /// FCU should be overridden with the parent block as head.
    should_override: struct { parent_block: ProtoBlock },
    /// FCU should NOT be overridden; reason explains why.
    should_not_override: struct { reason: NotReorgedReason },
};

/// Options controlling ForkChoice behavior.
pub const ForkChoiceOpts = struct {
    /// Enable proposer boost (default: true).
    proposer_boost: bool = true,
    /// Enable proposer boost reorging (default: false).
    proposer_boost_reorg: bool = false,
    /// Compute unrealized justified/finalized checkpoints (default: false).
    compute_unrealized: bool = false,
};

/// Mode for `updateAndGetHead`.
///
///   GetCanonicalHead:           updateHead() only, skip getProposerHead.
///   GetProposerHead:            updateHead() + getProposerHead() (for current-slot proposer).
///   GetPredictedProposerHead:   getHead() + predictProposerHead() (for next-slot planning).
pub const UpdateHeadOpt = enum {
    get_canonical_head,
    get_proposer_head,
    get_predicted_proposer_head,
};

/// Arguments for `updateAndGetHead`.
pub const UpdateAndGetHeadOpt = union(UpdateHeadOpt) {
    get_canonical_head: void,
    get_proposer_head: struct { sec_from_slot: u32, slot: Slot },
    get_predicted_proposer_head: struct { sec_from_slot: u32, slot: Slot },
};

/// Result of `updateAndGetHead` / `getProposerHead`.
pub const UpdateAndGetHeadResult = struct {
    head: ProtoBlock,
    is_head_timely: ?bool = null,
    not_reorged_reason: ?NotReorgedReason = null,
};

/// Checkpoint with balances (no Rc — used at API boundaries).
///
/// Unlike `ForkChoiceStore.JustifiedState` which uses reference-counted balances,
/// this is a simple value type for passing checkpoint + balance data across
/// function boundaries.
pub const CheckpointWithPayloadAndBalance = struct {
    checkpoint: CheckpointWithPayloadStatus,
    balances: []const u16,
};

/// Checkpoint with balances and precomputed total balance.
pub const CheckpointWithPayloadAndTotalBalance = struct {
    checkpoint: CheckpointWithPayloadStatus,
    balances: []const u16,
    total_balance: u64,
};

const fork_types = @import("fork_types");
const AnyIndexedAttestation = fork_types.AnyIndexedAttestation;
const AnyBeaconBlock = fork_types.AnyBeaconBlock;
const ForkSeq = @import("config").ForkSeq;
const CachedBeaconState = state_transition.CachedBeaconState;
const UnrealizedCheckpoints = state_transition.UnrealizedCheckpoints;
const BlockExtraMeta = proto_array_mod.BlockExtraMeta;

const ZERO_HASH = constants.ZERO_HASH;

// ── Helper functions ──

/// Compute a committee-weighted fraction of the justified total active balance.
/// Matches TS: `getCommitteeFraction(justifiedTotalActiveBalanceByIncrement, {slotsPerEpoch, committeePercent})`
pub fn getCommitteeFraction(total_active_balance_by_increment: u64, slots_per_epoch: u64, committee_percent: u64) u64 {
    assert(slots_per_epoch > 0);
    const committee_weight = total_active_balance_by_increment / slots_per_epoch;
    return (committee_weight * committee_percent) / 100;
}

// ── Helper types ──

/// Queued attestation for deferred processing (current-slot attestations).
pub const QueuedAttestation = struct {
    validator_index: ValidatorIndex,
    payload_status: PayloadStatus,
};

/// BlockRoot -> []QueuedAttestation for a single slot's queued attestations.
pub const BlockAttestationMap = std.AutoHashMapUnmanaged(Root, std.ArrayListUnmanaged(QueuedAttestation));

/// Slot -> BlockAttestationMap for all queued attestations.
pub const QueuedAttestationMap = std.AutoArrayHashMapUnmanaged(Slot, BlockAttestationMap);

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

// ── ForkChoice ──

/// High-level fork choice struct wrapping ProtoArray, Votes, and checkpoint state.
///
/// This is the public API matching Lodestar TS IForkChoice.
/// Instantiated from pre-built components (dependency injection), matching the TS constructor:
///   `new ForkChoice(config, fcStore, protoArray, validatorCount, metrics, opts?, logger?)`
/// Orchestrates: computeDeltas -> applyScoreChanges -> findHead.
pub const ForkChoice = struct {
    // ── Config & options ──
    config: *const BeaconConfig,
    opts: ForkChoiceOpts,

    // ── Core components (borrowed references — caller owns lifetime) ──
    proto_array: *ProtoArray,
    votes: Votes,
    fcStore: *ForkChoiceStore,
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

    /// Initialize ForkChoice in-place from pre-built components.
    /// The caller is responsible for the memory backing `self`, `proto_array`, and `fc_store`.
    /// Matches TS: `new ForkChoice(config, fcStore, protoArray, validatorCount, metrics, opts)`
    /// Votes are pre-allocated to `validator_count` and initialized to defaults.
    /// Head is computed via `updateHead()`.
    pub fn init(
        self: *ForkChoice,
        allocator: Allocator,
        config: *const BeaconConfig,
        fc_store: *ForkChoiceStore,
        proto_array: *ProtoArray,
        validator_count: u32,
        opts: ForkChoiceOpts,
    ) !void {
        self.* = .{
            .config = config,
            .opts = opts,
            .proto_array = proto_array,
            .votes = .{},
            .fcStore = fc_store,
            .deltas_cache = .empty,
            .head = undefined,
            .proposer_boost_root = null,
            .justified_proposer_boost_score = null,
            .balances = fc_store.justified.balances.acquire(),
            .queued_attestations = .empty,
            .queued_attestations_previous_slot = 0,
            .validated_attestation_datas = .empty,
            .irrecoverable_error = false,
        };

        // Pre-allocate votes for known validators (matches TS: new Array(validatorCount).fill(NULL_VOTE_INDEX))
        try self.votes.ensureValidatorCount(allocator, validator_count);

        // Compute initial head (matches TS: this.head = this.updateHead())
        try self.updateHead(allocator);
    }

    /// Release resources owned by ForkChoice (votes, caches, queued attestations).
    /// Does NOT free proto_array, fcStore, or `self` — caller owns those.
    pub fn deinit(self: *ForkChoice, allocator: Allocator) void {
        // Clean up queued attestations.
        var slot_iter = self.queued_attestations.iterator();
        while (slot_iter.next()) |entry| {
            var block_iter = entry.value_ptr.iterator();
            while (block_iter.next()) |block_entry| {
                block_entry.value_ptr.deinit(allocator);
            }
            entry.value_ptr.deinit(allocator);
        }
        self.queued_attestations.deinit(allocator);

        self.validated_attestation_datas.deinit(allocator);
        self.balances.release();
        self.deltas_cache.deinit(allocator);
        self.votes.deinit(allocator);
        self.* = undefined;
    }

    // ── Block processing ──

    /// Full block import matching TS `onBlock()`.
    /// Extracts checkpoints from state, computes unrealized checkpoints,
    /// updates fork choice store, and adds the block to the proto array.
    pub fn onBlock(
        self: *ForkChoice,
        allocator: Allocator,
        block: *const AnyBeaconBlock,
        block_root: Root,
        state: *CachedBeaconState,
        block_delay_sec: u32,
        current_slot: Slot,
        execution_status: proto_array_mod.ExecutionStatus,
        data_availability_status: proto_array_mod.DataAvailabilityStatus,
    ) !ProtoBlock {
        const slot = block.slot();
        const parent_root = block.parentRoot().*;

        // 1. Parent must be known.
        if (!self.proto_array.indices.contains(parent_root)) return error.InvalidBlock;

        // 2. Reject future slot.
        if (slot > current_slot) return error.InvalidBlock;

        // 3. Reject finalized slot.
        const finalized_slot = computeStartSlotAtEpoch(self.fcStore.finalized_checkpoint.epoch);
        if (slot <= finalized_slot) return error.InvalidBlock;

        // 4. Check finalized descendant.
        const parent_idx = self.proto_array.getDefaultNodeIndex(parent_root) orelse return error.InvalidBlock;
        const parent_node = &self.proto_array.nodes.items[parent_idx];
        if (!self.proto_array.isFinalizedRootOrDescendant(parent_node)) return error.InvalidBlock;

        // 5. Timeliness and proposer boost.
        const timely = self.isBlockTimely(slot, block_delay_sec);
        if (timely and self.proposer_boost_root == null) {
            self.proposer_boost_root = block_root;
        }

        // 6. Extract checkpoints from state.
        var ssz_justified: consensus_types.phase0.Checkpoint.Type = undefined;
        try state.state.currentJustifiedCheckpoint(&ssz_justified);
        var ssz_finalized: consensus_types.phase0.Checkpoint.Type = undefined;
        try state.state.finalizedCheckpoint(&ssz_finalized);

        const justified_checkpoint: CheckpointWithPayloadStatus = .{
            .epoch = ssz_justified.epoch,
            .root = ssz_justified.root,
        };
        const finalized_checkpoint: CheckpointWithPayloadStatus = .{
            .epoch = ssz_finalized.epoch,
            .root = ssz_finalized.root,
        };

        // 7. Compute or inherit unrealized checkpoints.
        var unrealized_justified = justified_checkpoint;
        var unrealized_finalized = finalized_checkpoint;
        if (self.opts.compute_unrealized) {
            const unrealized = try state_transition.computeUnrealizedCheckpoints(state, allocator);
            unrealized_justified = .{
                .epoch = unrealized.justified_checkpoint.epoch,
                .root = unrealized.justified_checkpoint.root,
            };
            unrealized_finalized = .{
                .epoch = unrealized.finalized_checkpoint.epoch,
                .root = unrealized.finalized_checkpoint.root,
            };
        }

        // 8. Update realized checkpoints.
        self.updateCheckpoints(justified_checkpoint, finalized_checkpoint);

        // 9. Update unrealized checkpoints.
        self.updateUnrealizedCheckpoints(unrealized_justified, unrealized_finalized);

        // 10. If block from past epoch: update realized with unrealized.
        const block_epoch = computeEpochAtSlot(slot);
        const current_epoch = computeEpochAtSlot(current_slot);
        if (block_epoch < current_epoch) {
            self.updateCheckpoints(unrealized_justified, unrealized_finalized);
        }

        // 11. Construct BlockExtraMeta based on fork.
        const fork_seq = block.forkSeq();
        const extra_meta: BlockExtraMeta = if (fork_seq.gte(.gloas)) blk: {
            // Gloas (ePBS): execution payload is separated.
            const validated_exec_status = try getPostGloasExecStatus(execution_status);
            const body = block.beaconBlockBody();
            if (body.blockType() == .full) {
                const payload = try body.executionPayload();
                break :blk .{ .post_merge = BlockExtraMeta.PostMergeMeta.init(
                    payload.blockHash().*,
                    payload.blockNumber(),
                    validated_exec_status,
                    data_availability_status,
                ) };
            } else {
                const header = try body.executionPayloadHeader();
                break :blk .{ .post_merge = BlockExtraMeta.PostMergeMeta.init(
                    header.blockHash(),
                    header.blockNumber(),
                    validated_exec_status,
                    data_availability_status,
                ) };
            }
        } else if (fork_seq.gte(.bellatrix)) blk: {
            // Post-merge, pre-Gloas: must be valid or syncing.
            const validated_exec_status = try getPreGloasExecStatus(execution_status);
            const body = block.beaconBlockBody();
            if (body.blockType() == .full) {
                const payload = try body.executionPayload();
                break :blk .{ .post_merge = BlockExtraMeta.PostMergeMeta.init(
                    payload.blockHash().*,
                    payload.blockNumber(),
                    validated_exec_status,
                    data_availability_status,
                ) };
            } else {
                const header = try body.executionPayloadHeader();
                break :blk .{ .post_merge = BlockExtraMeta.PostMergeMeta.init(
                    header.blockHash(),
                    header.blockNumber(),
                    validated_exec_status,
                    data_availability_status,
                ) };
            }
        } else blk: {
            // Pre-merge: validate status is pre_merge/pre_data.
            _ = try getPreMergeExecStatus(execution_status);
            _ = try getPreMergeDataStatus(data_availability_status);
            break :blk .{ .pre_merge = {} };
        };

        // 12. Construct ProtoBlock.
        const proto_block = ProtoBlock{
            .slot = slot,
            .block_root = block_root,
            .parent_root = parent_root,
            .state_root = block.stateRoot().*,
            .target_root = if (computeStartSlotAtEpoch(block_epoch) == slot) block_root else parent_node.target_root,
            .justified_epoch = justified_checkpoint.epoch,
            .justified_root = justified_checkpoint.root,
            .finalized_epoch = finalized_checkpoint.epoch,
            .finalized_root = finalized_checkpoint.root,
            .unrealized_justified_epoch = unrealized_justified.epoch,
            .unrealized_justified_root = unrealized_justified.root,
            .unrealized_finalized_epoch = unrealized_finalized.epoch,
            .unrealized_finalized_root = unrealized_finalized.root,
            .extra_meta = extra_meta,
            .timeliness = timely,
        };

        // 13. Add to proto array.
        try self.proto_array.onBlock(allocator, proto_block, current_slot, self.proposer_boost_root);

        return proto_block;
    }

    /// Simplified onBlock that takes a pre-constructed ProtoBlock.
    /// Used by tests and for cases where block/state processing is done externally.
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

    /// Process an indexed attestation for fork choice.
    /// Validates, then either applies immediately (past slot) or queues (current slot).
    /// Matching TS `onAttestation()`.
    pub fn onAttestation(
        self: *ForkChoice,
        allocator: Allocator,
        attestation: *const AnyIndexedAttestation,
        att_data_root: Root,
        force_import: bool,
    ) !void {
        const block_root = attestation.beaconBlockRoot();

        // Ignore zero-hash beacon_block_root.
        if (std.mem.eql(u8, &block_root, &ZERO_HASH)) return;

        // Validate the attestation.
        try self.validateOnAttestation(allocator, attestation, att_data_root, force_import);

        const att_slot = attestation.slot();
        const current_slot = self.fcStore.current_slot;

        // Determine payload status for Gloas.
        const payload_status: PayloadStatus = .full; // Pre-Gloas default

        const attesting_indices = attestation.attestingIndices();

        if (att_slot < current_slot) {
            // Past slot: apply immediately.
            for (attesting_indices) |validator_index| {
                try self.addLatestMessage(
                    allocator,
                    validator_index,
                    att_slot,
                    block_root,
                    payload_status,
                );
            }
        } else {
            // Current slot: queue for later processing.
            var slot_map = self.queued_attestations.getPtr(att_slot);
            if (slot_map == null) {
                try self.queued_attestations.put(allocator, att_slot, .{});
                slot_map = self.queued_attestations.getPtr(att_slot);
            }

            var block_list = slot_map.?.getPtr(block_root);
            if (block_list == null) {
                try slot_map.?.put(allocator, block_root, .{});
                block_list = slot_map.?.getPtr(block_root);
            }

            for (attesting_indices) |validator_index| {
                try block_list.?.append(allocator, .{
                    .validator_index = validator_index,
                    .payload_status = payload_status,
                });
            }
        }
    }

    // ── Attestation validation (private) ──

    /// Validate an attestation for fork choice. Matching TS validation chain.
    fn validateOnAttestation(
        self: *ForkChoice,
        allocator: Allocator,
        attestation: *const AnyIndexedAttestation,
        att_data_root: Root,
        force_import: bool,
    ) ForkChoiceError!void {
        try self.validateAttestationData(allocator, attestation, att_data_root, force_import);
    }

    /// Validate attestation data fields. Matching TS `validateAttestationData()`.
    fn validateAttestationData(
        self: *ForkChoice,
        allocator: Allocator,
        attestation: *const AnyIndexedAttestation,
        att_data_root: Root,
        force_import: bool,
    ) ForkChoiceError!void {
        // Skip validation if already validated this slot.
        if (!force_import) {
            if (self.validated_attestation_datas.contains(att_data_root)) return;
        }

        const target_epoch = attestation.targetEpoch();
        const current_epoch = computeEpochAtSlot(self.fcStore.current_slot);

        // Target epoch must not be in the future.
        if (target_epoch > current_epoch) return error.InvalidAttestation;

        // Target epoch must be current or previous (unless force_import).
        if (!force_import and target_epoch + 1 < current_epoch) return error.InvalidAttestation;

        // Target root must be known.
        const target_root = attestation.targetRoot();
        if (!self.proto_array.indices.contains(target_root)) return error.InvalidAttestation;

        // Beacon block root must be known.
        const block_root = attestation.beaconBlockRoot();
        if (!self.proto_array.indices.contains(block_root)) return error.InvalidAttestation;

        // Attestation slot must not be before block slot.
        const att_slot = attestation.slot();
        const block_slot = blk: {
            const indices = self.proto_array.indices.get(block_root) orelse return error.InvalidAttestation;
            const idx = indices.getByPayloadStatus(.full) orelse return error.InvalidAttestation;
            if (idx >= self.proto_array.nodes.items.len) return error.InvalidAttestation;
            break :blk self.proto_array.nodes.items[idx].slot;
        };
        if (att_slot < block_slot) return error.InvalidAttestation;

        // Cache validated attestation data root.
        self.validated_attestation_datas.put(
            allocator,
            att_data_root,
            {},
        ) catch {};
    }

    // ── Timeliness (private) ──

    /// Check if a block is timely (arrived within first interval of slot).
    /// Matching TS `isBlockTimely()`.
    fn isBlockTimely(self: *const ForkChoice, block_slot: Slot, block_delay_sec: u32) bool {
        // Only current-slot blocks can be timely.
        if (block_slot != self.fcStore.current_slot) return false;

        // Timely if arrived within first interval of the slot.
        const intervals_per_slot: u32 = 3; // INTERVALS_PER_SLOT from TS
        return block_delay_sec < @as(u32, @intCast(self.config.chain.SECONDS_PER_SLOT)) / intervals_per_slot;
    }

    // ── Execution / data status validation ──

    /// Validate pre-merge execution status. Must be `.pre_merge`.
    fn getPreMergeExecStatus(execution_status: ExecutionStatus) ForkChoiceError!ExecutionStatus {
        if (execution_status != .pre_merge) return error.InvalidBlock;
        return execution_status;
    }

    /// Validate pre-merge data availability status. Must be `.pre_data`.
    fn getPreMergeDataStatus(data_availability_status: DataAvailabilityStatus) ForkChoiceError!DataAvailabilityStatus {
        if (data_availability_status != .pre_data) return error.InvalidBlock;
        return data_availability_status;
    }

    /// Validate post-merge (pre-Gloas) execution status. Must be `.valid` or `.syncing`.
    fn getPreGloasExecStatus(execution_status: ExecutionStatus) ForkChoiceError!ExecutionStatus {
        if (execution_status == .pre_merge or execution_status == .payload_separated) return error.InvalidBlock;
        return execution_status;
    }

    /// Validate post-Gloas execution status. Must be `.payload_separated`.
    fn getPostGloasExecStatus(execution_status: ExecutionStatus) ForkChoiceError!ExecutionStatus {
        if (execution_status != .payload_separated) return error.InvalidBlock;
        return execution_status;
    }

    // ── Head selection ──

    /// Recompute fork choice head: computeDeltas -> applyScoreChanges -> findHead.
    /// Matches TS: `updateHead(): ProtoBlock`
    fn updateHead(self: *ForkChoice, allocator: Allocator) !void {
        // Check if scores need to be calculated/updated
        const old_balances = self.balances.get().items;
        const new_balances = self.fcStore.justified.balances.get().items;

        const vote_fields = self.votes.fields();
        const result = try computeDeltas(
            allocator,
            &self.deltas_cache,
            @intCast(self.proto_array.nodes.items.len),
            vote_fields.current_indices,
            vote_fields.next_indices,
            old_balances,
            new_balances,
            &self.fcStore.equivocating_indices,
        );

        self.balances.release();
        self.balances = self.fcStore.justified.balances.acquire();

        // Compute proposer boost: {root, score} | null
        const proposer_boost: ?proto_array_mod.ProtoArray.ProposerBoost = if (self.opts.proposer_boost and self.proposer_boost_root != null) blk: {
            const score = self.justified_proposer_boost_score orelse score_blk: {
                const s = getCommitteeFraction(self.fcStore.justified.total_balance, preset.SLOTS_PER_EPOCH, self.config.chain.PROPOSER_SCORE_BOOST);
                self.justified_proposer_boost_score = s;
                break :score_blk s;
            };
            break :blk .{ .root = self.proposer_boost_root.?, .score = score };
        } else null;

        const current_slot = self.fcStore.current_slot;

        try self.proto_array.applyScoreChanges(
            result.deltas,
            proposer_boost,
            self.fcStore.justified.checkpoint.epoch,
            self.fcStore.justified.checkpoint.root,
            self.fcStore.finalized_checkpoint.epoch,
            self.fcStore.finalized_checkpoint.root,
            current_slot,
        );

        const head_node = try self.proto_array.findHead(
            self.fcStore.justified.checkpoint.root,
            current_slot,
        );

        self.head = head_node.toBlock();
    }

    /// Get the cached head (without recomputing).
    pub fn getHead(self: *const ForkChoice) ProtoBlock {
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
        self.proposer_boost_root = root;
    }

    /// Clear proposer boost (typically at start of new slot).
    pub fn clearProposerBoost(self: *ForkChoice) void {
        self.proto_array.previous_proposer_boost = null;
        self.proposer_boost_root = null;
    }

    // ── Proposer boost reorg ──

    /// Determine whether to override fork choice update for proposer boost reorg.
    /// Called by `predictProposerHead` and `onBlock`.
    /// Matching TS `shouldOverrideForkChoiceUpdate()`.
    pub fn shouldOverrideForkChoiceUpdate(
        self: *ForkChoice,
        head_block: *const ProtoBlock,
        sec_from_slot: u32,
        current_slot: Slot,
    ) ShouldOverrideForkChoiceUpdateResult {
        if (!self.opts.proposer_boost or !self.opts.proposer_boost_reorg) {
            return .{ .should_not_override = .{ .reason = .proposer_boost_reorg_disabled } };
        }

        const parent_status = self.proto_array.getParentPayloadStatus(
            head_block.parent_root,
            head_block.parent_block_hash,
        ) catch {
            return .{ .should_not_override = .{ .reason = .parent_block_not_available } };
        };
        const parent_idx = self.proto_array.getNodeIndexByRootAndStatus(head_block.parent_root, parent_status) orelse {
            return .{ .should_not_override = .{ .reason = .parent_block_not_available } };
        };
        const parent_node = &self.proto_array.nodes.items[parent_idx];
        const proposal_slot = head_block.slot + 1;

        if (self.getPreliminaryProposerHead(head_block, parent_node, proposal_slot)) |reason| {
            return .{ .should_not_override = .{ .reason = reason } };
        }

        // TS: headBlock.slot === currentSlot || (proposalSlot === currentSlot && isProposingOnTime)
        const current_time_ok = head_block.slot == current_slot or
            (proposal_slot == current_slot and self.isProposingOnTime(sec_from_slot, current_slot));
        if (!current_time_ok) {
            return .{ .should_not_override = .{ .reason = .reorg_more_than_one_slot } };
        }

        return .{ .should_override = .{ .parent_block = parent_node.toBlock() } };
    }

    /// Full proposer head determination with weight threshold checks.
    /// Called during block proposal after `updateHead()`.
    /// Matching TS `getProposerHead()`.
    fn getProposerHead(
        self: *ForkChoice,
        head_block: *const ProtoBlock,
        sec_from_slot: u32,
        slot: Slot,
    ) UpdateAndGetHeadResult {
        const is_head_timely = head_block.timeliness;

        // Skip re-org attempt if proposer boost (reorg) are disabled
        if (!self.opts.proposer_boost or !self.opts.proposer_boost_reorg) {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .proposer_boost_reorg_disabled };
        }

        const parent_status = self.proto_array.getParentPayloadStatus(
            head_block.parent_root,
            head_block.parent_block_hash,
        ) catch {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .parent_block_not_available };
        };
        const parent_idx = self.proto_array.getNodeIndexByRootAndStatus(head_block.parent_root, parent_status) orelse {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .parent_block_not_available };
        };
        const parent_node = &self.proto_array.nodes.items[parent_idx];

        // Preliminary checks (timeliness, shuffling stability, FFG, finalization, slot distance)
        if (self.getPreliminaryProposerHead(head_block, parent_node, slot)) |reason| {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = reason };
        }

        // Only re-org if we are proposing on-time
        if (!self.isProposingOnTime(sec_from_slot, slot)) {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .not_proposing_on_time };
        }

        // No reorg if attempted reorg is more than a single slot
        // Half of single_slot_reorg check in the spec is done in getPreliminaryProposerHead()
        if (head_block.slot + 1 != slot) {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .reorg_more_than_one_slot };
        }

        // No reorg if proposer boost is still in effect
        if (self.proposer_boost_root) |boost_root| {
            if (std.mem.eql(u8, &boost_root, &head_block.block_root)) {
                return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .proposer_boost_not_worn_off };
            }
        }

        // No reorg if headBlock is "not weak" — weight exceeds REORG_HEAD_WEIGHT_THRESHOLD% of committee
        const reorg_threshold = getCommitteeFraction(self.fcStore.justified.total_balance, preset.SLOTS_PER_EPOCH, self.config.chain.REORG_HEAD_WEIGHT_THRESHOLD);
        const head_node_idx = self.proto_array.getNodeIndexByRootAndStatus(head_block.block_root, head_block.payload_status) orelse {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .head_block_not_weak };
        };
        if (self.proto_array.nodes.items[head_node_idx].weight >= reorg_threshold) {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .head_block_not_weak };
        }

        // No reorg if parentBlock is "not strong" — weight is <= REORG_PARENT_WEIGHT_THRESHOLD% of committee
        const parent_threshold = getCommitteeFraction(self.fcStore.justified.total_balance, preset.SLOTS_PER_EPOCH, self.config.chain.REORG_PARENT_WEIGHT_THRESHOLD);
        if (self.proto_array.nodes.items[parent_idx].weight <= parent_threshold) {
            return .{ .head = head_block.*, .is_head_timely = is_head_timely, .not_reorged_reason = .parent_block_not_strong };
        }

        // All checks passed — reorg to parent
        return .{ .head = parent_node.toBlock(), .is_head_timely = is_head_timely, .not_reorged_reason = null };
    }

    /// Preliminary proposer head check (before full weight analysis).
    /// Checks: timeliness, shuffling stability, FFG competitiveness, finalization, slot distance.
    /// Returns true if reorg is blocked (head stays), false if all preliminary checks pass.
    /// Matching TS `getPreliminaryProposerHead()`.
    fn getPreliminaryProposerHead(
        self: *const ForkChoice,
        head_block: *const ProtoBlock,
        parent_node: *const ProtoNode,
        slot: Slot,
    ) ?NotReorgedReason {
        // No reorg if headBlock is on time (is_head_late check)
        if (head_block.timeliness) {
            return .head_block_is_timely;
        }

        // No reorg if at epoch boundary where proposer shuffling could change (is_shuffling_stable)
        if (slot % preset.SLOTS_PER_EPOCH == 0) {
            return .not_shuffling_stable;
        }

        // No reorg if headBlock and parentBlock are not FFG competitive (is_ffg_competitive)
        if (head_block.unrealized_justified_epoch != parent_node.unrealized_justified_epoch or
            !std.mem.eql(u8, &head_block.unrealized_justified_root, &parent_node.unrealized_justified_root))
        {
            return .not_ffg_competitive;
        }

        // No reorg if chain is not finalizing within REORG_MAX_EPOCHS_SINCE_FINALIZATION (is_finalization_ok)
        const epochs_since_finalization = computeEpochAtSlot(slot) - self.fcStore.finalized_checkpoint.epoch;
        if (epochs_since_finalization > self.config.chain.REORG_MAX_EPOCHS_SINCE_FINALIZATION) {
            return .chain_long_unfinality;
        }

        // No reorg if this reorg spans more than a single slot
        if (parent_node.slot + 1 != head_block.slot) {
            return .parent_block_distance_more_than_one_slot;
        }

        // All preliminary checks passed — reorg allowed
        return null;
    }

    /// Predict the proposer head without full reorg analysis.
    /// Matching TS `predictProposerHead()`.
    fn predictProposerHead(
        self: *ForkChoice,
        head_block: *const ProtoBlock,
        sec_from_slot: u32,
        current_slot: Slot,
    ) ProtoBlock {
        if (!self.opts.proposer_boost or !self.opts.proposer_boost_reorg) {
            return head_block.*;
        }

        const result = self.shouldOverrideForkChoiceUpdate(head_block, sec_from_slot, current_slot);
        return switch (result) {
            .should_override => |r| r.parent_block,
            .should_not_override => head_block.*,
        };
    }

    /// Check if the proposer is proposing on time.
    /// https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/fork-choice.md#is_proposing_on_time
    fn isProposingOnTime(self: *const ForkChoice, sec_from_slot: u32, slot: Slot) bool {
        const proposer_reorg_cutoff = self.config.getProposerReorgCutoffMs(slot);
        // TS: secFromSlot * 1000 <= getProposerReorgCutoffMs(fork)
        return @as(u64, sec_from_slot) * 1000 <= proposer_reorg_cutoff;
    }

    /// Update head and return result. Multiplexer matching TS.
    pub fn updateAndGetHead(
        self: *ForkChoice,
        allocator: Allocator,
        opt: UpdateAndGetHeadOpt,
    ) !UpdateAndGetHeadResult {
        // TS: const canonicalHeadBlock = mode === GetPredictedProposerHead ? this.getHead() : this.updateHead();
        const canonical_head: ProtoBlock = switch (opt) {
            .get_predicted_proposer_head => self.head,
            else => blk: {
                try self.updateHead(allocator);
                break :blk self.head;
            },
        };

        return switch (opt) {
            .get_canonical_head => .{ .head = canonical_head },
            .get_proposer_head => |params| self.getProposerHead(&canonical_head, params.sec_from_slot, params.slot),
            .get_predicted_proposer_head => |params| .{
                .head = self.predictProposerHead(&canonical_head, params.sec_from_slot, params.slot),
            },
        };
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

    /// Advance time to `current_slot`, ticking each slot.
    /// Matching TS `updateTime()`.
    pub fn updateTime(self: *ForkChoice, allocator: Allocator, current_slot: Slot) !void {
        const previous_slot = self.fcStore.current_slot;
        if (current_slot <= previous_slot) return;

        // Tick each slot from previous+1 to current.
        var slot = previous_slot + 1;
        while (slot <= current_slot) : (slot += 1) {
            try self.onTick(slot);
        }

        // Process queued attestations after time advance.
        try self.processAttestationQueue(allocator);

        // Clear validated attestation data cache.
        self.validated_attestation_datas.clearRetainingCapacity();
    }

    pub fn getTime(self: *const ForkChoice) Slot {
        return self.fcStore.current_slot;
    }

    // ── Checkpoint management (private) ──

    /// Update realized checkpoints from block processing.
    /// Epoch-monotonic: only advances, never regresses.
    /// Matching TS `updateCheckpoints()`.
    fn updateCheckpoints(
        self: *ForkChoice,
        justified: CheckpointWithPayloadStatus,
        finalized: CheckpointWithPayloadStatus,
    ) void {
        // Update justified if epoch advances.
        if (justified.epoch > self.fcStore.justified.checkpoint.epoch) {
            // Retrieve new balances lazily via getter.
            const new_balances = self.fcStore.justified_balances_getter.get(justified);
            const new_total = store_mod.computeTotalBalance(new_balances.items);

            const new_rc = EffectiveBalanceIncrementsRc.init(
                new_balances.allocator,
                new_balances,
            ) catch return; // OOM: silently skip — TS getter is expected to never fail.

            self.fcStore.justified.balances.release();
            self.fcStore.justified = .{
                .checkpoint = justified,
                .balances = new_rc,
                .total_balance = new_total,
            };

            if (self.fcStore.events.on_justified) |cb| cb.call(justified);
        }

        // Update finalized if epoch advances.
        if (finalized.epoch > self.fcStore.finalized_checkpoint.epoch) {
            self.fcStore.setFinalizedCheckpoint(finalized);
        }
    }

    /// Update unrealized checkpoints from pull-up FFG.
    /// Epoch-monotonic: only advances, never regresses.
    /// Matching TS `updateUnrealizedCheckpoints()`.
    fn updateUnrealizedCheckpoints(
        self: *ForkChoice,
        justified: CheckpointWithPayloadStatus,
        finalized: CheckpointWithPayloadStatus,
    ) void {
        if (justified.epoch > self.fcStore.unrealized_justified.checkpoint.epoch) {
            self.fcStore.unrealized_justified = .{
                .checkpoint = justified,
                .balances = self.fcStore.unrealized_justified.balances,
                .total_balance = self.fcStore.unrealized_justified.total_balance,
            };
        }
        if (finalized.epoch > self.fcStore.unrealized_finalized_checkpoint.epoch) {
            self.fcStore.unrealized_finalized_checkpoint = finalized;
        }
    }

    // ── Attestation message processing (private) ──

    /// Record a single validator's latest message (vote).
    /// Skips equivocating validators. Uses slot-monotonicity for Gloas.
    /// Matching TS `addLatestMessage()`.
    fn addLatestMessage(
        self: *ForkChoice,
        allocator: Allocator,
        validator_index: ValidatorIndex,
        next_slot: Slot,
        next_root: Root,
        next_payload_status: PayloadStatus,
    ) !void {
        // Skip equivocating validators.
        if (self.fcStore.equivocating_indices.contains(validator_index)) return;

        try self.votes.ensureValidatorCount(allocator, @intCast(validator_index + 1));
        const fields = self.votes.fields();

        // Slot-monotonicity: reject stale votes.
        if (next_slot <= fields.next_slots[validator_index] and
            fields.next_indices[validator_index] != NULL_VOTE_INDEX)
        {
            return;
        }

        // Look up the node index for the target block.
        const indices = self.proto_array.indices.get(next_root) orelse return;
        const node_index = indices.getByPayloadStatus(next_payload_status) orelse return;

        fields.next_indices[validator_index] = @intCast(node_index);
        fields.next_slots[validator_index] = next_slot;
    }

    // ── Time management (private) ──

    /// Process a single slot tick. Matching TS `onTick()`.
    fn onTick(self: *ForkChoice, time: Slot) !void {
        const previous_slot = self.fcStore.current_slot;

        // Time must advance by exactly 1.
        if (time != previous_slot + 1) return error.InvalidSlotAdvance;

        self.fcStore.current_slot = time;

        // Reset proposer boost at slot boundary.
        self.proposer_boost_root = null;
        self.justified_proposer_boost_score = null;

        // At epoch boundary: realize unrealized checkpoints.
        const current_epoch = computeEpochAtSlot(time);
        const previous_epoch = computeEpochAtSlot(previous_slot);
        if (current_epoch > previous_epoch) {
            self.updateCheckpoints(
                self.fcStore.unrealized_justified.checkpoint,
                self.fcStore.unrealized_finalized_checkpoint,
            );
        }
    }

    /// Process queued attestations for past slots. Matching TS `processAttestationQueue()`.
    fn processAttestationQueue(self: *ForkChoice, allocator: Allocator) !void {
        const current_slot = self.fcStore.current_slot;

        // Collect slot keys to process (slots < current_slot).
        var slots_to_remove = std.ArrayList(Slot).init(allocator);
        defer slots_to_remove.deinit();

        var slot_iter = self.queued_attestations.iterator();
        while (slot_iter.next()) |entry| {
            const att_slot = entry.key_ptr.*;
            if (att_slot < current_slot) {
                // Process all attestations for this slot.
                var block_iter = entry.value_ptr.iterator();
                while (block_iter.next()) |block_entry| {
                    const block_root = block_entry.key_ptr.*;
                    const att_list = block_entry.value_ptr;
                    for (att_list.items) |queued_att| {
                        try self.addLatestMessage(
                            allocator,
                            queued_att.validator_index,
                            att_slot,
                            block_root,
                            queued_att.payload_status,
                        );
                    }
                    att_list.deinit(allocator);
                }
                entry.value_ptr.deinit(allocator);
                try slots_to_remove.append(att_slot);
            }
        }

        // Remove processed slots.
        for (slots_to_remove.items) |slot_key| {
            _ = self.queued_attestations.orderedRemove(slot_key);
        }
    }

    // ── Public checkpoint getters ──

    pub fn getJustifiedCheckpoint(self: *const ForkChoice) CheckpointWithPayloadStatus {
        return self.fcStore.justified.checkpoint;
    }

    pub fn getFinalizedCheckpoint(self: *const ForkChoice) CheckpointWithPayloadStatus {
        return self.fcStore.finalized_checkpoint;
    }

    // ── Pruning ──

    /// Prune finalized ancestors from the DAG to bound memory usage.
    /// Adjusts all vote indices — critical for correctness.
    /// Caller owns the returned pruned blocks slice.
    /// Matching TS `prune()`.
    pub fn prune(
        self: *ForkChoice,
        allocator: Allocator,
        finalized_root: Root,
    ) (Allocator.Error || ProtoArrayError)![]ProtoBlock {
        const pruned = try self.proto_array.maybePrune(allocator, finalized_root);
        const pruned_count: u32 = @intCast(pruned.len);

        if (pruned_count == 0) return pruned;

        // Adjust all vote indices — critical for correctness.
        const fields = self.votes.fields();
        for (0..self.votes.len()) |i| {
            if (fields.current_indices[i] != NULL_VOTE_INDEX) {
                if (fields.current_indices[i] >= pruned_count) {
                    fields.current_indices[i] -= pruned_count;
                } else {
                    fields.current_indices[i] = NULL_VOTE_INDEX;
                }
            }
            if (fields.next_indices[i] != NULL_VOTE_INDEX) {
                if (fields.next_indices[i] >= pruned_count) {
                    fields.next_indices[i] -= pruned_count;
                } else {
                    fields.next_indices[i] = NULL_VOTE_INDEX;
                }
            }
        }

        return pruned;
    }

    // ── Execution validation ──

    /// Propagate execution layer validity response through the DAG.
    /// Sets irrecoverable_error on failure instead of propagating the error.
    pub fn validateLatestHash(
        self: *ForkChoice,
        allocator: Allocator,
        response: LVHExecResponse,
        current_slot: Slot,
    ) void {
        self.proto_array.validateLatestHash(allocator, response, current_slot) catch {
            self.irrecoverable_error = true;
        };
    }

    // ── Block queries ──

    /// Check if a block root exists and is a finalized descendant.
    pub fn hasBlock(self: *const ForkChoice, block_root: Root) bool {
        const idx = self.proto_array.getDefaultNodeIndex(block_root) orelse return false;
        const node = &self.proto_array.nodes.items[idx];
        return self.proto_array.isFinalizedRootOrDescendant(node);
    }

    /// Check if a block root exists (without finalized descendant check).
    pub fn hasBlockUnsafe(self: *const ForkChoice, block_root: Root) bool {
        return self.proto_array.indices.contains(block_root);
    }

    /// Get a block by root and payload status (with finalized descendant check).
    pub fn getBlock(self: *const ForkChoice, block_root: Root, payload_status: PayloadStatus) ?ProtoBlock {
        const indices = self.proto_array.indices.get(block_root) orelse return null;
        const idx = indices.getByPayloadStatus(payload_status) orelse return null;
        if (idx >= self.proto_array.nodes.items.len) return null;
        const node_ptr = &self.proto_array.nodes.items[idx];
        if (!self.proto_array.isFinalizedRootOrDescendant(node_ptr)) return null;
        return node_ptr.toBlock();
    }

    /// Get a block by root with default (.full) payload status.
    pub fn getBlockDefaultStatus(self: *const ForkChoice, block_root: Root) ?ProtoBlock {
        return self.getBlock(block_root, .full);
    }

    /// Get a block matching both root and execution payload block hash.
    pub fn getBlockAndBlockHash(self: *const ForkChoice, block_root: Root, block_hash: Root) ?ProtoBlock {
        const block = self.getBlockDefaultStatus(block_root) orelse return null;
        const exec_hash = block.extra_meta.executionPayloadBlockHash() orelse return null;
        if (!std.mem.eql(u8, &exec_hash, &block_hash)) return null;
        return block;
    }

    /// Get the justified block from proto array.
    pub fn getJustifiedBlock(self: *const ForkChoice) !ProtoBlock {
        const cp = self.fcStore.justified.checkpoint;
        return self.getBlock(cp.root, cp.payload_status) orelse return error.JustifiedBlockNotFound;
    }

    /// Get the finalized block from proto array.
    pub fn getFinalizedBlock(self: *const ForkChoice) !ProtoBlock {
        const cp = self.fcStore.finalized_checkpoint;
        return self.getBlock(cp.root, cp.payload_status) orelse return error.FinalizedBlockNotFound;
    }

    /// Returns the root of the safe beacon block.
    ///
    /// Under honest majority and certain network synchronicity assumptions there exists a block
    /// that is safe from re-orgs. Normally this block is pretty close to the head of canonical
    /// chain which makes it valuable to expose a safe block to users.
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.6.0/fork_choice/safe-block.md#get_safe_beacon_block_root
    pub fn getSafeBeaconBlockRoot(self: *const ForkChoice) Root {
        return self.getJustifiedCheckpoint().root;
    }

    /// Returns the execution payload block hash for the safe block.
    ///
    /// This function assumes that the safe block is post-Bellatrix and should not
    /// be called otherwise. Our existing usage is aligned with this condition so
    /// no fork-check is performed inside this function.
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.6.0/fork_choice/safe-block.md#get_safe_execution_block_hash
    pub fn getSafeExecutionBlockHash(self: *const ForkChoice) Root {
        const justified_block = self.getJustifiedBlock() catch return ZERO_HASH;
        return justified_block.extra_meta.executionPayloadBlockHash() orelse ZERO_HASH;
    }

    /// Get the slot of the finalized checkpoint's block.
    pub fn getFinalizedCheckpointSlot(self: *const ForkChoice) Slot {
        return computeStartSlotAtEpoch(self.fcStore.finalized_checkpoint.epoch);
    }

    // ── Traversal ──

    /// Get the ancestor of a block at a given slot.
    /// Get the ancestor node at the given slot.
    /// Delegates to `protoArray.getAncestor()` matching TS: `this.protoArray.getAncestor(blockRoot, ancestorSlot)`.
    pub fn getAncestor(self: *const ForkChoice, block_root: Root, ancestor_slot: Slot) ProtoArrayError!ProtoNode {
        const node = try self.proto_array.getAncestor(block_root, ancestor_slot);
        return node.*;
    }

    /// Check if one block is a descendant of another.
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

    /// Get the canonical block matching the given root.
    pub fn getCanonicalBlockByRoot(self: *const ForkChoice, block_root: Root) ?ProtoBlock {
        // Check head first (iterator excludes start node).
        if (std.mem.eql(u8, &self.head.block_root, &block_root)) return self.head;
        var iter = self.proto_array.iterateAncestors(self.head.block_root, .full);
        while (iter.next() catch null) |node| {
            if (std.mem.eql(u8, &node.block_root, &block_root)) return node.toBlock();
        }
        return null;
    }

    /// Get the canonical block at a given slot.
    pub fn getCanonicalBlockAtSlot(self: *const ForkChoice, slot: Slot) ?ProtoBlock {
        // Check head first (iterator excludes start node).
        if (self.head.slot == slot) return self.head;
        var iter = self.proto_array.iterateAncestors(self.head.block_root, .full);
        while (iter.next() catch null) |node| {
            if (node.slot == slot) return node.toBlock();
            if (node.slot < slot) return null;
        }
        return null;
    }

    /// Get the canonical block at or before a given slot.
    pub fn getCanonicalBlockClosestLteSlot(self: *const ForkChoice, slot: Slot) ?ProtoBlock {
        // Check head first (iterator excludes start node).
        if (self.head.slot <= slot) return self.head;
        var iter = self.proto_array.iterateAncestors(self.head.block_root, .full);
        while (iter.next() catch null) |node| {
            if (node.slot <= slot) return node.toBlock();
        }
        return null;
    }

    /// Iterate backwards through ancestor blocks, starting from a block root.
    /// Returns non-finalized blocks only.
    /// Matching TS `iterateAncestorBlocks(blockRoot, payloadStatus)`.
    pub fn iterateAncestorBlocks(
        self: *const ForkChoice,
        block_root: Root,
        status: PayloadStatus,
    ) ProtoArray.AncestorIterator {
        return self.proto_array.iterateAncestors(block_root, status);
    }

    /// Get all ancestor blocks from head down to (and including) the given block.
    pub fn getAllAncestorBlocks(
        self: *const ForkChoice,
        allocator: Allocator,
        block_root: Root,
        status: PayloadStatus,
    ) ![]ProtoBlock {
        var result = std.ArrayList(ProtoBlock).init(allocator);
        errdefer result.deinit();

        // Include head (iterator excludes start node).
        try result.append(self.head);
        if (std.mem.eql(u8, &self.head.block_root, &block_root)) return result.toOwnedSlice();

        var iter = self.proto_array.iterateAncestors(self.head.block_root, status);
        while (try iter.next()) |node| {
            try result.append(node.toBlock());
            if (std.mem.eql(u8, &node.block_root, &block_root)) break;
        }
        return result.toOwnedSlice();
    }

    /// Get all non-ancestor blocks (blocks not on the canonical chain).
    pub fn getAllNonAncestorBlocks(
        self: *const ForkChoice,
        allocator: Allocator,
        block_root: Root,
        status: PayloadStatus,
    ) ![]ProtoBlock {
        _ = status;
        var ancestor_set = std.AutoHashMap(Root, void).init(allocator);
        defer ancestor_set.deinit();

        // Build set of ancestor roots.
        var iter = self.proto_array.iterateAncestors(self.head.block_root, .full);
        while (iter.next() catch null) |node| {
            try ancestor_set.put(node.block_root, {});
            if (std.mem.eql(u8, &node.block_root, &block_root)) break;
        }

        var result = std.ArrayList(ProtoBlock).init(allocator);
        errdefer result.deinit();

        for (self.proto_array.nodes.items) |node| {
            if (!ancestor_set.contains(node.block_root)) {
                try result.append(node.toBlock());
            }
        }
        return result.toOwnedSlice();
    }

    /// Get both ancestor and non-ancestor blocks in one pass.
    pub fn getAllAncestorAndNonAncestorBlocks(
        self: *const ForkChoice,
        allocator: Allocator,
        block_root: Root,
        status: PayloadStatus,
    ) !struct { ancestors: []ProtoBlock, non_ancestors: []ProtoBlock } {
        var ancestor_set = std.AutoHashMap(Root, void).init(allocator);
        defer ancestor_set.deinit();

        var ancestors = std.ArrayList(ProtoBlock).init(allocator);
        errdefer ancestors.deinit();
        var non_ancestors = std.ArrayList(ProtoBlock).init(allocator);
        errdefer non_ancestors.deinit();

        // Build ancestor set.
        var iter = self.proto_array.iterateAncestors(self.head.block_root, status);
        while (iter.next() catch null) |node| {
            try ancestor_set.put(node.block_root, {});
            try ancestors.append(node.toBlock());
            if (std.mem.eql(u8, &node.block_root, &block_root)) break;
        }

        // Collect non-ancestors.
        for (self.proto_array.nodes.items) |node| {
            if (!ancestor_set.contains(node.block_root)) {
                try non_ancestors.append(node.toBlock());
            }
        }
        return .{
            .ancestors = try ancestors.toOwnedSlice(),
            .non_ancestors = try non_ancestors.toOwnedSlice(),
        };
    }

    /// Get common ancestor depth between two blocks.
    /// Returns how deep the common ancestor is from the higher of the two blocks.
    pub fn getCommonAncestorDepth(self: *const ForkChoice, prev: *const ProtoBlock, new_block: *const ProtoBlock) AncestorResult {
        const prev_node = self.proto_array.getNode(prev.block_root, prev.payload_status) orelse
            return .{ .block_unknown = {} };
        const new_node = self.proto_array.getNode(new_block.block_root, new_block.payload_status) orelse
            return .{ .block_unknown = {} };

        const common_ancestor = self.proto_array.getCommonAncestor(prev_node, new_node) orelse
            return .{ .no_common_ancestor = {} };

        // If common ancestor is one of both nodes, they are direct descendants.
        if (std.mem.eql(u8, &common_ancestor.block_root, &prev_node.block_root) or
            std.mem.eql(u8, &common_ancestor.block_root, &new_node.block_root))
        {
            return .{ .descendant = {} };
        }

        return .{ .common_ancestor = .{ .depth = @intCast(@max(new_node.slot, prev_node.slot) - common_ancestor.slot) } };
    }

    /// Get the dependent root for a block at a given epoch difference.
    pub fn getDependentRoot(self: *const ForkChoice, block: ProtoBlock, epoch_diff: EpochDifference) !Root {
        const block_epoch = computeEpochAtSlot(block.slot);
        const dep_epoch = switch (epoch_diff) {
            .current => block_epoch,
            .previous => if (block_epoch > 0) block_epoch - 1 else 0,
        };
        const dep_slot = computeStartSlotAtEpoch(dep_epoch);

        if (block.slot <= dep_slot) return block.parent_root;

        var iter = self.proto_array.iterateAncestors(block.block_root, .full);
        while (try iter.next()) |node| {
            if (node.slot <= dep_slot) return node.block_root;
        }
        return block.parent_root;
    }

    // ── Getters ──

    /// Get the head block root (from cache, without recomputing).
    pub fn getHeadRoot(self: *const ForkChoice) Root {
        return self.head.block_root;
    }

    pub fn getProposerBoostRoot(self: *const ForkChoice) ?Root {
        return self.proposer_boost_root;
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

    /// Set the prune threshold.
    pub fn setPruneThreshold(self: *ForkChoice, threshold: u32) void {
        self.proto_array.prune_threshold = threshold;
    }

    // ── Debug / metrics ──

    /// Get all leaf nodes (heads of chains).
    pub fn getHeads(self: *const ForkChoice, allocator: Allocator) ![]ProtoBlock {
        var result = std.ArrayList(ProtoBlock).init(allocator);
        errdefer result.deinit();

        for (self.proto_array.nodes.items) |node| {
            if (node.best_child == null) {
                try result.append(node.toBlock());
            }
        }
        return result.toOwnedSlice();
    }

    /// Get all nodes in the DAG.
    pub fn getAllNodes(self: *const ForkChoice) []ProtoNode {
        return self.proto_array.nodes.items;
    }

    /// Forward-iterate all nodes. Very expensive — iterates the entire ProtoArray.
    /// Matching TS `forwarditerateAncestorBlocks()`.
    /// Returns a slice of ProtoNode (TS returns ProtoBlock, but in TS ProtoNode == ProtoBlock).
    pub fn forwardIterateAncestorBlocks(self: *const ForkChoice) []ProtoNode {
        return self.proto_array.nodes.items;
    }

    /// Count slots present in a window.
    pub fn getSlotsPresent(self: *const ForkChoice, window_start: Slot) u32 {
        var count: u32 = 0;
        for (self.proto_array.nodes.items) |node| {
            if (node.slot >= window_start) count += 1;
        }
        return count;
    }

    /// Lazy forward iterator over descendants of a given block.
    /// Matching TS `*forwardIterateDescendants(blockRoot, payloadStatus)`.
    /// Caller must call `deinit()` when done.
    pub const DescendantIterator = struct {
        nodes: []const ProtoNode,
        current_index: usize,
        roots_in_chain: std.AutoHashMap(Root, void),

        pub fn next(self: *DescendantIterator) Allocator.Error!?*const ProtoNode {
            while (self.current_index < self.nodes.len) {
                const node = &self.nodes[self.current_index];
                self.current_index += 1;
                if (self.roots_in_chain.contains(node.parent_root)) {
                    try self.roots_in_chain.put(node.block_root, {});
                    return node;
                }
            }
            return null;
        }

        pub fn deinit(self: *DescendantIterator) void {
            self.roots_in_chain.deinit();
        }
    };

    /// Forward-iterate descendants of a block.
    /// Matching TS `*forwardIterateDescendants(blockRoot, payloadStatus)`.
    /// Caller must call `deinit()` on the returned iterator when done.
    pub fn forwardIterateDescendants(
        self: *const ForkChoice,
        allocator: Allocator,
        block_root: Root,
        status: PayloadStatus,
    ) (Allocator.Error || ForkChoiceError)!DescendantIterator {
        const block_index = self.proto_array.getNodeIndexByRootAndStatus(block_root, status) orelse
            return error.MissingProtoArrayBlock;

        var roots_in_chain = std.AutoHashMap(Root, void).init(allocator);
        try roots_in_chain.put(block_root, {});

        return .{
            .nodes = self.proto_array.nodes.items,
            .current_index = block_index + 1,
            .roots_in_chain = roots_in_chain,
        };
    }

    /// Get block summaries by parent root.
    pub fn getBlockSummariesByParentRoot(
        self: *const ForkChoice,
        allocator: Allocator,
        parent_root: Root,
    ) ![]ProtoBlock {
        var result = std.ArrayList(ProtoBlock).init(allocator);
        errdefer result.deinit();

        for (self.proto_array.nodes.items) |node| {
            if (std.mem.eql(u8, &node.parent_root, &parent_root)) {
                try result.append(node.toBlock());
            }
        }
        return result.toOwnedSlice();
    }

    /// Get block summaries at a specific slot.
    pub fn getBlockSummariesAtSlot(
        self: *const ForkChoice,
        allocator: Allocator,
        slot: Slot,
    ) ![]ProtoBlock {
        var result = std.ArrayList(ProtoBlock).init(allocator);
        errdefer result.deinit();

        for (self.proto_array.nodes.items) |node| {
            if (node.slot == slot) {
                try result.append(node.toBlock());
            }
        }
        return result.toOwnedSlice();
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

/// Test-only helper: heap-allocates ProtoArray, ForkChoiceStore, and ForkChoice.
/// Use `deinitTestForkChoice` to free all three.
fn initTestForkChoice(
    allocator: Allocator,
    anchor_block: ProtoBlock,
    current_slot: Slot,
    justified_checkpoint: CheckpointWithPayloadStatus,
    finalized_checkpoint: CheckpointWithPayloadStatus,
    justified_balances: []const u16,
) !*ForkChoice {
    const pa = try allocator.create(ProtoArray);
    errdefer allocator.destroy(pa);

    pa.* = try ProtoArray.initialize(
        allocator,
        anchor_block,
        current_slot,
    );
    errdefer pa.deinit(allocator);

    const fc_store = try allocator.create(ForkChoiceStore);
    errdefer allocator.destroy(fc_store);

    fc_store.* = try ForkChoiceStore.init(
        allocator,
        current_slot,
        justified_checkpoint,
        finalized_checkpoint,
        justified_balances,
        test_balances_getter,
        .{},
    );
    errdefer fc_store.deinit();

    const fc = try allocator.create(ForkChoice);
    errdefer allocator.destroy(fc);

    try fc.init(allocator, getTestConfig(), fc_store, pa, 0, .{});
    return fc;
}

/// Test-only: free ForkChoice + its heap-allocated ProtoArray and ForkChoiceStore.
fn deinitTestForkChoice(allocator: Allocator, fc: *ForkChoice) void {
    const pa = fc.proto_array;
    const fc_store = fc.fcStore;
    fc.deinit(allocator);
    allocator.destroy(fc);
    pa.deinit(allocator);
    allocator.destroy(pa);
    fc_store.deinit();
    allocator.destroy(fc_store);
}

test "init and deinit" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try testing.expect(fc.hasBlock(genesis_root));
    try testing.expectEqual(@as(usize, 1), fc.nodeCount());
    try testing.expectEqual(genesis_root, fc.getHeadRoot());
}

test "onBlockFromProto adds block to DAG" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const block_a = makeTestBlock(1, block_a_root, genesis_root);
    try fc.onBlockFromProto(testing.allocator, block_a, 10);

    try testing.expect(fc.hasBlock(block_a_root));
    try testing.expectEqual(@as(usize, 2), fc.nodeCount());
}

test "onBlockFromProto rejects future slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const future_block = makeTestBlock(10, hashFromByte(0x02), genesis_root);
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, future_block, 5));
}

test "onBlockFromProto rejects unknown parent" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const orphan_block = makeTestBlock(1, hashFromByte(0x02), hashFromByte(0xFF));
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, orphan_block, 10));
}

/// Test-only: build a phase0 IndexedAttestation and wrap in AnyIndexedAttestation.
/// The caller must deinit `att.attesting_indices` when done.
fn makeTestAttestation(
    allocator: Allocator,
    validator_indices: []const ValidatorIndex,
    block_root: Root,
    target_epoch: Epoch,
    target_root: Root,
    att_slot: Slot,
) !consensus_types.phase0.IndexedAttestation.Type {
    var att: consensus_types.phase0.IndexedAttestation.Type = .{
        .attesting_indices = .{},
        .data = .{
            .slot = att_slot,
            .index = 0,
            .beacon_block_root = block_root,
            .source = .{ .epoch = 0, .root = ZERO_HASH },
            .target = .{ .epoch = target_epoch, .root = target_root },
        },
        .signature = [_]u8{0} ** 96,
    };
    for (validator_indices) |vi| {
        try att.attesting_indices.append(allocator, vi);
    }
    return att;
}

test "onAttestation applies past-slot attestation immediately" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{1});
    defer deinitTestForkChoice(testing.allocator, fc);

    // Add a block at slot 1 so the attestation has a known beacon_block_root.
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 10);

    // Attestation at slot 2, target epoch 0, current_slot=10 → past slot → immediate apply.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{0}, block_root, 0, genesis_root, 2);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xAA), false);

    // Validator 0 should have a vote now.
    try testing.expectEqual(@as(u32, 1), fc.votes.len());
}

test "onAttestation queues current-slot attestation" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    // current_slot = 5
    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{1});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 5);

    // Attestation at slot 5 (same as current_slot) → queued.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{0}, block_root, 0, genesis_root, 5);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xBB), false);

    // Should NOT have applied the vote yet.
    try testing.expectEqual(@as(u32, 0), fc.votes.len());

    // Should have queued it under slot 5.
    const slot_map = fc.queued_attestations.get(5);
    try testing.expect(slot_map != null);
}

test "onAttestation rejects future target epoch" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    // current_slot = 5 → current epoch = 0 (minimal SLOTS_PER_EPOCH=8)
    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 5);

    // Target epoch 99 is in the future → reject.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{0}, block_root, 99, genesis_root, 2);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xCC), false));
}

test "onAttestation rejects unknown target root" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const unknown_root = hashFromByte(0xFF);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 5);

    // Target root unknown to fork choice → reject.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{0}, block_root, 0, unknown_root, 2);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xDD), false));
}

test "onAttestation rejects unknown beacon block root" {
    const genesis_root = hashFromByte(0x01);
    const unknown_block = hashFromByte(0xFE);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    // beacon_block_root unknown → reject.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{0}, unknown_block, 0, genesis_root, 2);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try testing.expectError(error.InvalidAttestation, fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xEE), false));
}

test "onAttestation ignores zero-hash beacon block root" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    // Attestation with zero beacon_block_root should be silently ignored.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{0}, ZERO_HASH, 0, genesis_root, 2);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xFF), false);

    // No votes applied, no error.
    try testing.expectEqual(@as(u32, 0), fc.votes.len());
}

test "onAttestation with multiple validators shifts head" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{ 1, 1, 1 });
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 10);

    // Three validators vote for block_b via onAttestation.
    var att = try makeTestAttestation(testing.allocator, &[_]ValidatorIndex{ 0, 1, 2 }, block_b_root, 0, genesis_root, 2);
    defer att.attesting_indices.deinit(testing.allocator);
    var any_att = AnyIndexedAttestation{ .phase0 = &att };

    try fc.onAttestation(testing.allocator, &any_att, hashFromByte(0xAA), false);

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(block_b_root, fc.getHead().block_root);
}

test "getHead returns genesis when no votes" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.updateHead(testing.allocator);
    const head = fc.getHead();
    try testing.expectEqual(genesis_root, head.block_root);
}

test "getHead with votes shifts head" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 64, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{ 1, 1, 1 });
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 64);

    try fc.addLatestMessage(testing.allocator, 0, 1, block_b_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, block_b_root, .full);
    try fc.addLatestMessage(testing.allocator, 2, 1, block_b_root, .full);

    try fc.updateHead(testing.allocator);
    const head = fc.getHead();
    try testing.expectEqual(block_b_root, head.block_root);
}

test "onAttesterSlashing removes equivocating weight" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 64, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{ 1, 1, 1 });
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 64);

    try fc.addLatestMessage(testing.allocator, 0, 1, block_b_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, block_b_root, .full);
    try fc.addLatestMessage(testing.allocator, 2, 1, block_a_root, .full);

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(block_b_root, fc.getHead().block_root);

    try fc.onAttesterSlashing(&[_]ValidatorIndex{ 0, 1 });

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(block_a_root, fc.getHead().block_root);
}

test "updateTime advances slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try testing.expectEqual(@as(Slot, 0), fc.getTime());
    try fc.updateTime(testing.allocator, 10);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());

    // Time should not go backwards.
    try fc.updateTime(testing.allocator, 5);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());
}

test "updateCheckpoints advances justified on higher epoch" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const new_root = hashFromByte(0x02);
    fc.updateCheckpoints(
        .{ .epoch = 1, .root = new_root },
        .{ .epoch = 1, .root = new_root },
    );

    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.finalized_checkpoint.epoch);
}

test "updateCheckpoints does not regress justified epoch" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 64, makeTestCheckpoint(2, genesis_root), makeTestCheckpoint(1, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    fc.updateCheckpoints(
        .{ .epoch = 1, .root = hashFromByte(0x02) },
        .{ .epoch = 0, .root = hashFromByte(0x02) },
    );

    // Should not regress.
    try testing.expectEqual(@as(Epoch, 2), fc.fcStore.justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.finalized_checkpoint.epoch);
}

test "updateUnrealizedCheckpoints advances unrealized" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const new_root = hashFromByte(0x02);
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 2, .root = new_root },
        .{ .epoch = 1, .root = new_root },
    );

    try testing.expectEqual(@as(Epoch, 2), fc.fcStore.unrealized_justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.unrealized_finalized_checkpoint.epoch);
}

test "updateUnrealizedCheckpoints does not regress epoch" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    // First advance unrealized to epoch 3/2.
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 3, .root = hashFromByte(0x02) },
        .{ .epoch = 2, .root = hashFromByte(0x02) },
    );

    // Attempt to regress to epoch 1/1 — should be ignored.
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 1, .root = hashFromByte(0x03) },
        .{ .epoch = 1, .root = hashFromByte(0x03) },
    );

    try testing.expectEqual(@as(Epoch, 3), fc.fcStore.unrealized_justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 2), fc.fcStore.unrealized_finalized_checkpoint.epoch);
}

test "prune delegates to ProtoArray" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const pruned = try fc.prune(testing.allocator, genesis_root);
    try testing.expectEqual(@as(usize, 0), pruned.len);
}

test "isDescendant checks ancestry" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, block_b_root, block_a_root), 10);

    try testing.expect(try fc.isDescendant(genesis_root, .full, block_b_root, .full));
    try testing.expect(try fc.isDescendant(block_a_root, .full, block_b_root, .full));
    try testing.expect(!try fc.isDescendant(block_b_root, .full, block_a_root, .full));
}

test "addLatestMessage updates vote for non-equivocating validator" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 32, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 32);

    try fc.addLatestMessage(testing.allocator, 0, 1, block_root, .full);

    try testing.expectEqual(@as(u32, 1), fc.votes.len());
    const fields = fc.votes.fields();
    try testing.expect(fields.next_indices[0] != NULL_VOTE_INDEX);
}

test "addLatestMessage skips equivocating validator" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 32, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 32);

    // Mark validator 0 as equivocating.
    try fc.onAttesterSlashing(&[_]ValidatorIndex{0});

    try fc.addLatestMessage(testing.allocator, 0, 1, block_root, .full);

    // Vote should not be recorded.
    try testing.expectEqual(@as(u32, 0), fc.votes.len());
}

test "onTick resets proposer boost and advances slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    fc.proposer_boost_root = hashFromByte(0x02);
    fc.justified_proposer_boost_score = 100;

    try fc.onTick(1);

    try testing.expectEqual(@as(Slot, 1), fc.fcStore.current_slot);
    try testing.expectEqual(@as(?Root, null), fc.proposer_boost_root);
    try testing.expectEqual(@as(?u64, null), fc.justified_proposer_boost_score);
}

test "processAttestationQueue applies queued attestations for past slots" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 5);

    // Manually queue an attestation at slot 3 (past).
    var block_map = BlockAttestationMap{};
    var att_list = std.ArrayListUnmanaged(QueuedAttestation){};
    try att_list.append(testing.allocator, .{ .validator_index = 0, .payload_status = .full });
    try block_map.put(testing.allocator, block_root, att_list);
    try fc.queued_attestations.put(testing.allocator, 3, block_map);

    try fc.processAttestationQueue(testing.allocator);

    // Attestation should have been processed — votes updated.
    try testing.expectEqual(@as(u32, 1), fc.votes.len());
}

test "updateTime loops onTick and processes queue" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.updateTime(testing.allocator, 5);

    try testing.expectEqual(@as(Slot, 5), fc.fcStore.current_slot);
    try testing.expectEqual(@as(?Root, null), fc.proposer_boost_root);
}

test "prune adjusts vote indices" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 64, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{1});
    defer deinitTestForkChoice(testing.allocator, fc);
    fc.setPruneThreshold(0); // Always prune.

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, block_b_root, block_a_root), 64);

    // Vote for block_b.
    try fc.addLatestMessage(testing.allocator, 0, 2, block_b_root, .full);

    // Record the index before prune.
    const fields_before = fc.votes.fields();
    const idx_before = fields_before.next_indices[0];
    try testing.expect(idx_before != NULL_VOTE_INDEX);

    // Finalize block_a and prune.
    fc.fcStore.setFinalizedCheckpoint(.{ .epoch = 1, .root = block_a_root });
    const pruned = try fc.prune(testing.allocator, block_a_root);
    defer testing.allocator.free(pruned);

    // Vote index should be adjusted down by prune count.
    const fields_after = fc.votes.fields();
    if (pruned.len > 0) {
        const pruned_count: u32 = @intCast(pruned.len);
        if (idx_before >= pruned_count) {
            try testing.expectEqual(idx_before - pruned_count, fields_after.next_indices[0]);
        }
    }
}

test "updateHead recomputes head with deltas" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 64, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{1});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.addLatestMessage(testing.allocator, 0, 1, block_a_root, .full);

    try fc.updateHead(testing.allocator);

    try testing.expectEqual(block_a_root, fc.head.block_root);
}

test "isBlockTimely for current slot within threshold" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 5, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    // Block at current slot with small delay is timely (SECONDS_PER_SLOT=6, threshold=6/3=2).
    try testing.expect(fc.isBlockTimely(5, 1));
    // Block at past slot is never timely.
    try testing.expect(!fc.isBlockTimely(3, 0));
}

test "hasBlock checks finalized descendant" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 10);

    try testing.expect(fc.hasBlock(block_root));
    try testing.expect(fc.hasBlockUnsafe(block_root));
    try testing.expect(!fc.hasBlock(hashFromByte(0xFF)));
}

test "getBlockDefaultStatus returns ProtoBlock" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const block = fc.getBlockDefaultStatus(genesis_root);
    try testing.expect(block != null);
    try testing.expectEqual(genesis_root, block.?.block_root);
}

test "getCanonicalBlockAtSlot finds block on canonical chain" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 64, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &[_]u16{1});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.addLatestMessage(testing.allocator, 0, 1, block_a_root, .full);
    try fc.updateHead(testing.allocator);

    const block = fc.getCanonicalBlockAtSlot(1);
    try testing.expect(block != null);
    try testing.expectEqual(block_a_root, block.?.block_root);

    // No block at slot 2.
    try testing.expect(fc.getCanonicalBlockAtSlot(2) == null);
}

test "getHeads returns leaf nodes" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_b_root, genesis_root), 10);

    const heads = try fc.getHeads(testing.allocator);
    defer testing.allocator.free(heads);
    // Two leaf nodes (block_a and block_b).
    try testing.expectEqual(@as(usize, 2), heads.len);
}

test "getSlotsPresent counts nodes in window" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 10, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(5, block_a_root, genesis_root), 10);

    // Window from slot 3: genesis at 0 excluded, block at 5 included.
    try testing.expectEqual(@as(u32, 1), fc.getSlotsPresent(3));
    // Window from slot 0: both included.
    try testing.expectEqual(@as(u32, 2), fc.getSlotsPresent(0));
}

test "updateAndGetHead returns head for canonical" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const result = try fc.updateAndGetHead(testing.allocator, .{ .get_canonical_head = {} });
    try testing.expectEqual(genesis_root, result.head.block_root);
}

test "shouldOverrideForkChoiceUpdate disabled by default" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(testing.allocator, genesis_block, 0, makeTestCheckpoint(0, genesis_root), makeTestCheckpoint(0, genesis_root), &.{});
    defer deinitTestForkChoice(testing.allocator, fc);

    const result = fc.shouldOverrideForkChoiceUpdate(&genesis_block, 0, 1);
    switch (result) {
        .should_not_override => |r| try testing.expectEqual(NotReorgedReason.proposer_boost_reorg_disabled, r.reason),
        .should_override => return error.TestUnexpectedResult,
    }
}

test "getCommitteeFraction computes correctly" {
    // SLOTS_PER_EPOCH = 32 (mainnet preset)
    // committeeWeight = totalBalance / 32, then * percent / 100
    // SLOTS_PER_EPOCH = 32 (mainnet preset)
    // committeeWeight = totalBalance / slotsPerEpoch, then * percent / 100
    try testing.expectEqual(@as(u64, 1), getCommitteeFraction(100, 32, 40)); // 100/32=3, 3*40/100=1
    try testing.expectEqual(@as(u64, 0), getCommitteeFraction(0, 32, 40));
    try testing.expectEqual(@as(u64, 15), getCommitteeFraction(1000, 32, 50)); // 1000/32=31, 31*50/100=15
    try testing.expectEqual(@as(u64, 124), getCommitteeFraction(10000, 32, 40)); // 10000/32=312, 312*40/100=124
}

test "EpochDifference values" {
    try testing.expectEqual(@as(u1, 0), @intFromEnum(EpochDifference.current));
    try testing.expectEqual(@as(u1, 1), @intFromEnum(EpochDifference.previous));
}

test "AncestorResult tagged union" {
    const common: AncestorResult = .{ .common_ancestor = .{ .depth = 5 } };
    try testing.expectEqual(@as(u32, 5), common.common_ancestor.depth);

    const desc: AncestorResult = .{ .descendant = {} };
    try testing.expectEqual(AncestorStatus.descendant, desc);

    const unknown: AncestorResult = .{ .block_unknown = {} };
    try testing.expectEqual(AncestorStatus.block_unknown, unknown);
}

test "ShouldOverrideForkChoiceUpdateResult variants" {
    const no_override: ShouldOverrideForkChoiceUpdateResult = .{
        .should_not_override = .{ .reason = .head_block_is_timely },
    };
    try testing.expectEqual(NotReorgedReason.head_block_is_timely, no_override.should_not_override.reason);
}

test "UpdateAndGetHeadOpt variants" {
    const canonical: UpdateAndGetHeadOpt = .{ .get_canonical_head = {} };
    try testing.expectEqual(UpdateHeadOpt.get_canonical_head, canonical);

    const proposer: UpdateAndGetHeadOpt = .{ .get_proposer_head = .{ .sec_from_slot = 4, .slot = 100 } };
    try testing.expectEqual(@as(u32, 4), proposer.get_proposer_head.sec_from_slot);
    try testing.expectEqual(@as(Slot, 100), proposer.get_proposer_head.slot);
}

test "ForkChoiceOpts defaults" {
    const opts: ForkChoiceOpts = .{};
    try testing.expect(opts.proposer_boost);
    try testing.expect(!opts.proposer_boost_reorg);
    try testing.expect(!opts.compute_unrealized);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: Proposer Reorg Tests (Group 1+2)
// Source: TS getProposerHead.test.ts, shouldOverrideForkChoiceUpdate.test.ts
//         Go reorg_late_blocks_test.go
// ═══════════════════════════════════════════════════════════════════════════════

/// Test-only helper: create ForkChoice with custom options.
fn initTestForkChoiceWithOpts(
    allocator: Allocator,
    anchor_block: ProtoBlock,
    current_slot: Slot,
    justified_checkpoint: CheckpointWithPayloadStatus,
    finalized_checkpoint: CheckpointWithPayloadStatus,
    justified_balances: []const u16,
    opts: ForkChoiceOpts,
) !*ForkChoice {
    const pa = try allocator.create(ProtoArray);
    errdefer allocator.destroy(pa);
    pa.* = try ProtoArray.initialize(allocator, anchor_block, current_slot);
    errdefer pa.deinit(allocator);

    const fc_store = try allocator.create(ForkChoiceStore);
    errdefer allocator.destroy(fc_store);
    fc_store.* = try ForkChoiceStore.init(allocator, current_slot, justified_checkpoint, finalized_checkpoint, justified_balances, test_balances_getter, .{});
    errdefer fc_store.deinit();

    const fc = try allocator.create(ForkChoice);
    errdefer allocator.destroy(fc);
    try fc.init(allocator, getTestConfig(), fc_store, pa, 0, opts);
    return fc;
}

/// Test-only: set a node's weight directly by block root.
fn setTestNodeWeight(fc: *ForkChoice, root: Root, weight: i64) void {
    const idx = fc.proto_array.getDefaultNodeIndex(root) orelse return;
    fc.proto_array.nodes.items[idx].weight = weight;
}

/// Common parameters for proposer reorg tests.
/// Defaults represent a scenario where ALL reorg conditions are met:
///   3-block chain: genesis(0) → parent(9) → head(10), current_slot=11
///   Thresholds with 32 validators * 128 = total 4096 (mainnet SLOTS_PER_EPOCH=32):
///     committee_weight = 4096 / 32 = 128
///     reorg_threshold  = 128 * 20 (REORG_HEAD_WEIGHT_THRESHOLD) / 100 = 25
///     parent_threshold = 128 * 160 (REORG_PARENT_WEIGHT_THRESHOLD) / 100 = 204
const ReorgTestParams = struct {
    head_timely: bool = false,
    parent_slot: Slot = 9,
    head_slot: Slot = 10,
    current_slot: Slot = 11,
    finalized_epoch: Epoch = 0,
    head_uj_epoch: Epoch = 0,
    parent_uj_epoch: Epoch = 0,
    head_uj_root: Root = ZERO_HASH,
    parent_uj_root: Root = ZERO_HASH,
    head_weight: i64 = 20,
    parent_weight: i64 = 250,
};

const ReorgTestCtx = struct {
    fc: *ForkChoice,
    head_block: ProtoBlock,
    genesis_root: Root,
    parent_root: Root,
    head_root: Root,
};

fn initReorgTest(allocator: Allocator, params: ReorgTestParams) !ReorgTestCtx {
    const genesis_root = hashFromByte(0x01);
    const parent_root = hashFromByte(0x02);
    const head_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);
    const balances = [_]u16{128} ** 32;

    const fc = try initTestForkChoiceWithOpts(
        allocator,
        genesis_block,
        params.current_slot,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(params.finalized_epoch, genesis_root),
        &balances,
        .{ .proposer_boost = true, .proposer_boost_reorg = true },
    );
    errdefer deinitTestForkChoice(allocator, fc);

    var parent_block = makeTestBlock(params.parent_slot, parent_root, genesis_root);
    parent_block.unrealized_justified_epoch = params.parent_uj_epoch;
    parent_block.unrealized_justified_root = params.parent_uj_root;
    try fc.onBlockFromProto(allocator, parent_block, params.current_slot);

    var head_block = makeTestBlock(params.head_slot, head_root, parent_root);
    head_block.timeliness = params.head_timely;
    head_block.unrealized_justified_epoch = params.head_uj_epoch;
    head_block.unrealized_justified_root = params.head_uj_root;
    try fc.onBlockFromProto(allocator, head_block, params.current_slot);

    setTestNodeWeight(fc, head_root, params.head_weight);
    setTestNodeWeight(fc, parent_root, params.parent_weight);

    return .{
        .fc = fc,
        .head_block = head_block,
        .genesis_root = genesis_root,
        .parent_root = parent_root,
        .head_root = head_root,
    };
}

// ── Group 1: getProposerHead ──

test "getProposerHead reorgs when all conditions met" {
    var ctx = try initReorgTest(testing.allocator, .{});
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, null), result.not_reorged_reason);
    try testing.expectEqual(ctx.parent_root, result.head.block_root);
    try testing.expectEqual(@as(?bool, false), result.is_head_timely);
}

test "getProposerHead no reorg: head block is timely" {
    var ctx = try initReorgTest(testing.allocator, .{ .head_timely = true });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .head_block_is_timely), result.not_reorged_reason);
    try testing.expectEqual(ctx.head_root, result.head.block_root);
}

test "getProposerHead no reorg: not shuffling stable (epoch boundary)" {
    // current_slot=32 is epoch boundary (32 % 32 == 0), head=31, parent=30
    var ctx = try initReorgTest(testing.allocator, .{ .parent_slot = 30, .head_slot = 31, .current_slot = 32 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .not_shuffling_stable), result.not_reorged_reason);
}

test "getProposerHead no reorg: not FFG competitive (epoch differs)" {
    var ctx = try initReorgTest(testing.allocator, .{ .head_uj_epoch = 0, .parent_uj_epoch = 1 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .not_ffg_competitive), result.not_reorged_reason);
}

test "getProposerHead no reorg: not FFG competitive (root differs)" {
    var ctx = try initReorgTest(testing.allocator, .{ .head_uj_root = hashFromByte(0xAA) });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .not_ffg_competitive), result.not_reorged_reason);
}

test "getProposerHead no reorg: chain long unfinality" {
    // Finalized at epoch 0, current_slot=97 → epoch 3 → 3-0=3 > MAX(2)
    // (mainnet SLOTS_PER_EPOCH=32, epoch 3 starts at slot 96)
    var ctx = try initReorgTest(testing.allocator, .{
        .parent_slot = 95,
        .head_slot = 96,
        .current_slot = 97,
        .finalized_epoch = 0,
    });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .chain_long_unfinality), result.not_reorged_reason);
}

test "getProposerHead no reorg: parent distance more than one slot" {
    // parent at slot 7, head at slot 10: 7+1 != 10
    var ctx = try initReorgTest(testing.allocator, .{ .parent_slot = 7 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .parent_block_distance_more_than_one_slot), result.not_reorged_reason);
}

test "getProposerHead no reorg: reorg more than one slot" {
    // head at 10, current_slot=12: 10+1 != 12
    var ctx = try initReorgTest(testing.allocator, .{ .current_slot = 12 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .reorg_more_than_one_slot), result.not_reorged_reason);
}

test "getProposerHead no reorg: head block not weak" {
    // head weight 25 >= reorg_threshold 25
    var ctx = try initReorgTest(testing.allocator, .{ .head_weight = 25 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .head_block_not_weak), result.not_reorged_reason);
}

test "getProposerHead no reorg: parent block not strong" {
    // parent weight 204 <= parent_threshold 204
    var ctx = try initReorgTest(testing.allocator, .{ .parent_weight = 204 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 0, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .parent_block_not_strong), result.not_reorged_reason);
}

test "getProposerHead no reorg: not proposing on time" {
    // Minimal ChainConfig: PROPOSER_REORG_CUTOFF_BPS=1667, SLOT_DURATION_MS=6000
    // cutoff = (1667 * 6000 + 5000) / 10000 = 1000ms
    // sec_from_slot=2 → 2000ms > 1000ms → not on time
    var ctx = try initReorgTest(testing.allocator, .{});
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.getProposerHead(&ctx.head_block, 2, ctx.fc.fcStore.current_slot);
    try testing.expectEqual(@as(?NotReorgedReason, .not_proposing_on_time), result.not_reorged_reason);
}

// ── Group 2: shouldOverrideForkChoiceUpdate (deduplicated — preliminary checks covered by Group 1) ──

test "shouldOverrideFCU overrides when head.slot == current_slot" {
    // head_slot=10, current_slot=10 → head.slot == current_slot → timing passes
    var ctx = try initReorgTest(testing.allocator, .{ .current_slot = 10 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.shouldOverrideForkChoiceUpdate(&ctx.head_block, 0, 10);
    switch (result) {
        .should_override => |r| try testing.expectEqual(ctx.parent_root, r.parent_block.block_root),
        .should_not_override => return error.TestUnexpectedResult,
    }
}

test "shouldOverrideFCU overrides when proposal_slot == current_slot and on time" {
    // head_slot=10, current_slot=11 → proposal_slot=11==current_slot, sec_from_slot=0 → on time
    var ctx = try initReorgTest(testing.allocator, .{});
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.shouldOverrideForkChoiceUpdate(&ctx.head_block, 0, 11);
    switch (result) {
        .should_override => |r| try testing.expectEqual(ctx.parent_root, r.parent_block.block_root),
        .should_not_override => return error.TestUnexpectedResult,
    }
}

test "shouldOverrideFCU no override: timing fails" {
    // head_slot=10, current_slot=13 → head.slot!=13, proposal_slot=11!=13 → timing fails
    var ctx = try initReorgTest(testing.allocator, .{ .current_slot = 13 });
    defer deinitTestForkChoice(testing.allocator, ctx.fc);

    const result = ctx.fc.shouldOverrideForkChoiceUpdate(&ctx.head_block, 0, 13);
    switch (result) {
        .should_not_override => |r| try testing.expectEqual(NotReorgedReason.reorg_more_than_one_slot, r.reason),
        .should_override => return error.TestUnexpectedResult,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: getDependentRoot tests (Group 3)
// Source: TS forkChoice.test.ts
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a chain of blocks at given slots and return a ForkChoice for getDependentRoot testing.
/// `block_slots` must include slot 0 for genesis. All blocks connect linearly.
/// Returns roots where root[i] = hashFromByte(slot + 1) (so slot 0 → 0x01, slot 31 → 0x20, etc.)
fn initDependentRootChain(allocator: Allocator, block_slots: []const Slot) !*ForkChoice {
    assert(block_slots.len > 0);
    assert(block_slots[0] == 0);

    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    // Use a large current_slot so all blocks are valid.
    const max_slot = block_slots[block_slots.len - 1];
    const current_slot = max_slot + 10;

    var fc = try initTestForkChoice(
        allocator,
        genesis_block,
        current_slot,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    errdefer deinitTestForkChoice(allocator, fc);

    // Add remaining blocks.
    for (block_slots[1..], 1..) |slot, i| {
        const parent_slot = block_slots[i - 1];
        const parent_root = hashFromByte(@intCast(parent_slot + 1));
        const root = hashFromByte(@intCast(slot + 1));
        const block = makeTestBlock(slot, root, parent_root);
        try fc.onBlockFromProto(allocator, block, current_slot);
    }

    return fc;
}

fn rootForSlot(slot: Slot) Root {
    return hashFromByte(@intCast(slot + 1));
}

test "getDependentRoot table-driven" {
    // SLOTS_PER_EPOCH = 32 (mainnet preset).
    // getDependentRoot logic:
    //   dep_epoch = block_epoch (current) or block_epoch-1 (previous)
    //   dep_slot  = dep_epoch * 32
    //   Walk ancestors from block; first node with slot <= dep_slot is the dependent root.
    //   If block.slot <= dep_slot, return block.parent_root.

    const Case = struct {
        at_slot: Slot,
        /// Slots with actual blocks (must include 0 for genesis).
        chain_slots: []const Slot,
        epoch_diff: EpochDifference,
        expected_root: Root,
    };

    const cases = [_]Case{
        // Case 1: atSlot=32, pivot at 31, current epoch, no skipped slots
        // chain: 0,31,32. dep_slot=32. block.slot=32 <= dep_slot → parent_root = root(31)
        .{
            .at_slot = 32,
            .chain_slots = &[_]Slot{ 0, 31, 32 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(31),
        },
        // Case 2: atSlot=32, pivot at 30, current epoch, [31] skipped
        // chain: 0,30,32. dep_slot=32. block.slot=32 <= dep_slot → parent_root = root(30)
        .{
            .at_slot = 32,
            .chain_slots = &[_]Slot{ 0, 30, 32 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(30),
        },
        // Case 3: atSlot=32, pivot at 1, current epoch, [2..31] skipped
        // chain: 0,1,32. dep_slot=32. block.slot=32 <= dep_slot → parent_root = root(1)
        .{
            .at_slot = 32,
            .chain_slots = &[_]Slot{ 0, 1, 32 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(1),
        },
        // Case 4: atSlot=32, pivot at 0, current epoch, [1..31] skipped
        // chain: 0,32. dep_slot=32. block.slot=32 <= dep_slot → parent_root = root(0)
        .{
            .at_slot = 32,
            .chain_slots = &[_]Slot{ 0, 32 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(0),
        },
        // Case 5: atSlot=33, pivot at 32, current epoch, no skipped
        // chain: 0,32,33. epoch(33)=1, dep_slot=32. Walk from 33 → 32 (slot 32 <= 32) → root(32)
        .{
            .at_slot = 33,
            .chain_slots = &[_]Slot{ 0, 32, 33 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(32),
        },
        // Case 6: atSlot=33, pivot at 31, current epoch, [32] skipped
        // chain: 0,31,33. epoch(33)=1, dep_slot=32. Walk from 33 → 31 (slot 31 <= 32) → root(31)
        .{
            .at_slot = 33,
            .chain_slots = &[_]Slot{ 0, 31, 33 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(31),
        },
        // Case 7: atSlot=33, pivot at 0, current epoch, [1..32] skipped
        // chain: 0,33. epoch(33)=1, dep_slot=32. Walk from 33 → 0 (slot 0 <= 32) → root(0)
        .{
            .at_slot = 33,
            .chain_slots = &[_]Slot{ 0, 33 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(0),
        },
        // Case 8: atSlot=32, pivot at 31, previous epoch, no skipped
        // chain: 0,31,32. epoch(32)=1, prev_epoch=0, dep_slot=0.
        // Walk from 32 → 31 (slot 31 > 0) → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 32,
            .chain_slots = &[_]Slot{ 0, 31, 32 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 9: atSlot=32, pivot at 0, previous epoch, [1..31] skipped
        // chain: 0,32. epoch(32)=1, prev_epoch=0, dep_slot=0.
        // block.slot=32 > dep_slot=0. Walk → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 32,
            .chain_slots = &[_]Slot{ 0, 32 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 10: atSlot=33, pivot at 31, previous epoch, no skipped
        // chain: 0,31,33. epoch(33)=1, prev_epoch=0, dep_slot=0.
        // Walk from 33 → 31 → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 33,
            .chain_slots = &[_]Slot{ 0, 31, 33 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 11: atSlot=33, pivot at 0, previous epoch, [1..32] skipped
        // chain: 0,33. epoch(33)=1, prev_epoch=0, dep_slot=0.
        // Walk from 33 → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 33,
            .chain_slots = &[_]Slot{ 0, 33 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 12: atSlot=1, pivot at 0, current epoch, epoch 0 simple
        // chain: 0,1. epoch(1)=0, dep_slot=0. block.slot=1 > 0.
        // Walk from 1 → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 1,
            .chain_slots = &[_]Slot{ 0, 1 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(0),
        },
        // Case 13: atSlot=1, pivot at 0, previous epoch = genesis
        // chain: 0,1. epoch(1)=0, prev_epoch = max(0,0-1)=0, dep_slot=0.
        // block.slot=1 > 0. Walk → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 1,
            .chain_slots = &[_]Slot{ 0, 1 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 14: atSlot=4, pivot at 3, current epoch, mid epoch 0
        // chain: 0,3,4. epoch(4)=0, dep_slot=0. block.slot=4 > 0.
        // Walk from 4 → 3 → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 4,
            .chain_slots = &[_]Slot{ 0, 3, 4 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(0),
        },
        // Case 15: atSlot=4, pivot at 0, current epoch, mid epoch 0 all skipped
        // chain: 0,4. epoch(4)=0, dep_slot=0. block.slot=4 > 0.
        // Walk → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 4,
            .chain_slots = &[_]Slot{ 0, 4 },
            .epoch_diff = .current,
            .expected_root = rootForSlot(0),
        },
        // Case 16: atSlot=4, pivot at 3, previous epoch, mid epoch 0 previous
        // chain: 0,3,4. epoch(4)=0, prev_epoch=0, dep_slot=0.
        // block.slot=4 > 0. Walk → 3 → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 4,
            .chain_slots = &[_]Slot{ 0, 3, 4 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 17: atSlot=4, pivot at 0, previous epoch, mid epoch 0 all skipped
        // chain: 0,4. epoch(4)=0, prev_epoch=0, dep_slot=0.
        // block.slot=4 > 0. Walk → 0 (slot 0 <= 0) → root(0)
        .{
            .at_slot = 4,
            .chain_slots = &[_]Slot{ 0, 4 },
            .epoch_diff = .previous,
            .expected_root = rootForSlot(0),
        },
        // Case 18: atSlot=0, genesis slot, current epoch
        // chain: 0. epoch(0)=0, dep_slot=0. block.slot=0 <= 0 → parent_root = ZERO_HASH (genesis parent)
        .{
            .at_slot = 0,
            .chain_slots = &[_]Slot{0},
            .epoch_diff = .current,
            .expected_root = ZERO_HASH,
        },
    };

    for (cases) |tc| {
        var fc = try initDependentRootChain(testing.allocator, tc.chain_slots);
        defer deinitTestForkChoice(testing.allocator, fc);

        const head_root = rootForSlot(tc.at_slot);
        const block = fc.getBlockDefaultStatus(head_root) orelse return error.TestBlockNotFound;
        const result = try fc.getDependentRoot(block, tc.epoch_diff);
        try testing.expectEqual(tc.expected_root, result);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: getAllAncestorBlocks / getAllNonAncestorBlocks tests (Group 4)
// Source: TS forkChoice.test.ts
// ═══════════════════════════════════════════════════════════════════════════════

test "getAllAncestorBlocks returns ancestors from head to finalized" {
    // Chain: genesis(0) → block_a(1)
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{1},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 10);

    // Vote for block_a to make it head.
    try fc.addLatestMessage(testing.allocator, 0, 1, block_a_root, .full);
    try fc.updateHead(testing.allocator);
    try testing.expectEqual(block_a_root, fc.head.block_root);

    // Get ancestors from head to genesis root.
    const ancestors = try fc.getAllAncestorBlocks(testing.allocator, genesis_root, .full);
    defer testing.allocator.free(ancestors);

    // Should include head (block_a) and genesis.
    try testing.expectEqual(@as(usize, 2), ancestors.len);
    try testing.expectEqual(block_a_root, ancestors[0].block_root); // head first
    try testing.expectEqual(genesis_root, ancestors[1].block_root);
}

test "getAllAncestorAndNonAncestorBlocks with fork" {
    // Chain: genesis(0) → a(1) → b(2) → c(3)
    //                  \→ fork(1)
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const c_root = hashFromByte(0x04);
    const fork_root = hashFromByte(0x0A);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 1, 1 },
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, b_root, a_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(3, c_root, b_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, fork_root, genesis_root), 10);

    // Vote for c to make it head.
    try fc.addLatestMessage(testing.allocator, 0, 3, c_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 3, c_root, .full);
    try fc.updateHead(testing.allocator);
    try testing.expectEqual(c_root, fc.head.block_root);

    // Get combined results.
    const result = try fc.getAllAncestorAndNonAncestorBlocks(testing.allocator, genesis_root, .full);
    defer testing.allocator.free(result.ancestors);
    defer testing.allocator.free(result.non_ancestors);

    // ancestors: walk from head backwards to genesis (excluding head).
    // non-ancestors: all blocks not on that ancestor path.
    // Combined should cover all nodes in the DAG.
    const total_nodes = fc.nodeCount();
    // ancestors + non_ancestors should account for all nodes (head may or may not be included).
    try testing.expect(result.ancestors.len > 0);
    try testing.expect(result.non_ancestors.len > 0);
    try testing.expect(result.ancestors.len + result.non_ancestors.len <= total_nodes);

    // non_ancestors should contain the fork block.
    var found_fork = false;
    for (result.non_ancestors) |block| {
        if (std.mem.eql(u8, &block.block_root, &fork_root)) {
            found_fork = true;
            break;
        }
    }
    try testing.expect(found_fork);

    // ancestors should NOT contain the fork block.
    var fork_in_ancestors = false;
    for (result.ancestors) |block| {
        if (std.mem.eql(u8, &block.block_root, &fork_root)) {
            fork_in_ancestors = true;
            break;
        }
    }
    try testing.expect(!fork_in_ancestors);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: Unrealized justification tests (Group 8)
// Source: TS forkChoice.test.ts, Go forkchoice_test.go
// ═══════════════════════════════════════════════════════════════════════════════

test "unrealized justified realized on epoch boundary via updateTime" {
    // Setup: genesis at slot 0, advance unrealized justified to epoch 2.
    // Then tick past an epoch boundary → realized justified should be updated.
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        0,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Realized justified is epoch 0. Set unrealized to epoch 2.
    const new_root = hashFromByte(0x02);
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 2, .root = new_root },
        .{ .epoch = 1, .root = new_root },
    );
    try testing.expectEqual(@as(Epoch, 0), fc.fcStore.justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 2), fc.fcStore.unrealized_justified.checkpoint.epoch);

    // Tick from 0 to 32 (epoch boundary 0→1 with mainnet SLOTS_PER_EPOCH=32).
    try fc.updateTime(testing.allocator, 32);

    // After epoch boundary: unrealized justified (epoch 2) should be realized.
    try testing.expectEqual(@as(Epoch, 2), fc.fcStore.justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.finalized_checkpoint.epoch);
}

test "unrealized finalized realized on epoch boundary via updateTime" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        0,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    const new_root = hashFromByte(0x02);
    // Set unrealized finalized to epoch 3.
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 4, .root = new_root },
        .{ .epoch = 3, .root = new_root },
    );
    try testing.expectEqual(@as(Epoch, 0), fc.fcStore.finalized_checkpoint.epoch);

    // Tick past epoch boundary.
    try fc.updateTime(testing.allocator, 32);

    try testing.expectEqual(@as(Epoch, 3), fc.fcStore.finalized_checkpoint.epoch);
}

test "multiple epoch boundaries progressively realize unrealized checkpoints" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        0,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    const root_a = hashFromByte(0x02);
    // Set unrealized justified to epoch 1.
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 1, .root = root_a },
        .{ .epoch = 0, .root = genesis_root },
    );

    // Tick past first epoch boundary (slot 32).
    try fc.updateTime(testing.allocator, 32);
    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.justified.checkpoint.epoch);

    // Now set unrealized justified to epoch 3.
    const root_b = hashFromByte(0x03);
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 3, .root = root_b },
        .{ .epoch = 2, .root = root_b },
    );
    try testing.expectEqual(@as(Epoch, 1), fc.fcStore.justified.checkpoint.epoch); // not yet realized

    // Tick past second epoch boundary (slot 64).
    try fc.updateTime(testing.allocator, 64);
    try testing.expectEqual(@as(Epoch, 3), fc.fcStore.justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 2), fc.fcStore.finalized_checkpoint.epoch);
}

test "unrealized checkpoints not realized before epoch boundary" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        0,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 2, .root = hashFromByte(0x02) },
        .{ .epoch = 1, .root = hashFromByte(0x02) },
    );

    // Tick within the same epoch (slot 0 → 31).
    try fc.updateTime(testing.allocator, 31);

    // Unrealized should NOT be realized yet (no epoch boundary crossed).
    try testing.expectEqual(@as(Epoch, 0), fc.fcStore.justified.checkpoint.epoch);
    try testing.expectEqual(@as(Epoch, 0), fc.fcStore.finalized_checkpoint.epoch);
}

test "updateCheckpoints epoch monotonic: lower epoch ignored" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        0,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    const root_a = hashFromByte(0x02);
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 3, .root = root_a },
        .{ .epoch = 2, .root = root_a },
    );

    // Realize at epoch boundary.
    try fc.updateTime(testing.allocator, 32);
    try testing.expectEqual(@as(Epoch, 3), fc.fcStore.justified.checkpoint.epoch);

    // Now set unrealized to lower epoch (1) — should be ignored by updateUnrealizedCheckpoints.
    fc.updateUnrealizedCheckpoints(
        .{ .epoch = 1, .root = hashFromByte(0x03) },
        .{ .epoch = 0, .root = hashFromByte(0x03) },
    );

    // Tick to next epoch boundary.
    try fc.updateTime(testing.allocator, 64);

    // Justified should still be epoch 3 (lower unrealized was ignored).
    try testing.expectEqual(@as(Epoch, 3), fc.fcStore.justified.checkpoint.epoch);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: Proposer boost tests (Group 9)
// Source: TS forkChoice.test.ts, Go forkchoice_test.go
// ═══════════════════════════════════════════════════════════════════════════════

test "setProposerBoost affects head selection" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 128, 128 },
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Two competing blocks: a and b.
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, b_root, genesis_root), 10);

    // One vote each — root tiebreaker decides (b_root=0x03 > a_root=0x02).
    try fc.addLatestMessage(testing.allocator, 0, 1, a_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, b_root, .full);
    try fc.updateHead(testing.allocator);
    try testing.expectEqual(b_root, fc.head.block_root);

    // Boost a via proposer_boost_root. The score is computed from total_balance.
    fc.proposer_boost_root = a_root;
    fc.justified_proposer_boost_score = null; // force recompute
    try fc.updateHead(testing.allocator);
    try testing.expectEqual(a_root, fc.head.block_root);
}

test "clearProposerBoost reverts head to natural winner" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 128, 128 },
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, b_root, genesis_root), 10);

    try fc.addLatestMessage(testing.allocator, 0, 1, a_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, b_root, .full);

    // Boost a.
    fc.proposer_boost_root = a_root;
    fc.justified_proposer_boost_score = null;
    try fc.updateHead(testing.allocator);
    try testing.expectEqual(a_root, fc.head.block_root);

    // Stop boosting a — just null the boost root (leave previous_proposer_boost for undo).
    fc.proposer_boost_root = null;
    fc.justified_proposer_boost_score = null;
    try fc.updateHead(testing.allocator);
    // Natural winner is b (higher root value 0x03 > 0x02).
    try testing.expectEqual(b_root, fc.head.block_root);
}

test "proposer boost disabled by opts" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    // Create with proposer_boost = false.
    var fc = try initTestForkChoiceWithOpts(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 1, 1 },
        .{ .proposer_boost = false },
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, b_root, genesis_root), 10);

    try fc.addLatestMessage(testing.allocator, 0, 1, a_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, b_root, .full);

    // Set boost on a — but opts.proposer_boost is false, so updateHead should ignore it.
    fc.proposer_boost_root = a_root;
    fc.justified_proposer_boost_score = 1000;
    try fc.updateHead(testing.allocator);
    // b wins by root tiebreak (0x03 > 0x02).
    try testing.expectEqual(b_root, fc.head.block_root);
}

test "proposer boost score computation via getCommitteeFraction" {
    // Verify the boost score formula: total_balance / SLOTS_PER_EPOCH * PROPOSER_SCORE_BOOST / 100
    // With minimal config: PROPOSER_SCORE_BOOST = 40
    // SLOTS_PER_EPOCH = 32 (mainnet preset)
    // total_balance = 3200 → committee_weight = 100 → score = 100 * 40 / 100 = 40
    try testing.expectEqual(@as(u64, 40), getCommitteeFraction(3200, preset.SLOTS_PER_EPOCH, 40));

    // Edge: zero balance → zero boost.
    try testing.expectEqual(@as(u64, 0), getCommitteeFraction(0, preset.SLOTS_PER_EPOCH, 40));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: Execution status edge cases (Group 10)
// Source: Go forkchoice_test.go, TS forkChoice.test.ts
// ═══════════════════════════════════════════════════════════════════════════════

test "onBlockFromProto rejects block at finalized slot" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        64,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Finalize at epoch 1 (slot 32).
    fc.fcStore.setFinalizedCheckpoint(.{ .epoch = 1, .root = genesis_root });

    // Block at slot 32 (== finalized slot) should be rejected.
    const late_block = makeTestBlock(32, hashFromByte(0x02), genesis_root);
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, late_block, 64));

    // Block at slot 10 (< finalized slot) should also be rejected.
    const old_block = makeTestBlock(10, hashFromByte(0x03), genesis_root);
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, old_block, 64));
}

test "onBlockFromProto rejects block with unknown parent" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Block with unknown parent.
    const orphan = makeTestBlock(1, hashFromByte(0x02), hashFromByte(0xFF));
    try testing.expectError(error.InvalidBlock, fc.onBlockFromProto(testing.allocator, orphan, 10));
}

test "isDescendant returns false for unknown roots" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Unknown ancestor returns false.
    const result = try fc.isDescendant(hashFromByte(0xFF), .full, genesis_root, .full);
    try testing.expect(!result);

    // Unknown descendant returns false.
    const result2 = try fc.isDescendant(genesis_root, .full, hashFromByte(0xFF), .full);
    try testing.expect(!result2);
}

test "isDescendant identity comparison" {
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Same root, same status → true.
    const result = try fc.isDescendant(genesis_root, .full, genesis_root, .full);
    try testing.expect(result);
}

test "isDescendant across multiple blocks" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, b_root, a_root), 10);

    // b is descendant of genesis.
    try testing.expect(try fc.isDescendant(genesis_root, .full, b_root, .full));
    // b is descendant of a.
    try testing.expect(try fc.isDescendant(a_root, .full, b_root, .full));
    // a is NOT descendant of b.
    try testing.expect(!try fc.isDescendant(b_root, .full, a_root, .full));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port: Additional edge cases (Group 11)
// Source: TS forkChoice.test.ts, Go forkchoice_test.go
// ═══════════════════════════════════════════════════════════════════════════════

test "prune with multiple validators mixed valid and pruned indices" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        64,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 1, 1, 1 },
    );
    defer deinitTestForkChoice(testing.allocator, fc);
    fc.setPruneThreshold(0);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 64);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, b_root, a_root), 64);

    // Validator 0 votes for genesis (will be pruned).
    try fc.addLatestMessage(testing.allocator, 0, 0, genesis_root, .full);
    // Validator 1 votes for a (finalized, boundary case).
    try fc.addLatestMessage(testing.allocator, 1, 1, a_root, .full);
    // Validator 2 votes for b (survives prune).
    try fc.addLatestMessage(testing.allocator, 2, 2, b_root, .full);

    fc.fcStore.setFinalizedCheckpoint(.{ .epoch = 1, .root = a_root });
    const pruned = try fc.prune(testing.allocator, a_root);
    defer testing.allocator.free(pruned);

    const fields = fc.votes.fields();
    // Validator 0: voted for genesis (pruned) → NULL
    try testing.expectEqual(NULL_VOTE_INDEX, fields.next_indices[0]);
    // Validator 2: voted for b → index adjusted down
    try testing.expect(fields.next_indices[2] != NULL_VOTE_INDEX);
}

test "onAttesterSlashing affects head via computeDeltas" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 1, 1, 1 },
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, b_root, genesis_root), 10);

    // 2 votes for a, 1 for b → a wins.
    try fc.addLatestMessage(testing.allocator, 0, 1, a_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, a_root, .full);
    try fc.addLatestMessage(testing.allocator, 2, 1, b_root, .full);

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(a_root, fc.head.block_root);

    // Slash both validators voting for a. Their weight should be zeroed.
    try fc.onAttesterSlashing(&[_]u64{ 0, 1 });

    // Now b's single vote should win.
    try fc.updateHead(testing.allocator);
    try testing.expectEqual(b_root, fc.head.block_root);
}

test "multiple forks competing with votes" {
    // Fork diagram:
    //     genesis(0)
    //       / | \
    //      a  b  c   (all at slot 1)
    //              \
    //               d (slot 2)
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const c_root = hashFromByte(0x04);
    const d_root = hashFromByte(0x05);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{ 1, 1, 1, 1, 1 },
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, b_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, c_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(2, d_root, c_root), 10);

    // 1 vote a, 1 vote b, 3 votes d → d wins.
    try fc.addLatestMessage(testing.allocator, 0, 1, a_root, .full);
    try fc.addLatestMessage(testing.allocator, 1, 1, b_root, .full);
    try fc.addLatestMessage(testing.allocator, 2, 2, d_root, .full);
    try fc.addLatestMessage(testing.allocator, 3, 2, d_root, .full);
    try fc.addLatestMessage(testing.allocator, 4, 2, d_root, .full);

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(d_root, fc.head.block_root);

    // Head chain: d → c → genesis.
    const heads = try fc.getHeads(testing.allocator);
    defer testing.allocator.free(heads);
    // Should have 3 leaf nodes: a, b, d.
    try testing.expectEqual(@as(usize, 3), heads.len);
}

test "getSlotsPresent counts blocks in finalized window" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &.{},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Genesis at 0, a at 1, b at 5 (slots 2-4 skipped).
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(5, b_root, a_root), 10);

    // Count from slot 0 → 3 blocks present (genesis, a, b).
    const present = fc.getSlotsPresent(0);
    try testing.expectEqual(@as(u32, 3), present);

    // Count from slot 2 → 1 block present (only b at slot 5).
    const present2 = fc.getSlotsPresent(2);
    try testing.expectEqual(@as(u32, 1), present2);
}

test "addLatestMessage skips equivocating validator from slashing" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{1},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, a_root, genesis_root), 10);

    // First add a valid vote.
    try fc.addLatestMessage(testing.allocator, 0, 1, a_root, .full);
    try testing.expectEqual(@as(u32, 1), fc.votes.len());
    const fields1 = fc.votes.fields();
    try testing.expect(fields1.next_indices[0] != NULL_VOTE_INDEX);

    // Slash validator 0.
    try fc.onAttesterSlashing(&[_]u64{0});

    // Now try adding a newer vote — should be silently skipped.
    try fc.addLatestMessage(testing.allocator, 0, 2, a_root, .full);

    // next_indices should still point to the old vote (not updated to slot 2).
    const fields2 = fc.votes.fields();
    try testing.expectEqual(fields1.next_indices[0], fields2.next_indices[0]);
    // Slot should not have been updated (remains at 1, not 2).
    try testing.expectEqual(@as(Slot, 1), fields2.next_slots[0]);
}

test "getCanonicalBlockAtSlot exact match and getCanonicalBlockClosestLteSlot" {
    const genesis_root = hashFromByte(0x01);
    const a_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        10,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{1},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    // Block at slot 5 (slots 1-4 skipped).
    try fc.onBlockFromProto(testing.allocator, makeTestBlock(5, a_root, genesis_root), 10);

    try fc.addLatestMessage(testing.allocator, 0, 5, a_root, .full);
    try fc.updateHead(testing.allocator);

    // Exact match: slot 3 (skipped) → null.
    try testing.expectEqual(@as(?ProtoBlock, null), fc.getCanonicalBlockAtSlot(3));

    // Exact match: slot 5 → a.
    const block5 = fc.getCanonicalBlockAtSlot(5);
    try testing.expect(block5 != null);
    try testing.expectEqual(a_root, block5.?.block_root);

    // Closest LTE: slot 3 (skipped) → genesis (last block at or before 3).
    const closest = fc.getCanonicalBlockClosestLteSlot(3);
    try testing.expect(closest != null);
    try testing.expectEqual(genesis_root, closest.?.block_root);
}

test "deep chain head selection follows longest weighted branch" {
    // Build a deep chain: genesis → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8
    const genesis_root = hashFromByte(0x01);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try initTestForkChoice(
        testing.allocator,
        genesis_block,
        20,
        makeTestCheckpoint(0, genesis_root),
        makeTestCheckpoint(0, genesis_root),
        &[_]u16{1},
    );
    defer deinitTestForkChoice(testing.allocator, fc);

    var prev_root = genesis_root;
    var i: u8 = 1;
    while (i <= 8) : (i += 1) {
        const root = hashFromByte(i + 1);
        try fc.onBlockFromProto(testing.allocator, makeTestBlock(i, root, prev_root), 20);
        prev_root = root;
    }

    // Vote for the deepest block.
    const tip_root = hashFromByte(9); // slot 8, root 0x09
    try fc.addLatestMessage(testing.allocator, 0, 8, tip_root, .full);
    try fc.updateHead(testing.allocator);

    try testing.expectEqual(tip_root, fc.head.block_root);
    try testing.expectEqual(@as(usize, 9), fc.nodeCount()); // genesis + 8 blocks
}
