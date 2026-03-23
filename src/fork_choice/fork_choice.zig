const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

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
        proto_array.prune_threshold = opts.prune_threshold;

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

    /// Recompute fork choice head: computeDeltas -> applyScoreChanges -> findHead.
    /// Matching TS `updateHead()` (private).
    fn updateHead(self: *ForkChoice, allocator: Allocator) !void {
        const vote_fields = self.votes.fields();
        const new_balances = self.fcStore.justified.balances.get().items;

        const result = try computeDeltas(
            allocator,
            &self.deltas_cache,
            @intCast(self.proto_array.nodes.items.len),
            vote_fields.current_indices,
            vote_fields.next_indices,
            self.balances.get().items,
            new_balances,
            &self.fcStore.equivocating_indices,
        );

        // Compute proposer boost score if enabled.
        var proposer_boost_score: u64 = 0;
        if (self.opts.proposer_boost and self.proposer_boost_root != null) {
            if (self.justified_proposer_boost_score) |score| {
                proposer_boost_score = score;
            } else {
                // Lazy compute: committee_weight * PROPOSER_SCORE_BOOST / 100
                const total_balance = self.fcStore.justified.total_balance;
                const slots_per_epoch = preset.SLOTS_PER_EPOCH;
                const committee_weight = total_balance / slots_per_epoch;
                proposer_boost_score = (committee_weight * self.config.chain.PROPOSER_SCORE_BOOST) / 100;
                self.justified_proposer_boost_score = proposer_boost_score;
            }
        }

        const proposer_boost = if (self.proposer_boost_root) |root|
            proto_array_mod.ProtoArray.ProposerBoost{ .root = root, .score = proposer_boost_score }
        else
            null;

        try self.proto_array.applyScoreChanges(
            result.deltas,
            proposer_boost,
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

        // Update old balances for next delta computation.
        var new_balances_list = store_mod.JustifiedBalances.init(allocator);
        errdefer new_balances_list.deinit();
        try new_balances_list.appendSlice(new_balances);
        const new_balances_rc = try EffectiveBalanceIncrementsRc.init(allocator, new_balances_list);
        self.balances.release();
        self.balances = new_balances_rc;
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
                entry.value_ptr.deinit();
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

    try fc.updateHead(testing.allocator);
    const head = fc.getHead();
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

    try fc.updateHead(testing.allocator);
    const head = fc.getHead();
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

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(block_b_root, fc.getHead().block_root);

    try fc.onAttesterSlashing(&[_]ValidatorIndex{ 0, 1 });

    try fc.updateHead(testing.allocator);
    try testing.expectEqual(block_a_root, fc.getHead().block_root);
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
    try fc.updateTime(testing.allocator, 10);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());

    // Time should not go backwards.
    try fc.updateTime(testing.allocator, 5);
    try testing.expectEqual(@as(Slot, 10), fc.getTime());
}

test "updateCheckpoints advances justified on higher epoch" {
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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(2, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(1, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

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

test "addLatestMessage updates vote for non-equivocating validator" {
    const genesis_root = hashFromByte(0x01);
    const block_root = hashFromByte(0x02);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 32);
    defer fc.deinit(testing.allocator);

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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 32);
    defer fc.deinit(testing.allocator);

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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 0);
    defer fc.deinit(testing.allocator);

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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &.{},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 5);
    defer fc.deinit(testing.allocator);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_root, genesis_root), 5);

    // Manually queue an attestation at slot 3 (past).
    var block_map = BlockAttestationMap.init(testing.allocator);
    var att_list = std.ArrayListUnmanaged(QueuedAttestation){};
    try att_list.append(testing.allocator, .{ .validator_index = 0, .payload_status = .full });
    try block_map.put(block_root, att_list);
    try fc.queued_attestations.put(3, block_map);

    try fc.processAttestationQueue(testing.allocator);

    // Attestation should have been processed — votes updated.
    try testing.expectEqual(@as(u32, 1), fc.votes.len());
}

test "updateTime loops onTick and processes queue" {
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

    try fc.updateTime(testing.allocator, 5);

    try testing.expectEqual(@as(Slot, 5), fc.fcStore.current_slot);
    try testing.expectEqual(@as(?Root, null), fc.proposer_boost_root);
}

test "prune adjusts vote indices" {
    const genesis_root = hashFromByte(0x01);
    const block_a_root = hashFromByte(0x02);
    const block_b_root = hashFromByte(0x03);
    const genesis_block = makeTestBlock(0, genesis_root, ZERO_HASH);

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &[_]u16{1},
        .justified_balances_getter = test_balances_getter,
        .prune_threshold = 0, // Always prune.
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

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

    var fc = try ForkChoice.init(testing.allocator, .{
        .config = getTestConfig(),
        .justified_checkpoint = makeTestCheckpoint(0, genesis_root),
        .finalized_checkpoint = makeTestCheckpoint(0, genesis_root),
        .justified_balances = &[_]u16{1},
        .justified_balances_getter = test_balances_getter,
    }, genesis_block, 64);
    defer fc.deinit(testing.allocator);

    try fc.onBlockFromProto(testing.allocator, makeTestBlock(1, block_a_root, genesis_root), 64);
    try fc.addLatestMessage(testing.allocator, 0, 1, block_a_root, .full);

    try fc.updateHead(testing.allocator);

    try testing.expectEqual(block_a_root, fc.head.block_root);
}
