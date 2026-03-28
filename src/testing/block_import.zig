//! Block import pipeline for deterministic simulation testing.
//!
//! Wires together state regen, state caches, STFN, BeaconDB, and head
//! tracking into a single importBlock() path — the same code path a
//! production beacon node uses on every received block.
//!
//! The pipeline:
//!   1. Get pre-state via block root → state root index
//!   2. Clone pre-state (never mutate cached copies)
//!   3. processSlots to advance to block slot
//!   4. processBlock to apply the block body
//!   5. Commit tree changes and compute roots
//!   6. Cache post-state in BlockStateCache
//!   7. Persist block to BeaconDB
//!   8. On epoch boundaries: cache checkpoint state
//!   9. Update HeadTracker

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const db_mod = @import("db");

const CachedBeaconState = state_transition.CachedBeaconState;
const StateRegen = state_transition.StateRegen;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const CheckpointKey = state_transition.CheckpointKey;
const BeaconDB = db_mod.BeaconDB;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const HeadTracker = @import("head_tracker.zig").HeadTracker;

const chain_blocks = @import("chain").blocks;
pub const ImportResult = chain_blocks.ImportResult;

pub const BlockImporter = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    cp_cache: *CheckpointStateCache,
    regen: *StateRegen,
    db: *BeaconDB,
    head_tracker: *HeadTracker,

    /// Maps block root → state root for state lookup in block cache.
    /// The block cache is keyed by state root, but we receive parent_root
    /// (a block root) from incoming blocks.
    block_to_state: std.AutoArrayHashMap([32]u8, [32]u8),

    pub fn init(
        allocator: Allocator,
        block_cache: *BlockStateCache,
        cp_cache: *CheckpointStateCache,
        regen: *StateRegen,
        db: *BeaconDB,
        head_tracker: *HeadTracker,
    ) BlockImporter {
        return .{
            .allocator = allocator,
            .block_cache = block_cache,
            .cp_cache = cp_cache,
            .regen = regen,
            .db = db,
            .head_tracker = head_tracker,
            .block_to_state = std.AutoArrayHashMap([32]u8, [32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *BlockImporter) void {
        self.block_to_state.deinit();
    }

    /// Register a genesis block root → state root mapping so the first
    /// block import can find its parent state.
    pub fn registerGenesisRoot(self: *BlockImporter, block_root: [32]u8, state_root: [32]u8) !void {
        try self.block_to_state.put(block_root, state_root);
    }

    /// Get state for a block root by first resolving to state root.
    fn getStateByBlockRoot(self: *BlockImporter, block_root: [32]u8) ?*CachedBeaconState {
        const state_root = self.block_to_state.get(block_root) orelse return null;
        return self.block_cache.get(state_root);
    }

    /// Import a signed beacon block through the full pipeline.
    pub fn importBlock(
        self: *BlockImporter,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const block_slot = signed_block.message.slot;
        const parent_root = signed_block.message.parent_root;

        const prev_epoch = computeEpochAtSlot(if (block_slot > 0) block_slot - 1 else 0);
        const target_epoch = computeEpochAtSlot(block_slot);
        const is_epoch_transition = target_epoch != prev_epoch;

        // 1. Get pre-state via block root → state root index.
        const pre_state = self.getStateByBlockRoot(parent_root) orelse
            return error.NoPreStateAvailable;

        // 2–5. Run STFN on a clone.
        const stfn_result = try self.runStateTransition(pre_state, signed_block, block_slot);
        const post_state = stfn_result.post_state;

        // 6. Cache post-state in BlockStateCache.
        const cached_state_root = try self.regen.onNewBlock(post_state, true);
        _ = cached_state_root;

        // Record block_root → state_root mapping for future lookups.
        try self.block_to_state.put(stfn_result.block_root, stfn_result.state_root);

        // 7. Persist block to BeaconDB.
        const any_signed = AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        const block_bytes = try any_signed.serialize(self.allocator);
        defer self.allocator.free(block_bytes);
        try self.db.putBlock(stfn_result.block_root, block_bytes);

        // 8. On epoch boundary: cache checkpoint state.
        if (is_epoch_transition) {
            const cp_state = try post_state.clone(self.allocator, .{ .transfer_cache = false });
            errdefer {
                cp_state.deinit();
                self.allocator.destroy(cp_state);
            }

            try self.regen.onCheckpoint(
                .{ .epoch = target_epoch, .root = stfn_result.block_root },
                cp_state,
            );
        }

        // 9. Update head tracker.
        try self.head_tracker.onBlock(stfn_result.block_root, block_slot);
        if (is_epoch_transition) {
            try self.head_tracker.onEpochTransition(post_state);
        }

        return .{
            .block_root = stfn_result.block_root,
            .state_root = stfn_result.state_root,
            .slot = block_slot,
            .epoch_transition = is_epoch_transition,
            .execution_optimistic = false,
        };
    }

    const StfnResult = struct {
        post_state: *CachedBeaconState,
        state_root: [32]u8,
        block_root: [32]u8,
    };

    /// Run state transition on a clone of pre_state. Returns caller-owned post-state.
    fn runStateTransition(
        self: *BlockImporter,
        pre_state: *CachedBeaconState,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
        block_slot: u64,
    ) !StfnResult {
        const post_state = try pre_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        // Advance to block slot (may trigger epoch transition).
        try state_transition.processSlots(self.allocator, post_state, block_slot, .{});

        // Apply the block.
        const any_signed = AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        const block = any_signed.beaconBlock();

        switch (post_state.state.forkSeq()) {
            inline else => |f| {
                switch (block.blockType()) {
                    inline else => |bt| {
                        if (comptime bt == .blinded and f.lt(.bellatrix)) {
                            return error.InvalidBlockTypeForFork;
                        }
                        try state_transition.processBlock(
                            f,
                            self.allocator,
                            post_state.config,
                            post_state.epoch_cache,
                            post_state.state.castToFork(f),
                            &post_state.slashings_cache,
                            bt,
                            block.castToFork(bt, f),
                            .{
                                .execution_payload_status = .valid,
                                .data_availability_status = .available,
                            },
                            .{ .verify_signature = false },
                        );
                    },
                }
            },
        }

        // Commit and compute roots.
        try post_state.state.commit();
        const state_root = (try post_state.state.hashTreeRoot()).*;

        // Compute block_root from a BeaconBlockHeader with state_root filled.
        // This matches the canonical block root used by process_slot: after
        // process_block sets latest_block_header with state_root=0, the next
        // process_slot fills state_root and then hashes the header into
        // block_roots[slot]. We reproduce that here so block_to_state
        // lookups match the parent_root computed by the block generator.
        const any_block = any_signed.beaconBlock();
        var body_root: [32]u8 = undefined;
        try any_block.beaconBlockBody().hashTreeRoot(self.allocator, &body_root);
        const header = types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = signed_block.message.parent_root,
            .state_root = state_root,
            .body_root = body_root,
        };
        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&header, &block_root);

        return .{
            .post_state = post_state,
            .state_root = state_root,
            .block_root = block_root,
        };
    }
};
