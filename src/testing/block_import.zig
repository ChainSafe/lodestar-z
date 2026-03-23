//! Block import pipeline for deterministic simulation testing.
//!
//! Wires together state regen, state caches, STFN, BeaconDB, and head
//! tracking into a single importBlock() path — the same code path a
//! production beacon node uses on every received block.
//!
//! The pipeline:
//!   1. Get pre-state via StateRegen (block cache → checkpoint cache → DB)
//!   2. Clone pre-state (never mutate cached copies)
//!   3. processSlots to advance to block slot
//!   4. processBlock to apply the block body
//!   5. Commit tree changes and compute roots
//!   6. Cache post-state in BlockStateCache via StateRegen
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

pub const ImportResult = struct {
    block_root: [32]u8,
    state_root: [32]u8,
    slot: u64,
    epoch_transition: bool,
};

pub const BlockImporter = struct {
    allocator: Allocator,
    regen: *StateRegen,
    db: *BeaconDB,
    head_tracker: *HeadTracker,

    pub fn init(
        allocator: Allocator,
        regen: *StateRegen,
        db: *BeaconDB,
        head_tracker: *HeadTracker,
    ) BlockImporter {
        return .{
            .allocator = allocator,
            .regen = regen,
            .db = db,
            .head_tracker = head_tracker,
        };
    }

    /// Import a signed beacon block through the full pipeline.
    ///
    /// This is the core of what a beacon node does on every block:
    /// get pre-state → STFN → cache post-state → persist → update head.
    pub fn importBlock(
        self: *BlockImporter,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const block_slot = signed_block.message.slot;
        const parent_root = signed_block.message.parent_root;

        const prev_epoch = computeEpochAtSlot(if (block_slot > 0) block_slot - 1 else 0);
        const target_epoch = computeEpochAtSlot(block_slot);
        const is_epoch_transition = target_epoch != prev_epoch;

        // 1. Get pre-state via StateRegen.
        const pre_state = try self.regen.getPreState(parent_root, block_slot);

        // 2. Clone the pre-state — never mutate cached copies.
        var post_state = try pre_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        // 3. Advance to block slot (may trigger epoch transition).
        try state_transition.processSlots(self.allocator, post_state, block_slot, .{});

        // 4. Apply the block via processBlock.
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

        // 5. Commit tree changes and compute roots.
        try post_state.state.commit();
        const state_root = (try post_state.state.hashTreeRoot()).*;

        // 6. Compute block root.
        var block_root: [32]u8 = undefined;
        const any_block = any_signed.beaconBlock();
        try any_block.hashTreeRoot(self.allocator, &block_root);

        // 7. Cache post-state via StateRegen.
        _ = try self.regen.onNewBlock(post_state, true);

        // 8. Persist block to BeaconDB.
        const block_bytes = try any_signed.serialize(self.allocator);
        defer self.allocator.free(block_bytes);
        try self.db.putBlock(block_root, block_bytes);

        // 9. On epoch boundary: cache checkpoint state.
        if (is_epoch_transition) {
            // Clone the post-state for checkpoint cache (regen owns the other copy).
            const cp_state = try post_state.clone(self.allocator, .{ .transfer_cache = false });
            errdefer {
                cp_state.deinit();
                self.allocator.destroy(cp_state);
            }

            try self.regen.onCheckpoint(
                .{ .epoch = target_epoch, .root = block_root },
                cp_state,
            );
        }

        // 10. Update head tracker.
        try self.head_tracker.onBlock(block_root, block_slot);
        if (is_epoch_transition) {
            try self.head_tracker.onEpochTransition(post_state);
        }

        return .{
            .block_root = block_root,
            .state_root = state_root,
            .slot = block_slot,
            .epoch_transition = is_epoch_transition,
        };
    }
};
