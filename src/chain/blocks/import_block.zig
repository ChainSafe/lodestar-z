//! Final block import stage — writes verified blocks into the chain.
//!
//! After all verification stages pass, this stage performs the side effects:
//! 1. Persist block to DB (hot store)
//! 2. Import into fork choice DAG
//! 3. Process attestations into fork choice
//! 4. Process attester slashings into fork choice
//! 5. Cache post-state in block state cache
//! 6. Cache checkpoint state at epoch boundaries
//! 7. Compute and update head
//! 8. Notify EL via forkchoiceUpdated (if head/finality changed)
//! 9. Publish chain notifications
//! 10. Notify queued regen / reprocess controller
//!
//! Order matters: DB write before fork choice (so blocks in FC always exist
//! in DB), fork choice before head update, head update before notifications.
//!
//! Reference: Lodestar chain/blocks/importBlock.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const HeadResult = fork_choice_mod.HeadResult;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const FcExecutionStatus = fork_choice_mod.ExecutionStatus;
const FcDataAvailabilityStatus = fork_choice_mod.DataAvailabilityStatus;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

const pipeline_types = @import("types.zig");
const VerifiedBlock = pipeline_types.VerifiedBlock;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const ImportResult = pipeline_types.ImportResult;
const ExecutionStatus = pipeline_types.ExecutionStatus;
const BlockImportError = pipeline_types.BlockImportError;

const chain_types = @import("../types.zig");
const NotificationSink = chain_types.NotificationSink;

const block_import = @import("../block_import.zig");
const HeadTracker = block_import.HeadTracker;
const QueuedStateRegen = @import("../queued_regen.zig").QueuedStateRegen;
const reprocess_mod = @import("../reprocess.zig");
const ReprocessQueue = reprocess_mod.ReprocessQueue;
const PendingReason = reprocess_mod.PendingReason;

/// Maximum number of slots in the past for which we publish block notifications.
/// Prevents flooding downstream subscribers during sync.
const EVENTSTREAM_EMIT_RECENT_BLOCK_SLOTS: u64 = 64;

/// Fork choice attestation epoch limit.
/// Attestations from blocks older than current_epoch - 1 are skipped.
const FORK_CHOICE_ATT_EPOCH_LIMIT: u64 = 1;

// ---------------------------------------------------------------------------
// Import context — all the chain state needed for import
// ---------------------------------------------------------------------------

/// Everything needed to import a verified block into the chain.
///
/// The Chain struct passes this context to avoid import_block.zig depending
/// on the full Chain type (breaking circular imports).
pub const ImportContext = struct {
    allocator: Allocator,

    // -- State management --
    block_state_cache: *state_transition.BlockStateCache,
    state_regen: *state_transition.StateRegen,
    queued_regen: ?*QueuedStateRegen,

    // -- Fork choice --
    fork_choice: ?*ForkChoice,

    // -- Persistence --
    db: *BeaconDB,

    // -- Head tracking --
    head_tracker: *HeadTracker,

    // -- Block root → state root mapping --
    block_to_state: *std.AutoArrayHashMap([32]u8, [32]u8),

    // -- Chain notifications --
    notification_sink: ?NotificationSink,

    // -- Reprocessing -- (P1-10 fix)
    /// When set, blocks that fail with ParentUnknown are queued here for
    /// reprocessing once the parent arrives via onBlockImported().
    reprocess_queue: ?*ReprocessQueue = null,

    // -- Finality callback -- (W2 fix)
    /// Called when a new finalized epoch is detected during import.
    /// Prunes block state cache, fork choice DAG, and other caches.
    /// Signature: fn(ptr: *anyopaque, finalized_epoch: u64, finalized_root: [32]u8) void
    on_finalized_ptr: ?*anyopaque = null,
    on_finalized_fn: ?*const fn (ptr: *anyopaque, finalized_epoch: u64, finalized_root: [32]u8) void = null,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Import a fully verified block into the chain state.
///
/// This function produces permanent side-effects:
/// - Block stored in DB
/// - Fork choice DAG updated
/// - Post-state cached
/// - Head potentially updated
/// - chain notifications published
///
/// The block MUST have passed all verification stages before reaching this point.
pub fn importVerifiedBlock(
    ctx: ImportContext,
    verified: VerifiedBlock,
    opts: ImportBlockOpts,
) BlockImportError!ImportResult {
    const block_input = verified.block_input;
    const post_state = verified.post_state;
    const block_root = verified.block_root;
    const state_root = verified.state_root;
    const block_slot = block_input.block.beaconBlock().slot();

    const prev_epoch = computeEpochAtSlot(if (block_slot > 0) block_slot - 1 else 0);
    const block_epoch = computeEpochAtSlot(block_slot);
    const is_epoch_transition = block_epoch != prev_epoch;

    // 1. Persist block to hot DB.
    // Done BEFORE fork choice so blocks in FC always exist in DB.
    // On restart, orphaned blocks in DB are harmlessly pruned.
    const any_signed = block_input.block;
    const block_bytes = any_signed.serialize(ctx.allocator) catch
        return BlockImportError.InternalError;
    defer ctx.allocator.free(block_bytes);
    ctx.db.putBlock(block_root, block_bytes) catch
        return BlockImportError.InternalError;

    // 2. Import block into fork choice DAG.
    if (opts.update_fork_choice) {
        if (ctx.fork_choice) |fc| {
            // Advance fork choice clock to at least the block's slot.
            // This prevents blocks from being rejected as "from the future" when
            // the chain has advanced faster than the fork choice clock (e.g., range sync,
            // test replay, or blocks imported before the first onSlot tick).
            if (block_slot > fc.getTime()) {
                fc.updateTime(ctx.allocator, block_slot) catch |err| switch (err) {
                    error.OutOfMemory => return BlockImportError.InternalError,
                    else => {
                        std.log.warn("FC updateTime failed at slot {d}: {}", .{ block_slot, err });
                    },
                };
            }

            // Map pipeline execution/DA status to fork choice BlockExtraMeta.
            const fc_exec_status: FcExecutionStatus = switch (verified.execution_status) {
                .valid => .valid,
                .syncing => .syncing,
                .pre_merge => .pre_merge,
                .invalid => .invalid,
            };
            const fc_da_status: FcDataAvailabilityStatus = switch (verified.data_availability_status) {
                .not_required, .pre_data => .pre_data,
                .available => .available,
                .out_of_range => .out_of_range,
                .pending => .pre_data,
            };

            // C-boost fix: pass block_delay_sec based on block source.
            // Gossip blocks are "timely" (delay=0 → proposer boost applies).
            // Sync/API/regen blocks use delay=5 (> ATTESTATION_DUE threshold of 4s)
            // so they do NOT receive proposer boost.
            // TODO: replace with actual wall-clock arrival time tracking.
            const block_delay_sec: u32 = switch (block_input.source) {
                .gossip => 0, // timely — proposer boost applies
                else => 5, // late — no proposer boost (threshold is >4s)
            };
            const beacon_block = verified.block_input.block.beaconBlock();
            const fc_block_ok = if (fc.onBlock(
                ctx.allocator,
                &beacon_block,
                post_state,
                block_delay_sec,
                fc.getTime(),
                fc_exec_status,
                fc_da_status,
            )) |_| true else |err| blk: {
                std.log.warn("ForkChoice.onBlock failed for slot {d}: {}", .{ block_slot, err });
                break :blk false;
            };

            // 3a. Wire attestations from the imported block into fork choice.
            // Skip attestation/slashing wiring when onBlockFromState failed — the block
            // is not in the fork choice DAG so votes and slashings cannot reference it.
            if (fc_block_ok) {
                // Only process attestations when block epoch is recent enough:
                // blocks older than current_epoch - FORK_CHOICE_ATT_EPOCH_LIMIT have no
                // effect on fork choice head selection.
                const current_epoch = computeEpochAtSlot(fc.getTime());
                if (block_epoch + FORK_CHOICE_ATT_EPOCH_LIMIT >= current_epoch) {
                    const block_body = block_input.block.beaconBlock().beaconBlockBody();
                    const any_atts = block_body.attestations();
                    switch (any_atts) {
                        .phase0 => |atts| {
                            for (atts.items) |*att| {
                                const att_slot = att.data.slot;
                                const att_target_epoch = att.data.target.epoch;
                                const att_block_root = att.data.beacon_block_root;
                                var indices = post_state.epoch_cache.getAttestingIndicesPhase0(att) catch continue;
                                defer indices.deinit();
                                for (indices.items) |validator_index| {
                                    fc.onSingleVote(
                                        ctx.allocator,
                                        validator_index,
                                        att_slot,
                                        att_block_root,
                                        att_target_epoch,
                                    ) catch |err| switch (err) {
                                        error.OutOfMemory => return BlockImportError.InternalError,
                                        else => {},
                                    };
                                }
                            }
                        },
                        .electra => |atts| {
                            for (atts.items) |*att| {
                                const att_slot = att.data.slot;
                                const att_target_epoch = att.data.target.epoch;
                                const att_block_root = att.data.beacon_block_root;
                                var indices = post_state.epoch_cache.getAttestingIndicesElectra(att) catch continue;
                                defer indices.deinit();
                                for (indices.items) |validator_index| {
                                    fc.onSingleVote(
                                        ctx.allocator,
                                        validator_index,
                                        att_slot,
                                        att_block_root,
                                        att_target_epoch,
                                    ) catch |err| switch (err) {
                                        error.OutOfMemory => return BlockImportError.InternalError,
                                        else => {},
                                    };
                                }
                            }
                        },
                    }
                }

                // 3b. Wire attester slashings into fork choice.
                // Mark equivocating validators so their weight is excluded from future head computation.
                // Delegate to fc.onAttesterSlashing() which encapsulates the sorted-intersection logic.
                const any_slashings = block_input.block.beaconBlock().beaconBlockBody().attesterSlashings();
                switch (any_slashings) {
                    .phase0 => |slashings| {
                        for (slashings.items) |*slashing| {
                            const any_slashing = fork_types.AnyAttesterSlashing{ .phase0 = slashing.* };
                            fc.onAttesterSlashing(ctx.allocator, &any_slashing) catch |err| return switch (err) {
                                error.OutOfMemory => BlockImportError.InternalError,
                            };
                        }
                    },
                    .electra => |slashings| {
                        for (slashings.items) |*slashing| {
                            const any_slashing = fork_types.AnyAttesterSlashing{ .electra = slashing.* };
                            fc.onAttesterSlashing(ctx.allocator, &any_slashing) catch |err| return switch (err) {
                                error.OutOfMemory => BlockImportError.InternalError,
                            };
                        }
                    },
                }
            } // end if (fc_block_ok)
        }
    }

    // 3. Cache post-state via state regen.
    const cached_state_root = if (ctx.queued_regen) |qr|
        qr.onNewBlock(post_state, true) catch return BlockImportError.InternalError
    else
        ctx.state_regen.onNewBlock(post_state, true) catch return BlockImportError.InternalError;
    _ = cached_state_root;

    // Map block root → state root for future pre-state lookups.
    ctx.block_to_state.put(block_root, state_root) catch
        return BlockImportError.InternalError;

    // 4. Cache checkpoint state at epoch boundaries.
    if (is_epoch_transition) {
        const cp_state = post_state.clone(ctx.allocator, .{ .transfer_cache = false }) catch
            return BlockImportError.InternalError;
        errdefer {
            cp_state.deinit();
            ctx.allocator.destroy(cp_state);
        }

        if (ctx.queued_regen) |qr| {
            qr.onCheckpoint(
                .{ .epoch = block_epoch, .root = block_root },
                cp_state,
            ) catch return BlockImportError.InternalError;
        } else {
            ctx.state_regen.onCheckpoint(
                .{ .epoch = block_epoch, .root = block_root },
                cp_state,
            ) catch return BlockImportError.InternalError;
        }
    }

    // 5. Update head tracker.
    ctx.head_tracker.onBlock(block_root, block_slot, state_root) catch
        return BlockImportError.InternalError;
    if (is_epoch_transition) {
        ctx.head_tracker.onEpochTransition(post_state) catch
            return BlockImportError.InternalError;
    }

    // 6. Recompute fork choice head and detect reorgs (if requested).
    head_recompute: {
        if (!opts.update_head) break :head_recompute;
        const fc = ctx.fork_choice orelse break :head_recompute;

        // Save the old head before recomputation.
        const old_head_root = fc.head.block_root;
        const old_head_slot = fc.head.slot;
        const old_head_state_root = fc.head.state_root;

        // Recompute head: computeDeltas → applyScoreChanges → findHead.
        const uagh_result = fc.updateAndGetHead(ctx.allocator, .get_canonical_head) catch |err| {
            std.log.warn("importBlock: getHead failed: {}", .{err});
            break :head_recompute;
        };
        const new_head = HeadResult{
            .block_root = uagh_result.head.block_root,
            .slot = uagh_result.head.slot,
            .state_root = uagh_result.head.state_root,
            .execution_optimistic = false,
        };

        // Check finality changes.
        const new_finalized = fc.getFinalizedCheckpoint();
        if (new_finalized.epoch > ctx.head_tracker.finalized_epoch) {
            if (ctx.notification_sink) |sink| {
                const fin_state_root = ctx.block_to_state.get(new_finalized.root) orelse
                    [_]u8{0} ** 32;
                sink.publish(.{ .finalized_checkpoint = .{
                    .epoch = new_finalized.epoch,
                    .root = new_finalized.root,
                    .state_root = fin_state_root,
                } });
            }
            // Prune caches for the new finalized checkpoint (W2 fix).
            // Without this, block state cache and fork choice DAG grow without bound (OOM).
            if (ctx.on_finalized_fn) |on_fin| {
                if (ctx.on_finalized_ptr) |ptr| {
                    on_fin(ptr, new_finalized.epoch, new_finalized.root);
                }
            }
        }

        // Update HeadTracker from fork choice result (P0-3 fix).
        // Head is ONLY updated here — based on fork choice's authoritative getHead result.
        // HeadTracker.onBlock no longer sets head; it only records slot→root mappings.
        ctx.head_tracker.setHead(new_head.block_root, new_head.slot, new_head.state_root);

        // If head changed, detect reorg and emit head event from detectAndEmitReorg.
        // If head didn't change, emit head event here (block extended canonical chain).
        if (!std.mem.eql(u8, &new_head.block_root, &old_head_root)) {
            detectAndEmitReorg(
                ctx,
                old_head_root,
                old_head_slot,
                old_head_state_root,
                new_head,
                is_epoch_transition,
            );
        } else {
            // Head didn't change (same root) — emit head event for the new canonical tip.
            if (ctx.notification_sink) |sink| {
                sink.publish(.{ .head = .{
                    .slot = new_head.slot,
                    .block_root = new_head.block_root,
                    .state_root = new_head.state_root,
                    .epoch_transition = is_epoch_transition,
                    .execution_optimistic = new_head.execution_optimistic,
                } });
            }
        }
    }

    // 7. Publish block notification (only for recent blocks to avoid flooding during sync).
    // Use block_slot as fallback when fork choice current_slot is 0 (e.g., after genesis init
    // before updateTime is called). This avoids integer overflow in the subtraction.
    //
    // NOTE (P0-4 fix): head notifications are published ONLY from the fork-choice
    // recompute block above (step 6), not here. Previously both places emitted them, causing
    // double-emission on every new block. Now:
    // - 'block' event: emitted here for all recent blocks
    // - 'head' event: emitted from fork choice recompute (detectAndEmitReorg or head-unchanged path)
    const current_slot = blk: {
        if (ctx.fork_choice) |fc| {
            if (fc.getTime() >= block_slot) break :blk fc.getTime();
        }
        break :blk block_slot;
    };
    if (current_slot - block_slot < EVENTSTREAM_EMIT_RECENT_BLOCK_SLOTS) {
        if (ctx.notification_sink) |sink| {
            sink.publish(.{ .block = .{
                .slot = block_slot,
                .block_root = block_root,
            } });
        }
    }

    // 8. Notify reprocess queue (P1-10 fix).
    // Any blocks that were waiting for this block as their parent can now be reprocessed.
    // This handles the common case of out-of-order block delivery on gossip.
    if (ctx.reprocess_queue) |rq| {
        var released = rq.onBlockImported(block_root);
        defer released.deinit(ctx.allocator);
        // Log but don't reprocess inline (avoids deep recursion / stack overflow).
        // Callers should drain the queue asynchronously after import.
        if (released.items.len > 0) {
            std.log.info("importBlock: {d} block(s) queued for reprocessing (parent={s}...)", .{
                released.items.len,
                &std.fmt.bytesToHex(block_root[0..4], .lower),
            });
        }
    }

    return ImportResult{
        .block_root = block_root,
        .state_root = state_root,
        .slot = block_slot,
        .epoch_transition = is_epoch_transition,
        .execution_optimistic = verified.execution_status == .syncing,
    };
}

// ---------------------------------------------------------------------------
// Head recomputation helpers
// ---------------------------------------------------------------------------

/// Detect and publish a chain reorg notification when head switches branches.
///
/// Walks the proto_array to find the common ancestor of old and new head,
/// computes reorg depth, and publishes a `chain_reorg` notification.
fn detectAndEmitReorg(
    ctx: ImportContext,
    old_head_root: [32]u8,
    old_head_slot: u64,
    old_head_state_root: [32]u8,
    new_head: HeadResult,
    is_epoch_transition: bool,
) void {
    const fc = ctx.fork_choice orelse return;

    std.log.info("head changed: old={s}... new={s}...", .{
        &std.fmt.bytesToHex(old_head_root[0..4], .lower),
        &std.fmt.bytesToHex(new_head.block_root[0..4], .lower),
    });

    // Find old and new head nodes in proto_array.
    const old_node = fc.proto_array.getNode(old_head_root, .full) orelse
        fc.proto_array.getNode(old_head_root, .pending);
    const new_node = fc.proto_array.getNode(new_head.block_root, .full) orelse
        fc.proto_array.getNode(new_head.block_root, .pending);

    if (old_node != null and new_node != null) {
        const ancestor = fc.proto_array.getCommonAncestor(old_node.?, new_node.?);
        if (ancestor) |anc| {
            const reorg_depth = if (old_head_slot > anc.slot) old_head_slot - anc.slot else 0;

            if (reorg_depth > 0) {
                std.log.warn("chain reorg detected depth={d} old={s}... new={s}...", .{
                    reorg_depth,
                    &std.fmt.bytesToHex(old_head_root[0..4], .lower),
                    &std.fmt.bytesToHex(new_head.block_root[0..4], .lower),
                });

                if (ctx.notification_sink) |sink| {
                    sink.publish(.{ .chain_reorg = .{
                        .slot = new_head.slot,
                        .depth = reorg_depth,
                        .old_head_root = old_head_root,
                        .new_head_root = new_head.block_root,
                        .old_state_root = old_head_state_root,
                        .new_state_root = new_head.state_root,
                        .epoch = computeEpochAtSlot(new_head.slot),
                    } });
                }
                return;
            }
        }
    }

    // No reorg (or ancestor not found) — emit head event.
    if (ctx.notification_sink) |sink| {
        sink.publish(.{ .head = .{
            .slot = new_head.slot,
            .block_root = new_head.block_root,
            .state_root = new_head.state_root,
            .epoch_transition = is_epoch_transition,
            .execution_optimistic = new_head.execution_optimistic,
        } });
    }
}

/// Compute the dependent root for a given epoch.
///
/// Returns the block root at the slot just before the start of `epoch`.
/// Used for validator duty computation — when this root changes, duties
/// for `epoch` must be recomputed.
///
/// Reference: Lodestar chain/reorg.ts getDependentRoot()
pub fn getDependentRoot(
    ctx: ImportContext,
    epoch: u64,
) ?[32]u8 {
    const fc = ctx.fork_choice orelse return null;
    if (epoch == 0) return null;

    // dependent slot = computeStartSlotAtEpoch(epoch) - 1
    const epoch_start = computeStartSlotAtEpoch(epoch);
    if (epoch_start == 0) return null;
    const dependent_slot = epoch_start - 1;

    // Find ancestor of current head at dependent_slot.
    const head_root = fc.head.block_root;
    const ancestor = fc.getAncestor(head_root, dependent_slot) catch return null;
    return ancestor.block_root;
}

/// Compute previous and current duty dependent roots for head notifications.
///
/// Returns a struct with:
/// - previous_duty_dependent_root: root at start of (epoch-1) - 1
/// - current_duty_dependent_root: root at start of epoch - 1
///
/// Returns null roots when not computable (genesis, missing nodes).
pub fn getDutyDependentRoots(
    ctx: ImportContext,
    slot: u64,
) struct { previous: [32]u8, current: [32]u8 } {
    const epoch = computeEpochAtSlot(slot);
    const zero = [_]u8{0} ** 32;
    return .{
        .previous = if (epoch > 0) getDependentRoot(ctx, epoch - 1) orelse zero else zero,
        .current = getDependentRoot(ctx, epoch) orelse zero,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ImportContext struct compiles" {
    // Type-check only — no runtime test possible without full chain setup.
    _ = ImportContext;
}

test "EVENTSTREAM_EMIT_RECENT_BLOCK_SLOTS constant" {
    try std.testing.expectEqual(@as(u64, 64), EVENTSTREAM_EMIT_RECENT_BLOCK_SLOTS);
}

test "FORK_CHOICE_ATT_EPOCH_LIMIT constant" {
    try std.testing.expectEqual(@as(u64, 1), FORK_CHOICE_ATT_EPOCH_LIMIT);
}

test "getDependentRoot and getDutyDependentRoots: compile-check exported signatures" {
    // Type-level check only — full test requires a live proto_array.
    // Verifies that the function signatures are stable and exported.
    const info = @typeInfo(@TypeOf(getDependentRoot));
    _ = info;
    const info2 = @typeInfo(@TypeOf(getDutyDependentRoots));
    _ = info2;
}
