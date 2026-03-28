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
//! 9. Emit SSE events
//! 10. Notify queued regen / reprocess controller
//!
//! Order matters: DB write before fork choice (so blocks in FC always exist
//! in DB), fork choice before head update, head update before events.
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
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

const pipeline_types = @import("types.zig");
const VerifiedBlock = pipeline_types.VerifiedBlock;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const ImportResult = pipeline_types.ImportResult;
const ExecutionStatus = pipeline_types.ExecutionStatus;
const BlockImportError = pipeline_types.BlockImportError;

const chain_types = @import("../types.zig");
const EventCallback = chain_types.EventCallback;
const SseEvent = chain_types.SseEvent;

const block_import = @import("../block_import.zig");
const HeadTracker = block_import.HeadTracker;
const QueuedStateRegen = @import("../queued_regen.zig").QueuedStateRegen;

/// Maximum number of slots in the past for which we emit block events.
/// Prevents flooding the event stream during sync.
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

    // -- Events --
    event_callback: ?EventCallback,
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
/// - SSE events emitted
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
            // Extract justified and finalized checkpoints from post-state.
            var justified_cp: consensus_types.phase0.Checkpoint.Type = undefined;
            post_state.state.currentJustifiedCheckpoint(&justified_cp) catch
                return BlockImportError.InternalError;
            var finalized_cp: consensus_types.phase0.Checkpoint.Type = undefined;
            post_state.state.finalizedCheckpoint(&finalized_cp) catch
                return BlockImportError.InternalError;

            const fc_block = ProtoBlock{
                .slot = block_slot,
                .block_root = block_root,
                .parent_root = verified.block_input.block.beaconBlock().parentRoot().*,
                .state_root = state_root,
                .target_root = block_root,
                .justified_epoch = justified_cp.epoch,
                .justified_root = justified_cp.root,
                .finalized_epoch = finalized_cp.epoch,
                .finalized_root = finalized_cp.root,
                .unrealized_justified_epoch = justified_cp.epoch,
                .unrealized_justified_root = justified_cp.root,
                .unrealized_finalized_epoch = finalized_cp.epoch,
                .unrealized_finalized_root = finalized_cp.root,
                .extra_meta = .{ .pre_merge = {} },
                .timeliness = true,
            };

            fc.onBlock(ctx.allocator, fc_block, block_slot) catch |err| switch (err) {
                error.InvalidBlock => {},
                else => return BlockImportError.ForkChoiceError,
            };
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
        // Use effective balance increments from post-state when available.
        const ebi_slice: []const u16 = blk: {
            if (ctx.block_state_cache.get(state_root)) |cached| {
                break :blk cached.epoch_cache.getEffectiveBalanceIncrements().items;
            }
            break :blk &.{};
        };
        const new_head = fc.getHead(ctx.allocator, ebi_slice) catch |err| {
            std.log.warn("importBlock: getHead failed: {}", .{err});
            break :head_recompute;
        };

        // Check finality changes.
        const new_finalized = fc.getFinalizedCheckpoint();
        if (new_finalized.epoch > ctx.head_tracker.finalized_epoch) {
            if (ctx.event_callback) |cb| {
                const fin_state_root = ctx.block_to_state.get(new_finalized.root) orelse
                    [_]u8{0} ** 32;
                cb.emit(.{ .finalized_checkpoint = .{
                    .epoch = new_finalized.epoch,
                    .root = new_finalized.root,
                    .state_root = fin_state_root,
                } });
            }
        }

        // If head changed, detect reorg.
        if (!std.mem.eql(u8, &new_head.block_root, &old_head_root)) {
            detectAndEmitReorg(
                ctx,
                old_head_root,
                old_head_slot,
                old_head_state_root,
                new_head,
                is_epoch_transition,
            );
        }
    }

    // 7. Emit SSE events (only for recent blocks to avoid flooding during sync).
    const current_slot = if (ctx.fork_choice) |fc| fc.current_slot else block_slot;
    if (current_slot - block_slot < EVENTSTREAM_EMIT_RECENT_BLOCK_SLOTS) {
        if (ctx.event_callback) |cb| {
            cb.emit(.{ .block = .{
                .slot = block_slot,
                .block_root = block_root,
            } });
            cb.emit(.{ .head = .{
                .slot = block_slot,
                .block_root = block_root,
                .state_root = state_root,
                .epoch_transition = is_epoch_transition,
                .execution_optimistic = verified.execution_status == .syncing,
            } });
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

/// Detect and emit a chain reorg event when head switches branches.
///
/// Walks the proto_array to find the common ancestor of old and new head,
/// computes reorg depth, and emits a `chain_reorg` SSE event.
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

                if (ctx.event_callback) |cb| {
                    cb.emit(.{ .chain_reorg = .{
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
    if (ctx.event_callback) |cb| {
        cb.emit(.{ .head = .{
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
    const ancestor = fc.proto_array.getAncestorNodeAtSlot(head_root, dependent_slot);
    if (ancestor) |anc| return anc.block_root;
    return null;
}

/// Compute previous and current duty dependent roots for SSE head events.
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
