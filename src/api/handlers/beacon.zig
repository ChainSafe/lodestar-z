//! Beacon API handlers.
//!
//! Pure functions implementing the `/eth/v1/beacon/*` and `/eth/v2/beacon/*`
//! endpoints. These require chain state access through the ApiContext.

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const CachedBeaconState = context.CachedBeaconState;
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyExecutionPayload = fork_types.AnyExecutionPayload;
const AnyExecutionPayloadHeader = fork_types.AnyExecutionPayloadHeader;
const BlockType = fork_types.BlockType;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;
const consensus_types = @import("consensus_types");

/// GET /eth/v1/beacon/genesis
///
/// Returns genesis time, genesis validators root, and genesis fork version.
pub fn getGenesis(ctx: *ApiContext) HandlerResult(types.GenesisData) {
    const cfg = ctx.beacon_config;
    // Use actual genesis time (set from genesis/checkpoint state) if available;
    // fall back to config minimum for compatibility when genesis_time is not yet set.
    const genesis_time = if (ctx.genesis_time != 0) ctx.genesis_time else cfg.chain.MIN_GENESIS_TIME;
    return .{
        .data = .{
            .genesis_time = genesis_time,
            .genesis_validators_root = cfg.genesis_validator_root,
            .genesis_fork_version = cfg.chain.GENESIS_FORK_VERSION,
        },
        .meta = .{ .finalized = true },
    };
}

/// GET /eth/v1/beacon/headers/{block_id}
///
/// Returns the block header for the given block identifier.
pub fn getBlockHeader(ctx: *ApiContext, block_id: types.BlockId) !HandlerResult(types.BlockHeaderData) {
    const result = try resolveBlockHeader(ctx, block_id);
    return .{
        .data = result.header,
        .meta = .{
            .execution_optimistic = result.execution_optimistic,
            .finalized = result.finalized,
        },
    };
}

/// GET /eth/v2/beacon/blocks/{block_id}
///
/// Returns the full signed beacon block for the given block identifier.
/// The response is fork-versioned; callers should check the `version` field.
///
/// Note: Returns raw SSZ bytes from the DB. The HTTP layer is responsible
/// for content negotiation (JSON vs SSZ encoding).
pub fn getBlock(ctx: *ApiContext, block_id: types.BlockId) !BlockResult {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);

    const block_bytes = (try ctx.blockBytesByRoot(slot_info.root)) orelse
        return error.BlockNotFound;

    // Determine fork from slot for version metadata
    const fork_name = forkNameFromSlot(ctx, slot_info.slot);

    return .{
        .data = block_bytes,
        .slot = slot_info.slot,
        .execution_optimistic = slot_info.execution_optimistic,
        .finalized = slot_info.finalized,
        .fork_name = fork_name,
    };
}

pub const BlockResult = struct {
    /// Raw SSZ bytes of the signed beacon block.
    data: []const u8,
    slot: u64,
    execution_optimistic: bool,
    finalized: bool,
    fork_name: handler_result.Fork = .phase0,
    block_type: BlockType = .full,
};

pub const BlobSidecarsResult = struct {
    data: []const u8,
    slot: u64,
    execution_optimistic: bool,
    finalized: bool,
    fork_name: handler_result.Fork = .deneb,
};

/// Determine the fork name for a given slot using the beacon config.
fn forkNameFromSlot(ctx: *ApiContext, slot: u64) handler_result.Fork {
    const fork_seq = ctx.beacon_config.forkSeq(slot);
    return switch (fork_seq) {
        .phase0 => .phase0,
        .altair => .altair,
        .bellatrix => .bellatrix,
        .capella => .capella,
        .deneb => .deneb,
        .electra => .electra,
        .fulu => .fulu,
        .gloas => .gloas,
    };
}

/// GET /eth/v2/beacon/states/{state_id}/validators
///
/// Returns the list of validators for the given state.
/// Supports optional filtering by validator IDs and statuses.
///
/// Resolves states through the chain-backed API state query boundary.
/// Head comes from the live head-state path; historical lookups go through
/// chain-owned state lookup/regeneration.
pub fn getValidators(
    ctx: *ApiContext,
    state_id: types.StateId,
    _: types.ValidatorQuery,
) !HandlerResult([]const types.ValidatorData) {
    const resolved = try resolveState(ctx, state_id);
    return buildValidatorResponse(ctx, resolved.state, resolved.meta);
}

/// Build a validator response from a CachedBeaconState.
fn buildValidatorResponse(
    ctx: *ApiContext,
    state: *CachedBeaconState,
    meta: ResolvedStateMeta,
) !HandlerResult([]const types.ValidatorData) {
    // Read validators and balances from the state
    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);
    const balances = try state.state.balancesSlice(ctx.allocator);
    defer ctx.allocator.free(balances);

    const epoch = (try state.state.slot()) / preset.SLOTS_PER_EPOCH;

    var result = std.ArrayListUnmanaged(types.ValidatorData).empty;
    errdefer result.deinit(ctx.allocator);

    for (validators, 0..) |v, i| {
        const balance = if (i < balances.len) balances[i] else 0;
        try result.append(ctx.allocator, .{
            .index = @intCast(i),
            .balance = balance,
            .status = types.ValidatorStatus.fromValidator(&v, epoch),
            .validator = .{
                .pubkey = v.pubkey,
                .withdrawal_credentials = v.withdrawal_credentials,
                .effective_balance = v.effective_balance,
                .slashed = v.slashed,
                .activation_eligibility_epoch = v.activation_eligibility_epoch,
                .activation_epoch = v.activation_epoch,
                .exit_epoch = v.exit_epoch,
                .withdrawable_epoch = v.withdrawable_epoch,
            },
        });
    }

    return .{
        .data = try result.toOwnedSlice(ctx.allocator),
        .meta = .{
            .execution_optimistic = meta.execution_optimistic,
            .finalized = meta.finalized,
        },
    };
}

/// GET /eth/v2/beacon/states/{state_id}/validators/{validator_id}
///
/// Returns a single validator from the given state.
pub fn getValidator(
    ctx: *ApiContext,
    state_id: types.StateId,
    validator_id: types.ValidatorId,
) !HandlerResult(types.ValidatorData) {
    const resolved = try resolveState(ctx, state_id);
    const state = resolved.state;

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);
    const balances = try state.state.balancesSlice(ctx.allocator);
    defer ctx.allocator.free(balances);

    const epoch = (try state.state.slot()) / preset.SLOTS_PER_EPOCH;

    // Resolve validator index from id
    const index: u64 = switch (validator_id) {
        .index => |idx| idx,
        .pubkey => |pk| blk: {
            for (validators, 0..) |v, i| {
                if (std.mem.eql(u8, &v.pubkey, &pk)) break :blk @intCast(i);
            }
            return error.ValidatorNotFound;
        },
    };

    if (index >= validators.len) return error.ValidatorNotFound;

    const v = validators[index];
    const balance = if (index < balances.len) balances[index] else 0;

    return .{
        .data = .{
            .index = index,
            .balance = balance,
            .status = types.ValidatorStatus.fromValidator(&v, epoch),
            .validator = .{
                .pubkey = v.pubkey,
                .withdrawal_credentials = v.withdrawal_credentials,
                .effective_balance = v.effective_balance,
                .slashed = v.slashed,
                .activation_eligibility_epoch = v.activation_eligibility_epoch,
                .activation_epoch = v.activation_epoch,
                .exit_epoch = v.exit_epoch,
                .withdrawable_epoch = v.withdrawable_epoch,
            },
        },
        .meta = .{
            .execution_optimistic = resolved.meta.execution_optimistic,
            .finalized = resolved.meta.finalized,
        },
    };
}

/// GET /eth/v1/beacon/states/{state_id}/root
///
/// Returns the state root for the given state identifier.
pub fn getStateRoot(ctx: *ApiContext, state_id: types.StateId) !HandlerResult([32]u8) {
    const head = ctx.currentHeadTracker();
    switch (state_id) {
        .head => {
            return .{
                .data = head.head_state_root,
                .meta = .{
                    .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
                    .finalized = std.mem.eql(u8, &head.head_root, &head.finalized_root),
                },
            };
        },
        .finalized => {
            const finalized_state_root = (try ctx.stateRootByBlockRoot(head.finalized_root)) orelse
                return error.StateNotAvailable;
            return .{
                .data = finalized_state_root,
                .meta = .{ .finalized = true },
            };
        },
        .genesis => {
            const genesis_state_root = (try ctx.stateRootBySlot(0)) orelse
                return error.StateNotAvailable;
            return .{
                .data = genesis_state_root,
                .meta = .{ .finalized = true },
            };
        },
        .justified => {
            const justified_state_root = (try ctx.stateRootByBlockRoot(head.justified_root)) orelse
                return error.StateNotAvailable;
            return .{
                .data = justified_state_root,
                .meta = .{
                    .execution_optimistic = ctx.blockExecutionOptimistic(head.justified_root),
                    .finalized = std.mem.eql(u8, &head.justified_root, &head.finalized_root),
                },
            };
        },
        .slot => |slot| {
            const state_root_opt = try ctx.stateRootBySlot(slot);
            if (state_root_opt == null) {
                if ((try ctx.blockRootBySlot(slot)) == null and (try ctx.stateArchiveAtSlot(slot)) == null) {
                    return error.SlotNotFound;
                }
                return error.StateNotAvailable;
            }
            const state_root = state_root_opt.?;
            return .{
                .data = state_root,
                .meta = .{
                    .execution_optimistic = try ctx.stateExecutionOptimisticBySlot(slot),
                    .finalized = slot <= head.finalized_slot,
                },
            };
        },
        .root => |root| {
            const meta = try resolveStateMetaByRoot(ctx, root);
            return .{
                .data = root,
                .meta = .{
                    .execution_optimistic = meta.execution_optimistic,
                    .finalized = meta.finalized,
                },
            };
        },
    }
}

/// GET /eth/v1/beacon/states/{state_id}/fork
///
/// Returns the fork data for the given state.
pub fn getStateFork(ctx: *ApiContext, state_id: types.StateId) !HandlerResult(types.ForkData) {
    const resolved = try resolveState(ctx, state_id);
    const slot = try resolved.state.state.slot();

    // Walk the config's fork schedule to find the active fork at this slot
    const cfg = ctx.beacon_config;
    const epoch = slot / preset.SLOTS_PER_EPOCH;

    var result = types.ForkData{
        .previous_version = cfg.chain.GENESIS_FORK_VERSION,
        .current_version = cfg.chain.GENESIS_FORK_VERSION,
        .epoch = 0,
    };

    // Walk ascending fork schedule
    for (cfg.forks_ascending_epoch_order) |fork_info| {
        if (fork_info.epoch <= epoch) {
            result = .{
                .previous_version = fork_info.prev_version,
                .current_version = fork_info.version,
                .epoch = fork_info.epoch,
            };
        } else {
            break;
        }
    }

    return .{
        .data = result,
        .meta = .{
            .execution_optimistic = resolved.meta.execution_optimistic,
            .finalized = resolved.meta.finalized,
        },
    };
}

/// GET /eth/v1/beacon/states/{state_id}/finality_checkpoints
///
/// Returns the finality checkpoints (previous justified, current justified, finalized).
///
/// Loads the beacon state for the given state_id via resolveState, then reads
/// the previous_justified, current_justified, and finalized checkpoints directly
/// from the state. Falls back to head tracker data when state is not available.
pub fn getFinalityCheckpoints(ctx: *ApiContext, state_id: types.StateId) !HandlerResult(types.FinalityCheckpoints) {
    const head = ctx.currentHeadTracker();
    const resolved = resolveState(ctx, state_id) catch |err| switch (state_id) {
        .head => {
            return .{
                .data = .{
                    .previous_justified = .{
                        .epoch = head.justified_slot / preset.SLOTS_PER_EPOCH,
                        .root = head.justified_root,
                    },
                    .current_justified = .{
                        .epoch = head.justified_slot / preset.SLOTS_PER_EPOCH,
                        .root = head.justified_root,
                    },
                    .finalized = .{
                        .epoch = head.finalized_slot / preset.SLOTS_PER_EPOCH,
                        .root = head.finalized_root,
                    },
                },
                .meta = .{
                    .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
                    .finalized = std.mem.eql(u8, &head.head_root, &head.finalized_root),
                },
            };
        },
        else => return err,
    };
    const state = resolved.state;

    var prev_justified: consensus_types.phase0.Checkpoint.Type = undefined;
    try state.state.previousJustifiedCheckpoint(&prev_justified);

    var curr_justified: consensus_types.phase0.Checkpoint.Type = undefined;
    try state.state.currentJustifiedCheckpoint(&curr_justified);

    var finalized: consensus_types.phase0.Checkpoint.Type = undefined;
    try state.state.finalizedCheckpoint(&finalized);

    return .{
        .data = .{
            .previous_justified = .{
                .epoch = prev_justified.epoch,
                .root = prev_justified.root,
            },
            .current_justified = .{
                .epoch = curr_justified.epoch,
                .root = curr_justified.root,
            },
            .finalized = .{
                .epoch = finalized.epoch,
                .root = finalized.root,
            },
        },
        .meta = .{
            .execution_optimistic = resolved.meta.execution_optimistic,
            .finalized = resolved.meta.finalized,
        },
    };
}

/// POST /eth/v2/beacon/blocks
///
/// Submit a signed beacon block for propagation and import.
///
/// Accepts raw SSZ bytes of a SignedBeaconBlock and forwards them to
/// the block import pipeline registered on the ApiContext. Returns
/// `202 Accepted` when the live ingress path queues or drops the block
/// without immediate import, and `error.NotImplemented` if no import
/// callback is wired.
pub fn submitBlock(
    ctx: *ApiContext,
    block_bytes: []const u8,
    block_type: BlockType,
    broadcast_validation: types.BroadcastValidation,
) !HandlerResult(void) {
    const cb = ctx.block_import orelse return error.NotImplemented;
    const import_result = try cb.importFn(cb.ptr, .{
        .block_bytes = block_bytes,
        .block_type = block_type,
        .broadcast_validation = broadcast_validation,
    });
    return .{
        .data = {},
        .status = switch (import_result) {
            .imported => 0,
            .queued, .ignored => 202,
        },
    };
}

pub fn submitBlindedBlock(
    ctx: *ApiContext,
    block_bytes: []const u8,
    broadcast_validation: types.BroadcastValidation,
) !HandlerResult(void) {
    return submitBlock(ctx, block_bytes, .blinded, broadcast_validation);
}

/// POST /eth/v1/beacon/pool/attestations
/// POST /eth/v1/beacon/pool/voluntary_exits
/// POST /eth/v1/beacon/pool/proposer_slashings
/// POST /eth/v1/beacon/pool/attester_slashings
/// POST /eth/v1/beacon/pool/bls_to_execution_changes
/// POST /eth/v1/beacon/pool/sync_committees
///
/// All pool submission endpoints follow the same pattern: accept an encoded
/// object, import it through the node callback surface, and return 200 on
/// success. A non-empty request without a wired pool-submit callback is a
/// misconfigured node and returns `error.NotImplemented`.
/// POST /eth/v1/beacon/pool/attestations
///
/// Submit attestations to the local op pool.
/// body is JSON: array of Attestation objects.
/// Validates and forwards to the pool_submit callback if available.
pub fn submitPoolAttestations(ctx: *ApiContext, attestations: []const consensus_types.phase0.Attestation.Type) !HandlerResult(void) {
    if (attestations.len == 0) return .{ .data = {} };
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitAttestationFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, .{ .phase0 = attestations });
    return .{ .data = {} };
}

/// POST /eth/v2/beacon/pool/attestations
///
/// Submit attestations to the pool via the v2 endpoint.
/// For Electra slots, expects SingleAttestation[] format:
///   {committee_index, attester_index, data, signature}
/// For pre-Electra slots, falls back to phase0 Attestation[] format.
pub fn submitPoolAttestationsV2(ctx: *ApiContext, attestations: context.SubmittedAttestations) !HandlerResult(void) {
    const is_empty = switch (attestations) {
        .phase0 => |items| items.len == 0,
        .electra_single => |items| items.len == 0,
    };
    if (is_empty) return .{ .data = {} };
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitAttestationFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, attestations);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/voluntary_exits
///
/// Submit a signed voluntary exit to the local op pool.
pub fn submitPoolVoluntaryExits(ctx: *ApiContext, exit: consensus_types.phase0.SignedVoluntaryExit.Type) !HandlerResult(void) {
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitVoluntaryExitFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, exit);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/proposer_slashings
///
/// Submit a proposer slashing to the local op pool.
pub fn submitPoolProposerSlashings(ctx: *ApiContext, slashing: consensus_types.phase0.ProposerSlashing.Type) !HandlerResult(void) {
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitProposerSlashingFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, slashing);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/attester_slashings
///
/// Submit an attester slashing to the local op pool.
pub fn submitPoolAttesterSlashings(ctx: *ApiContext, slashing: context.SubmittedAttesterSlashing) !HandlerResult(void) {
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitAttesterSlashingFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, slashing);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/bls_to_execution_changes
///
/// Submit BLS-to-execution changes to the local op pool.
pub fn submitPoolBlsToExecutionChanges(ctx: *ApiContext, changes: []const consensus_types.capella.SignedBLSToExecutionChange.Type) !HandlerResult(void) {
    if (changes.len == 0) return .{ .data = {} };
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitBlsChangeFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, changes);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/sync_committees
///
/// Submit sync committee messages to the local pool.
pub fn submitPoolSyncCommittees(ctx: *ApiContext, messages: []const consensus_types.altair.SyncCommitteeMessage.Type) !HandlerResult(void) {
    if (messages.len == 0) return .{ .data = {} };
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitSyncCommitteeMessageFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, messages);
    return .{ .data = {} };
}

// ---------------------------------------------------------------------------
// Pool endpoints
// ---------------------------------------------------------------------------

const OpPoolCallback = context.OpPoolCallback;

/// GET /eth/v1/beacon/pool/attestations
///
/// Returns pending attestations from the operation pool.
/// Supports optional `slot` and `committee_index` query parameter filters.
///
/// This endpoint is pre-Electra only. Post-Electra callers must use the v2
/// endpoint, which can only become fully correct once the pool preserves full
/// Electra attestation shape.
pub fn getPoolAttestations(
    ctx: *ApiContext,
    slot_filter: ?u64,
    committee_index_filter: ?u64,
) !HandlerResult([]const OpPoolCallback.Phase0Attestation) {
    const query_slot = slot_filter orelse ctx.currentHeadTracker().head_slot;
    if (ctx.beacon_config.forkSeq(query_slot).gte(.electra)) return error.InvalidRequest;

    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getAttestationsFn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator, slot_filter, committee_index_filter);
    return .{ .data = items };
}

/// GET /eth/v2/beacon/pool/attestations
///
/// Returns pending attestations from the operation pool in fork-versioned format.
/// Supports optional `slot` and `committee_index` query parameter filters.
pub fn getPoolAttestationsV2(
    ctx: *ApiContext,
    slot_filter: ?u64,
    committee_index_filter: ?u64,
) !HandlerResult([]const OpPoolCallback.AnyAttestation) {
    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getAttestationsV2Fn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator, slot_filter, committee_index_filter);
    return .{ .data = items };
}

/// GET /eth/v1/beacon/pool/voluntary_exits
///
/// Returns pending signed voluntary exits from the operation pool.
pub fn getPoolVoluntaryExits(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.SignedVoluntaryExit) {
    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getVoluntaryExitsFn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

/// GET /eth/v1/beacon/pool/proposer_slashings
///
/// Returns pending proposer slashings from the operation pool.
pub fn getPoolProposerSlashings(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.ProposerSlashing) {
    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getProposerSlashingsFn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

/// GET /eth/v1/beacon/pool/attester_slashings
///
/// Returns pending attester slashings from the operation pool.
/// Post-Electra callers must use the v2 endpoint.
pub fn getPoolAttesterSlashings(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.AnyAttesterSlashing) {
    const head_slot = ctx.currentHeadTracker().head_slot;
    if (ctx.beacon_config.forkSeq(head_slot).gte(.electra)) return error.InvalidRequest;

    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getAttesterSlashingsFn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

/// GET /eth/v2/beacon/pool/attester_slashings
///
/// Returns pending attester slashings from the operation pool in fork-aware format.
pub fn getPoolAttesterSlashingsV2(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.AnyAttesterSlashing) {
    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getAttesterSlashingsFn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator);
    const slot = ctx.currentHeadTracker().head_slot;
    return .{
        .data = items,
        .meta = .{ .version = forkNameFromSlot(ctx, slot) },
    };
}

/// GET /eth/v1/beacon/pool/bls_to_execution_changes
///
/// Returns pending signed BLS-to-execution changes from the operation pool.
pub fn getPoolBlsToExecutionChanges(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.SignedBLSToExecutionChange) {
    const cb = ctx.op_pool orelse return error.NotImplemented;
    const get_fn = cb.getBlsToExecutionChangesFn orelse return error.NotImplemented;
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

fn getPoolCountsFromCtx(ctx: *ApiContext) [5]usize {
    const cb = ctx.op_pool orelse return [5]usize{ 0, 0, 0, 0, 0 };
    return cb.getPoolCountsFn(cb.ptr);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const SlotAndRoot = struct {
    slot: u64,
    root: [32]u8,
    execution_optimistic: bool,
    finalized: bool,
    canonical: bool,
};

fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
    if (block_bytes.len < 108) return null;
    return std.mem.readInt(u64, block_bytes[100..108], .little);
}

fn readStateSlotFromSsz(state_bytes: []const u8) ?u64 {
    if (state_bytes.len < 48) return null;
    return std.mem.readInt(u64, state_bytes[40..48], .little);
}

fn resolveBlockSlotAndRoot(ctx: *ApiContext, block_id: types.BlockId) !SlotAndRoot {
    const head = ctx.currentHeadTracker();
    switch (block_id) {
        .head => return .{
            .slot = head.head_slot,
            .root = head.head_root,
            .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
            .finalized = std.mem.eql(u8, &head.head_root, &head.finalized_root),
            .canonical = true,
        },
        .finalized => return .{
            .slot = head.finalized_slot,
            .root = head.finalized_root,
            .execution_optimistic = false,
            .finalized = true,
            .canonical = true,
        },
        .justified => return .{
            .slot = head.justified_slot,
            .root = head.justified_root,
            .execution_optimistic = ctx.blockExecutionOptimistic(head.justified_root),
            .finalized = std.mem.eql(u8, &head.justified_root, &head.finalized_root),
            .canonical = true,
        },
        .genesis => {
            const root = (try ctx.blockRootBySlot(0)) orelse return error.BlockNotFound;
            return .{
                .slot = 0,
                .root = root,
                .execution_optimistic = false,
                .finalized = true,
                .canonical = true,
            };
        },
        .slot => |slot| {
            const root = (try ctx.blockRootBySlot(slot)) orelse return error.SlotNotFound;
            return .{
                .slot = slot,
                .root = root,
                .execution_optimistic = try ctx.blockExecutionOptimisticAtSlot(slot),
                .finalized = slot <= head.finalized_slot,
                .canonical = true,
            };
        },
        .root => |root| {
            // We have the root; look up the block to get the real slot.
            const block_bytes = (try ctx.blockBytesByRoot(root)) orelse return error.BlockNotFound;
            defer ctx.allocator.free(block_bytes);

            const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return error.BlockNotFound;
            const canonical_root = try ctx.blockRootBySlot(slot);
            const canonical = if (canonical_root) |canonical_block_root|
                std.mem.eql(u8, &canonical_block_root, &root)
            else
                false;
            return .{
                .slot = slot,
                .root = root,
                .execution_optimistic = ctx.blockExecutionOptimistic(root),
                .finalized = canonical and slot <= head.finalized_slot,
                .canonical = canonical,
            };
        },
    }
}

const BlockHeaderResult = struct {
    header: types.BlockHeaderData,
    execution_optimistic: bool,
    finalized: bool,
};

const BlockHeaderListMeta = struct {
    saw_any: bool = false,
    execution_optimistic: bool = false,
    finalized: bool = true,

    fn observe(self: *BlockHeaderListMeta, result: BlockHeaderResult) void {
        self.saw_any = true;
        self.execution_optimistic = self.execution_optimistic or result.execution_optimistic;
        self.finalized = self.finalized and result.finalized;
    }
};

fn resolveBlockHeader(ctx: *ApiContext, block_id: types.BlockId) !BlockHeaderResult {
    return resolveBlockHeaderFromSlotInfo(ctx, try resolveBlockSlotAndRoot(ctx, block_id));
}

fn resolveBlockHeaderFromSlotInfo(ctx: *ApiContext, slot_info: SlotAndRoot) !BlockHeaderResult {
    // Try to load and deserialize the block to get real header fields.
    const block_bytes_opt = try ctx.blockBytesByRoot(slot_info.root);

    if (block_bytes_opt) |block_bytes| {
        defer ctx.allocator.free(block_bytes);

        const fork_seq = ctx.beacon_config.forkSeq(slot_info.slot);
        const any_signed = try AnySignedBeaconBlock.deserialize(ctx.allocator, .full, fork_seq, block_bytes);
        defer any_signed.deinit(ctx.allocator);

        const block = any_signed.beaconBlock();

        // Compute body_root via hash_tree_root of the body
        var body_root: [32]u8 = [_]u8{0} ** 32;
        try block.beaconBlockBody().hashTreeRoot(ctx.allocator, &body_root);

        const sig = any_signed.signature();

        return .{
            .header = .{
                .root = slot_info.root,
                .canonical = slot_info.canonical,
                .header = .{
                    .message = .{
                        .slot = block.slot(),
                        .proposer_index = block.proposerIndex(),
                        .parent_root = block.parentRoot().*,
                        .state_root = block.stateRoot().*,
                        .body_root = body_root,
                    },
                    .signature = sig.*,
                },
            },
            .execution_optimistic = slot_info.execution_optimistic,
            .finalized = slot_info.finalized,
        };
    }

    return error.BlockNotFound;
}

fn appendBlockHeaderMatch(
    ctx: *ApiContext,
    headers: *std.ArrayListUnmanaged(types.BlockHeaderData),
    seen_roots: *std.AutoHashMap([32]u8, void),
    meta: *BlockHeaderListMeta,
    slot_info: SlotAndRoot,
    parent_root_opt: ?[32]u8,
) !void {
    if (seen_roots.contains(slot_info.root)) return;

    const result = try resolveBlockHeaderFromSlotInfo(ctx, slot_info);
    if (parent_root_opt) |parent_root| {
        if (!std.mem.eql(u8, &result.header.header.message.parent_root, &parent_root)) return;
    }

    try seen_roots.put(slot_info.root, {});
    try headers.append(ctx.allocator, result.header);
    meta.observe(result);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

const PoolSubmitProbe = struct {
    phase0_attestation_len: usize = 0,
    electra_attestation_len: usize = 0,

    fn submitAttestation(ptr: *anyopaque, attestations: context.SubmittedAttestations) anyerror!void {
        const self: *PoolSubmitProbe = @ptrCast(@alignCast(ptr));
        switch (attestations) {
            .phase0 => |items| self.phase0_attestation_len = items.len,
            .electra_single => |items| self.electra_attestation_len = items.len,
        }
    }
};

const HeadBlockOverrides = struct {
    proposer_index: ?u64 = null,
    parent_root: ?[32]u8 = null,
    state_root: ?[32]u8 = null,
    signature: ?[96]u8 = null,
};

fn storePhase0HeadBlock(tc: *test_helpers.TestContext, overrides: HeadBlockOverrides) !void {
    const ct = @import("consensus_types");

    var signed_block = ct.phase0.SignedBeaconBlock.default_value;
    signed_block.message.slot = tc.head_tracker.head_slot;
    if (overrides.proposer_index) |proposer_index| signed_block.message.proposer_index = proposer_index;
    if (overrides.parent_root) |parent_root| signed_block.message.parent_root = parent_root;
    if (overrides.state_root) |state_root| signed_block.message.state_root = state_root;
    if (overrides.signature) |signature| signed_block.signature = signature;

    const block_size = ct.phase0.SignedBeaconBlock.serializedSize(&signed_block);
    const block_bytes = try std.testing.allocator.alloc(u8, block_size);
    defer std.testing.allocator.free(block_bytes);
    _ = ct.phase0.SignedBeaconBlock.serializeIntoBytes(&signed_block, block_bytes);
    try tc.db.putBlock(tc.head_tracker.head_root, block_bytes);
}

test "getGenesis returns genesis data from config" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getGenesis(&tc.ctx);
    try std.testing.expectEqual(@as(u64, 1606824000), resp.data.genesis_time);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "submitPoolAttestations returns NotImplemented without callback when body non-empty" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = submitPoolAttestations(&tc.ctx, &.{consensus_types.phase0.Attestation.default_value});
    try std.testing.expectError(error.NotImplemented, result);
}

test "submitPoolAttestations forwards body to pool_submit callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var probe = PoolSubmitProbe{};
    tc.ctx.pool_submit = .{
        .ptr = @ptrCast(&probe),
        .submitAttestationFn = &PoolSubmitProbe.submitAttestation,
    };

    _ = try submitPoolAttestations(&tc.ctx, &.{consensus_types.phase0.Attestation.default_value});
    try std.testing.expectEqual(@as(usize, 1), probe.phase0_attestation_len);
    try std.testing.expectEqual(@as(usize, 0), probe.electra_attestation_len);
}

test "submitPoolAttestationsV2 returns NotImplemented without callback when body non-empty" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = submitPoolAttestationsV2(&tc.ctx, .{ .phase0 = &.{consensus_types.phase0.Attestation.default_value} });
    try std.testing.expectError(error.NotImplemented, result);
}

test "getStateRoot for head returns head state root" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getStateRoot(&tc.ctx, .head);
    try std.testing.expectEqual(tc.head_tracker.head_state_root, resp.data);
}

test "getStateRoot for slot returns state_root from block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // Build a minimal phase0 signed block with a known state_root and store it.
    const ct = @import("consensus_types");

    var signed_block = ct.phase0.SignedBeaconBlock.default_value;
    signed_block.message.slot = 1;
    signed_block.message.state_root = [_]u8{0xee} ** 32;

    // Serialize the block
    const block_size = ct.phase0.SignedBeaconBlock.serializedSize(&signed_block);
    const block_bytes = try std.testing.allocator.alloc(u8, block_size);
    defer std.testing.allocator.free(block_bytes);
    _ = ct.phase0.SignedBeaconBlock.serializeIntoBytes(&signed_block, block_bytes);

    // Compute block root (just use a fixed test root)
    const block_root = [_]u8{0x11} ** 32;
    try tc.db.putBlockArchive(1, block_root, block_bytes);

    const resp = try getStateRoot(&tc.ctx, .{ .slot = 1 });
    try std.testing.expectEqual([_]u8{0xee} ** 32, resp.data);
}

test "getStateRoot for slot returns SlotNotFound if no block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getStateRoot(&tc.ctx, .{ .slot = 999 });
    try std.testing.expectError(error.SlotNotFound, result);
}

test "getStateRoot for unknown root returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = getStateRoot(&tc.ctx, .{ .root = [_]u8{0x55} ** 32 });
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getStateRoot for finalized root marks response finalized" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const finalized_slot: u64 = 1;
    try test_state.cached_state.state.setSlot(finalized_slot);
    const state_root = (try test_state.cached_state.state.hashTreeRoot()).*;
    const state_bytes = try test_state.cached_state.state.serialize(allocator);
    defer allocator.free(state_bytes);
    try tc.db.putStateArchive(finalized_slot, state_root, state_bytes);

    var finalized_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    finalized_block.message.slot = finalized_slot;
    finalized_block.message.state_root = state_root;
    const finalized_root = [_]u8{0x12} ** 32;
    const finalized_block_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&finalized_block);
    const finalized_block_bytes = try allocator.alloc(u8, finalized_block_size);
    defer allocator.free(finalized_block_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&finalized_block, finalized_block_bytes);
    try tc.db.putBlockArchive(finalized_slot, finalized_root, finalized_block_bytes);

    const resp = try getStateRoot(&tc.ctx, .{ .root = state_root });
    try std.testing.expectEqual(state_root, resp.data);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "getStateFork returns genesis fork for slot 0" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();
    try test_state.cached_state.state.setSlot(0);
    tc.chain_fixture.state_by_slot = test_state.cached_state;

    const resp = try getStateFork(&tc.ctx, .genesis);
    try std.testing.expectEqual(tc.ctx.beacon_config.chain.GENESIS_FORK_VERSION, resp.data.current_version);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "getStateFork for missing slot returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try std.testing.expectError(error.StateNotAvailable, getStateFork(&tc.ctx, .{ .slot = 999 }));
}

test "getFinalityCheckpoints returns checkpoint data" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getFinalityCheckpoints(&tc.ctx, .head);
    const expected_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH;
    try std.testing.expectEqual(expected_epoch, resp.data.finalized.epoch);
}

test "getFinalityCheckpoints for missing slot returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try std.testing.expectError(error.StateNotAvailable, getFinalityCheckpoints(&tc.ctx, .{ .slot = 999 }));
}

test "getBlockHeader for head returns header" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try storePhase0HeadBlock(&tc, .{});

    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expectEqual(tc.head_tracker.head_slot, resp.data.header.message.slot);
    try std.testing.expect(resp.data.canonical);
}

test "getBlockHeader for head extracts real fields from DB block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try storePhase0HeadBlock(&tc, .{
        .proposer_index = 42,
        .parent_root = [_]u8{0xab} ** 32,
        .state_root = [_]u8{0xcd} ** 32,
        .signature = [_]u8{0xef} ** 96,
    });

    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expectEqual(@as(u64, 42), resp.data.header.message.proposer_index);
    try std.testing.expectEqual([_]u8{0xab} ** 32, resp.data.header.message.parent_root);
    try std.testing.expectEqual([_]u8{0xcd} ** 32, resp.data.header.message.state_root);
    try std.testing.expectEqual([_]u8{0xef} ** 96, resp.data.header.signature);
}

test "getBlockHeader for head reports execution optimistic from chain query" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try storePhase0HeadBlock(&tc, .{});
    tc.sync_status.is_optimistic = true;

    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expect(resp.meta.execution_optimistic orelse false);
}

test "getBlockHeaders filters resolved header by parent_root" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const matching = try getBlockHeaders(&tc.ctx, null, tc.head_tracker.head_root);
    defer std.testing.allocator.free(matching.data);
    try std.testing.expectEqual(@as(usize, 0), matching.data.len);

    const parent_root = [_]u8{0x42} ** 32;
    try storePhase0HeadBlock(&tc, .{ .parent_root = parent_root });
    tc.chain_fixture.fork_choice_nodes = try std.testing.allocator.alloc(types.ForkChoiceNode, 1);
    tc.chain_fixture.fork_choice_nodes.?[0] = .{
        .slot = tc.head_tracker.head_slot,
        .block_root = tc.head_tracker.head_root,
        .parent_root = parent_root,
        .justified_epoch = tc.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
        .finalized_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
        .weight = 1,
        .validity = "valid",
        .execution_block_hash = [_]u8{0} ** 32,
    };

    const filtered = try getBlockHeaders(&tc.ctx, null, parent_root);
    defer std.testing.allocator.free(filtered.data);
    try std.testing.expectEqual(@as(usize, 1), filtered.data.len);
    try std.testing.expectEqual(parent_root, filtered.data[0].header.message.parent_root);
}

test "getBlockHeaders returns empty when parent_root filter mismatches" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try storePhase0HeadBlock(&tc, .{ .parent_root = [_]u8{0x11} ** 32 });

    const filtered = try getBlockHeaders(&tc.ctx, null, [_]u8{0x22} ** 32);
    defer std.testing.allocator.free(filtered.data);
    try std.testing.expectEqual(@as(usize, 0), filtered.data.len);
}

test "getBlockHeader for head returns BlockNotFound when block bytes are missing" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try std.testing.expectError(error.BlockNotFound, getBlockHeader(&tc.ctx, .head));
}

test "getBlockHeaders for missing slot returns empty" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const filtered = try getBlockHeaders(&tc.ctx, 999_999, null);
    defer std.testing.allocator.free(filtered.data);
    try std.testing.expectEqual(@as(usize, 0), filtered.data.len);
}

test "getBlockHeaders without filters returns BlockNotFound when head block bytes are missing" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try std.testing.expectError(error.BlockNotFound, getBlockHeaders(&tc.ctx, null, null));
}

test "getBlockHeader for root marks noncanonical sibling as noncanonical" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try storePhase0HeadBlock(&tc, .{});

    const sibling_root = [_]u8{0x66} ** 32;
    var sibling_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    sibling_block.message.slot = tc.head_tracker.head_slot;
    sibling_block.message.parent_root = [_]u8{0x33} ** 32;
    const sibling_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&sibling_block);
    const sibling_bytes = try std.testing.allocator.alloc(u8, sibling_size);
    defer std.testing.allocator.free(sibling_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&sibling_block, sibling_bytes);
    try tc.db.putBlock(sibling_root, sibling_bytes);

    const resp = try getBlockHeader(&tc.ctx, .{ .root = sibling_root });
    try std.testing.expectEqual(tc.head_tracker.head_slot, resp.data.header.message.slot);
    try std.testing.expect(!resp.data.canonical);
    try std.testing.expect(!(resp.meta.finalized orelse false));
}

test "getBlockHeader for genesis resolves canonical slot zero root" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const genesis_root = [_]u8{0x10} ** 32;
    var genesis_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    genesis_block.message.slot = 0;
    const genesis_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&genesis_block);
    const genesis_bytes = try std.testing.allocator.alloc(u8, genesis_size);
    defer std.testing.allocator.free(genesis_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&genesis_block, genesis_bytes);
    try tc.db.putBlockArchive(0, genesis_root, genesis_bytes);

    const resp = try getBlockHeader(&tc.ctx, .genesis);
    try std.testing.expectEqual(genesis_root, resp.data.root);
    try std.testing.expectEqual(@as(u64, 0), resp.data.header.message.slot);
    try std.testing.expect(resp.data.canonical);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "getBlockHeaders returns hot siblings for slot filter" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    try storePhase0HeadBlock(&tc, .{});

    const sibling_root = [_]u8{0x77} ** 32;
    var sibling_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    sibling_block.message.slot = tc.head_tracker.head_slot;
    sibling_block.message.parent_root = [_]u8{0x44} ** 32;
    const sibling_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&sibling_block);
    const sibling_bytes = try std.testing.allocator.alloc(u8, sibling_size);
    defer std.testing.allocator.free(sibling_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&sibling_block, sibling_bytes);
    try tc.db.putBlock(sibling_root, sibling_bytes);

    tc.chain_fixture.fork_choice_nodes = try std.testing.allocator.alloc(types.ForkChoiceNode, 2);
    tc.chain_fixture.fork_choice_nodes.?[0] = .{
        .slot = tc.head_tracker.head_slot,
        .block_root = tc.head_tracker.head_root,
        .parent_root = null,
        .justified_epoch = tc.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
        .finalized_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
        .weight = 1,
        .validity = "valid",
        .execution_block_hash = [_]u8{0} ** 32,
    };
    tc.chain_fixture.fork_choice_nodes.?[1] = .{
        .slot = tc.head_tracker.head_slot,
        .block_root = sibling_root,
        .parent_root = [_]u8{0x44} ** 32,
        .justified_epoch = tc.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
        .finalized_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
        .weight = 1,
        .validity = "valid",
        .execution_block_hash = [_]u8{0} ** 32,
    };

    const resp = try getBlockHeaders(&tc.ctx, tc.head_tracker.head_slot, null);
    defer std.testing.allocator.free(resp.data);

    try std.testing.expectEqual(@as(usize, 2), resp.data.len);
    try std.testing.expect(resp.data[0].canonical);
    try std.testing.expectEqual(tc.head_tracker.head_root, resp.data[0].root);
    try std.testing.expect(!resp.data[1].canonical);
    try std.testing.expectEqual(sibling_root, resp.data[1].root);
}

test "getBlockHeaders returns finalized canonical child for parent_root filter" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const parent_root = [_]u8{0x21} ** 32;
    const child_root = [_]u8{0x22} ** 32;
    var child_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    child_block.message.slot = 1;
    child_block.message.parent_root = parent_root;
    const child_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&child_block);
    const child_bytes = try std.testing.allocator.alloc(u8, child_size);
    defer std.testing.allocator.free(child_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&child_block, child_bytes);
    try tc.db.putBlockArchiveCanonical(1, child_root, parent_root, child_bytes);

    const resp = try getBlockHeaders(&tc.ctx, null, parent_root);
    defer std.testing.allocator.free(resp.data);

    try std.testing.expectEqual(@as(usize, 1), resp.data.len);
    try std.testing.expectEqual(child_root, resp.data[0].root);
    try std.testing.expect(resp.data[0].canonical);
}

test "getBlockHeaders applies parent_root filter to canonical slot match" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const canonical_parent_root = [_]u8{0x11} ** 32;
    try storePhase0HeadBlock(&tc, .{ .parent_root = canonical_parent_root });

    var sibling_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    sibling_block.message.slot = tc.head_tracker.head_slot;
    sibling_block.message.parent_root = [_]u8{0x44} ** 32;
    const sibling_root = [_]u8{0x55} ** 32;
    const sibling_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&sibling_block);
    const sibling_bytes = try std.testing.allocator.alloc(u8, sibling_size);
    defer std.testing.allocator.free(sibling_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&sibling_block, sibling_bytes);
    try tc.db.putBlock(sibling_root, sibling_bytes);

    tc.chain_fixture.fork_choice_nodes = try std.testing.allocator.alloc(types.ForkChoiceNode, 2);
    tc.chain_fixture.fork_choice_nodes.?[0] = .{
        .slot = tc.head_tracker.head_slot,
        .block_root = tc.head_tracker.head_root,
        .parent_root = canonical_parent_root,
        .justified_epoch = tc.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
        .finalized_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
        .weight = 1,
        .validity = "valid",
        .execution_block_hash = [_]u8{0} ** 32,
    };
    tc.chain_fixture.fork_choice_nodes.?[1] = .{
        .slot = tc.head_tracker.head_slot,
        .block_root = sibling_root,
        .parent_root = [_]u8{0x44} ** 32,
        .justified_epoch = tc.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
        .finalized_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
        .weight = 1,
        .validity = "valid",
        .execution_block_hash = [_]u8{0} ** 32,
    };

    const resp = try getBlockHeaders(&tc.ctx, tc.head_tracker.head_slot, [_]u8{0x44} ** 32);
    defer std.testing.allocator.free(resp.data);

    try std.testing.expectEqual(@as(usize, 1), resp.data.len);
    try std.testing.expectEqual(sibling_root, resp.data[0].root);
    try std.testing.expectEqual([_]u8{0x44} ** 32, resp.data[0].header.message.parent_root);
    try std.testing.expect(!resp.data[0].canonical);
}

test "getBlobSidecars returns archived blob sidecars for slot" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const sidecar_size = consensus_types.deneb.BlobSidecar.fixed_size;
    const slot: u64 = tc.ctx.beacon_config.chain.DENEB_FORK_EPOCH * preset.SLOTS_PER_EPOCH;
    tc.head_tracker.finalized_slot = slot;
    const block_root = [_]u8{0x44} ** 32;
    const blob_bytes = try allocator.alloc(u8, sidecar_size * 2);
    defer allocator.free(blob_bytes);
    @memset(blob_bytes, 0);
    std.mem.writeInt(u64, blob_bytes[0..8], 0, .little);
    std.mem.writeInt(u64, blob_bytes[sidecar_size .. sidecar_size + 8], 1, .little);

    try tc.db.putBlockArchive(slot, block_root, "archived_block");
    try tc.db.putBlobSidecarsArchive(slot, blob_bytes);

    const result = try getBlobSidecars(&tc.ctx, .{ .slot = slot }, null);
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(u64, slot), result.slot);
    try std.testing.expectEqual(handler_result.Fork.deneb, result.fork_name);
    try std.testing.expectEqualSlices(u8, blob_bytes, result.data);
    try std.testing.expect(result.finalized);
}

test "getBlobSidecars filters requested indices" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const sidecar_size = consensus_types.deneb.BlobSidecar.fixed_size;
    const block_root = [_]u8{0x45} ** 32;
    const blob_bytes = try allocator.alloc(u8, sidecar_size * 3);
    defer allocator.free(blob_bytes);
    @memset(blob_bytes, 0);
    std.mem.writeInt(u64, blob_bytes[0..8], 0, .little);
    std.mem.writeInt(u64, blob_bytes[sidecar_size .. sidecar_size + 8], 1, .little);
    std.mem.writeInt(u64, blob_bytes[sidecar_size * 2 .. sidecar_size * 2 + 8], 2, .little);

    var signed_block = consensus_types.phase0.SignedBeaconBlock.default_value;
    signed_block.message.slot = tc.head_tracker.head_slot;
    const block_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&signed_block);
    const block_bytes = try allocator.alloc(u8, block_size);
    defer allocator.free(block_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&signed_block, block_bytes);
    try tc.db.putBlock(block_root, block_bytes);
    try tc.db.putBlobSidecars(block_root, blob_bytes);

    const result = try getBlobSidecars(&tc.ctx, .{ .root = block_root }, &.{1});
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, sidecar_size), result.data.len);
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, result.data[0..8], .little));
}

test "getValidators without head state returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    // test context defaults to archive-backed state reads unless a live state is injected
    const result = getValidators(&tc.ctx, .head, .{});
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getValidators non-head returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getValidators(&tc.ctx, .{ .slot = 10 }, .{});
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getValidators with head state returns non-empty list" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const resp = try getValidators(&tc.ctx, .head, .{});
    defer allocator.free(resp.data);

    try std.testing.expectEqual(@as(usize, 4), resp.data.len);
    // Each validator should have a valid index
    try std.testing.expectEqual(@as(u64, 0), resp.data[0].index);
    try std.testing.expectEqual(@as(u64, 3), resp.data[3].index);
}

test "getValidators with head state propagates optimistic meta" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;
    tc.sync_status.is_optimistic = true;

    const resp = try getValidators(&tc.ctx, .head, .{});
    defer allocator.free(resp.data);

    try std.testing.expect(resp.meta.execution_optimistic orelse false);
}

test "getValidator with valid index returns data" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const resp = try getValidator(&tc.ctx, .head, .{ .index = 2 });
    try std.testing.expectEqual(@as(u64, 2), resp.data.index);
    // Validator should be active (activation_epoch 0, exit_epoch max)
    try std.testing.expectEqual(types.ValidatorStatus.active_ongoing, resp.data.status);
}

test "getValidator with out-of-range index returns ValidatorNotFound" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const result = getValidator(&tc.ctx, .head, .{ .index = 99 });
    try std.testing.expectError(error.ValidatorNotFound, result);
}

test "getStateSyncCommittees returns validators for current sync period" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();
    tc.chain_fixture.head_state = test_state.cached_state;

    const resp = try getStateSyncCommittees(&tc.ctx, .head, null);
    defer allocator.free(resp.data.validators);
    for (resp.data.validator_aggregates) |aggregate| allocator.free(aggregate);
    defer allocator.free(resp.data.validator_aggregates);

    try std.testing.expect(resp.data.validators.len > 0);
    try std.testing.expectEqual(@as(usize, 4), resp.data.validator_aggregates.len);
}

test "getStateSyncCommittees returns InvalidRequest for unsupported sync period" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();
    tc.chain_fixture.head_state = test_state.cached_state;

    const unsupported_epoch = test_state.cached_state.epoch_cache.epoch + (2 * preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
    try std.testing.expectError(error.InvalidRequest, getStateSyncCommittees(&tc.ctx, .head, unsupported_epoch));
}

test "getStateCommittees returns InvalidRequest for unsupported epoch" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();
    tc.chain_fixture.head_state = test_state.cached_state;

    const unsupported_epoch = test_state.cached_state.epoch_cache.epoch + 2;
    try std.testing.expectError(error.InvalidRequest, getStateCommittees(&tc.ctx, .head, unsupported_epoch, null, null));
}

test "getStateRandao returns InvalidRequest for future epoch" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();
    tc.chain_fixture.head_state = test_state.cached_state;

    const future_epoch = (try test_state.cached_state.state.slot()) / preset.SLOTS_PER_EPOCH + 1;
    try std.testing.expectError(error.InvalidRequest, getStateRandao(&tc.ctx, .head, future_epoch));
}

test "getStateRandao returns InvalidRequest for overwritten historical epoch" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();
    const current_epoch = preset.EPOCHS_PER_HISTORICAL_VECTOR + 2;
    try test_state.cached_state.state.setSlot(current_epoch * preset.SLOTS_PER_EPOCH);
    tc.chain_fixture.head_state = test_state.cached_state;

    try std.testing.expectError(error.InvalidRequest, getStateRandao(&tc.ctx, .head, 0));
}

test "submitBlock returns NotImplemented when block_import is null" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    // block_import defaults to null
    const fake_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const result = submitBlock(&tc.ctx, &fake_bytes, .full, .gossip);
    try std.testing.expectError(error.NotImplemented, result);
}

test "submitBlock invokes block_import callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // Mock callback that records invocation
    const MockImporter = struct {
        called: bool = false,
        received_len: usize = 0,
        block_type: BlockType = .full,
        broadcast_validation: types.BroadcastValidation = .gossip,

        fn importBlock(ptr: *anyopaque, params: context.PublishedBlockParams) anyerror!context.PublishedBlockImportResult {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.called = true;
            self.received_len = params.block_bytes.len;
            self.block_type = params.block_type;
            self.broadcast_validation = params.broadcast_validation;
            return .queued;
        }
    };

    var mock = MockImporter{};
    tc.ctx.block_import = .{
        .ptr = &mock,
        .importFn = &MockImporter.importBlock,
    };

    const fake_bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ** 4;
    const result = try submitBlock(&tc.ctx, &fake_bytes, .full, .consensus);

    try std.testing.expect(mock.called);
    try std.testing.expectEqual(fake_bytes.len, mock.received_len);
    try std.testing.expectEqual(BlockType.full, mock.block_type);
    try std.testing.expectEqual(types.BroadcastValidation.consensus, mock.broadcast_validation);
    try std.testing.expectEqual(@as(u16, 202), result.status);
}

test "submitBlock keeps imported response on default status" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const Importer = struct {
        fn importBlock(_: *anyopaque, _: context.PublishedBlockParams) anyerror!context.PublishedBlockImportResult {
            return .imported;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.block_import = .{
        .ptr = &dummy,
        .importFn = &Importer.importBlock,
    };

    const fake_bytes = [_]u8{ 0xDE, 0xAD };
    const result = try submitBlock(&tc.ctx, &fake_bytes, .full, .gossip);
    try std.testing.expectEqual(@as(u16, 0), result.status);
}

test "submitBlock propagates error from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const FailImporter = struct {
        fn importBlock(_: *anyopaque, _: context.PublishedBlockParams) anyerror!context.PublishedBlockImportResult {
            return error.BlockAlreadyKnown;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.block_import = .{
        .ptr = &dummy,
        .importFn = &FailImporter.importBlock,
    };

    const fake_bytes = [_]u8{0x01};
    const result = submitBlock(&tc.ctx, &fake_bytes, .full, .gossip);
    try std.testing.expectError(error.BlockAlreadyKnown, result);
}

test "getBlindedBlock returns pre-execution full block bytes" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const block_bytes = "phase0_block";
    try tc.db.putBlock(tc.head_tracker.head_root, block_bytes);

    const result = try getBlindedBlock(&tc.ctx, .head);
    defer std.testing.allocator.free(result.data);

    try std.testing.expectEqual(handler_result.Fork.phase0, result.fork_name);
    try std.testing.expectEqualSlices(u8, block_bytes, result.data);
}

test "getBlindedBlock returns blinded execution-fork block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const execution_slot = tc.ctx.beacon_config.chain.BELLATRIX_FORK_EPOCH * preset.SLOTS_PER_EPOCH;
    const block_root = [_]u8{0x44} ** 32;
    var block = consensus_types.bellatrix.SignedBeaconBlock.default_value;
    block.message.slot = execution_slot;
    const block_bytes = try std.testing.allocator.alloc(u8, consensus_types.bellatrix.SignedBeaconBlock.serializedSize(&block));
    defer std.testing.allocator.free(block_bytes);
    _ = consensus_types.bellatrix.SignedBeaconBlock.serializeIntoBytes(&block, block_bytes);
    try tc.db.putBlockArchive(execution_slot, block_root, block_bytes);

    const result = try getBlindedBlock(&tc.ctx, .{ .slot = execution_slot });
    defer std.testing.allocator.free(result.data);

    try std.testing.expectEqual(BlockType.blinded, result.block_type);
    var blinded = try AnySignedBeaconBlock.deserialize(std.testing.allocator, .blinded, .bellatrix, result.data);
    defer blinded.deinit(std.testing.allocator);
    try std.testing.expectEqual(fork_types.BlockType.blinded, blinded.blockType());
}

test "getPoolAttestations returns NotImplemented when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPoolAttestations(&tc.ctx, null, null);
    try std.testing.expectError(error.NotImplemented, resp);
}

test "getPoolAttestations returns items from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockOpPool = struct {
        fn getPoolCounts(_: *anyopaque) [5]usize {
            return .{ 10, 3, 1, 2, 5 };
        }
        fn getAttestations(_: *anyopaque, allocator: std.mem.Allocator, _: ?u64, _: ?u64) anyerror![]OpPoolCallback.Phase0Attestation {
            var result = try allocator.alloc(OpPoolCallback.Phase0Attestation, 2);
            result[0] = .{
                .aggregation_bits = .{ .data = std.ArrayListUnmanaged(u8).empty, .bit_len = 0 },
                .data = .{
                    .slot = 42,
                    .index = 0,
                    .beacon_block_root = [_]u8{0} ** 32,
                    .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
                    .target = .{ .epoch = 1, .root = [_]u8{0} ** 32 },
                },
                .signature = [_]u8{0} ** 96,
            };
            result[1] = result[0];
            result[1].data.slot = 43;
            return result;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.op_pool = .{
        .ptr = &dummy,
        .getPoolCountsFn = &MockOpPool.getPoolCounts,
        .getAttestationsFn = &MockOpPool.getAttestations,
    };

    const resp = try getPoolAttestations(&tc.ctx, null, null);
    defer {
        for (resp.data) |*item| consensus_types.phase0.Attestation.deinit(std.testing.allocator, @constCast(item));
        std.testing.allocator.free(resp.data);
    }
    try std.testing.expectEqual(@as(usize, 2), resp.data.len);
    try std.testing.expectEqual(@as(u64, 42), resp.data[0].data.slot);
    try std.testing.expectEqual(@as(u64, 43), resp.data[1].data.slot);
}

test "getPoolAttestations returns InvalidRequest when head is Electra" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    tc.head_tracker.head_slot = tc.ctx.beacon_config.chain.ELECTRA_FORK_EPOCH * preset.SLOTS_PER_EPOCH;
    try std.testing.expectError(error.InvalidRequest, getPoolAttestations(&tc.ctx, null, null));
}

test "getPoolAttestationsV2 returns electra items from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockOpPoolV2 = struct {
        fn getPoolCounts(_: *anyopaque) [5]usize {
            return .{ 1, 0, 0, 0, 0 };
        }
        fn getAttestationsV2(_: *anyopaque, allocator: std.mem.Allocator, _: ?u64, _: ?u64) anyerror![]OpPoolCallback.AnyAttestation {
            var result = try allocator.alloc(OpPoolCallback.AnyAttestation, 1);
            var att = consensus_types.electra.Attestation.default_value;
            att.data.slot = preset.SLOTS_PER_EPOCH * @import("config").mainnet.chain_config.ELECTRA_FORK_EPOCH;
            att.committee_bits.set(3, true) catch unreachable;
            result[0] = .{ .electra = att };
            return result;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.op_pool = .{
        .ptr = &dummy,
        .getPoolCountsFn = &MockOpPoolV2.getPoolCounts,
        .getAttestationsV2Fn = &MockOpPoolV2.getAttestationsV2,
    };

    const resp = try getPoolAttestationsV2(&tc.ctx, null, 3);
    defer {
        for (resp.data) |*item| @constCast(item).deinit(std.testing.allocator);
        std.testing.allocator.free(resp.data);
    }
    try std.testing.expectEqual(@as(usize, 1), resp.data.len);
    try std.testing.expect(resp.data[0] == .electra);
}

test "getPoolVoluntaryExits returns NotImplemented when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPoolVoluntaryExits(&tc.ctx);
    try std.testing.expectError(error.NotImplemented, resp);
}

test "getPoolProposerSlashings returns NotImplemented when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPoolProposerSlashings(&tc.ctx);
    try std.testing.expectError(error.NotImplemented, resp);
}

test "getPoolAttesterSlashings returns NotImplemented when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPoolAttesterSlashings(&tc.ctx);
    try std.testing.expectError(error.NotImplemented, resp);
}

test "getPoolBlsToExecutionChanges returns NotImplemented when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPoolBlsToExecutionChanges(&tc.ctx);
    try std.testing.expectError(error.NotImplemented, resp);
}

// ---------------------------------------------------------------------------
// JSON wire types for pool submission parsing
// ---------------------------------------------------------------------------

const AttestationDataJsonWire = struct {
    slot: u64,
    index: u64,
    beacon_block_root: []const u8,
    source: CheckpointJsonWire,
    target: CheckpointJsonWire,
};

const CheckpointJsonWire = struct {
    epoch: u64,
    root: []const u8,
};

const AttestationJsonWire = struct {
    aggregation_bits: []const u8,
    data: AttestationDataJsonWire,
    signature: []const u8,
};

/// Electra attestation JSON wire type (EIP-7549).
/// Includes committee_bits bitvector not present in pre-Electra format.
const ElectraAttestationJsonWire = struct {
    aggregation_bits: []const u8,
    data: AttestationDataJsonWire,
    signature: []const u8,
    committee_bits: []const u8,
};

/// SingleAttestation JSON wire type (Electra v2 POST format).
/// This is the format validators submit via POST /eth/v2/beacon/pool/attestations.
/// Different from the full Attestation — contains committee_index + attester_index
/// instead of aggregation_bits + committee_bits.
const SingleAttestationJsonWire = struct {
    committee_index: u64,
    attester_index: u64,
    data: AttestationDataJsonWire,
    signature: []const u8,
};

const SignedVoluntaryExitJsonWire = struct {
    message: VoluntaryExitJsonWire,
    signature: []const u8,
};

const VoluntaryExitJsonWire = struct {
    epoch: u64,
    validator_index: u64,
};

const BeaconBlockHeaderJsonWire = struct {
    slot: u64,
    proposer_index: u64,
    parent_root: []const u8,
    state_root: []const u8,
    body_root: []const u8,
};

const SignedBeaconBlockHeaderJsonWire = struct {
    message: BeaconBlockHeaderJsonWire,
    signature: []const u8,
};

const ProposerSlashingJsonWire = struct {
    signed_header_1: SignedBeaconBlockHeaderJsonWire,
    signed_header_2: SignedBeaconBlockHeaderJsonWire,
};

const IndexedAttestationJsonWire = struct {
    attesting_indices: []const u64,
    data: AttestationDataJsonWire,
    signature: []const u8,
};

const AttesterSlashingJsonWire = struct {
    attestation_1: IndexedAttestationJsonWire,
    attestation_2: IndexedAttestationJsonWire,
};

const BLSToExecutionChangeJsonWire = struct {
    validator_index: u64,
    from_bls_pubkey: []const u8,
    to_execution_address: []const u8,
};

const SignedBLSToExecutionChangeJsonWire = struct {
    message: BLSToExecutionChangeJsonWire,
    signature: []const u8,
};

const SyncCommitteeMessageJsonWire = struct {
    slot: u64,
    beacon_block_root: []const u8,
    validator_index: u64,
    signature: []const u8,
};

// ---------------------------------------------------------------------------
// Hex parsing helpers
// ---------------------------------------------------------------------------

/// Parse a 0x-prefixed hex string into a fixed-size byte array.
/// Returns error.InvalidHex if parsing fails.
fn parseHexBytes(comptime N: usize, hex: []const u8) ![N]u8 {
    const src = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;
    if (src.len != N * 2) return error.InvalidHex;
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, src) catch return error.InvalidHex;
    return out;
}

/// Parse a 0x-prefixed hex string as BLS signature (96 bytes).
fn parseSignature(hex: []const u8) ![96]u8 {
    return parseHexBytes(96, hex);
}

/// Parse a 0x-prefixed hex string as a 32-byte root.
fn parseRoot(hex: []const u8) ![32]u8 {
    return parseHexBytes(32, hex);
}

/// Parse a 0x-prefixed hex string as a 48-byte BLS public key.
fn parsePubkey(hex: []const u8) ![48]u8 {
    return parseHexBytes(48, hex);
}

/// Parse a 0x-prefixed hex string as a 20-byte execution address.
fn parseAddress(hex: []const u8) ![20]u8 {
    return parseHexBytes(20, hex);
}

// ---------------------------------------------------------------------------
// State resolution helper
// ---------------------------------------------------------------------------

/// Metadata about a resolved state for response envelope.
const ResolvedStateMeta = struct {
    execution_optimistic: bool,
    finalized: bool,
};

fn resolveStateMetaForRootAndSlot(
    ctx: *ApiContext,
    state_root: [32]u8,
    slot: u64,
) !ResolvedStateMeta {
    const head = ctx.currentHeadTracker();
    const canonical_root = try ctx.stateRootBySlot(slot);
    const canonical = if (canonical_root) |canonical_state_root|
        std.mem.eql(u8, &canonical_state_root, &state_root)
    else
        false;
    return .{
        .execution_optimistic = ctx.stateExecutionOptimisticByRoot(state_root),
        .finalized = canonical and slot <= head.finalized_slot,
    };
}

fn resolveStateMetaByRoot(ctx: *ApiContext, state_root: [32]u8) !ResolvedStateMeta {
    if (try ctx.stateByRoot(state_root)) |state| {
        return resolveStateMetaForRootAndSlot(ctx, state_root, try state.state.slot());
    }

    const state_bytes = (try ctx.stateBytesByRoot(state_root)) orelse return error.StateNotAvailable;
    defer ctx.allocator.free(state_bytes);

    const slot = readStateSlotFromSsz(state_bytes) orelse return error.StateNotAvailable;
    return resolveStateMetaForRootAndSlot(ctx, state_root, slot);
}

/// Resolve a state_id to a CachedBeaconState.
///
/// Supports all Beacon API state identifiers:
///   - "head"      → current head state
///   - "justified" → current justified checkpoint state
///   - "finalized" → finalized checkpoint state
///   - "genesis"   → state at slot 0
///   - <slot>      → canonical state at the given slot
///   - 0x<root>    → state by root
///
/// Returns error.StateNotAvailable if the state cannot be resolved.
fn resolveState(ctx: *ApiContext, state_id: types.StateId) !struct { state: *CachedBeaconState, meta: ResolvedStateMeta } {
    const head = ctx.currentHeadTracker();
    switch (state_id) {
        .head => {
            const state = ctx.headState() orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{
                    .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
                    .finalized = std.mem.eql(u8, &head.head_root, &head.finalized_root),
                },
            };
        },
        .justified => {
            const state = (try ctx.stateByBlockRoot(head.justified_root)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{
                    .execution_optimistic = ctx.blockExecutionOptimistic(head.justified_root),
                    .finalized = std.mem.eql(u8, &head.justified_root, &head.finalized_root),
                },
            };
        },
        .finalized => {
            const state = (try ctx.stateByBlockRoot(head.finalized_root)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{ .execution_optimistic = false, .finalized = true },
            };
        },
        .genesis => {
            const state = (try ctx.stateBySlot(0)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{ .execution_optimistic = false, .finalized = true },
            };
        },
        .slot => |slot| {
            const state = (try ctx.stateBySlot(slot)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{
                    .execution_optimistic = try ctx.stateExecutionOptimisticBySlot(slot),
                    .finalized = slot <= head.finalized_slot,
                },
            };
        },
        .root => |root| {
            const state = (try ctx.stateByRoot(root)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = try resolveStateMetaForRootAndSlot(ctx, root, try state.state.slot()),
            };
        },
    }
}

// ---------------------------------------------------------------------------
// State committee endpoints
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/states/{state_id}/committees
///
/// Returns beacon committee assignments for an epoch.
/// Query params: epoch (optional), index (optional), slot (optional).
pub fn getStateCommittees(
    ctx: *ApiContext,
    state_id: types.StateId,
    epoch_opt: ?u64,
    slot_opt: ?u64,
    index_opt: ?u64,
) !HandlerResult([]const types.CommitteeData) {
    const resolved = try resolveState(ctx, state_id);
    const state = resolved.state;

    const current_slot = try state.state.slot();
    const current_epoch = current_slot / preset.SLOTS_PER_EPOCH;
    const epoch = epoch_opt orelse current_epoch;

    const epoch_cache = state.epoch_cache;
    const committees_per_slot = epoch_cache.getCommitteeCountPerSlot(epoch) catch {
        return error.InvalidRequest;
    };

    // Determine which slots to enumerate.
    const epoch_start_slot = epoch * preset.SLOTS_PER_EPOCH;

    var result = std.ArrayListUnmanaged(types.CommitteeData).empty;
    errdefer {
        for (result.items) |item| ctx.allocator.free(item.validators);
        result.deinit(ctx.allocator);
    }

    for (0..preset.SLOTS_PER_EPOCH) |slot_offset| {
        const slot = epoch_start_slot + slot_offset;

        // Filter by slot if provided.
        if (slot_opt) |filter_slot| {
            if (slot != filter_slot) continue;
        }

        for (0..committees_per_slot) |committee_idx| {
            // Filter by index if provided.
            if (index_opt) |filter_index| {
                if (committee_idx != filter_index) continue;
            }

            const committee = epoch_cache.getBeaconCommittee(slot, @intCast(committee_idx)) catch unreachable;

            // Copy validator indices.
            const validators = try ctx.allocator.alloc(u64, committee.len);
            for (committee, 0..) |vi, i| {
                validators[i] = @intCast(vi);
            }

            try result.append(ctx.allocator, .{
                .index = committee_idx,
                .slot = slot,
                .validators = validators,
            });
        }
    }

    return .{
        .data = try result.toOwnedSlice(ctx.allocator),
        .meta = .{
            .execution_optimistic = resolved.meta.execution_optimistic,
            .finalized = resolved.meta.finalized,
        },
    };
}

/// GET /eth/v1/beacon/states/{state_id}/sync_committees
///
/// Returns the sync committee for a given state and optional epoch.
pub fn getStateSyncCommittees(
    ctx: *ApiContext,
    state_id: types.StateId,
    epoch_param: ?u64,
) !HandlerResult(types.SyncCommitteeData) {
    const resolved = try resolveState(ctx, state_id);
    const state = resolved.state;

    const current_slot = try state.state.slot();
    const current_epoch = current_slot / preset.SLOTS_PER_EPOCH;
    const epoch = epoch_param orelse current_epoch;

    const epoch_cache = state.epoch_cache;
    const sc = epoch_cache.getIndexedSyncCommitteeAtEpoch(epoch) catch {
        return error.InvalidRequest;
    };

    const sync_indices = sc.getValidatorIndices();
    if (sync_indices.len == 0) {
        // Pre-Altair fork or empty sync committee
        const validators = try ctx.allocator.alloc(u64, 0);
        const aggs = try ctx.allocator.alloc([]const u64, 0);
        return .{
            .data = .{
                .validators = validators,
                .validator_aggregates = aggs,
            },
            .meta = .{
                .execution_optimistic = resolved.meta.execution_optimistic,
                .finalized = resolved.meta.finalized,
            },
        };
    }

    // Build flat validators list.
    const validators = try ctx.allocator.alloc(u64, sync_indices.len);
    for (sync_indices, 0..) |vi, i| {
        validators[i] = @intCast(vi);
    }

    // Build subcommittee aggregates: 4 groups of SYNC_COMMITTEE_SIZE/4.
    const subcommittee_size = sync_indices.len / 4;
    const aggregates = try ctx.allocator.alloc([]const u64, 4);
    for (0..4) |sub| {
        const start = sub * subcommittee_size;
        const end = start + subcommittee_size;
        const sub_validators = try ctx.allocator.alloc(u64, subcommittee_size);
        for (sync_indices[start..end], 0..) |vi, i| {
            sub_validators[i] = @intCast(vi);
        }
        aggregates[sub] = sub_validators;
    }

    return .{
        .data = .{
            .validators = validators,
            .validator_aggregates = aggregates,
        },
        .meta = .{
            .execution_optimistic = resolved.meta.execution_optimistic,
            .finalized = resolved.meta.finalized,
        },
    };
}

/// GET /eth/v1/beacon/states/{state_id}/randao
///
/// Returns RANDAO mix for a state and optional epoch.
pub fn getStateRandao(
    ctx: *ApiContext,
    state_id: types.StateId,
    epoch_opt: ?u64,
) !HandlerResult(types.RandaoData) {
    const resolved = try resolveState(ctx, state_id);
    const state = resolved.state;

    const current_slot = try state.state.slot();
    const current_epoch = current_slot / preset.SLOTS_PER_EPOCH;
    const epoch = epoch_opt orelse current_epoch;

    if (epoch > current_epoch) return error.InvalidRequest;
    if (current_epoch >= preset.EPOCHS_PER_HISTORICAL_VECTOR and epoch + preset.EPOCHS_PER_HISTORICAL_VECTOR <= current_epoch) {
        return error.InvalidRequest;
    }

    // Read randao_mixes from the state.
    var randao_mixes = try state.state.randaoMixes();
    const mix_ptr = try randao_mixes.getFieldRoot(epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR);
    const mix: [32]u8 = mix_ptr.*;

    return .{
        .data = .{ .randao = mix },
        .meta = .{
            .execution_optimistic = resolved.meta.execution_optimistic,
            .finalized = resolved.meta.finalized,
        },
    };
}

// ---------------------------------------------------------------------------
// Block headers (all)
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/headers
///
/// Returns block headers matching optional slot and parent_root filters.
pub fn getBlockHeaders(
    ctx: *ApiContext,
    slot_opt: ?u64,
    parent_root_opt: ?[32]u8,
) !HandlerResult([]const types.BlockHeaderData) {
    var headers = std.ArrayListUnmanaged(types.BlockHeaderData).empty;
    errdefer headers.deinit(ctx.allocator);

    if (slot_opt == null and parent_root_opt == null) {
        const header_result = try resolveBlockHeader(ctx, .head);
        try headers.append(ctx.allocator, header_result.header);
        return .{
            .data = try headers.toOwnedSlice(ctx.allocator),
            .meta = .{
                .execution_optimistic = header_result.execution_optimistic,
                .finalized = header_result.finalized,
            },
        };
    }

    const head = ctx.currentHeadTracker();
    var seen_roots = std.AutoHashMap([32]u8, void).init(ctx.allocator);
    defer seen_roots.deinit();
    var meta = BlockHeaderListMeta{};

    if (slot_opt) |slot| {
        if (try ctx.blockRootBySlot(slot)) |root| {
            try appendBlockHeaderMatch(ctx, &headers, &seen_roots, &meta, .{
                .slot = slot,
                .root = root,
                .execution_optimistic = try ctx.blockExecutionOptimisticAtSlot(slot),
                .finalized = slot <= head.finalized_slot,
                .canonical = true,
            }, parent_root_opt);
        }
    }

    if (parent_root_opt) |parent_root| {
        if (try ctx.finalizedBlockRootByParentRoot(parent_root)) |root| {
            const slot_info = try resolveBlockSlotAndRoot(ctx, .{ .root = root });
            if (slot_opt == null or slot_info.slot == slot_opt.?) {
                try appendBlockHeaderMatch(ctx, &headers, &seen_roots, &meta, slot_info, parent_root_opt);
            }
        }
    }

    const dump_opt = ctx.forkChoiceDump(ctx.allocator) catch |err| switch (err) {
        error.NotImplemented => null,
        else => return err,
    };
    if (dump_opt) |dump| {
        defer ctx.allocator.free(dump.fork_choice_nodes);
        for (dump.fork_choice_nodes) |node| {
            if (slot_opt) |slot| {
                if (node.slot != slot) continue;
            }
            if (parent_root_opt) |parent_root| {
                const node_parent_root = node.parent_root orelse continue;
                if (!std.mem.eql(u8, &node_parent_root, &parent_root)) continue;
            }

            const canonical_root = try ctx.blockRootBySlot(node.slot);
            const canonical = if (canonical_root) |canonical_block_root|
                std.mem.eql(u8, &canonical_block_root, &node.block_root)
            else
                false;
            try appendBlockHeaderMatch(ctx, &headers, &seen_roots, &meta, .{
                .slot = node.slot,
                .root = node.block_root,
                .execution_optimistic = ctx.blockExecutionOptimistic(node.block_root),
                .finalized = canonical and node.slot <= head.finalized_slot,
                .canonical = canonical,
            }, parent_root_opt);
        }
    }

    return .{
        .data = try headers.toOwnedSlice(ctx.allocator),
        .meta = if (meta.saw_any)
            .{
                .execution_optimistic = meta.execution_optimistic,
                .finalized = meta.finalized,
            }
        else
            .{},
    };
}

// ---------------------------------------------------------------------------
// Blob sidecars endpoint
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/blob_sidecars/{block_id}
///
/// Returns raw SSZ bytes for the block's blob sidecars.
///
/// The HTTP layer is responsible for fork-aware JSON serialization.
pub fn getBlobSidecars(
    ctx: *ApiContext,
    block_id: types.BlockId,
    indices_opt: ?[]const u64,
) !BlobSidecarsResult {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);
    const raw_bytes = (try ctx.blobSidecarsByRoot(slot_info.root)) orelse {
        return .{
            .data = try ctx.allocator.dupe(u8, &.{}),
            .slot = slot_info.slot,
            .execution_optimistic = slot_info.execution_optimistic,
            .finalized = slot_info.finalized,
            .fork_name = forkNameFromSlot(ctx, slot_info.slot),
        };
    };

    const filtered_bytes = if (indices_opt) |indices|
        try filterBlobSidecarsByIndex(ctx.allocator, raw_bytes, indices)
    else
        raw_bytes;
    if (indices_opt != null) ctx.allocator.free(raw_bytes);

    return .{
        .data = filtered_bytes,
        .slot = slot_info.slot,
        .execution_optimistic = slot_info.execution_optimistic,
        .finalized = slot_info.finalized,
        .fork_name = forkNameFromSlot(ctx, slot_info.slot),
    };
}

fn filterBlobSidecarsByIndex(
    allocator: std.mem.Allocator,
    raw_bytes: []const u8,
    indices: []const u64,
) ![]const u8 {
    if (indices.len == 0 or raw_bytes.len == 0) return try allocator.dupe(u8, &.{});

    const sidecar_size = consensus_types.deneb.BlobSidecar.fixed_size;
    if (raw_bytes.len % sidecar_size != 0) return error.InvalidRequest;

    var filtered = std.ArrayListUnmanaged(u8).empty;
    defer filtered.deinit(allocator);

    var offset: usize = 0;
    while (offset + sidecar_size <= raw_bytes.len) : (offset += sidecar_size) {
        const sidecar_bytes = raw_bytes[offset..][0..sidecar_size];
        const sidecar_index = std.mem.readInt(u64, sidecar_bytes[0..8], .little);
        if (containsU64(indices, sidecar_index)) {
            try filtered.appendSlice(allocator, sidecar_bytes);
        }
    }

    return filtered.toOwnedSlice(allocator);
}

fn containsU64(values: []const u64, needle: u64) bool {
    for (values) |value| {
        if (value == needle) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Blinded blocks endpoint
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/blinded_blocks/{block_id}
///
/// Returns the blinded block for the given block identifier.
/// For pre-Bellatrix forks, this is identical to the full block.
pub fn getBlindedBlock(
    ctx: *ApiContext,
    block_id: types.BlockId,
) !BlockResult {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);
    const fork_name = forkNameFromSlot(ctx, slot_info.slot);
    return switch (fork_name) {
        .phase0, .altair => try getBlock(ctx, block_id),
        .gloas => error.NotImplemented,
        else => blk: {
            const full_block_bytes = (try ctx.blockBytesByRoot(slot_info.root)) orelse
                return error.BlockNotFound;
            defer ctx.allocator.free(full_block_bytes);

            const fork_seq = ctx.beacon_config.forkSeq(slot_info.slot);
            const full_block = try AnySignedBeaconBlock.deserialize(ctx.allocator, .full, fork_seq, full_block_bytes);
            defer full_block.deinit(ctx.allocator);

            break :blk .{
                .data = try blindedBytesFromFullSignedBlock(ctx.allocator, full_block),
                .slot = slot_info.slot,
                .execution_optimistic = slot_info.execution_optimistic,
                .finalized = slot_info.finalized,
                .fork_name = fork_name,
                .block_type = .blinded,
            };
        },
    };
}

fn blindedBytesFromFullSignedBlock(allocator: std.mem.Allocator, full_block: AnySignedBeaconBlock) ![]u8 {
    switch (full_block) {
        .phase0, .altair => return error.InvalidFork,
        .blinded_bellatrix, .blinded_capella, .blinded_deneb, .blinded_electra, .blinded_fulu => return error.InvalidBlockType,
        .full_gloas => return error.InvalidFork,
        .full_bellatrix => |block| {
            var payload_header = try AnyExecutionPayloadHeader.init(.bellatrix);
            defer payload_header.deinit(allocator);
            const any_payload: AnyExecutionPayload = .{ .bellatrix = block.message.body.execution_payload };
            try any_payload.createPayloadHeader(allocator, &payload_header);

            const blinded = consensus_types.bellatrix.SignedBlindedBeaconBlock.Type{
                .message = .{
                    .slot = block.message.slot,
                    .proposer_index = block.message.proposer_index,
                    .parent_root = block.message.parent_root,
                    .state_root = block.message.state_root,
                    .body = .{
                        .randao_reveal = block.message.body.randao_reveal,
                        .eth1_data = block.message.body.eth1_data,
                        .graffiti = block.message.body.graffiti,
                        .proposer_slashings = block.message.body.proposer_slashings,
                        .attester_slashings = block.message.body.attester_slashings,
                        .attestations = block.message.body.attestations,
                        .deposits = block.message.body.deposits,
                        .voluntary_exits = block.message.body.voluntary_exits,
                        .sync_aggregate = block.message.body.sync_aggregate,
                        .execution_payload_header = payload_header.bellatrix,
                    },
                },
                .signature = block.signature,
            };
            const out = try allocator.alloc(u8, consensus_types.bellatrix.SignedBlindedBeaconBlock.serializedSize(&blinded));
            errdefer allocator.free(out);
            _ = consensus_types.bellatrix.SignedBlindedBeaconBlock.serializeIntoBytes(&blinded, out);
            return out;
        },
        .full_capella => |block| {
            var payload_header = try AnyExecutionPayloadHeader.init(.capella);
            defer payload_header.deinit(allocator);
            const any_payload: AnyExecutionPayload = .{ .capella = block.message.body.execution_payload };
            try any_payload.createPayloadHeader(allocator, &payload_header);

            const blinded = consensus_types.capella.SignedBlindedBeaconBlock.Type{
                .message = .{
                    .slot = block.message.slot,
                    .proposer_index = block.message.proposer_index,
                    .parent_root = block.message.parent_root,
                    .state_root = block.message.state_root,
                    .body = .{
                        .randao_reveal = block.message.body.randao_reveal,
                        .eth1_data = block.message.body.eth1_data,
                        .graffiti = block.message.body.graffiti,
                        .proposer_slashings = block.message.body.proposer_slashings,
                        .attester_slashings = block.message.body.attester_slashings,
                        .attestations = block.message.body.attestations,
                        .deposits = block.message.body.deposits,
                        .voluntary_exits = block.message.body.voluntary_exits,
                        .sync_aggregate = block.message.body.sync_aggregate,
                        .execution_payload_header = payload_header.capella,
                        .bls_to_execution_changes = block.message.body.bls_to_execution_changes,
                    },
                },
                .signature = block.signature,
            };
            const out = try allocator.alloc(u8, consensus_types.capella.SignedBlindedBeaconBlock.serializedSize(&blinded));
            errdefer allocator.free(out);
            _ = consensus_types.capella.SignedBlindedBeaconBlock.serializeIntoBytes(&blinded, out);
            return out;
        },
        .full_deneb => |block| {
            var payload_header = try AnyExecutionPayloadHeader.init(.deneb);
            defer payload_header.deinit(allocator);
            const any_payload: AnyExecutionPayload = .{ .deneb = block.message.body.execution_payload };
            try any_payload.createPayloadHeader(allocator, &payload_header);

            const blinded = consensus_types.deneb.SignedBlindedBeaconBlock.Type{
                .message = .{
                    .slot = block.message.slot,
                    .proposer_index = block.message.proposer_index,
                    .parent_root = block.message.parent_root,
                    .state_root = block.message.state_root,
                    .body = .{
                        .randao_reveal = block.message.body.randao_reveal,
                        .eth1_data = block.message.body.eth1_data,
                        .graffiti = block.message.body.graffiti,
                        .proposer_slashings = block.message.body.proposer_slashings,
                        .attester_slashings = block.message.body.attester_slashings,
                        .attestations = block.message.body.attestations,
                        .deposits = block.message.body.deposits,
                        .voluntary_exits = block.message.body.voluntary_exits,
                        .sync_aggregate = block.message.body.sync_aggregate,
                        .execution_payload_header = payload_header.deneb,
                        .bls_to_execution_changes = block.message.body.bls_to_execution_changes,
                        .blob_kzg_commitments = block.message.body.blob_kzg_commitments,
                    },
                },
                .signature = block.signature,
            };
            const out = try allocator.alloc(u8, consensus_types.deneb.SignedBlindedBeaconBlock.serializedSize(&blinded));
            errdefer allocator.free(out);
            _ = consensus_types.deneb.SignedBlindedBeaconBlock.serializeIntoBytes(&blinded, out);
            return out;
        },
        .full_electra => |block| {
            var payload_header = try AnyExecutionPayloadHeader.init(.electra);
            defer payload_header.deinit(allocator);
            const any_payload: AnyExecutionPayload = .{ .deneb = block.message.body.execution_payload };
            try any_payload.createPayloadHeader(allocator, &payload_header);

            const blinded = consensus_types.electra.SignedBlindedBeaconBlock.Type{
                .message = .{
                    .slot = block.message.slot,
                    .proposer_index = block.message.proposer_index,
                    .parent_root = block.message.parent_root,
                    .state_root = block.message.state_root,
                    .body = .{
                        .randao_reveal = block.message.body.randao_reveal,
                        .eth1_data = block.message.body.eth1_data,
                        .graffiti = block.message.body.graffiti,
                        .proposer_slashings = block.message.body.proposer_slashings,
                        .attester_slashings = block.message.body.attester_slashings,
                        .attestations = block.message.body.attestations,
                        .deposits = block.message.body.deposits,
                        .voluntary_exits = block.message.body.voluntary_exits,
                        .sync_aggregate = block.message.body.sync_aggregate,
                        .execution_payload_header = payload_header.deneb,
                        .bls_to_execution_changes = block.message.body.bls_to_execution_changes,
                        .blob_kzg_commitments = block.message.body.blob_kzg_commitments,
                        .execution_requests = block.message.body.execution_requests,
                    },
                },
                .signature = block.signature,
            };
            const out = try allocator.alloc(u8, consensus_types.electra.SignedBlindedBeaconBlock.serializedSize(&blinded));
            errdefer allocator.free(out);
            _ = consensus_types.electra.SignedBlindedBeaconBlock.serializeIntoBytes(&blinded, out);
            return out;
        },
        .full_fulu => |block| {
            var payload_header = try AnyExecutionPayloadHeader.init(.fulu);
            defer payload_header.deinit(allocator);
            const any_payload: AnyExecutionPayload = .{ .deneb = block.message.body.execution_payload };
            try any_payload.createPayloadHeader(allocator, &payload_header);

            const blinded = consensus_types.fulu.SignedBlindedBeaconBlock.Type{
                .message = .{
                    .slot = block.message.slot,
                    .proposer_index = block.message.proposer_index,
                    .parent_root = block.message.parent_root,
                    .state_root = block.message.state_root,
                    .body = .{
                        .randao_reveal = block.message.body.randao_reveal,
                        .eth1_data = block.message.body.eth1_data,
                        .graffiti = block.message.body.graffiti,
                        .proposer_slashings = block.message.body.proposer_slashings,
                        .attester_slashings = block.message.body.attester_slashings,
                        .attestations = block.message.body.attestations,
                        .deposits = block.message.body.deposits,
                        .voluntary_exits = block.message.body.voluntary_exits,
                        .sync_aggregate = block.message.body.sync_aggregate,
                        .execution_payload_header = payload_header.deneb,
                        .bls_to_execution_changes = block.message.body.bls_to_execution_changes,
                        .blob_kzg_commitments = block.message.body.blob_kzg_commitments,
                        .execution_requests = block.message.body.execution_requests,
                    },
                },
                .signature = block.signature,
            };
            const out = try allocator.alloc(u8, consensus_types.fulu.SignedBlindedBeaconBlock.serializedSize(&blinded));
            errdefer allocator.free(out);
            _ = consensus_types.fulu.SignedBlindedBeaconBlock.serializeIntoBytes(&blinded, out);
            return out;
        },
    }
}

// ---------------------------------------------------------------------------
// Rewards endpoints
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/rewards/blocks/{block_id}
///
/// Returns proposer reward breakdown for the given block.
pub fn getBlockRewards(
    ctx: *ApiContext,
    block_id: types.BlockId,
) !HandlerResult(types.BlockRewards) {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);
    return .{
        .data = try ctx.blockRewards(slot_info.root),
        .meta = .{
            .version = forkNameFromSlot(ctx, slot_info.slot),
            .execution_optimistic = slot_info.execution_optimistic,
            .finalized = slot_info.finalized,
        },
    };
}

/// POST /eth/v1/beacon/rewards/attestations/{epoch}
///
/// Returns per-validator attestation rewards for the epoch.
pub fn getAttestationRewards(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) !HandlerResult(types.AttestationRewardsData) {
    const slot = (epoch + 1) * preset.SLOTS_PER_EPOCH - 1;
    const head = ctx.currentHeadTracker();
    return .{
        .data = try ctx.attestationRewards(epoch, validator_indices),
        .meta = .{
            .version = forkNameFromSlot(ctx, slot),
            .execution_optimistic = try ctx.stateExecutionOptimisticBySlot(slot),
            .finalized = slot <= head.finalized_slot,
        },
    };
}

/// POST /eth/v1/beacon/rewards/sync_committee/{block_id}
///
/// Returns sync committee rewards per validator for the given block.
pub fn getSyncCommitteeRewards(
    ctx: *ApiContext,
    block_id: types.BlockId,
    validator_indices: []const u64,
) !HandlerResult([]const types.SyncCommitteeReward) {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);
    return .{
        .data = try ctx.syncCommitteeRewards(slot_info.root, validator_indices),
        .meta = .{
            .version = forkNameFromSlot(ctx, slot_info.slot),
            .execution_optimistic = slot_info.execution_optimistic,
            .finalized = slot_info.finalized,
        },
    };
}
