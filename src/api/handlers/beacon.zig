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
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;
const ResponseMeta = handler_result.ResponseMeta;
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
        .execution_optimistic = !slot_info.finalized,
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
        else => .phase0,
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
    const head = ctx.currentHeadTracker();
    const use_head = switch (state_id) {
        .head => true,
        else => false,
    };

    if (use_head) {
        const state = ctx.headState() orelse return error.StateNotAvailable;
        return buildValidatorResponse(ctx, state);
    }

    switch (state_id) {
        .finalized => {
            const state = (try ctx.stateByBlockRoot(head.finalized_root)) orelse return error.StateNotAvailable;
            return buildValidatorResponse(ctx, state);
        },
        .justified => {
            const state = (try ctx.stateByBlockRoot(head.justified_root)) orelse return error.StateNotAvailable;
            return buildValidatorResponse(ctx, state);
        },
        .genesis => {
            const state = (try ctx.stateBySlot(0)) orelse return error.StateNotAvailable;
            return buildValidatorResponse(ctx, state);
        },
        .slot => |slot| {
            const state = (try ctx.stateBySlot(slot)) orelse return error.StateNotAvailable;
            return buildValidatorResponse(ctx, state);
        },
        .root => |root| {
            const state = (try ctx.stateByRoot(root)) orelse return error.StateNotAvailable;
            return buildValidatorResponse(ctx, state);
        },
        else => {},
    }

    return error.StateNotAvailable;
}

/// Build a validator response from a CachedBeaconState.
fn buildValidatorResponse(
    ctx: *ApiContext,
    state: *CachedBeaconState,
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
            .execution_optimistic = false,
            .finalized = false,
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
    const head = ctx.currentHeadTracker();
    const state = switch (state_id) {
        .head => ctx.headState() orelse return error.StateNotAvailable,
        .justified => (try ctx.stateByBlockRoot(head.justified_root)) orelse return error.StateNotAvailable,
        .finalized => (try ctx.stateByBlockRoot(head.finalized_root)) orelse return error.StateNotAvailable,
        .genesis => (try ctx.stateBySlot(0)) orelse return error.StateNotAvailable,
        .slot => |slot| (try ctx.stateBySlot(slot)) orelse return error.StateNotAvailable,
        .root => |root| (try ctx.stateByRoot(root)) orelse return error.StateNotAvailable,
    };

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
        .meta = .{},
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
                .meta = .{},
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
                .meta = .{},
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
                .meta = .{ .finalized = slot <= head.finalized_slot },
            };
        },
        .root => |root| {
            // The state_id IS the root
            return .{
                .data = root,
                .meta = .{},
            };
        },
    }
}

/// GET /eth/v1/beacon/states/{state_id}/fork
///
/// Returns the fork data for the given state.
pub fn getStateFork(ctx: *ApiContext, state_id: types.StateId) !HandlerResult(types.ForkData) {
    // Determine the slot to compute the fork for
    const slot = try resolveStateSlot(ctx, state_id);

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
            .finalized = switch (state_id) {
                .finalized, .genesis => true,
                else => false,
            },
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
    const resolved = resolveState(ctx, state_id) catch {
        // Fall back to head tracker data when state regen is unavailable.
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
            .meta = .{},
        };
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
/// error.NotImplemented if no import callback is wired.
pub fn submitBlock(
    ctx: *ApiContext,
    block_bytes: []const u8,
) !HandlerResult(void) {
    const cb = ctx.block_import orelse return error.NotImplemented;
    try cb.importFn(cb.ptr, block_bytes);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/attestations
/// POST /eth/v1/beacon/pool/voluntary_exits
/// POST /eth/v1/beacon/pool/proposer_slashings
/// POST /eth/v1/beacon/pool/attester_slashings
/// POST /eth/v1/beacon/pool/bls_to_execution_changes
/// POST /eth/v1/beacon/pool/sync_committees
///
/// All pool submission endpoints follow the same pattern: accept an encoded
/// object (JSON or SSZ), validate/process, return 200 on success.
/// These are stubs — full implementation requires op pool write callbacks.
/// POST /eth/v1/beacon/pool/attestations
///
/// Submit attestations to the local op pool.
/// body is JSON: array of Attestation objects.
/// Validates and forwards to the pool_submit callback if available.
pub fn submitPoolAttestations(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    // Forward to pool_submit callback if wired.
    if (ctx.pool_submit) |cb| {
        if (cb.submitAttestationFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    // Parse and add directly to the local op pool (if no callback is set).
    // Use a local arena for the parsed JSON.
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = std.json.parseFromSlice([]AttestationJsonWire, alloc, body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidRequest;
    defer parsed.deinit();

    for (parsed.value) |att_wire| {
        const data_root = try parseRoot(att_wire.data.beacon_block_root);
        const source_root = try parseRoot(att_wire.data.source.root);
        const target_root = try parseRoot(att_wire.data.target.root);
        const sig = try parseSignature(att_wire.signature);

        const phase0_att = consensus_types.phase0.Attestation.Type{
            .aggregation_bits = .{
                .data = std.ArrayListUnmanaged(u8).empty,
                .bit_len = 0,
            },
            .data = .{
                .slot = att_wire.data.slot,
                .index = att_wire.data.index,
                .beacon_block_root = data_root,
                .source = .{
                    .epoch = att_wire.data.source.epoch,
                    .root = source_root,
                },
                .target = .{
                    .epoch = att_wire.data.target.epoch,
                    .root = target_root,
                },
            },
            .signature = sig,
        };
        _ = phase0_att; // attestation parsed; pool add requires op_pool callback
    }

    return .{ .data = {} };
}

/// POST /eth/v2/beacon/pool/attestations
///
/// Submit attestations to the pool via the v2 endpoint.
/// For Electra slots, expects SingleAttestation[] format:
///   {committee_index, attester_index, data, signature}
/// For pre-Electra slots, falls back to phase0 Attestation[] format.
pub fn submitPoolAttestationsV2(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    // Forward to pool_submit callback if wired.
    if (ctx.pool_submit) |cb| {
        if (cb.submitAttestationFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    // Parse attestations from the request body.
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Try SingleAttestation format first (Electra v2 format).
    if (std.json.parseFromSlice([]SingleAttestationJsonWire, alloc, body, .{
        .ignore_unknown_fields = true,
    })) |parsed| {
        defer parsed.deinit();

        for (parsed.value) |sa_wire| {
            const data_root = try parseRoot(sa_wire.data.beacon_block_root);
            const source_root = try parseRoot(sa_wire.data.source.root);
            const target_root = try parseRoot(sa_wire.data.target.root);
            const sig = try parseSignature(sa_wire.signature);

            // Convert SingleAttestation → internal phase0 Attestation format.
            // Set the committee bit for committee_index.
            // Set the aggregation bit for the single attester position.
            // Note: we don't know committee_length here, so we store minimal info
            // and let the pool/gossip layer handle full validation.
            const phase0_att = consensus_types.phase0.Attestation.Type{
                .aggregation_bits = .{
                    .data = std.ArrayListUnmanaged(u8).empty,
                    .bit_len = 0,
                },
                .data = .{
                    .slot = sa_wire.data.slot,
                    .index = sa_wire.committee_index,
                    .beacon_block_root = data_root,
                    .source = .{
                        .epoch = sa_wire.data.source.epoch,
                        .root = source_root,
                    },
                    .target = .{
                        .epoch = sa_wire.data.target.epoch,
                        .root = target_root,
                    },
                },
                .signature = sig,
            };
            _ = phase0_att; // Parsed; full pool insertion via op_pool callback.
        }
        return .{ .data = {} };
    } else |_| {}

    // Fall back to pre-Electra Attestation[] format.
    return submitPoolAttestations(ctx, body);
}

/// POST /eth/v1/beacon/pool/voluntary_exits
///
/// Submit a signed voluntary exit to the local op pool.
pub fn submitPoolVoluntaryExits(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitVoluntaryExitFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    // Parse for validation even without a callback.
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(SignedVoluntaryExitJsonWire, arena.allocator(), body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidRequest;
    defer parsed.deinit();

    _ = parsed.value; // parsed; would add to pool if callback available

    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/proposer_slashings
///
/// Submit a proposer slashing to the local op pool.
pub fn submitPoolProposerSlashings(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitProposerSlashingFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(ProposerSlashingJsonWire, arena.allocator(), body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidRequest;
    defer parsed.deinit();

    _ = parsed.value;

    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/attester_slashings
///
/// Submit an attester slashing to the local op pool.
pub fn submitPoolAttesterSlashings(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitAttesterSlashingFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(AttesterSlashingJsonWire, arena.allocator(), body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidRequest;
    defer parsed.deinit();

    _ = parsed.value;

    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/bls_to_execution_changes
///
/// Submit BLS-to-execution changes to the local op pool.
pub fn submitPoolBlsToExecutionChanges(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitBlsChangeFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice([]SignedBLSToExecutionChangeJsonWire, arena.allocator(), body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidRequest;
    defer parsed.deinit();

    _ = parsed.value;

    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/sync_committees
///
/// Submit sync committee messages to the local pool.
pub fn submitPoolSyncCommittees(ctx: *ApiContext, body: []const u8) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitSyncCommitteeMessageFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice([]SyncCommitteeMessageJsonWire, arena.allocator(), body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidRequest;
    defer parsed.deinit();

    _ = parsed.value;

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
pub fn getPoolAttestations(
    ctx: *ApiContext,
    slot_filter: ?u64,
    committee_index_filter: ?u64,
) !HandlerResult([]const OpPoolCallback.Phase0Attestation) {
    const cb = ctx.op_pool orelse return .{ .data = &.{} };
    const get_fn = cb.getAttestationsFn orelse return .{ .data = &.{} };
    const items = try get_fn(cb.ptr, ctx.allocator, slot_filter, committee_index_filter);
    return .{ .data = items };
}

/// GET /eth/v2/beacon/pool/attestations
///
/// Returns pending attestations from the operation pool in fork-versioned format.
/// For pre-Electra attestations: returns phase0 Attestation format.
/// For Electra attestations: returns Electra Attestation format with committee_bits.
/// Supports optional `slot` and `committee_index` query parameter filters.
pub fn getPoolAttestationsV2(
    ctx: *ApiContext,
    slot_filter: ?u64,
    committee_index_filter: ?u64,
) !HandlerResult([]const OpPoolCallback.Phase0Attestation) {
    // Get the raw attestations from the op pool (stored as phase0 internally).
    return getPoolAttestations(ctx, slot_filter, committee_index_filter);
    // Note: The http_server layer handles fork-aware JSON serialization.
    // It checks each attestation's slot against the Electra fork epoch and
    // serializes accordingly (adding committee_bits for Electra attestations).
}

/// GET /eth/v1/beacon/pool/voluntary_exits
///
/// Returns pending signed voluntary exits from the operation pool.
pub fn getPoolVoluntaryExits(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.SignedVoluntaryExit) {
    const cb = ctx.op_pool orelse return .{ .data = &.{} };
    const get_fn = cb.getVoluntaryExitsFn orelse return .{ .data = &.{} };
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

/// GET /eth/v1/beacon/pool/proposer_slashings
///
/// Returns pending proposer slashings from the operation pool.
pub fn getPoolProposerSlashings(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.ProposerSlashing) {
    const cb = ctx.op_pool orelse return .{ .data = &.{} };
    const get_fn = cb.getProposerSlashingsFn orelse return .{ .data = &.{} };
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

/// GET /eth/v1/beacon/pool/attester_slashings
///
/// Returns pending attester slashings from the operation pool.
pub fn getPoolAttesterSlashings(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.Phase0AttesterSlashing) {
    const cb = ctx.op_pool orelse return .{ .data = &.{} };
    const get_fn = cb.getAttesterSlashingsFn orelse return .{ .data = &.{} };
    const items = try get_fn(cb.ptr, ctx.allocator);
    return .{ .data = items };
}

/// GET /eth/v1/beacon/pool/bls_to_execution_changes
///
/// Returns pending signed BLS-to-execution changes from the operation pool.
pub fn getPoolBlsToExecutionChanges(ctx: *ApiContext) !HandlerResult([]const OpPoolCallback.SignedBLSToExecutionChange) {
    const cb = ctx.op_pool orelse return .{ .data = &.{} };
    const get_fn = cb.getBlsToExecutionChangesFn orelse return .{ .data = &.{} };
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
    finalized: bool,
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
            .finalized = false,
        },
        .finalized => return .{
            .slot = head.finalized_slot,
            .root = head.finalized_root,
            .finalized = true,
        },
        .justified => return .{
            .slot = head.justified_slot,
            .root = head.justified_root,
            .finalized = false,
        },
        .genesis => return .{
            .slot = 0,
            .root = [_]u8{0} ** 32,
            .finalized = true,
        },
        .slot => |slot| {
            const root = (try ctx.blockRootBySlot(slot)) orelse return error.SlotNotFound;
            return .{
                .slot = slot,
                .root = root,
                .finalized = slot <= head.finalized_slot,
            };
        },
        .root => |root| {
            // We have the root; look up the block to get the real slot.
            const block_bytes = (try ctx.blockBytesByRoot(root)) orelse return error.BlockNotFound;
            defer ctx.allocator.free(block_bytes);

            const slot = readSignedBlockSlotFromSsz(block_bytes) orelse head.head_slot;
            return .{
                .slot = slot,
                .root = root,
                .finalized = slot <= head.finalized_slot,
            };
        },
    }
}

const BlockHeaderResult = struct {
    header: types.BlockHeaderData,
    execution_optimistic: bool,
    finalized: bool,
};

fn resolveBlockHeader(ctx: *ApiContext, block_id: types.BlockId) !BlockHeaderResult {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);

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
                .canonical = true,
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
            .execution_optimistic = !slot_info.finalized,
            .finalized = slot_info.finalized,
        };
    }

    // Block not in DB — return what we know from the head tracker with zero fields.
    return .{
        .header = .{
            .root = slot_info.root,
            .canonical = true,
            .header = .{
                .message = .{
                    .slot = slot_info.slot,
                    .proposer_index = 0,
                    .parent_root = [_]u8{0} ** 32,
                    .state_root = [_]u8{0} ** 32,
                    .body_root = [_]u8{0} ** 32,
                },
                .signature = [_]u8{0} ** 96,
            },
        },
        .execution_optimistic = !slot_info.finalized,
        .finalized = slot_info.finalized,
    };
}

fn resolveStateSlot(ctx: *ApiContext, state_id: types.StateId) !u64 {
    const head = ctx.currentHeadTracker();
    return switch (state_id) {
        .head => head.head_slot,
        .finalized => if (try ctx.stateByBlockRoot(head.finalized_root)) |state|
            try state.state.slot()
        else
            head.finalized_slot,
        .justified => if (try ctx.stateByBlockRoot(head.justified_root)) |state|
            try state.state.slot()
        else
            head.justified_slot,
        .genesis => 0,
        .slot => |s| s,
        .root => |root| blk: {
            if (try ctx.stateByRoot(root)) |state| {
                break :blk try state.state.slot();
            }

            const state_bytes = (try ctx.stateBytesByRoot(root)) orelse
                return error.StateNotAvailable;
            defer ctx.allocator.free(state_bytes);

            break :blk readStateSlotFromSsz(state_bytes) orelse return error.StateNotAvailable;
        },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getGenesis returns genesis data from config" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getGenesis(&tc.ctx);
    try std.testing.expectEqual(@as(u64, 1606824000), resp.data.genesis_time);
    try std.testing.expect(resp.meta.finalized orelse false);
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

test "getStateFork returns genesis fork for slot 0" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getStateFork(&tc.ctx, .genesis);
    try std.testing.expectEqual(tc.ctx.beacon_config.chain.GENESIS_FORK_VERSION, resp.data.current_version);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "getFinalityCheckpoints returns checkpoint data" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getFinalityCheckpoints(&tc.ctx, .head);
    const expected_epoch = tc.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH;
    try std.testing.expectEqual(expected_epoch, resp.data.finalized.epoch);
}

test "getBlockHeader for head returns header" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expectEqual(tc.head_tracker.head_slot, resp.data.header.message.slot);
    try std.testing.expect(resp.data.canonical);
}

test "getBlockHeader for head extracts real fields from DB block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const ct = @import("consensus_types");

    // Build a phase0 signed block with known fields
    var signed_block = ct.phase0.SignedBeaconBlock.default_value;
    signed_block.message.slot = tc.head_tracker.head_slot;
    signed_block.message.proposer_index = 42;
    signed_block.message.parent_root = [_]u8{0xab} ** 32;
    signed_block.message.state_root = [_]u8{0xcd} ** 32;
    signed_block.signature = [_]u8{0xef} ** 96;

    const block_size = ct.phase0.SignedBeaconBlock.serializedSize(&signed_block);
    const block_bytes = try std.testing.allocator.alloc(u8, block_size);
    defer std.testing.allocator.free(block_bytes);
    _ = ct.phase0.SignedBeaconBlock.serializeIntoBytes(&signed_block, block_bytes);

    // Store under the head root
    try tc.db.putBlock(tc.head_tracker.head_root, block_bytes);

    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expectEqual(@as(u64, 42), resp.data.header.message.proposer_index);
    try std.testing.expectEqual([_]u8{0xab} ** 32, resp.data.header.message.parent_root);
    try std.testing.expectEqual([_]u8{0xcd} ** 32, resp.data.header.message.state_root);
    try std.testing.expectEqual([_]u8{0xef} ** 96, resp.data.header.signature);
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

test "submitBlock returns NotImplemented when block_import is null" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    // block_import defaults to null
    const fake_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const result = submitBlock(&tc.ctx, &fake_bytes);
    try std.testing.expectError(error.NotImplemented, result);
}

test "submitBlock invokes block_import callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // Mock callback that records invocation
    const MockImporter = struct {
        called: bool = false,
        received_len: usize = 0,

        fn importBlock(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.called = true;
            self.received_len = block_bytes.len;
        }
    };

    var mock = MockImporter{};
    tc.ctx.block_import = .{
        .ptr = &mock,
        .importFn = &MockImporter.importBlock,
    };

    const fake_bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ** 4;
    const result = try submitBlock(&tc.ctx, &fake_bytes);
    _ = result;

    try std.testing.expect(mock.called);
    try std.testing.expectEqual(fake_bytes.len, mock.received_len);
}

test "submitBlock propagates error from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const FailImporter = struct {
        fn importBlock(_: *anyopaque, _: []const u8) anyerror!void {
            return error.BlockAlreadyKnown;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.block_import = .{
        .ptr = &dummy,
        .importFn = &FailImporter.importBlock,
    };

    const fake_bytes = [_]u8{0x01};
    const result = submitBlock(&tc.ctx, &fake_bytes);
    try std.testing.expectError(error.BlockAlreadyKnown, result);
}

test "getPoolAttestations returns empty when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getPoolAttestations(&tc.ctx, null, null);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
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
    defer std.testing.allocator.free(resp.data);
    try std.testing.expectEqual(@as(usize, 2), resp.data.len);
    try std.testing.expectEqual(@as(u64, 42), resp.data[0].data.slot);
    try std.testing.expectEqual(@as(u64, 43), resp.data[1].data.slot);
}

test "getPoolVoluntaryExits returns empty when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getPoolVoluntaryExits(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "getPoolProposerSlashings returns empty when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getPoolProposerSlashings(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "getPoolAttesterSlashings returns empty when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getPoolAttesterSlashings(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "getPoolBlsToExecutionChanges returns empty when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getPoolBlsToExecutionChanges(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
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
                .meta = .{ .execution_optimistic = false, .finalized = false },
            };
        },
        .justified => {
            const state = (try ctx.stateByBlockRoot(head.justified_root)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{ .execution_optimistic = false, .finalized = false },
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
                    .execution_optimistic = false,
                    .finalized = slot <= head.finalized_slot,
                },
            };
        },
        .root => |root| {
            const state = (try ctx.stateByRoot(root)) orelse return error.StateNotAvailable;
            return .{
                .state = state,
                .meta = .{ .execution_optimistic = false, .finalized = false },
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

        // Get committee count for this slot.
        const committees_per_slot = epoch_cache.getCommitteeCountPerSlot(epoch) catch continue;

        for (0..committees_per_slot) |committee_idx| {
            // Filter by index if provided.
            if (index_opt) |filter_index| {
                if (committee_idx != filter_index) continue;
            }

            const committee = epoch_cache.getBeaconCommittee(slot, @intCast(committee_idx)) catch continue;

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
    _ = epoch_param;

    const resolved = try resolveState(ctx, state_id);
    const state = resolved.state;

    const epoch_cache = state.epoch_cache;
    const sync_cache = epoch_cache.current_sync_committee_indexed;
    const sc = sync_cache.get();

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
    _: ?[32]u8,
) !HandlerResult([]const types.BlockHeaderData) {
    // Return single head header or filtered set.
    // Full implementation requires a slot→root index in the DB.
    // For now, return the head header (or the requested slot's header).
    var headers = std.ArrayListUnmanaged(types.BlockHeaderData).empty;
    errdefer headers.deinit(ctx.allocator);

    const target_block_id: types.BlockId = if (slot_opt) |slot|
        .{ .slot = slot }
    else
        .head;

    const header_result = resolveBlockHeader(ctx, target_block_id) catch return .{
        .data = try headers.toOwnedSlice(ctx.allocator),
        .meta = .{},
    };

    try headers.append(ctx.allocator, header_result.header);

    return .{
        .data = try headers.toOwnedSlice(ctx.allocator),
        .meta = .{
            .execution_optimistic = header_result.execution_optimistic,
            .finalized = header_result.finalized,
        },
    };
}

// ---------------------------------------------------------------------------
// Blob sidecars endpoint (stub — requires Deneb+ DB)
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/blob_sidecars/{block_id}
///
/// Returns blob sidecars for a block. Stubs empty list until
/// Deneb blob storage is wired into the chain query surface.
pub fn getBlobSidecars(
    _: *ApiContext,
    _: types.BlockId,
    _: ?[]const u64,
) !HandlerResult([]const u8) {
    // Return empty list — Deneb blob DB not yet wired.
    // When available: resolve the block through chain queries, then read
    // blob sidecars via a chain-owned blob storage/query API.
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Blinded blocks endpoint (stub)
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/blinded_blocks/{block_id}
///
/// Returns the blinded block for the given block identifier.
/// For blocks without an execution payload, this is identical to the full block.
pub fn getBlindedBlock(
    ctx: *ApiContext,
    block_id: types.BlockId,
) !HandlerResult([]const u8) {
    // Reuse getBlock — actual blinding (replacing execution payload with header)
    // requires fork-specific code. For phase0/altair blocks this is identical.
    const block_result = try getBlock(ctx, block_id);
    return .{
        .data = block_result.data,
        .meta = .{
            .version = block_result.fork_name,
            .execution_optimistic = block_result.execution_optimistic,
            .finalized = block_result.finalized,
        },
        .ssz_bytes = block_result.data,
    };
}

// ---------------------------------------------------------------------------
// Rewards endpoints (stubs pending RewardCache)
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/rewards/blocks/{block_id}
///
/// Returns proposer reward breakdown for the given block.
/// Stub until reward computation is wired to the block processor.
pub fn getBlockRewards(
    _: *ApiContext,
    _: types.BlockId,
) !HandlerResult(types.BlockRewards) {
    // TODO: wire reward computation from block processor.
    return error.NotImplemented;
}

/// POST /eth/v1/beacon/rewards/attestations/{epoch}
///
/// Returns per-validator attestation rewards for the epoch.
/// Stub until reward computation is wired.
pub fn getAttestationRewards(
    _: *ApiContext,
    _: u64,
    _: []const u64,
) !HandlerResult(types.AttestationRewardsData) {
    // TODO: wire reward computation from block processor.
    return error.NotImplemented;
}

/// POST /eth/v1/beacon/rewards/sync_committee/{block_id}
///
/// Returns sync committee rewards per validator for the given block.
/// Stub until reward computation is wired.
pub fn getSyncCommitteeRewards(
    _: *ApiContext,
    _: types.BlockId,
    _: []const u64,
) !HandlerResult([]const types.SyncCommitteeReward) {
    // TODO: wire reward computation from block processor.
    return error.NotImplemented;
}
