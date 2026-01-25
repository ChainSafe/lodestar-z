const std = @import("std");
const napi = @import("zapi:napi");
const c = @import("config");
const state_transition = @import("state_transition");
const BeaconState = state_transition.BeaconState;
const CachedBeaconState = state_transition.CachedBeaconState;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const SignedBlock = state_transition.SignedBlock;
const isExecutionEnabledFunc = state_transition.isExecutionEnabled;
const computeUnrealizedCheckpoints = state_transition.computeUnrealizedCheckpoints;
const getEffectiveBalanceIncrementsZeroInactiveFn = state_transition.getEffectiveBalanceIncrementsZeroInactive;
const processSlotsFn = state_transition.state_transition.processSlots;
const ValidatorStatus = state_transition.ValidatorStatus;
const getValidatorStatus = state_transition.getValidatorStatus;
const getBlockRootAtSlot = state_transition.getBlockRootAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const isMergeTransitionComplete = state_transition.isMergeTransitionComplete;
const getRandaoMix = state_transition.getRandaoMix;
const preset = @import("preset").preset;
const ct = @import("consensus_types");
const pool = @import("./pool.zig");
const config = @import("./config.zig");
const pubkey = @import("./pubkeys.zig");
const sszValueToNapiValue = @import("./to_napi_value.zig").sszValueToNapiValue;
const numberSliceToNapiValue = @import("./to_napi_value.zig").numberSliceToNapiValue;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = gpa.allocator();

pub fn BeaconStateView_finalize(_: napi.Env, cached_state: *CachedBeaconState, _: ?*anyopaque) void {
    cached_state.deinit();
    allocator.destroy(cached_state);
}

pub fn BeaconStateView_ctor(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try allocator.create(CachedBeaconState);
    errdefer allocator.destroy(cached_state);

    _ = try env.wrap(
        cb.this(),
        CachedBeaconState,
        cached_state,
        BeaconStateView_finalize,
        null,
    );

    return cb.this();
}

pub fn BeaconStateView_createFromBytes(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const ctor = cb.this();

    var fork_name_buf: [16]u8 = undefined;
    const fork_name = try cb.arg(0).getValueStringUtf8(&fork_name_buf);
    const fork = c.ForkSeq.fromName(fork_name);

    const bytes_info = try cb.arg(1).getTypedarrayInfo();
    const state = try allocator.create(BeaconState);
    errdefer allocator.destroy(state);

    state.* = try BeaconState.deserialize(allocator, &pool.pool, fork, bytes_info.data);
    errdefer state.deinit();

    const cached_state_value = try env.newInstance(ctor, .{});

    const cached_state = try env.unwrap(CachedBeaconState, cached_state_value);

    try cached_state.init(
        allocator,
        state,
        .{
            .config = &config.config,
            .index_to_pubkey = &pubkey.index2pubkey,
            .pubkey_to_index = &pubkey.pubkey2index,
        },
        null,
    );

    return cached_state_value;
}

pub fn BeaconStateView_slot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot = try cached_state.state.slot();
    return try env.createInt64(@intCast(slot));
}

pub fn BeaconStateView_root(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return sszValueToNapiValue(env, ct.primitive.Root, try cached_state.state.hashTreeRoot());
}

pub fn BeaconStateView_epoch(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot = try cached_state.state.slot();
    return try env.createInt64(@intCast(slot / preset.SLOTS_PER_EPOCH));
}

pub fn BeaconStateView_genesisTime(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return try env.createInt64(@intCast(try cached_state.state.genesisTime()));
}

pub fn BeaconStateView_genesisValidatorsRoot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return sszValueToNapiValue(env, ct.primitive.Root, try cached_state.state.genesisValidatorsRoot());
}

pub fn BeaconStateView_latestBlockHeader(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var header_view = try cached_state.state.latestBlockHeader();
    var header: ct.phase0.BeaconBlockHeader.Type = undefined;
    try header_view.toValue(allocator, &header);
    return try sszValueToNapiValue(env, ct.phase0.BeaconBlockHeader, &header);
}

pub fn BeaconStateView_previousJustifiedCheckpoint(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var cp: ct.phase0.Checkpoint.Type = undefined;
    try cached_state.state.previousJustifiedCheckpoint(&cp);
    return try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp);
}

pub fn BeaconStateView_currentJustifiedCheckpoint(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var cp: ct.phase0.Checkpoint.Type = undefined;
    try cached_state.state.currentJustifiedCheckpoint(&cp);
    return try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp);
}

pub fn BeaconStateView_finalizedCheckpoint(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var cp: ct.phase0.Checkpoint.Type = undefined;
    try cached_state.state.finalizedCheckpoint(&cp);
    return try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp);
}

pub fn BeaconStateView_proposers(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return numberSliceToNapiValue(
        env,
        u64,
        &cached_state.getEpochCache().proposers,
        .{},
    );
}

pub fn BeaconStateView_proposersNextEpoch(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    if (cached_state.getEpochCache().proposers_next_epoch) |*proposers| {
        return numberSliceToNapiValue(
            env,
            u64,
            proposers,
            .{},
        );
    }
    return env.getNull();
}

pub fn BeaconStateView_getBalance(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const index: u64 = @intCast(try cb.arg(0).getValueInt64());
    var balances = try cached_state.state.balances();
    const balance = try balances.get(index);
    return try env.createBigintUint64(balance);
}

pub fn BeaconStateView_isExecutionEnabled(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    // arg 0: fork name
    var fork_name_buf: [16]u8 = undefined;
    const fork_name = try cb.arg(0).getValueStringUtf8(&fork_name_buf);
    const fork = c.ForkSeq.fromName(fork_name);

    // arg 1: signed block bytes
    const bytes_info = try cb.arg(1).getTypedarrayInfo();

    // Deserialize the signed block
    const signed_block = try SignedBeaconBlock.deserialize(allocator, fork, bytes_info.data);
    defer signed_block.deinit(allocator);

    const signed = SignedBlock{ .regular = signed_block };
    const result = isExecutionEnabledFunc(cached_state.state, signed.message());
    return try env.getBoolean(result);
}

pub fn BeaconStateView_getEffectiveBalanceIncrementsZeroInactive(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var result = try getEffectiveBalanceIncrementsZeroInactiveFn(allocator, cached_state);
    defer result.deinit();

    const validator_count = result.items.len;

    // Create Uint16Array to return
    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(validator_count * 2, &arraybuffer_bytes);
    const dest = @as([*]u16, @ptrCast(@alignCast(arraybuffer_bytes)));
    @memcpy(dest[0..validator_count], result.items);

    return try env.createTypedarray(.uint16, validator_count, arraybuffer, 0);
}

pub fn BeaconStateView_isExecutionStateType(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const fork_seq = cached_state.state.forkSeq();
    return try env.getBoolean(fork_seq.gte(.bellatrix));
}

pub fn BeaconStateView_getFinalizedRootProof(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var proof = try cached_state.state.getFinalizedRootProof(allocator);
    defer proof.deinit(allocator);

    const witnesses = std.ArrayListUnmanaged([32]u8).fromOwnedSlice(proof.witnesses);
    return try sszValueToNapiValue(env, ct.misc.Roots, &witnesses);
}

pub fn BeaconStateView_computeUnrealizedCheckpoints(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const result = try computeUnrealizedCheckpoints(cached_state, allocator);

    const obj = try env.createObject();
    try obj.setNamedProperty(
        "justifiedCheckpoint",
        try sszValueToNapiValue(env, ct.phase0.Checkpoint, &result.justified_checkpoint),
    );
    try obj.setNamedProperty(
        "finalizedCheckpoint",
        try sszValueToNapiValue(env, ct.phase0.Checkpoint, &result.finalized_checkpoint),
    );
    return obj;
}

/// Get a validator by index.
pub fn BeaconStateView_getValidator(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const index: u64 = @intCast(try cb.arg(0).getValueInt64());

    var validators = try cached_state.state.validators();
    var validator_view = try validators.get(index);
    var validator: ct.phase0.Validator.Type = undefined;
    try validator_view.toValue(allocator, &validator);

    const obj = try env.createObject();
    // pubkey is 48 bytes, create Uint8Array directly
    var pubkey_bytes: [*]u8 = undefined;
    const pubkey_buf = try env.createArrayBuffer(48, &pubkey_bytes);
    @memcpy(pubkey_bytes[0..48], &validator.pubkey);
    try obj.setNamedProperty("pubkey", try env.createTypedarray(.uint8, 48, pubkey_buf, 0));
    try obj.setNamedProperty("withdrawalCredentials", try sszValueToNapiValue(env, ct.primitive.Bytes32, &validator.withdrawal_credentials));
    try obj.setNamedProperty("effectiveBalance", try env.createBigintUint64(validator.effective_balance));
    try obj.setNamedProperty("slashed", try env.getBoolean(validator.slashed));
    try obj.setNamedProperty("activationEligibilityEpoch", try env.createBigintUint64(validator.activation_eligibility_epoch));
    try obj.setNamedProperty("activationEpoch", try env.createBigintUint64(validator.activation_epoch));
    try obj.setNamedProperty("exitEpoch", try env.createBigintUint64(validator.exit_epoch));
    try obj.setNamedProperty("withdrawableEpoch", try env.createBigintUint64(validator.withdrawable_epoch));
    return obj;
}

/// Get the status of a validator by index.
/// Arguments:
/// - arg 0: validator index (number)
/// Returns: status string
pub fn BeaconStateView_getValidatorStatus(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const index: u64 = @intCast(try cb.arg(0).getValueInt64());
    const current_epoch = cached_state.getEpochCache().epoch;

    var validators = try cached_state.state.validators();
    var validator_view = try validators.get(index);
    var validator: ct.phase0.Validator.Type = undefined;
    try validator_view.toValue(allocator, &validator);

    const status = getValidatorStatus(&validator, current_epoch);
    return try env.createStringUtf8(status.toString());
}

/// Get the total number of validators in the registry.
pub fn BeaconStateView_getValidatorCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var validators = try cached_state.state.validators();
    const count = try validators.length();
    return try env.createInt64(@intCast(count));
}

/// Get the number of active validators at the current epoch.
pub fn BeaconStateView_getActiveValidatorCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch_cache = cached_state.getEpochCache();
    const count = epoch_cache.current_shuffling.get().active_indices.len;
    return try env.createInt64(@intCast(count));
}

/// Get the beacon proposer for a given slot.
/// Arguments:
/// - arg 0: slot (number)
/// Returns: validator index of the proposer
pub fn BeaconStateView_getBeaconProposer(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot: u64 = @intCast(try cb.arg(0).getValueInt64());
    const proposer = try cached_state.getEpochCache().getBeaconProposer(slot);
    return try env.createInt64(@intCast(proposer));
}

/// Get all beacon proposers for the current epoch.
/// Returns: array of validator indices (length = SLOTS_PER_EPOCH)
pub fn BeaconStateView_getBeaconProposers(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return numberSliceToNapiValue(
        env,
        u64,
        &cached_state.getEpochCache().proposers,
        .{},
    );
}

/// Get all beacon proposers for the previous epoch.
/// Returns: array of validator indices or null if not available
pub fn BeaconStateView_getBeaconProposersPrevEpoch(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    if (cached_state.getEpochCache().proposers_prev_epoch) |*proposers| {
        return numberSliceToNapiValue(env, u64, proposers, .{});
    }
    return env.getNull();
}

/// Get all beacon proposers for the next epoch.
/// Returns: array of validator indices or null if not available (pre-Fulu)
pub fn BeaconStateView_getBeaconProposersNextEpoch(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    if (cached_state.getEpochCache().proposers_next_epoch) |*proposers| {
        return numberSliceToNapiValue(env, u64, proposers, .{});
    }
    return env.getNull();
}

/// Get the indexed sync committee at a given epoch.
/// Arguments:
/// - arg 0: epoch (number)
/// Returns: object with validatorIndices (number[])
pub fn BeaconStateView_getIndexedSyncCommitteeAtEpoch(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch: u64 = @intCast(try cb.arg(0).getValueInt64());

    const sync_committee = cached_state.getEpochCache().getIndexedSyncCommitteeAtEpoch(epoch) catch {
        try env.throwError("NO_SYNC_COMMITTEE", "Sync committee not available for requested epoch");
        return env.getNull();
    };

    const obj = try env.createObject();
    try obj.setNamedProperty(
        "validatorIndices",
        try numberSliceToNapiValue(env, u64, sync_committee.getValidatorIndices(), .{}),
    );
    return obj;
}

/// Get the block root at a given slot.
/// Arguments:
/// - arg 0: slot (number)
/// Returns: Root (Uint8Array)
pub fn BeaconStateView_getBlockRootAtSlot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot: u64 = @intCast(try cb.arg(0).getValueInt64());

    const root = getBlockRootAtSlot(cached_state.state, slot) catch |err| {
        const msg = switch (err) {
            error.SlotTooBig => "Can only get block root in the past",
            error.SlotTooSmall => "Cannot get block root more than SLOTS_PER_HISTORICAL_ROOT in the past",
            else => "Failed to get block root",
        };
        try env.throwError("INVALID_SLOT", msg);
        return env.getNull();
    };

    return sszValueToNapiValue(env, ct.primitive.Root, root);
}

/// Get the block root at the start of a given epoch.
/// Arguments:
/// - arg 0: epoch (number)
/// Returns: Root (Uint8Array)
pub fn BeaconStateView_getBlockRoot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch: u64 = @intCast(try cb.arg(0).getValueInt64());
    const slot = computeStartSlotAtEpoch(epoch);

    const root = getBlockRootAtSlot(cached_state.state, slot) catch |err| {
        const msg = switch (err) {
            error.SlotTooBig => "Can only get block root in the past",
            error.SlotTooSmall => "Cannot get block root more than SLOTS_PER_HISTORICAL_ROOT in the past",
            else => "Failed to get block root",
        };
        try env.throwError("INVALID_EPOCH", msg);
        return env.getNull();
    };

    return sszValueToNapiValue(env, ct.primitive.Root, root);
}

/// Check if the merge transition is complete.
/// Returns: boolean
pub fn BeaconStateView_isMergeTransitionComplete(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return env.getBoolean(isMergeTransitionComplete(cached_state.state));
}

/// Get the randao mix at a given epoch.
/// Arguments:
/// - arg 0: epoch (number)
/// Returns: Bytes32 (Uint8Array)
pub fn BeaconStateView_getRandaoMix(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch: u64 = @intCast(try cb.arg(0).getValueInt64());

    const mix = getRandaoMix(cached_state.state, epoch) catch {
        try env.throwError("INVALID_EPOCH", "Failed to get randao mix for epoch");
        return env.getNull();
    };

    return sszValueToNapiValue(env, ct.primitive.Bytes32, mix);
}

/// Get the historical summaries from the state (Capella+).
/// Returns: array of {blockSummaryRoot: Uint8Array, stateSummaryRoot: Uint8Array}
pub fn BeaconStateView_getHistoricalSummaries(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var historical_summaries = cached_state.state.historicalSummaries() catch {
        try env.throwError("STATE_ERROR", "Failed to get historicalSummaries");
        return env.getNull();
    };

    // Bulk read all values at once
    const summaries = historical_summaries.getAllReadonlyValues(allocator) catch {
        try env.throwError("STATE_ERROR", "Failed to get historicalSummaries values");
        return env.getNull();
    };
    defer allocator.free(summaries);

    const result = try env.createArray();
    for (summaries, 0..) |summary, i| {
        const obj = try env.createObject();
        try obj.setNamedProperty("blockSummaryRoot", try sszValueToNapiValue(env, ct.primitive.Root, &summary.block_summary_root));
        try obj.setNamedProperty("stateSummaryRoot", try sszValueToNapiValue(env, ct.primitive.Root, &summary.state_summary_root));
        try result.setElement(@intCast(i), obj);
    }

    return result;
}

/// Get the pending deposits from the state (Electra+).
/// Returns: array of {pubkey, withdrawalCredentials, amount, signature, slot}
pub fn BeaconStateView_getPendingDeposits(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var pending_deposits = cached_state.state.pendingDeposits() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingDeposits");
        return env.getNull();
    };

    const deposits = pending_deposits.getAllReadonlyValues(allocator) catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingDeposits values");
        return env.getNull();
    };
    defer allocator.free(deposits);

    const result = try env.createArray();
    for (deposits, 0..) |deposit, i| {
        const obj = try env.createObject();
        try obj.setNamedProperty("pubkey", try sszValueToNapiValue(env, ct.primitive.BLSPubkey, &deposit.pubkey));
        try obj.setNamedProperty("withdrawalCredentials", try sszValueToNapiValue(env, ct.primitive.Bytes32, &deposit.withdrawal_credentials));
        try obj.setNamedProperty("amount", try env.createBigintUint64(deposit.amount));
        try obj.setNamedProperty("signature", try sszValueToNapiValue(env, ct.primitive.BLSSignature, &deposit.signature));
        try obj.setNamedProperty("slot", try env.createBigintUint64(deposit.slot));
        try result.setElement(@intCast(i), obj);
    }

    return result;
}

/// Get the pending partial withdrawals from the state (Electra+).
pub fn BeaconStateView_getPendingPartialWithdrawals(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var pending_partial_withdrawals = cached_state.state.pendingPartialWithdrawals() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingPartialWithdrawals");
        return env.getNull();
    };

    const withdrawals = pending_partial_withdrawals.getAllReadonlyValues(allocator) catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingPartialWithdrawals values");
        return env.getNull();
    };
    defer allocator.free(withdrawals);

    const result = try env.createArray();
    for (withdrawals, 0..) |withdrawal, i| {
        const obj = try env.createObject();
        try obj.setNamedProperty("validatorIndex", try env.createInt64(@intCast(withdrawal.validator_index)));
        try obj.setNamedProperty("amount", try env.createBigintUint64(withdrawal.amount));
        try obj.setNamedProperty("withdrawableEpoch", try env.createBigintUint64(withdrawal.withdrawable_epoch));
        try result.setElement(@intCast(i), obj);
    }

    return result;
}

/// Get the pending consolidations from the state
pub fn BeaconStateView_getPendingConsolidations(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var pending_consolidations = cached_state.state.pendingConsolidations() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingConsolidations");
        return env.getNull();
    };

    const consolidations = pending_consolidations.getAllReadonlyValues(allocator) catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingConsolidations values");
        return env.getNull();
    };
    defer allocator.free(consolidations);

    const result = try env.createArray();
    for (consolidations, 0..) |consolidation, i| {
        const obj = try env.createObject();
        try obj.setNamedProperty("sourceIndex", try env.createInt64(@intCast(consolidation.source_index)));
        try obj.setNamedProperty("targetIndex", try env.createInt64(@intCast(consolidation.target_index)));
        try result.setElement(@intCast(i), obj);
    }

    return result;
}

/// Get the proposer lookahead from the state (Fulu+).
pub fn BeaconStateView_getProposerLookahead(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var proposer_lookahead = cached_state.state.proposerLookahead() catch {
        try env.throwError("STATE_ERROR", "Failed to get proposerLookahead");
        return env.getNull();
    };

    const lookahead = proposer_lookahead.getAll(allocator) catch {
        try env.throwError("STATE_ERROR", "Failed to get proposerLookahead values");
        return env.getNull();
    };
    defer allocator.free(lookahead);

    return try numberSliceToNapiValue(env, u64, lookahead, .{ .typed_array = .uint32 });
}

/// Get a single Merkle proof  for a node at the given generalized index.
pub fn BeaconStateView_getSingleProof(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const gindex: u64 = @intCast(try cb.arg(0).getValueInt64());

    var proof = cached_state.state.getSingleProof(allocator, gindex) catch {
        try env.throwError("STATE_ERROR", "Failed to get single proof");
        return env.getNull();
    };
    defer proof.deinit(allocator);

    const result = try env.createArray();
    for (proof.witnesses, 0..) |witness, i| {
        var witness_bytes: [*]u8 = undefined;
        const witness_buf = try env.createArrayBuffer(32, &witness_bytes);
        @memcpy(witness_bytes[0..32], &witness);
        try result.setElement(@intCast(i), try env.createTypedarray(.uint8, 32, witness_buf, 0));
    }

    return result;
}

/// Get the proposer rewards for the state.
pub fn BeaconStateView_proposerRewards(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const rewards = cached_state.getProposerRewards();

    const obj = try env.createObject();
    try obj.setNamedProperty(
        "attestations",
        try env.createBigintUint64(rewards.attestations),
    );
    try obj.setNamedProperty(
        "syncAggregate",
        try env.createBigintUint64(rewards.sync_aggregate),
    );
    try obj.setNamedProperty(
        "slashing",
        try env.createBigintUint64(rewards.slashing),
    );
    return obj;
}

/// Process slots from current state slot to target slot, returning a new BeaconStateView.
///
/// Arguments:
/// - arg 0: target slot (number)
/// - arg 1: options object (optional) with `dontTransferCache` boolean
pub fn BeaconStateView_processSlots(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot: u64 = @intCast(try cb.arg(0).getValueInt64());

    var dont_transfer_cache = false;
    if (cb.getArg(1)) |options_arg| {
        if (try options_arg.typeof() == .object) {
            if (try options_arg.hasNamedProperty("dontTransferCache")) {
                dont_transfer_cache = try (try options_arg.getNamedProperty("dontTransferCache")).getValueBool();
            }
        }
    }
    const post_state = try cached_state.clone(allocator, .{ .transfer_cache = !dont_transfer_cache });
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    try processSlotsFn(allocator, post_state, slot, .{});

    const ctor = try cb.this().getNamedProperty("constructor");
    const new_state_value = try env.newInstance(ctor, .{});
    const dummy_state = try env.unwrap(CachedBeaconState, new_state_value);
    dummy_state.* = post_state.*;
    allocator.destroy(post_state);

    return new_state_value;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const beacon_state_view_ctor = try env.defineClass(
        "BeaconStateView",
        0,
        BeaconStateView_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            .{ .utf8name = "slot", .getter = napi.wrapCallback(0, BeaconStateView_slot) },
            .{ .utf8name = "root", .getter = napi.wrapCallback(0, BeaconStateView_root) },
            .{ .utf8name = "epoch", .getter = napi.wrapCallback(0, BeaconStateView_epoch) },
            .{ .utf8name = "genesisTime", .getter = napi.wrapCallback(0, BeaconStateView_genesisTime) },
            .{ .utf8name = "genesisValidatorsRoot", .getter = napi.wrapCallback(0, BeaconStateView_genesisValidatorsRoot) },
            .{ .utf8name = "latestBlockHeader", .getter = napi.wrapCallback(0, BeaconStateView_latestBlockHeader) },
            .{ .utf8name = "previousJustifiedCheckpoint", .getter = napi.wrapCallback(0, BeaconStateView_previousJustifiedCheckpoint) },
            .{ .utf8name = "currentJustifiedCheckpoint", .getter = napi.wrapCallback(0, BeaconStateView_currentJustifiedCheckpoint) },
            .{ .utf8name = "finalizedCheckpoint", .getter = napi.wrapCallback(0, BeaconStateView_finalizedCheckpoint) },
            .{ .utf8name = "proposers", .getter = napi.wrapCallback(0, BeaconStateView_proposers) },
            .{ .utf8name = "proposersNextEpoch", .getter = napi.wrapCallback(0, BeaconStateView_proposersNextEpoch) },
            .{ .utf8name = "getBalance", .method = napi.wrapCallback(1, BeaconStateView_getBalance) },
            .{ .utf8name = "getValidator", .method = napi.wrapCallback(1, BeaconStateView_getValidator) },
            .{ .utf8name = "getValidatorStatus", .method = napi.wrapCallback(1, BeaconStateView_getValidatorStatus) },
            .{ .utf8name = "validatorCount", .getter = napi.wrapCallback(0, BeaconStateView_getValidatorCount) },
            .{ .utf8name = "activeValidatorCount", .getter = napi.wrapCallback(0, BeaconStateView_getActiveValidatorCount) },
            .{ .utf8name = "getBeaconProposer", .method = napi.wrapCallback(1, BeaconStateView_getBeaconProposer) },
            .{ .utf8name = "getBeaconProposers", .method = napi.wrapCallback(0, BeaconStateView_getBeaconProposers) },
            .{ .utf8name = "getBeaconProposersPrevEpoch", .method = napi.wrapCallback(0, BeaconStateView_getBeaconProposersPrevEpoch) },
            .{ .utf8name = "getBeaconProposersNextEpoch", .method = napi.wrapCallback(0, BeaconStateView_getBeaconProposersNextEpoch) },
            .{ .utf8name = "getIndexedSyncCommitteeAtEpoch", .method = napi.wrapCallback(1, BeaconStateView_getIndexedSyncCommitteeAtEpoch) },
            .{ .utf8name = "getBlockRootAtSlot", .method = napi.wrapCallback(1, BeaconStateView_getBlockRootAtSlot) },
            .{ .utf8name = "getBlockRoot", .method = napi.wrapCallback(1, BeaconStateView_getBlockRoot) },
            .{ .utf8name = "isMergeTransitionComplete", .method = napi.wrapCallback(0, BeaconStateView_isMergeTransitionComplete) },
            .{ .utf8name = "getRandaoMix", .method = napi.wrapCallback(1, BeaconStateView_getRandaoMix) },
            .{ .utf8name = "getHistoricalSummaries", .method = napi.wrapCallback(0, BeaconStateView_getHistoricalSummaries) },
            .{ .utf8name = "getPendingDeposits", .method = napi.wrapCallback(0, BeaconStateView_getPendingDeposits) },
            .{ .utf8name = "getPendingPartialWithdrawals", .method = napi.wrapCallback(0, BeaconStateView_getPendingPartialWithdrawals) },
            .{ .utf8name = "getPendingConsolidations", .method = napi.wrapCallback(0, BeaconStateView_getPendingConsolidations) },
            .{ .utf8name = "getProposerLookahead", .method = napi.wrapCallback(0, BeaconStateView_getProposerLookahead) },
            .{ .utf8name = "getSingleProof", .method = napi.wrapCallback(1, BeaconStateView_getSingleProof) },
            .{ .utf8name = "isExecutionEnabled", .method = napi.wrapCallback(2, BeaconStateView_isExecutionEnabled) },
            .{ .utf8name = "isExecutionStateType", .method = napi.wrapCallback(0, BeaconStateView_isExecutionStateType) },
            .{ .utf8name = "getEffectiveBalanceIncrementsZeroInactive", .method = napi.wrapCallback(0, BeaconStateView_getEffectiveBalanceIncrementsZeroInactive) },
            .{ .utf8name = "getFinalizedRootProof", .method = napi.wrapCallback(0, BeaconStateView_getFinalizedRootProof) },
            .{ .utf8name = "computeUnrealizedCheckpoints", .method = napi.wrapCallback(0, BeaconStateView_computeUnrealizedCheckpoints) },
            .{ .utf8name = "processSlots", .method = napi.wrapCallback(1, BeaconStateView_processSlots) },
            .{ .utf8name = "proposerRewards", .getter = napi.wrapCallback(0, BeaconStateView_proposerRewards) },
        },
    );
    // Static method on constructor
    try beacon_state_view_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "createFromBytes",
        .method = napi.wrapCallback(2, BeaconStateView_createFromBytes),
    }});

    try exports.setNamedProperty("BeaconStateView", beacon_state_view_ctor);
}
