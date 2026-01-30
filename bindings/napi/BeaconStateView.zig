const std = @import("std");
const napi = @import("zapi:napi");
const c = @import("config");
const st = @import("state_transition");
const CachedBeaconState = st.CachedBeaconState;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const AnyExecutionPayloadHeader = @import("fork_types").AnyExecutionPayloadHeader;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const preset = @import("preset").preset;
const ct = @import("consensus_types");
const pool = @import("./pool.zig");
const config = @import("./config.zig");
const pubkey = @import("./pubkeys.zig");
const sszValueToNapiValue = @import("./to_napi_value.zig").sszValueToNapiValue;
const numberSliceToNapiValue = @import("./to_napi_value.zig").numberSliceToNapiValue;

const getter = @import("napi_property_descriptor.zig").getter;
const method = @import("napi_property_descriptor.zig").method;

/// Allocator used for all BeaconStateView instances.
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
    const state = try allocator.create(AnyBeaconState);
    errdefer allocator.destroy(state);

    state.* = try AnyBeaconState.deserialize(allocator, &pool.pool, fork, bytes_info.data);
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

pub fn BeaconStateView_fork(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var fork_view = try cached_state.state.fork();
    var fork: ct.phase0.Fork.Type = undefined;
    try fork_view.toValue(allocator, &fork);
    return try sszValueToNapiValue(env, ct.phase0.Fork, &fork);
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

pub fn BeaconStateView_eth1Data(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var eth1_data_view = try cached_state.state.eth1Data();
    var eth1_data: ct.phase0.Eth1Data.Type = undefined;
    try eth1_data_view.toValue(allocator, &eth1_data);
    return try sszValueToNapiValue(env, ct.phase0.Eth1Data, &eth1_data);
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

/// Get the block root at a given slot.
/// Arguments:
/// - arg 0: slot (number)
/// Returns: Root (Uint8Array)
pub fn BeaconStateView_getBlockRoot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot: u64 = @intCast(try cb.arg(0).getValueInt64());

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.getBlockRootAtSlot(f, cached_state.state.castToFork(f), slot),
    };
    const root = result catch |err| {
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

/// Get the randao mix at a given epoch.
/// Arguments:
/// - arg 0: epoch (number)
/// Returns: Bytes32 (Uint8Array)
pub fn BeaconStateView_getRandaoMix(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch: u64 = @intCast(try cb.arg(0).getValueInt64());

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.getRandaoMix(f, cached_state.state.castToFork(f), epoch),
    };
    const mix = result catch {
        try env.throwError("INVALID_EPOCH", "Failed to get randao mix for epoch");
        return env.getNull();
    };

    return sszValueToNapiValue(env, ct.primitive.Bytes32, mix);
}

pub fn BeaconStateView_previousEpochParticipation(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var view = try cached_state.state.previousEpochParticipation();
    var previous_epoch_participation: ct.altair.EpochParticipation.Type = .{};
    try view.toValue(allocator, &previous_epoch_participation);
    defer previous_epoch_participation.deinit(allocator);
    return try sszValueToNapiValue(env, ct.altair.EpochParticipation, &previous_epoch_participation);
}

pub fn BeaconStateView_currentEpochParticipation(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var view = try cached_state.state.currentEpochParticipation();
    var current_epoch_participation: ct.altair.EpochParticipation.Type = .{};
    try view.toValue(allocator, &current_epoch_participation);
    defer current_epoch_participation.deinit(allocator);
    return try sszValueToNapiValue(env, ct.altair.EpochParticipation, &current_epoch_participation);
}

pub fn BeaconStateView_latestExecutionPayloadHeader(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var header: AnyExecutionPayloadHeader = undefined;
    try cached_state.state.latestExecutionPayloadHeader(allocator, &header);
    defer header.deinit(allocator);

    return switch (header) {
        .bellatrix => |*h| try sszValueToNapiValue(env, ct.bellatrix.ExecutionPayloadHeader, h),
        .capella => |*h| try sszValueToNapiValue(env, ct.capella.ExecutionPayloadHeader, h),
        .deneb => |*h| try sszValueToNapiValue(env, ct.deneb.ExecutionPayloadHeader, h),
    };
}

/// Get the historical summaries from the state (Capella+).
/// Returns: array of {blockSummaryRoot: Uint8Array, stateSummaryRoot: Uint8Array}
pub fn BeaconStateView_historicalSummaries(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
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

    const summaries_arraylist = ct.capella.HistoricalSummaries.Type.fromOwnedSlice(summaries);
    return try sszValueToNapiValue(env, ct.capella.HistoricalSummaries, &summaries_arraylist);
}

/// Get the pending deposits from the state (Electra+).
/// Returns: Uint8Array of SSZ serialized PendingDeposits list
pub fn BeaconStateView_pendingDeposits(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var pending_deposits = cached_state.state.pendingDeposits() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingDeposits");
        return env.getNull();
    };

    const size = pending_deposits.serializedSize() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingDeposits size");
        return env.getNull();
    };

    var bytes: [*]u8 = undefined;
    const buf = try env.createArrayBuffer(size, &bytes);
    _ = pending_deposits.serializeIntoBytes(bytes[0..size]) catch {
        try env.throwError("STATE_ERROR", "Failed to serialize pendingDeposits");
        return env.getNull();
    };

    return try env.createTypedarray(.uint8, size, buf, 0);
}

pub fn BeaconStateView_pendingDepositsCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var pending_deposits = try cached_state.state.pendingDeposits();
    return try env.createInt64(@intCast(try pending_deposits.length()));
}

/// Get the pending partial withdrawals from the state (Electra+).
/// Returns: Uint8Array of SSZ serialized PendingPartialWithdrawals list
pub fn BeaconStateView_pendingPartialWithdrawals(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var pending_partial_withdrawals = cached_state.state.pendingPartialWithdrawals() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingPartialWithdrawals");
        return env.getNull();
    };

    const size = pending_partial_withdrawals.serializedSize() catch {
        try env.throwError("STATE_ERROR", "Failed to get pendingPartialWithdrawals size");
        return env.getNull();
    };

    var bytes: [*]u8 = undefined;
    const buf = try env.createArrayBuffer(size, &bytes);
    _ = pending_partial_withdrawals.serializeIntoBytes(bytes[0..size]) catch {
        try env.throwError("STATE_ERROR", "Failed to serialize pendingPartialWithdrawals");
        return env.getNull();
    };

    return try env.createTypedarray(.uint8, size, buf, 0);
}

pub fn BeaconStateView_pendingPartialWithdrawalsCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var pending_partial_withdrawals = try cached_state.state.pendingPartialWithdrawals();
    return try env.createInt64(@intCast(try pending_partial_withdrawals.length()));
}

/// Get the pending consolidations from the state
pub fn BeaconStateView_pendingConsolidations(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
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

    const consolidations_arraylist = ct.electra.PendingConsolidations.Type.fromOwnedSlice(consolidations);
    return try sszValueToNapiValue(env, ct.electra.PendingConsolidations, &consolidations_arraylist);
}

pub fn BeaconStateView_pendingConsolidationsCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var pending_consolidations = try cached_state.state.pendingConsolidations();
    return try env.createInt64(@intCast(try pending_consolidations.length()));
}

/// Get the proposer lookahead from the state (Fulu+).
pub fn BeaconStateView_proposerLookahead(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
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

// pub fn BeaconStateView_executionPayloadAvailability

// pub fn BeaconStateView_getShufflingAtEpoch

/// Get the previous decision root for the state.
pub fn BeaconStateView_previousDecisionRoot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const root = cached_state.previousDecisionRoot();
    return sszValueToNapiValue(env, ct.primitive.Root, &root);
}

/// Get the current decision root for the state.
pub fn BeaconStateView_currentDecisionRoot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const root = cached_state.currentDecisionRoot();
    return sszValueToNapiValue(env, ct.primitive.Root, &root);
}

/// Get the next decision root for the state.
pub fn BeaconStateView_nextDecisionRoot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const root = cached_state.nextDecisionRoot();
    return sszValueToNapiValue(env, ct.primitive.Root, &root);
}

/// Get the shuffling decision root for a given epoch.
pub fn BeaconStateView_getShufflingDecisionRoot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch: u64 = @intCast(try cb.arg(0).getValueInt64());
    const root = st.calculateShufflingDecisionRoot(allocator, cached_state.state, epoch) catch {
        try env.throwError("STATE_ERROR", "Failed to calculate shuffling decision root");
        return env.getNull();
    };
    return sszValueToNapiValue(env, ct.primitive.Root, &root);
}

pub fn BeaconStateView_previousProposers(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    if (cached_state.getEpochCache().proposers_prev_epoch) |*proposers| {
        return numberSliceToNapiValue(
            env,
            u64,
            proposers,
            .{},
        );
    }
    return env.getNull();
}
pub fn BeaconStateView_currentProposers(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return numberSliceToNapiValue(
        env,
        u64,
        &cached_state.getEpochCache().proposers,
        .{},
    );
}

pub fn BeaconStateView_nextProposers(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
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

pub fn BeaconStateView_currentSyncCommittee(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var current_sync_committee = try cached_state.state.currentSyncCommittee();
    var result: ct.altair.SyncCommittee.Type = undefined;
    try current_sync_committee.toValue(allocator, &result);
    return try sszValueToNapiValue(env, ct.altair.SyncCommittee, &result);
}

pub fn BeaconStateView_nextSyncCommittee(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var next_sync_committee = try cached_state.state.nextSyncCommittee();
    var result: ct.altair.SyncCommittee.Type = undefined;
    try next_sync_committee.toValue(allocator, &result);
    return try sszValueToNapiValue(env, ct.altair.SyncCommittee, &result);
}

pub fn BeaconStateView_currentSyncCommitteeIndexed(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const sync_committee_cache = cached_state.getEpochCache().current_sync_committee_indexed.get();
    const validator_indices = sync_committee_cache.getValidatorIndices();
    const validator_index_map = sync_committee_cache.getValidatorIndexMap();
    const obj = try env.createObject();
    try obj.setNamedProperty(
        "validatorIndices",
        try numberSliceToNapiValue(env, u32, @as([]const u32, @ptrCast(validator_indices)), .{ .typed_array = .uint32 }),
    );

    const global = try env.getGlobal();
    const map_ctor = try global.getNamedProperty("Map");
    const map = try env.newInstance(map_ctor, .{});
    const set_fn = try map.getNamedProperty("set");

    // TODO: might need to check the perf here; another way is to send a array instead and convert them in js side.
    var iterator = validator_index_map.iterator();
    while (iterator.next()) |entry| {
        const idx = entry.key_ptr.*;
        const positions = entry.value_ptr;

        const key_value_napi = try env.createInt64(@intCast(idx));
        const positions_napi = try numberSliceToNapiValue(env, u32, @as([]const u32, @ptrCast(positions.items)), .{ .typed_array = .uint32 });

        _ = try env.callFunction(set_fn, map, .{ key_value_napi, positions_napi });
    }

    try obj.setNamedProperty("validatorIndexMap", map);

    return obj;
}

pub fn BeaconStateView_syncProposerReward(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const sync_proposer_reward = cached_state.getEpochCache().sync_proposer_reward;
    return try env.createInt64(@intCast(sync_proposer_reward));
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

pub fn BeaconStateView_effectiveBalanceIncrements(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const increments = cached_state.getEpochCache().getEffectiveBalanceIncrements();
    return try numberSliceToNapiValue(env, u16, increments.items, .{ .typed_array = .uint16 });
}

pub fn BeaconStateView_getEffectiveBalanceIncrementsZeroInactive(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    var result = try st.getEffectiveBalanceIncrementsZeroInactive(allocator, cached_state);
    defer result.deinit();

    return try numberSliceToNapiValue(env, u16, result.items, .{ .typed_array = .uint16 });
}

pub fn BeaconStateView_getBalance(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const index: u64 = @intCast(try cb.arg(0).getValueInt64());
    var balances = try cached_state.state.balances();
    const balance = try balances.get(index);
    return try env.createBigintUint64(balance);
}

/// Get a validator by index.
pub fn BeaconStateView_getValidator(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const index: u64 = @intCast(try cb.arg(0).getValueInt64());

    var validators = try cached_state.state.validators();
    var validator_view = try validators.get(index);
    var validator: ct.phase0.Validator.Type = undefined;
    try validator_view.toValue(allocator, &validator);

    return try sszValueToNapiValue(env, ct.phase0.Validator, &validator);
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

    const status = st.getValidatorStatus(&validator, current_epoch);
    return try env.createStringUtf8(status.toString());
}

/// Get the total number of validators in the registry.
pub fn BeaconStateView_validatorCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const count = try cached_state.state.validatorsCount();
    return try env.createInt64(@intCast(count));
}

/// Get the number of active validators at the current epoch.
pub fn BeaconStateView_activeValidatorCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch_cache = cached_state.getEpochCache();
    const count = epoch_cache.current_shuffling.get().active_indices.len;
    return try env.createInt64(@intCast(count));
}

pub fn BeaconStateView_isExecutionStateType(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const fork_seq = cached_state.state.forkSeq();
    return try env.getBoolean(fork_seq.gte(.bellatrix));
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
    const signed_block = try AnySignedBeaconBlock.deserialize(
        allocator,
        .full,
        fork,
        bytes_info.data,
    );
    defer signed_block.deinit(allocator);

    if (signed_block.forkSeq() != cached_state.state.forkSeq()) {
        try env.throwError("FORK_MISMATCH", "Fork of signed block does not match state fork");
        return env.getNull();
    }
    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| switch (signed_block.blockType()) {
            inline else => |bt| if (comptime bt == .blinded and f.lt(.bellatrix)) {
                return error.InvalidBlockTypeForFork;
            } else st.isExecutionEnabled(
                f,
                cached_state.state.castToFork(f),
                bt,
                signed_block.beaconBlock().castToFork(bt, f),
            ),
        },
    };
    return try env.getBoolean(result);
}

/// Check if the merge transition is complete.
/// Returns: boolean
pub fn BeaconStateView_isMergeTransitionComplete(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.isMergeTransitionComplete(f, cached_state.state.castToFork(f)),
    };
    return env.getBoolean(result);
}

// pub fn BeaconStateView_getExpectedWithdrawals

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

// pub fn BeaconStateView_computeBlockRewards

// pub fn BeaconStateView_computeAttestationRewards

// pub fn BeaconStateView_computeSyncCommitteeRewards

// pub fn BeaconStateView_getLatestWeakSubjectivityCheckpointEpoch

/// Get the validity status of a signed voluntary exit.
pub fn BeaconStateView_getVoluntaryExitValidity(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const verify_signature = try cb.arg(1).getValueBool();

    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    var signed_voluntary_exit: ct.phase0.SignedVoluntaryExit.Type = ct.phase0.SignedVoluntaryExit.default_value;
    ct.phase0.SignedVoluntaryExit.deserializeFromBytes(bytes_info.data, &signed_voluntary_exit) catch {
        try env.throwError("DESERIALIZE_ERROR", "Failed to deserialize SignedVoluntaryExit");
        return env.getNull();
    };

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.getVoluntaryExitValidity(
            f,
            cached_state.config,
            cached_state.getEpochCache(),
            cached_state.state.castToFork(f),
            &signed_voluntary_exit,
            verify_signature,
        ),
    };
    const validity = result catch {
        try env.throwError("VALIDATION_ERROR", "Failed to get voluntary exit validity");
        return env.getNull();
    };

    return env.createStringUtf8(@tagName(validity));
}

/// Check if a signed voluntary exit is valid.
pub fn BeaconStateView_isValidVoluntaryExit(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const verify_signature = try cb.arg(1).getValueBool();

    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    var signed_voluntary_exit: ct.phase0.SignedVoluntaryExit.Type = ct.phase0.SignedVoluntaryExit.default_value;
    ct.phase0.SignedVoluntaryExit.deserializeFromBytes(bytes_info.data, &signed_voluntary_exit) catch {
        try env.throwError("DESERIALIZE_ERROR", "Failed to deserialize SignedVoluntaryExit");
        return env.getNull();
    };

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.isValidVoluntaryExit(
            f,
            cached_state.config,
            cached_state.getEpochCache(),
            cached_state.state.castToFork(f),
            &signed_voluntary_exit,
            verify_signature,
        ),
    };
    const is_valid = result catch {
        try env.throwError("VALIDATION_ERROR", "Failed to validate voluntary exit");
        return env.getNull();
    };

    return env.getBoolean(is_valid);
}

pub fn BeaconStateView_getFinalizedRootProof(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var proof = try cached_state.state.getFinalizedRootProof(allocator);
    defer proof.deinit(allocator);

    const witnesses = std.ArrayListUnmanaged([32]u8).fromOwnedSlice(proof.witnesses);
    return try sszValueToNapiValue(env, ct.misc.Roots, &witnesses);
}

// pub fn BeaconStateView_getSyncCommitteesWitness

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

// pub fn BeaconStateView_createMultiProof

pub fn BeaconStateView_computeUnrealizedCheckpoints(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const result = try st.computeUnrealizedCheckpoints(cached_state, allocator);

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

pub fn BeaconStateView_clonedCount(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return try env.createInt64(@intCast(cached_state.cloned_count));
}

pub fn BeaconStateView_clonedCountWithTransferCache(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return try env.createInt64(@intCast(cached_state.cloned_count_with_transfer_cache));
}

pub fn BeaconStateView_createdWithTransferCache(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    return try env.getBoolean(cached_state.created_with_transfer_cache);
}

// pub fn BeaconStateView_isStateValidatorsNodesPopulated

// pub fn BeaconStateView_loadOtherState

pub fn BeaconStateView_serialize(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const result = try cached_state.state.serialize(allocator);
    return try numberSliceToNapiValue(env, u8, result, .{ .typed_array = .uint8 });
}

pub fn BeaconStateView_serializedSize(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const size = switch (cached_state.state.*) {
        inline else => |*state| try state.serializedSize(),
    };
    return try env.createInt64(@intCast(size));
}

/// arg 0: output: preallocated Uint8Array buffer
/// arg 1: offset: offset of buffer where serialization should start
pub fn BeaconStateView_serializeToBytes(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    const output_info = try cb.arg(0).getTypedarrayInfo();
    if (output_info.array_type != .uint8) {
        return error.InvalidOutputBufferType;
    }

    const offset = try cb.arg(1).getValueUint32();
    if (offset > output_info.length) {
        return error.InvalidOffset;
    }

    const output_slice = output_info.data[offset..];
    const bytes_written = switch (cached_state.state.*) {
        inline else => |*state| try state.serializeIntoBytes(output_slice),
    };

    return try env.createInt64(@intCast(bytes_written));
}

pub fn BeaconStateView_serializeValidators(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var validators_view = try cached_state.state.validators();

    const size = try validators_view.serializedSize();
    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(size, &arraybuffer_bytes);
    _ = try validators_view.serializeIntoBytes(arraybuffer_bytes[0..size]);
    return try env.createTypedarray(.uint8, size, arraybuffer, 0);
}

pub fn BeaconStateView_serializedValidatorsSize(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var validators_view = try cached_state.state.validators();
    const size = try validators_view.serializedSize();
    return try env.createInt64(@intCast(size));
}

pub fn BeaconStateView_serializeValidatorsToBytes(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());

    // arg 0: output
    const output_info = try cb.arg(0).getTypedarrayInfo();
    if (output_info.array_type != .uint8) {
        return error.InvalidOutputBufferType;
    }

    // arg 1: offset
    const offset = try cb.arg(1).getValueUint32();
    if (offset > output_info.length) {
        return error.InvalidOffset;
    }

    var validators_view = try cached_state.state.validators();
    const output_slice = output_info.data[offset..];
    const bytes_written = try validators_view.serializeIntoBytes(output_slice);
    return try env.createInt64(@intCast(bytes_written));
}

pub fn BeaconStateView_hashTreeRoot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const root = try cached_state.state.hashTreeRoot();
    return try numberSliceToNapiValue(env, u8, root, .{ .typed_array = .uint8 });
}

// pub fn BeaconStateView_stateTransition

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

    try st.processSlots(allocator, post_state, slot, .{});

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
            getter(BeaconStateView_slot),
            getter(BeaconStateView_fork),
            getter(BeaconStateView_epoch),
            getter(BeaconStateView_genesisTime),
            getter(BeaconStateView_genesisValidatorsRoot),
            getter(BeaconStateView_eth1Data),
            getter(BeaconStateView_latestBlockHeader),
            getter(BeaconStateView_previousJustifiedCheckpoint),
            getter(BeaconStateView_currentJustifiedCheckpoint),
            getter(BeaconStateView_finalizedCheckpoint),
            method(1, BeaconStateView_getBlockRoot),
            method(1, BeaconStateView_getRandaoMix),
            getter(BeaconStateView_previousEpochParticipation),
            getter(BeaconStateView_currentEpochParticipation),
            getter(BeaconStateView_latestExecutionPayloadHeader),
            getter(BeaconStateView_historicalSummaries),
            getter(BeaconStateView_pendingDeposits),
            getter(BeaconStateView_pendingDepositsCount),
            getter(BeaconStateView_pendingPartialWithdrawals),
            getter(BeaconStateView_pendingPartialWithdrawalsCount),
            getter(BeaconStateView_pendingConsolidations),
            getter(BeaconStateView_pendingConsolidationsCount),
            getter(BeaconStateView_proposerLookahead),
            // getter(BeaconStateView_executionPayloadAvailability),

            // method(1, BeaconStateView_getShufflingAtEpoch),
            getter(BeaconStateView_previousDecisionRoot),
            getter(BeaconStateView_currentDecisionRoot),
            getter(BeaconStateView_nextDecisionRoot),
            method(1, BeaconStateView_getShufflingDecisionRoot),
            getter(BeaconStateView_currentProposers),
            getter(BeaconStateView_nextProposers),
            getter(BeaconStateView_previousProposers),
            method(1, BeaconStateView_getBeaconProposer),
            getter(BeaconStateView_currentSyncCommittee),
            getter(BeaconStateView_nextSyncCommittee),
            getter(BeaconStateView_currentSyncCommitteeIndexed),
            getter(BeaconStateView_syncProposerReward),
            method(1, BeaconStateView_getIndexedSyncCommitteeAtEpoch),

            getter(BeaconStateView_effectiveBalanceIncrements),
            method(0, BeaconStateView_getEffectiveBalanceIncrementsZeroInactive),
            method(1, BeaconStateView_getBalance),
            method(1, BeaconStateView_getValidator),
            method(1, BeaconStateView_getValidatorStatus),
            getter(BeaconStateView_validatorCount),
            getter(BeaconStateView_activeValidatorCount),

            getter(BeaconStateView_isMergeTransitionComplete),
            getter(BeaconStateView_isExecutionStateType),
            method(2, BeaconStateView_isExecutionEnabled),

            // method(0, BeaconStateView_getExpectedWithdrawals),

            getter(BeaconStateView_proposerRewards),
            // method(2, BeaconStateView_computeBlockRewards),
            // method(2, BeaconStateView_computeAttestationRewards),
            // method(2, BeaconStateView_computeSyncCommitteeRewards),
            // method(0, BeaconStateView_getLatestWeakSubjectivityCheckpointEpoch),

            method(2, BeaconStateView_getVoluntaryExitValidity),
            method(2, BeaconStateView_isValidVoluntaryExit),

            method(0, BeaconStateView_getFinalizedRootProof),
            // method(1, BeaconStateView_getSyncCommitteesWitness),
            method(1, BeaconStateView_getSingleProof),
            // method(1, BeaconStateView_createMultiProof),

            method(0, BeaconStateView_computeUnrealizedCheckpoints),

            getter(BeaconStateView_clonedCount),
            getter(BeaconStateView_clonedCountWithTransferCache),
            getter(BeaconStateView_createdWithTransferCache),
            // getter(BeaconStateView_isStateValidatorsNodesPopulated),

            // method(2, BeaconStateView_loadOtherState),
            method(0, BeaconStateView_serialize),
            method(0, BeaconStateView_serializedSize),
            method(2, BeaconStateView_serializeToBytes),
            method(0, BeaconStateView_serializeValidators),
            method(0, BeaconStateView_serializedValidatorsSize),
            method(2, BeaconStateView_serializeValidatorsToBytes),

            method(0, BeaconStateView_hashTreeRoot),

            // method(2, BeaconStateView_stateTransition),
            method(1, BeaconStateView_processSlots),
        },
    );
    // Static method on constructor
    try beacon_state_view_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "createFromBytes",
        .method = napi.wrapCallback(2, BeaconStateView_createFromBytes),
    }});

    try exports.setNamedProperty("BeaconStateView", beacon_state_view_ctor);
}
