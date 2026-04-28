const std = @import("std");
const napi = @import("zapi:zapi").napi;
const js = @import("zapi:zapi").js;
const c = @import("config");
const fork_types = @import("fork_types");
const st = @import("state_transition");
const CachedBeaconState = st.CachedBeaconState;
const AnyBeaconState = fork_types.AnyBeaconState;
const AnyExecutionPayloadHeader = fork_types.AnyExecutionPayloadHeader;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const preset = @import("preset").preset;
const ct = @import("consensus_types");
const pool = @import("./pool.zig");
const config = @import("./config.zig");
const pubkey = @import("./pubkeys.zig");
const js_types = @import("./js_types.zig");
const sszValueToNapiValue = @import("./to_napi_value.zig").sszValueToNapiValue;
const numberSliceToNapiValue = @import("./to_napi_value.zig").numberSliceToNapiValue;
const napi_io = @import("./io.zig");

/// Allocator used for all BeaconStateView instances.
var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = gpa.allocator();

pub const js_meta = js.class(.{ .properties = .{
    .slot = js.prop(.{ .get = true, .set = false }),
    .fork = js.prop(.{ .get = true, .set = false }),
    .epoch = js.prop(.{ .get = true, .set = false }),
    .genesisTime = js.prop(.{ .get = true, .set = false }),
    .genesisValidatorsRoot = js.prop(.{ .get = true, .set = false }),
    .eth1Data = js.prop(.{ .get = true, .set = false }),
    .latestBlockHeader = js.prop(.{ .get = true, .set = false }),
    .previousJustifiedCheckpoint = js.prop(.{ .get = true, .set = false }),
    .currentJustifiedCheckpoint = js.prop(.{ .get = true, .set = false }),
    .finalizedCheckpoint = js.prop(.{ .get = true, .set = false }),
    .previousEpochParticipation = js.prop(.{ .get = true, .set = false }),
    .currentEpochParticipation = js.prop(.{ .get = true, .set = false }),
    .latestExecutionPayloadHeader = js.prop(.{ .get = true, .set = false }),
    .historicalSummaries = js.prop(.{ .get = true, .set = false }),
    .pendingDeposits = js.prop(.{ .get = true, .set = false }),
    .pendingDepositsCount = js.prop(.{ .get = true, .set = false }),
    .pendingPartialWithdrawals = js.prop(.{ .get = true, .set = false }),
    .pendingPartialWithdrawalsCount = js.prop(.{ .get = true, .set = false }),
    .pendingConsolidations = js.prop(.{ .get = true, .set = false }),
    .pendingConsolidationsCount = js.prop(.{ .get = true, .set = false }),
    .proposerLookahead = js.prop(.{ .get = true, .set = false }),
    .previousDecisionRoot = js.prop(.{ .get = true, .set = false }),
    .currentDecisionRoot = js.prop(.{ .get = true, .set = false }),
    .nextDecisionRoot = js.prop(.{ .get = true, .set = false }),
    .currentProposers = js.prop(.{ .get = true, .set = false }),
    .nextProposers = js.prop(.{ .get = true, .set = false }),
    .previousProposers = js.prop(.{ .get = true, .set = false }),
    .currentSyncCommittee = js.prop(.{ .get = true, .set = false }),
    .currentSyncCommitteeIndexed = js.prop(.{ .get = true, .set = false }),
    .nextSyncCommittee = js.prop(.{ .get = true, .set = false }),
    .syncProposerReward = js.prop(.{ .get = true, .set = false }),
    .effectiveBalanceIncrements = js.prop(.{ .get = true, .set = false }),
    .validatorCount = js.prop(.{ .get = true, .set = false }),
    .activeValidatorCount = js.prop(.{ .get = true, .set = false }),
    .isMergeTransitionComplete = js.prop(.{ .get = true, .set = false }),
    .isExecutionStateType = js.prop(.{ .get = true, .set = false }),
    .proposerRewards = js.prop(.{ .get = true, .set = false }),
    .clonedCount = js.prop(.{ .get = true, .set = false }),
    .clonedCountWithTransferCache = js.prop(.{ .get = true, .set = false }),
    .createdWithTransferCache = js.prop(.{ .get = true, .set = false }),
} });

cached_state: ?*CachedBeaconState = null,
const Self = @This();

pub fn init() Self {
    return .{};
}

pub fn deinit(self: *Self) void {
    if (self.cached_state) |cached_state| {
        cached_state.deinit();
        allocator.destroy(cached_state);
        self.cached_state = null;
    }
}

// -------------------------
// Class Methods
// -------------------------
pub fn createFromBytes(bytes: js.Uint8Array) !Self {
    const state = try allocator.create(AnyBeaconState);
    errdefer allocator.destroy(state);

    const byte_slice = try bytes.toSlice();
    const slot_value = fork_types.readSlotFromAnyBeaconStateBytes(byte_slice);
    const fork_seq = config.state.config.forkSeq(slot_value);
    state.* = try AnyBeaconState.deserialize(allocator, &pool.state.pool, fork_seq, byte_slice);
    errdefer state.deinit();

    const cached_state = try allocator.create(CachedBeaconState);
    errdefer allocator.destroy(cached_state);

    try cached_state.init(
        allocator,
        state,
        .{
            .config = &config.state.config,
            .index_to_pubkey = &pubkey.state.index2pubkey,
            .pubkey_to_index = &pubkey.state.pubkey2index,
        },
        null,
    );

    return .{ .cached_state = cached_state };
}

// -------------------------
// Getters
// -------------------------
pub fn slot(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    const slot_value = try cached_state.state.slot();
    return js.Number.from(slot_value);
}

pub fn fork(self: *const Self) !js_types.Fork {
    const env = js.env();
    const cached_state = try self.requireState();
    var fork_view = try cached_state.state.fork();
    var fork_value: ct.phase0.Fork.Type = undefined;
    try fork_view.toValue(allocator, &fork_value);
    return js_types.wrap(js_types.Fork, try sszValueToNapiValue(env, ct.phase0.Fork, &fork_value));
}

pub fn epoch(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    const slot_value = try cached_state.state.slot();
    return js.Number.from(slot_value / preset.SLOTS_PER_EPOCH);
}

pub fn genesisTime(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    return js.Number.from(try cached_state.state.genesisTime());
}

pub fn genesisValidatorsRoot(self: *const Self) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Root, try cached_state.state.genesisValidatorsRoot()));
}

pub fn eth1Data(self: *const Self) !js_types.Eth1Data {
    const env = js.env();
    const cached_state = try self.requireState();
    var eth1_data_view = try cached_state.state.eth1Data();
    var eth1_data: ct.phase0.Eth1Data.Type = undefined;
    try eth1_data_view.toValue(allocator, &eth1_data);
    return js_types.wrap(js_types.Eth1Data, try sszValueToNapiValue(env, ct.phase0.Eth1Data, &eth1_data));
}

pub fn latestBlockHeader(self: *const Self) !js_types.BeaconBlockHeader {
    const env = js.env();
    const cached_state = try self.requireState();
    var header_view = try cached_state.state.latestBlockHeader();
    var header: ct.phase0.BeaconBlockHeader.Type = undefined;
    try header_view.toValue(allocator, &header);
    return js_types.wrap(js_types.BeaconBlockHeader, try sszValueToNapiValue(env, ct.phase0.BeaconBlockHeader, &header));
}

pub fn previousJustifiedCheckpoint(self: *const Self) !js_types.Checkpoint {
    const env = js.env();
    const cached_state = try self.requireState();
    var cp: ct.phase0.Checkpoint.Type = undefined;
    try cached_state.state.previousJustifiedCheckpoint(&cp);
    return js_types.wrap(js_types.Checkpoint, try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp));
}

pub fn currentJustifiedCheckpoint(self: *const Self) !js_types.Checkpoint {
    const env = js.env();
    const cached_state = try self.requireState();
    var cp: ct.phase0.Checkpoint.Type = undefined;
    try cached_state.state.currentJustifiedCheckpoint(&cp);
    return js_types.wrap(js_types.Checkpoint, try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp));
}

pub fn finalizedCheckpoint(self: *const Self) !js_types.Checkpoint {
    const env = js.env();
    const cached_state = try self.requireState();
    var cp: ct.phase0.Checkpoint.Type = undefined;
    try cached_state.state.finalizedCheckpoint(&cp);
    return js_types.wrap(js_types.Checkpoint, try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp));
}

pub fn previousEpochParticipation(self: *const Self) !js.Uint8Array {
    const cached_state = try self.requireState();
    var view = try cached_state.state.previousEpochParticipation();

    const size = try view.serializedSize();
    const result = try js.Uint8Array.alloc(size);
    _ = try view.serializeIntoBytes(try result.toSlice());
    return result;
}

pub fn currentEpochParticipation(self: *const Self) !js.Uint8Array {
    const cached_state = try self.requireState();
    var view = try cached_state.state.currentEpochParticipation();

    const size = try view.serializedSize();
    const result = try js.Uint8Array.alloc(size);
    _ = try view.serializeIntoBytes(try result.toSlice());
    return result;
}

pub fn latestExecutionPayloadHeader(self: *const Self) !js.Value {
    const env = js.env();
    const cached_state = try self.requireState();
    var header: AnyExecutionPayloadHeader = undefined;
    try cached_state.state.latestExecutionPayloadHeader(allocator, &header);
    defer header.deinit(allocator);

    const value = switch (header) {
        .bellatrix => |*h| try sszValueToNapiValue(env, ct.bellatrix.ExecutionPayloadHeader, h),
        .capella => |*h| try sszValueToNapiValue(env, ct.capella.ExecutionPayloadHeader, h),
        .deneb => |*h| try sszValueToNapiValue(env, ct.deneb.ExecutionPayloadHeader, h),
    };
    return asJsValue(value);
}

// -------------------------
// Instance Methods
// -------------------------

pub fn getBlockRoot(self: *const Self, slot_arg: js.Number) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const slot_value: u64 = @intCast(try slot_arg.toI64());

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.getBlockRootAtSlot(f, cached_state.state.castToFork(f), slot_value),
    };
    const root = result catch |err| {
        const msg = switch (err) {
            error.SlotTooBig => "Can only get block root in the past",
            error.SlotTooSmall => "Cannot get block root more than SLOTS_PER_HISTORICAL_ROOT in the past",
            else => "Failed to get block root",
        };
        return throwNullAs(js.Uint8Array, "INVALID_SLOT", msg);
    };

    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Root, root));
}

pub fn getRandaoMix(self: *const Self, epoch_arg: js.Number) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const epoch_value: u64 = @intCast(try epoch_arg.toI64());

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.getRandaoMix(f, cached_state.state.castToFork(f), epoch_value),
    };
    const mix = result catch {
        return throwNullAs(js.Uint8Array, "INVALID_EPOCH", "Failed to get randao mix for epoch");
    };

    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Bytes32, mix));
}

/// Get the historical summaries from the state (Capella+).
/// Returns: array of {blockSummaryRoot: Uint8Array, stateSummaryRoot: Uint8Array}
pub fn historicalSummaries(self: *const Self) !js.Array {
    const env = js.env();
    const cached_state = try self.requireState();
    var historical_summaries_view = try cached_state.state.historicalSummaries();
    var historical_summaries = ct.capella.HistoricalSummaries.default_value;
    try historical_summaries_view.toValue(allocator, &historical_summaries);
    defer historical_summaries.deinit(allocator);
    return js_types.wrap(js.Array, try sszValueToNapiValue(env, ct.capella.HistoricalSummaries, &historical_summaries));
}

/// Get the pending deposits from the state (Electra+).
/// Returns: Uint8Array of SSZ serialized PendingDeposits list
pub fn pendingDeposits(self: *const Self) !js.Uint8Array {
    const cached_state = try self.requireState();

    var pending_deposits = cached_state.state.pendingDeposits() catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to get pendingDeposits");
    };

    const size = pending_deposits.serializedSize() catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to get pendingDeposits size");
    };

    const result = try js.Uint8Array.alloc(size);
    _ = pending_deposits.serializeIntoBytes(try result.toSlice()) catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to serialize pendingDeposits");
    };

    return result;
}

pub fn pendingDepositsCount(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    var pending_deposits = try cached_state.state.pendingDeposits();
    return js.Number.from(try pending_deposits.length());
}

/// Get the pending partial withdrawals from the state (Electra+).
/// Returns: Uint8Array of SSZ serialized PendingPartialWithdrawals list
pub fn pendingPartialWithdrawals(self: *const Self) !js.Uint8Array {
    const cached_state = try self.requireState();

    var pending_partial_withdrawals = cached_state.state.pendingPartialWithdrawals() catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to get pendingPartialWithdrawals");
    };
    const size = pending_partial_withdrawals.serializedSize() catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to get pendingPartialWithdrawals size");
    };

    const result = try js.Uint8Array.alloc(size);
    _ = pending_partial_withdrawals.serializeIntoBytes(try result.toSlice()) catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to serialize pendingPartialWithdrawals");
    };
    return result;
}

pub fn pendingPartialWithdrawalsCount(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    var pending_partial_withdrawals = try cached_state.state.pendingPartialWithdrawals();
    return js.Number.from(try pending_partial_withdrawals.length());
}

/// Get the pending consolidations from the state
pub fn pendingConsolidations(self: *const Self) !js.Uint8Array {
    const cached_state = try self.requireState();

    var pending_consolidations = cached_state.state.pendingConsolidations() catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to get pendingConsolidations");
    };
    const size = pending_consolidations.serializedSize() catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to get pendingConsolidations size");
    };

    const result = try js.Uint8Array.alloc(size);
    _ = pending_consolidations.serializeIntoBytes(try result.toSlice()) catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to serialize pendingConsolidations");
    };

    return result;
}

pub fn pendingConsolidationsCount(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    var pending_consolidations = try cached_state.state.pendingConsolidations();
    return js.Number.from(try pending_consolidations.length());
}

/// Get the proposer lookahead from the state (Fulu+).
pub fn proposerLookahead(self: *const Self) !js.Uint32Array {
    const env = js.env();
    const cached_state = try self.requireState();

    var proposer_lookahead = cached_state.state.proposerLookahead() catch {
        return throwNullAs(js.Uint32Array, "STATE_ERROR", "Failed to get proposerLookahead");
    };

    const lookahead = proposer_lookahead.getAll(allocator) catch {
        return throwNullAs(js.Uint32Array, "STATE_ERROR", "Failed to get proposerLookahead values");
    };
    defer allocator.free(lookahead);

    return .{ .val = try numberSliceToNapiValue(env, u64, lookahead, .{ .typed_array = .uint32 }) };
}

// pub fn BeaconStateView_executionPayloadAvailability

// pub fn BeaconStateView_getShufflingAtEpoch

pub fn previousDecisionRoot(self: *const Self) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const root = cached_state.previousDecisionRoot();
    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Root, &root));
}

pub fn currentDecisionRoot(self: *const Self) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const root = cached_state.currentDecisionRoot();
    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Root, &root));
}

/// Get the next decision root for the state.
pub fn nextDecisionRoot(self: *const Self) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const root = cached_state.nextDecisionRoot();
    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Root, &root));
}

/// Get the shuffling decision root for a given epoch.
pub fn getShufflingDecisionRoot(self: *const Self, epoch_arg: js.Number) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const epoch_value: u64 = @intCast(try epoch_arg.toI64());
    const root = st.calculateShufflingDecisionRoot(cached_state.state, epoch_value) catch {
        return throwNullAs(js.Uint8Array, "STATE_ERROR", "Failed to calculate shuffling decision root");
    };
    return js_types.wrap(js.Uint8Array, try sszValueToNapiValue(env, ct.primitive.Root, &root));
}

pub fn previousProposers(self: *const Self) !?js.Array {
    const env = js.env();
    const cached_state = try self.requireState();
    if (cached_state.epoch_cache.proposers_prev_epoch) |*proposers| {
        return .{ .val = try numberSliceToNapiValue(env, u64, proposers, .{}) };
    }
    return null;
}

pub fn currentProposers(self: *const Self) !js.Array {
    const env = js.env();
    const cached_state = try self.requireState();
    return .{ .val = try numberSliceToNapiValue(env, u64, &cached_state.epoch_cache.proposers, .{}) };
}

pub fn nextProposers(self: *const Self) !?js.Array {
    const env = js.env();
    const cached_state = try self.requireState();
    if (cached_state.epoch_cache.proposers_next_epoch) |*proposers| {
        return .{ .val = try numberSliceToNapiValue(env, u64, proposers, .{}) };
    }
    return null;
}

/// Get the beacon proposer for a given slot.
/// Arguments:
/// - arg 0: slot (number)
/// Returns: validator index of the proposer
pub fn getBeaconProposer(self: *const Self, slot_arg: js.Number) !js.Number {
    const cached_state = try self.requireState();
    const slot_value: u64 = @intCast(try slot_arg.toI64());
    const proposer = try cached_state.epoch_cache.getBeaconProposer(slot_value);
    return js.Number.from(proposer);
}

pub fn currentSyncCommittee(self: *const Self) !js_types.SyncCommittee {
    const env = js.env();
    const cached_state = try self.requireState();
    var current_sync_committee = try cached_state.state.currentSyncCommittee();
    var result: ct.altair.SyncCommittee.Type = undefined;
    try current_sync_committee.toValue(allocator, &result);
    return js_types.wrap(js_types.SyncCommittee, try sszValueToNapiValue(env, ct.altair.SyncCommittee, &result));
}

pub fn nextSyncCommittee(self: *const Self) !js_types.SyncCommittee {
    const env = js.env();
    const cached_state = try self.requireState();
    var next_sync_committee = try cached_state.state.nextSyncCommittee();
    var result: ct.altair.SyncCommittee.Type = undefined;
    try next_sync_committee.toValue(allocator, &result);
    return js_types.wrap(js_types.SyncCommittee, try sszValueToNapiValue(env, ct.altair.SyncCommittee, &result));
}

pub fn currentSyncCommitteeIndexed(self: *const Self) !js_types.IndexedSyncCommitteeWithMap {
    const env = js.env();
    const cached_state = try self.requireState();
    const sync_committee_cache = cached_state.epoch_cache.current_sync_committee_indexed.get();
    const validator_indices = sync_committee_cache.getValidatorIndices();
    const validator_index_map = sync_committee_cache.getValidatorIndexMap();

    const obj = try env.createObject();
    try obj.setNamedProperty(
        "validatorIndices",
        try numberSliceToNapiValue(
            env,
            u64,
            validator_indices,
            .{ .typed_array = .uint32 },
        ),
    );

    const global = try env.getGlobal();
    const map_ctor = try global.getNamedProperty("Map");
    const map = try env.newInstance(map_ctor, .{});
    const set_fn = try map.getNamedProperty("set");

    var iterator = validator_index_map.iterator();
    while (iterator.next()) |entry| {
        const idx = entry.key_ptr.*;
        const positions = entry.value_ptr;

        const key_value_napi = try env.createInt64(@intCast(idx));
        const positions_napi = try numberSliceToNapiValue(
            env,
            u32,
            positions.items,
            .{ .typed_array = .uint32 },
        );

        _ = try env.callFunction(set_fn, map, .{ key_value_napi, positions_napi });
    }

    try obj.setNamedProperty("validatorIndexMap", map);
    return .{ .val = obj };
}

pub fn syncProposerReward(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    const sync_proposer_reward = cached_state.epoch_cache.sync_proposer_reward;
    return js.Number.from(sync_proposer_reward);
}

/// Get the indexed sync committee at a given epoch.
/// Returns: object with validatorIndices (Uint32Array)
pub fn getIndexedSyncCommitteeAtEpoch(self: *const Self, epoch_arg: js.Number) !js_types.IndexedSyncCommittee {
    const env = js.env();
    const cached_state = try self.requireState();
    const epoch_value: u64 = @intCast(try epoch_arg.toI64());

    const sync_committee = cached_state.epoch_cache.getIndexedSyncCommitteeAtEpoch(epoch_value) catch {
        return throwNullAs(js_types.IndexedSyncCommittee, "NO_SYNC_COMMITTEE", "Sync committee not available for requested epoch");
    };

    const obj = try env.createObject();
    try obj.setNamedProperty(
        "validatorIndices",
        try numberSliceToNapiValue(env, u64, sync_committee.getValidatorIndices(), .{ .typed_array = .uint32 }),
    );
    return .{ .val = obj };
}

pub fn effectiveBalanceIncrements(self: *const Self) !js.Uint16Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const increments = cached_state.epoch_cache.getEffectiveBalanceIncrements();
    return .{ .val = try numberSliceToNapiValue(env, u16, increments.items, .{ .typed_array = .uint16 }) };
}

pub fn getEffectiveBalanceIncrementsZeroInactive(self: *const Self) !js.Uint16Array {
    const env = js.env();
    const cached_state = try self.requireState();
    var result = try st.getEffectiveBalanceIncrementsZeroInactive(allocator, cached_state);
    defer result.deinit(allocator);
    return .{ .val = try numberSliceToNapiValue(env, u16, result.items, .{ .typed_array = .uint16 }) };
}

pub fn getBalance(self: *const Self, index_arg: js.Number) !js.BigInt {
    const cached_state = try self.requireState();
    const index_value: u64 = @intCast(try index_arg.toI64());
    var balances = try cached_state.state.balances();
    const balance = try balances.get(index_value);
    return js.BigInt.from(balance);
}

/// Get a validator by index.
pub fn getValidator(self: *const Self, index_arg: js.Number) !js_types.Validator {
    const env = js.env();
    const cached_state = try self.requireState();
    const index_value: u64 = @intCast(try index_arg.toI64());

    var validators = try cached_state.state.validators();
    var validator_view = try validators.get(index_value);
    var validator: ct.phase0.Validator.Type = undefined;
    try validator_view.toValue(allocator, &validator);

    return js_types.wrap(js_types.Validator, try sszValueToNapiValue(env, ct.phase0.Validator, &validator));
}

/// Get the status of a validator by index.
/// Returns: status string
pub fn getValidatorStatus(self: *const Self, index_arg: js.Number) !js.String {
    const cached_state = try self.requireState();
    const index_value: u64 = @intCast(try index_arg.toI64());
    const current_epoch = cached_state.epoch_cache.epoch;

    var validators = try cached_state.state.validators();
    var validator_view = try validators.get(index_value);
    var validator: ct.phase0.Validator.Type = undefined;
    try validator_view.toValue(allocator, &validator);

    const status = st.getValidatorStatus(&validator, current_epoch);
    return js.String.from(status.toString());
}

/// Get the total number of validators in the registry.
pub fn validatorCount(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    const count = try cached_state.state.validatorsCount();
    return js.Number.from(count);
}

/// Get the number of active validators at the current epoch.
pub fn activeValidatorCount(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    const count = cached_state.epoch_cache.current_shuffling.get().active_indices.len;
    return js.Number.from(count);
}

pub fn isExecutionStateType(self: *const Self) !js.Boolean {
    const cached_state = try self.requireState();
    const fork_seq = cached_state.state.forkSeq();
    return js.Boolean.from(fork_seq.gte(.bellatrix));
}

/// Check if the merge transition is complete.
pub fn isExecutionEnabled(self: *const Self, fork_name_value: js.String, signed_block_bytes: js.Uint8Array) !js.Boolean {
    const cached_state = try self.requireState();

    var fork_name_buf: [16]u8 = undefined;
    const fork_name = try fork_name_value.toSlice(&fork_name_buf);
    const fork_seq = c.ForkSeq.fromName(fork_name);

    const bytes = try signed_block_bytes.toSlice();
    const signed_block = try AnySignedBeaconBlock.deserialize(
        allocator,
        .full,
        fork_seq,
        bytes,
    );
    defer signed_block.deinit(allocator);

    if (signed_block.forkSeq() != cached_state.state.forkSeq()) {
        return throwNullAs(js.Boolean, "FORK_MISMATCH", "Fork of signed block does not match state fork");
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
    return js.Boolean.from(result);
}

/// Check if the merge transition is complete.
pub fn isMergeTransitionComplete(self: *const Self) !js.Boolean {
    const cached_state = try self.requireState();
    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.isMergeTransitionComplete(f, cached_state.state.castToFork(f)),
    };
    return js.Boolean.from(result);
}

// pub fn BeaconStateView_getExpectedWithdrawals

/// Get the proposer rewards for the state.
pub fn proposerRewards(self: *const Self) !js_types.ProposerRewards {
    const env = js.env();
    const cached_state = try self.requireState();
    const rewards = cached_state.getProposerRewards();

    const obj = try env.createObject();
    try obj.setNamedProperty("attestations", try env.createBigintUint64(rewards.attestations));
    try obj.setNamedProperty("syncAggregate", try env.createBigintUint64(rewards.sync_aggregate));
    try obj.setNamedProperty("slashing", try env.createBigintUint64(rewards.slashing));
    return .{ .val = obj };
}

// pub fn BeaconStateView_computeBlockRewards

// pub fn BeaconStateView_computeAttestationRewards

// pub fn BeaconStateView_computeSyncCommitteeRewards

// pub fn BeaconStateView_getLatestWeakSubjectivityCheckpointEpoch

/// Get the validity status of a signed voluntary exit.
pub fn getVoluntaryExitValidity(self: *const Self, signed_exit_bytes: js.Uint8Array, verify_signature_value: js.Boolean) !js.String {
    const env = js.env();
    const cached_state = try self.requireState();
    const verify_signature = verify_signature_value.assertBool();
    const bytes = try signed_exit_bytes.toSlice();

    var signed_voluntary_exit: ct.phase0.SignedVoluntaryExit.Type = ct.phase0.SignedVoluntaryExit.default_value;
    ct.phase0.SignedVoluntaryExit.deserializeFromBytes(bytes, &signed_voluntary_exit) catch {
        return throwNullAs(js.String, "DESERIALIZE_ERROR", "Failed to deserialize SignedVoluntaryExit");
    };

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.getVoluntaryExitValidity(
            f,
            cached_state.config,
            cached_state.epoch_cache,
            cached_state.state.castToFork(f),
            &signed_voluntary_exit,
            verify_signature,
        ),
    };
    const validity = result catch {
        return throwNullAs(js.String, "VALIDATION_ERROR", "Failed to get voluntary exit validity");
    };

    return .{ .val = try env.createStringUtf8(@tagName(validity)) };
}

/// Check if a signed voluntary exit is valid.
pub fn isValidVoluntaryExit(self: *const Self, signed_exit_bytes: js.Uint8Array, verify_signature_value: js.Boolean) !js.Boolean {
    const cached_state = try self.requireState();
    const verify_signature = verify_signature_value.assertBool();
    const bytes = try signed_exit_bytes.toSlice();

    var signed_voluntary_exit: ct.phase0.SignedVoluntaryExit.Type = ct.phase0.SignedVoluntaryExit.default_value;
    ct.phase0.SignedVoluntaryExit.deserializeFromBytes(bytes, &signed_voluntary_exit) catch {
        return throwNullAs(js.Boolean, "DESERIALIZE_ERROR", "Failed to deserialize SignedVoluntaryExit");
    };

    const result = switch (cached_state.state.forkSeq()) {
        inline else => |f| st.isValidVoluntaryExit(
            f,
            cached_state.config,
            cached_state.epoch_cache,
            cached_state.state.castToFork(f),
            &signed_voluntary_exit,
            verify_signature,
        ),
    };
    const is_valid = result catch {
        return throwNullAs(js.Boolean, "VALIDATION_ERROR", "Failed to validate voluntary exit");
    };

    return js.Boolean.from(is_valid);
}

pub fn getFinalizedRootProof(self: *const Self) !js.Array {
    const env = js.env();
    const cached_state = try self.requireState();
    var proof = try cached_state.state.getFinalizedRootProof(allocator);
    defer proof.deinit(allocator);

    const witnesses = std.ArrayListUnmanaged([32]u8).fromOwnedSlice(proof.witnesses);
    return js_types.wrap(js.Array, try sszValueToNapiValue(
        env,
        ct.phase0.HistoricalRoots,
        &witnesses,
    ));
}

// pub fn BeaconStateView_getSyncCommitteesWitness

/// Get a single Merkle proof  for a node at the given generalized index.
pub fn getSingleProof(self: *const Self, gindex_arg: js.Number) !js.Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const gindex: u64 = @intCast(try gindex_arg.toI64());

    var proof = cached_state.state.getSingleProof(allocator, gindex) catch {
        return throwNullAs(js.Array, "STATE_ERROR", "Failed to get single proof");
    };
    defer proof.deinit(allocator);

    const result = try env.createArray();
    for (proof.witnesses, 0..) |witness, i| {
        try result.setElement(@intCast(i), js.Uint8Array.from(&witness).toValue());
    }

    return .{ .val = result };
}

// pub fn BeaconStateView_getSyncCommitteesWitness

/// Create a compact multi-proof from a descriptor.
/// Returns: {type: string, leaves: Uint8Array[], descriptor: Uint8Array}
pub fn createMultiProof(self: *const Self, descriptor: js.Uint8Array) !js_types.MultiProof {
    const persistent_merkle_tree = @import("persistent_merkle_tree");
    const env = js.env();
    const cached_state = try self.requireState();
    const descriptor_bytes = try descriptor.toSlice();

    try cached_state.state.commit();
    const root_node = switch (cached_state.state.*) {
        inline else => |state| state.root,
    };

    const proof_input = persistent_merkle_tree.proof.ProofInput{
        .compactMulti = .{ .descriptor = descriptor_bytes },
    };

    var proof = persistent_merkle_tree.proof.createProof(
        allocator,
        &pool.state.pool,
        root_node,
        proof_input,
    ) catch {
        return throwNullAs(js_types.MultiProof, "STATE_ERROR", "Failed to create proof");
    };
    defer proof.deinit(allocator);

    const result = try env.createObject();
    const proof_type_str = switch (proof) {
        inline else => |_, tag| @tagName(tag),
    };
    try result.setNamedProperty("type", try env.createStringUtf8(proof_type_str));

    switch (proof) {
        .compactMulti => |compact| {
            const leaves_array = try env.createArray();
            for (compact.leaves, 0..) |leaf, i| {
                try leaves_array.setElement(@intCast(i), js.Uint8Array.from(&leaf).toValue());
            }
            try result.setNamedProperty("leaves", leaves_array);

            try result.setNamedProperty(
                "descriptor",
                js.Uint8Array.from(compact.descriptor).toValue(),
            );
        },
        else => return throwNullAs(js_types.MultiProof, "STATE_ERROR", "Unexpected proof type"),
    }

    return .{ .val = result };
}

pub fn computeUnrealizedCheckpoints(self: *const Self) !js_types.UnrealizedCheckpoints {
    const env = js.env();
    const cached_state = try self.requireState();
    const result = try st.computeUnrealizedCheckpoints(allocator, napi_io.get(), cached_state);

    const obj = try env.createObject();
    try obj.setNamedProperty(
        "justifiedCheckpoint",
        try sszValueToNapiValue(env, ct.phase0.Checkpoint, &result.justified_checkpoint),
    );
    try obj.setNamedProperty(
        "finalizedCheckpoint",
        try sszValueToNapiValue(env, ct.phase0.Checkpoint, &result.finalized_checkpoint),
    );
    return .{ .val = obj };
}

pub fn clonedCount(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    return js.Number.from(cached_state.cloned_count);
}

pub fn clonedCountWithTransferCache(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    return js.Number.from(cached_state.cloned_count_with_transfer_cache);
}

pub fn createdWithTransferCache(self: *const Self) !js.Boolean {
    const cached_state = try self.requireState();
    return js.Boolean.from(cached_state.created_with_transfer_cache);
}

// pub fn BeaconStateView_isStateValidatorsNodesPopulated

// pub fn BeaconStateView_loadOtherState

pub fn serialize(self: *const Self) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const result = try cached_state.state.serialize(allocator);
    defer allocator.free(result);
    return .{ .val = try numberSliceToNapiValue(env, u8, result, .{ .typed_array = .uint8 }) };
}

pub fn serializedSize(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    const size = switch (cached_state.state.*) {
        inline else => |state| try state.serializedSize(),
    };
    return js.Number.from(size);
}

/// arg 0: output: preallocated Uint8Array buffer
/// arg 1: offset: offset of buffer where serialization should start
pub fn serializeToBytes(self: *const Self, output: js.Uint8Array, offset: js.Number) !js.Number {
    const output_slice = try output.toSlice();
    const off = try offset.toU32();
    if (off > output_slice.len) return error.InvalidOffset;

    const cached_state = try self.requireState();
    const bytes_written = switch (cached_state.state.*) {
        inline else => |state| try state.serializeIntoBytes(output_slice[off..]),
    };

    return js.Number.from(bytes_written);
}

pub fn serializeValidators(self: *const Self) !js.Uint8Array {
    const cached_state = try self.requireState();
    var validators_view = try cached_state.state.validators();

    const size = try validators_view.serializedSize();
    const result = try js.Uint8Array.alloc(size);
    _ = try validators_view.serializeIntoBytes(try result.toSlice());
    return result;
}

pub fn serializedValidatorsSize(self: *const Self) !js.Number {
    const cached_state = try self.requireState();
    var validators_view = try cached_state.state.validators();
    const size = try validators_view.serializedSize();
    return js.Number.from(size);
}

pub fn serializeValidatorsToBytes(self: *const Self, output: js.Uint8Array, offset: js.Number) !js.Number {
    const output_slice = try output.toSlice();
    const off = try offset.toU32();
    if (off > output_slice.len) return error.InvalidOffset;

    const cached_state = try self.requireState();
    var validators_view = try cached_state.state.validators();
    const bytes_written = try validators_view.serializeIntoBytes(output_slice[off..]);
    return js.Number.from(bytes_written);
}

pub fn hashTreeRoot(self: *const Self) !js.Uint8Array {
    const env = js.env();
    const cached_state = try self.requireState();
    const root = try cached_state.state.hashTreeRoot();
    return .{ .val = try numberSliceToNapiValue(env, u8, root, .{ .typed_array = .uint8 }) };
}

// pub fn BeaconStateView_stateTransition

/// Process slots from current state slot to target slot, returning a new BeaconStateView.
///
/// Arguments:
/// - arg 0: target slot (number)
/// - arg 1: options object (optional) with `transferCache` boolean
pub fn processSlots(self: *const Self, slot_arg: js.Number, options: ?js.Value) !Self {
    const cached_state = try self.requireState();
    const slot_value: u64 = @intCast(try slot_arg.toI64());
    const transfer_cache = try optionalBool(options, "transferCache", false);
    const post_state = try cached_state.clone(allocator, .{ .transfer_cache = transfer_cache });
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    try st.processSlots(allocator, napi_io.get(), post_state, slot_value, .{});
    return .{ .cached_state = post_state };
}

fn requireState(self: *const Self) !*CachedBeaconState {
    return self.cached_state orelse error.InvalidState;
}

fn asJsValue(value: napi.Value) js.Value {
    return .{ .val = value };
}

fn jsNull() !js.Value {
    return asJsValue(try js.env().getNull());
}

fn jsNullAs(comptime T: type) !T {
    return js_types.wrap(T, try js.env().getNull());
}

fn throwNull(code: [:0]const u8, message: [:0]const u8) !js.Value {
    const env = js.env();
    try env.throwError(code, message);
    return jsNull();
}

fn throwNullAs(comptime T: type, code: [:0]const u8, message: [:0]const u8) !T {
    const env = js.env();
    try env.throwError(code, message);
    return jsNullAs(T);
}

fn optionalBool(options: ?js.Value, name: [:0]const u8, default_value: bool) !bool {
    if (options) |value| {
        const raw = value.toValue();
        if (try raw.typeof() == .object) {
            if (try raw.hasNamedProperty(name)) {
                return try (try raw.getNamedProperty(name)).getValueBool();
            }
        }
    }
    return default_value;
}
