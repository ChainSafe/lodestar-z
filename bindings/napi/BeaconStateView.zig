const std = @import("std");
const zapi = @import("zapi");
const js = zapi.js;
const napi = zapi.napi;
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
const config_bindings = @import("./config.zig");
const pubkey = @import("./pubkeys.zig");
const sszValueToNapiValue = @import("./to_napi_value.zig").sszValueToNapiValue;
const numberSliceToNapiValue = @import("./to_napi_value.zig").numberSliceToNapiValue;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = gpa.allocator();

fn asJsValue(value: napi.Value) js.Value {
    return .{ .val = value };
}

fn jsNull() !js.Value {
    return asJsValue(try js.env().getNull());
}

fn throwNull(code: [:0]const u8, message: [:0]const u8) !js.Value {
    const env = js.env();
    try env.throwError(code, message);
    return jsNull();
}

fn optionalBool(options: ?js.Value, name: [:0]const u8, default_value: bool) !bool {
    if (options) |value| {
        const raw = value.toValue();
        if (try raw.typeof() == .object and try raw.hasNamedProperty(name)) {
            return try (try raw.getNamedProperty(name)).getValueBool();
        }
    }
    return default_value;
}

pub const BeaconStateView = struct {
    pub const js_meta = js.class(.{
        .properties = .{
            .slot = true,
            .fork = true,
            .epoch = true,
            .genesisTime = true,
            .genesisValidatorsRoot = true,
            .eth1Data = true,
            .latestBlockHeader = true,
            .previousJustifiedCheckpoint = true,
            .currentJustifiedCheckpoint = true,
            .finalizedCheckpoint = true,
            .previousEpochParticipation = true,
            .currentEpochParticipation = true,
            .latestExecutionPayloadHeader = true,
            .historicalSummaries = true,
            .pendingDeposits = true,
            .pendingDepositsCount = true,
            .pendingPartialWithdrawals = true,
            .pendingPartialWithdrawalsCount = true,
            .pendingConsolidations = true,
            .pendingConsolidationsCount = true,
            .proposerLookahead = true,
            .previousDecisionRoot = true,
            .currentDecisionRoot = true,
            .nextDecisionRoot = true,
            .currentProposers = true,
            .nextProposers = true,
            .previousProposers = true,
            .currentSyncCommittee = true,
            .nextSyncCommittee = true,
            .currentSyncCommitteeIndexed = true,
            .syncProposerReward = true,
            .effectiveBalanceIncrements = true,
            .validatorCount = true,
            .activeValidatorCount = true,
            .isMergeTransitionComplete = true,
            .isExecutionStateType = true,
            .proposerRewards = true,
            .clonedCount = true,
            .clonedCountWithTransferCache = true,
            .createdWithTransferCache = true,
        },
    });

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

    fn requireState(self: *const Self) !*CachedBeaconState {
        return self.cached_state orelse error.InvalidState;
    }

    pub fn createFromBytes(bytes: js.Uint8Array) !Self {
        const state = try allocator.create(AnyBeaconState);
        errdefer allocator.destroy(state);

        const byte_slice = try bytes.toSlice();
        const slot_value = fork_types.readSlotFromAnyBeaconStateBytes(byte_slice);
        const fork_seq = config_bindings.state.config.forkSeq(slot_value);
        state.* = try AnyBeaconState.deserialize(allocator, &pool.state.pool, fork_seq, byte_slice);
        errdefer state.deinit();

        const cached_state = try allocator.create(CachedBeaconState);
        errdefer allocator.destroy(cached_state);

        try cached_state.init(
            allocator,
            state,
            .{
                .config = &config_bindings.state.config,
                .index_to_pubkey = &pubkey.state.index2pubkey,
                .pubkey_to_index = &pubkey.state.pubkey2index,
            },
            null,
        );

        return .{ .cached_state = cached_state };
    }

    pub fn slot(self: *const Self) !js.Number {
        const slot_value = try (try self.requireState()).state.slot();
        return js.Number.from(slot_value);
    }

    pub fn fork(self: *const Self) !js.Value {
        const env = js.env();
        var fork_view = try (try self.requireState()).state.fork();
        var fork_value: ct.phase0.Fork.Type = undefined;
        try fork_view.toValue(allocator, &fork_value);
        return asJsValue(try sszValueToNapiValue(env, ct.phase0.Fork, &fork_value));
    }

    pub fn epoch(self: *const Self) !js.Number {
        const slot_value = try (try self.requireState()).state.slot();
        return js.Number.from(slot_value / preset.SLOTS_PER_EPOCH);
    }

    pub fn genesisTime(self: *const Self) !js.Number {
        return js.Number.from(try (try self.requireState()).state.genesisTime());
    }

    pub fn genesisValidatorsRoot(self: *const Self) !js.Value {
        const env = js.env();
        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Root, try (try self.requireState()).state.genesisValidatorsRoot()));
    }

    pub fn eth1Data(self: *const Self) !js.Value {
        const env = js.env();
        var eth1_data_view = try (try self.requireState()).state.eth1Data();
        var eth1_data: ct.phase0.Eth1Data.Type = undefined;
        try eth1_data_view.toValue(allocator, &eth1_data);
        return asJsValue(try sszValueToNapiValue(env, ct.phase0.Eth1Data, &eth1_data));
    }

    pub fn latestBlockHeader(self: *const Self) !js.Value {
        const env = js.env();
        var header_view = try (try self.requireState()).state.latestBlockHeader();
        var header: ct.phase0.BeaconBlockHeader.Type = undefined;
        try header_view.toValue(allocator, &header);
        return asJsValue(try sszValueToNapiValue(env, ct.phase0.BeaconBlockHeader, &header));
    }

    pub fn previousJustifiedCheckpoint(self: *const Self) !js.Value {
        const env = js.env();
        var cp: ct.phase0.Checkpoint.Type = undefined;
        try (try self.requireState()).state.previousJustifiedCheckpoint(&cp);
        return asJsValue(try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp));
    }

    pub fn currentJustifiedCheckpoint(self: *const Self) !js.Value {
        const env = js.env();
        var cp: ct.phase0.Checkpoint.Type = undefined;
        try (try self.requireState()).state.currentJustifiedCheckpoint(&cp);
        return asJsValue(try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp));
    }

    pub fn finalizedCheckpoint(self: *const Self) !js.Value {
        const env = js.env();
        var cp: ct.phase0.Checkpoint.Type = undefined;
        try (try self.requireState()).state.finalizedCheckpoint(&cp);
        return asJsValue(try sszValueToNapiValue(env, ct.phase0.Checkpoint, &cp));
    }

    pub fn getBlockRoot(self: *const Self, slot_arg: js.Number) !js.Value {
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
            return throwNull("INVALID_SLOT", msg);
        };

        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Root, root));
    }

    pub fn getRandaoMix(self: *const Self, epoch_arg: js.Number) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();
        const epoch_value: u64 = @intCast(try epoch_arg.toI64());

        const result = switch (cached_state.state.forkSeq()) {
            inline else => |f| st.getRandaoMix(f, cached_state.state.castToFork(f), epoch_value),
        };
        const mix = result catch {
            return throwNull("INVALID_EPOCH", "Failed to get randao mix for epoch");
        };

        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Bytes32, mix));
    }

    pub fn previousEpochParticipation(self: *const Self) !js.Uint8Array {
        const env = js.env();
        var view = try (try self.requireState()).state.previousEpochParticipation();

        const size = try view.serializedSize();
        var bytes: [*]u8 = undefined;
        const buf = try env.createArrayBuffer(size, &bytes);
        _ = try view.serializeIntoBytes(bytes[0..size]);

        return .{ .val = try env.createTypedarray(.uint8, size, buf, 0) };
    }

    pub fn currentEpochParticipation(self: *const Self) !js.Uint8Array {
        const env = js.env();
        var view = try (try self.requireState()).state.currentEpochParticipation();

        const size = try view.serializedSize();
        var bytes: [*]u8 = undefined;
        const buf = try env.createArrayBuffer(size, &bytes);
        _ = try view.serializeIntoBytes(bytes[0..size]);

        return .{ .val = try env.createTypedarray(.uint8, size, buf, 0) };
    }

    pub fn latestExecutionPayloadHeader(self: *const Self) !js.Value {
        const env = js.env();
        var header: AnyExecutionPayloadHeader = undefined;
        try (try self.requireState()).state.latestExecutionPayloadHeader(allocator, &header);
        defer header.deinit(allocator);

        const value = switch (header) {
            .bellatrix => |*h| try sszValueToNapiValue(env, ct.bellatrix.ExecutionPayloadHeader, h),
            .capella => |*h| try sszValueToNapiValue(env, ct.capella.ExecutionPayloadHeader, h),
            .deneb => |*h| try sszValueToNapiValue(env, ct.deneb.ExecutionPayloadHeader, h),
        };
        return asJsValue(value);
    }

    pub fn historicalSummaries(self: *const Self) !js.Value {
        const env = js.env();
        var historical_summaries_view = try (try self.requireState()).state.historicalSummaries();
        var historical_summaries = ct.capella.HistoricalSummaries.default_value;
        try historical_summaries_view.toValue(allocator, &historical_summaries);
        defer historical_summaries.deinit(allocator);
        return asJsValue(try sszValueToNapiValue(env, ct.capella.HistoricalSummaries, &historical_summaries));
    }

    pub fn pendingDeposits(self: *const Self) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();

        var pending_deposits = cached_state.state.pendingDeposits() catch {
            return throwNull("STATE_ERROR", "Failed to get pendingDeposits");
        };

        const size = pending_deposits.serializedSize() catch {
            return throwNull("STATE_ERROR", "Failed to get pendingDeposits size");
        };

        var bytes: [*]u8 = undefined;
        const buf = try env.createArrayBuffer(size, &bytes);
        _ = pending_deposits.serializeIntoBytes(bytes[0..size]) catch {
            return throwNull("STATE_ERROR", "Failed to serialize pendingDeposits");
        };

        return asJsValue(try env.createTypedarray(.uint8, size, buf, 0));
    }

    pub fn pendingDepositsCount(self: *const Self) !js.Number {
        var pending_deposits = try (try self.requireState()).state.pendingDeposits();
        return js.Number.from(try pending_deposits.length());
    }

    pub fn pendingPartialWithdrawals(self: *const Self) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();

        var pending_partial_withdrawals = cached_state.state.pendingPartialWithdrawals() catch {
            return throwNull("STATE_ERROR", "Failed to get pendingPartialWithdrawals");
        };
        const size = pending_partial_withdrawals.serializedSize() catch {
            return throwNull("STATE_ERROR", "Failed to get pendingPartialWithdrawals size");
        };

        var bytes: [*]u8 = undefined;
        const buf = try env.createArrayBuffer(size, &bytes);
        _ = pending_partial_withdrawals.serializeIntoBytes(bytes[0..size]) catch {
            return throwNull("STATE_ERROR", "Failed to serialize pendingPartialWithdrawals");
        };
        return asJsValue(try env.createTypedarray(.uint8, size, buf, 0));
    }

    pub fn pendingPartialWithdrawalsCount(self: *const Self) !js.Number {
        var pending_partial_withdrawals = try (try self.requireState()).state.pendingPartialWithdrawals();
        return js.Number.from(try pending_partial_withdrawals.length());
    }

    pub fn pendingConsolidations(self: *const Self) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();

        var pending_consolidations = cached_state.state.pendingConsolidations() catch {
            return throwNull("STATE_ERROR", "Failed to get pendingConsolidations");
        };
        const size = pending_consolidations.serializedSize() catch {
            return throwNull("STATE_ERROR", "Failed to get pendingConsolidations size");
        };

        var bytes: [*]u8 = undefined;
        const buf = try env.createArrayBuffer(size, &bytes);
        _ = pending_consolidations.serializeIntoBytes(bytes[0..size]) catch {
            return throwNull("STATE_ERROR", "Failed to serialize pendingConsolidations");
        };

        return asJsValue(try env.createTypedarray(.uint8, size, buf, 0));
    }

    pub fn pendingConsolidationsCount(self: *const Self) !js.Number {
        var pending_consolidations = try (try self.requireState()).state.pendingConsolidations();
        return js.Number.from(try pending_consolidations.length());
    }

    pub fn proposerLookahead(self: *const Self) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();

        var proposer_lookahead = cached_state.state.proposerLookahead() catch {
            return throwNull("STATE_ERROR", "Failed to get proposerLookahead");
        };

        const lookahead = proposer_lookahead.getAll(allocator) catch {
            return throwNull("STATE_ERROR", "Failed to get proposerLookahead values");
        };
        defer allocator.free(lookahead);

        return asJsValue(try numberSliceToNapiValue(env, u64, lookahead, .{ .typed_array = .uint32 }));
    }

    pub fn previousDecisionRoot(self: *const Self) !js.Value {
        const env = js.env();
        const root = (try self.requireState()).previousDecisionRoot();
        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Root, &root));
    }

    pub fn currentDecisionRoot(self: *const Self) !js.Value {
        const env = js.env();
        const root = (try self.requireState()).currentDecisionRoot();
        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Root, &root));
    }

    pub fn nextDecisionRoot(self: *const Self) !js.Value {
        const env = js.env();
        const root = (try self.requireState()).nextDecisionRoot();
        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Root, &root));
    }

    pub fn getShufflingDecisionRoot(self: *const Self, epoch_arg: js.Number) !js.Value {
        const env = js.env();
        const epoch_value: u64 = @intCast(try epoch_arg.toI64());
        const root = st.calculateShufflingDecisionRoot((try self.requireState()).state, epoch_value) catch {
            return throwNull("STATE_ERROR", "Failed to calculate shuffling decision root");
        };
        return asJsValue(try sszValueToNapiValue(env, ct.primitive.Root, &root));
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

    pub fn getBeaconProposer(self: *const Self, slot_arg: js.Number) !js.Number {
        const slot_value: u64 = @intCast(try slot_arg.toI64());
        const proposer = try (try self.requireState()).epoch_cache.getBeaconProposer(slot_value);
        return js.Number.from(proposer);
    }

    pub fn currentSyncCommittee(self: *const Self) !js.Value {
        const env = js.env();
        var current_sync_committee = try (try self.requireState()).state.currentSyncCommittee();
        var result: ct.altair.SyncCommittee.Type = undefined;
        try current_sync_committee.toValue(allocator, &result);
        return asJsValue(try sszValueToNapiValue(env, ct.altair.SyncCommittee, &result));
    }

    pub fn nextSyncCommittee(self: *const Self) !js.Value {
        const env = js.env();
        var next_sync_committee = try (try self.requireState()).state.nextSyncCommittee();
        var result: ct.altair.SyncCommittee.Type = undefined;
        try next_sync_committee.toValue(allocator, &result);
        return asJsValue(try sszValueToNapiValue(env, ct.altair.SyncCommittee, &result));
    }

    pub fn currentSyncCommitteeIndexed(self: *const Self) !js.Value {
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
                u32,
                @as([]const u32, @ptrCast(validator_indices)),
                .{ .typed_array = null },
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
                @as([]const u32, @ptrCast(positions.items)),
                .{ .typed_array = .uint32 },
            );

            _ = try env.callFunction(set_fn, map, .{ key_value_napi, positions_napi });
        }

        try obj.setNamedProperty("validatorIndexMap", map);
        return asJsValue(obj);
    }

    pub fn syncProposerReward(self: *const Self) !js.Number {
        const sync_proposer_reward = (try self.requireState()).epoch_cache.sync_proposer_reward;
        return js.Number.from(sync_proposer_reward);
    }

    pub fn getIndexedSyncCommitteeAtEpoch(self: *const Self, epoch_arg: js.Number) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();
        const epoch_value: u64 = @intCast(try epoch_arg.toI64());

        const sync_committee = cached_state.epoch_cache.getIndexedSyncCommitteeAtEpoch(epoch_value) catch {
            return throwNull("NO_SYNC_COMMITTEE", "Sync committee not available for requested epoch");
        };

        const obj = try env.createObject();
        try obj.setNamedProperty(
            "validatorIndices",
            try numberSliceToNapiValue(env, u64, sync_committee.getValidatorIndices(), .{}),
        );
        return asJsValue(obj);
    }

    pub fn effectiveBalanceIncrements(self: *const Self) !js.Uint16Array {
        const env = js.env();
        const increments = (try self.requireState()).epoch_cache.getEffectiveBalanceIncrements();
        return .{ .val = try numberSliceToNapiValue(env, u16, increments.items, .{ .typed_array = .uint16 }) };
    }

    pub fn getEffectiveBalanceIncrementsZeroInactive(self: *const Self) !js.Uint16Array {
        const env = js.env();
        var result = try st.getEffectiveBalanceIncrementsZeroInactive(allocator, try self.requireState());
        defer result.deinit();
        return .{ .val = try numberSliceToNapiValue(env, u16, result.items, .{ .typed_array = .uint16 }) };
    }

    pub fn getBalance(self: *const Self, index_arg: js.Number) !js.BigInt {
        const index_value: u64 = @intCast(try index_arg.toI64());
        var balances = try (try self.requireState()).state.balances();
        const balance = try balances.get(index_value);
        return js.BigInt.from(balance);
    }

    pub fn getValidator(self: *const Self, index_arg: js.Number) !js.Value {
        const env = js.env();
        const index_value: u64 = @intCast(try index_arg.toI64());

        var validators = try (try self.requireState()).state.validators();
        var validator_view = try validators.get(index_value);
        var validator: ct.phase0.Validator.Type = undefined;
        try validator_view.toValue(allocator, &validator);

        return asJsValue(try sszValueToNapiValue(env, ct.phase0.Validator, &validator));
    }

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

    pub fn validatorCount(self: *const Self) !js.Number {
        const count = try (try self.requireState()).state.validatorsCount();
        return js.Number.from(count);
    }

    pub fn activeValidatorCount(self: *const Self) !js.Number {
        const count = (try self.requireState()).epoch_cache.current_shuffling.get().active_indices.len;
        return js.Number.from(count);
    }

    pub fn isExecutionStateType(self: *const Self) !js.Boolean {
        const fork_seq = (try self.requireState()).state.forkSeq();
        return js.Boolean.from(fork_seq.gte(.bellatrix));
    }

    pub fn isExecutionEnabled(self: *const Self, fork_name_value: js.String, signed_block_bytes: js.Uint8Array) !js.Value {
        const env = js.env();
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
            return throwNull("FORK_MISMATCH", "Fork of signed block does not match state fork");
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
        return asJsValue(try env.getBoolean(result));
    }

    pub fn isMergeTransitionComplete(self: *const Self) !js.Boolean {
        const cached_state = try self.requireState();
        const result = switch (cached_state.state.forkSeq()) {
            inline else => |f| st.isMergeTransitionComplete(f, cached_state.state.castToFork(f)),
        };
        return js.Boolean.from(result);
    }

    pub fn proposerRewards(self: *const Self) !js.Value {
        const env = js.env();
        const rewards = (try self.requireState()).getProposerRewards();

        const obj = try env.createObject();
        try obj.setNamedProperty("attestations", try env.createBigintUint64(rewards.attestations));
        try obj.setNamedProperty("syncAggregate", try env.createBigintUint64(rewards.sync_aggregate));
        try obj.setNamedProperty("slashing", try env.createBigintUint64(rewards.slashing));
        return asJsValue(obj);
    }

    pub fn getVoluntaryExitValidity(self: *const Self, signed_exit_bytes: js.Uint8Array, verify_signature_value: js.Boolean) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();
        const verify_signature = verify_signature_value.assertBool();
        const bytes = try signed_exit_bytes.toSlice();

        var signed_voluntary_exit: ct.phase0.SignedVoluntaryExit.Type = ct.phase0.SignedVoluntaryExit.default_value;
        ct.phase0.SignedVoluntaryExit.deserializeFromBytes(bytes, &signed_voluntary_exit) catch {
            return throwNull("DESERIALIZE_ERROR", "Failed to deserialize SignedVoluntaryExit");
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
            return throwNull("VALIDATION_ERROR", "Failed to get voluntary exit validity");
        };

        return asJsValue(try env.createStringUtf8(@tagName(validity)));
    }

    pub fn isValidVoluntaryExit(self: *const Self, signed_exit_bytes: js.Uint8Array, verify_signature_value: js.Boolean) !js.Value {
        const env = js.env();
        const cached_state = try self.requireState();
        const verify_signature = verify_signature_value.assertBool();
        const bytes = try signed_exit_bytes.toSlice();

        var signed_voluntary_exit: ct.phase0.SignedVoluntaryExit.Type = ct.phase0.SignedVoluntaryExit.default_value;
        ct.phase0.SignedVoluntaryExit.deserializeFromBytes(bytes, &signed_voluntary_exit) catch {
            return throwNull("DESERIALIZE_ERROR", "Failed to deserialize SignedVoluntaryExit");
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
            return throwNull("VALIDATION_ERROR", "Failed to validate voluntary exit");
        };

        return asJsValue(try env.getBoolean(is_valid));
    }

    pub fn getFinalizedRootProof(self: *const Self) !js.Value {
        const env = js.env();
        var proof = try (try self.requireState()).state.getFinalizedRootProof(allocator);
        defer proof.deinit(allocator);

        const witnesses = std.ArrayListUnmanaged([32]u8).fromOwnedSlice(proof.witnesses);
        return asJsValue(try sszValueToNapiValue(
            env,
            ct.phase0.HistoricalRoots,
            &witnesses,
        ));
    }

    pub fn getSingleProof(self: *const Self, gindex_arg: js.Number) !js.Value {
        const env = js.env();
        const gindex: u64 = @intCast(try gindex_arg.toI64());

        var proof = (try self.requireState()).state.getSingleProof(allocator, gindex) catch {
            return throwNull("STATE_ERROR", "Failed to get single proof");
        };
        defer proof.deinit(allocator);

        const result = try env.createArray();
        for (proof.witnesses, 0..) |witness, i| {
            var witness_bytes: [*]u8 = undefined;
            const witness_buf = try env.createArrayBuffer(32, &witness_bytes);
            @memcpy(witness_bytes[0..32], &witness);
            try result.setElement(@intCast(i), try env.createTypedarray(.uint8, 32, witness_buf, 0));
        }

        return asJsValue(result);
    }

    pub fn createMultiProof(self: *const Self, descriptor: js.Uint8Array) !js.Value {
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
            return throwNull("STATE_ERROR", "Failed to create proof");
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
                    var leaf_bytes: [*]u8 = undefined;
                    const leaf_buf = try env.createArrayBuffer(32, &leaf_bytes);
                    @memcpy(leaf_bytes[0..32], &leaf);
                    try leaves_array.setElement(@intCast(i), try env.createTypedarray(.uint8, 32, leaf_buf, 0));
                }
                try result.setNamedProperty("leaves", leaves_array);

                var descriptor_buf_bytes: [*]u8 = undefined;
                const descriptor_buf = try env.createArrayBuffer(compact.descriptor.len, &descriptor_buf_bytes);
                @memcpy(descriptor_buf_bytes[0..compact.descriptor.len], compact.descriptor);
                try result.setNamedProperty(
                    "descriptor",
                    try env.createTypedarray(.uint8, compact.descriptor.len, descriptor_buf, 0),
                );
            },
            else => return throwNull("STATE_ERROR", "Unexpected proof type"),
        }

        return asJsValue(result);
    }

    pub fn computeUnrealizedCheckpoints(self: *const Self) !js.Value {
        const env = js.env();
        const result = try st.computeUnrealizedCheckpoints(try self.requireState(), allocator);

        const obj = try env.createObject();
        try obj.setNamedProperty(
            "justifiedCheckpoint",
            try sszValueToNapiValue(env, ct.phase0.Checkpoint, &result.justified_checkpoint),
        );
        try obj.setNamedProperty(
            "finalizedCheckpoint",
            try sszValueToNapiValue(env, ct.phase0.Checkpoint, &result.finalized_checkpoint),
        );
        return asJsValue(obj);
    }

    pub fn clonedCount(self: *const Self) !js.Number {
        return js.Number.from((try self.requireState()).cloned_count);
    }

    pub fn clonedCountWithTransferCache(self: *const Self) !js.Number {
        return js.Number.from((try self.requireState()).cloned_count_with_transfer_cache);
    }

    pub fn createdWithTransferCache(self: *const Self) !js.Boolean {
        return js.Boolean.from((try self.requireState()).created_with_transfer_cache);
    }

    pub fn serialize(self: *const Self) !js.Uint8Array {
        const env = js.env();
        const result = try (try self.requireState()).state.serialize(allocator);
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
        const env = js.env();
        var validators_view = try (try self.requireState()).state.validators();

        const size = try validators_view.serializedSize();
        var arraybuffer_bytes: [*]u8 = undefined;
        const arraybuffer = try env.createArrayBuffer(size, &arraybuffer_bytes);
        _ = try validators_view.serializeIntoBytes(arraybuffer_bytes[0..size]);
        return .{ .val = try env.createTypedarray(.uint8, size, arraybuffer, 0) };
    }

    pub fn serializedValidatorsSize(self: *const Self) !js.Number {
        var validators_view = try (try self.requireState()).state.validators();
        const size = try validators_view.serializedSize();
        return js.Number.from(size);
    }

    pub fn serializeValidatorsToBytes(self: *const Self, output: js.Uint8Array, offset: js.Number) !js.Number {
        const output_slice = try output.toSlice();
        const off = try offset.toU32();
        if (off > output_slice.len) return error.InvalidOffset;

        var validators_view = try (try self.requireState()).state.validators();
        const bytes_written = try validators_view.serializeIntoBytes(output_slice[off..]);
        return js.Number.from(bytes_written);
    }

    pub fn hashTreeRoot(self: *const Self) !js.Uint8Array {
        const env = js.env();
        const root = try (try self.requireState()).state.hashTreeRoot();
        return .{ .val = try numberSliceToNapiValue(env, u8, root, .{ .typed_array = .uint8 }) };
    }

    pub fn processSlots(self: *const Self, slot_arg: js.Number, options: ?js.Value) !Self {
        const slot_value: u64 = @intCast(try slot_arg.toI64());
        const transfer_cache = try optionalBool(options, "transferCache", false);
        const post_state = try (try self.requireState()).clone(allocator, .{ .transfer_cache = transfer_cache });
        errdefer {
            post_state.deinit();
            allocator.destroy(post_state);
        }

        try st.processSlots(allocator, post_state, slot_value, .{});
        return .{ .cached_state = post_state };
    }
};
