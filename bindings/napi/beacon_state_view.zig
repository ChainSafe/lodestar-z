const std = @import("std");
const napi = @import("zapi:napi");
const c = @import("config");
const state_transition = @import("state_transition");
const BeaconState = state_transition.BeaconState;
const CachedBeaconState = state_transition.CachedBeaconState;
const ExecutionPayloadHeader = state_transition.ExecutionPayloadHeader;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const SignedBlock = state_transition.SignedBlock;
const isExecutionEnabledFunc = state_transition.isExecutionEnabled;
const computeUnrealizedCheckpoints = state_transition.computeUnrealizedCheckpoints;
const getEffectiveBalanceIncrementsZeroInactiveFn = state_transition.getEffectiveBalanceIncrementsZeroInactive;
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

pub fn BeaconStateView_proposersPrevEpoch(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
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
    const result = cached_state.getEpochCache().current_sync_committee_indexed.get();
    const validator_indices = result.getValidatorIndices();
    const validator_index_map = result.getValidatorIndexMap();
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

pub fn BeaconStateView_effectiveBalanceIncrements(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const increments = cached_state.getEpochCache().getEffectiveBalanceIncrements();
    return try numberSliceToNapiValue(env, u16, increments.items, .{ .typed_array = .uint16 });
}

pub fn BeaconStateView_latestExecutionPayloadHeader(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var header: ExecutionPayloadHeader = undefined;
    try cached_state.state.latestExecutionPayloadHeader(allocator, &header);
    defer header.deinit(allocator);

    return switch (header) {
        .bellatrix => |*h| try sszValueToNapiValue(env, ct.bellatrix.ExecutionPayloadHeader, h),
        .capella => |*h| try sszValueToNapiValue(env, ct.capella.ExecutionPayloadHeader, h),
        .deneb => |*h| try sszValueToNapiValue(env, ct.deneb.ExecutionPayloadHeader, h),
        .electra => |*h| try sszValueToNapiValue(env, ct.electra.ExecutionPayloadHeader, h),
        .fulu => |*h| try sszValueToNapiValue(env, ct.fulu.ExecutionPayloadHeader, h),
    };
}

pub fn BeaconStateView_syncProposerReward(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const sync_proposer_reward = cached_state.getEpochCache().sync_proposer_reward;
    return try env.createInt64(@intCast(sync_proposer_reward));
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
    var currnet_epoch_participation: ct.altair.EpochParticipation.Type = .{};
    try view.toValue(allocator, &currnet_epoch_participation);
    defer currnet_epoch_participation.deinit(allocator);
    return try sszValueToNapiValue(env, ct.altair.EpochParticipation, &currnet_epoch_participation);
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

pub fn BeaconStateView_serializeToBytes(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
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

    const output_slice = output_info.data[offset..];
    const bytes_written = switch (cached_state.state.*) {
        inline else => |*state| try state.serializeIntoBytes(output_slice),
    };

    return try env.createInt64(@intCast(bytes_written));
}

pub fn BeaconStateView_hashTreeRoot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const root = try cached_state.state.hashTreeRoot();
    return try numberSliceToNapiValue(env, u8, root, .{ .typed_array = .uint8 });
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
            .{ .utf8name = "latestExecutionPayloadHeader", .getter = napi.wrapCallback(0, BeaconStateView_latestExecutionPayloadHeader) },
            .{ .utf8name = "previousJustifiedCheckpoint", .getter = napi.wrapCallback(0, BeaconStateView_previousJustifiedCheckpoint) },
            .{ .utf8name = "currentJustifiedCheckpoint", .getter = napi.wrapCallback(0, BeaconStateView_currentJustifiedCheckpoint) },
            .{ .utf8name = "finalizedCheckpoint", .getter = napi.wrapCallback(0, BeaconStateView_finalizedCheckpoint) },
            .{ .utf8name = "proposers", .getter = napi.wrapCallback(0, BeaconStateView_proposers) },
            .{ .utf8name = "proposersNextEpoch", .getter = napi.wrapCallback(0, BeaconStateView_proposersNextEpoch) },
            .{ .utf8name = "proposersPrevEpoch", .getter = napi.wrapCallback(0, BeaconStateView_proposersPrevEpoch) },
            .{ .utf8name = "currentSyncCommittee", .getter = napi.wrapCallback(0, BeaconStateView_currentSyncCommittee) },
            .{ .utf8name = "nextSyncCommittee", .getter = napi.wrapCallback(0, BeaconStateView_nextSyncCommittee) },
            .{ .utf8name = "currentSyncCommitteeIndexed", .getter = napi.wrapCallback(0, BeaconStateView_currentSyncCommitteeIndexed) },
            .{ .utf8name = "syncProposerReward", .getter = napi.wrapCallback(0, BeaconStateView_syncProposerReward) },
            .{ .utf8name = "effectiveBalanceIncrements", .getter = napi.wrapCallback(0, BeaconStateView_effectiveBalanceIncrements) },
            .{ .utf8name = "previousEpochParticipation", .getter = napi.wrapCallback(0, BeaconStateView_previousEpochParticipation) },
            .{ .utf8name = "currentEpochParticipation", .getter = napi.wrapCallback(0, BeaconStateView_currentEpochParticipation) },
            .{ .utf8name = "getBalance", .method = napi.wrapCallback(1, BeaconStateView_getBalance) },
            .{ .utf8name = "isExecutionEnabled", .method = napi.wrapCallback(2, BeaconStateView_isExecutionEnabled) },
            .{ .utf8name = "isExecutionStateType", .method = napi.wrapCallback(0, BeaconStateView_isExecutionStateType) },
            .{ .utf8name = "getEffectiveBalanceIncrementsZeroInactive", .method = napi.wrapCallback(0, BeaconStateView_getEffectiveBalanceIncrementsZeroInactive) },
            .{ .utf8name = "getFinalizedRootProof", .method = napi.wrapCallback(0, BeaconStateView_getFinalizedRootProof) },
            .{ .utf8name = "computeUnrealizedCheckpoints", .method = napi.wrapCallback(0, BeaconStateView_computeUnrealizedCheckpoints) },
            .{ .utf8name = "serialize", .method = napi.wrapCallback(0, BeaconStateView_serialize) },
            .{ .utf8name = "serializedSize", .method = napi.wrapCallback(0, BeaconStateView_serializedSize) },
            .{ .utf8name = "serializeToBytes", .method = napi.wrapCallback(2, BeaconStateView_serializeToBytes) },
            .{ .utf8name = "hashTreeRoot", .method = napi.wrapCallback(0, BeaconStateView_hashTreeRoot) },
        },
    );
    // Static method on constructor
    try beacon_state_view_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "createFromBytes",
        .method = napi.wrapCallback(2, BeaconStateView_createFromBytes),
    }});

    try exports.setNamedProperty("BeaconStateView", beacon_state_view_ctor);
}
