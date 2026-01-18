const std = @import("std");
const napi = @import("zapi:napi");
const c = @import("config");
const state_transition = @import("state_transition");
const BeaconState = state_transition.BeaconState;
const CachedBeaconState = state_transition.CachedBeaconState;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const SignedBlock = state_transition.SignedBlock;
const isExecutionEnabledFunc = state_transition.isExecutionEnabled;
const preset = @import("preset").preset;
const types = @import("consensus_types");
const pool = @import("./pool.zig");
const config = @import("./config.zig");
const pubkey = @import("./pubkey2index.zig");

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
    const root = try cached_state.state.hashTreeRoot();
    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(32, &arraybuffer_bytes);
    const typedarray = try env.createTypedarray(.uint8, 32, arraybuffer, 0);
    @memcpy(arraybuffer_bytes[0..32], root);
    return typedarray;
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
    const root = try cached_state.state.genesisValidatorsRoot();
    var bytes: [*]u8 = undefined;
    const buf = try env.createArrayBuffer(32, &bytes);
    @memcpy(bytes[0..32], root);
    return try env.createTypedarray(.uint8, 32, buf, 0);
}

pub fn BeaconStateView_latestBlockHeader(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var header_view = try cached_state.state.latestBlockHeader();
    var header: types.phase0.BeaconBlockHeader.Type = undefined;
    try header_view.toValue(allocator, &header);
    const obj = try env.createObject();
    try obj.setNamedProperty("slot", try env.createInt64(@intCast(header.slot)));
    try obj.setNamedProperty("proposerIndex", try env.createInt64(@intCast(header.proposer_index)));
    var pr: [*]u8 = undefined;
    const pr_buf = try env.createArrayBuffer(32, &pr);
    @memcpy(pr[0..32], &header.parent_root);
    try obj.setNamedProperty("parentRoot", try env.createTypedarray(.uint8, 32, pr_buf, 0));
    var sr: [*]u8 = undefined;
    const sr_buf = try env.createArrayBuffer(32, &sr);
    @memcpy(sr[0..32], &header.state_root);
    try obj.setNamedProperty("stateRoot", try env.createTypedarray(.uint8, 32, sr_buf, 0));
    var br: [*]u8 = undefined;
    const br_buf = try env.createArrayBuffer(32, &br);
    @memcpy(br[0..32], &header.body_root);
    try obj.setNamedProperty("bodyRoot", try env.createTypedarray(.uint8, 32, br_buf, 0));
    return obj;
}

fn checkpointToObject(env: napi.Env, cp: *const types.phase0.Checkpoint.Type) !napi.Value {
    const obj = try env.createObject();
    try obj.setNamedProperty("epoch", try env.createInt64(@intCast(cp.epoch)));
    var bytes: [*]u8 = undefined;
    const buf = try env.createArrayBuffer(32, &bytes);
    @memcpy(bytes[0..32], &cp.root);
    try obj.setNamedProperty("root", try env.createTypedarray(.uint8, 32, buf, 0));
    return obj;
}

pub fn BeaconStateView_previousJustifiedCheckpoint(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var cp: types.phase0.Checkpoint.Type = undefined;
    try cached_state.state.previousJustifiedCheckpoint(&cp);
    return checkpointToObject(env, &cp);
}

pub fn BeaconStateView_currentJustifiedCheckpoint(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var cp: types.phase0.Checkpoint.Type = undefined;
    try cached_state.state.currentJustifiedCheckpoint(&cp);
    return checkpointToObject(env, &cp);
}

pub fn BeaconStateView_finalizedCheckpoint(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var cp: types.phase0.Checkpoint.Type = undefined;
    try cached_state.state.finalizedCheckpoint(&cp);
    return checkpointToObject(env, &cp);
}

pub fn BeaconStateView_proposers(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch_cache = cached_state.getEpochCache();
    const proposers = epoch_cache.proposers;

    const arr = try env.createArrayWithLength(preset.SLOTS_PER_EPOCH);
    for (0..preset.SLOTS_PER_EPOCH) |i| {
        try arr.setElement(@intCast(i), try env.createInt64(@intCast(proposers[i])));
    }
    return arr;
}

pub fn BeaconStateView_proposersNextEpoch(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const epoch_cache = cached_state.getEpochCache();

    if (epoch_cache.proposers_next_epoch) |proposers| {
        const arr = try env.createArrayWithLength(preset.SLOTS_PER_EPOCH);
        for (0..preset.SLOTS_PER_EPOCH) |i| {
            try arr.setElement(@intCast(i), try env.createInt64(@intCast(proposers[i])));
        }
        return arr;
    }
    return env.getNull();
}

// getBalance(index: number): bigint
pub fn BeaconStateView_getBalance(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const index: u64 = @intCast(try cb.arg(0).getValueInt64());
    var balances = try cached_state.state.balances();
    const balance = try balances.get(index);
    return try env.createBigintUint64(balance);
}

// isExecutionEnabled(forkName: string, signedBlockBytes: Uint8Array): boolean
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

pub fn BeaconStateView_getFinalizedRootProof(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    var proof = try cached_state.state.getFinalizedRootProof(allocator);
    defer proof.deinit(allocator);

    const arr = try env.createArrayWithLength(proof.witnesses.len);
    for (proof.witnesses, 0..) |witness, i| {
        var bytes: [*]u8 = undefined;
        const buf = try env.createArrayBuffer(32, &bytes);
        @memcpy(bytes[0..32], &witness);
        try arr.setElement(@intCast(i), try env.createTypedarray(.uint8, 32, buf, 0));
    }
    return arr;
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
            .{ .utf8name = "isExecutionEnabled", .method = napi.wrapCallback(2, BeaconStateView_isExecutionEnabled) },
            .{ .utf8name = "getFinalizedRootProof", .method = napi.wrapCallback(0, BeaconStateView_getFinalizedRootProof) },
        },
    );
    // Static method on constructor
    try beacon_state_view_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "createFromBytes",
        .method = napi.wrapCallback(2, BeaconStateView_createFromBytes),
    }});

    try exports.setNamedProperty("BeaconStateView", beacon_state_view_ctor);
}
