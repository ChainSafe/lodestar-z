const std = @import("std");
const napi = @import("zapi:napi");
const c = @import("config");
const ForkSeq = c.ForkSeq;
const state_transition = @import("state_transition");
const ComputeIndexUtils = state_transition.committee_indices.ComputeIndexUtils(u32);
const ByteCount = state_transition.committee_indices.ByteCount;
const preset = state_transition.preset;

const allocator = std.heap.page_allocator;

pub fn ProposerIndex_computeProposerIndex(env: napi.Env, cb: napi.CallbackInfo(4)) !napi.Value {
    // arg 0: fork (string)
    var fork_name_buf: [16]u8 = undefined;
    const fork_name = try cb.arg(0).getValueStringUtf8(&fork_name_buf);
    const fork = ForkSeq.fromName(fork_name);

    // arg 1: effectiveBalanceIncrements (Uint16Array)
    const effective_balance_info = try cb.arg(1).getTypedarrayInfo();
    if (effective_balance_info.array_type != .uint16) {
        return error.InvalidEffectiveBalanceIncrementsType;
    }
    const effective_balance_increments: []u16 = @alignCast(std.mem.bytesAsSlice(u16, effective_balance_info.data));

    // arg 2: indices (Uint32Array)
    const indices_info = try cb.arg(2).getTypedarrayInfo();
    if (indices_info.array_type != .uint32) {
        return error.InvalidIndicesType;
    }
    const indices: []u32 = @alignCast(std.mem.bytesAsSlice(u32, indices_info.data));

    // arg 3: seed (Uint8Array, 32 bytes)
    const seed_info = try cb.arg(3).getTypedarrayInfo();
    if (seed_info.data.len != 32) {
        return error.InvalidSeedLength;
    }

    // Derive fork-dependent parameters
    const rand_byte_count: ByteCount = if (fork.gte(.electra)) .Two else .One;
    const max_effective_balance: u64 = if (fork.gte(.electra)) preset.MAX_EFFECTIVE_BALANCE_ELECTRA else preset.MAX_EFFECTIVE_BALANCE;

    const proposer_index = try ComputeIndexUtils.computeProposerIndex(
        allocator,
        seed_info.data,
        indices,
        effective_balance_increments,
        rand_byte_count,
        max_effective_balance,
        preset.EFFECTIVE_BALANCE_INCREMENT,
        preset.SHUFFLE_ROUND_COUNT,
    );

    return try env.createUint32(proposer_index);
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    try exports.setNamedProperty("computeProposerIndex", try env.createFunction(
        "computeProposerIndex",
        4,
        ProposerIndex_computeProposerIndex,
        null,
    ));
}
