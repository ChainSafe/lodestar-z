//! JS binding for the `swap_or_not_shuffle` module.
//!
//! The exposed surface is limited to what Lodestar actually calls
//! (ChainSafe/lodestar#9829): `unshuffleList`, `computeProposerIndex`,
//! `computeSyncCommitteeIndices`, plus the pre-existing in-place
//! `innerShuffleList`. Names, argument order, return values and error
//! messages match the `@chainsafe/swap-or-not-shuffle` npm package so the
//! call sites are a drop-in swap. The package's remaining exports (forward
//! `shuffleList`, the async variants, `ComputeShuffledIndex`, the Electra
//! wrappers, `SHUFFLE_ROUNDS_*`, `ByteCount`) stay unbound until a consumer
//! needs them — the Zig module still implements them.

const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const sons = @import("swap_or_not_shuffle");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug) gpa.allocator() else std.heap.c_allocator;

/// Error messages copied verbatim from the reference implementation.
fn shuffleErrorMessage(err: anyerror) [:0]const u8 {
    return switch (err) {
        error.InvalidSeedLength => "Shuffling seed must be 32 bytes long",
        error.InvalidActiveIndicesLength => "ActiveIndices must fit in a u32",
        error.InvalidNumberOfRounds => "Rounds must be between 0 and 255",
        else => @errorName(err),
    };
}

/// Throw the reference error message; the DSL wrapper's own throw of the Zig
/// error name is then swallowed as a pending exception.
fn throwShufflingError(err: anyerror) anyerror {
    js.throwError(shuffleErrorMessage(err));
    return err;
}

fn byteCountFromJs(rand_byte_count: js.Number) !sons.ByteCount {
    return switch (rand_byte_count.assertI32()) {
        1 => .one,
        2 => .two,
        else => throwShufflingError(error.InvalidByteCount),
    };
}

/// JS: innerShuffleList(out: Uint32Array, seed: Uint8Array, rounds: number, forwards: boolean): void
///
/// In-place, zero-allocation variant: mutates `out` directly instead of
/// returning a copy. Not part of the reference package API.
pub fn innerShuffleList(list: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number, forwards: js.Boolean) !void {
    const list_u32 = try list.toSlice();
    const seed_slice = try seed.toSlice();

    const rounds_i32 = rounds.assertI32();
    if (rounds_i32 < 0) return error.InvalidRoundsSize;
    if (rounds_i32 > 255) return error.InvalidRoundsSize;

    const is_forwards = forwards.assertBool();

    try sons.innerShuffleList(u32, list_u32, seed_slice, rounds_i32, is_forwards);
}

/// JS: unshuffleList(activeIndices: Uint32Array, seed: Uint8Array, rounds: number): Uint32Array
///
/// The input array is copied, un-shuffled in place inside the copy, and
/// returned; the caller's array is never mutated (same as the reference).
pub fn unshuffleList(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number) !js.Uint32Array {
    const input = try active_indices.toSlice();
    const out_array = try js.Uint32Array.alloc(input.len);
    const out = try out_array.toSlice();
    @memcpy(out, input);

    const forwards = false;
    sons.innerShuffleList(u32, out, try seed.toSlice(), rounds.assertI32(), forwards) catch |err| {
        return throwShufflingError(err);
    };
    return out_array;
}

/// JS: computeProposerIndex(seed, activeIndices, effectiveBalanceIncrements, randByteCount, maxEffectiveBalanceElectra, effectiveBalanceIncrement, rounds): number
pub fn computeProposerIndex(
    seed: js.Uint8Array,
    active_indices: js.Uint32Array,
    effective_balance_increments: js.Uint16Array,
    rand_byte_count: js.Number,
    max_effective_balance_electra: js.Number,
    effective_balance_increment: js.Number,
    rounds: js.Number,
) !js.Number {
    const result = sons.computeProposerIndex(
        allocator,
        try seed.toSlice(),
        try active_indices.toSlice(),
        try effective_balance_increments.toSlice(),
        try byteCountFromJs(rand_byte_count),
        max_effective_balance_electra.assertI64(),
        effective_balance_increment.assertI64(),
        rounds.assertU32(),
    ) catch |err| return throwShufflingError(err);
    return js.Number.from(result);
}

/// JS: computeSyncCommitteeIndices(seed, activeIndices, effectiveBalanceIncrements, randByteCount, syncCommitteeSize, maxEffectiveBalanceElectra, effectiveBalanceIncrement, rounds): Uint32Array
pub fn computeSyncCommitteeIndices(
    seed: js.Uint8Array,
    active_indices: js.Uint32Array,
    effective_balance_increments: js.Uint16Array,
    rand_byte_count: js.Number,
    sync_committee_size: js.Number,
    max_effective_balance_electra: js.Number,
    effective_balance_increment: js.Number,
    rounds: js.Number,
) !js.Uint32Array {
    const result = sons.computeSyncCommitteeIndices(
        allocator,
        try seed.toSlice(),
        try active_indices.toSlice(),
        try effective_balance_increments.toSlice(),
        try byteCountFromJs(rand_byte_count),
        sync_committee_size.assertU32(),
        max_effective_balance_electra.assertI64(),
        effective_balance_increment.assertI64(),
        rounds.assertU32(),
    ) catch |err| return throwShufflingError(err);
    defer allocator.free(result);
    return js.Uint32Array.from(result);
}
