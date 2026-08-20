//! JS binding for the `swap_or_not_shuffle` module. Function names and
//! argument order match `@chainsafe/swap-or-not-shuffle`; errors surface as
//! Zig error names, like the other bindings here.

const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const sons = @import("swap_or_not_shuffle");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug) gpa.allocator() else std.heap.c_allocator;

/// `assertI32`/`assertU32` coerce with ToInt32/ToUint32, which wrap: a caller
/// passing 2**32 + 10 would silently be given 10. Require an exact integer so
/// out-of-range values are rejected instead.
fn exactI32(value: js.Number) !i32 {
    const f = try value.toF64();
    if (!std.math.isFinite(f) or @trunc(f) != f or
        f < @as(f64, std.math.minInt(i32)) or f > @as(f64, std.math.maxInt(i32)))
    {
        return error.InvalidInteger;
    }
    return @intFromFloat(f);
}

fn byteCountFromJs(rand_byte_count: js.Number) !sons.ByteCount {
    return switch (rand_byte_count.assertI32()) {
        1 => .one,
        2 => .two,
        else => error.InvalidByteCount,
    };
}

/// JS: innerShuffleList(out: Uint32Array, seed: Uint8Array, rounds: number, forwards: boolean): void
///
/// Shuffles `out` in place, no allocation.
pub fn innerShuffleList(list: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number, forwards: js.Boolean) !void {
    const list_u32 = try list.toSlice();
    const seed_slice = try seed.toSlice();

    const rounds_i32 = exactI32(rounds) catch return error.InvalidRoundsSize;
    if (rounds_i32 < 0) return error.InvalidRoundsSize;
    if (rounds_i32 > 255) return error.InvalidRoundsSize;

    const is_forwards = forwards.assertBool();

    try sons.innerShuffleList(u32, list_u32, seed_slice, rounds_i32, is_forwards);
}

/// JS: unshuffleList(activeIndices: Uint32Array, seed: Uint8Array, rounds: number): Uint32Array
///
/// Copies the input array and un-shuffles the copy.
///
/// Returns the copy.
pub fn unshuffleList(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number) !js.Uint32Array {
    const input = try active_indices.toSlice();
    const out_array = try js.Uint32Array.alloc(input.len);
    const out = try out_array.toSlice();
    @memcpy(out, input);

    const forwards = false;
    try sons.innerShuffleList(u32, out, try seed.toSlice(), try exactI32(rounds), forwards);
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
    const result = try sons.computeProposerIndex(
        allocator,
        try seed.toSlice(),
        try active_indices.toSlice(),
        try effective_balance_increments.toSlice(),
        try byteCountFromJs(rand_byte_count),
        max_effective_balance_electra.assertI64(),
        effective_balance_increment.assertI64(),
        try rounds.toU32Exact(),
    );
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
    const result = try sons.computeSyncCommitteeIndices(
        allocator,
        try seed.toSlice(),
        try active_indices.toSlice(),
        try effective_balance_increments.toSlice(),
        try byteCountFromJs(rand_byte_count),
        try sync_committee_size.toU32Exact(),
        max_effective_balance_electra.assertI64(),
        effective_balance_increment.assertI64(),
        try rounds.toU32Exact(),
    );
    defer allocator.free(result);
    return js.Uint32Array.from(result);
}
