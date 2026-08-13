//! JS binding for the `swap_or_not_shuffle` module.
//!
//! Except for `innerShuffleList` (an in-place, zero-allocation variant kept
//! for internal use), the exposed API mirrors the
//! `@chainsafe/swap-or-not-shuffle` npm package exactly: same function names,
//! argument order, return values, and error messages.

const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const napi = @import("zapi:zapi").napi;
const sons = @import("swap_or_not_shuffle");
const async_task = @import("./async_task.zig");

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

/// JS: shuffleList(activeIndices: Uint32Array, seed: Uint8Array, rounds: number): Uint32Array
pub fn shuffleList(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number) !js.Uint32Array {
    return shuffleListSync(active_indices, seed, rounds, true);
}

/// JS: unshuffleList(activeIndices: Uint32Array, seed: Uint8Array, rounds: number): Uint32Array
pub fn unshuffleList(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number) !js.Uint32Array {
    return shuffleListSync(active_indices, seed, rounds, false);
}

/// The input array is copied, shuffled in-place inside the copy, and returned;
/// the caller's array is never mutated (same as the reference).
fn shuffleListSync(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number, forwards: bool) !js.Uint32Array {
    const input = try active_indices.toSlice();
    const out_array = try js.Uint32Array.alloc(input.len);
    const out = try out_array.toSlice();
    @memcpy(out, input);

    sons.innerShuffleList(u32, out, try seed.toSlice(), rounds.assertI32(), forwards) catch |err| {
        return throwShufflingError(err);
    };
    return out_array;
}

/// JS: asyncShuffleList(activeIndices: Uint32Array, seed: Uint8Array, rounds: number): Promise<Uint32Array>
pub fn asyncShuffleList(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number) !js.Value {
    return shuffleListAsync(active_indices, seed, rounds, true, "asyncShuffleList");
}

/// JS: asyncUnshuffleList(activeIndices: Uint32Array, seed: Uint8Array, rounds: number): Promise<Uint32Array>
pub fn asyncUnshuffleList(active_indices: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number) !js.Value {
    return shuffleListAsync(active_indices, seed, rounds, false, "asyncUnshuffleList");
}

/// Shuffles a copy of the input off the JS thread. Inputs are copied with the
/// async_task allocator so the worker never touches JS-managed memory and the
/// result buffer can be transferred to JS zero-copy.
const ShuffleTask = struct {
    input: []u32,
    /// Copied at its original length; the worker validates it, so invalid
    /// seeds reject the promise exactly like the reference.
    seed: []u8,
    rounds: i32,
    forwards: bool,

    pub fn compute(self: *ShuffleTask) !void {
        try sons.innerShuffleList(u32, self.input, self.seed, self.rounds, self.forwards);
    }

    pub fn resolve(self: *ShuffleTask, env: napi.Env) !napi.Value {
        return async_task.transferOwnedSlice(u32, .uint32, env, &self.input);
    }

    pub fn errorMessage(err: anyerror) [:0]const u8 {
        return shuffleErrorMessage(err);
    }

    pub fn deinit(self: *ShuffleTask) void {
        // input is empty (freeing is a no-op) when resolve transferred it to JS
        async_task.allocator.free(self.input);
        async_task.allocator.free(self.seed);
    }
};

fn shuffleListAsync(
    active_indices: js.Uint32Array,
    seed: js.Uint8Array,
    rounds: js.Number,
    forwards: bool,
    comptime resource_name: []const u8,
) !js.Value {
    const input = try async_task.allocator.dupe(u32, try active_indices.toSlice());
    errdefer async_task.allocator.free(input);
    const seed_copy = try async_task.allocator.dupe(u8, try seed.toSlice());
    errdefer async_task.allocator.free(seed_copy);

    return async_task.spawn(ShuffleTask, .{
        .input = input,
        .seed = seed_copy,
        .rounds = rounds.assertI32(),
        .forwards = forwards,
    }, resource_name);
}

/// JS: new ComputeShuffledIndex(seed: Uint8Array, indexCount: number, rounds: number)
pub const ComputeShuffledIndex = struct {
    pub const js_meta = js.class(.{});

    inner: sons.ComputeShuffledIndex,

    pub fn init(seed: js.Uint8Array, index_count: js.Number, rounds: js.Number) !ComputeShuffledIndex {
        const inner = sons.ComputeShuffledIndex.init(
            allocator,
            try seed.toSlice(),
            index_count.assertU32(),
            rounds.assertU32(),
        ) catch |err| return throwShufflingError(err);
        return .{ .inner = inner };
    }

    pub fn deinit(self: *ComputeShuffledIndex) void {
        self.inner.deinit();
    }

    /// JS: get(index: number): number
    pub fn get(self: *ComputeShuffledIndex, index: js.Number) !js.Number {
        return js.Number.from(try self.inner.get(index.assertU32()));
    }
};

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

/// JS: computeProposerIndexElectra(seed, activeIndices, effectiveBalanceIncrements, maxEffectiveBalanceElectra, effectiveBalanceIncrement, rounds): number
pub fn computeProposerIndexElectra(
    seed: js.Uint8Array,
    active_indices: js.Uint32Array,
    effective_balance_increments: js.Uint16Array,
    max_effective_balance_electra: js.Number,
    effective_balance_increment: js.Number,
    rounds: js.Number,
) !js.Number {
    const result = sons.computeProposerIndexElectra(
        allocator,
        try seed.toSlice(),
        try active_indices.toSlice(),
        try effective_balance_increments.toSlice(),
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

/// JS: computeSyncCommitteeIndicesElectra(seed, activeIndices, effectiveBalanceIncrements, syncCommitteeSize, maxEffectiveBalanceElectra, effectiveBalanceIncrement, rounds): Uint32Array
pub fn computeSyncCommitteeIndicesElectra(
    seed: js.Uint8Array,
    active_indices: js.Uint32Array,
    effective_balance_increments: js.Uint16Array,
    sync_committee_size: js.Number,
    max_effective_balance_electra: js.Number,
    effective_balance_increment: js.Number,
    rounds: js.Number,
) !js.Uint32Array {
    const result = sons.computeSyncCommitteeIndicesElectra(
        allocator,
        try seed.toSlice(),
        try active_indices.toSlice(),
        try effective_balance_increments.toSlice(),
        sync_committee_size.assertU32(),
        max_effective_balance_electra.assertI64(),
        effective_balance_increment.assertI64(),
        rounds.assertU32(),
    ) catch |err| return throwShufflingError(err);
    defer allocator.free(result);
    return js.Uint32Array.from(result);
}
