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

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug) gpa.allocator() else std.heap.c_allocator;

/// Error messages copied verbatim from the reference implementation.
fn errorMessage(err: anyerror) [:0]const u8 {
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
    js.throwError(errorMessage(err));
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

/// Heap-allocated context shared between the JS thread (which kicks off the
/// work), the libuv worker thread (which shuffles), and the JS thread again
/// (which resolves/rejects the Promise). Inputs are copied so the worker never
/// touches JS-managed memory.
const AsyncShuffleData = struct {
    input: []u32,
    /// Copied at its original length; the worker validates it, so invalid
    /// seeds reject the promise exactly like the reference.
    seed: []u8,
    rounds: i32,
    forwards: bool,
    err: ?anyerror,
    deferred: napi.Deferred,
    work: napi.c.napi_async_work,
};

fn shuffleListAsync(
    active_indices: js.Uint32Array,
    seed: js.Uint8Array,
    rounds: js.Number,
    forwards: bool,
    comptime resource_name_str: []const u8,
) !js.Value {
    const env = js.env();

    const data = try allocator.create(AsyncShuffleData);
    errdefer allocator.destroy(data);

    data.input = try allocator.dupe(u32, try active_indices.toSlice());
    errdefer allocator.free(data.input);
    data.seed = try allocator.dupe(u8, try seed.toSlice());
    errdefer allocator.free(data.seed);
    data.rounds = rounds.assertI32();
    data.forwards = forwards;
    data.err = null;
    data.deferred = undefined;
    data.work = undefined;

    const deferred_cleanup_value = try env.getUndefined();
    const resource_name = try env.createStringUtf8(resource_name_str);

    const work = try env.createAsyncWork(
        AsyncShuffleData,
        null,
        resource_name,
        asyncShuffleExecute,
        asyncShuffleComplete,
        data,
    );
    errdefer work.delete() catch |err| {
        std.log.err("failed to delete unqueued async shuffle work: {s}", .{@errorName(err)});
    };

    data.work = work.work;

    // Settle the unreturned Promise so Node can release its deferred handle.
    data.deferred = try env.createPromise();
    errdefer data.deferred.resolve(deferred_cleanup_value) catch |err| {
        std.log.err("failed to settle unreturned async shuffle promise: {s}", .{@errorName(err)});
    };

    try work.queue();

    return .{ .val = data.deferred.getPromise() };
}

/// Runs on a libuv worker thread. MUST NOT call any napi APIs.
fn asyncShuffleExecute(_: napi.Env, data: *AsyncShuffleData) void {
    sons.innerShuffleList(u32, data.input, data.seed, data.rounds, data.forwards) catch |err| {
        data.err = err;
    };
}

/// Runs on the JS thread once the worker has finished. Always settles the
/// promise; if settling itself fails we fall back to a bare reject so callers
/// never see a dangling Promise.
fn asyncShuffleComplete(env: napi.Env, status: napi.status.Status, data: *AsyncShuffleData) void {
    var input_owned = true;
    defer {
        napi.status.check(napi.c.napi_delete_async_work(env.env, data.work)) catch {};
        allocator.free(data.seed);
        if (input_owned) allocator.free(data.input);
        allocator.destroy(data);
    }

    settleAsyncShuffle(env, status, data, &input_owned) catch {
        rejectWithMessage(env, data.deferred, "InternalError") catch {};
    };
}

fn settleAsyncShuffle(env: napi.Env, status: napi.status.Status, data: *AsyncShuffleData, input_owned: *bool) !void {
    if (status != .ok) {
        // libuv's async work itself failed (e.g. cancelled), not the shuffle.
        return rejectWithMessage(env, data.deferred, @tagName(status));
    }
    if (data.err) |err| {
        return rejectWithMessage(env, data.deferred, errorMessage(err));
    }

    if (data.input.len == 0) {
        const arraybuffer = try env.createArrayBuffer(0, null);
        const result = try env.createTypedarray(.uint32, 0, arraybuffer, 0);
        return data.deferred.resolve(result);
    }

    // Zero-copy: transfer the worker's result buffer to JS as an external
    // ArrayBuffer; V8 frees it via the finalizer when the array is collected.
    const byte_len = data.input.len * @sizeOf(u32);
    const finalize_cb = comptime napi.wrapSliceFinalizeCallback(u32, asyncResultFinalizer);
    const len_hint: ?*anyopaque = @ptrFromInt(data.input.len);
    const arraybuffer = try env.createExternalArrayBuffer(std.mem.sliceAsBytes(data.input), finalize_cb, len_hint);
    input_owned.* = false;
    _ = env.adjustExternalMemory(@intCast(byte_len)) catch {};

    const result = try env.createTypedarray(.uint32, data.input.len, arraybuffer, 0);
    try data.deferred.resolve(result);
}

/// Frees the result buffer handed to `createExternalArrayBuffer` and reverses
/// the matching `adjustExternalMemory` accounting.
fn asyncResultFinalizer(env: napi.Env, data: []u32) void {
    const byte_len = data.len * @sizeOf(u32);
    allocator.free(data);
    _ = env.adjustExternalMemory(-@as(i64, @intCast(byte_len))) catch {};
}

/// Reject `deferred` with `new Error(message)` so JS callers can match on
/// `err.message` exactly like with the reference package.
fn rejectWithMessage(env: napi.Env, deferred: napi.Deferred, message: []const u8) !void {
    const msg_val = try env.createStringUtf8(message);
    const err_val = try env.createError(napi.Value{ .env = env.env, .value = null }, msg_val);
    try deferred.reject(err_val);
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
