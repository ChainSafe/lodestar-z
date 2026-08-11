//! v2 pubkey cache bindings backed by the lock-free draft cache. Mirrors
//! `pubkeys.zig` (minus PKIX save/load) so the two implementations can be
//! benchmarked side by side from JS. See `pubkey_cache_lockfree.zig`.

const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const blst_bindings = @import("./blst.zig");
const state_transition = @import("state_transition");
const LockFreePubkeyCache = state_transition.LockFreePubkeyCache;
const Validator = @import("consensus_types").phase0.Validator.Type;

/// Uses the page allocator for the process-wide cache's internal allocations.
const allocator = std.heap.page_allocator;

const default_initial_capacity: u32 = 0;
const max_stack_aggregate_pubkeys = 512;

const State = struct {
    cache: LockFreePubkeyCache = undefined,
    initialized: bool = false,
    control_env: napi.c.napi_env = null,

    pub fn init(self: *State, env: napi.Env) !void {
        if (self.initialized) return;

        self.cache = try LockFreePubkeyCache.initCapacity(allocator, js.io(), default_initial_capacity);
        self.initialized = true;
        self.control_env = env.env;
    }

    pub fn deinit(self: *State) void {
        if (!self.initialized) return;
        self.cache.deinit();
        self.initialized = false;
        self.control_env = null;
    }

    fn requireControlEnvironment(self: *const State, env: napi.Env) !void {
        if (self.control_env == null or self.control_env != env.env) {
            return error.PubkeyCacheControlEnvironmentOnly;
        }
    }
};

pub var state: State = .{};

/// JS: pubkeysV2.reset()
pub fn reset() !void {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    try state.requireControlEnvironment(js.env());
    try state.cache.clear(js.io());
}

/// JS: pubkeysV2.getIndex(pubkeyBytes) → number | null
pub fn getIndex(pubkey: js.Uint8Array) !js.Value {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) return error.InvalidPubkeyLength;
    const pubkey_bytes = pubkey_slice[0..48].*;

    const io = js.io();
    const index = state.cache.get(io, pubkey_bytes);

    const e = js.env();
    if (index) |validator_index| {
        return .{ .val = try e.createUint32(@intCast(validator_index)) };
    }
    return .{ .val = try e.getNull() };
}

/// JS: pubkeysV2.get(index) → PublicKey | undefined
pub fn get(index: js.Number) !?blst_bindings.PublicKey {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const idx = try index.toU32();
    const io = js.io();
    const public_key = state.cache.getPubkey(io, idx) orelse return null;
    return .{ .raw = public_key };
}

/// JS: pubkeysV2.getPubkeyBytes(index) → Uint8Array | undefined
pub fn getPubkeyBytes(index: js.Number) !?js.Uint8Array {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const idx = try index.toU32();
    const io = js.io();
    const pubkey_bytes = state.cache.getPubkeyBytes(io, idx) orelse return null;
    return try js.Uint8Array.fromExternal(pubkey_bytes[0..]);
}

/// JS: pubkeysV2.aggregate(indices) → PublicKey
pub fn aggregate(indices: js.Array) !blst_bindings.PublicKey {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const len = try indices.length();
    if (len == 0) return error.EmptyPublicKeyArray;

    var indices_stack: [max_stack_aggregate_pubkeys]u64 = undefined;
    const exact_indices = if (len <= indices_stack.len)
        indices_stack[0..len]
    else blk: {
        const buf = try allocator.alloc(u64, len);
        break :blk buf;
    };
    defer if (len > indices_stack.len) allocator.free(exact_indices);

    for (0..len) |i| {
        exact_indices[i] = try (try indices.getNumber(@intCast(i))).toU32();
    }

    const io = js.io();
    const aggregate_pubkey = if (exact_indices.len == 1)
        state.cache.getPubkey(io, exact_indices[0]) orelse return error.PubkeyIndexNotFound
    else
        state.cache.aggregate(io, exact_indices) catch |err| switch (err) {
            error.InvalidIndex => return error.PubkeyIndexNotFound,
            else => return error.AggregationFailed,
        };

    return .{ .raw = aggregate_pubkey };
}

/// JS: pubkeysV2.append(index, pubkeyBytes)
pub fn append(index: js.Number, pubkey: js.Uint8Array) !void {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const idx = try index.toU32();
    const io = js.io();

    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) return error.InvalidPubkeyLength;
    const pubkey_bytes = pubkey_slice[0..48].*;

    try state.cache.append(io, pubkey_bytes, idx);
}

/// JS: pubkeysV2.syncPubkeys(validators)
pub fn syncPubkeys(validators: js.Array) !void {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const validator_count = try validators.length();
    const io = js.io();
    const num_cached = state.cache.count(io);
    if (validator_count <= num_cached) return;

    const num_new_validators = validator_count - num_cached;

    // SAFETY: the first `num_cached` validator ptrs are intentionally left undefined,
    // because syncPubkeys only has to append the last `num_new_validators` pubkeys.
    const validator_ptrs = try allocator.alloc(*const Validator, validator_count);
    defer allocator.free(validator_ptrs);

    const new_validators = try allocator.alloc(Validator, num_new_validators);
    defer allocator.free(new_validators);

    for (num_cached..validator_count, 0..) |new_index, i| {
        const value = try validators.get(@intCast(new_index));
        const partial_validator = try (try value.asObject(struct { pubkey: js.Uint8Array })).get();

        new_validators[i] = undefined;
        new_validators[i].pubkey = try partial_validator.pubkey.toArray(blst_bindings.PublicKey.COMPRESS_SIZE);
        validator_ptrs[new_index] = &new_validators[i];
    }

    try state.cache.syncPubkeys(io, validator_ptrs);
}

/// JS: pubkeysV2.size() → number
pub fn size() !js.Number {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    const io = js.io();
    return js.Number.from(state.cache.count(io));
}

/// JS: pubkeysV2.ensureCapacity(newSize)
pub fn ensureCapacity(new_size: js.Number) !void {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const requested = try new_size.toU32();
    const io = js.io();
    try state.cache.ensureTotalCapacity(io, requested);
}

/// JS: pubkeysV2.capacity() → number
pub fn capacity() !js.Number {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    const io = js.io();
    const current_capacity: u32 = @intCast(state.cache.capacity(io));
    return js.Number.from(current_capacity);
}
