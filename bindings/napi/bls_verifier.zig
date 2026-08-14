const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const bls = @import("bls");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const blst_bindings = @import("./blst.zig");
const pubkeys = @import("./pubkeys.zig");

const NativePublicKey = bls.PublicKey;
const signature_set_verifier = state_transition.signature_set_verifier;

// Bound synchronous NAPI work and the fixed stack buffers below. Lodestar's
// worker jobs normally contain at most 128 sets, so 256 provides headroom while
// requiring unusually large direct callers to chunk explicitly.
const max_verify_sets = 256;
const max_same_message_sets = bls.MAX_AGGREGATE_PER_JOB;
const max_indices_per_set = preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT;
const SignatureSetBatch = signature_set_verifier.SignatureSetBatch(max_verify_sets);
const SameMessageSignatureSetBatch = signature_set_verifier.SameMessageSignatureSetBatch(max_same_message_sets);

const SetType = enum(u32) {
    indexed = 0,
    aggregate = 1,
    single = 2,
};

fn uint32Slice(value: napi.Value) ![]u32 {
    try js.Uint32Array.validateArg(value);
    return (js.Uint32Array{ .val = value }).toSlice();
}

fn uint32(value: napi.Value) !u32 {
    const number = try value.getValueDouble();
    const max_u32: f64 = @floatFromInt(std.math.maxInt(u32));
    if (!std.math.isFinite(number) or number < 0 or number > max_u32 or @floor(number) != number) {
        return error.InvalidUint32;
    }
    return @intFromFloat(number);
}

/// Verify indexed, aggregate, and raw-pubkey signature sets synchronously.
///
/// Returns false as soon as a cryptographically invalid set is encountered.
/// Evaluation short-circuits, so later sets are not inspected. Cache and
/// interface errors throw only when encountered before the result is known.
pub fn verifySignatureSets(sets: js.Array) !js.Boolean {
    const count = try sets.length();
    if (count == 0) return js.Boolean.from(false);
    if (count > max_verify_sets) return error.TooManySets;

    var batch: SignatureSetBatch = .{};
    const io = js.io();

    for (0..count) |i| {
        const set = (try sets.get(@intCast(i))).toValue();
        const set_type: SetType = switch (try uint32(try set.getNamedProperty("type"))) {
            @intFromEnum(SetType.indexed) => .indexed,
            @intFromEnum(SetType.aggregate) => .aggregate,
            @intFromEnum(SetType.single) => .single,
            else => return error.InvalidSetType,
        };

        const message_value = js.Value{ .val = try set.getNamedProperty("message") };
        const message = try (try message_value.asUint8Array()).toSlice();
        if (message.len != 32) return error.InvalidMessageLength;

        const public_key: NativePublicKey = switch (set_type) {
            .indexed => blk: {
                if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
                const index = try uint32(try set.getNamedProperty("index"));
                break :blk pubkeys.state.cache.getPubkey(io, index) orelse
                    return error.PubkeyIndexNotFound;
            },
            .aggregate => blk: {
                if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
                const indices = try uint32Slice(try set.getNamedProperty("indices"));
                if (indices.len > max_indices_per_set) return error.TooManyIndices;
                break :blk pubkeys.state.cache.aggregateU32(io, indices) catch |err| switch (err) {
                    error.InvalidIndex => return error.PubkeyIndexNotFound,
                    error.InvalidLength => return error.EmptyIndices,
                };
            },
            .single => blk: {
                const value = js.Value{ .val = try set.getNamedProperty("pubkey") };
                const bytes = try (try value.asUint8Array()).toSlice();
                break :blk NativePublicKey.keyValidate(bytes) catch return js.Boolean.from(false);
            },
        };

        const signature_value = js.Value{ .val = try set.getNamedProperty("signature") };
        const signature = try (try signature_value.asUint8Array()).toSlice();
        if (!batch.append(&public_key, message[0..32], signature)) return js.Boolean.from(false);
    }

    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;
    return js.Boolean.from(try batch.verify(io, pool));
}

/// Randomly aggregate and verify indexed signatures over the same message.
/// Returns one result per input, falling back to individual checks only when
/// the aggregate check fails.
pub fn verifySignatureSetsSameMessage(sets: js.Array, message: js.Uint8Array) !js.Array {
    const count = try sets.length();
    if (count > max_same_message_sets) return error.TooManySets;

    const results = js.Array.createWithLength(count);
    if (count == 0) return results;

    const message_slice = try message.toSlice();
    if (message_slice.len != 32) return error.InvalidMessageLength;
    const exact_message = message_slice[0..32].*;

    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;

    var batch: SameMessageSignatureSetBatch = .{};

    const io = js.io();
    for (0..count) |i| {
        const set = (try sets.get(@intCast(i))).toValue();
        const index = try uint32(try set.getNamedProperty("index"));
        const public_key = pubkeys.state.cache.getPubkey(io, index) orelse
            return error.PubkeyIndexNotFound;

        const signature_value = js.Value{ .val = try set.getNamedProperty("signature") };
        const signature = try (try signature_value.asUint8Array()).toSlice();
        batch.append(&public_key, signature);
    }

    var verification_results: [max_same_message_sets]bool = undefined;
    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;
    try batch.verify(
        io,
        pool,
        &exact_message,
        verification_results[0..count],
    );

    for (0..count) |i| {
        try results.set(@intCast(i), js.Boolean.from(verification_results[i]));
    }

    return results;
}

pub fn indexedSetType() js.Number {
    return js.Number.from(@intFromEnum(SetType.indexed));
}

pub fn aggregateSetType() js.Number {
    return js.Number.from(@intFromEnum(SetType.aggregate));
}

pub fn singleSetType() js.Number {
    return js.Number.from(@intFromEnum(SetType.single));
}

pub fn maxBatchSize() js.Number {
    return js.Number.from(max_verify_sets);
}

pub fn maxSameMessageBatchSize() js.Number {
    return js.Number.from(max_same_message_sets);
}
