const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const bls = @import("bls");
const preset = @import("preset").preset;
const blst_bindings = @import("./blst.zig");
const blst_verifier = @import("./blst_verifier.zig");
const pubkeys = @import("./pubkeys.zig");

const NativePublicKey = bls.PublicKey;
const NativeSignature = bls.Signature;
const BatchVerifyItem = bls.BatchVerifyItem;
const DST = bls.DST;

// Bound synchronous NAPI work and the fixed stack buffers below. Lodestar's
// worker jobs normally contain at most 128 sets, so 256 provides headroom while
// requiring unusually large direct callers to chunk explicitly.
const max_verify_sets = 256;
const max_same_message_sets = bls.MAX_AGGREGATE_PER_JOB;
const max_indices_per_set = preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT;

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

fn parseSignature(set: napi.Value) !?NativeSignature {
    const value = js.Value{ .val = try set.getNamedProperty("signature") };
    const bytes = try (try value.asUint8Array()).toSlice();
    var signature = NativeSignature.deserialize(bytes) catch return null;
    signature.validate(true) catch return null;
    return signature;
}

fn resolvePublicKey(set: napi.Value, set_type: SetType) !?NativePublicKey {
    const io = js.io();
    return switch (set_type) {
        .indexed => blk: {
            if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
            const index = try uint32(try set.getNamedProperty("index"));
            break :blk pubkeys.state.cache.getPubkey(io, index) orelse
                return error.PubkeyIndexNotFound;
        },
        .aggregate => blk: {
            if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
            const indices = try uint32Slice(try set.getNamedProperty("indices"));
            if (indices.len == 0) return error.EmptyIndices;
            if (indices.len > max_indices_per_set) return error.TooManyIndices;

            break :blk pubkeys.state.cache.aggregateU32(io, indices) catch |err| switch (err) {
                error.InvalidIndex => return error.PubkeyIndexNotFound,
                error.InvalidLength => return error.EmptyIndices,
            };
        },
        .single => blk: {
            const value = js.Value{ .val = try set.getNamedProperty("pubkey") };
            const bytes = try (try value.asUint8Array()).toSlice();
            var public_key = NativePublicKey.deserialize(bytes) catch break :blk null;
            public_key.validate() catch break :blk null;
            break :blk public_key;
        },
    };
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

    var messages: [max_verify_sets][32]u8 = undefined;
    var public_keys: [max_verify_sets]NativePublicKey = undefined;
    var signatures: [max_verify_sets]NativeSignature = undefined;
    var items: [max_verify_sets]BatchVerifyItem = undefined;

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
        messages[i] = message[0..32].*;

        public_keys[i] = (try resolvePublicKey(set, set_type)) orelse
            return js.Boolean.from(false);

        signatures[i] = (try parseSignature(set)) orelse
            return js.Boolean.from(false);

        items[i] = .{
            .message = messages[i],
            .public_key = &public_keys[i],
            .signature = &signatures[i],
            .randomness = undefined,
        };
    }

    if (count == 1) {
        signatures[0].verify(
            false,
            &messages[0],
            DST,
            null,
            &public_keys[0],
            false,
        ) catch return js.Boolean.from(false);
        return js.Boolean.from(true);
    }

    const pool = blst_bindings.state.thread_pool orelse
        return error.ThreadPoolNotInitialized;
    const result = try blst_verifier.verifySignatureSets(
        js.io(),
        pool,
        items[0..count],
        .{
            .pks_validate = false,
            .sigs_groupcheck = false,
            .propagate_pool_shutdown = true,
        },
    );

    return js.Boolean.from(result);
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

    var public_keys: [max_same_message_sets]NativePublicKey = undefined;
    var public_key_refs: [max_same_message_sets]*const NativePublicKey = undefined;
    var signatures: [max_same_message_sets]NativeSignature = undefined;
    var signature_refs: [max_same_message_sets]*const NativeSignature = undefined;
    var signature_valid: [max_same_message_sets]bool = undefined;
    var can_aggregate = true;

    const io = js.io();
    for (0..count) |i| {
        const set = (try sets.get(@intCast(i))).toValue();
        const index = try uint32(try set.getNamedProperty("index"));
        public_keys[i] = pubkeys.state.cache.getPubkey(io, index) orelse
            return error.PubkeyIndexNotFound;
        public_key_refs[i] = &public_keys[i];

        if (try parseSignature(set)) |signature| {
            signatures[i] = signature;
            signature_refs[i] = &signatures[i];
            signature_valid[i] = true;
        } else {
            signature_valid[i] = false;
            can_aggregate = false;
        }
    }

    if (can_aggregate) {
        const pool = blst_bindings.state.thread_pool orelse
            return error.ThreadPoolNotInitialized;
        if (try blst_verifier.verifySameMessage(
            io,
            pool,
            public_key_refs[0..count],
            signature_refs[0..count],
            &exact_message,
        )) {
            for (0..count) |i| try results.set(@intCast(i), js.Boolean.from(true));
            return results;
        }
    }

    for (0..count) |i| {
        const is_valid = signature_valid[i] and blk: {
            signatures[i].verify(
                false,
                &exact_message,
                DST,
                null,
                &public_keys[i],
                false,
            ) catch break :blk false;
            break :blk true;
        };
        try results.set(@intCast(i), js.Boolean.from(is_valid));
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
