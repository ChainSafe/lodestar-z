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

const max_verify_sets = 256;
const max_same_message_sets = bls.MAX_AGGREGATE_PER_JOB;
const max_indices_per_set = preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT;

const SetType = enum(u32) {
    indexed = 0,
    aggregate = 1,
    single = 2,
};

fn uint8Slice(value: napi.Value) ![]u8 {
    return blst_verifier.uint8Slice(value);
}

fn uint32Slice(value: napi.Value) ![]u32 {
    if (!(try value.isTypedarray())) return error.TypeMismatch;
    const info = try value.getTypedarrayInfo();
    if (info.array_type != .uint32) return error.TypeMismatch;

    const byte_ptr: [*]u8 = info.data.ptr;
    const typed_ptr: [*]u32 = @ptrCast(@alignCast(byte_ptr));
    return typed_ptr[0..info.length];
}

fn uint32(value: napi.Value) !u32 {
    const number = try value.getValueDouble();
    const max_u32: f64 = @floatFromInt(std.math.maxInt(u32));
    if (!std.math.isFinite(number) or number < 0 or number > max_u32 or @floor(number) != number) {
        return error.InvalidUint32;
    }
    return @intFromFloat(number);
}

fn parseMessage(set: napi.Value) ![32]u8 {
    const message = try uint8Slice(try set.getNamedProperty("message"));
    if (message.len != 32) return error.InvalidMessageLength;
    return message[0..32].*;
}

fn parseSignature(set: napi.Value) !?NativeSignature {
    const bytes = try uint8Slice(try set.getNamedProperty("signature"));
    return blst_verifier.parseSignature(bytes);
}

fn parsePublicKey(set: napi.Value) !?NativePublicKey {
    const bytes = try uint8Slice(try set.getNamedProperty("pubkey"));
    if (bytes.len != NativePublicKey.COMPRESS_SIZE and
        bytes.len != NativePublicKey.SERIALIZE_SIZE)
    {
        return null;
    }
    var public_key = NativePublicKey.deserialize(bytes) catch return null;
    public_key.validate() catch return null;
    return public_key;
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
        .single => try parsePublicKey(set),
    };
}

/// Verify indexed, aggregate, and raw-pubkey signature sets synchronously.
///
/// Invalid cryptographic inputs return false. Cache misses and malformed
/// interface inputs throw so callers do not classify operational failures as
/// invalid signatures.
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

        messages[i] = try parseMessage(set);

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
        false,
        false,
        true,
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
