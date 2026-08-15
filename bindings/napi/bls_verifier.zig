const zapi = @import("zapi:zapi");
const js = zapi.js;
const bls = @import("bls");

const async_verifier = @import("./bls_verifier_async.zig");
const common = @import("./bls_verifier_common.zig");
const blst_bindings = @import("./blst.zig");
const pubkeys = @import("./pubkeys.zig");

const max_verify_sets = common.max_verify_sets;
const max_same_message_sets = common.max_same_message_sets;
const max_indices_per_set = common.max_indices_per_set;
const SignatureSetBatch = common.SignatureSetBatch;
const SameMessageSignatureSetBatch = common.SameMessageSignatureSetBatch;
const SetType = common.SetType;
const CommonSet = common.CommonSet;
const IndexedSet = common.IndexedSet;
const AggregateSet = common.AggregateSet;
const SingleSet = common.SingleSet;
const SameMessageSet = common.SameMessageSet;
const uint32 = common.uint32;

/// Verify indexed, aggregate, and raw-pubkey signature sets synchronously.
///
/// Returns false on cryptographic failure. Throws for malformed inputs and
/// cache misses encountered before a result is known.
pub fn verifySignatureSets(sets: js.Array) !js.Boolean {
    const count = try sets.length();
    if (count == 0) return js.Boolean.from(false);
    if (count > max_verify_sets) return error.TooManySets;

    var batch: SignatureSetBatch = .{};
    const io = js.io();

    for (0..count) |i| {
        const value = try sets.get(@intCast(i));
        const set = try (try value.asObject(CommonSet)).get();
        const set_type: SetType = switch (try uint32(set.type)) {
            @intFromEnum(SetType.indexed) => .indexed,
            @intFromEnum(SetType.aggregate) => .aggregate,
            @intFromEnum(SetType.single) => .single,
            else => return error.InvalidSetType,
        };

        const message = try set.message.toSlice();
        if (message.len != 32) return error.InvalidMessageLength;

        const public_key: bls.PublicKey = switch (set_type) {
            .indexed => blk: {
                if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
                const indexed = try (try value.asObject(IndexedSet)).get();
                const index = try uint32(indexed.index);
                break :blk pubkeys.state.cache.getPubkey(io, index) orelse
                    return error.PubkeyIndexNotFound;
            },
            .aggregate => blk: {
                if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
                const aggregate = try (try value.asObject(AggregateSet)).get();
                const indices = try aggregate.indices.toSlice();
                if (indices.len > max_indices_per_set) return error.TooManyIndices;
                break :blk pubkeys.state.cache.aggregateIndices(io, u32, indices) catch |err| switch (err) {
                    error.InvalidIndex => return error.PubkeyIndexNotFound,
                    error.InvalidLength => return error.EmptyIndices,
                };
            },
            .single => blk: {
                const single = try (try value.asObject(SingleSet)).get();
                const bytes = try single.pubkey.toSlice();
                break :blk bls.PublicKey.keyValidate(bytes) catch return js.Boolean.from(false);
            },
        };

        const signature = try set.signature.toSlice();
        if (!batch.append(&public_key, message[0..32], signature)) return js.Boolean.from(false);
    }

    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;
    return js.Boolean.from(try batch.verify(io, pool));
}

/// Randomly aggregate and verify indexed signatures over the same message.
///
/// Returns one validity result per input, preserving order. Uses aggregate
/// verification with individual fallback. Throws on invalid input, cache
/// errors, or pool unavailability.
pub fn verifySignatureSetsSameMessage(sets: js.Array, message: js.Uint8Array) !js.Array {
    const count = try sets.length();
    if (count > max_same_message_sets) return error.TooManySets;

    const results = js.Array.createWithLength(count);
    if (count == 0) return results;

    const message_slice = try message.toSlice();
    if (message_slice.len != 32) return error.InvalidMessageLength;

    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;

    var batch: SameMessageSignatureSetBatch = .{};

    const io = js.io();
    for (0..count) |i| {
        const value = try sets.get(@intCast(i));
        const set = try (try value.asObject(SameMessageSet)).get();
        const index = try uint32(set.index);
        const public_key = pubkeys.state.cache.getPubkey(io, index) orelse
            return error.PubkeyIndexNotFound;

        batch.append(&public_key, try set.signature.toSlice());
    }

    var verification_results: [max_same_message_sets]bool = undefined;
    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;
    try batch.verify(
        io,
        pool,
        message_slice[0..32],
        verification_results[0..count],
    );

    for (0..count) |i| {
        try results.set(@intCast(i), js.Boolean.from(verification_results[i]));
    }

    return results;
}

pub fn verifySignatureSetsAsync(sets: js.Array, critical: ?js.Boolean) !js.Value {
    return async_verifier.verifySignatureSets(sets, critical);
}

pub fn verifySignatureSetsSameMessageAsync(
    sets: js.Array,
    message: js.Uint8Array,
    critical: ?js.Boolean,
) !js.Value {
    return async_verifier.verifySignatureSetsSameMessage(sets, message, critical);
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
