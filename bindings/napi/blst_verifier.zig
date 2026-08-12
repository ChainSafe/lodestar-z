const std = @import("std");
const zapi = @import("zapi:zapi");
const napi = zapi.napi;
const bls = @import("bls");

const NativePublicKey = bls.PublicKey;
const NativeSignature = bls.Signature;
const SigningRoot = bls.SigningRoot;
const Pairing = bls.Pairing;
const ThreadPool = bls.ThreadPool;
const BatchVerifyItem = bls.BatchVerifyItem;
const DST = bls.DST;
const MAX_AGGREGATE_PER_JOB = bls.MAX_AGGREGATE_PER_JOB;

const random_scalar_retries_max = 8;

pub fn uint8Slice(value: napi.Value) ![]u8 {
    if (!(try value.isTypedarray())) return error.TypeMismatch;
    const info = try value.getTypedarrayInfo();
    if (info.array_type != .uint8) return error.TypeMismatch;
    return info.data;
}

pub fn parseSignature(bytes: []const u8) ?NativeSignature {
    if (bytes.len != NativeSignature.COMPRESS_SIZE and
        bytes.len != NativeSignature.SERIALIZE_SIZE)
    {
        return null;
    }

    var signature = NativeSignature.deserialize(bytes) catch return null;
    signature.validate(true) catch return null;
    return signature;
}

pub fn ensureNonzeroRandomScalar(io: std.Io, scalar: *[8]u8) !void {
    if (!std.mem.allEqual(u8, scalar, 0)) return;

    for (0..random_scalar_retries_max) |_| {
        io.random(scalar);
        if (!std.mem.allEqual(u8, scalar, 0)) return;
    }
    return error.RandomScalarGenerationFailed;
}

pub fn verifySignatureSets(
    io: std.Io,
    pool: *ThreadPool,
    items: []BatchVerifyItem,
    pks_validate: bool,
    sigs_groupcheck: bool,
    propagate_pool_shutdown: bool,
) !bool {
    for (items) |*item| {
        io.random(&item.randomness);
        try ensureNonzeroRandomScalar(io, item.randomness[0..8]);
    }

    return pool.verifyMultipleAggregateSignatures(
        io,
        items,
        DST,
        pks_validate,
        sigs_groupcheck,
    ) catch |err| switch (err) {
        error.ShuttingDown, error.Canceled => if (propagate_pool_shutdown) return err else false,
        else => false,
    };
}

pub fn verifySameMessage(
    io: std.Io,
    pool: *ThreadPool,
    public_keys: []*const NativePublicKey,
    signatures: []*const NativeSignature,
    message: *const SigningRoot,
) !bool {
    var randomness: [MAX_AGGREGATE_PER_JOB * 32]u8 = undefined;
    io.random(randomness[0 .. public_keys.len * 32]);
    for (0..public_keys.len) |i| {
        try ensureNonzeroRandomScalar(io, randomness[i * 32 ..][0..8]);
    }

    var aggregate_public_key: NativePublicKey = undefined;
    var aggregate_signature: NativeSignature = undefined;
    try pool.aggregateWithRandomness(
        io,
        public_keys,
        signatures,
        randomness[0 .. public_keys.len * 32],
        false,
        false,
        &aggregate_public_key,
        &aggregate_signature,
    );

    var pairing_buffer: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    return aggregate_signature.fastAggregateVerifyPreAggregated(
        false,
        &pairing_buffer,
        message,
        DST,
        &aggregate_public_key,
    ) catch false;
}
