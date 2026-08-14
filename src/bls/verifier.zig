const std = @import("std");
const bls = @import("root.zig");

const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const SigningRoot = bls.SigningRoot;
const Pairing = bls.Pairing;
const ThreadPool = bls.ThreadPool;
const BatchVerifyItem = bls.BatchVerifyItem;
const DST = bls.DST;
const MAX_AGGREGATE_PER_JOB = bls.MAX_AGGREGATE_PER_JOB;

// A correct RNG produces an all-zero 64-bit scalar with probability 2^-64.
// Keep retries bounded so a broken RNG fails instead of looping forever.
const random_scalar_retries_max = 8;

pub const VerifySignatureSetsOptions = struct {
    pks_validate: bool = true,
    sigs_groupcheck: bool = true,
};

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
    options: VerifySignatureSetsOptions,
) !bool {
    if (items.len == 0) return false;
    if (items.len == 1) {
        const item = &items[0];
        item.signature.verify(
            options.sigs_groupcheck,
            item.message,
            DST,
            null,
            item.public_key,
            options.pks_validate,
        ) catch return false;
        return true;
    }

    for (items) |*item| {
        io.random(&item.randomness);
        try ensureNonzeroRandomScalar(io, item.randomness[0..8]);
    }

    return pool.verifyMultipleAggregateSignatures(
        io,
        items,
        DST,
        options.pks_validate,
        options.sigs_groupcheck,
    );
}

test "single signature set verification" {
    const ikm = [_]u8{1} ** 32;
    var message = [_]u8{2} ** 32;
    const secret_key = try bls.SecretKey.keyGen(&ikm, null);
    const public_key = secret_key.toPublicKey();
    const signature = secret_key.sign(&message, DST, null);
    var items = [_]BatchVerifyItem{.{
        .message = &message,
        .public_key = &public_key,
        .signature = &signature,
        .randomness = undefined,
    }};

    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 1 });
    defer pool.deinit(std.testing.io);

    try std.testing.expect(try verifySignatureSets(
        std.testing.io,
        pool,
        &items,
        .{ .pks_validate = true, .sigs_groupcheck = true },
    ));

    message = [_]u8{3} ** 32;
    try std.testing.expect(!try verifySignatureSets(
        std.testing.io,
        pool,
        &items,
        .{ .pks_validate = true, .sigs_groupcheck = true },
    ));
}

pub fn verifySameMessage(
    io: std.Io,
    pool: *ThreadPool,
    public_keys: []*const PublicKey,
    signatures: []*const Signature,
    message: *const SigningRoot,
) !bool {
    if (public_keys.len == 0 or public_keys.len != signatures.len) return error.InvalidLength;
    if (public_keys.len > MAX_AGGREGATE_PER_JOB) return error.TooManySignatureSets;

    var randomness: [MAX_AGGREGATE_PER_JOB * 32]u8 = undefined;
    io.random(randomness[0 .. public_keys.len * 32]);
    for (0..public_keys.len) |i| {
        try ensureNonzeroRandomScalar(io, randomness[i * 32 ..][0..8]);
    }

    var aggregate_public_key: PublicKey = undefined;
    var aggregate_signature: Signature = undefined;
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

test "same-message verification rejects invalid set counts" {
    var empty_public_keys = [_]*const PublicKey{};
    var empty_signatures = [_]*const Signature{};
    const message = [_]u8{0} ** 32;
    const pool: *ThreadPool = undefined;

    try std.testing.expectError(
        error.InvalidLength,
        verifySameMessage(
            std.testing.io,
            pool,
            &empty_public_keys,
            &empty_signatures,
            &message,
        ),
    );

    const too_many = MAX_AGGREGATE_PER_JOB + 1;
    var public_keys: [too_many]*const PublicKey = undefined;
    var signatures: [too_many]*const Signature = undefined;
    try std.testing.expectError(
        error.TooManySignatureSets,
        verifySameMessage(
            std.testing.io,
            pool,
            &public_keys,
            &signatures,
            &message,
        ),
    );
}
