const std = @import("std");
const bls = @import("bls");
const testing = std.testing;
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const interop = @import("../test_utils/interop_pubkeys.zig");
const sign_util = @import("bls.zig");
const PubkeyCache = @import("../cache/pubkey_cache.zig").PubkeyCache;
const indexed_verify = @import("indexed_verify.zig");
const VerifySet = indexed_verify.VerifySet;
const SameMessageSet = indexed_verify.SameMessageSet;

const cached_count = 8;

const Harness = struct {
    cache: PubkeyCache,
    pool: *bls.ThreadPool,
    pubkeys: [cached_count]types.primitive.BLSPubkey.Type,

    fn init() !Harness {
        var pubkeys: [cached_count]types.primitive.BLSPubkey.Type = undefined;
        try interop.interopPubkeysCached(cached_count, &pubkeys);

        var cache = PubkeyCache.init(testing.allocator, testing.io);
        errdefer cache.deinit();
        for (pubkeys, 0..) |pubkey, i| {
            try cache.append(testing.io, pubkey, i);
        }

        const pool = try bls.ThreadPool.init(testing.allocator, testing.io, .{ .n_workers = 2 });
        return .{ .cache = cache, .pool = pool, .pubkeys = pubkeys };
    }

    fn deinit(self: *Harness) void {
        self.pool.deinit(testing.io);
        self.cache.deinit();
    }

    fn verify(self: *Harness, sets: []const VerifySet) !bool {
        return indexed_verify.verifyIndexedSets(testing.allocator, testing.io, &self.cache, self.pool, sets);
    }

    fn verifySameMessage(self: *Harness, message: []const u8, sets: []const SameMessageSet) !bool {
        return indexed_verify.verifySameMessageSets(testing.allocator, testing.io, &self.cache, self.pool, message, sets);
    }
};

fn interopSigBytes(index: usize, message: *const bls.SigningRoot) ![96]u8 {
    const sig = try interop.interopSign(index, message);
    return sig.compress();
}

test "indexed_verify: mixed batch of all three set shapes verifies" {
    var h = try Harness.init();
    defer h.deinit();

    const msg_a: bls.SigningRoot = @splat(7);
    const msg_b: bls.SigningRoot = @splat(8);
    const msg_c: bls.SigningRoot = @splat(9);

    const indexed_sig = try interopSigBytes(0, &msg_a);

    // Aggregate of validators 1 and 2 over msg_b.
    const agg = try bls.AggregateSignature.aggregate(&.{
        try interop.interopSign(1, &msg_b),
        try interop.interopSign(2, &msg_b),
    }, false);
    const agg_sig = agg.toSignature().compress();

    // Single set: a key that is NOT in the validator registry.
    var ikm = [_]u8{42} ** 32;
    const sk = try bls.SecretKey.keyGen(&ikm, null);
    const single_pk = sk.toPublicKey().compress();
    const single_sig = sign_util.sign(sk, &msg_c).compress();

    const indices = [_]u32{ 1, 2 };
    const sets = [_]VerifySet{
        .{ .indexed = .{ .index = 0, .message = &msg_a, .signature = &indexed_sig } },
        .{ .aggregate = .{ .indices = &indices, .message = &msg_b, .signature = &agg_sig } },
        .{ .single = .{ .public_key = &single_pk, .message = &msg_c, .signature = &single_sig } },
    };
    try testing.expect(try h.verify(&sets));
}

test "indexed_verify: wrong signature fails the batch" {
    var h = try Harness.init();
    defer h.deinit();

    const msg: bls.SigningRoot = @splat(7);
    // Signed by validator 1, claimed for validator 0.
    const sig = try interopSigBytes(1, &msg);
    const sets = [_]VerifySet{
        .{ .indexed = .{ .index = 0, .message = &msg, .signature = &sig } },
    };
    try testing.expect(!try h.verify(&sets));
}

test "indexed_verify: semantic-failure inputs return false, caller bugs error" {
    var h = try Harness.init();
    defer h.deinit();

    const msg: bls.SigningRoot = @splat(7);
    const good_sig = try interopSigBytes(0, &msg);
    const garbage96: [96]u8 = @splat(0xaa);
    const garbage48: [48]u8 = @splat(0xaa);
    const empty_indices = [_]u32{};
    const unknown_in_aggregate = [_]u32{ 1, 99 };

    // Empty batch.
    try testing.expect(!try h.verify(&.{}));
    // Malformed signature bytes.
    try testing.expect(!try h.verify(&.{
        .{ .indexed = .{ .index = 0, .message = &msg, .signature = &garbage96 } },
    }));
    // Invalid raw public key in a single set.
    try testing.expect(!try h.verify(&.{
        .{ .single = .{ .public_key = &garbage48, .message = &msg, .signature = &good_sig } },
    }));
    // Unknown validator index.
    try testing.expect(!try h.verify(&.{
        .{ .indexed = .{ .index = 99, .message = &msg, .signature = &good_sig } },
    }));
    // Unknown index inside an aggregate.
    try testing.expect(!try h.verify(&.{
        .{ .aggregate = .{ .indices = &unknown_in_aggregate, .message = &msg, .signature = &good_sig } },
    }));
    // Empty aggregate indices.
    try testing.expect(!try h.verify(&.{
        .{ .aggregate = .{ .indices = &empty_indices, .message = &msg, .signature = &good_sig } },
    }));
    // Mixed batch where one set is bad fails the whole batch.
    try testing.expect(!try h.verify(&.{
        .{ .indexed = .{ .index = 0, .message = &msg, .signature = &good_sig } },
        .{ .indexed = .{ .index = 99, .message = &msg, .signature = &good_sig } },
    }));
    // Wrong message length is a caller bug, not a peer-scored failure.
    const short_msg = [_]u8{1} ** 31;
    try testing.expectError(error.InvalidMessageLength, h.verify(&.{
        .{ .indexed = .{ .index = 0, .message = &short_msg, .signature = &good_sig } },
    }));
}

test "indexed_verify: aggregate edge shapes — one index, duplicate indices" {
    var h = try Harness.init();
    defer h.deinit();

    const msg: bls.SigningRoot = @splat(11);

    // Aggregate of exactly one index behaves like an indexed set.
    const solo_sig = try interopSigBytes(3, &msg);
    const solo = [_]u32{3};
    try testing.expect(try h.verify(&.{
        .{ .aggregate = .{ .indices = &solo, .message = &msg, .signature = &solo_sig } },
    }));

    // Duplicate indices: key aggregated twice, so the matching signature is
    // the same signer's signature aggregated twice.
    const twice = try bls.AggregateSignature.aggregate(&.{
        try interop.interopSign(4, &msg),
        try interop.interopSign(4, &msg),
    }, false);
    const twice_sig = twice.toSignature().compress();
    const duplicated = [_]u32{ 4, 4 };
    try testing.expect(try h.verify(&.{
        .{ .aggregate = .{ .indices = &duplicated, .message = &msg, .signature = &twice_sig } },
    }));
}

test "indexed_verify: same-message fused verification" {
    var h = try Harness.init();
    defer h.deinit();

    const msg: bls.SigningRoot = @splat(21);
    var sig_bytes: [4][96]u8 = undefined;
    for (0..4) |i| {
        sig_bytes[i] = try interopSigBytes(i, &msg);
    }

    const good = [_]SameMessageSet{
        .{ .index = 0, .signature = &sig_bytes[0] },
        .{ .index = 1, .signature = &sig_bytes[1] },
        .{ .index = 2, .signature = &sig_bytes[2] },
        .{ .index = 3, .signature = &sig_bytes[3] },
    };
    try testing.expect(try h.verifySameMessage(&msg, &good));

    // One signature swapped between validators fails the fused batch.
    const one_bad = [_]SameMessageSet{
        .{ .index = 0, .signature = &sig_bytes[0] },
        .{ .index = 1, .signature = &sig_bytes[2] },
        .{ .index = 2, .signature = &sig_bytes[1] },
        .{ .index = 3, .signature = &sig_bytes[3] },
    };
    try testing.expect(!try h.verifySameMessage(&msg, &one_bad));

    // Unknown index.
    const unknown = [_]SameMessageSet{
        .{ .index = 0, .signature = &sig_bytes[0] },
        .{ .index = 99, .signature = &sig_bytes[1] },
    };
    try testing.expect(!try h.verifySameMessage(&msg, &unknown));

    // Empty input.
    try testing.expect(!try h.verifySameMessage(&msg, &.{}));

    // Wrong message length is a caller bug.
    const short_msg = [_]u8{1} ** 31;
    try testing.expectError(error.InvalidMessageLength, h.verifySameMessage(&short_msg, &good));
}

test "indexed_verify: same-message batches chunk across the pool job bound" {
    var h = try Harness.init();
    defer h.deinit();

    // More sets than MAX_AGGREGATE_PER_JOB (128) forces multi-chunk
    // aggregation; reuse the harness signers cyclically.
    const total = 130;
    const msg: bls.SigningRoot = @splat(31);
    var sig_bytes: [cached_count][96]u8 = undefined;
    for (0..cached_count) |i| {
        sig_bytes[i] = try interopSigBytes(i, &msg);
    }

    var sets: [total]SameMessageSet = undefined;
    for (0..total) |i| {
        sets[i] = .{ .index = i % cached_count, .signature = &sig_bytes[i % cached_count] };
    }
    try testing.expect(try h.verifySameMessage(&msg, &sets));

    // One corrupted signature fails the multi-chunk batch.
    sets[129] = .{ .index = 129 % cached_count, .signature = &sig_bytes[(129 + 1) % cached_count] };
    try testing.expect(!try h.verifySameMessage(&msg, &sets));
}

test "indexed_verify: oversized inputs are caller bugs" {
    var h = try Harness.init();
    defer h.deinit();

    const msg: bls.SigningRoot = @splat(1);
    // Structurally valid signature: per-set caps are checked after wire
    // parsing, so garbage bytes would return false before the cap error.
    const valid_sig = try interopSigBytes(0, &msg);

    const big_sets = try testing.allocator.alloc(SameMessageSet, indexed_verify.max_sets + 1);
    defer testing.allocator.free(big_sets);
    @memset(big_sets, .{ .index = 0, .signature = &valid_sig });
    try testing.expectError(error.TooManySignatureSets, h.verifySameMessage(&msg, big_sets));

    const big_indices = try testing.allocator.alloc(u32, indexed_verify.max_aggregate_indices + 1);
    defer testing.allocator.free(big_indices);
    @memset(big_indices, 0);
    try testing.expectError(error.TooManyAggregateIndices, h.verify(&.{
        .{ .aggregate = .{ .indices = big_indices, .message = &msg, .signature = &valid_sig } },
    }));
}
