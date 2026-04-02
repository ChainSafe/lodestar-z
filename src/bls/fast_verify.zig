/// Number of random bytes used for verification.
const RAND_BYTES = 8;

/// Number of random bits used for verification.
const RAND_BITS = 8 * RAND_BYTES;

/// Verify multiple aggregate signatures efficiently using random coefficients.
///
/// Source: https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
///
/// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
pub fn verifyMultipleAggregateSignatures(
    pairing_buf: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
) BlstError!bool {
    if (n_elems == 0) {
        return BlstError.VerifyFail;
    }

    var pairing = Pairing.init(
        pairing_buf,
        true,
        dst,
    );

    for (0..n_elems) |i| {
        try pairing.mulAndAggregate(
            pks[i],
            pks_validate,
            sigs[i],
            sigs_groupcheck,
            &rands[i],
            RAND_BITS,
            &msgs[i],
        );
    }

    pairing.commit();

    return pairing.finalVerify(null);
}

/// Verify an array of signature sets by resolving aggregate pubkeys and
/// decompressing signatures inside the verification loop.
pub fn verifySignatureSets(
    pairing_buf: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    sets: []const SignatureSet,
    dst: []const u8,
    rands: []const [32]u8,
) BlstError!bool {
    if (sets.len == 0 or rands.len != sets.len) {
        return BlstError.VerifyFail;
    }

    var pairing = Pairing.init(
        pairing_buf,
        true,
        dst,
    );

    for (sets, 0..) |set, i| {
        const pk = try set.resolvePublicKey();
        const sig = try set.decompressSignature();
        try pairing.mulAndAggregate(
            &pk,
            false,
            &sig,
            true,
            &rands[i],
            RAND_BITS,
            &set.signing_root,
        );
    }

    pairing.commit();
    return pairing.finalVerify(null);
}

pub const SameMessageAggregate = struct {
    public_key: AggregatePublicKey,
    signature: AggregateSignature,
};

/// Aggregate signature sets that all sign the same message using the same
/// randomized weighting scheme as `verifySignatureSets`.
pub fn aggregateSignatureSetsSameMessage(
    sets: []const SignatureSet,
    message: *const [32]u8,
    rands: []const [32]u8,
) BlstError!SameMessageAggregate {
    if (sets.len == 0 or rands.len != sets.len) {
        return BlstError.VerifyFail;
    }

    var aggregate: ?SameMessageAggregate = null;

    for (sets, 0..) |set, i| {
        if (!std.mem.eql(u8, &set.signing_root, message)) {
            return BlstError.VerifyFail;
        }

        const pk = try set.resolvePublicKey();
        const sig = try set.decompressSignature();

        const weighted_pk = weightPublicKey(&pk, &rands[i]);
        const weighted_sig = weightSignature(&sig, &rands[i]);

        if (aggregate) |*agg| {
            c.blst_p1_add_or_double(
                @ptrCast(&agg.public_key.point),
                @ptrCast(&agg.public_key.point),
                @ptrCast(&weighted_pk.point),
            );
            c.blst_p2_add_or_double(
                @ptrCast(&agg.signature.point),
                @ptrCast(&agg.signature.point),
                @ptrCast(&weighted_sig.point),
            );
        } else {
            aggregate = .{
                .public_key = weighted_pk,
                .signature = weighted_sig,
            };
        }
    }

    return aggregate orelse BlstError.VerifyFail;
}

/// Verify signature sets that all sign the same message by collapsing them
/// into one weighted aggregate public key and one weighted aggregate signature.
pub fn verifySignatureSetsSameMessage(
    pairing_buf: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    sets: []const SignatureSet,
    dst: []const u8,
    rands: []const [32]u8,
) BlstError!bool {
    if (sets.len == 0) {
        return BlstError.VerifyFail;
    }

    const message = sets[0].signing_root;
    const aggregate = try aggregateSignatureSetsSameMessage(sets, &message, rands);
    const sig = aggregate.signature.toSignature();
    const pk = aggregate.public_key.toPublicKey();

    return sig.fastAggregateVerifyPreAggregated(
        true,
        pairing_buf,
        &message,
        dst,
        &pk,
    );
}

fn weightPublicKey(pk: *const PublicKey, rand: *const [32]u8) AggregatePublicKey {
    var base = c.blst_p1{};
    c.blst_p1_from_affine(@ptrCast(&base), @ptrCast(&pk.point));

    var weighted = AggregatePublicKey{};
    c.blst_p1_mult(
        @ptrCast(&weighted.point),
        @ptrCast(&base),
        rand,
        RAND_BITS,
    );
    return weighted;
}

fn weightSignature(sig: *const Signature, rand: *const [32]u8) AggregateSignature {
    var base = c.blst_p2{};
    c.blst_p2_from_affine(@ptrCast(&base), @ptrCast(&sig.point));

    var weighted = AggregateSignature{};
    c.blst_p2_mult(
        @ptrCast(&weighted.point),
        @ptrCast(&base),
        rand,
        RAND_BITS,
    );
    return weighted;
}

const BlstError = @import("error.zig").BlstError;
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const SignatureSet = @import("signature_set.zig").SignatureSet;
const std = @import("std");
const c = @cImport({
    @cInclude("blst.h");
});

test "verifySignatureSetsSameMessage verifies same-message sets" {
    const SecretKey = @import("SecretKey.zig");

    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const msg = [_]u8{0xAB} ** 32;

    var sigs: [5]Signature = undefined;
    var pks: [5]PublicKey = undefined;
    var sets: [3]SignatureSet = undefined;

    for (0..5) |i| {
        var ikm = base_ikm;
        ikm[0] +%= @intCast(i);
        const sk = try SecretKey.keyGen(&ikm, null);
        pks[i] = sk.toPublicKey();
        sigs[i] = sk.sign(&msg, blst.DST, null);
    }

    const agg_sig = try AggregateSignature.aggregate(sigs[1..3], false);
    sets[0] = SignatureSet.initSingle(pks[0], msg, sigs[0].compress());
    sets[1] = SignatureSet.initAggregate(pks[1..3], msg, agg_sig.toSignature().compress());
    sets[2] = SignatureSet.initSingle(pks[4], msg, sigs[4].compress());

    var prng = std.Random.DefaultPrng.init(0xA11C_EBAA_DCAF_E123);
    const rand = prng.random();
    var rands: [3][32]u8 = undefined;
    for (&rands) |*r| std.Random.bytes(rand, r);

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    try std.testing.expect(try verifySignatureSetsSameMessage(
        &pairing_buf,
        &sets,
        blst.DST,
        &rands,
    ));
}

test "verifySignatureSetsSameMessage rejects mixed signing roots" {
    const SecretKey = @import("SecretKey.zig");

    const ikm_a: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const ikm_b: [32]u8 = .{
        0x94, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const msg_a = [_]u8{0xAA} ** 32;
    const msg_b = [_]u8{0xBB} ** 32;

    const sk_a = try SecretKey.keyGen(&ikm_a, null);
    const sk_b = try SecretKey.keyGen(&ikm_b, null);
    const sig_a = sk_a.sign(&msg_a, blst.DST, null);
    const sig_b = sk_b.sign(&msg_b, blst.DST, null);

    const sets = [_]SignatureSet{
        SignatureSet.initSingle(sk_a.toPublicKey(), msg_a, sig_a.compress()),
        SignatureSet.initSingle(sk_b.toPublicKey(), msg_b, sig_b.compress()),
    };

    var prng = std.Random.DefaultPrng.init(0xBEEF_F00D_1234_5678);
    const rand = prng.random();
    var rands: [2][32]u8 = undefined;
    for (&rands) |*r| std.Random.bytes(rand, r);

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    try std.testing.expectError(
        BlstError.VerifyFail,
        verifySignatureSetsSameMessage(&pairing_buf, &sets, blst.DST, &rands),
    );
}
