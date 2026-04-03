const std = @import("std");
const bls = @import("bls");
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const SecretKey = bls.SecretKey;

/// See https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
const DST: []const u8 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub fn sign(secret_key: SecretKey, msg: []const u8) Signature {
    return secret_key.sign(msg, DST, null);
}

/// Verify a signature against a message and public key.
///
/// If `pk_validate` is `true`, the public key will be infinity and group checked.
///
/// If `sig_groupcheck` is `true`, the signature will be group checked.
pub fn verify(msg: []const u8, pk: *const PublicKey, sig: *const Signature, in_pk_validate: ?bool, in_sig_groupcheck: ?bool) bls.BlstError!void {
    const sig_groupcheck = in_sig_groupcheck orelse false;
    const pk_validate = in_pk_validate orelse false;
    try sig.verify(sig_groupcheck, msg, DST, null, pk, pk_validate);
}

/// The `msg` must be at least 32 bytes; only the first 32 are passed to
/// fast aggregate verification.
pub fn fastAggregateVerify(msg: []const u8, pks: []const PublicKey, sig: *const Signature, in_pk_validate: ?bool, in_sigs_group_check: ?bool) !bool {
    std.debug.assert(msg.len >= 32);

    var pairing_buf: [bls.Pairing.sizeOf()]u8 align(bls.Pairing.buf_align) = undefined;

    const sigs_groupcheck = in_sigs_group_check orelse false;
    const pks_validate = in_pk_validate orelse false;
    return sig.fastAggregateVerify(sigs_groupcheck, &pairing_buf, msg[0..32], DST, pks, pks_validate) catch return false;
}

test "bls - sanity" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    const msg = [_]u8{1} ** 32;
    const sig = sign(sk, &msg);
    const pk = sk.toPublicKey();
    try verify(&msg, &pk, &sig, null, null);

    var pks = [_]PublicKey{pk};
    var pks_slice: []const PublicKey = pks[0..1];
    const result = try fastAggregateVerify(&msg, pks_slice[0..], &sig, null, null);
    try std.testing.expect(result);
}

test "bls - sign and verify round trip variable-length message" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    const msg = "ethereum consensus";
    const sig = sign(sk, msg);
    const pk = sk.toPublicKey();
    try verify(msg, &pk, &sig, null, null);
}

test "bls - verify with pubkey and signature subgroup checks" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    const msg = [_]u8{0xab} ** 32;
    const sig = sign(sk, &msg);
    const pk = sk.toPublicKey();
    try verify(&msg, &pk, &sig, true, true);
}

test "bls - fastAggregateVerify uses only first 32 bytes of longer buffer" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    var msg64: [64]u8 = undefined;
    @memset(msg64[32..], 0xcd);
    @memset(msg64[0..32], 0x42);
    const sig = sign(sk, msg64[0..32]);
    const pk = sk.toPublicKey();
    var pks = [_]PublicKey{pk};
    const ok = try fastAggregateVerify(&msg64, pks[0..], &sig, null, null);
    try std.testing.expect(ok);
}

test "bls - verify fails on wrong message" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    var msg = [_]u8{1} ** 32;
    const sig = sign(sk, &msg);
    const pk = sk.toPublicKey();
    msg[0] ^= 1;
    try std.testing.expectError(bls.BlstError.VerifyFail, verify(&msg, &pk, &sig, null, null));
}

test "bls - verify fails on wrong public key" {
    const ikm_a: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const ikm_b: [32]u8 = [_]u8{
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    };
    const sk_a = try SecretKey.keyGen(ikm_a[0..], null);
    const sk_b = try SecretKey.keyGen(ikm_b[0..], null);
    const msg = [_]u8{1} ** 32;
    const sig = sign(sk_a, &msg);
    const pk_b = sk_b.toPublicKey();
    try std.testing.expectError(bls.BlstError.VerifyFail, verify(&msg, &pk_b, &sig, null, null));
}

test "bls - fastAggregateVerify false on wrong message" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    var msg = [_]u8{1} ** 32;
    const sig = sign(sk, &msg);
    const pk = sk.toPublicKey();
    msg[31] ^= 0xff;
    var pks = [_]PublicKey{pk};
    const result = try fastAggregateVerify(&msg, pks[0..], &sig, null, null);
    try std.testing.expect(!result);
}
