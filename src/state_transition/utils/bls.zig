const std = @import("std");
const blst = @import("blst");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const SecretKey = blst.SecretKey;

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
pub fn verify(msg: []const u8, pk: *const PublicKey, sig: *const Signature, in_pk_validate: ?bool, in_sig_groupcheck: ?bool) blst.BlstError!void {
    const sig_groupcheck = in_sig_groupcheck orelse false;
    const pk_validate = in_pk_validate orelse false;
    try sig.verify(sig_groupcheck, msg, DST, null, pk, pk_validate);
}

pub fn fastAggregateVerify(msg: []const u8, pks: []const PublicKey, sig: *const Signature, in_pk_validate: ?bool, in_sigs_group_check: ?bool) !bool {
    var pairing_buf: [blst.Pairing.sizeOf()]u8 = undefined;

    const sigs_groupcheck = in_sigs_group_check orelse false;
    const pks_validate = in_pk_validate orelse false;
    return sig.fastAggregateVerify(sigs_groupcheck, &pairing_buf, msg[0..32], DST, pks, pks_validate) catch return false;
}

// TODO: unit tests
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
