const std = @import("std");
const bls = @import("bls");
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const SecretKey = bls.SecretKey;

/// See https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
const DST: []const u8 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub fn sign(secret_key: SecretKey, message: []const u8) Signature {
    return secret_key.sign(message, DST, null);
}

/// Verify a signature against a message and public key.
///
/// If `pk_validate` is `true`, the public key will be infinity and group checked.
///
/// If `sig_groupcheck` is `true`, the signature will be group checked.
pub fn verify(message: []const u8, public_key: *const PublicKey, signature: *const Signature, pk_validate: ?bool, sig_groupcheck: ?bool) bls.BlstError!void {
    const sig_groupcheck_flag = sig_groupcheck orelse false;
    const pk_validate_flag = pk_validate orelse false;
    try signature.verify(sig_groupcheck_flag, message, DST, null, public_key, pk_validate_flag);
}

/// The `message` must be at least 32 bytes; only the first 32 are passed to
/// fast aggregate verification.
pub fn fastAggregateVerify(message: []const u8, public_keys: []const PublicKey, signature: *const Signature, pk_validate: ?bool, sig_groupcheck: ?bool) !bool {
    std.debug.assert(message.len >= 32);

    var pairing_buf: [bls.Pairing.sizeOf()]u8 align(bls.Pairing.buf_align) = undefined;

    const sig_groupcheck_flag = sig_groupcheck orelse false;
    const pk_validate_flag = pk_validate orelse false;
    return signature.fastAggregateVerify(sig_groupcheck_flag, &pairing_buf, message[0..32], DST, public_keys, pk_validate_flag) catch return false;
}

test "bls - sanity" {
    const input_key_material: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const secret_key = try SecretKey.keyGen(input_key_material[0..], null);
    const message = [_]u8{1} ** 32;
    const signature = sign(secret_key, &message);
    const public_key = secret_key.toPublicKey();
    try verify(&message, &public_key, &signature, null, null);

    const public_keys = [_]PublicKey{public_key};
    const public_keys_slice: []const PublicKey = public_keys[0..1];
    const fast_aggregate_verified = try fastAggregateVerify(&message, public_keys_slice, &signature, null, null);
    try std.testing.expectEqual(true, fast_aggregate_verified);
}

test "bls - sign and verify round trip variable-length message" {
    const input_key_material: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const secret_key = try SecretKey.keyGen(input_key_material[0..], null);
    const message = "ethereum consensus";
    const signature = sign(secret_key, message);
    const public_key = secret_key.toPublicKey();
    try verify(message, &public_key, &signature, null, null);
}

test "bls - verify with pubkey and signature subgroup checks" {
    const input_key_material: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const secret_key = try SecretKey.keyGen(input_key_material[0..], null);
    const message = [_]u8{0xab} ** 32;
    const signature = sign(secret_key, &message);
    const public_key = secret_key.toPublicKey();
    try verify(&message, &public_key, &signature, true, true);
}

test "bls - fastAggregateVerify uses only first 32 bytes of longer buffer" {
    const input_key_material: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const secret_key = try SecretKey.keyGen(input_key_material[0..], null);
    var message_64: [64]u8 = undefined;
    @memset(message_64[32..], 0xcd);
    @memset(message_64[0..32], 0x42);
    const signature = sign(secret_key, message_64[0..32]);
    const public_key = secret_key.toPublicKey();
    var public_keys = [_]PublicKey{public_key};
    const fast_aggregate_verified = try fastAggregateVerify(&message_64, public_keys[0..], &signature, null, null);
    try std.testing.expectEqual(true, fast_aggregate_verified);
}

test "bls - verify fails on wrong message" {
    const input_key_material: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const secret_key = try SecretKey.keyGen(input_key_material[0..], null);
    var message = [_]u8{1} ** 32;
    const signature = sign(secret_key, &message);
    const public_key = secret_key.toPublicKey();
    message[0] ^= 1;
    try std.testing.expectError(bls.BlstError.VerifyFail, verify(&message, &public_key, &signature, null, null));
}

test "bls - verify fails on wrong public key" {
    const input_key_material_a: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const input_key_material_b: [32]u8 = [_]u8{
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    };
    const secret_key_a = try SecretKey.keyGen(input_key_material_a[0..], null);
    const secret_key_b = try SecretKey.keyGen(input_key_material_b[0..], null);
    const message = [_]u8{1} ** 32;
    const signature = sign(secret_key_a, &message);
    const public_key_b = secret_key_b.toPublicKey();
    try std.testing.expectError(bls.BlstError.VerifyFail, verify(&message, &public_key_b, &signature, null, null));
}

test "bls - fastAggregateVerify false on wrong message" {
    const input_key_material: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const secret_key = try SecretKey.keyGen(input_key_material[0..], null);
    var message = [_]u8{1} ** 32;
    const signature = sign(secret_key, &message);
    const public_key = secret_key.toPublicKey();
    message[31] ^= 0xff;
    var public_keys = [_]PublicKey{public_key};
    const fast_aggregate_verified = try fastAggregateVerify(&message, public_keys[0..], &signature, null, null);
    try std.testing.expectEqual(false, fast_aggregate_verified);
}
