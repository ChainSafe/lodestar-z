//! secp256k1 wrapper for discv5 — ECDH and signing

const std = @import("std");

const secp256k1_lib = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_recovery.h");
});

// Thread-local secp256k1 context (signing+verification).
threadlocal var _ctx: ?*secp256k1_lib.secp256k1_context = null;

fn getCtx() *secp256k1_lib.secp256k1_context {
    if (_ctx) |c| return c;
    const flags = secp256k1_lib.SECP256K1_CONTEXT_SIGN | secp256k1_lib.SECP256K1_CONTEXT_VERIFY;
    const c = secp256k1_lib.secp256k1_context_create(flags) orelse @panic("secp256k1_context_create failed");
    _ctx = c;
    return c;
}

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignature,
    SigningFailed,
    EcdhFailed,
};

/// Compressed public key (33 bytes)
pub const CompressedPubKey = [33]u8;
/// Uncompressed public key (65 bytes)
pub const UncompressedPubKey = [65]u8;

/// Derive compressed public key from secret key bytes
pub fn pubkeyFromSecret(secret: *const [32]u8) Error!CompressedPubKey {
    const ctx = getCtx();
    var pk: secp256k1_lib.secp256k1_pubkey = undefined;
    if (secp256k1_lib.secp256k1_ec_pubkey_create(ctx, &pk, secret) != 1) {
        return Error.InvalidSecretKey;
    }
    var out: CompressedPubKey = undefined;
    var outlen: usize = 33;
    _ = secp256k1_lib.secp256k1_ec_pubkey_serialize(ctx, &out, &outlen, &pk, secp256k1_lib.SECP256K1_EC_COMPRESSED);
    return out;
}

/// ECDH: pubkey * seckey → compressed shared secret point
/// This is the raw EC multiplication, returning compressed output
pub fn ecdh(pubkey_bytes: *const [33]u8, seckey: *const [32]u8) Error![33]u8 {
    const ctx = getCtx();
    var pk: secp256k1_lib.secp256k1_pubkey = undefined;
    if (secp256k1_lib.secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bytes, 33) != 1) {
        return Error.InvalidPublicKey;
    }
    // Multiply the pubkey point by the scalar (seckey)
    if (secp256k1_lib.secp256k1_ec_pubkey_tweak_mul(ctx, &pk, seckey) != 1) {
        return Error.EcdhFailed;
    }
    var out: [33]u8 = undefined;
    var outlen: usize = 33;
    _ = secp256k1_lib.secp256k1_ec_pubkey_serialize(ctx, &out, &outlen, &pk, secp256k1_lib.SECP256K1_EC_COMPRESSED);
    return out;
}

/// Sign: sign a 32-byte message hash with a secret key → compact 64-byte signature
pub fn sign(msg_hash: *const [32]u8, seckey: *const [32]u8) Error![64]u8 {
    const ctx = getCtx();
    var sig: secp256k1_lib.secp256k1_ecdsa_signature = undefined;
    if (secp256k1_lib.secp256k1_ecdsa_sign(ctx, &sig, msg_hash, seckey, null, null) != 1) {
        return Error.SigningFailed;
    }
    var compact: [64]u8 = undefined;
    _ = secp256k1_lib.secp256k1_ecdsa_signature_serialize_compact(ctx, &compact, &sig);
    return compact;
}

/// Verify: verify a compact 64-byte signature against msg_hash and compressed pubkey
pub fn verify(msg_hash: *const [32]u8, sig_compact: *const [64]u8, pubkey_bytes: *const [33]u8) Error!void {
    const ctx = getCtx();
    var pk: secp256k1_lib.secp256k1_pubkey = undefined;
    if (secp256k1_lib.secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bytes, 33) != 1) {
        return Error.InvalidPublicKey;
    }
    var sig: secp256k1_lib.secp256k1_ecdsa_signature = undefined;
    if (secp256k1_lib.secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_compact) != 1) {
        return Error.InvalidSignature;
    }
    if (secp256k1_lib.secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pk) != 1) {
        return Error.InvalidSignature;
    }
}

/// Decompress a 33-byte compressed public key to 65-byte uncompressed form.
/// Returns Error.InvalidPublicKey if the key is invalid.
pub fn uncompressedFromCompressed(compressed: *const [33]u8) Error!UncompressedPubKey {
    const ctx = getCtx();
    var pk: secp256k1_lib.secp256k1_pubkey = undefined;
    if (secp256k1_lib.secp256k1_ec_pubkey_parse(ctx, &pk, compressed, 33) != 1) {
        return Error.InvalidPublicKey;
    }
    var out: UncompressedPubKey = undefined;
    var outlen: usize = 65;
    _ = secp256k1_lib.secp256k1_ec_pubkey_serialize(ctx, &out, &outlen, &pk, secp256k1_lib.SECP256K1_EC_UNCOMPRESSED);
    return out;
}
