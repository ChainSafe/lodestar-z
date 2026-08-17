//! secp256k1 wrapper for discv5 — ECDH and signing.
//!
//! This module intentionally uses Zig std.crypto instead of a libsecp256k1 C
//! dependency so the discv5 module remains self-contained and testable from the
//! standalone Lodestar-Z build graph.

const std = @import("std");

const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

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
pub const KeyPair = Ecdsa.KeyPair;
pub const SecretKey = Ecdsa.SecretKey;
pub const PublicKey = Ecdsa.PublicKey;

/// Construct a keypair from fixed secret bytes, mainly for protocol vectors and
/// deterministic fixtures. Runtime code should usually call `KeyPair.generate`.
pub fn keyPairFromSecret(secret: *const [32]u8) Error!KeyPair {
    const secret_key = SecretKey.fromBytes(secret.*) catch return Error.InvalidSecretKey;
    return KeyPair.fromSecretKey(secret_key) catch return Error.InvalidSecretKey;
}

pub fn compressedPubkey(key_pair: *const KeyPair) CompressedPubKey {
    return key_pair.public_key.toCompressedSec1();
}

/// ECDH: pubkey * keypair.secret → compressed shared secret point.
///
/// This matches the previous wrapper contract: return the compressed SEC-1
/// encoding of the scalar-multiplied point, not a KDF output.
pub fn ecdh(pubkey_bytes: *const [33]u8, key_pair: *const KeyPair) Error![33]u8 {
    const peer = Secp256k1.fromSec1(pubkey_bytes) catch return Error.InvalidPublicKey;
    const secret = key_pair.secret_key.toBytes();
    const shared = peer.mul(secret, .big) catch return Error.EcdhFailed;
    return shared.toCompressedSec1();
}

/// Sign a 32-byte message hash with a keypair → compact 64-byte signature.
pub fn sign(msg_hash: *const [32]u8, key_pair: *const KeyPair) Error![64]u8 {
    const sig = key_pair.signPrehashed(msg_hash.*, null) catch return Error.SigningFailed;
    return sig.toBytes();
}

/// Verify a compact 64-byte signature against msg_hash and compressed pubkey.
pub fn verify(msg_hash: *const [32]u8, sig_compact: *const [64]u8, pubkey_bytes: *const [33]u8) Error!void {
    const public_key = PublicKey.fromSec1(pubkey_bytes) catch return Error.InvalidPublicKey;
    const sig = Ecdsa.Signature.fromBytes(sig_compact.*);
    sig.verifyPrehashed(msg_hash.*, public_key) catch return Error.InvalidSignature;
}

/// Decompress a 33-byte compressed public key to 65-byte uncompressed form.
/// Returns Error.InvalidPublicKey if the key is invalid.
pub fn uncompressedFromCompressed(compressed: *const [33]u8) Error!UncompressedPubKey {
    const public_key = PublicKey.fromSec1(compressed) catch return Error.InvalidPublicKey;
    return public_key.toUncompressedSec1();
}

test "secp256k1 std.crypto wrapper derives, signs, verifies, and rejects invalid signatures" {
    const io = std.Options.debug_io;
    const key_pair = KeyPair.generate(io);
    const public_key = compressedPubkey(&key_pair);

    var msg_hash = [_]u8{0} ** 32;
    msg_hash[31] = 42;

    const sig = try sign(&msg_hash, &key_pair);
    try verify(&msg_hash, &sig, &public_key);

    var bad_sig = sig;
    bad_sig[0] ^= 1;
    try std.testing.expectError(Error.InvalidSignature, verify(&msg_hash, &bad_sig, &public_key));
}

test "secp256k1 std.crypto wrapper computes symmetric raw ECDH point" {
    const io = std.Options.debug_io;
    const a_key_pair = KeyPair.generate(io);
    const b_key_pair = KeyPair.generate(io);
    const a_public = compressedPubkey(&a_key_pair);
    const b_public = compressedPubkey(&b_key_pair);

    const ab = try ecdh(&b_public, &a_key_pair);
    const ba = try ecdh(&a_public, &b_key_pair);
    try std.testing.expectEqualSlices(u8, &ab, &ba);

    const uncompressed = try uncompressedFromCompressed(&a_public);
    try std.testing.expectEqual(@as(u8, 0x04), uncompressed[0]);
}
