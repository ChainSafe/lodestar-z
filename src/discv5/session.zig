//! Session key derivation and management for discv5
//!
//! "v4" identity scheme:
//! - ECDH: secp256k1 point multiplication
//! - HKDF: SHA256-based key derivation per discv5 theory spec
//! - AES-128-GCM: message encryption
//! - ID-nonce signing: secp256k1 ECDSA

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const secp = @import("secp256k1.zig");

pub const SESSION_KEY_SIZE = 16;

pub const DerivedKeys = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
};

/// ECDH: compute shared secret = compress(pubkey * seckey)
pub fn ecdh(pubkey: *const [33]u8, seckey: *const [32]u8) ![33]u8 {
    return secp.ecdh(pubkey, seckey);
}

/// HKDF-Extract: HMAC-SHA256(salt, ikm) → PRK
fn hkdfExtract(salt: []const u8, ikm: []const u8) [32]u8 {
    var prk: [32]u8 = undefined;
    HmacSha256.create(&prk, ikm, salt);
    return prk;
}

/// HKDF-Expand: expand PRK with info to get `length` bytes
fn hkdfExpand(prk: *const [32]u8, info: []const u8, out: []u8) void {
    var t: [32]u8 = undefined;
    var prev: []const u8 = &[_]u8{};
    var pos: usize = 0;
    var counter: u8 = 1;

    while (pos < out.len) {
        var hmac = HmacSha256.init(prk);
        hmac.update(prev);
        hmac.update(info);
        hmac.update(&[_]u8{counter});
        hmac.final(&t);
        prev = &t;

        const chunk = @min(32, out.len - pos);
        @memcpy(out[pos .. pos + chunk], t[0..chunk]);
        pos += chunk;
        counter += 1;
    }
}

/// Derive session keys from discv5 handshake
/// Per discv5 theory spec:
///   secret = ecdh(dest-pubkey, ephemeral-key)
///   kdf-info = "discovery v5 key agreement" || node-id-A || node-id-B
///   prk = HKDF-Extract(salt=challenge-data, ikm=secret)
///   key-data = HKDF-Expand(prk, kdf-info, 32)
///   initiator-key = key-data[:16]
///   recipient-key = key-data[16:]
pub fn deriveKeys(
    ephemeral_seckey: *const [32]u8,
    dest_pubkey: *const [33]u8,
    node_id_a: *const [32]u8,
    node_id_b: *const [32]u8,
    challenge_data: []const u8,
) !DerivedKeys {
    // 1. ECDH
    const shared_secret = try ecdh(dest_pubkey, ephemeral_seckey);

    // 2. HKDF-Extract: salt=challenge-data, ikm=shared_secret
    const prk = hkdfExtract(challenge_data, &shared_secret);

    // 3. HKDF-Expand: info = "discovery v5 key agreement" || node-id-A || node-id-B
    const prefix = "discovery v5 key agreement";
    var kdf_info: [26 + 32 + 32]u8 = undefined;
    @memcpy(kdf_info[0..26], prefix);
    @memcpy(kdf_info[26..58], node_id_a);
    @memcpy(kdf_info[58..90], node_id_b);

    var key_data: [32]u8 = undefined;
    hkdfExpand(&prk, &kdf_info, &key_data);

    return DerivedKeys{
        .initiator_key = key_data[0..16].*,
        .recipient_key = key_data[16..32].*,
    };
}

/// Compute the id-signature for a handshake
/// Per discv5 theory spec:
///   id-signature-text  = "discovery v5 identity proof"
///   id-signature-input = id-signature-text || challenge-data || ephemeral-pubkey || node-id-B
///   id-signature       = id_sign(sha256(id-signature-input))
pub fn signIdNonce(
    static_key: *const [32]u8,
    challenge_data: []const u8,
    eph_pubkey: *const [33]u8,
    dest_node_id: *const [32]u8,
) ![64]u8 {
    const prefix = "discovery v5 identity proof";
    var msg_buf: [27 + 256 + 33 + 32]u8 = undefined;
    var msg_len: usize = 0;
    @memcpy(msg_buf[msg_len .. msg_len + prefix.len], prefix);
    msg_len += prefix.len;
    @memcpy(msg_buf[msg_len .. msg_len + challenge_data.len], challenge_data);
    msg_len += challenge_data.len;
    @memcpy(msg_buf[msg_len .. msg_len + 33], eph_pubkey);
    msg_len += 33;
    @memcpy(msg_buf[msg_len .. msg_len + 32], dest_node_id);
    msg_len += 32;

    var hash: [32]u8 = undefined;
    Sha256.hash(msg_buf[0..msg_len], &hash, .{});

    return secp.sign(&hash, static_key);
}

/// Verify an id-signature
pub fn verifyIdSignature(
    sig: *const [64]u8,
    pubkey: *const [33]u8,
    challenge_data: []const u8,
    eph_pubkey: *const [33]u8,
    local_node_id: *const [32]u8,
) !void {
    const prefix = "discovery v5 identity proof";
    var msg_buf: [27 + 256 + 33 + 32]u8 = undefined;
    var msg_len: usize = 0;
    @memcpy(msg_buf[msg_len .. msg_len + prefix.len], prefix);
    msg_len += prefix.len;
    @memcpy(msg_buf[msg_len .. msg_len + challenge_data.len], challenge_data);
    msg_len += challenge_data.len;
    @memcpy(msg_buf[msg_len .. msg_len + 33], eph_pubkey);
    msg_len += 33;
    @memcpy(msg_buf[msg_len .. msg_len + 32], local_node_id);
    msg_len += 32;

    var hash: [32]u8 = undefined;
    Sha256.hash(msg_buf[0..msg_len], &hash, .{});

    try secp.verify(&hash, sig, pubkey);
}

// =========== Test vectors ===========

test "discv5 ECDH test vector" {
    const hex = @import("hex.zig");
    const public_key = hex.hexToBytesComptime(33, "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231");
    const secret_key = hex.hexToBytesComptime(32, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const expected = hex.hexToBytesComptime(33, "033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e");

    const shared = try ecdh(&public_key, &secret_key);
    try std.testing.expectEqualSlices(u8, &expected, &shared);
}

test "discv5 key derivation test vector" {
    const hex = @import("hex.zig");
    const eph_key = hex.hexToBytesComptime(32, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const dest_pubkey = hex.hexToBytesComptime(33, "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91");
    const node_id_a = hex.hexToBytesComptime(32, "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
    const node_id_b = hex.hexToBytesComptime(32, "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    const challenge_data = hex.hexToBytesComptime(63, "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");

    const expected_initiator = hex.hexToBytesComptime(16, "dccc82d81bd610f4f76d3ebe97a40571");
    const expected_recipient = hex.hexToBytesComptime(16, "ac74bb8773749920b0d3a8881c173ec5");

    const keys = try deriveKeys(&eph_key, &dest_pubkey, &node_id_a, &node_id_b, &challenge_data);
    try std.testing.expectEqualSlices(u8, &expected_initiator, &keys.initiator_key);
    try std.testing.expectEqualSlices(u8, &expected_recipient, &keys.recipient_key);
}

test "discv5 id-nonce signing test vector" {
    const hex = @import("hex.zig");
    const static_key = hex.hexToBytesComptime(32, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const challenge_data = hex.hexToBytesComptime(63, "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");
    const eph_pubkey = hex.hexToBytesComptime(33, "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231");
    const node_id_b = hex.hexToBytesComptime(32, "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    const expected_sig = hex.hexToBytesComptime(64, "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6");

    const sig = try signIdNonce(&static_key, &challenge_data, &eph_pubkey, &node_id_b);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);
}
