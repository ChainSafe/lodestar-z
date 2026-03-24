//! Official discv5 wire test vectors
//!
//! Tests from discv5-wire-test-vectors.md

const std = @import("std");
const hex = @import("hex.zig");
const packet = @import("packet.zig");
const session = @import("session.zig");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const node_a_id = hex.hexToBytesComptime(32, "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
const node_b_id = hex.hexToBytesComptime(32, "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");

// =========== Packet decoding test vectors ===========

test "discv5 wire: ping message packet (flag 0)" {
    const alloc = std.testing.allocator;

    // 95 bytes (190 hex chars)
    const raw_hex =
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55" ++
        "ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc";
    var raw: [95]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    var parsed = try packet.decode(alloc, &raw, &node_b_id);
    defer parsed.deinit();

    try std.testing.expectEqual(packet.FLAG_MESSAGE, parsed.static_header.flag);

    const expected_nonce = hex.hexToBytesComptime(12, "ffffffffffffffffffffffff");
    try std.testing.expectEqualSlices(u8, &expected_nonce, &parsed.static_header.nonce);

    // Decrypt: read-key = 0x00000000000000000000000000000000
    const read_key = [_]u8{0} ** 16;
    const pt = try packet.decryptMessage(
        alloc,
        &read_key,
        &parsed.static_header.nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );
    defer alloc.free(pt);

    try std.testing.expectEqual(@as(u8, 0x01), pt[0]);

    const msg = @import("messages.zig");
    const ping = try msg.Ping.decode(pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01 }, ping.req_id.slice());
    try std.testing.expectEqual(@as(u64, 2), ping.enr_seq);
}

test "discv5 wire: WHOAREYOU packet (flag 1)" {
    const alloc = std.testing.allocator;

    const raw_hex =
        "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad" ++
        "1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d";
    var raw: [63]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    var parsed = try packet.decode(alloc, &raw, &node_b_id);
    defer parsed.deinit();

    try std.testing.expectEqual(packet.FLAG_WHOAREYOU, parsed.static_header.flag);
    try std.testing.expectEqual(@as(u16, 24), parsed.static_header.authdata_size);

    const id_nonce = parsed.authdata_raw[0..16];
    const expected_nonce = hex.hexToBytesComptime(16, "0102030405060708090a0b0c0d0e0f10");
    try std.testing.expectEqualSlices(u8, &expected_nonce, id_nonce);

    const enr_seq_bytes = parsed.authdata_raw[16..24];
    const enr_seq = std.mem.readInt(u64, enr_seq_bytes[0..8], .big);
    try std.testing.expectEqual(@as(u64, 0), enr_seq);
}

test "discv5 wire: ping handshake packet (flag 2, no ENR)" {
    const alloc = std.testing.allocator;

    const raw_hex =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
        "ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef" ++
        "268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb" ++
        "a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
        "f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83" ++
        "9cf8";
    var raw: [194]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    var parsed = try packet.decode(alloc, &raw, &node_b_id);
    defer parsed.deinit();

    try std.testing.expectEqual(packet.FLAG_HANDSHAKE, parsed.static_header.flag);

    const authdata = parsed.authdata_raw;
    const src_id = authdata[0..32];
    try std.testing.expectEqualSlices(u8, &node_a_id, src_id);

    const sig_size = authdata[32];
    const eph_key_size = authdata[33];
    try std.testing.expectEqual(@as(u8, 64), sig_size);
    try std.testing.expectEqual(@as(u8, 33), eph_key_size);

    const eph_pubkey = authdata[34 + sig_size .. 34 + sig_size + eph_key_size];
    const expected_eph_pubkey = hex.hexToBytesComptime(33, "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5");
    try std.testing.expectEqualSlices(u8, &expected_eph_pubkey, eph_pubkey);

    // Decrypt: read-key = 0x4f9fac6de7567d1e3b1241dffe90f662
    const read_key = hex.hexToBytesComptime(16, "4f9fac6de7567d1e3b1241dffe90f662");
    const nonce = hex.hexToBytesComptime(12, "ffffffffffffffffffffffff");

    const pt = try packet.decryptMessage(
        alloc,
        &read_key,
        &nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );
    defer alloc.free(pt);

    try std.testing.expectEqual(@as(u8, 0x01), pt[0]);
    const msg = @import("messages.zig");
    const ping = try msg.Ping.decode(pt);
    try std.testing.expectEqual(@as(u64, 1), ping.enr_seq);
}

test "discv5 wire: ping handshake with ENR (flag 2)" {
    const alloc = std.testing.allocator;

    const raw_hex =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
        "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856" ++
        "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2" ++
        "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
        "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6" ++
        "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1" ++
        "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a" ++
        "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e" ++
        "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394" ++
        "71";
    var raw: [321]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    var parsed = try packet.decode(alloc, &raw, &node_b_id);
    defer parsed.deinit();

    try std.testing.expectEqual(packet.FLAG_HANDSHAKE, parsed.static_header.flag);

    const authdata = parsed.authdata_raw;
    const sig_size = authdata[32];
    const eph_key_size = authdata[33];

    const record_start = 34 + sig_size + eph_key_size;
    try std.testing.expect(authdata.len > record_start);

    // Decrypt: read-key = 0x53b1c075f41876423154e157470c2f48
    const read_key = hex.hexToBytesComptime(16, "53b1c075f41876423154e157470c2f48");
    const nonce = hex.hexToBytesComptime(12, "ffffffffffffffffffffffff");

    const pt = try packet.decryptMessage(
        alloc,
        &read_key,
        &nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );
    defer alloc.free(pt);

    try std.testing.expectEqual(@as(u8, 0x01), pt[0]);
    const msg = @import("messages.zig");
    const ping = try msg.Ping.decode(pt);
    try std.testing.expectEqual(@as(u64, 1), ping.enr_seq);
}

// =========== Cryptographic primitive test vectors ===========

test "discv5 crypto: ECDH" {
    const public_key = hex.hexToBytesComptime(33, "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231");
    const secret_key = hex.hexToBytesComptime(32, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const expected = hex.hexToBytesComptime(33, "033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e");

    const shared = try session.ecdh(&public_key, &secret_key);
    try std.testing.expectEqualSlices(u8, &expected, &shared);
}

test "discv5 crypto: key derivation (HKDF)" {
    const eph_key = hex.hexToBytesComptime(32, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const dest_pubkey = hex.hexToBytesComptime(33, "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91");
    const challenge_data = hex.hexToBytesComptime(63, "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");

    const expected_initiator = hex.hexToBytesComptime(16, "dccc82d81bd610f4f76d3ebe97a40571");
    const expected_recipient = hex.hexToBytesComptime(16, "ac74bb8773749920b0d3a8881c173ec5");

    const keys = try session.deriveKeys(&eph_key, &dest_pubkey, &node_a_id, &node_b_id, &challenge_data);
    try std.testing.expectEqualSlices(u8, &expected_initiator, &keys.initiator_key);
    try std.testing.expectEqualSlices(u8, &expected_recipient, &keys.recipient_key);
}

test "discv5 crypto: id-nonce signing" {
    const static_key = hex.hexToBytesComptime(32, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const challenge_data = hex.hexToBytesComptime(63, "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");
    const eph_pubkey = hex.hexToBytesComptime(33, "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231");
    const expected_sig = hex.hexToBytesComptime(64, "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6");

    const sig = try session.signIdNonce(&static_key, &challenge_data, &eph_pubkey, &node_b_id);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);
}

test "discv5 crypto: AES-GCM encryption" {
    const enc_key = hex.hexToBytesComptime(16, "9f2d77db7004bf8a1a85107ac686990b");
    const nonce = hex.hexToBytesComptime(12, "27b5af763c446acd2749fe8e");
    const pt = hex.hexToBytesComptime(4, "01c20101");
    const ad = hex.hexToBytesComptime(32, "93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903");
    const expected_ct = hex.hexToBytesComptime(20, "a5d12a2d94b8ccb3ba55558229867dc13bfa3648");

    var ct_buf: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct_buf, &tag, &pt, &ad, nonce, enc_key);

    var result: [20]u8 = undefined;
    @memcpy(result[0..4], &ct_buf);
    @memcpy(result[4..], &tag);

    try std.testing.expectEqualSlices(u8, &expected_ct, &result);
}
