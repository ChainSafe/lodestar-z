//! Discovery v5 packet encoding/decoding

const std = @import("std");
const Allocator = std.mem.Allocator;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const MASKING_IV_SIZE = 16;
pub const STATIC_HEADER_SIZE = 6 + 2 + 1 + 12 + 2; // = 23
pub const PROTOCOL_ID = "discv5";
pub const VERSION: u16 = 0x0001;

pub const FLAG_MESSAGE: u8 = 0;
pub const FLAG_WHOAREYOU: u8 = 1;
pub const FLAG_HANDSHAKE: u8 = 2;

pub const NONCE_SIZE = 12;
pub const NODE_ID_SIZE = 32;

pub const Error = error{
    InvalidPacket,
    InvalidProtocolId,
    UnsupportedVersion,
    DecryptionFailed,
    BufferTooSmall,
    InvalidFlag,
    OutOfMemory,
};

pub const StaticHeader = struct {
    protocol_id: [6]u8,
    version: u16,
    flag: u8,
    nonce: [12]u8,
    authdata_size: u16,
};

pub const ParsedPacket = struct {
    masking_iv: [16]u8,
    header_raw: []u8,
    static_header: StaticHeader,
    authdata_raw: []const u8,
    message_ciphertext: []const u8,
    alloc: Allocator,

    pub fn deinit(self: *ParsedPacket) void {
        self.alloc.free(self.header_raw);
    }
};

/// AES-128-CTR encrypt/decrypt in place
pub fn aesCtr(key: *const [16]u8, iv: *const [16]u8, data: []u8) void {
    const aes = Aes128.initEnc(key.*);
    var counter = iv.*;
    var i: usize = 0;
    while (i < data.len) {
        var keystream: [16]u8 = undefined;
        aes.encrypt(&keystream, &counter);
        // Increment counter (big-endian)
        var j: usize = 15;
        while (true) {
            counter[j] +%= 1;
            if (counter[j] != 0) break;
            if (j == 0) break;
            j -= 1;
        }
        const chunk = @min(16, data.len - i);
        for (0..chunk) |k| {
            data[i + k] ^= keystream[k];
        }
        i += chunk;
    }
}

/// Decode a raw UDP packet
pub fn decode(alloc: Allocator, raw: []const u8, dest_node_id: *const [32]u8) Error!ParsedPacket {
    if (raw.len < MASKING_IV_SIZE + STATIC_HEADER_SIZE) return Error.InvalidPacket;

    const masking_iv = raw[0..16].*;
    const masking_key = dest_node_id[0..16];

    if (raw.len < 39) return Error.InvalidPacket;

    // Decrypt the full header (static + authdata) at once
    // First we need to know authdata_size, which is in the static header
    // So decrypt static header first to get authdata_size
    const masked_static = raw[16 .. 16 + STATIC_HEADER_SIZE];
    var static_buf: [STATIC_HEADER_SIZE]u8 = undefined;
    @memcpy(&static_buf, masked_static);
    aesCtr(masking_key[0..16], &masking_iv, &static_buf);

    if (!std.mem.eql(u8, static_buf[0..6], PROTOCOL_ID)) {
        return Error.InvalidProtocolId;
    }

    const version = std.mem.readInt(u16, static_buf[6..8], .big);
    if (version != VERSION) return Error.UnsupportedVersion;

    const flag = static_buf[8];
    const nonce = static_buf[9..21].*;
    const authdata_size = std.mem.readInt(u16, static_buf[21..23], .big);

    if (raw.len < 16 + STATIC_HEADER_SIZE + authdata_size) return Error.InvalidPacket;

    const header_total = STATIC_HEADER_SIZE + authdata_size;
    const header_raw = try alloc.alloc(u8, header_total);
    errdefer alloc.free(header_raw);

    // Decrypt full header: copy masked bytes then decrypt
    @memcpy(header_raw[0..STATIC_HEADER_SIZE], raw[16 .. 16 + STATIC_HEADER_SIZE]);
    @memcpy(header_raw[STATIC_HEADER_SIZE..header_total], raw[16 + STATIC_HEADER_SIZE .. 16 + header_total]);
    aesCtr(masking_key[0..16], &masking_iv, header_raw);

    const static_header = StaticHeader{
        .protocol_id = header_raw[0..6].*,
        .version = std.mem.readInt(u16, header_raw[6..8], .big),
        .flag = flag,
        .nonce = nonce,
        .authdata_size = authdata_size,
    };

    const authdata_raw = header_raw[STATIC_HEADER_SIZE..header_total];
    const message_ciphertext = raw[16 + header_total ..];

    return ParsedPacket{
        .masking_iv = masking_iv,
        .header_raw = header_raw,
        .static_header = static_header,
        .authdata_raw = authdata_raw,
        .message_ciphertext = message_ciphertext,
        .alloc = alloc,
    };
}

/// Decrypt a message packet using AES-128-GCM
pub fn decryptMessage(
    alloc: Allocator,
    read_key: *const [16]u8,
    nonce: *const [12]u8,
    ciphertext: []const u8,
    masking_iv: *const [16]u8,
    header_raw: []const u8,
) Error![]u8 {
    if (ciphertext.len < 16) return Error.DecryptionFailed;

    const ct = ciphertext[0 .. ciphertext.len - 16];
    var tag: [16]u8 = undefined;
    @memcpy(&tag, ciphertext[ciphertext.len - 16 ..]);

    const ad = try alloc.alloc(u8, 16 + header_raw.len);
    defer alloc.free(ad);
    @memcpy(ad[0..16], masking_iv);
    @memcpy(ad[16..], header_raw);

    const pt = try alloc.alloc(u8, ct.len);

    Aes128Gcm.decrypt(pt, ct, tag, ad, nonce.*, read_key.*) catch {
        alloc.free(pt);
        return Error.DecryptionFailed;
    };

    return pt;
}

/// Encrypt a message using AES-128-GCM
pub fn encryptMessage(
    alloc: Allocator,
    write_key: *const [16]u8,
    nonce: *const [12]u8,
    plaintext: []const u8,
    masking_iv: *const [16]u8,
    header_raw: []const u8,
) Error![]u8 {
    const ad = try alloc.alloc(u8, 16 + header_raw.len);
    defer alloc.free(ad);
    @memcpy(ad[0..16], masking_iv);
    @memcpy(ad[16..], header_raw);

    const ct_with_tag = try alloc.alloc(u8, plaintext.len + 16);
    errdefer alloc.free(ct_with_tag);

    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(ct_with_tag[0..plaintext.len], &tag, plaintext, ad, nonce.*, write_key.*);
    @memcpy(ct_with_tag[plaintext.len..], &tag);

    return ct_with_tag;
}

/// Encode a full packet
pub fn encode(
    alloc: Allocator,
    masking_iv: *const [16]u8,
    dest_node_id: *const [32]u8,
    flag: u8,
    nonce: *const [12]u8,
    authdata: []const u8,
    message_ciphertext: []const u8,
) Error![]u8 {
    const authdata_size: u16 = @intCast(authdata.len);
    const header_total = STATIC_HEADER_SIZE + authdata.len;

    var header = try alloc.alloc(u8, header_total);
    defer alloc.free(header);

    @memcpy(header[0..6], PROTOCOL_ID);
    std.mem.writeInt(u16, header[6..8], VERSION, .big);
    header[8] = flag;
    @memcpy(header[9..21], nonce);
    std.mem.writeInt(u16, header[21..23], authdata_size, .big);
    @memcpy(header[STATIC_HEADER_SIZE..], authdata);

    const masked_header = try alloc.dupe(u8, header);
    defer alloc.free(masked_header);
    aesCtr(dest_node_id[0..16], masking_iv, masked_header);

    const total = 16 + header_total + message_ciphertext.len;
    const packet = try alloc.alloc(u8, total);
    @memcpy(packet[0..16], masking_iv);
    @memcpy(packet[16 .. 16 + header_total], masked_header);
    @memcpy(packet[16 + header_total ..], message_ciphertext);

    return packet;
}

test "discv5 packet: AES-CTR masking round-trip" {
    var data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const key = [_]u8{0xaa} ** 16;
    const iv = [_]u8{0xbb} ** 16;
    aesCtr(&key, &iv, &data);
    aesCtr(&key, &iv, &data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 }, &data);
}

test "discv5 packet: AES-GCM encrypt/decrypt" {
    const hex = @import("hex.zig");

    const key = hex.hexToBytesComptime(16, "9f2d77db7004bf8a1a85107ac686990b");
    const nonce = hex.hexToBytesComptime(12, "27b5af763c446acd2749fe8e");
    const pt = hex.hexToBytesComptime(4, "01c20101");
    const ad = hex.hexToBytesComptime(32, "93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903");
    const expected_ct = hex.hexToBytesComptime(20, "a5d12a2d94b8ccb3ba55558229867dc13bfa3648");

    var ct: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, &pt, &ad, nonce, key);
    var actual: [20]u8 = undefined;
    @memcpy(actual[0..4], &ct);
    @memcpy(actual[4..], &tag);

    try std.testing.expectEqualSlices(u8, &expected_ct, &actual);

    var pt2: [4]u8 = undefined;
    try Aes128Gcm.decrypt(&pt2, &ct, tag, &ad, nonce, key);
    try std.testing.expectEqualSlices(u8, &pt, &pt2);
}
