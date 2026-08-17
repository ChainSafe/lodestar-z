//! Discovery v5 packet encoding/decoding

const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const MASKING_IV_SIZE = 16;
pub const MAX_PACKET_SIZE: usize = 1280;
pub const STATIC_HEADER_SIZE = 6 + 2 + 1 + 12 + 2; // = 23
pub const PROTOCOL_ID = "discv5";
pub const VERSION: u16 = 0x0001;

pub const FLAG_MESSAGE: u8 = 0;
pub const FLAG_WHOAREYOU: u8 = 1;
pub const FLAG_HANDSHAKE: u8 = 2;

pub const NONCE_SIZE = 12;
pub const NODE_ID_SIZE = 32;
pub const GCM_TAG_SIZE = 16;
pub const ID_NONCE_SIZE = 16;
pub const WHOAREYOU_AUTHDATA_SIZE = ID_NONCE_SIZE + 8;
pub const WHOAREYOU_CHALLENGE_DATA_SIZE = MASKING_IV_SIZE + STATIC_HEADER_SIZE + WHOAREYOU_AUTHDATA_SIZE;

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

/// Views into a decoded discv5 packet.
///
/// `decode` mutates the caller-owned packet buffer in place: bytes
/// `MASKING_IV_SIZE..MASKING_IV_SIZE + header_raw.len` are changed from the
/// masked wire header into the plaintext `static_header || authdata` header.
/// The message ciphertext bytes are not modified.
///
/// All slices in this struct borrow from that caller-owned packet buffer, so a
/// `ParsedPacket` must not outlive the `raw` buffer passed to `decode`.
pub const ParsedPacket = struct {
    masking_iv: [16]u8,
    /// Plaintext `static_header || authdata`, used as AES-GCM associated data.
    header_raw: []const u8,
    static_header: StaticHeader,
    /// Plaintext authdata slice inside `header_raw`.
    authdata_raw: []const u8,
    /// Encrypted message payload slice inside the original packet buffer.
    message_ciphertext: []const u8,
};

pub const MessagePacketKind = enum {
    ordinary,
    handshake,

    fn flag(self: MessagePacketKind) u8 {
        return switch (self) {
            .ordinary => FLAG_MESSAGE,
            .handshake => FLAG_HANDSHAKE,
        };
    }
};

pub const MessagePacketArgs = struct {
    kind: MessagePacketKind,
    masking_iv: *const [MASKING_IV_SIZE]u8,
    recipient_node_id: *const [NODE_ID_SIZE]u8,
    nonce: *const [NONCE_SIZE]u8,
    authdata: []const u8,
    write_key: *const [16]u8,
    plaintext: []const u8,
};

pub const WhoareyouPacketArgs = struct {
    masking_iv: *const [MASKING_IV_SIZE]u8,
    recipient_node_id: *const [NODE_ID_SIZE]u8,
    request_nonce: *const [NONCE_SIZE]u8,
    id_nonce: *const [ID_NONCE_SIZE]u8,
    enr_seq: u64,
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

/// Decode a raw UDP packet in place.
///
/// The caller must pass a mutable packet buffer. On success, the header bytes in
/// `raw` are unmasked in place and the returned `ParsedPacket` borrows slices
/// from `raw`. The message ciphertext is left untouched. On failure before the
/// final in-place unmasking step, `raw` is left unchanged.
pub fn decode(raw: []u8, dest_node_id: *const [32]u8) Error!ParsedPacket {
    if (raw.len < MASKING_IV_SIZE + STATIC_HEADER_SIZE) return Error.InvalidPacket;

    const masking_iv = raw[0..16].*;
    const masking_key = dest_node_id[0..16];

    if (raw.len < 39) return Error.InvalidPacket;

    // Probe a stack copy of the static header first so `raw` remains unchanged
    // until we know the full authdata length and can validate packet bounds.
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
    const header_raw = raw[16 .. 16 + header_total];
    // Unmask static_header || authdata in place with the CTR stream starting at
    // byte zero. This preserves the exact plaintext header used as GCM AD.
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
    };
}

/// Decrypt a message packet using AES-128-GCM
/// Decrypt a message packet into caller-owned memory.
///
/// `out` must hold the plaintext (`ciphertext.len - GCM_TAG_SIZE`), and
/// `ad_buf` must hold `masking_iv || header_raw`.
pub fn decryptMessageInto(
    out: []u8,
    ad_buf: []u8,
    read_key: *const [16]u8,
    nonce: *const [12]u8,
    ciphertext: []const u8,
    masking_iv: *const [16]u8,
    header_raw: []const u8,
) Error![]u8 {
    if (ciphertext.len < GCM_TAG_SIZE) return Error.DecryptionFailed;

    const ct = ciphertext[0 .. ciphertext.len - GCM_TAG_SIZE];
    if (ct.len > out.len) return Error.BufferTooSmall;
    const ad_len = MASKING_IV_SIZE + header_raw.len;
    if (ad_len > ad_buf.len) return Error.BufferTooSmall;

    var tag: [GCM_TAG_SIZE]u8 = undefined;
    @memcpy(&tag, ciphertext[ciphertext.len - GCM_TAG_SIZE ..]);

    const ad = ad_buf[0..ad_len];
    @memcpy(ad[0..MASKING_IV_SIZE], masking_iv);
    @memcpy(ad[MASKING_IV_SIZE..], header_raw);

    const pt = out[0..ct.len];
    Aes128Gcm.decrypt(pt, ct, tag, ad, nonce.*, read_key.*) catch {
        return Error.DecryptionFailed;
    };

    return pt;
}

/// Encode an ordinary or handshake message packet.
///
/// The header is written in plaintext first so it can serve as AES-GCM
/// associated data together with the masking IV. It is masked in place only
/// after the ciphertext and tag have been produced.
/// Encode an ordinary or handshake message packet into caller-owned memory.
pub fn encodeMessagePacketInto(out: []u8, args: MessagePacketArgs) Error![]u8 {
    const header_total = try headerSize(args.authdata);
    const message_offset = MASKING_IV_SIZE + header_total;
    const tag_offset = message_offset + args.plaintext.len;
    const total = tag_offset + GCM_TAG_SIZE;
    if (total > out.len) return Error.BufferTooSmall;

    const encoded = out[0..total];
    @memcpy(encoded[0..MASKING_IV_SIZE], args.masking_iv);
    const header = encoded[MASKING_IV_SIZE..][0..header_total];
    try writeHeader(header, args.kind.flag(), args.nonce, args.authdata);

    const ad = encoded[0..message_offset];
    const ciphertext = encoded[message_offset..tag_offset];
    var tag: [GCM_TAG_SIZE]u8 = undefined;
    Aes128Gcm.encrypt(ciphertext, &tag, args.plaintext, ad, args.nonce.*, args.write_key.*);
    @memcpy(encoded[tag_offset..], &tag);

    aesCtr(args.recipient_node_id[0..MASKING_IV_SIZE], args.masking_iv, header);
    return encoded;
}

/// Encode a WHOAREYOU challenge packet.
///
/// If `challenge_data_out` is provided, it receives
/// `masking_iv || plaintext_static_header || plaintext_authdata`, the exact
/// challenge data used by the identity proof.
/// Encode a WHOAREYOU challenge packet into caller-owned memory.
pub fn encodeWhoareyouPacketInto(
    out: []u8,
    args: WhoareyouPacketArgs,
    challenge_data_out: ?*[WHOAREYOU_CHALLENGE_DATA_SIZE]u8,
) Error![]u8 {
    if (out.len < WHOAREYOU_CHALLENGE_DATA_SIZE) return Error.BufferTooSmall;

    var authdata: [WHOAREYOU_AUTHDATA_SIZE]u8 = undefined;
    @memcpy(authdata[0..ID_NONCE_SIZE], args.id_nonce);
    std.mem.writeInt(u64, authdata[ID_NONCE_SIZE..WHOAREYOU_AUTHDATA_SIZE], args.enr_seq, .big);

    const encoded = out[0..WHOAREYOU_CHALLENGE_DATA_SIZE];
    @memcpy(encoded[0..MASKING_IV_SIZE], args.masking_iv);
    const header = encoded[MASKING_IV_SIZE..];
    try writeHeader(header, FLAG_WHOAREYOU, args.request_nonce, &authdata);

    if (challenge_data_out) |challenge_out| {
        challenge_out.* = encoded[0..WHOAREYOU_CHALLENGE_DATA_SIZE].*;
    }

    aesCtr(args.recipient_node_id[0..MASKING_IV_SIZE], args.masking_iv, header);
    return encoded;
}

fn headerSize(authdata: []const u8) Error!usize {
    if (authdata.len > std.math.maxInt(u16)) return Error.InvalidPacket;
    return STATIC_HEADER_SIZE + authdata.len;
}

fn writeHeader(
    header: []u8,
    flag: u8,
    nonce: *const [NONCE_SIZE]u8,
    authdata: []const u8,
) Error!void {
    const total = try headerSize(authdata);
    if (header.len < total) return Error.BufferTooSmall;
    const out = header[0..total];

    const authdata_size: u16 = @intCast(authdata.len);
    @memcpy(out[0..6], PROTOCOL_ID);
    std.mem.writeInt(u16, out[6..8], VERSION, .big);
    out[8] = flag;
    @memcpy(out[9..21], nonce);
    std.mem.writeInt(u16, out[21..23], authdata_size, .big);
    @memcpy(out[STATIC_HEADER_SIZE..], authdata);
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
    const hex = @import("hex");

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
