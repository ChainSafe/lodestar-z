//! Ethereum Node Record (ENR) — EIP-778
//!
//! An ENR encodes node identity and contact information.
//! Format: `[signature, seq, k, v, k, v, ...]` RLP list.
//! Identity scheme "v4": secp256k1 key pair, NodeId = keccak256(uncompressed pubkey)

const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("rlp.zig");
const secp = @import("secp256k1.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const NodeId = [32]u8;

/// Maximum ENR size in bytes (per spec)
pub const MAX_ENR_SIZE = 300;

pub const Error = error{
    InvalidEnr,
    InvalidSignature,
    InvalidPublicKey,
    UnsupportedScheme,
    OutOfMemory,
    BufferTooSmall,
};

/// A parsed ENR (Ethereum Node Record)
pub const Enr = struct {
    seq: u64,
    /// Compressed secp256k1 public key (33 bytes), or null if not present
    pubkey: ?[33]u8,
    /// IPv4 address (4 bytes), or null
    ip: ?[4]u8,
    /// UDP port
    udp: ?u16,
    /// TCP port
    tcp: ?u16,
    /// IPv6 address (16 bytes), or null
    ip6: ?[16]u8,
    /// UDP6 port
    udp6: ?u16,
    /// Raw RLP of the entire record (for signature verification and re-encoding)
    raw: []u8,
    alloc: Allocator,

    pub fn deinit(self: *Enr) void {
        self.alloc.free(self.raw);
    }

    /// Compute NodeId from ENR public key
    pub fn nodeId(self: *const Enr) ?NodeId {
        const pk = self.pubkey orelse return null;
        return nodeIdFromCompressedPubkey(&pk);
    }
};

/// Compute NodeId = keccak256(uncompressed pubkey[1..]) from compressed pubkey
pub fn nodeIdFromCompressedPubkey(compressed: *const [33]u8) NodeId {
    // Decompress pubkey to get uncompressed form
    // For discv5 v4 scheme: node-id = keccak256(pubkey_uncompressed[1..65])
    // We need to decompress. Use the secp256k1 library to get uncompressed form.
    // Actually per spec: "The node ID of a v4 identity is the keccak256 hash of the
    // uncompressed public key, excluding the 0x04 prefix."
    // We'll compute from the compressed key by using the crypto library.

    // Use std crypto to decompress - P256 is secp256r1, not secp256k1
    // We must use the secp256k1 library for this.
    // For now: derive using the raw compressed bytes approach via std.
    // Actually, let's use the secp256k1 cImport directly.

    const secp256k1_c = @cImport({
        @cInclude("secp256k1.h");
    });

    var pk: secp256k1_c.secp256k1_pubkey = undefined;
    const ctx = secp256k1_c.secp256k1_context_create(secp256k1_c.SECP256K1_CONTEXT_VERIFY) orelse
        @panic("secp256k1_context_create failed");
    defer secp256k1_c.secp256k1_context_destroy(ctx);

    if (secp256k1_c.secp256k1_ec_pubkey_parse(ctx, &pk, compressed, 33) != 1) {
        // Invalid key — return zeroed node id
        return [_]u8{0} ** 32;
    }

    var uncompressed: [65]u8 = undefined;
    var uncompressed_len: usize = 65;
    _ = secp256k1_c.secp256k1_ec_pubkey_serialize(ctx, &uncompressed, &uncompressed_len, &pk, secp256k1_c.SECP256K1_EC_UNCOMPRESSED);

    var node_id: NodeId = undefined;
    Keccak256.hash(uncompressed[1..65], &node_id, .{});
    return node_id;
}

/// Decode an ENR from RLP-encoded bytes
pub fn decode(alloc: Allocator, data: []const u8) Error!Enr {
    if (data.len > MAX_ENR_SIZE) return Error.InvalidEnr;

    var r = rlp.Reader.init(data);
    var list = r.readList() catch return Error.InvalidEnr;

    // signature (skip for now - verify separately)
    _ = list.readBytes() catch return Error.InvalidEnr;

    // seq
    const seq = list.readUint64() catch return Error.InvalidEnr;

    var enr = Enr{
        .seq = seq,
        .pubkey = null,
        .ip = null,
        .udp = null,
        .tcp = null,
        .ip6 = null,
        .udp6 = null,
        .raw = try alloc.dupe(u8, data),
        .alloc = alloc,
    };
    errdefer alloc.free(enr.raw);

    // Parse key-value pairs
    while (!list.atEnd()) {
        const key = list.readBytes() catch break;
        if (list.atEnd()) break;

        if (std.mem.eql(u8, key, "secp256k1")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len == 33) {
                enr.pubkey = val[0..33].*;
            }
        } else if (std.mem.eql(u8, key, "ip")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len == 4) {
                enr.ip = val[0..4].*;
            }
        } else if (std.mem.eql(u8, key, "udp")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len > 0 and val.len <= 2) {
                var port: u16 = 0;
                for (val) |b| port = (port << 8) | b;
                enr.udp = port;
            }
        } else if (std.mem.eql(u8, key, "tcp")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len > 0 and val.len <= 2) {
                var port: u16 = 0;
                for (val) |b| port = (port << 8) | b;
                enr.tcp = port;
            }
        } else if (std.mem.eql(u8, key, "ip6")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len == 16) {
                enr.ip6 = val[0..16].*;
            }
        } else if (std.mem.eql(u8, key, "udp6")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len > 0 and val.len <= 2) {
                var port: u16 = 0;
                for (val) |b| port = (port << 8) | b;
                enr.udp6 = port;
            }
        } else {
            // Skip unknown key value
            list.skipItem() catch break;
        }
    }

    return enr;
}

/// Build and sign an ENR
pub const Builder = struct {
    alloc: Allocator,
    seq: u64,
    secret_key: [32]u8,
    ip: ?[4]u8 = null,
    udp: ?u16 = null,
    tcp: ?u16 = null,
    ip6: ?[16]u8 = null,
    udp6: ?u16 = null,

    pub fn init(alloc: Allocator, secret_key: [32]u8, seq: u64) Builder {
        return .{
            .alloc = alloc,
            .seq = seq,
            .secret_key = secret_key,
        };
    }

    /// Encode and sign the ENR, returning owned bytes
    pub fn encode(self: *const Builder) ![]u8 {
        // Build the content (without signature) for signing
        var content_writer = rlp.Writer.init(self.alloc);
        defer content_writer.deinit();

        // Content = RLP([seq, "id", "v4", "secp256k1", pubkey, ...])
        // The content to sign is: "enr-record-prefix" + RLP content (without sig)
        // Actually per EIP-778: sig = sign("enr:" || RLP(seq, k, v, ...))
        const pubkey = try secp.pubkeyFromSecret(&self.secret_key);

        const content_list_start = try content_writer.beginList();
        try content_writer.writeUint64(self.seq);
        // id = "v4"
        try content_writer.writeBytes("id");
        try content_writer.writeBytes("v4");
        // secp256k1 pubkey
        try content_writer.writeBytes("secp256k1");
        try content_writer.writeBytes(&pubkey);
        // ip
        if (self.ip) |ip| {
            try content_writer.writeBytes("ip");
            try content_writer.writeBytes(&ip);
        }
        // udp
        if (self.udp) |udp| {
            try content_writer.writeBytes("udp");
            const port_bytes = [2]u8{ @as(u8, @intCast(udp >> 8)), @as(u8, @intCast(udp & 0xff)) };
            try content_writer.writeBytes(port_bytes[if (port_bytes[0] == 0) 1 else 0..2]);
        }
        try content_writer.finishList(content_list_start);
        const content_rlp = content_writer.bytes();

        // Sign: sign("enr:" || content_rlp)
        const prefix = "enr:";
        var to_sign = try self.alloc.alloc(u8, prefix.len + content_rlp.len);
        defer self.alloc.free(to_sign);
        @memcpy(to_sign[0..prefix.len], prefix);
        @memcpy(to_sign[prefix.len..], content_rlp);

        var hash: [32]u8 = undefined;
        Keccak256.hash(to_sign, &hash, .{});
        const sig = try secp.sign(&hash, &self.secret_key);

        // Build full ENR: RLP([sig, seq, k, v, ...])
        var full_writer = rlp.Writer.init(self.alloc);
        defer full_writer.deinit();

        const list_start = try full_writer.beginList();
        try full_writer.writeBytes(&sig);
        try full_writer.writeUint64(self.seq);
        try full_writer.writeBytes("id");
        try full_writer.writeBytes("v4");
        try full_writer.writeBytes("secp256k1");
        try full_writer.writeBytes(&pubkey);
        if (self.ip) |ip| {
            try full_writer.writeBytes("ip");
            try full_writer.writeBytes(&ip);
        }
        if (self.udp) |udp| {
            try full_writer.writeBytes("udp");
            const port_bytes = [2]u8{ @as(u8, @intCast(udp >> 8)), @as(u8, @intCast(udp & 0xff)) };
            try full_writer.writeBytes(port_bytes[if (port_bytes[0] == 0) 1 else 0..2]);
        }
        try full_writer.finishList(list_start);

        return full_writer.toOwnedSlice();
    }
};

test "ENR nodeIdFromCompressedPubkey" {
    // Test that we correctly compute NodeId from a compressed pubkey
    const hex = @import("hex.zig");
    // node-a-key from test vectors
    const secret_key = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pubkey = try secp.pubkeyFromSecret(&secret_key);
    const node_id = nodeIdFromCompressedPubkey(&pubkey);

    // Expected from test vectors: node-a-id = 0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb
    const expected = hex.hexToBytesComptime(32, "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
    try std.testing.expectEqualSlices(u8, &expected, &node_id);
}
