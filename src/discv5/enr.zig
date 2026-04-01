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
    /// TCP6 port
    tcp6: ?u16,
    quic: ?u16,
    quic6: ?u16,
    /// Fork digest from eth2 ENR field (first 4 bytes of ENRForkID SSZ)
    eth2_fork_digest: ?[4]u8,
    /// Full eth2 ENR field (16 bytes: fork_digest + next_fork_version + next_fork_epoch)
    eth2_raw: ?[16]u8,
    /// Attestation subnet bitfield (8 bytes = 64 subnets)
    attnets: ?[8]u8,
    /// Sync committee subnet bitfield (1 byte = 4 sync committees)
    syncnets: ?[1]u8,
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
    // Per discv5/v4 identity scheme:
    //   node-id = keccak256(uncompressed_pubkey[1..65])
    // Reuse the thread-local secp256k1 context from secp256k1.zig to avoid
    // allocating a new context on every call.
    const uncompressed = secp.uncompressedFromCompressed(compressed) catch {
        // Invalid key — return zeroed node id
        return [_]u8{0} ** 32;
    };
    var node_id: NodeId = undefined;
    Keccak256.hash(uncompressed[1..65], &node_id, .{});
    return node_id;
}

/// Decode an ENR from RLP-encoded bytes
pub fn decode(alloc: Allocator, data: []const u8) Error!Enr {
    if (data.len > MAX_ENR_SIZE) return Error.InvalidEnr;

    var r = rlp.Reader.init(data);
    var list = r.readList() catch return Error.InvalidEnr;

    const signature_bytes = list.readBytes() catch return Error.InvalidEnr;
    if (signature_bytes.len != 64) return Error.InvalidSignature;
    const content_payload = list.data[list.pos..];

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
        .tcp6 = null,
        .quic = null,
        .quic6 = null,
        .eth2_fork_digest = null,
        .eth2_raw = null,
        .attnets = null,
        .syncnets = null,
        .raw = try alloc.dupe(u8, data),
        .alloc = alloc,
    };
    errdefer alloc.free(enr.raw);
    var saw_id_v4 = false;

    // Parse key-value pairs
    while (!list.atEnd()) {
        const key = list.readBytes() catch return Error.InvalidEnr;
        if (list.atEnd()) return Error.InvalidEnr;

        if (std.mem.eql(u8, key, "secp256k1")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len == 33) {
                enr.pubkey = val[0..33].*;
            }
        } else if (std.mem.eql(u8, key, "id")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (!std.mem.eql(u8, val, "v4")) return Error.UnsupportedScheme;
            saw_id_v4 = true;
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
        } else if (std.mem.eql(u8, key, "tcp6")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len > 0 and val.len <= 2) {
                var port: u16 = 0;
                for (val) |b| port = (port << 8) | b;
                enr.tcp6 = port;
            }
        } else if (std.mem.eql(u8, key, "quic")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len > 0 and val.len <= 2) {
                var port: u16 = 0;
                for (val) |b| port = (port << 8) | b;
                enr.quic = port;
            }
        } else if (std.mem.eql(u8, key, "quic6")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len > 0 and val.len <= 2) {
                var port: u16 = 0;
                for (val) |b| port = (port << 8) | b;
                enr.quic6 = port;
            }
        } else if (std.mem.eql(u8, key, "eth2")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            // ENRForkID SSZ: fork_digest(4) + next_fork_version(4) + next_fork_epoch(8) = 16 bytes
            if (val.len >= 4) {
                enr.eth2_fork_digest = val[0..4].*;
            }
            if (val.len >= 16) {
                enr.eth2_raw = val[0..16].*;
            }
        } else if (std.mem.eql(u8, key, "attnets")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len == 8) {
                enr.attnets = val[0..8].*;
            }
        } else if (std.mem.eql(u8, key, "syncnets")) {
            const val = list.readBytes() catch return Error.InvalidEnr;
            if (val.len == 1) {
                enr.syncnets = val[0..1].*;
            }
        } else {
            // Skip unknown key value
            list.skipItem() catch return Error.InvalidEnr;
        }
    }

    if (!saw_id_v4) return Error.UnsupportedScheme;
    const pubkey = enr.pubkey orelse return Error.InvalidPublicKey;

    var sig_hash: [32]u8 = undefined;
    hashSignedPortion(content_payload, &sig_hash);
    const signature: [64]u8 = signature_bytes[0..64].*;
    secp.verify(&sig_hash, &signature, &pubkey) catch return Error.InvalidSignature;

    return enr;
}

fn hashSignedPortion(content_payload: []const u8, out: *[32]u8) void {
    var hasher = Keccak256.init(.{});
    updateListPrefix(&hasher, content_payload.len);
    hasher.update(content_payload);
    hasher.final(out);
}

fn updateListPrefix(hasher: *Keccak256, payload_len: usize) void {
    if (payload_len <= 55) {
        hasher.update(&[_]u8{@as(u8, 0xc0) + @as(u8, @intCast(payload_len))});
        return;
    }

    var len_bytes: [8]u8 = undefined;
    var count: usize = 0;
    var tmp = payload_len;
    while (tmp > 0) : (tmp >>= 8) {
        len_bytes[len_bytes.len - 1 - count] = @intCast(tmp & 0xff);
        count += 1;
    }
    hasher.update(&[_]u8{@as(u8, 0xf7) + @as(u8, @intCast(count))});
    hasher.update(len_bytes[len_bytes.len - count ..]);
}

/// Build and sign an ENR
pub const Builder = struct {
    alloc: Allocator,
    seq: u64,
    secret_key: [32]u8,
    ip: ?[4]u8 = null,
    udp: ?u16 = null,
    tcp: ?u16 = null,
    quic: ?u16 = null,
    ip6: ?[16]u8 = null,
    udp6: ?u16 = null,
    tcp6: ?u16 = null,
    quic6: ?u16 = null,
    /// eth2 ENR field: ENRForkID SSZ = fork_digest(4) + next_fork_version(4) + next_fork_epoch(8)
    eth2: ?[16]u8 = null,
    /// Attestation subnet bitfield (8 bytes = 64 bits for 64 subnets)
    attnets: ?[8]u8 = null,
    /// Sync committee subnet bitfield (1 byte = 4 bits for 4 sync committees)
    syncnets: ?[1]u8 = null,

    pub fn init(alloc: Allocator, secret_key: [32]u8, seq: u64) Builder {
        return .{
            .alloc = alloc,
            .seq = seq,
            .secret_key = secret_key,
        };
    }

    /// Set the eth2 ENR field from fork digest, next fork version, and next fork epoch.
    pub fn setEth2(self: *Builder, fork_digest: [4]u8, next_fork_version: [4]u8, next_fork_epoch: u64) void {
        var eth2_val: [16]u8 = undefined;
        @memcpy(eth2_val[0..4], &fork_digest);
        @memcpy(eth2_val[4..8], &next_fork_version);
        std.mem.writeInt(u64, eth2_val[8..16], next_fork_epoch, .little);
        self.eth2 = eth2_val;
    }

    /// Helper to write a port as minimal big-endian bytes.
    fn writePort(writer: *rlp.Writer, port: u16) !void {
        const port_bytes = [2]u8{ @as(u8, @intCast(port >> 8)), @as(u8, @intCast(port & 0xff)) };
        try writer.writeBytes(port_bytes[if (port_bytes[0] == 0) 1 else 0..2]);
    }

    /// Write all key-value pairs in alphabetical order to an RLP writer.
    /// EIP-778 requires keys to be sorted.
    fn writeKVPairs(self: *const Builder, writer: *rlp.Writer, pubkey: *const [33]u8) !void {
        // Alphabetical order: attnets, eth2, id, ip, ip6, quic, quic6,
        //                     secp256k1, syncnets, tcp, tcp6, udp, udp6
        if (self.attnets) |attnets| {
            try writer.writeBytes("attnets");
            try writer.writeBytes(&attnets);
        }
        if (self.eth2) |eth2_val| {
            try writer.writeBytes("eth2");
            try writer.writeBytes(&eth2_val);
        }
        try writer.writeBytes("id");
        try writer.writeBytes("v4");
        if (self.ip) |ip| {
            try writer.writeBytes("ip");
            try writer.writeBytes(&ip);
        }
        if (self.ip6) |ip6| {
            try writer.writeBytes("ip6");
            try writer.writeBytes(&ip6);
        }
        if (self.quic) |port| {
            try writer.writeBytes("quic");
            try writePort(writer, port);
        }
        if (self.quic6) |port| {
            try writer.writeBytes("quic6");
            try writePort(writer, port);
        }
        try writer.writeBytes("secp256k1");
        try writer.writeBytes(pubkey);
        if (self.syncnets) |syncnets| {
            try writer.writeBytes("syncnets");
            try writer.writeBytes(&syncnets);
        }
        if (self.tcp) |port| {
            try writer.writeBytes("tcp");
            try writePort(writer, port);
        }
        if (self.tcp6) |port| {
            try writer.writeBytes("tcp6");
            try writePort(writer, port);
        }
        if (self.udp) |port| {
            try writer.writeBytes("udp");
            try writePort(writer, port);
        }
        if (self.udp6) |port| {
            try writer.writeBytes("udp6");
            try writePort(writer, port);
        }
    }

    /// Encode and sign the ENR, returning owned bytes.
    pub fn encode(self: *const Builder) ![]u8 {
        const pubkey = try secp.pubkeyFromSecret(&self.secret_key);

        // Build the content (without signature) for signing.
        // Per EIP-778: sig = sign(keccak256(RLP([seq, k, v, ...])))
        var content_writer = rlp.Writer.init(self.alloc);
        defer content_writer.deinit();

        const content_list_start = try content_writer.beginList();
        try content_writer.writeUint64(self.seq);
        try self.writeKVPairs(&content_writer, &pubkey);
        try content_writer.finishList(content_list_start);
        const content_rlp = content_writer.bytes();

        var hash: [32]u8 = undefined;
        Keccak256.hash(content_rlp, &hash, .{});
        const sig = try secp.sign(&hash, &self.secret_key);

        // Build full ENR: RLP([sig, seq, k, v, ...])
        var full_writer = rlp.Writer.init(self.alloc);
        defer full_writer.deinit();

        const list_start = try full_writer.beginList();
        try full_writer.writeBytes(&sig);
        try full_writer.writeUint64(self.seq);
        try self.writeKVPairs(&full_writer, &pubkey);
        try full_writer.finishList(list_start);

        return full_writer.toOwnedSlice();
    }

    /// Encode the ENR and return as a base64url string with "enr:" prefix.
    /// Caller owns the returned slice.
    pub fn encodeToString(self: *const Builder) ![]u8 {
        const raw = try self.encode();
        defer self.alloc.free(raw);

        const b64_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw.len);
        const result = try self.alloc.alloc(u8, 4 + b64_len); // "enr:" prefix
        @memcpy(result[0..4], "enr:");
        _ = std.base64.url_safe_no_pad.Encoder.encode(result[4..], raw);
        return result;
    }
};

/// Check if a subnet bit is set in an attnets bitfield.
pub fn isSubnetSet(attnets: [8]u8, subnet_id: u6) bool {
    const byte_idx = subnet_id / 8;
    const bit_idx: u3 = @intCast(subnet_id % 8);
    return (attnets[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
}

/// Count the number of set subnet bits in an attnets bitfield.
pub fn countSubnets(attnets: [8]u8) u32 {
    var count: u32 = 0;
    for (attnets) |byte| {
        count += @popCount(byte);
    }
    return count;
}

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

test "ENR Builder: key-value pairs sorted alphabetically (EIP-778)" {
    // Regression test: ENR keys must be sorted alphabetically per EIP-778.
    // Correct order: id, ip, secp256k1, udp
    // Previous bug: id, secp256k1, ip, udp — produced an invalid signature.
    //
    // Test vector from https://github.com/ethereum/devp2p/blob/master/enr.md:
    //   private key: b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291
    //   seq: 1, ip: 127.0.0.1, udp: 30303
    //   expected node-id: a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7
    const hex_mod = @import("hex.zig");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var builder = Builder.init(alloc, secret_key, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 30303;
    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    // Re-parse and check the node ID is the expected one (proves the pubkey is embedded correctly)
    var parsed = try decode(alloc, enr_bytes);
    defer parsed.deinit();

    const expected_node_id = hex_mod.hexToBytesComptime(32, "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    const node_id = parsed.nodeId() orelse return error.NoNodeId;
    try std.testing.expectEqualSlices(u8, &expected_node_id, &node_id);
}

test "ENR Builder: encode with eth2 and attnets" {
    const hex_mod = @import("hex.zig");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var builder = Builder.init(alloc, secret_key, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;
    builder.tcp = 9000;
    builder.quic = 9001;
    builder.setEth2([4]u8{ 0x6a, 0x95, 0xa1, 0xb0 }, [4]u8{ 0, 0, 0, 0 }, 0xffffffffffffffff);
    builder.attnets = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    // Re-parse and verify fields are present
    var parsed = try decode(alloc, enr_bytes);
    defer parsed.deinit();

    try std.testing.expect(parsed.ip != null);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parsed.ip.?);
    try std.testing.expectEqual(@as(?u16, 9000), parsed.udp);
    try std.testing.expectEqual(@as(?u16, 9000), parsed.tcp);
    try std.testing.expectEqual(@as(?u16, 9001), parsed.quic);
    try std.testing.expect(parsed.eth2_fork_digest != null);
    try std.testing.expectEqual([4]u8{ 0x6a, 0x95, 0xa1, 0xb0 }, parsed.eth2_fork_digest.?);
    try std.testing.expect(parsed.attnets != null);
    try std.testing.expectEqual([8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, parsed.attnets.?);
}

test "ENR Builder: encodeToString produces valid enr: prefix" {
    const hex_mod = @import("hex.zig");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var builder = Builder.init(alloc, secret_key, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;

    const enr_str = try builder.encodeToString();
    defer alloc.free(enr_str);

    try std.testing.expect(std.mem.startsWith(u8, enr_str, "enr:"));
}

test "ENR decode rejects tampered signature" {
    const hex_mod = @import("hex.zig");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var builder = Builder.init(alloc, secret_key, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;

    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    const tampered = try alloc.dupe(u8, enr_bytes);
    defer alloc.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    try std.testing.expectError(Error.InvalidSignature, decode(alloc, tampered));
}

test "isSubnetSet and countSubnets" {
    // All subnets set
    const all = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectEqual(@as(u32, 64), countSubnets(all));
    try std.testing.expect(isSubnetSet(all, 0));
    try std.testing.expect(isSubnetSet(all, 63));

    // Only subnet 0 set
    const one = [8]u8{ 0x01, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqual(@as(u32, 1), countSubnets(one));
    try std.testing.expect(isSubnetSet(one, 0));
    try std.testing.expect(!isSubnetSet(one, 1));

    // Subnet 8 set (bit 0 of byte 1)
    const s8 = [8]u8{ 0, 0x01, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(isSubnetSet(s8, 8));
    try std.testing.expect(!isSubnetSet(s8, 0));
}
