//! Persistent Ethereum network identity.
//!
//! The beacon node should know its advertised network identity before it is
//! constructed. That means:
//! - one persistent secp256k1 secret key
//! - a peer ID derived from that key
//! - a persisted local ENR derived from that key plus the current CLI overrides
//!
//! The same secp256k1 key is used for ENR advertisement and libp2p host identity.

const std = @import("std");
const Allocator = std.mem.Allocator;

const discv5 = @import("discv5");
const secp256k1 = discv5.secp256k1;
const enr_mod = discv5.enr;
const EnrBuilder = enr_mod.Builder;
const libp2p = @import("zig-libp2p");
const libp2p_identity = libp2p.identity;
const NodeOptions = @import("options.zig").NodeOptions;

const log = std.log.scoped(.identity);

pub const NodeIdentity = struct {
    allocator: Allocator,
    secret_key: [32]u8,
    public_key: secp256k1.CompressedPubKey,
    node_id: enr_mod.NodeId,
    peer_id: []const u8,
    enr: []const u8,

    pub fn deinit(self: *NodeIdentity) void {
        self.allocator.free(self.peer_id);
        self.allocator.free(self.enr);
    }

    pub fn libp2pKeyPair(self: *const NodeIdentity) libp2p_identity.KeyPair {
        return .{
            .key_type = .SECP256K1,
            .backend = .secp256k1,
            .storage = .{ .secp256k1 = .{ .secret = self.secret_key } },
        };
    }
};

pub const PersistentIdentityPaths = struct {
    secret_key: []const u8,
    enr: []const u8,
};

pub fn createEphemeralIdentity(
    allocator: Allocator,
    io: std.Io,
    opts: NodeOptions,
) !NodeIdentity {
    const secret_key = try loadOrCreateSecretKey(io, "");
    return buildIdentity(allocator, io, secret_key, "", opts);
}

/// Load an existing identity from disk, or generate and persist a new one.
pub fn loadOrCreatePersistentIdentity(
    allocator: Allocator,
    io: std.Io,
    paths: PersistentIdentityPaths,
    opts: NodeOptions,
) !NodeIdentity {
    const secret_key = try loadOrCreateSecretKey(io, paths.secret_key);
    return buildIdentity(allocator, io, secret_key, paths.enr, opts);
}

fn buildIdentity(
    allocator: Allocator,
    io: std.Io,
    secret_key: [32]u8,
    enr_path: []const u8,
    opts: NodeOptions,
) !NodeIdentity {
    const public_key = secp256k1.pubkeyFromSecret(&secret_key) catch return error.InvalidSecretKey;
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&public_key);
    const peer_id = try derivePeerId(allocator, secret_key);
    errdefer allocator.free(peer_id);

    const enr_text = try loadOrBuildEnr(allocator, io, secret_key, &public_key, enr_path, opts);
    errdefer allocator.free(enr_text);

    return .{
        .allocator = allocator,
        .secret_key = secret_key,
        .public_key = public_key,
        .node_id = node_id,
        .peer_id = peer_id,
        .enr = enr_text,
    };
}

fn derivePeerId(allocator: Allocator, secret_key: [32]u8) ![]const u8 {
    const key_pair = libp2p_identity.KeyPair{
        .key_type = .SECP256K1,
        .backend = .secp256k1,
        .storage = .{ .secp256k1 = .{ .secret = secret_key } },
    };
    const peer_id = try key_pair.peerId(allocator);
    const scratch = try allocator.alloc(u8, peer_id.toBase58Len());
    defer allocator.free(scratch);
    const encoded = try peer_id.toBase58(scratch);
    return allocator.dupe(u8, encoded);
}

fn loadOrBuildEnr(
    allocator: Allocator,
    io: std.Io,
    secret_key: [32]u8,
    public_key: *const secp256k1.CompressedPubKey,
    enr_path: []const u8,
    opts: NodeOptions,
) ![]const u8 {
    const existing = if (enr_path.len > 0) try loadEnrText(io, allocator, enr_path) else null;
    defer if (existing) |text| allocator.free(text);

    var seq: u64 = 1;
    if (existing) |text| {
        seq = parseExistingEnrSeq(allocator, text, public_key) catch |err| switch (err) {
            error.PublicKeyMismatch, error.InvalidEnr => blk: {
                log.warn("Ignoring persisted local ENR at '{s}': {}", .{ enr_path, err });
                break :blk 1;
            },
            else => return err,
        };
    }

    var builder = try initBuilderForOptions(allocator, secret_key, seq, opts);
    var enr_text = try builder.encodeToString();
    errdefer allocator.free(enr_text);

    if (existing) |text| {
        if (!std.mem.eql(u8, text, enr_text)) {
            allocator.free(enr_text);
            builder.seq = seq + 1;
            enr_text = try builder.encodeToString();
        }
    }

    if (enr_path.len > 0) {
        try persistEnrText(io, enr_path, enr_text);
    }

    return enr_text;
}

fn parseExistingEnrSeq(
    allocator: Allocator,
    enr_text: []const u8,
    expected_pubkey: *const secp256k1.CompressedPubKey,
) !u64 {
    const raw = try decodeEnrText(allocator, enr_text);
    defer allocator.free(raw);

    var parsed = enr_mod.decode(allocator, raw) catch return error.InvalidEnr;
    defer parsed.deinit();

    const pubkey = parsed.pubkey orelse return error.InvalidEnr;
    if (!std.mem.eql(u8, pubkey[0..], expected_pubkey[0..])) {
        return error.PublicKeyMismatch;
    }
    return parsed.seq;
}

fn initBuilderForOptions(
    allocator: Allocator,
    secret_key: [32]u8,
    seq: u64,
    opts: NodeOptions,
) !EnrBuilder {
    var builder = EnrBuilder.init(allocator, secret_key, seq);

    if (try advertisedIp4(opts)) |ip4| {
        builder.ip = ip4;
        builder.udp = opts.enr_udp orelse opts.discovery_port orelse opts.p2p_port;
        builder.quic = opts.enr_tcp orelse opts.p2p_port;
    }

    if (try advertisedIp6(opts)) |ip6| {
        builder.ip6 = ip6;
        builder.udp6 = opts.enr_udp6 orelse opts.discovery_port6 orelse opts.discovery_port orelse opts.p2p_port6 orelse opts.p2p_port;
        builder.quic6 = opts.enr_tcp6 orelse opts.p2p_port6 orelse opts.p2p_port;
    }

    return builder;
}

fn advertisedIp4(opts: NodeOptions) !?[4]u8 {
    if (opts.enr_ip) |ip| return try parseIp4(ip);
    const host = opts.p2p_host orelse return null;
    if (std.mem.eql(u8, host, "0.0.0.0")) return null;
    return try parseIp4(host);
}

fn advertisedIp6(opts: NodeOptions) !?[16]u8 {
    if (opts.enr_ip6) |ip| return try parseIp6(ip);
    const host = opts.p2p_host6 orelse return null;
    if (std.mem.eql(u8, host, "::")) return null;
    return try parseIp6(host);
}

fn parseIp4(raw: []const u8) ![4]u8 {
    const addr = std.Io.net.IpAddress.parseIp4(raw, 0) catch return error.InvalidIpAddress;
    return switch (addr) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => return error.InvalidIpAddress,
    };
}

fn parseIp6(raw: []const u8) ![16]u8 {
    const addr = std.Io.net.IpAddress.parseIp6(raw, 0) catch return error.InvalidIpAddress;
    return switch (addr) {
        .ip4 => return error.InvalidIpAddress,
        .ip6 => |ip6| ip6.bytes,
    };
}

fn loadOrCreateSecretKey(io: std.Io, key_path: []const u8) ![32]u8 {
    if (key_path.len == 0) {
        const key = try generateRandomKey(io);
        log.info("Using ephemeral node identity (no key path)", .{});
        return key;
    }

    return loadFromPath(io, key_path) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const key = try generateRandomKey(io);
            try persistToPath(io, key_path, &key);
            log.info("Generated new node identity at {s}", .{key_path});
            break :blk key;
        },
        else => {
            log.err("Failed to load node identity from '{s}': {}", .{ key_path, err });
            return err;
        },
    };
}

fn generateRandomKey(io: std.Io) ![32]u8 {
    var key: [32]u8 = undefined;
    const urandom = try std.Io.Dir.cwd().openFile(io, "/dev/urandom", .{});
    defer urandom.close(io);
    const n = try urandom.readPositionalAll(io, &key, 0);
    if (n != 32) return error.ShortRead;
    return key;
}

fn loadFromPath(io: std.Io, path: []const u8) ![32]u8 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return error.ReadFailed,
    };
    defer file.close(io);

    var buf: [128]u8 = undefined;
    const stat = file.stat(io) catch return error.ReadFailed;
    if (stat.size > buf.len) return error.ReadFailed;

    const n = file.readPositionalAll(io, buf[0..@intCast(stat.size)], 0) catch return error.ReadFailed;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n\r");
    if (trimmed.len != 64) return error.InvalidKeyLength;

    var secret_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret_key, trimmed) catch return error.InvalidKeyHex;

    log.info("Loaded node identity from {s}", .{path});
    return secret_key;
}

fn persistToPath(io: std.Io, path: []const u8, secret_key: *const [32]u8) !void {
    const file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch return error.WriteFailed;
    defer file.close(io);

    var hex_buf: [65]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{s}\n", .{&std.fmt.bytesToHex(secret_key.*, .lower)}) catch
        return error.WriteFailed;
    try file.writePositionalAll(io, hex, 0);
}

fn loadEnrText(io: std.Io, allocator: Allocator, path: []const u8) !?[]u8 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return error.ReadFailed,
    };
    defer file.close(io);

    const stat = file.stat(io) catch return error.ReadFailed;
    if (stat.size == 0 or stat.size > 4096) return error.ReadFailed;

    const buf = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n\r");
    return try allocator.dupe(u8, trimmed);
}

fn persistEnrText(io: std.Io, path: []const u8, enr_text: []const u8) !void {
    const file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch return error.WriteFailed;
    defer file.close(io);
    try file.writePositionalAll(io, enr_text, 0);
}

fn decodeEnrText(allocator: Allocator, enr_text: []const u8) ![]u8 {
    var trimmed = std.mem.trim(u8, enr_text, " \t\n\r");
    if (std.mem.startsWith(u8, trimmed, "enr:")) {
        trimmed = trimmed[4..];
    }

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidEnr;
    const raw = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(raw);
    std.base64.url_safe_no_pad.Decoder.decode(raw, trimmed) catch return error.InvalidEnr;
    return raw;
}

test "initBuilderForOptions only advertises QUIC transport" {
    var builder = try initBuilderForOptions(
        std.testing.allocator,
        [_]u8{1} ** 32,
        1,
        .{
            .enr_ip = "127.0.0.1",
            .enr_ip6 = "2001:db8::1",
            .p2p_port = 9000,
            .p2p_port6 = 9001,
        },
    );
    defer builder.deinit();

    try std.testing.expectEqual(@as(?u16, null), builder.tcp);
    try std.testing.expectEqual(@as(?u16, 9000), builder.quic);
    try std.testing.expectEqual(@as(?u16, null), builder.tcp6);
    try std.testing.expectEqual(@as(?u16, 9001), builder.quic6);
}
