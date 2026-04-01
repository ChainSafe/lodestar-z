//! Persistent Ethereum network identity.
//!
//! The beacon node should know its advertised network identity before it is
//! constructed. That means:
//! - one persistent secp256k1 secret key
//! - a peer ID derived from that key
//! - a persisted local ENR derived from that key plus the current CLI overrides
//!
//! The libp2p transport stack in `zig-libp2p` still does not accept
//! secp256k1 host keys for QUIC/TLS, so this module prepares the canonical
//! Ethereum identity even though the transport layer cannot fully consume it yet.

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
        builder.tcp = opts.enr_tcp orelse opts.p2p_port;
        builder.quic = opts.enr_tcp orelse opts.p2p_port;
    }

    if (try advertisedIp6(opts)) |ip6| {
        builder.ip6 = ip6;
        builder.udp6 = opts.enr_udp6 orelse opts.discovery_port orelse opts.p2p_port;
        builder.tcp6 = opts.enr_tcp6 orelse opts.p2p_port;
        builder.quic6 = opts.enr_tcp6 orelse opts.p2p_port;
    }

    return builder;
}

fn advertisedIp4(opts: NodeOptions) !?[4]u8 {
    if (opts.enr_ip) |ip| return try parseIp4(ip);
    if (std.mem.eql(u8, opts.p2p_host, "0.0.0.0")) return null;
    return try parseIp4(opts.p2p_host);
}

fn advertisedIp6(opts: NodeOptions) !?[16]u8 {
    if (opts.enr_ip6) |ip| return try parseIp6(ip);
    return null;
}

fn parseIp4(raw: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, raw, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= out.len) return error.InvalidIpAddress;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpAddress;
        i += 1;
    }
    if (i != out.len) return error.InvalidIpAddress;
    return out;
}

fn parseIp6(raw: []const u8) ![16]u8 {
    var result: [16]u8 = [_]u8{0} ** 16;
    if (std.mem.eql(u8, raw, "::")) return result;

    var it = std.mem.splitSequence(u8, raw, ":");
    var i: usize = 0;
    while (it.next()) |part| {
        if (part.len == 0) continue;
        if (i >= 8) return error.InvalidIpAddress;
        const value = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpAddress;
        result[i * 2] = @intCast(value >> 8);
        result[i * 2 + 1] = @intCast(value & 0xff);
        i += 1;
    }
    return result;
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
