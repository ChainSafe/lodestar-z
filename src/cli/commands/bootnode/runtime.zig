//! Standalone discv5 bootnode.
//!
//! Implements a minimal discv5 discovery node that:
//! - Generates or loads a persistent secp256k1 identity
//! - Builds and signs a local ENR with configured addresses
//! - Runs a discv5 service bound to a UDP socket
//! - Seeds its routing table from CLI bootnodes, file, or network defaults
//! - Periodically logs peer reachability statistics
//! - Persists identity (key + ENR) across restarts
//!
//! Feature parity with TS Lodestar: packages/cli/src/cmds/bootnode/

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const discv5 = @import("discv5");
const BindAddresses = discv5.BindAddresses;
const Discv5Service = discv5.Service;
const Enr = discv5.enr.Enr;
const EnrBuilder = discv5.enr.Builder;
const NodeId = discv5.enr.NodeId;
const enr_mod = discv5.enr;
const secp = discv5.secp256k1;
const Address = discv5.Address;

const ShutdownHandler = @import("../../shutdown.zig").ShutdownHandler;

const log = std.log.scoped(.bootnode);

// ── Version ─────────────────────────────────────────────────────────────────

const VERSION = "0.1.0";

// ── CLI Options ─────────────────────────────────────────────────────────────

pub const BootnodeOpts = struct {
    /// IPv4 listen address. If both families are omitted, defaults to "0.0.0.0".
    listen_address: ?[]const u8 = null,
    /// UDP port (default 9000)
    port: u16 = 9000,
    /// IPv6 listen address (optional)
    listen_address6: ?[]const u8 = null,
    /// IPv6 UDP port (optional)
    port6: ?u16 = null,
    /// Comma-separated ENR strings to seed routing table
    bootnodes: ?[]const u8 = null,
    /// Path to file with bootnode ENRs (one per line)
    bootnodes_file: ?[]const u8 = null,
    /// Override ENR IP
    enr_ip: ?[]const u8 = null,
    /// Override ENR IPv6
    enr_ip6: ?[]const u8 = null,
    /// Override ENR UDP port
    enr_udp: ?u16 = null,
    /// Override ENR IPv6 UDP port
    enr_udp6: ?u16 = null,
    /// Persist ENR + key across restarts (default true)
    persist_network_identity: bool = true,
    /// Allow non-local addresses in ENR
    nat: bool = false,
    /// Root data directory
    data_dir: []const u8 = "",
    /// Target Ethereum network
    network: []const u8 = "mainnet",
};

// ── Key Management ──────────────────────────────────────────────────────────

/// Load a private key from `<dir>/peer-id`, or generate and save a new one.
fn loadOrGenerateKey(io: Io, allocator: Allocator, dir_path: []const u8, persist: bool) !struct { key: [32]u8, created: bool } {
    // Try to load existing key
    if (persist and dir_path.len > 0) {
        const key_path = try std.fmt.allocPrint(allocator, "{s}/peer-id", .{dir_path});
        defer allocator.free(key_path);

        if (Io.Dir.cwd().openFile(io, key_path, .{})) |file| {
            defer file.close(io);
            var buf: [64]u8 = undefined;
            const file_stat = try file.stat(io);
            const n = try file.readPositionalAll(io, buf[0..@min(file_stat.size, 64)], 0);
            if (n == 64) {
                // Hex-encoded 32-byte key
                var key: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&key, buf[0..64]) catch return .{ .key = undefined, .created = true };
                log.info("Loaded private key from {s}", .{key_path});
                return .{ .key = key, .created = false };
            }
        } else |_| {}
    }

    // Generate new key
    var key: [32]u8 = undefined;
    io.random(&key);
    // Verify it's a valid secp256k1 key
    _ = secp.pubkeyFromSecret(&key) catch {
        // Extremely unlikely but retry once
        io.random(&key);
        _ = try secp.pubkeyFromSecret(&key);
    };

    // Save if configured
    if (persist and dir_path.len > 0) {
        try Io.Dir.cwd().createDirPath(io, dir_path);
        const key_path = try std.fmt.allocPrint(allocator, "{s}/peer-id", .{dir_path});
        defer allocator.free(key_path);

        const hex_buf = std.fmt.bytesToHex(key, .lower);
        writeFileContents(io, key_path, &hex_buf) catch |err| {
            log.warn("Failed to save private key to {s}: {}", .{ key_path, err });
        };
        log.info("Generated and saved new private key to {s}", .{key_path});
    } else {
        log.info("Generated ephemeral private key (not persisted)", .{});
    }

    return .{ .key = key, .created = true };
}

/// Load ENR text from `<dir>/enr`, returning null if not found.
fn loadEnrFromDisk(io: Io, allocator: Allocator, dir_path: []const u8) !?[]u8 {
    const enr_path = try std.fmt.allocPrint(allocator, "{s}/enr", .{dir_path});
    defer allocator.free(enr_path);

    const file = Io.Dir.cwd().openFile(io, enr_path, .{}) catch return null;
    defer file.close(io);
    const file_stat = try file.stat(io);
    if (file_stat.size > 4096) return null;
    const buf = try allocator.alloc(u8, file_stat.size);
    defer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    return try allocator.dupe(u8, std.mem.trim(u8, buf[0..n], " \t\n\r"));
}

/// Save ENR text to `<dir>/enr`.
fn saveEnrToDisk(io: Io, allocator: Allocator, dir_path: []const u8, enr_str: []const u8) !void {
    try Io.Dir.cwd().createDirPath(io, dir_path);
    const enr_path = try std.fmt.allocPrint(allocator, "{s}/enr", .{dir_path});
    defer allocator.free(enr_path);
    try writeFileContents(io, enr_path, enr_str);
    log.info("Saved ENR to {s}", .{enr_path});
}

/// Write bytes to a file, creating or truncating.
fn writeFileContents(io: Io, path: []const u8, data: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, data, 0);
}

fn decodeEnrText(allocator: Allocator, enr_str: []const u8) ![]u8 {
    const enr_data = if (std.mem.startsWith(u8, enr_str, "enr:"))
        enr_str[4..]
    else
        enr_str;

    const decoded_len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(enr_data);
    const raw = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(raw);
    try std.base64.url_safe_no_pad.Decoder.decode(raw, enr_data);
    return raw;
}

fn encodeEnrText(allocator: Allocator, enr_bytes: []const u8) ![]u8 {
    const b64_len = std.base64.url_safe_no_pad.Encoder.calcSize(enr_bytes.len);
    const result = try allocator.alloc(u8, 4 + b64_len);
    @memcpy(result[0..4], "enr:");
    _ = std.base64.url_safe_no_pad.Encoder.encode(result[4..], enr_bytes);
    return result;
}

fn loadPersistedEnr(io: Io, allocator: Allocator, dir_path: []const u8, expected_node_id: *const NodeId) !?Enr {
    const enr_text = try loadEnrFromDisk(io, allocator, dir_path) orelse return null;
    defer allocator.free(enr_text);

    const raw = decodeEnrText(allocator, enr_text) catch return null;
    errdefer allocator.free(raw);

    var parsed = enr_mod.decode(allocator, raw) catch {
        allocator.free(raw);
        return null;
    };
    allocator.free(raw);

    const node_id = parsed.nodeId() orelse {
        parsed.deinit();
        return null;
    };
    if (!std.mem.eql(u8, &node_id, expected_node_id)) {
        parsed.deinit();
        return null;
    }

    return parsed;
}

// ── Address Parsing ─────────────────────────────────────────────────────────

fn parseIp4(s: []const u8) ?[4]u8 {
    const addr = Io.net.IpAddress.parseIp4(s, 0) catch return null;
    return switch (addr) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => null,
    };
}

fn parseIp6(s: []const u8) ?[16]u8 {
    const addr = Io.net.IpAddress.parseIp6(s, 0) catch return null;
    return switch (addr) {
        .ip4 => null,
        .ip6 => |ip6| ip6.bytes,
    };
}

fn isUnspecifiedIp4(ip: [4]u8) bool {
    return std.mem.eql(u8, &ip, &[_]u8{ 0, 0, 0, 0 });
}

fn isUnspecifiedIp6(ip: [16]u8) bool {
    return std.mem.eql(u8, &ip, &([_]u8{0} ** 16));
}

fn trimmedOption(opt: ?[]const u8) ?[]const u8 {
    const value = opt orelse return null;
    const trimmed = std.mem.trim(u8, value, " \t");
    return if (trimmed.len == 0) null else trimmed;
}

fn resolveBindAddresses(opts: BootnodeOpts) !BindAddresses {
    const listen_address4 = trimmedOption(opts.listen_address);
    const listen_address6 = trimmedOption(opts.listen_address6);

    var wants_ip4 = listen_address4 != null or opts.enr_ip != null or opts.enr_udp != null;
    const wants_ip6 = listen_address6 != null or opts.port6 != null or opts.enr_ip6 != null or opts.enr_udp6 != null;
    if (!wants_ip4 and !wants_ip6) wants_ip4 = true;

    var bind_addresses = BindAddresses{};
    if (wants_ip4) {
        const ip4 = if (listen_address4) |addr|
            parseIp4(addr) orelse return error.InvalidListenAddress
        else
            [4]u8{ 0, 0, 0, 0 };
        bind_addresses.ip4 = .{ .ip4 = .{ .bytes = ip4, .port = opts.port } };
    }

    if (wants_ip6) {
        const ip6 = if (listen_address6) |addr|
            parseIp6(addr) orelse return error.InvalidListenAddress
        else
            [_]u8{0} ** 16;
        bind_addresses.ip6 = .{ .ip6 = .{ .bytes = ip6, .port = opts.port6 orelse opts.port } };
    }

    return bind_addresses;
}

// ── ENR Bootnode Seeding ────────────────────────────────────────────────────

/// Parse ENR string, decode, and add to the discv5 service.
fn seedEnrToService(allocator: Allocator, service: *Discv5Service, enr_str: []const u8) bool {
    const trimmed = std.mem.trim(u8, enr_str, " \t\n\r");
    if (trimmed.len == 0) return false;

    const raw = decodeEnrText(allocator, trimmed) catch return false;
    defer allocator.free(raw);
    return service.addEnr(raw);
}

/// Seed routing table from comma-separated ENR string.
fn seedFromBootnodeList(allocator: Allocator, service: *Discv5Service, list: []const u8) usize {
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |enr_str| {
        if (seedEnrToService(allocator, service, enr_str)) {
            count += 1;
        }
    }
    return count;
}

/// Seed routing table from a file with one ENR per line.
fn seedFromBootnodeFile(io: Io, allocator: Allocator, service: *Discv5Service, path: []const u8) !usize {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const file_stat = try file.stat(io);
    if (file_stat.size > 1024 * 1024) return error.FileTooLarge; // 1MB limit
    const content = try allocator.alloc(u8, file_stat.size);
    defer allocator.free(content);
    const n = try file.readPositionalAll(io, content, 0);

    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, content[0..n], '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or std.mem.startsWith(u8, trimmed, "#")) continue;
        if (seedEnrToService(allocator, service, trimmed)) count += 1;
    }
    return count;
}

// ── Peer Statistics ─────────────────────────────────────────────────────────

const PeerStats = struct {
    total: usize,
    ip4_only: usize,
    ip6_only: usize,
    dual_stack: usize,
    @"unreachable": usize,
};

fn countPeerStats(service: *const Discv5Service, allocator: Allocator) PeerStats {
    var stats = PeerStats{
        .total = 0,
        .ip4_only = 0,
        .ip6_only = 0,
        .dual_stack = 0,
        .@"unreachable" = 0,
    };

    var bucket_idx: u8 = 0;
    while (bucket_idx < 255) : (bucket_idx += 1) {
        const bucket = service.protocol.routing_table.getBucket(bucket_idx);
        for (bucket) |entry| {
            if (entry.status != .connected) continue;
            stats.total += 1;

            if (service.findEnr(&entry.node_id)) |raw_enr| {
                var parsed = enr_mod.decode(allocator, raw_enr) catch {
                    countAddrOnlyStat(&stats, entry.addr);
                    continue;
                };
                defer parsed.deinit();

                const has_ip4 = parsed.ip != null and parsed.udp != null;
                const has_ip6 = parsed.ip6 != null and parsed.udp6 != null;
                if (has_ip4 and has_ip6) {
                    stats.dual_stack += 1;
                } else if (has_ip4) {
                    stats.ip4_only += 1;
                } else if (has_ip6) {
                    stats.ip6_only += 1;
                } else {
                    stats.@"unreachable" += 1;
                }
            } else {
                countAddrOnlyStat(&stats, entry.addr);
            }
        }
    }

    return stats;
}

fn countAddrOnlyStat(stats: *PeerStats, addr: Address) void {
    switch (addr) {
        .ip4 => |ip4| {
            if (std.mem.eql(u8, &ip4.bytes, &[_]u8{ 0, 0, 0, 0 })) {
                stats.@"unreachable" += 1;
            } else {
                stats.ip4_only += 1;
            }
        },
        .ip6 => |ip6| {
            if (std.mem.eql(u8, &ip6.bytes, &([_]u8{0} ** 16))) {
                stats.@"unreachable" += 1;
            } else {
                stats.ip6_only += 1;
            }
        },
    }
}

fn populateBootnodeEnrBuilder(
    builder: *EnrBuilder,
    opts: BootnodeOpts,
    bind_ip4: ?[4]u8,
    bound_port4: ?u16,
    bind_ip6: ?[16]u8,
    bound_port6: ?u16,
    persisted_enr: ?*const Enr,
) !void {
    if (opts.enr_ip) |ip_str| {
        builder.ip = parseIp4(ip_str) orelse return error.InvalidEnrAddress;
    } else if (bind_ip4) |ip4| {
        if (!isUnspecifiedIp4(ip4)) {
            builder.ip = ip4;
        } else if (persisted_enr) |persisted| {
            builder.ip = persisted.ip;
        } else {
            builder.ip = null;
        }
    } else {
        builder.ip = null;
    }

    if (builder.ip != null) {
        builder.udp = opts.enr_udp orelse bound_port4 orelse if (persisted_enr) |persisted| persisted.udp else null;
    } else {
        builder.udp = null;
    }

    if (opts.enr_ip6) |ip6_str| {
        builder.ip6 = parseIp6(ip6_str) orelse return error.InvalidEnrAddress;
    } else if (bind_ip6) |ip6| {
        if (!isUnspecifiedIp6(ip6)) {
            builder.ip6 = ip6;
        } else if (persisted_enr) |persisted| {
            builder.ip6 = persisted.ip6;
        } else {
            builder.ip6 = null;
        }
    } else {
        builder.ip6 = null;
    }

    if (builder.ip6 != null) {
        builder.udp6 = opts.enr_udp6 orelse bound_port6 orelse if (persisted_enr) |persisted| persisted.udp6 else null;
    } else {
        builder.udp6 = null;
    }
}

fn advertisedEndpointsEqual(builder: *const EnrBuilder, enr: *const Enr) bool {
    return std.meta.eql(builder.ip, enr.ip) and
        builder.udp == enr.udp and
        std.meta.eql(builder.ip6, enr.ip6) and
        builder.udp6 == enr.udp6;
}

fn nextEnrSeq(persisted_enr: ?*const Enr, builder: *const EnrBuilder) u64 {
    const persisted = persisted_enr orelse return 1;
    return if (advertisedEndpointsEqual(builder, persisted)) persisted.seq else persisted.seq + 1;
}

fn persistCurrentEnr(io: Io, allocator: Allocator, dir_path: []const u8, service: *const Discv5Service) void {
    const local_enr = service.localEnr() orelse return;
    const enr_text = encodeEnrText(allocator, local_enr) catch return;
    defer allocator.free(enr_text);
    saveEnrToDisk(io, allocator, dir_path, enr_text) catch |err| {
        log.warn("Failed to persist ENR: {}", .{err});
    };
}

fn logAdvertisedEnr(service: *const Discv5Service) void {
    const local_enr = service.localEnr() orelse return;
    var parsed = enr_mod.decode(std.heap.page_allocator, local_enr) catch return;
    defer parsed.deinit();

    if (parsed.ip) |ip| {
        log.info("  enrAddr:    {d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], parsed.udp orelse 0 });
    }
    if (parsed.ip6) |ip6| {
        log.info("  enrAddr6:   [{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{d}", .{
            ip6[0],               ip6[1], ip6[2],  ip6[3],  ip6[4],  ip6[5],  ip6[6],  ip6[7],
            ip6[8],               ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15],
            parsed.udp6 orelse 0,
        });
    }
}

fn drainBootnodeEvents(
    io: Io,
    allocator: Allocator,
    service: *Discv5Service,
    bootnode_dir: []const u8,
    persist_identity: bool,
) void {
    while (service.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(allocator);

        switch (owned) {
            .local_enr_updated => {
                log.info("Advertised ENR updated", .{});
                if (persist_identity and bootnode_dir.len > 0) {
                    persistCurrentEnr(io, allocator, bootnode_dir, service);
                }
            },
            .peer_connected => |connected| {
                log.debug("Peer connected: 0x{s} {}", .{ &std.fmt.bytesToHex(connected.peer_id, .lower), connected.peer_addr });
            },
            .peer_disconnected => |disconnected| {
                log.debug("Peer disconnected: 0x{s} {}", .{ &std.fmt.bytesToHex(disconnected.peer_id, .lower), disconnected.peer_addr });
            },
            .request_timeout => |timeout| {
                log.debug("Request timeout: peer=0x{s} kind={s}", .{
                    &std.fmt.bytesToHex(timeout.peer_id, .lower),
                    @tagName(timeout.kind),
                });
            },
            .lookup_finished => |lookup_finished| {
                log.debug("Lookup {d} finished (timed_out={}, enrs={d})", .{
                    lookup_finished.lookup_id,
                    lookup_finished.timed_out,
                    lookup_finished.enrs.len,
                });
            },
            else => {},
        }
    }
}

// ── Main Entry Point ────────────────────────────────────────────────────────

pub fn run(io: Io, allocator: Allocator, opts: BootnodeOpts) !void {
    log.info("lodestar-z bootnode v{s} starting", .{VERSION});

    // ── Data directory ──────────────────────────────────────────────
    const bootnode_dir: []const u8 = if (opts.data_dir.len > 0) blk: {
        const dir = try std.fmt.allocPrint(allocator, "{s}/bootnode", .{opts.data_dir});
        break :blk dir;
    } else "";
    defer if (bootnode_dir.len > 0) allocator.free(bootnode_dir);

    // ── Install signal handlers ─────────────────────────────────────
    ShutdownHandler.installSignalHandlers();

    // ── Key management ──────────────────────────────────────────────
    const key_result = try loadOrGenerateKey(io, allocator, bootnode_dir, opts.persist_network_identity);
    const secret_key = key_result.key;

    // Derive public key and node ID
    const pubkey = try secp.pubkeyFromSecret(&secret_key);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pubkey);

    var persisted_enr = if (opts.persist_network_identity and bootnode_dir.len > 0)
        try loadPersistedEnr(io, allocator, bootnode_dir, &node_id)
    else
        null;
    defer if (persisted_enr) |*enr| enr.deinit();

    const bind_addresses = try resolveBindAddresses(opts);

    // ── Create discv5 service ───────────────────────────────────────
    var service = try Discv5Service.init(io, allocator, .{
        .bind_addresses = bind_addresses,
        .protocol_config = .{
            .local_secret_key = secret_key,
            .local_node_id = node_id,
        },
        .receive_timeout_ms = 100,
        .ping_interval_ms = 30_000,
    });
    defer service.deinit();

    // ── Build local ENR from the bound socket ───────────────────────
    const bind_ip4 = if (bind_addresses.ip4) |addr| switch (addr) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    } else null;
    const bind_ip6 = if (bind_addresses.ip6) |addr| switch (addr) {
        .ip4 => unreachable,
        .ip6 => |ip6| ip6.bytes,
    } else null;

    var enr_builder = EnrBuilder.init(allocator, secret_key, 1);
    try populateBootnodeEnrBuilder(
        &enr_builder,
        opts,
        bind_ip4,
        service.boundPort(.ip4),
        bind_ip6,
        service.boundPort(.ip6),
        if (persisted_enr) |*enr| enr else null,
    );
    enr_builder.seq = nextEnrSeq(if (persisted_enr) |*enr| enr else null, &enr_builder);

    const local_enr = try enr_builder.encode();
    defer allocator.free(local_enr);
    try service.setLocalEnr(local_enr);
    service.config.enr_update = enr_builder.ip == null and enr_builder.ip6 == null;

    if (opts.persist_network_identity and bootnode_dir.len > 0) {
        persistCurrentEnr(io, allocator, bootnode_dir, &service);
    }

    // ── Log identity ────────────────────────────────────────────────
    log.info("  network:    {s}", .{opts.network});
    log.info("  nodeId:     0x{s}", .{&std.fmt.bytesToHex(node_id, .lower)});
    if (service.boundAddress(.ip4)) |addr| log.info("  bindAddr4:  {}", .{addr});
    if (service.boundAddress(.ip6)) |addr| log.info("  bindAddr6:  {}", .{addr});
    logAdvertisedEnr(&service);
    if (service.localEnr()) |raw_enr| {
        const enr_str = try encodeEnrText(allocator, raw_enr);
        defer allocator.free(enr_str);
        log.info("  ENR:        {s}", .{enr_str});
    }

    // ── Seed routing table ──────────────────────────────────────────
    var total_seeded: usize = 0;

    // From --bootnodes CLI option
    if (opts.bootnodes) |bn_list| {
        const n = seedFromBootnodeList(allocator, &service, bn_list);
        total_seeded += n;
        log.info("Seeded {d} bootnode(s) from --bootnodes", .{n});
    }

    // From --bootnodesFile
    if (opts.bootnodes_file) |bn_file| {
        const n = seedFromBootnodeFile(io, allocator, &service, bn_file) catch |err| blk: {
            log.warn("Failed to read bootnodes file '{s}': {}", .{ bn_file, err });
            break :blk @as(usize, 0);
        };
        total_seeded += n;
        log.info("Seeded {d} bootnode(s) from --bootnodesFile", .{n});
    }

    log.info("Routing table: {d} peer(s) after seeding ({d} added this run)", .{ service.knownPeerCount(), total_seeded });
    if (service.knownPeerCount() > 0) {
        _ = service.startRandomLookup() catch {};
    }

    // ── Main loop: poll service + periodic stats ────────────────────
    log.info("Bootnode running. Press Ctrl-C to stop.", .{});
    var next_stats_at_ns = @as(i64, @intCast(Io.Timestamp.now(io, .real).toNanoseconds())) + 10 * std.time.ns_per_s;

    while (!ShutdownHandler.shouldStop()) {
        service.poll();
        drainBootnodeEvents(io, allocator, &service, bootnode_dir, opts.persist_network_identity);

        const now_ns = @as(i64, @intCast(Io.Timestamp.now(io, .real).toNanoseconds()));
        if (now_ns >= next_stats_at_ns) {
            logStats(&service, allocator);
            next_stats_at_ns = now_ns + 10 * std.time.ns_per_s;
        }
    }

    // ── Shutdown ────────────────────────────────────────────────────
    log.info("Shutting down bootnode...", .{});

    if (opts.persist_network_identity and bootnode_dir.len > 0) {
        persistCurrentEnr(io, allocator, bootnode_dir, &service);
    }

    drainBootnodeEvents(io, allocator, &service, bootnode_dir, opts.persist_network_identity);
    log.info("Bootnode stopped.", .{});
}

fn logStats(service: *const Discv5Service, allocator: Allocator) void {
    const stats = countPeerStats(service, allocator);
    log.info("peers: {d} connected ({d} ip4, {d} ip6, {d} dual, {d} unreachable) | known: {d} | sessions: {d}", .{
        stats.total,
        stats.ip4_only,
        stats.ip6_only,
        stats.dual_stack,
        stats.@"unreachable",
        service.knownPeerCount(),
        service.protocol.sessions.count(),
    });
}
