//! Standalone discv5 bootnode.
//!
//! Implements a minimal discv5 discovery node that:
//! - Generates or loads a persistent secp256k1 identity
//! - Builds and signs a local ENR with configured addresses
//! - Runs a discv5 protocol instance bound to a UDP transport
//! - Seeds its routing table from CLI bootnodes, file, or network defaults
//! - Periodically logs peer reachability statistics
//! - Persists identity (key + ENR) across restarts
//!
//! Feature parity with TS Lodestar: packages/cli/src/cmds/bootnode/

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const discv5 = @import("discv5");
const Protocol = discv5.protocol.Protocol;
const Enr = discv5.enr.Enr;
const EnrBuilder = discv5.enr.Builder;
const NodeId = discv5.enr.NodeId;
const enr_mod = discv5.enr;
const secp = discv5.secp256k1;
const transport_mod = discv5.transport;
const Address = transport_mod.Address;
const Transport = transport_mod.Transport;

const ShutdownHandler = @import("shutdown.zig").ShutdownHandler;

const log = std.log.scoped(.bootnode);

// ── Version ─────────────────────────────────────────────────────────────────

const VERSION = "0.1.0";

// ── CLI Options ─────────────────────────────────────────────────────────────

pub const BootnodeOpts = struct {
    /// IPv4 listen address (default "0.0.0.0")
    listen_address: []const u8 = "0.0.0.0",
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

// ── Raw Linux UDP Transport ─────────────────────────────────────────────────
// std.posix.socket is removed in newer Zig; use Linux syscalls directly.

const SockaddrIn = extern struct {
    family: u16 = linux.AF.INET,
    port: u16 = 0, // big-endian
    addr: u32 = 0, // big-endian
    zero: [8]u8 = [_]u8{0} ** 8,
};

const Timeval = extern struct {
    sec: i64,
    usec: i64,
};

fn htons(x: u16) u16 {
    return std.mem.nativeToBig(u16, x);
}

fn htonl(x: u32) u32 {
    return std.mem.nativeToBig(u32, x);
}

fn ipToU32(ip: [4]u8) u32 {
    return htonl((@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]));
}

const LinuxUdpTransport = struct {
    sockfd: i32,

    fn init(bind_ip: [4]u8, bind_port: u16) !LinuxUdpTransport {
        const r = linux.syscall3(.socket, linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        const rc: isize = @bitCast(r);
        if (rc < 0) return error.SocketFailed;
        const sockfd: i32 = @intCast(r);

        // Set recv timeout to 100ms for non-blocking-like behavior
        const tv = Timeval{ .sec = 0, .usec = 100_000 };
        _ = linux.syscall5(
            .setsockopt,
            @intCast(sockfd),
            linux.SOL.SOCKET,
            linux.SO.RCVTIMEO,
            @intFromPtr(&tv),
            @sizeOf(Timeval),
        );

        var sa = SockaddrIn{
            .port = htons(bind_port),
            .addr = ipToU32(bind_ip),
        };
        const bind_rc: isize = @bitCast(linux.syscall3(.bind, @intCast(sockfd), @intFromPtr(&sa), @sizeOf(SockaddrIn)));
        if (bind_rc != 0) return error.BindFailed;

        return .{ .sockfd = sockfd };
    }

    fn deinit(self: *LinuxUdpTransport) void {
        _ = linux.syscall1(.close, @intCast(self.sockfd));
    }

    fn transport(self: *LinuxUdpTransport) Transport {
        return .{
            .ptr = @ptrCast(self),
            .sendFn = sendImpl,
            .recvFn = recvImpl,
            .closeFn = closeImpl,
        };
    }

    fn sendImpl(ptr: *anyopaque, dest: Address, data: []const u8) anyerror!void {
        const self: *LinuxUdpTransport = @ptrCast(@alignCast(ptr));
        const sa = SockaddrIn{
            .port = htons(dest.port),
            .addr = ipToU32(dest.ip),
        };
        const r = linux.syscall6(
            .sendto,
            @intCast(self.sockfd),
            @intFromPtr(data.ptr),
            data.len,
            0,
            @intFromPtr(&sa),
            @sizeOf(SockaddrIn),
        );
        const rc: isize = @bitCast(r);
        if (rc < 0) return error.SendFailed;
    }

    fn recvImpl(ptr: *anyopaque, buf: []u8) anyerror!transport_mod.RecvResult {
        const self: *LinuxUdpTransport = @ptrCast(@alignCast(ptr));
        var src_addr: SockaddrIn = .{};
        var src_len: u32 = @sizeOf(SockaddrIn);
        const r = linux.syscall6(
            .recvfrom,
            @intCast(self.sockfd),
            @intFromPtr(buf.ptr),
            buf.len,
            0,
            @intFromPtr(&src_addr),
            @intFromPtr(&src_len),
        );
        const rc: isize = @bitCast(r);
        if (rc < 0) return error.WouldBlock;
        const n: usize = @intCast(rc);

        // Extract IP from network-byte-order u32
        const addr_be = std.mem.toBytes(src_addr.addr);

        return .{
            .data = buf[0..n],
            .from = .{
                .ip = addr_be,
                .port = std.mem.bigToNative(u16, src_addr.port),
            },
        };
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *LinuxUdpTransport = @ptrCast(@alignCast(ptr));
        _ = linux.syscall1(.close, @intCast(self.sockfd));
    }
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
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    return std.mem.trim(u8, buf[0..n], " \t\n\r");
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

// ── Address Parsing ─────────────────────────────────────────────────────────

fn parseIp4(s: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return null;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return octets;
}

fn parseIp6(s: []const u8) ?[16]u8 {
    // Basic IPv6 parser — handles full colon-hex form and "::" shorthand
    var result: [16]u8 = [_]u8{0} ** 16;
    if (std.mem.eql(u8, s, "::")) return result;

    var it = std.mem.splitSequence(u8, s, ":");
    var i: usize = 0;
    while (it.next()) |part| {
        if (part.len == 0) continue; // handle :: expansion (simplified)
        if (i >= 8) return null;
        const val = std.fmt.parseInt(u16, part, 16) catch return null;
        result[i * 2] = @intCast(val >> 8);
        result[i * 2 + 1] = @intCast(val & 0xff);
        i += 1;
    }
    return result;
}

// ── ENR Bootnode Seeding ────────────────────────────────────────────────────

/// Parse ENR string, decode, and add to protocol routing table.
fn seedEnrToProtocol(allocator: Allocator, protocol_inst: *Protocol, enr_str: []const u8) bool {
    // Strip "enr:" prefix if present
    var s: []const u8 = enr_str;
    if (std.mem.startsWith(u8, s, "enr:")) s = s[4..];
    s = std.mem.trim(u8, s, " \t\n\r");
    if (s.len == 0) return false;

    // Base64url decode
    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(s) catch return false;
    const raw = allocator.alloc(u8, decoded_len) catch return false;
    defer allocator.free(raw);
    std.base64.url_safe_no_pad.Decoder.decode(raw, s) catch return false;

    // Parse ENR
    var enr = enr_mod.decode(allocator, raw) catch return false;
    defer enr.deinit();

    const node_id = enr.nodeId() orelse return false;
    const ip = enr.ip orelse return false;
    const port = enr.udp orelse return false;

    protocol_inst.addNode(node_id, .{ .ip = ip, .port = port });
    return true;
}

/// Seed routing table from comma-separated ENR string.
fn seedFromBootnodeList(allocator: Allocator, protocol_inst: *Protocol, list: []const u8) usize {
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |enr_str| {
        const trimmed = std.mem.trim(u8, enr_str, " \t\n\r");
        if (trimmed.len > 0 and seedEnrToProtocol(allocator, protocol_inst, trimmed)) {
            count += 1;
        }
    }
    return count;
}

/// Seed routing table from a file with one ENR per line.
fn seedFromBootnodeFile(io: Io, allocator: Allocator, protocol_inst: *Protocol, path: []const u8) !usize {
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
        if (trimmed.len > 0 and !std.mem.startsWith(u8, trimmed, "#")) {
            if (seedEnrToProtocol(allocator, protocol_inst, trimmed)) {
                count += 1;
            }
        }
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

fn countPeerStats(protocol_inst: *const Protocol) PeerStats {
    var stats = PeerStats{
        .total = 0,
        .ip4_only = 0,
        .ip6_only = 0,
        .dual_stack = 0,
        .@"unreachable" = 0,
    };

    // Walk all buckets and count entries
    var bucket_idx: u8 = 0;
    while (bucket_idx < 255) : (bucket_idx += 1) {
        const bucket = protocol_inst.routing_table.getBucket(bucket_idx);
        for (bucket) |entry| {
            if (entry.status != .connected) continue;
            stats.total += 1;
            // Entries in kbucket store [6]u8 addr: 4 bytes IP + 2 bytes port
            const ip = entry.addr[0..4];
            const is_zero_ip = std.mem.eql(u8, ip, &[_]u8{ 0, 0, 0, 0 });
            if (is_zero_ip) {
                stats.@"unreachable" += 1;
            } else {
                // In our current implementation, kbucket only stores IPv4
                stats.ip4_only += 1;
            }
        }
    }

    return stats;
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

    // ── Build local ENR ─────────────────────────────────────────────
    const enr_seq: u64 = 1;
    var enr_builder = EnrBuilder.init(allocator, secret_key, enr_seq);

    // IPv4 address
    const listen_ip4 = parseIp4(opts.listen_address) orelse [4]u8{ 0, 0, 0, 0 };
    if (opts.enr_ip) |ip_str| {
        enr_builder.ip = parseIp4(ip_str);
    } else if (opts.nat or !std.mem.eql(u8, &listen_ip4, &[_]u8{ 0, 0, 0, 0 })) {
        enr_builder.ip = listen_ip4;
    }

    // UDP port
    enr_builder.udp = if (opts.enr_udp) |p| p else opts.port;

    // IPv6 address
    if (opts.enr_ip6) |ip6_str| {
        enr_builder.ip6 = parseIp6(ip6_str);
    } else if (opts.listen_address6) |addr6| {
        enr_builder.ip6 = parseIp6(addr6);
    }

    // IPv6 UDP port
    if (opts.enr_udp6) |p| {
        enr_builder.udp6 = p;
    } else if (opts.port6) |p| {
        enr_builder.udp6 = p;
    }

    // Encode ENR
    const enr_str = try enr_builder.encodeToString();
    defer allocator.free(enr_str);

    // Save ENR to disk if persisting
    if (opts.persist_network_identity and bootnode_dir.len > 0) {
        saveEnrToDisk(io, allocator, bootnode_dir, enr_str) catch |err| {
            log.warn("Failed to save ENR: {}", .{err});
        };
    }

    // ── Log identity ────────────────────────────────────────────────
    log.info("  network:    {s}", .{opts.network});
    log.info("  nodeId:     0x{s}", .{&std.fmt.bytesToHex(node_id, .lower)});
    log.info("  bindAddr:   {s}:{d}", .{ opts.listen_address, opts.port });
    if (enr_builder.ip) |ip| {
        log.info("  enrAddr:    {d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], enr_builder.udp orelse opts.port });
    }
    if (opts.listen_address6) |addr6| {
        log.info("  bindAddr6:  [{s}]:{d}", .{ addr6, opts.port6 orelse opts.port });
    }
    log.info("  ENR:        {s}", .{enr_str});

    // ── Create discv5 protocol ──────────────────────────────────────
    var protocol_inst = try Protocol.init(allocator, .{
        .local_secret_key = secret_key,
        .local_node_id = node_id,
        .listen_addr = .{ .ip = listen_ip4, .port = opts.port },
    });
    defer protocol_inst.deinit();

    // ── Bind UDP transport ──────────────────────────────────────────
    var udp = try LinuxUdpTransport.init(listen_ip4, opts.port);
    defer udp.deinit();
    const udp_transport = udp.transport();

    log.info("UDP transport bound to {d}.{d}.{d}.{d}:{d}", .{
        listen_ip4[0], listen_ip4[1], listen_ip4[2], listen_ip4[3], opts.port,
    });

    // ── Seed routing table ──────────────────────────────────────────
    var total_seeded: usize = 0;

    // From --bootnodes CLI option
    if (opts.bootnodes) |bn_list| {
        const n = seedFromBootnodeList(allocator, &protocol_inst, bn_list);
        total_seeded += n;
        log.info("Seeded {d} bootnode(s) from --bootnodes", .{n});
    }

    // From --bootnodesFile
    if (opts.bootnodes_file) |bn_file| {
        const n = seedFromBootnodeFile(io, allocator, &protocol_inst, bn_file) catch |err| blk: {
            log.warn("Failed to read bootnodes file '{s}': {}", .{ bn_file, err });
            break :blk @as(usize, 0);
        };
        total_seeded += n;
        log.info("Seeded {d} bootnode(s) from --bootnodesFile", .{n});
    }

    log.info("Routing table: {d} peer(s) after seeding", .{protocol_inst.routing_table.nodeCount()});

    // ── Main loop: recv packets + periodic stats ────────────────────
    log.info("Bootnode running. Press Ctrl-C to stop.", .{});

    var recv_buf: [2048]u8 = undefined;
    var packets_processed: u64 = 0;

    // Stats timer — log every 10 seconds
    var stats_counter: u32 = 0;
    const stats_interval: u32 = 100; // ~100 recv timeouts at ~100ms each ≈ 10s

    while (!ShutdownHandler.shouldStop()) {
        // Non-blocking recv with timeout (100ms set via SO_RCVTIMEO)
        const result = udp_transport.recv(&recv_buf) catch |err| {
            switch (err) {
                error.WouldBlock => {},
                else => {
                    // On recv errors, sleep briefly and retry
                    io.sleep(.{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch break;
                },
            }
            stats_counter += 1;
            if (stats_counter >= stats_interval) {
                logStats(&protocol_inst, packets_processed);
                stats_counter = 0;
            }
            continue;
        };

        // Process received packet
        protocol_inst.handlePacket(result.data, result.from, udp_transport) catch |err| {
            log.debug("Packet handling error from {d}.{d}.{d}.{d}:{d}: {}", .{
                result.from.ip[0], result.from.ip[1], result.from.ip[2], result.from.ip[3],
                result.from.port, err,
            });
        };
        packets_processed += 1;

        // Periodic stats
        stats_counter += 1;
        if (stats_counter >= stats_interval) {
            logStats(&protocol_inst, packets_processed);
            stats_counter = 0;
        }
    }

    // ── Shutdown ────────────────────────────────────────────────────
    log.info("Shutting down bootnode...", .{});

    // Persist updated ENR on shutdown (sequence number may have changed)
    if (opts.persist_network_identity and bootnode_dir.len > 0) {
        saveEnrToDisk(io, allocator, bootnode_dir, enr_str) catch |err| {
            log.warn("Failed to persist ENR on shutdown: {}", .{err});
        };
    }

    log.info("Bootnode stopped. Processed {d} packets total.", .{packets_processed});
}

fn logStats(protocol_inst: *const Protocol, packets_processed: u64) void {
    const stats = countPeerStats(protocol_inst);
    log.info("peers: {d} total ({d} ip4, {d} ip6, {d} dual, {d} unreachable) | packets: {d}", .{
        stats.total,
        stats.ip4_only,
        stats.ip6_only,
        stats.dual_stack,
        stats.@"unreachable",
        packets_processed,
    });
}
