//! Discovery service: bridges discv5 peer discovery with the P2P layer.
//!
//! Provides:
//! - Local ENR construction and management (IP, ports, eth2 fork digest, attnets)
//! - Discv5 routing table seeding from bootnode ENRs
//! - Periodic random-node-ID lookups for diverse peer discovery
//! - Subnet-targeted queries for attestation subnet peers
//! - Fork digest filtering on discovered ENRs
//! - Discovered peer queue for the P2P layer to consume
//! - ENR updates on fork transitions (sequence number bumping)
//!
//! Reference: Lodestar packages/beacon-node/src/network/peers/discover.ts

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const discv5 = @import("discv5");
const Protocol = discv5.protocol.Protocol;
const ProtocolEvent = discv5.protocol.Event;
const Enr = discv5.enr.Enr;
const EnrBuilder = discv5.enr.Builder;
const NodeId = discv5.enr.NodeId;
const enr_mod = discv5.enr;
const UdpSocket = discv5.UdpSocket;
const bootnodes = @import("bootnodes.zig");
const BootnodeInfo = bootnodes.BootnodeInfo;

const log = std.log.scoped(.discovery);

// ── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_LOOKUP_INTERVAL_MS: u64 = 30_000;
const MAX_DISCOVERED_QUEUE: usize = 256;
const MAX_ENR_DECODE_BUF: usize = 512;
const FAR_FUTURE_EPOCH: u64 = 0xffffffffffffffff;
const LOOKUP_PARALLELISM: usize = 3;

// ── Configuration ───────────────────────────────────────────────────────────

pub const DiscoveryConfig = struct {
    listen_port: u16 = 9000,
    bootnode_enrs: []const BootnodeInfo = &bootnodes.mainnet,
    cli_bootnodes: []const []const u8 = &.{},
    target_peers: u32 = 50,
    lookup_interval_ms: u64 = DEFAULT_LOOKUP_INTERVAL_MS,
    secret_key: [32]u8 = [_]u8{0} ** 32,
    local_ip: [4]u8 = [_]u8{ 0, 0, 0, 0 },
    p2p_port: u16 = 9000,
    fork_digest: [4]u8 = [_]u8{0} ** 4,
    next_fork_version: [4]u8 = [_]u8{0} ** 4,
    next_fork_epoch: u64 = FAR_FUTURE_EPOCH,
    enabled: bool = true,
};

// ── Discovered Peer ─────────────────────────────────────────────────────────

pub const DiscoveredPeer = struct {
    node_id: [32]u8,
    ip: [4]u8,
    port: u16,
    pubkey: [33]u8,
    has_quic: bool,
    attnets: ?[8]u8,
    fork_digest: ?[4]u8,
    source: DiscoverySource,
};

pub const DiscoverySource = enum {
    random_lookup,
    subnet_query,
    bootnode,
    direct,
};

pub const SubnetQuery = struct {
    subnet_id: u6,
    min_peers: u32 = 1,
};

// ── Discovery Service ───────────────────────────────────────────────────────

/// ENR cache entry for subnet-targeted queries.
pub const CachedEnr = struct {
    node_id: [32]u8,
    ip: [4]u8,
    port: u16,
    attnets: [8]u8,
    fork_digest: [4]u8,
};

pub const DiscoveryService = struct {
    allocator: Allocator,
    io: Io,
    config: DiscoveryConfig,
    socket: UdpSocket,
    protocol: Protocol,
    local_enr: ?[]u8,
    enr_seq: u64,
    current_fork_digest: [4]u8,
    discovered_peers: std.ArrayListUnmanaged(DiscoveredPeer),
    pending_subnet_queries: std.ArrayListUnmanaged(SubnetQuery),
    /// ENR cache for subnet-targeted queries.
    /// Stores parsed ENR records indexed by node ID (hex string ownership).
    enr_cache: std.StringHashMap(CachedEnr),
    connected_peers: u32,
    total_lookups: u64,
    total_discovered: u64,
    total_filtered_out: u64,

    pub fn init(io: Io, allocator: Allocator, config: DiscoveryConfig) !DiscoveryService {
        var socket = try UdpSocket.bind(io, .{
            .bytes = config.local_ip,
            .port = config.listen_port,
        });
        errdefer socket.close();

        const listen_port = socket.address.port;
        const node_id = blk: {
            if (std.mem.eql(u8, &config.secret_key, &([_]u8{0} ** 32))) {
                break :blk [_]u8{0} ** 32;
            }
            const pk = discv5.secp256k1.pubkeyFromSecret(&config.secret_key) catch
                break :blk [_]u8{0} ** 32;
            break :blk enr_mod.nodeIdFromCompressedPubkey(&pk);
        };
        const local_enr = blk: {
            if (std.mem.eql(u8, &config.secret_key, &([_]u8{0} ** 32))) break :blk null;
            var builder = EnrBuilder.init(allocator, config.secret_key, 1);
            builder.ip = config.local_ip;
            builder.udp = listen_port;
            builder.tcp = config.p2p_port;
            builder.quic = config.p2p_port;
            builder.setEth2(config.fork_digest, config.next_fork_version, config.next_fork_epoch);
            builder.attnets = [_]u8{0} ** 8;
            builder.syncnets = [_]u8{0} ** 1;
            break :blk try builder.encode();
        };
        errdefer if (local_enr) |raw| allocator.free(raw);

        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .socket = socket,
            .protocol = try Protocol.init(io, allocator, .{
                .local_node_id = node_id,
                .local_secret_key = config.secret_key,
                .local_enr = local_enr,
                .local_enr_seq = 1,
            }),
            .local_enr = local_enr,
            .enr_seq = 1,
            .current_fork_digest = config.fork_digest,
            .discovered_peers = .empty,
            .pending_subnet_queries = .empty,
            .enr_cache = std.StringHashMap(CachedEnr).init(allocator),
            .connected_peers = 0,
            .total_lookups = 0,
            .total_discovered = 0,
            .total_filtered_out = 0,
        };
    }

    pub fn deinit(self: *DiscoveryService) void {
        self.discovered_peers.deinit(self.allocator);
        self.pending_subnet_queries.deinit(self.allocator);
        // Free ENR cache (keys are owned string copies).
        var iter = self.enr_cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.enr_cache.deinit();
        if (self.local_enr) |raw| self.allocator.free(raw);
        self.protocol.deinit();
        self.socket.close();
    }

    // ── ENR Management ──────────────────────────────────────────────────

    pub fn buildLocalEnr(self: *const DiscoveryService) ![]u8 {
        var builder = EnrBuilder.init(self.allocator, self.config.secret_key, self.enr_seq);
        builder.ip = self.config.local_ip;
        builder.udp = self.socket.address.port;
        builder.tcp = self.config.p2p_port;
        builder.quic = self.config.p2p_port;
        builder.setEth2(self.current_fork_digest, self.config.next_fork_version, self.config.next_fork_epoch);
        builder.attnets = [_]u8{0} ** 8;
        builder.syncnets = [_]u8{0} ** 1;
        return builder.encode();
    }

    pub fn buildLocalEnrString(self: *const DiscoveryService) ![]u8 {
        var builder = EnrBuilder.init(self.allocator, self.config.secret_key, self.enr_seq);
        builder.ip = self.config.local_ip;
        builder.udp = self.socket.address.port;
        builder.tcp = self.config.p2p_port;
        builder.quic = self.config.p2p_port;
        builder.setEth2(self.current_fork_digest, self.config.next_fork_version, self.config.next_fork_epoch);
        builder.attnets = [_]u8{0} ** 8;
        builder.syncnets = [_]u8{0} ** 1;
        return builder.encodeToString();
    }

    pub fn updateForkDigest(self: *DiscoveryService, fork_digest: [4]u8, next_fork_version: [4]u8, next_fork_epoch: u64) void {
        self.current_fork_digest = fork_digest;
        self.config.fork_digest = fork_digest;
        self.config.next_fork_version = next_fork_version;
        self.config.next_fork_epoch = next_fork_epoch;
        self.enr_seq += 1;
        if (!std.mem.eql(u8, &self.config.secret_key, &([_]u8{0} ** 32))) {
            var builder = EnrBuilder.init(self.allocator, self.config.secret_key, self.enr_seq);
            builder.ip = self.config.local_ip;
            builder.udp = self.socket.address.port;
            builder.tcp = self.config.p2p_port;
            builder.quic = self.config.p2p_port;
            builder.setEth2(fork_digest, next_fork_version, next_fork_epoch);
            builder.attnets = [_]u8{0} ** 8;
            builder.syncnets = [_]u8{0} ** 1;
            if (builder.encode()) |updated| {
                if (self.local_enr) |raw| self.allocator.free(raw);
                self.local_enr = updated;
                self.protocol.config.local_enr = updated;
                self.protocol.config.local_enr_seq = self.enr_seq;
            } else |_| {}
        }
        log.info("ENR updated: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} seq={d}", .{
            fork_digest[0], fork_digest[1], fork_digest[2], fork_digest[3], self.enr_seq,
        });
    }

    // ── Bootnode Seeding ────────────────────────────────────────────────

    pub fn seedBootnodes(self: *DiscoveryService) void {
        var seeded: u32 = 0;
        for (self.config.bootnode_enrs) |bn| {
            if (self.decodeAndInsertEnr(bn.enr)) seeded += 1;
        }
        for (self.config.cli_bootnodes) |enr_str| {
            if (self.decodeAndInsertEnr(enr_str)) seeded += 1;
        }
        log.info("Seeded routing table with {d} bootnodes ({d} known peers total)", .{
            seeded, self.knownPeerCount(),
        });
    }

    fn decodeAndInsertEnr(self: *DiscoveryService, enr_str: []const u8) bool {
        const enr_data = if (std.mem.startsWith(u8, enr_str, "enr:"))
            enr_str[4..]
        else
            enr_str;

        const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(enr_data) catch return false;
        if (decoded_len > MAX_ENR_DECODE_BUF) return false;

        var buf: [MAX_ENR_DECODE_BUF]u8 = undefined;
        std.base64.url_safe_no_pad.Decoder.decode(buf[0..decoded_len], enr_data) catch return false;

        var parsed = enr_mod.decode(self.allocator, buf[0..decoded_len]) catch return false;
        defer parsed.deinit();

        const pk = parsed.pubkey orelse return false;
        const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

        if (std.mem.eql(u8, &node_id, &self.protocol.config.local_node_id)) return false;

        const ip = parsed.ip orelse [4]u8{ 0, 0, 0, 0 };
        const port = parsed.udp orelse parsed.tcp orelse 0;

        self.protocol.addNode(node_id, &pk, .{ .bytes = ip, .port = port }, buf[0..decoded_len]);
        return true;
    }

    // ── Peer Discovery ──────────────────────────────────────────────────

    pub fn discoverPeers(self: *DiscoveryService) void {
        self.pollNetwork();
        if (!self.config.enabled) return;
        if (self.connected_peers >= self.config.target_peers) return;
        self.total_lookups += 1;
        self.randomLookup();
        self.processSubnetQueries();
        self.pollNetwork();
    }

    fn randomLookup(self: *DiscoveryService) void {
        var target: NodeId = undefined;
        self.protocol.rng.random().bytes(&target);
        var closest: [16]discv5.kbucket.Entry = undefined;
        const found = self.protocol.routing_table.findClosest(&target, 16, &closest);
        var requests_sent: usize = 0;
        for (closest[0..found]) |entry| {
            if (requests_sent >= LOOKUP_PARALLELISM) break;
            if (self.protocol.hasActiveFindNodeRequest(&entry.node_id)) continue;
            const peer = self.protocol.getKnownNode(&entry.node_id) orelse continue;

            var distances: [4]u16 = undefined;
            const distance_count = buildLookupDistances(&target, &peer.node_id, &distances);
            if (distance_count == 0) continue;

            _ = self.protocol.sendFindNode(
                &peer.node_id,
                &peer.pubkey,
                peer.addr,
                distances[0..distance_count],
                &self.socket,
            ) catch continue;
            requests_sent += 1;
        }
    }

    fn processSubnetQueries(self: *DiscoveryService) void {
        const queries = self.pending_subnet_queries.items;
        if (queries.len == 0) return;
        for (queries) |query| {
            self.findSubnetPeers(query.subnet_id, query.min_peers);
        }
        self.pending_subnet_queries.clearRetainingCapacity();
    }

    /// Find peers advertising a specific attestation subnet via ENR cache scan.
    ///
    /// Scans the ENR cache for nodes that advertise `subnet_id` in their attnets
    /// field. Advertises when a node has the corresponding bit set in the 8-byte
    /// attnets bitvector.
    ///
    /// If fewer than `min_peers` are found in cache, falls back to a random lookup
    /// to populate the cache with fresh candidates.
    fn findSubnetPeers(self: *DiscoveryService, subnet_id: u6, min_peers: u32) void {
        var found: u32 = 0;

        // Scan ENR cache for nodes with this subnet bit set.
        // attnets is an 8-byte bitvector; use the helper from enr_mod.
        var iter = self.enr_cache.iterator();
        while (iter.next()) |entry| {
            const cached = entry.value_ptr.*;
            // Only consider peers on our fork.
            if (!std.mem.eql(u8, &cached.fork_digest, &self.current_fork_digest)) continue;
            if (!enr_mod.isSubnetSet(cached.attnets, subnet_id)) continue;

            // This peer advertises our subnet — queue for dialing.
            self.evaluateCandidate(cached.node_id, blk: {
                var addr: [6]u8 = undefined;
                @memcpy(addr[0..4], &cached.ip);
                addr[4] = @intCast(cached.port >> 8);
                addr[5] = @intCast(cached.port & 0xff);
                break :blk addr;
            }, .subnet_query);
            found += 1;
            if (found >= min_peers) break;
        }

        if (found < min_peers) {
            log.debug("Subnet {d}: found {d}/{d} peers in cache, falling back to random lookup", .{
                subnet_id, found, min_peers,
            });
            // Do a random lookup to populate the cache with fresh candidates.
            self.randomLookup();
        } else {
            log.debug("Subnet {d}: found {d} candidate peer(s) in ENR cache", .{ subnet_id, found });
        }
    }

    /// Record an ENR in the cache for future subnet-targeted queries.
    ///
    /// Called when we receive an ENR response from a peer during discovery.
    /// The ENR is parsed for fork digest and attnets fields.
    pub fn recordEnr(self: *DiscoveryService, node_id: [32]u8, enr: *const Enr) void {
        // Only cache ENRs on our fork.
        const fd = enr.eth2_fork_digest orelse return;
        if (!std.mem.eql(u8, &fd, &self.current_fork_digest)) return;

        const attnets = enr.attnets orelse [_]u8{0} ** 8;
        const ip = enr.ip orelse return;
        const port = enr.quic orelse enr.udp orelse enr.tcp orelse return;

        // Generate a string key from node_id (hex).
        const key_hex = std.fmt.bytesToHex(node_id, .lower);
        const key = self.allocator.dupe(u8, &key_hex) catch return;

        const gop = self.enr_cache.getOrPut(key) catch {
            self.allocator.free(key);
            return;
        };
        if (gop.found_existing) {
            self.allocator.free(key);
        }
        gop.value_ptr.* = .{
            .node_id = node_id,
            .ip = ip,
            .port = port,
            .attnets = attnets,
            .fork_digest = fd,
        };
    }

    fn pollNetwork(self: *DiscoveryService) void {
        self.drainIncomingPackets();
        self.drainProtocolEvents();
    }

    fn drainIncomingPackets(self: *DiscoveryService) void {
        var recv_buf: [discv5.protocol.MAX_PACKET_SIZE]u8 = undefined;
        while (true) {
            const result = self.socket.receiveTimeout(&recv_buf, .{
                .duration = .{
                    .raw = Io.Duration.fromMilliseconds(1),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => return,
                else => return,
            };

            self.protocol.handlePacket(result.data, result.from, &self.socket) catch {};
        }
    }

    fn drainProtocolEvents(self: *DiscoveryService) void {
        while (self.protocol.popEvent()) |event| {
            var owned_event = event;
            defer owned_event.deinit(self.allocator);

            switch (owned_event) {
                .pong => {},
                .nodes => |nodes| {
                    for (nodes.enrs) |raw_enr| {
                        var parsed = enr_mod.decode(self.allocator, raw_enr) catch continue;
                        defer parsed.deinit();

                        const node_id = parsed.nodeId() orelse continue;
                        if (!self.filterEnr(&parsed)) continue;
                        self.recordEnr(node_id, &parsed);
                        self.evaluateEnrCandidate(node_id, &parsed, .random_lookup);
                    }
                },
            }
        }
    }

    fn evaluateCandidate(self: *DiscoveryService, node_id: NodeId, addr: [6]u8, source: DiscoverySource) void {
        if (std.mem.eql(u8, &node_id, &self.protocol.config.local_node_id)) return;
        const ip = [4]u8{ addr[0], addr[1], addr[2], addr[3] };
        const port = @as(u16, addr[4]) << 8 | @as(u16, addr[5]);
        if (std.mem.eql(u8, &ip, &[4]u8{ 0, 0, 0, 0 }) and port == 0) return;

        for (self.discovered_peers.items) |existing| {
            if (std.mem.eql(u8, &existing.node_id, &node_id)) return;
        }
        if (self.discovered_peers.items.len >= MAX_DISCOVERED_QUEUE) {
            self.total_filtered_out += 1;
            return;
        }

        self.discovered_peers.append(self.allocator, .{
            .node_id = node_id,
            .ip = ip,
            .port = port,
            .pubkey = [_]u8{0} ** 33,
            .has_quic = false,
            .attnets = null,
            .fork_digest = null,
            .source = source,
        }) catch return;
        self.total_discovered += 1;
    }

    fn evaluateEnrCandidate(self: *DiscoveryService, node_id: NodeId, enr: *const Enr, source: DiscoverySource) void {
        if (std.mem.eql(u8, &node_id, &self.protocol.config.local_node_id)) return;
        const ip = enr.ip orelse return;
        const port = enr.quic orelse enr.udp orelse enr.tcp orelse return;

        for (self.discovered_peers.items) |existing| {
            if (std.mem.eql(u8, &existing.node_id, &node_id)) return;
        }
        if (self.discovered_peers.items.len >= MAX_DISCOVERED_QUEUE) {
            self.total_filtered_out += 1;
            return;
        }

        self.discovered_peers.append(self.allocator, .{
            .node_id = node_id,
            .ip = ip,
            .port = port,
            .pubkey = enr.pubkey orelse [_]u8{0} ** 33,
            .has_quic = enr.quic != null,
            .attnets = enr.attnets,
            .fork_digest = enr.eth2_fork_digest,
            .source = source,
        }) catch return;
        self.total_discovered += 1;
    }

    pub fn filterEnr(self: *const DiscoveryService, enr: *const Enr) bool {
        if (enr.ip == null) return false;
        const has_port = (enr.quic != null) or (enr.udp != null) or (enr.tcp != null);
        if (!has_port) return false;
        if (enr.eth2_fork_digest) |fd| {
            if (!std.mem.eql(u8, &fd, &self.current_fork_digest)) return false;
        }
        return true;
    }

    // ── Subnet Queries ──────────────────────────────────────────────────

    pub fn requestSubnetPeers(self: *DiscoveryService, subnet_id: u6, min_peers: u32) void {
        self.pending_subnet_queries.append(self.allocator, .{
            .subnet_id = subnet_id,
            .min_peers = min_peers,
        }) catch {
            log.warn("Failed to queue subnet query for subnet {d}", .{subnet_id});
        };
    }

    // ── Peer Queue ──────────────────────────────────────────────────────

    pub fn drainDiscoveredPeers(self: *DiscoveryService) []DiscoveredPeer {
        return self.discovered_peers.toOwnedSlice(self.allocator) catch &.{};
    }

    pub fn hasDiscoveredPeers(self: *const DiscoveryService) bool {
        return self.discovered_peers.items.len > 0;
    }

    pub fn discoveredPeerCount(self: *const DiscoveryService) usize {
        return self.discovered_peers.items.len;
    }

    pub fn setConnectedPeers(self: *DiscoveryService, count: u32) void {
        self.connected_peers = count;
    }

    pub fn knownPeerCount(self: *const DiscoveryService) usize {
        return self.protocol.routing_table.nodeCount();
    }

    pub fn getStats(self: *const DiscoveryService) DiscoveryStats {
        return .{
            .known_peers = self.knownPeerCount(),
            .connected_peers = self.connected_peers,
            .total_lookups = self.total_lookups,
            .total_discovered = self.total_discovered,
            .total_filtered_out = self.total_filtered_out,
            .queued_peers = self.discovered_peers.items.len,
            .pending_subnet_queries = self.pending_subnet_queries.items.len,
            .enr_cache_size = self.enr_cache.count(),
            .enr_seq = self.enr_seq,
        };
    }
};

fn appendUniqueDistance(out: []u16, len: *usize, distance: u16) void {
    for (out[0..len.*]) |existing| {
        if (existing == distance) return;
    }
    out[len.*] = distance;
    len.* += 1;
}

fn buildLookupDistances(target: *const NodeId, peer_id: *const NodeId, out: []u16) usize {
    var len: usize = 0;
    appendUniqueDistance(out, &len, 0);

    const raw_distance = discv5.kbucket.logDistance(target, peer_id) orelse return len;
    const wire_distance: u16 = @as(u16, raw_distance) + 1;
    appendUniqueDistance(out, &len, wire_distance);
    if (wire_distance > 1) appendUniqueDistance(out, &len, wire_distance - 1);
    if (wire_distance < 256) appendUniqueDistance(out, &len, wire_distance + 1);
    return len;
}

pub const DiscoveryStats = struct {
    known_peers: usize,
    connected_peers: u32,
    total_lookups: u64,
    total_discovered: u64,
    total_filtered_out: u64,
    queued_peers: usize,
    pending_subnet_queries: usize,
    /// Number of ENRs cached for subnet-targeted queries.
    enr_cache_size: usize,
    enr_seq: u64,
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "DiscoveryService: init and deinit" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    try std.testing.expectEqual(@as(u32, 0), svc.connected_peers);
    try std.testing.expectEqual(@as(u64, 1), svc.enr_seq);
}

test "DiscoveryService: seedBootnodes runs without crash" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.seedBootnodes();
}

test "DiscoveryService: seedBootnodes with real key inserts peers" {
    const hex_mod = discv5.hex;
    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0, .secret_key = secret_key });
    defer svc.deinit();
    svc.seedBootnodes();
    try std.testing.expect(svc.knownPeerCount() > 0);
}

test "DiscoveryService: updateForkDigest bumps seq" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    try std.testing.expectEqual(@as(u64, 1), svc.enr_seq);
    svc.updateForkDigest([4]u8{ 0xAB, 0xCD, 0xEF, 0x01 }, [4]u8{ 0, 0, 0, 0 }, FAR_FUTURE_EPOCH);
    try std.testing.expectEqual(@as(u64, 2), svc.enr_seq);
    try std.testing.expectEqual([4]u8{ 0xAB, 0xCD, 0xEF, 0x01 }, svc.current_fork_digest);
}

test "DiscoveryService: discoverPeers respects target_peers" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0, .target_peers = 5 });
    defer svc.deinit();
    svc.connected_peers = 5;
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 0), svc.total_lookups);
    svc.connected_peers = 2;
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 1), svc.total_lookups);
}

test "DiscoveryService: discoverPeers disabled" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0, .enabled = false });
    defer svc.deinit();
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 0), svc.total_lookups);
}

test "DiscoveryService: drainDiscoveredPeers returns and clears queue" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.protocol.addNode([_]u8{0x11} ** 32, null, .{ .bytes = .{ 1, 2, 3, 4 }, .port = 9000 }, null);
    svc.protocol.addNode([_]u8{0x22} ** 32, null, .{ .bytes = .{ 5, 6, 7, 8 }, .port = 9001 }, null);
    svc.discoverPeers();
    const peers = svc.drainDiscoveredPeers();
    defer svc.allocator.free(peers);
    try std.testing.expect(!svc.hasDiscoveredPeers());
}

test "DiscoveryService: requestSubnetPeers queues a query" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.requestSubnetPeers(5, 2);
    try std.testing.expectEqual(@as(usize, 1), svc.pending_subnet_queries.items.len);
    try std.testing.expectEqual(@as(u6, 5), svc.pending_subnet_queries.items[0].subnet_id);
}

test "DiscoveryService: filterEnr accepts valid ENR" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{
        .listen_port = 0,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
    });
    defer svc.deinit();

    var enr_data = [_]u8{0} ** 4;
    var enr = Enr{
        .seq = 1,
        .pubkey = [_]u8{0x02} ** 33,
        .ip = [4]u8{ 1, 2, 3, 4 },
        .udp = 9000,
        .tcp = null,
        .ip6 = null,
        .udp6 = null,
        .quic = 9001,
        .quic6 = null,
        .eth2_fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
        .eth2_raw = null,
        .attnets = null,
        .syncnets = null,
        .raw = &enr_data,
        .alloc = std.testing.allocator,
    };
    try std.testing.expect(svc.filterEnr(&enr));

    enr.eth2_fork_digest = [4]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    try std.testing.expect(!svc.filterEnr(&enr));

    enr.eth2_fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 };
    enr.ip = null;
    try std.testing.expect(!svc.filterEnr(&enr));
}

test "DiscoveryService: buildLocalEnr produces valid ENR" {
    const hex_mod = discv5.hex;
    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{
        .secret_key = secret_key,
        .local_ip = [4]u8{ 127, 0, 0, 1 },
        .listen_port = 0,
        .p2p_port = 9000,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
    });
    defer svc.deinit();

    const enr_bytes = try svc.buildLocalEnr();
    defer svc.allocator.free(enr_bytes);

    var parsed = try enr_mod.decode(svc.allocator, enr_bytes);
    defer parsed.deinit();
    try std.testing.expect(parsed.pubkey != null);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parsed.ip.?);
    try std.testing.expectEqual(@as(?u16, svc.socket.address.port), parsed.udp);
    try std.testing.expect(parsed.eth2_fork_digest != null);
}

test "DiscoveryService: getStats returns valid state" {
    var svc = try DiscoveryService.init(std.Options.debug_io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    const stats = svc.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_lookups);
    try std.testing.expectEqual(@as(u32, 0), stats.connected_peers);
    try std.testing.expectEqual(@as(u64, 1), stats.enr_seq);
}

test "DiscoveredPeer struct layout" {
    const peer = DiscoveredPeer{
        .node_id = [_]u8{0xAA} ** 32,
        .ip = .{ 1, 2, 3, 4 },
        .port = 9000,
        .pubkey = [_]u8{0xBB} ** 33,
        .has_quic = true,
        .attnets = [_]u8{0xFF} ** 8,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
        .source = .random_lookup,
    };
    try std.testing.expectEqual(@as(u16, 9000), peer.port);
    try std.testing.expect(peer.has_quic);
}
