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
const Address = discv5.Address;
const BindAddresses = discv5.BindAddresses;
const Discv5Service = discv5.Service;
const Enr = discv5.enr.Enr;
const EnrBuilder = discv5.enr.Builder;
const NodeId = discv5.enr.NodeId;
const enr_mod = discv5.enr;
const bootnodes = @import("bootnodes.zig");
const subnet_service = @import("subnet_service.zig");
const SubnetKind = subnet_service.SubnetKind;
const custody = @import("custody.zig");

const log = std.log.scoped(.discovery);

// ── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_LOOKUP_INTERVAL_MS: u64 = 30_000;
const MAX_DISCOVERED_QUEUE: usize = 256;
const MAX_ENR_DECODE_BUF: usize = 512;
const FAR_FUTURE_EPOCH: u64 = 0xffffffffffffffff;
const LOOKUP_PARALLELISM: usize = 3;
const CustodyColumnsBitfield = std.StaticBitSet(@as(usize, custody.NUMBER_OF_COLUMNS));

// ── Configuration ───────────────────────────────────────────────────────────

pub const DiscoveryConfig = struct {
    listen_port: u16 = 9000,
    listen_port6: ?u16 = null,
    bootnodes: []const []const u8 = &.{},
    target_peers: u32 = 50,
    lookup_interval_ms: u64 = DEFAULT_LOOKUP_INTERVAL_MS,
    secret_key: [32]u8 = [_]u8{0} ** 32,
    local_ip: ?[4]u8 = null,
    local_ip6: ?[16]u8 = null,
    enr_ip: ?[4]u8 = null,
    enr_ip6: ?[16]u8 = null,
    enr_udp: ?u16 = null,
    enr_udp6: ?u16 = null,
    p2p_port: u16 = 9000,
    p2p_port6: ?u16 = null,
    custody_group_count: ?u64 = null,
    default_custody_group_count: u64 = custody.CUSTODY_REQUIREMENT,
    fork_digest: [4]u8 = [_]u8{0} ** 4,
    next_fork_version: [4]u8 = [_]u8{0} ** 4,
    next_fork_epoch: u64 = FAR_FUTURE_EPOCH,
    enabled: bool = true,
};

// ── Discovered Peer ─────────────────────────────────────────────────────────

pub const DiscoveredPeer = struct {
    node_id: [32]u8,
    addr_ip4: ?Address = null,
    addr_ip6: ?Address = null,
    pubkey: [33]u8,
    has_quic: bool,
    attnets: ?[8]u8,
    fork_digest: ?[4]u8,
    source: DiscoverySource,
};

pub const DiscoverySource = enum {
    random_lookup,
    subnet_query,
    custody_query,
    bootnode,
    direct,
};

pub const SubnetQuery = struct {
    kind: SubnetKind = .attestation,
    subnet_id: u6,
    min_peers: u32 = 1,
};

pub const CustodyQuery = struct {
    column_index: u64,
    min_peers: u32 = 1,
};

// ── Discovery Service ───────────────────────────────────────────────────────

/// ENR cache entry for subnet-targeted queries.
pub const CachedEnr = struct {
    node_id: [32]u8,
    addr_ip4: ?Address,
    addr_ip6: ?Address,
    pubkey: ?[33]u8,
    has_quic: bool,
    attnets: [8]u8,
    syncnets: [1]u8,
    custody_group_count: ?u64,
    custody_columns: CustodyColumnsBitfield,
    fork_digest: [4]u8,
};

pub const DiscoveryService = struct {
    allocator: Allocator,
    io: Io,
    config: DiscoveryConfig,
    service: Discv5Service,
    current_fork_digest: [4]u8,
    discovered_peers: std.ArrayListUnmanaged(DiscoveredPeer),
    pending_subnet_queries: std.ArrayListUnmanaged(SubnetQuery),
    pending_custody_queries: std.ArrayListUnmanaged(CustodyQuery),
    active_attestation_queries: std.AutoHashMap(u8, u32),
    active_sync_queries: std.AutoHashMap(u8, u32),
    active_custody_queries: std.AutoHashMap(u64, u32),
    lookup_sources: std.AutoHashMap(u32, DiscoverySource),
    /// ENR cache for subnet-targeted queries.
    /// Stores parsed ENR records indexed by node ID (hex string ownership).
    enr_cache: std.StringHashMap(CachedEnr),
    connected_peers: u32,
    generic_peers_to_discover: u32,
    total_lookups: u64,
    total_discovered: u64,
    total_filtered_out: u64,
    local_enr_changed: bool,

    pub fn init(io: Io, allocator: Allocator, config: DiscoveryConfig) !DiscoveryService {
        const node_id = blk: {
            if (std.mem.eql(u8, &config.secret_key, &([_]u8{0} ** 32))) {
                break :blk [_]u8{0} ** 32;
            }
            const pk = discv5.secp256k1.pubkeyFromSecret(&config.secret_key) catch
                break :blk [_]u8{0} ** 32;
            break :blk enr_mod.nodeIdFromCompressedPubkey(&pk);
        };

        var service = try Discv5Service.init(io, allocator, .{
            .bind_addresses = resolveBindAddresses(&config),
            .protocol_config = .{
                .local_node_id = node_id,
                .local_secret_key = config.secret_key,
            },
            .lookup_parallelism = LOOKUP_PARALLELISM,
        });
        errdefer service.deinit();

        const local_enr = blk: {
            if (std.mem.eql(u8, &config.secret_key, &([_]u8{0} ** 32))) break :blk null;
            var builder = EnrBuilder.init(allocator, config.secret_key, 1);
            if (advertisedIp4(&config, &service)) |ip4| {
                builder.ip = ip4;
                builder.udp = config.enr_udp orelse service.boundPort(.ip4) orelse return error.MissingBindAddress;
                builder.tcp = config.p2p_port;
                builder.quic = config.p2p_port;
            }
            if (advertisedIp6(&config, &service)) |ip6| {
                builder.ip6 = ip6;
                builder.udp6 = config.enr_udp6 orelse service.boundPort(.ip6) orelse return error.MissingBindAddress;
                builder.tcp6 = config.p2p_port6 orelse config.p2p_port;
                builder.quic6 = config.p2p_port6 orelse config.p2p_port;
            }
            builder.setEth2(config.fork_digest, config.next_fork_version, config.next_fork_epoch);
            builder.attnets = [_]u8{0} ** 8;
            builder.syncnets = [_]u8{0} ** 1;
            builder.custody_group_count = config.custody_group_count;
            break :blk try builder.encode();
        };
        errdefer if (local_enr) |raw| allocator.free(raw);
        if (local_enr) |raw| {
            service.setLocalEnr(raw) catch |err| switch (err) {
                error.StaleEnrSeq => {},
                else => return err,
            };
            allocator.free(raw);
        }
        service.config.enr_update = advertisedIp4(&config, &service) == null and advertisedIp6(&config, &service) == null;

        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .service = service,
            .current_fork_digest = config.fork_digest,
            .discovered_peers = .empty,
            .pending_subnet_queries = .empty,
            .pending_custody_queries = .empty,
            .active_attestation_queries = std.AutoHashMap(u8, u32).init(allocator),
            .active_sync_queries = std.AutoHashMap(u8, u32).init(allocator),
            .active_custody_queries = std.AutoHashMap(u64, u32).init(allocator),
            .lookup_sources = std.AutoHashMap(u32, DiscoverySource).init(allocator),
            .enr_cache = std.StringHashMap(CachedEnr).init(allocator),
            .connected_peers = 0,
            .generic_peers_to_discover = 0,
            .total_lookups = 0,
            .total_discovered = 0,
            .total_filtered_out = 0,
            .local_enr_changed = false,
        };
    }

    pub fn deinit(self: *DiscoveryService) void {
        self.discovered_peers.deinit(self.allocator);
        self.pending_subnet_queries.deinit(self.allocator);
        self.pending_custody_queries.deinit(self.allocator);
        self.active_attestation_queries.deinit();
        self.active_sync_queries.deinit();
        self.active_custody_queries.deinit();
        self.lookup_sources.deinit();
        // Free ENR cache (keys are owned string copies).
        var iter = self.enr_cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.enr_cache.deinit();
        self.service.deinit();
    }

    // ── ENR Management ──────────────────────────────────────────────────

    pub fn buildLocalEnr(self: *const DiscoveryService) ![]u8 {
        return (try self.service.dupeLocalEnr(self.allocator)) orelse error.NoLocalEnr;
    }

    pub fn buildLocalEnrString(self: *const DiscoveryService) ![]u8 {
        const local_enr = self.service.localEnr() orelse return error.NoLocalEnr;
        const b64_len = std.base64.url_safe_no_pad.Encoder.calcSize(local_enr.len);
        const result = try self.allocator.alloc(u8, 4 + b64_len);
        @memcpy(result[0..4], "enr:");
        _ = std.base64.url_safe_no_pad.Encoder.encode(result[4..], local_enr);
        return result;
    }

    pub fn updateForkDigest(self: *DiscoveryService, fork_digest: [4]u8, next_fork_version: [4]u8, next_fork_epoch: u64) void {
        self.current_fork_digest = fork_digest;
        self.config.fork_digest = fork_digest;
        self.config.next_fork_version = next_fork_version;
        self.config.next_fork_epoch = next_fork_epoch;
        if (!std.mem.eql(u8, &self.config.secret_key, &([_]u8{0} ** 32))) {
            self.rebuildLocalEnrWithForkDigest() catch {};
        }
        log.debug("ENR updated: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} seq={d}", .{
            fork_digest[0], fork_digest[1], fork_digest[2], fork_digest[3], self.service.localEnrSeq(),
        });
    }

    // ── Bootnode Seeding ────────────────────────────────────────────────

    pub fn seedBootnodes(self: *DiscoveryService) void {
        var seeded: u32 = 0;
        for (self.config.bootnodes) |enr_str| {
            if (self.decodeAndInsertEnr(enr_str)) seeded += 1;
        }
        log.info("seeded routing table with {d} bootnodes ({d} known peers total)", .{
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

        if (std.mem.eql(u8, &node_id, &self.service.protocol.config.local_node_id)) return false;
        return self.service.addEnr(buf[0..decoded_len]);
    }

    // ── Peer Discovery ──────────────────────────────────────────────────

    pub fn discoverPeers(self: *DiscoveryService) void {
        self.pollNetwork();
        if (!self.config.enabled) return;

        if (self.generic_peers_to_discover == 0 and self.connected_peers < self.config.target_peers) {
            self.generic_peers_to_discover = self.config.target_peers - self.connected_peers;
        }

        self.refreshActiveQueries();
        self.queueCachedCandidates();
        if (self.hasOutstandingRequests()) {
            self.startRandomLookup(.random_lookup);
        }
        self.pollNetwork();
    }

    /// Request a generic discovery lookup even if we are already at the target
    /// peer count. Used when peer-quality or custody coverage demand more
    /// candidates rather than just a higher raw peer count.
    pub fn requestMorePeers(self: *DiscoveryService, count: u32) void {
        if (count == 0) return;
        self.generic_peers_to_discover = @max(self.generic_peers_to_discover, count);
    }

    fn startRandomLookup(self: *DiscoveryService, source: DiscoverySource) void {
        const lookup_id = self.service.startRandomLookup() catch return;
        self.total_lookups += 1;
        self.lookup_sources.put(lookup_id, source) catch {};
    }

    fn refreshActiveQueries(self: *DiscoveryService) void {
        self.active_attestation_queries.clearRetainingCapacity();
        self.active_sync_queries.clearRetainingCapacity();
        self.active_custody_queries.clearRetainingCapacity();

        const subnet_queries = self.pending_subnet_queries.items;
        for (subnet_queries) |query| {
            const map = switch (query.kind) {
                .attestation => &self.active_attestation_queries,
                .sync_committee => &self.active_sync_queries,
            };
            const result = map.getOrPut(@intCast(query.subnet_id)) catch continue;
            if (!result.found_existing or result.value_ptr.* < query.min_peers) {
                result.value_ptr.* = query.min_peers;
            }
        }
        self.pending_subnet_queries.clearRetainingCapacity();

        const custody_queries = self.pending_custody_queries.items;
        for (custody_queries) |query| {
            const result = self.active_custody_queries.getOrPut(query.column_index) catch continue;
            if (!result.found_existing or result.value_ptr.* < query.min_peers) {
                result.value_ptr.* = query.min_peers;
            }
        }
        self.pending_custody_queries.clearRetainingCapacity();
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
        const syncnets = enr.syncnets orelse [_]u8{0} ** 1;
        const addr_ip4 = addressFromEnr(enr, .ip4);
        const addr_ip6 = addressFromEnr(enr, .ip6);
        if (addr_ip4 == null and addr_ip6 == null) return;

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
        const effective_custody_group_count = enr.custody_group_count orelse self.config.default_custody_group_count;
        gop.value_ptr.* = .{
            .node_id = node_id,
            .addr_ip4 = addr_ip4,
            .addr_ip6 = addr_ip6,
            .pubkey = enr.pubkey,
            .has_quic = enr.quic != null or enr.quic6 != null,
            .attnets = attnets,
            .syncnets = syncnets,
            .custody_group_count = effective_custody_group_count,
            .custody_columns = deriveCustodyColumnsBitfield(self.allocator, node_id, effective_custody_group_count),
            .fork_digest = fd,
        };
    }

    pub fn poll(self: *DiscoveryService) void {
        self.pollNetwork();
    }

    fn pollNetwork(self: *DiscoveryService) void {
        self.service.poll();
        self.drainServiceEvents();
    }

    fn drainServiceEvents(self: *DiscoveryService) void {
        while (self.service.popEvent()) |event| {
            var owned_event = event;
            defer owned_event.deinit(self.allocator);

            switch (owned_event) {
                .pong => {},
                .nodes => {},
                .discovered_enr => |discovered| {
                    var parsed = enr_mod.decode(self.allocator, discovered.enr) catch continue;
                    defer parsed.deinit();

                    if (!self.filterEnr(&parsed)) continue;
                    self.recordEnr(discovered.node_id, &parsed);
                    const queued_source = self.sourceForDiscoveredNode(discovered.node_id, self.sourceForLookup(discovered.lookup_id)) orelse continue;
                    _ = self.evaluateEnrCandidate(discovered.node_id, &parsed, queued_source);
                },
                .lookup_finished => |lookup_finished| {
                    _ = self.lookup_sources.remove(lookup_finished.lookup_id);
                },
                .talkreq => {},
                .talkresp => {},
                .local_enr_updated => {
                    self.local_enr_changed = true;
                },
                .peer_connected => {},
                .peer_disconnected => {},
                .request_timeout => {},
            }
        }
    }

    fn evaluateCandidate(
        self: *DiscoveryService,
        node_id: NodeId,
        addr_ip4: ?Address,
        addr_ip6: ?Address,
        pubkey: ?[33]u8,
        has_quic: bool,
        attnets: ?[8]u8,
        fork_digest: ?[4]u8,
        source: DiscoverySource,
    ) bool {
        if (std.mem.eql(u8, &node_id, &self.service.protocol.config.local_node_id)) return false;
        if (addr_ip4 == null and addr_ip6 == null) return false;

        for (self.discovered_peers.items) |*existing| {
            if (!std.mem.eql(u8, &existing.node_id, &node_id)) continue;
            if (existing.addr_ip4 == null) existing.addr_ip4 = addr_ip4;
            if (existing.addr_ip6 == null) existing.addr_ip6 = addr_ip6;
            if (pubkey) |key| existing.pubkey = key;
            if (attnets) |bits| existing.attnets = bits;
            if (fork_digest) |fd| existing.fork_digest = fd;
            existing.has_quic = existing.has_quic or has_quic;
            existing.source = source;
            return false;
        }
        if (self.discovered_peers.items.len >= MAX_DISCOVERED_QUEUE) {
            self.total_filtered_out += 1;
            return false;
        }

        self.discovered_peers.append(self.allocator, .{
            .node_id = node_id,
            .addr_ip4 = addr_ip4,
            .addr_ip6 = addr_ip6,
            .pubkey = pubkey orelse [_]u8{0} ** 33,
            .has_quic = has_quic,
            .attnets = attnets,
            .fork_digest = fork_digest,
            .source = source,
        }) catch return false;
        self.total_discovered += 1;
        return true;
    }

    fn evaluateEnrCandidate(self: *DiscoveryService, node_id: NodeId, enr: *const Enr, source: DiscoverySource) bool {
        return self.evaluateCandidate(
            node_id,
            addressFromEnr(enr, .ip4),
            addressFromEnr(enr, .ip6),
            enr.pubkey,
            enr.quic != null or enr.quic6 != null,
            enr.attnets,
            enr.eth2_fork_digest,
            source,
        );
    }

    pub fn filterEnr(self: *const DiscoveryService, enr: *const Enr) bool {
        if (addressFromEnr(enr, .ip4) == null and addressFromEnr(enr, .ip6) == null) return false;
        if (enr.eth2_fork_digest) |fd| {
            if (!std.mem.eql(u8, &fd, &self.current_fork_digest)) return false;
        }
        return true;
    }

    // ── Subnet Queries ──────────────────────────────────────────────────

    pub fn requestSubnetPeers(self: *DiscoveryService, kind: SubnetKind, subnet_id: u6, min_peers: u32) void {
        self.pending_subnet_queries.append(self.allocator, .{
            .kind = kind,
            .subnet_id = subnet_id,
            .min_peers = min_peers,
        }) catch {
            log.debug("failed to queue {s} subnet query for subnet {d}", .{ @tagName(kind), subnet_id });
        };
    }

    pub fn requestCustodyColumnPeers(self: *DiscoveryService, column_index: u64, min_peers: u32) void {
        self.pending_custody_queries.append(self.allocator, .{
            .column_index = column_index,
            .min_peers = min_peers,
        }) catch {
            log.debug("failed to queue custody query for column {d}", .{column_index});
        };
    }

    // ── Peer Queue ──────────────────────────────────────────────────────

    pub fn takeDiscoveredPeers(self: *DiscoveryService, max_count: usize) []DiscoveredPeer {
        if (max_count == 0 or self.discovered_peers.items.len == 0) return &.{};

        const take_count = @min(max_count, self.discovered_peers.items.len);
        var peers = self.allocator.alloc(DiscoveredPeer, take_count) catch return &.{};

        var taken: usize = 0;
        while (taken < take_count) : (taken += 1) {
            const best_index = self.bestDiscoveredPeerIndex();
            peers[taken] = self.discovered_peers.orderedRemove(best_index);
        }

        return peers;
    }

    pub fn drainDiscoveredPeers(self: *DiscoveryService) []DiscoveredPeer {
        return self.takeDiscoveredPeers(self.discovered_peers.items.len);
    }

    pub fn hasDiscoveredPeers(self: *const DiscoveryService) bool {
        return self.discovered_peers.items.len > 0;
    }

    pub fn discoveredPeerCount(self: *const DiscoveryService) usize {
        return self.discovered_peers.items.len;
    }

    pub fn takeLocalEnrChanged(self: *DiscoveryService) bool {
        const changed = self.local_enr_changed;
        self.local_enr_changed = false;
        return changed;
    }

    pub fn setConnectedPeers(self: *DiscoveryService, count: u32) void {
        self.connected_peers = count;
    }

    pub fn knownPeerCount(self: *const DiscoveryService) usize {
        return self.service.knownPeerCount();
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
            .enr_seq = self.service.localEnrSeq(),
        };
    }

    fn bestDiscoveredPeerIndex(self: *const DiscoveryService) usize {
        std.debug.assert(self.discovered_peers.items.len > 0);

        var best_index: usize = 0;
        var best_priority = discoverySourcePriority(self.discovered_peers.items[0].source);
        for (self.discovered_peers.items[1..], 1..) |peer, index| {
            const priority = discoverySourcePriority(peer.source);
            if (priority < best_priority) {
                best_index = index;
                best_priority = priority;
            }
        }
        return best_index;
    }

    fn rebuildLocalEnrWithForkDigest(self: *DiscoveryService) !void {
        const next_seq = self.service.localEnrSeq() + 1;
        var builder = EnrBuilder.init(self.allocator, self.config.secret_key, next_seq);
        builder.tcp = self.config.p2p_port;
        builder.quic = self.config.p2p_port;
        builder.setEth2(self.current_fork_digest, self.config.next_fork_version, self.config.next_fork_epoch);
        builder.attnets = [_]u8{0} ** 8;
        builder.syncnets = [_]u8{0} ** 1;
        builder.custody_group_count = self.config.custody_group_count;

        if (self.service.localEnr()) |local_enr| {
            var parsed = try enr_mod.decode(self.allocator, local_enr);
            defer parsed.deinit();

            builder.ip = parsed.ip;
            builder.udp = parsed.udp;
            builder.tcp = parsed.tcp orelse self.config.p2p_port;
            builder.quic = parsed.quic orelse self.config.p2p_port;
            builder.ip6 = parsed.ip6;
            builder.udp6 = parsed.udp6;
            builder.tcp6 = parsed.tcp6;
            builder.quic6 = parsed.quic6;
            builder.attnets = parsed.attnets orelse builder.attnets.?;
            builder.syncnets = parsed.syncnets orelse builder.syncnets.?;
            builder.custody_group_count = parsed.custody_group_count orelse builder.custody_group_count;
        } else {
            if (advertisedIp4(&self.config, &self.service)) |ip4| {
                builder.ip = ip4;
                builder.udp = self.config.enr_udp orelse self.service.boundPort(.ip4) orelse return error.MissingBindAddress;
            }
            if (advertisedIp6(&self.config, &self.service)) |ip6| {
                builder.ip6 = ip6;
                builder.udp6 = self.config.enr_udp6 orelse self.service.boundPort(.ip6) orelse return error.MissingBindAddress;
                builder.tcp6 = self.config.p2p_port6 orelse self.config.p2p_port;
                builder.quic6 = self.config.p2p_port6 orelse self.config.p2p_port;
            }
        }

        const updated = try builder.encode();
        errdefer self.allocator.free(updated);
        try self.service.setLocalEnr(updated);
        self.allocator.free(updated);
    }

    pub fn updateSubnets(self: *DiscoveryService, attnets: [8]u8, syncnets: [1]u8) !void {
        const local_enr = self.service.localEnr() orelse return error.NoLocalEnr;

        var parsed = try enr_mod.decode(self.allocator, local_enr);
        defer parsed.deinit();

        if (std.mem.eql(u8, &(parsed.attnets orelse [_]u8{0} ** 8), &attnets) and
            std.mem.eql(u8, &(parsed.syncnets orelse [_]u8{0} ** 1), &syncnets))
        {
            return;
        }

        const next_seq = self.service.localEnrSeq() + 1;
        var builder = EnrBuilder.init(self.allocator, self.config.secret_key, next_seq);
        builder.ip = parsed.ip;
        builder.udp = parsed.udp;
        builder.tcp = parsed.tcp orelse self.config.p2p_port;
        builder.quic = parsed.quic orelse self.config.p2p_port;
        builder.ip6 = parsed.ip6;
        builder.udp6 = parsed.udp6;
        builder.tcp6 = parsed.tcp6;
        builder.quic6 = parsed.quic6;
        builder.attnets = attnets;
        builder.syncnets = syncnets;
        builder.custody_group_count = parsed.custody_group_count;
        builder.setEth2(self.current_fork_digest, self.config.next_fork_version, self.config.next_fork_epoch);

        const updated = try builder.encode();
        defer self.allocator.free(updated);
        try self.service.setLocalEnr(updated);
    }

    fn sourceForLookup(self: *const DiscoveryService, lookup_id: ?u32) DiscoverySource {
        const id = lookup_id orelse return .direct;
        return self.lookup_sources.get(id) orelse .direct;
    }

    fn queueCachedCandidates(self: *DiscoveryService) void {
        var iter = self.enr_cache.iterator();
        while (iter.next()) |entry| {
            self.maybeQueueCachedEnr(entry.value_ptr);
        }
    }

    fn maybeQueueCachedEnr(self: *DiscoveryService, cached: *const CachedEnr) void {
        const queued_source = self.sourceForCachedEnr(cached, null) orelse return;
        const queued = self.evaluateCandidate(
            cached.node_id,
            cached.addr_ip4,
            cached.addr_ip6,
            cached.pubkey,
            cached.has_quic,
            cached.attnets,
            cached.fork_digest,
            queued_source,
        );
        if (!queued) return;

        if (self.generic_peers_to_discover > 0) self.generic_peers_to_discover -= 1;
        self.consumeMatchingSubnetQueries(cached);
        self.consumeMatchingCustodyQueries(cached);
    }

    fn sourceForCachedEnr(self: *const DiscoveryService, cached: *const CachedEnr, fallback: ?DiscoverySource) ?DiscoverySource {
        if (!std.mem.eql(u8, &cached.fork_digest, &self.current_fork_digest)) return null;
        if (self.cachedMatchesCustodyQueries(cached)) return .custody_query;
        if (self.cachedMatchesSubnetQueries(cached)) return .subnet_query;
        if (self.generic_peers_to_discover > 0) return fallback orelse .random_lookup;
        return null;
    }

    fn sourceForDiscoveredNode(self: *const DiscoveryService, node_id: NodeId, fallback: DiscoverySource) ?DiscoverySource {
        const key_hex = std.fmt.bytesToHex(node_id, .lower);
        const cached = self.enr_cache.get(key_hex[0..]) orelse return if (self.generic_peers_to_discover > 0) fallback else null;
        return self.sourceForCachedEnr(&cached, fallback);
    }

    fn cachedMatchesSubnetQueries(self: *const DiscoveryService, cached: *const CachedEnr) bool {
        var att_iter = self.active_attestation_queries.iterator();
        while (att_iter.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            if (enr_mod.isSubnetSet(cached.attnets, @intCast(entry.key_ptr.*))) return true;
        }

        var sync_iter = self.active_sync_queries.iterator();
        while (sync_iter.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            if (syncSubnetSet(cached.syncnets, @intCast(entry.key_ptr.*))) return true;
        }

        return false;
    }

    fn cachedMatchesCustodyQueries(self: *const DiscoveryService, cached: *const CachedEnr) bool {
        var iter = self.active_custody_queries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            const column_index = entry.key_ptr.*;
            if (column_index >= custody.NUMBER_OF_COLUMNS) continue;
            if (cached.custody_columns.isSet(@intCast(column_index))) return true;
        }
        return false;
    }

    fn consumeMatchingSubnetQueries(self: *DiscoveryService, cached: *const CachedEnr) void {
        var att_iter = self.active_attestation_queries.iterator();
        while (att_iter.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            if (enr_mod.isSubnetSet(cached.attnets, @intCast(entry.key_ptr.*))) {
                entry.value_ptr.* -|= 1;
            }
        }

        var sync_iter = self.active_sync_queries.iterator();
        while (sync_iter.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            if (syncSubnetSet(cached.syncnets, @intCast(entry.key_ptr.*))) {
                entry.value_ptr.* -|= 1;
            }
        }
    }

    fn consumeMatchingCustodyQueries(self: *DiscoveryService, cached: *const CachedEnr) void {
        var iter = self.active_custody_queries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            const column_index = entry.key_ptr.*;
            if (column_index >= custody.NUMBER_OF_COLUMNS) continue;
            if (cached.custody_columns.isSet(@intCast(column_index))) {
                entry.value_ptr.* -|= 1;
            }
        }
    }

    fn hasOutstandingRequests(self: *const DiscoveryService) bool {
        if (self.generic_peers_to_discover > 0) return true;

        var att_iter = self.active_attestation_queries.valueIterator();
        while (att_iter.next()) |count| {
            if (count.* > 0) return true;
        }

        var sync_iter = self.active_sync_queries.valueIterator();
        while (sync_iter.next()) |count| {
            if (count.* > 0) return true;
        }

        var custody_iter = self.active_custody_queries.valueIterator();
        while (custody_iter.next()) |count| {
            if (count.* > 0) return true;
        }

        return false;
    }
};

fn deriveCustodyColumnsBitfield(allocator: Allocator, node_id: NodeId, custody_group_count: u64) CustodyColumnsBitfield {
    var bitfield = CustodyColumnsBitfield.initEmpty();
    if (custody_group_count == 0) return bitfield;

    const custody_columns = custody.getCustodyColumns(allocator, node_id, custody_group_count) catch return bitfield;
    defer allocator.free(custody_columns);

    for (custody_columns) |column_index| {
        if (column_index < custody.NUMBER_OF_COLUMNS) {
            bitfield.set(@intCast(column_index));
        }
    }
    return bitfield;
}

fn resolveBindAddresses(config: *const DiscoveryConfig) BindAddresses {
    const wants_ip6 = config.local_ip6 != null or config.listen_port6 != null or config.enr_ip6 != null or config.enr_udp6 != null or config.p2p_port6 != null;
    const wants_ip4 = config.local_ip != null or config.enr_ip != null or config.enr_udp != null or !wants_ip6;

    var bind_addresses = BindAddresses{};
    if (wants_ip4) {
        bind_addresses.ip4 = .{
            .ip4 = .{
                .bytes = config.local_ip orelse [_]u8{ 0, 0, 0, 0 },
                .port = config.listen_port,
            },
        };
    }
    if (wants_ip6) {
        bind_addresses.ip6 = .{
            .ip6 = .{
                .bytes = config.local_ip6 orelse ([_]u8{0} ** 16),
                .port = config.listen_port6 orelse config.listen_port,
            },
        };
    }
    return bind_addresses;
}

fn advertisedIp4(config: *const DiscoveryConfig, service: *const Discv5Service) ?[4]u8 {
    if (config.enr_ip) |ip4| return ip4;
    const bind_addr = service.boundAddress(.ip4) orelse return null;
    return switch (bind_addr) {
        .ip4 => |ip4| if (std.mem.eql(u8, &ip4.bytes, &[_]u8{ 0, 0, 0, 0 })) null else ip4.bytes,
        .ip6 => null,
    };
}

fn advertisedIp6(config: *const DiscoveryConfig, service: *const Discv5Service) ?[16]u8 {
    if (config.enr_ip6) |ip6| return ip6;
    const bind_addr = service.boundAddress(.ip6) orelse return null;
    return switch (bind_addr) {
        .ip4 => null,
        .ip6 => |ip6| if (std.mem.eql(u8, &ip6.bytes, &([_]u8{0} ** 16))) null else ip6.bytes,
    };
}

fn addressFromEnr(enr: *const Enr, family: Address.Family) ?Address {
    return switch (family) {
        .ip4 => if (enr.ip) |ip4|
            if (enr.quic orelse enr.udp orelse enr.tcp) |port|
                Address{ .ip4 = .{ .bytes = ip4, .port = port } }
            else
                null
        else
            null,
        .ip6 => if (enr.ip6) |ip6|
            if (enr.quic6 orelse enr.udp6 orelse enr.tcp6) |port|
                Address{ .ip6 = .{ .bytes = ip6, .port = port } }
            else
                null
        else
            null,
    };
}

fn syncSubnetSet(syncnets: [1]u8, subnet_id: u6) bool {
    return (syncnets[0] & (@as(u8, 1) << @intCast(subnet_id))) != 0;
}

fn discoverySourcePriority(source: DiscoverySource) u8 {
    return switch (source) {
        .direct, .bootnode => 0,
        .custody_query => 1,
        .subnet_query => 2,
        .random_lookup => 3,
    };
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
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    try std.testing.expectEqual(@as(u32, 0), svc.connected_peers);
    try std.testing.expectEqual(@as(u64, 0), svc.service.localEnrSeq());
}

test "DiscoveryService: seedBootnodes runs without crash" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.seedBootnodes();
}

test "DiscoveryService: seedBootnodes with real key inserts peers" {
    const hex_mod = discv5.hex;
    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
        .listen_port = 0,
        .secret_key = secret_key,
        .bootnodes = &.{bootnodes.mainnet[0].enr},
    });
    defer svc.deinit();
    svc.seedBootnodes();
    try std.testing.expect(svc.knownPeerCount() > 0);
}

test "DiscoveryService: updateForkDigest bumps seq" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    try std.testing.expectEqual(@as(u64, 0), svc.service.localEnrSeq());
    svc.updateForkDigest([4]u8{ 0xAB, 0xCD, 0xEF, 0x01 }, [4]u8{ 0, 0, 0, 0 }, FAR_FUTURE_EPOCH);
    try std.testing.expectEqual(@as(u64, 0), svc.service.localEnrSeq());
    try std.testing.expectEqual([4]u8{ 0xAB, 0xCD, 0xEF, 0x01 }, svc.current_fork_digest);
}

test "DiscoveryService: discoverPeers respects target_peers" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0, .target_peers = 5 });
    defer svc.deinit();
    svc.connected_peers = 5;
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 0), svc.total_lookups);
    svc.connected_peers = 2;
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 1), svc.total_lookups);
}

test "DiscoveryService: requestMorePeers forces lookup at target" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0, .target_peers = 5 });
    defer svc.deinit();

    svc.connected_peers = 5;
    svc.requestMorePeers(3);
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 1), svc.total_lookups);
}

test "DiscoveryService: subnet query still runs at target peer count" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0, .target_peers = 5 });
    defer svc.deinit();

    svc.connected_peers = 5;
    svc.requestSubnetPeers(.attestation, 5, 1);
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 1), svc.total_lookups);
}

test "DiscoveryService: discoverPeers disabled" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0, .enabled = false });
    defer svc.deinit();
    svc.discoverPeers();
    try std.testing.expectEqual(@as(u64, 0), svc.total_lookups);
}

test "DiscoveryService: drainDiscoveredPeers returns and clears queue" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.service.addNode([_]u8{0x11} ** 32, null, .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 9000 } }, null);
    svc.service.addNode([_]u8{0x22} ** 32, null, .{ .ip4 = .{ .bytes = .{ 5, 6, 7, 8 }, .port = 9001 } }, null);
    svc.discoverPeers();
    const peers = svc.drainDiscoveredPeers();
    defer if (peers.len > 0) svc.allocator.free(peers);
    try std.testing.expect(!svc.hasDiscoveredPeers());
}

test "DiscoveryService: requestSubnetPeers queues a query" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.requestSubnetPeers(.attestation, 5, 2);
    try std.testing.expectEqual(@as(usize, 1), svc.pending_subnet_queries.items.len);
    try std.testing.expectEqual(.attestation, svc.pending_subnet_queries.items[0].kind);
    try std.testing.expectEqual(@as(u6, 5), svc.pending_subnet_queries.items[0].subnet_id);
}

test "DiscoveryService: requestCustodyColumnPeers queues a query" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    svc.requestCustodyColumnPeers(7, 2);
    try std.testing.expectEqual(@as(usize, 1), svc.pending_custody_queries.items.len);
    try std.testing.expectEqual(@as(u64, 7), svc.pending_custody_queries.items[0].column_index);
    try std.testing.expectEqual(@as(u32, 2), svc.pending_custody_queries.items[0].min_peers);
}

test "DiscoveryService: custody query queues matching cached peer" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
        .listen_port = 0,
        .target_peers = 5,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
    });
    defer svc.deinit();

    const node_id = [_]u8{0x11} ** 32;
    const custody_columns = try custody.getCustodyColumns(std.testing.allocator, node_id, 4);
    defer std.testing.allocator.free(custody_columns);

    var enr_data = [_]u8{0} ** 4;
    var enr = Enr{
        .seq = 1,
        .pubkey = [_]u8{0x02} ** 33,
        .ip = [4]u8{ 1, 2, 3, 4 },
        .udp = 9000,
        .tcp = null,
        .ip6 = null,
        .udp6 = null,
        .tcp6 = null,
        .quic = 9001,
        .quic6 = null,
        .eth2_fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
        .eth2_raw = null,
        .attnets = null,
        .syncnets = null,
        .custody_group_count = 4,
        .raw = &enr_data,
        .alloc = std.testing.allocator,
    };
    svc.recordEnr(node_id, &enr);

    svc.connected_peers = svc.config.target_peers;
    svc.requestCustodyColumnPeers(custody_columns[0], 1);
    svc.discoverPeers();

    const peers = svc.drainDiscoveredPeers();
    defer if (peers.len > 0) svc.allocator.free(peers);

    try std.testing.expectEqual(@as(usize, 1), peers.len);
    try std.testing.expectEqualSlices(u8, &node_id, &peers[0].node_id);
    try std.testing.expectEqual(DiscoverySource.custody_query, peers[0].source);
    try std.testing.expectEqual(enr.pubkey.?, peers[0].pubkey);
    try std.testing.expectEqual(@as(u64, 0), svc.total_lookups);
}

test "DiscoveryService: takeDiscoveredPeers prioritizes targeted sources" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();

    try svc.discovered_peers.append(std.testing.allocator, .{
        .node_id = [_]u8{0x01} ** 32,
        .addr_ip4 = .{ .ip4 = .{ .bytes = .{ 1, 1, 1, 1 }, .port = 9000 } },
        .addr_ip6 = null,
        .pubkey = [_]u8{0x11} ** 33,
        .has_quic = true,
        .attnets = null,
        .fork_digest = null,
        .source = .random_lookup,
    });
    try svc.discovered_peers.append(std.testing.allocator, .{
        .node_id = [_]u8{0x02} ** 32,
        .addr_ip4 = .{ .ip4 = .{ .bytes = .{ 2, 2, 2, 2 }, .port = 9000 } },
        .addr_ip6 = null,
        .pubkey = [_]u8{0x22} ** 33,
        .has_quic = true,
        .attnets = null,
        .fork_digest = null,
        .source = .subnet_query,
    });
    try svc.discovered_peers.append(std.testing.allocator, .{
        .node_id = [_]u8{0x03} ** 32,
        .addr_ip4 = .{ .ip4 = .{ .bytes = .{ 3, 3, 3, 3 }, .port = 9000 } },
        .addr_ip6 = null,
        .pubkey = [_]u8{0x33} ** 33,
        .has_quic = true,
        .attnets = null,
        .fork_digest = null,
        .source = .custody_query,
    });

    const selected = svc.takeDiscoveredPeers(2);
    defer if (selected.len > 0) svc.allocator.free(selected);

    try std.testing.expectEqual(@as(usize, 2), selected.len);
    try std.testing.expectEqual(DiscoverySource.custody_query, selected[0].source);
    try std.testing.expectEqual(DiscoverySource.subnet_query, selected[1].source);
    try std.testing.expectEqual(@as(usize, 1), svc.discovered_peers.items.len);
    try std.testing.expectEqual(DiscoverySource.random_lookup, svc.discovered_peers.items[0].source);
}

test "DiscoveryService: custody query starts lookup when cache is insufficient" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
        .listen_port = 0,
        .target_peers = 5,
    });
    defer svc.deinit();

    svc.connected_peers = svc.config.target_peers;
    svc.requestCustodyColumnPeers(7, 1);
    svc.discoverPeers();

    try std.testing.expectEqual(@as(u64, 1), svc.total_lookups);
}

test "DiscoveryService: filterEnr accepts valid ENR" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
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
        .tcp6 = null,
        .quic = 9001,
        .quic6 = null,
        .eth2_fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
        .eth2_raw = null,
        .attnets = null,
        .syncnets = null,
        .custody_group_count = null,
        .raw = &enr_data,
        .alloc = std.testing.allocator,
    };
    try std.testing.expect(svc.filterEnr(&enr));

    enr.eth2_fork_digest = [4]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    try std.testing.expect(!svc.filterEnr(&enr));

    enr.eth2_fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 };
    enr.ip = null;
    try std.testing.expect(!svc.filterEnr(&enr));

    enr.ip6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    enr.udp6 = 9002;
    try std.testing.expect(svc.filterEnr(&enr));
}

test "DiscoveryService: buildLocalEnr produces valid ENR" {
    const hex_mod = discv5.hex;
    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
        .secret_key = secret_key,
        .local_ip = [4]u8{ 127, 0, 0, 1 },
        .listen_port = 0,
        .p2p_port = 9000,
        .custody_group_count = 4,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
    });
    defer svc.deinit();

    const enr_bytes = try svc.buildLocalEnr();
    defer svc.allocator.free(enr_bytes);

    var parsed = try enr_mod.decode(svc.allocator, enr_bytes);
    defer parsed.deinit();
    try std.testing.expect(parsed.pubkey != null);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parsed.ip.?);
    try std.testing.expectEqual(svc.service.boundPort(.ip4), parsed.udp);
    try std.testing.expect(parsed.eth2_fork_digest != null);
    try std.testing.expectEqual(@as(?u64, 4), parsed.custody_group_count);
}

test "DiscoveryService: buildLocalEnr supports ipv6-only" {
    const hex_mod = discv5.hex;
    const secret_key = hex_mod.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
        .secret_key = secret_key,
        .local_ip6 = loopback6,
        .listen_port = 0,
        .listen_port6 = 0,
        .p2p_port = 9000,
        .p2p_port6 = 9001,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
    });
    defer svc.deinit();

    const enr_bytes = try svc.buildLocalEnr();
    defer svc.allocator.free(enr_bytes);

    var parsed = try enr_mod.decode(svc.allocator, enr_bytes);
    defer parsed.deinit();
    try std.testing.expect(parsed.ip == null);
    try std.testing.expectEqual(loopback6, parsed.ip6.?);
    try std.testing.expectEqual(@as(?u16, null), svc.service.boundPort(.ip4));
    try std.testing.expectEqual(svc.service.boundPort(.ip6), parsed.udp6);
    try std.testing.expectEqual(@as(?u16, 9001), parsed.tcp6);
}

test "DiscoveryService: updateForkDigest preserves live ENR address" {
    const hex_mod = discv5.hex;
    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{
        .secret_key = secret_key,
        .local_ip = [4]u8{ 127, 0, 0, 1 },
        .listen_port = 0,
        .p2p_port = 9000,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
    });
    defer svc.deinit();

    svc.discoverPeers();
    try std.testing.expect(svc.takeLocalEnrChanged());
    try std.testing.expect(!svc.takeLocalEnrChanged());

    var voted_builder = EnrBuilder.init(std.testing.allocator, secret_key, svc.service.localEnrSeq() + 1);
    voted_builder.ip = .{ 203, 0, 113, 9 };
    voted_builder.udp = svc.service.boundPort(.ip4) orelse return error.MissingBindAddress;
    voted_builder.tcp = 9000;
    voted_builder.quic = 9000;
    voted_builder.setEth2(svc.current_fork_digest, svc.config.next_fork_version, svc.config.next_fork_epoch);
    voted_builder.attnets = [_]u8{0} ** 8;
    voted_builder.syncnets = [_]u8{0} ** 1;
    const voted_enr = try voted_builder.encode();
    defer std.testing.allocator.free(voted_enr);

    try svc.service.setLocalEnr(voted_enr);
    svc.updateForkDigest([4]u8{ 0xAB, 0xCD, 0xEF, 0x01 }, [4]u8{ 0, 0, 0, 0 }, FAR_FUTURE_EPOCH);
    svc.discoverPeers();
    try std.testing.expect(svc.takeLocalEnrChanged());
    try std.testing.expect(!svc.takeLocalEnrChanged());

    const current_enr = try svc.buildLocalEnr();
    defer std.testing.allocator.free(current_enr);

    var parsed = try enr_mod.decode(std.testing.allocator, current_enr);
    defer parsed.deinit();
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 9 }, parsed.ip.?);
    try std.testing.expectEqual(svc.service.boundPort(.ip4), parsed.udp);
    try std.testing.expectEqual([4]u8{ 0xAB, 0xCD, 0xEF, 0x01 }, parsed.eth2_fork_digest.?);
    try std.testing.expectEqual(@as(u64, 3), svc.service.localEnrSeq());
}

test "DiscoveryService: getStats returns valid state" {
    var svc = try DiscoveryService.init(std.testing.io, std.testing.allocator, .{ .listen_port = 0 });
    defer svc.deinit();
    const stats = svc.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_lookups);
    try std.testing.expectEqual(@as(u32, 0), stats.connected_peers);
    try std.testing.expectEqual(@as(u64, 0), stats.enr_seq);
}

test "DiscoveredPeer struct layout" {
    const peer = DiscoveredPeer{
        .node_id = [_]u8{0xAA} ** 32,
        .addr_ip4 = .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 9000 } },
        .pubkey = [_]u8{0xBB} ** 33,
        .has_quic = true,
        .attnets = [_]u8{0xFF} ** 8,
        .fork_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xb0 },
        .source = .random_lookup,
    };
    try std.testing.expect(peer.addr_ip4 != null);
    try std.testing.expect(peer.addr_ip6 == null);
    try std.testing.expect(peer.has_quic);
}
