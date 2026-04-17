//! P2P service integration layer for eth-p2p-z.
//!
//! Bridges eth-p2p-z's comptime Switch with lodestar-z's networking stack:
//! - `P2pService` wraps a Switch configured with all eth2 req/resp protocols
//!   and a gossipsub handler, plus an EthGossipAdapter for subscribe/publish.
//! - The Switch is comptime-composed with QUIC transport and the 8 req/resp
//!   protocol handlers plus gossipsub.
//! - Inbound gossip events are drained from gossipsub and routed by the node's
//!   GossipHandler.
//! - Req/resp messages are dispatched by each `Eth2Protocol` handler into
//!   `req_resp_handler`.
//!
//! Usage:
//! ```zig
//! var svc = try P2pService.init(io, allocator, .{
//!     .fork_digest = node.getForkDigest(),
//!     .req_resp_context = &rr_ctx,
//! });
//! defer svc.deinit(io);
//! try svc.start(io, listen_multiaddr);
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const libp2p = @import("zig-libp2p");
const quic_mod = libp2p.quic_new;
const QuicTransport = quic_mod.QuicTransport;
const identity_mod = libp2p.identity;
const gossipsub_mod = libp2p.gossipsub;
const GossipsubHandler = gossipsub_mod.Handler;
const GossipsubService = gossipsub_mod.Service;
const GossipsubConfig = gossipsub_mod.Config;
const swarm_mod = libp2p.swarm;
const identify_mod = libp2p.identify;
const IdentifyHandler = identify_mod.Handler;
const Multiaddr = @import("multiaddr").Multiaddr;

const eth2_protocols = @import("eth2_protocols.zig");
const eth_gossip = @import("eth_gossip.zig");
const gossip_topics = @import("gossip_topics.zig");
const peer_manager_mod = @import("peer_manager.zig");
const peer_scoring = @import("peer_scoring.zig");
const rate_limiter = @import("rate_limiter.zig");
const req_resp_handler = @import("req_resp_handler.zig");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const PeerManager = peer_manager_mod.PeerManager;
const SelfRateLimiter = rate_limiter.SelfRateLimiter;
const SelfRateLimitMethod = rate_limiter.SelfRateLimitMethod;

const EthGossipAdapter = eth_gossip.EthGossipAdapter;
pub const GossipTopicType = eth_gossip.GossipTopicType;
pub const ActiveGossipFork = eth_gossip.EthGossipAdapter.ActiveFork;
pub const GossipEvent = gossipsub_mod.config.Event;
pub const GossipValidationResult = gossipsub_mod.ValidationResult;
pub const QuicStream = quic_mod.Stream;
const ReqRespContext = req_resp_handler.ReqRespContext;
const TopicTypeCount = std.meta.fields(gossip_topics.GossipTopicType).len;

const StatusProtocol = eth2_protocols.StatusProtocol;
const StatusV2Protocol = eth2_protocols.StatusV2Protocol;
const GoodbyeProtocol = eth2_protocols.GoodbyeProtocol;
const PingProtocol = eth2_protocols.PingProtocol;
const MetadataProtocol = eth2_protocols.MetadataProtocol;
const MetadataV3Protocol = eth2_protocols.MetadataV3Protocol;
const BlocksByRangeProtocol = eth2_protocols.BlocksByRangeProtocol;
const BlocksByRootProtocol = eth2_protocols.BlocksByRootProtocol;
const BlobSidecarsByRangeProtocol = eth2_protocols.BlobSidecarsByRangeProtocol;
const BlobSidecarsByRootProtocol = eth2_protocols.BlobSidecarsByRootProtocol;
const DataColumnsByRangeProtocol = eth2_protocols.DataColumnsByRangeProtocol;
const DataColumnsByRootProtocol = eth2_protocols.DataColumnsByRootProtocol;
const ReqRespServerPolicy = eth2_protocols.ReqRespServerPolicy;
const LightClientBootstrapProtocol = eth2_protocols.LightClientBootstrapProtocol;
const LightClientUpdatesByRangeProtocol = eth2_protocols.LightClientUpdatesByRangeProtocol;
const LightClientFinalityUpdateProtocol = eth2_protocols.LightClientFinalityUpdateProtocol;
const LightClientOptimisticUpdateProtocol = eth2_protocols.LightClientOptimisticUpdateProtocol;

const log = std.log.scoped(.p2p_service);

fn unixTimeMs(io: Io) u64 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms >= 0) @intCast(ms) else 0;
}

const UniqueGossipsubPeerStats = struct {
    topic_peers: u64 = 0,
    mesh_peers: u64 = 0,
    mesh_peers_by_topic: [TopicTypeCount]u64 = [_]u64{0} ** TopicTypeCount,
    tracked_topics_with_peers: u64 = 0,
    tracked_topic_peers: u64 = 0,
};

fn addUniquePeers(
    unique_peers: *std.StringHashMap(void),
    peer_set: *const std.StringHashMap(void),
) !void {
    var peer_iter = peer_set.keyIterator();
    while (peer_iter.next()) |peer_id| {
        _ = try unique_peers.getOrPut(peer_id.*);
    }
}

fn computeUniqueGossipsubPeerStats(
    allocator: Allocator,
    topic_map: *const std.StringHashMap(std.StringHashMap(void)),
    mesh_map: *const std.StringHashMap(std.StringHashMap(void)),
    tracked_subscriptions: *const std.StringHashMap(void),
) !UniqueGossipsubPeerStats {
    var stack_alloc = std.heap.stackFallback(4096, allocator);
    const temp_alloc = stack_alloc.get();

    var topic_unique = std.StringHashMap(void).init(temp_alloc);
    defer topic_unique.deinit();
    var mesh_unique = std.StringHashMap(void).init(temp_alloc);
    defer mesh_unique.deinit();
    var tracked_unique = std.StringHashMap(void).init(temp_alloc);
    defer tracked_unique.deinit();
    var mesh_unique_by_topic: [TopicTypeCount]std.StringHashMap(void) = undefined;
    for (&mesh_unique_by_topic) |*unique_by_topic| {
        unique_by_topic.* = std.StringHashMap(void).init(temp_alloc);
    }
    defer {
        for (&mesh_unique_by_topic) |*unique_by_topic| unique_by_topic.deinit();
    }

    var topic_iter = topic_map.iterator();
    while (topic_iter.next()) |entry| {
        try addUniquePeers(&topic_unique, entry.value_ptr);
    }

    var mesh_iter = mesh_map.iterator();
    while (mesh_iter.next()) |entry| {
        try addUniquePeers(&mesh_unique, entry.value_ptr);
        if (gossip_topics.parseTopic(entry.key_ptr.*)) |parsed| {
            try addUniquePeers(&mesh_unique_by_topic[@intFromEnum(parsed.topic_type)], entry.value_ptr);
        }
    }

    var tracked_topics_with_peers: u64 = 0;
    var tracked_iter = tracked_subscriptions.keyIterator();
    while (tracked_iter.next()) |topic_key| {
        if (topic_map.getPtr(topic_key.*)) |peer_set| {
            if (peer_set.count() == 0) continue;
            tracked_topics_with_peers += 1;
            try addUniquePeers(&tracked_unique, peer_set);
        }
    }

    var stats: UniqueGossipsubPeerStats = .{
        .topic_peers = topic_unique.count(),
        .mesh_peers = mesh_unique.count(),
        .tracked_topics_with_peers = tracked_topics_with_peers,
        .tracked_topic_peers = tracked_unique.count(),
    };
    for (&mesh_unique_by_topic, 0..) |unique_by_topic, idx| {
        stats.mesh_peers_by_topic[idx] = unique_by_topic.count();
    }
    return stats;
}

const identify_supported_protocols_without_light_client = &.{
    "/eth2/beacon_chain/req/status/1/ssz_snappy",
    "/eth2/beacon_chain/req/status/2/ssz_snappy",
    "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
    "/eth2/beacon_chain/req/ping/1/ssz_snappy",
    "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
    "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
    "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
    "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy",
    "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy",
    "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy",
    "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
    "/meshsub/1.2.0",
    "/ipfs/id/1.0.0",
};

const identify_supported_protocols_with_light_client = &.{
    "/eth2/beacon_chain/req/status/1/ssz_snappy",
    "/eth2/beacon_chain/req/status/2/ssz_snappy",
    "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
    "/eth2/beacon_chain/req/ping/1/ssz_snappy",
    "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
    "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
    "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
    "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy",
    "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy",
    "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy",
    "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
    "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy",
    "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy",
    "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy",
    "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy",
    "/meshsub/1.2.0",
    "/ipfs/id/1.0.0",
};

// ─── Switch types ────────────────────────────────────────────────────────────

pub const Eth2SwitchWithoutLightClient = swarm_mod.Switch(.{
    .transports = &.{QuicTransport},
    .protocols = &.{
        StatusProtocol,
        StatusV2Protocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
        MetadataV3Protocol,
        BlocksByRangeProtocol,
        BlocksByRootProtocol,
        BlobSidecarsByRangeProtocol,
        BlobSidecarsByRootProtocol,
        DataColumnsByRangeProtocol,
        DataColumnsByRootProtocol,
        GossipsubHandler,
        IdentifyHandler,
    },
});

pub const Eth2SwitchWithLightClient = swarm_mod.Switch(.{
    .transports = &.{QuicTransport},
    .protocols = &.{
        StatusProtocol,
        StatusV2Protocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
        MetadataV3Protocol,
        BlocksByRangeProtocol,
        BlocksByRootProtocol,
        BlobSidecarsByRangeProtocol,
        BlobSidecarsByRootProtocol,
        DataColumnsByRangeProtocol,
        DataColumnsByRootProtocol,
        LightClientBootstrapProtocol,
        LightClientUpdatesByRangeProtocol,
        LightClientFinalityUpdateProtocol,
        LightClientOptimisticUpdateProtocol,
        GossipsubHandler,
        IdentifyHandler,
    },
});

const Network = union(enum) {
    without_light_client: Eth2SwitchWithoutLightClient,
    with_light_client: Eth2SwitchWithLightClient,

    fn listen(self: *@This(), io: Io, listen_addr: Multiaddr) !void {
        switch (self.*) {
            inline else => |*network| try network.listen(io, listen_addr),
        }
    }

    fn dial(self: *@This(), io: Io, peer_addr: Multiaddr) ![]const u8 {
        return switch (self.*) {
            inline else => |*network| try network.dial(io, peer_addr),
        };
    }

    fn isPeerConnected(self: *@This(), io: Io, peer_id: []const u8) bool {
        return switch (self.*) {
            inline else => |*network| network.isPeerConnected(io, peer_id),
        };
    }

    fn snapshotConnectedPeerIds(self: *@This(), io: Io, allocator: Allocator) ![][]const u8 {
        switch (self.*) {
            inline else => |*network| return network.snapshotConnectedPeerIds(io, allocator),
        }
    }

    fn newStreamWithPayload(
        self: *@This(),
        io: Io,
        peer_id: []const u8,
        comptime Protocol: type,
        ssz_payload: ?[]const u8,
    ) !void {
        switch (self.*) {
            inline else => |*network| try network.newStreamWithPayload(io, peer_id, Protocol, ssz_payload),
        }
    }

    fn dialProtocol(self: *@This(), io: Io, peer_id: []const u8, protocol_id: []const u8) !quic_mod.Stream {
        return switch (self.*) {
            inline else => |*network| try network.dialProtocol(io, peer_id, protocol_id),
        };
    }

    fn disconnectPeer(self: *@This(), io: Io, peer_id: []const u8) bool {
        return switch (self.*) {
            inline else => |*network| network.disconnectPeer(io, peer_id),
        };
    }

    fn identifyResult(self: *@This(), peer_id: []const u8) ?*const identify_mod.IdentifyResult {
        return switch (self.*) {
            inline else => |*network| network.getHandler(IdentifyHandler).getPeerResult(peer_id),
        };
    }

    fn close(self: *@This(), io: Io) void {
        switch (self.*) {
            inline else => |*network| network.close(io),
        }
    }

    fn deinit(self: *@This(), io: Io) void {
        switch (self.*) {
            inline else => |*network| {
                network.deinit(io);
                network.getHandler(IdentifyHandler).deinit();
            },
        }
    }

    fn listenAddrs(self: *const @This()) []const std.Io.net.IpAddress {
        return switch (self.*) {
            inline else => |network| network.listenAddrs(),
        };
    }
};

// ─── Configuration ───────────────────────────────────────────────────────────

pub const P2pConfig = struct {
    /// Current fork digest (4-byte prefix for gossip topics).
    fork_digest: [4]u8,
    /// Active fork sequence, determines which SSZ schemas to use for gossip deserialization.
    fork_seq: ForkSeq,
    /// Req/resp handler callbacks (provides blocks, status, etc.).
    req_resp_context: *const ReqRespContext,
    /// Optional inbound req/resp server policy (rate limiting, disconnects).
    req_resp_server_policy: ?*const ReqRespServerPolicy = null,
    /// Optional libp2p host identity for QUIC/TLS and peer-id derivation.
    /// When null, eth-p2p-z generates an ephemeral host identity.
    host_identity: ?identity_mod.KeyPair = null,
    /// Identify agent version to advertise. Null hides implementation details.
    identify_agent_version: ?[]const u8 = null,
    /// Disable the light-client req/resp server surface. This defaults to true
    /// because the current node does not implement those handlers yet.
    disable_light_client_server: bool = true,
    /// GossipSub router configuration.
    gossipsub_config: GossipsubConfig = .{},
};

// ─── P2pService ──────────────────────────────────────────────────────────────

pub const ReqRespRequestPermit = struct {
    limiter: *SelfRateLimiter,
    peer_id: []const u8,
    method: SelfRateLimitMethod,
    request_id: u64,
    active: bool = true,

    pub fn deinit(self: *ReqRespRequestPermit, io: Io) void {
        defer if (self.peer_id.len != 0) {
            self.limiter.allocator.free(self.peer_id);
            self.peer_id = &.{};
        };

        if (!self.active) return;
        self.limiter.requestCompleted(io, self.peer_id, self.method, self.request_id);
        self.active = false;
    }
};

pub const P2pService = struct {
    const Self = @This();
    const TopicDigestSummary = struct {
        digest: [4]u8 = [_]u8{0} ** 4,
        topic_count: u64 = 0,
        peer_count: u64 = 0,
    };

    allocator: Allocator,
    network: Network,
    gossipsub: *GossipsubService,
    gossip_adapter: EthGossipAdapter,
    host_identity: ?*identity_mod.KeyPair,
    req_resp_self_limiter: SelfRateLimiter,

    pub const GossipsubMetricsSnapshot = struct {
        outbound_streams: u64 = 0,
        tracked_subscriptions: u64 = 0,
        known_topics: u64 = 0,
        mesh_topics: u64 = 0,
        mesh_peers: u64 = 0,
        topic_peers: u64 = 0,
        mesh_peers_by_topic: [TopicTypeCount]u64 = [_]u64{0} ** TopicTypeCount,
        tracked_topics_with_peers: u64 = 0,
        tracked_topic_peers: u64 = 0,
        pending_events: u64 = 0,
        pending_sends: u64 = 0,
        pending_send_bytes: u64 = 0,
    };

    pub fn init(io: Io, allocator: Allocator, config: P2pConfig) !Self {
        const gossipsub = try GossipsubService.init(allocator, config.gossipsub_config);
        errdefer gossipsub.deinit(io);

        const host_identity = if (config.host_identity) |identity| blk: {
            const ptr = try allocator.create(identity_mod.KeyPair);
            errdefer allocator.destroy(ptr);
            ptr.* = identity;
            break :blk ptr;
        } else null;
        errdefer if (host_identity) |ptr| {
            ptr.deinit();
            allocator.destroy(ptr);
        };

        const identify_handler = IdentifyHandler{
            .allocator = allocator,
            .config = .{
                .protocol_version = "eth2/1.0.0",
                .agent_version = config.identify_agent_version,
                .supported_protocols = if (config.disable_light_client_server)
                    identify_supported_protocols_without_light_client
                else
                    identify_supported_protocols_with_light_client,
            },
            .peer_results = .empty,
        };

        const network: Network = if (config.disable_light_client_server)
            .{ .without_light_client = Eth2SwitchWithoutLightClient.init(
                allocator,
                .{ .host_identity = host_identity },
                .{
                    StatusProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    StatusV2Protocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    GoodbyeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    PingProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    MetadataProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    MetadataV3Protocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlocksByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlocksByRootProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlobSidecarsByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlobSidecarsByRootProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    DataColumnsByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    DataColumnsByRootProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    GossipsubHandler{ .svc = gossipsub },
                    identify_handler,
                },
            ) }
        else
            .{ .with_light_client = Eth2SwitchWithLightClient.init(
                allocator,
                .{ .host_identity = host_identity },
                .{
                    StatusProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    StatusV2Protocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    GoodbyeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    PingProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    MetadataProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    MetadataV3Protocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlocksByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlocksByRootProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlobSidecarsByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    BlobSidecarsByRootProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    DataColumnsByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    DataColumnsByRootProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    LightClientBootstrapProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    LightClientUpdatesByRangeProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    LightClientFinalityUpdateProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    LightClientOptimisticUpdateProtocol.init(allocator, config.req_resp_context, config.req_resp_server_policy),
                    GossipsubHandler{ .svc = gossipsub },
                    identify_handler,
                },
            ) };

        const gossip_adapter = EthGossipAdapter.init(
            allocator,
            gossipsub,
            config.fork_digest,
            config.fork_seq,
        );

        return .{
            .allocator = allocator,
            .network = network,
            .gossipsub = gossipsub,
            .gossip_adapter = gossip_adapter,
            .host_identity = host_identity,
            .req_resp_self_limiter = SelfRateLimiter.init(allocator),
        };
    }

    /// Start listening and subscribe to standard eth2 gossip topics.
    pub fn start(self: *Self, io: Io, listen_addr: Multiaddr) !void {
        // Set initial time for gossipsub router (PRUNE backoff, scoring).
        {
            self.gossipsub.setTime(io, unixTimeMs(io));
        }
        try self.network.listen(io, listen_addr);
        try self.subscribeEthTopics(io);
        self.startHeartbeat(io);
        log.info("p2p service started", .{});
    }

    pub fn subscribeEthTopics(self: *Self, io: Io) !void {
        try self.gossip_adapter.subscribeEthTopics(io);
    }

    pub fn unsubscribeEthTopics(self: *Self, io: Io) !void {
        try self.gossip_adapter.unsubscribeEthTopics(io);
    }

    pub fn gossipsubMetricsSnapshot(self: *Self, io: Io) GossipsubMetricsSnapshot {
        self.gossipsub.state_mu.lockUncancelable(io);
        defer self.gossipsub.state_mu.unlock(io);

        var snapshot: GossipsubMetricsSnapshot = .{
            .outbound_streams = @intCast(self.gossipsub.outbound_streams.count()),
            .tracked_subscriptions = @intCast(self.gossipsub.tracked_subscriptions.count()),
            .known_topics = @intCast(self.gossipsub.router.topics.count()),
            .mesh_topics = @intCast(self.gossipsub.router.mesh.count()),
            .pending_events = @intCast(self.gossipsub.router.events.items.len),
            .pending_sends = @intCast(self.gossipsub.pending_sends.items.len),
            .pending_send_bytes = @intCast(self.gossipsub.pending_send_bytes),
        };

        const unique_stats = computeUniqueGossipsubPeerStats(
            self.allocator,
            &self.gossipsub.router.topics,
            &self.gossipsub.router.mesh,
            &self.gossipsub.tracked_subscriptions,
        ) catch |err| {
            log.warn("failed to compute unique gossipsub peer metrics: {}", .{err});
            return snapshot;
        };
        snapshot.mesh_peers = unique_stats.mesh_peers;
        snapshot.topic_peers = unique_stats.topic_peers;
        snapshot.mesh_peers_by_topic = unique_stats.mesh_peers_by_topic;
        snapshot.tracked_topics_with_peers = unique_stats.tracked_topics_with_peers;
        snapshot.tracked_topic_peers = unique_stats.tracked_topic_peers;

        return snapshot;
    }

    pub fn logGossipsubTopicDiagnostics(self: *Self, io: Io) void {
        const max_digest_summaries = 4;
        var tracked_digests: [max_digest_summaries]TopicDigestSummary = [_]TopicDigestSummary{.{}} ** max_digest_summaries;
        var tracked_digest_count: usize = 0;
        var known_digests: [max_digest_summaries]TopicDigestSummary = [_]TopicDigestSummary{.{}} ** max_digest_summaries;
        var known_digest_count: usize = 0;
        var tracked_sample: ?[]const u8 = null;
        var known_sample: ?[]const u8 = null;

        self.gossipsub.state_mu.lockUncancelable(io);
        defer self.gossipsub.state_mu.unlock(io);

        var tracked_iter = self.gossipsub.tracked_subscriptions.keyIterator();
        while (tracked_iter.next()) |topic_key| {
            if (tracked_sample == null) tracked_sample = topic_key.*;
            const parsed = gossip_topics.parseTopic(topic_key.*) orelse continue;
            addDigestSummary(&tracked_digests, &tracked_digest_count, parsed.fork_digest, 1, 0);
        }

        var known_iter = self.gossipsub.router.topics.iterator();
        while (known_iter.next()) |entry| {
            if (known_sample == null) known_sample = entry.key_ptr.*;
            const parsed = gossip_topics.parseTopic(entry.key_ptr.*) orelse continue;
            addDigestSummary(
                &known_digests,
                &known_digest_count,
                parsed.fork_digest,
                1,
                @intCast(entry.value_ptr.count()),
            );
        }

        log.warn(
            "gossipsub topic mismatch: tracked_subscriptions={d} known_topics={d} topic_peers={d} tracked_sample={s} known_sample={s}",
            .{
                self.gossipsub.tracked_subscriptions.count(),
                self.gossipsub.router.topics.count(),
                countTopicPeerRefs(self),
                tracked_sample orelse "<none>",
                known_sample orelse "<none>",
            },
        );

        for (tracked_digests[0..tracked_digest_count]) |summary| {
            const digest_hex = std.fmt.bytesToHex(&summary.digest, .lower);
            log.warn("gossipsub tracked digest {s}: topics={d}", .{
                &digest_hex,
                summary.topic_count,
            });
        }

        for (known_digests[0..known_digest_count]) |summary| {
            const digest_hex = std.fmt.bytesToHex(&summary.digest, .lower);
            log.warn("gossipsub known digest {s}: topics={d} peer_refs={d}", .{
                &digest_hex,
                summary.topic_count,
                summary.peer_count,
            });
        }
    }

    fn addDigestSummary(
        summaries: *[4]TopicDigestSummary,
        summary_count: *usize,
        digest: [4]u8,
        topic_count: u64,
        peer_count: u64,
    ) void {
        for (summaries[0..summary_count.*]) |*summary| {
            if (std.mem.eql(u8, &summary.digest, &digest)) {
                summary.topic_count +%= topic_count;
                summary.peer_count +%= peer_count;
                return;
            }
        }

        if (summary_count.* >= summaries.len) return;
        summaries[summary_count.*] = .{
            .digest = digest,
            .topic_count = topic_count,
            .peer_count = peer_count,
        };
        summary_count.* += 1;
    }

    fn countTopicPeerRefs(self: *Self) u64 {
        var total: u64 = 0;
        var iter = self.gossipsub.router.topics.iterator();
        while (iter.next()) |entry| {
            total +%= @intCast(entry.value_ptr.count());
        }
        return total;
    }

    /// Dial a remote peer by QUIC multiaddr. Caller owns the returned peer ID.
    pub fn dial(self: *Self, io: Io, peer_addr: Multiaddr) ![]const u8 {
        return self.network.dial(io, peer_addr);
    }

    /// Return whether the peer currently has an active transport connection.
    pub fn isPeerConnected(self: *Self, io: Io, peer_id: []const u8) bool {
        return self.network.isPeerConnected(io, peer_id);
    }

    /// Snapshot the currently connected peer IDs. Caller owns the returned slice and entries.
    pub fn snapshotConnectedPeerIds(self: *Self, io: Io, allocator: Allocator) ![][]const u8 {
        return self.network.snapshotConnectedPeerIds(io, allocator);
    }

    /// Open a new outbound stream for a protocol to a connected peer.
    /// `ssz_payload` is passed as context to `handleOutbound`; use `null` for
    /// zero-body requests (Metadata) and provide the serialized SSZ bytes for
    /// protocols like Status that include a request body.
    pub fn newStream(
        self: *Self,
        io: Io,
        peer_id: []const u8,
        comptime Protocol: type,
        ssz_payload: ?[]const u8,
    ) !void {
        try self.network.newStreamWithPayload(io, peer_id, Protocol, ssz_payload);
    }

    /// Open a negotiated outbound stream for a given protocol ID.
    ///
    /// Returns the raw QUIC stream after multistream negotiation. The caller
    /// owns the stream and is responsible for writing the request, reading
    /// the response, and closing it.
    pub fn dialProtocol(self: *Self, io: Io, peer_id: []const u8, protocol_id: []const u8) !quic_mod.Stream {
        return self.network.dialProtocol(io, peer_id, protocol_id);
    }

    pub fn acquireReqRespRequestPermit(
        self: *Self,
        io: Io,
        peer_id: []const u8,
        method: SelfRateLimitMethod,
    ) !ReqRespRequestPermit {
        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);

        const request_id = try self.req_resp_self_limiter.allow(io, owned_peer_id, method);
        return .{
            .limiter = &self.req_resp_self_limiter,
            .peer_id = owned_peer_id,
            .method = method,
            .request_id = request_id,
        };
    }

    pub fn pruneReqRespSelfLimiter(self: *Self, io: Io) void {
        self.req_resp_self_limiter.pruneInactive(io);
    }

    pub fn reqRespSelfLimiterPeerCount(self: *Self, io: Io) usize {
        return self.req_resp_self_limiter.peerCount(io);
    }

    /// Ask libp2p to open an outbound gossipsub stream to a connected peer.
    pub fn openGossipsubStream(self: *Self, io: Io, peer_id: []const u8) !void {
        try self.newStream(io, peer_id, GossipsubHandler, null);
    }

    /// Open an outbound gossipsub stream without blocking the caller. The
    /// stream is long-lived, so doing this inline would stall the node loop.
    pub fn openGossipsubStreamAsync(self: *Self, io: Io, peer_id: []const u8) !void {
        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);
        switch (self.network) {
            inline else => |*network| {
                network.background.concurrent(io, gossipsubStreamTask, .{ self, io, owned_peer_id }) catch |err| {
                    log.debug("Failed to spawn concurrent gossipsub stream task: {}", .{err});
                    network.background.async(io, gossipsubStreamTask, .{ self, io, owned_peer_id });
                };
            },
        }
    }

    fn gossipsubStreamTask(self: *Self, io: Io, peer_id: []u8) void {
        defer self.allocator.free(peer_id);
        self.openGossipsubStream(io, peer_id) catch |err| {
            log.debug("Failed to open outbound gossipsub stream to {s}: {}", .{ peer_id, err });
        };
    }

    /// Request libp2p identify data from a connected peer.
    pub fn requestIdentify(self: *Self, io: Io, peer_id: []const u8) !void {
        try self.newStream(io, peer_id, IdentifyHandler, null);
    }

    /// Request libp2p identify data without blocking the caller.
    pub fn requestIdentifyAsync(self: *Self, io: Io, peer_id: []const u8) !void {
        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);
        switch (self.network) {
            inline else => |*network| {
                network.background.concurrent(io, identifyStreamTask, .{ self, io, owned_peer_id }) catch |err| {
                    log.debug("Failed to spawn concurrent identify task: {}", .{err});
                    network.background.async(io, identifyStreamTask, .{ self, io, owned_peer_id });
                };
            },
        }
    }

    fn identifyStreamTask(self: *Self, io: Io, peer_id: []u8) void {
        defer self.allocator.free(peer_id);
        self.requestIdentify(io, peer_id) catch |err| {
            log.debug("Failed to open outbound identify stream to {s}: {}", .{ peer_id, err });
        };
    }

    /// Gracefully close a connected peer transport. The switch will clean up
    /// handler state when its connection task observes the closure.
    pub fn disconnectPeer(self: *Self, io: Io, peer_id: []const u8) bool {
        return self.network.disconnectPeer(io, peer_id);
    }

    /// Return the latest identify result for a peer, if available.
    pub fn identifyResult(self: *Self, peer_id: []const u8) ?*const identify_mod.IdentifyResult {
        return self.network.identifyResult(peer_id);
    }

    /// Publish an SSZ message to a gossip topic.
    ///
    /// The message is Snappy-compressed internally by `EthGossipAdapter.publish`.
    pub fn publishGossip(
        self: *Self,
        io: Io,
        topic_type: GossipTopicType,
        subnet_id: ?u8,
        ssz_bytes: []const u8,
    ) !void {
        return self.gossip_adapter.publish(io, topic_type, subnet_id, ssz_bytes);
    }

    /// Drain pending gossipsub events. Caller owns the returned slice.
    pub fn drainGossipEvents(self: *Self, io: Io) ![]GossipEvent {
        return self.gossipsub.drainEvents(io);
    }

    /// Report the final validation result for an inbound gossip message.
    pub fn reportGossipValidationResult(
        self: *Self,
        io: Io,
        msg_id: []const u8,
        result: GossipValidationResult,
    ) bool {
        return self.gossipsub.reportValidationResult(io, msg_id, result);
    }

    /// Report an invalid inbound gossip message to gossipsub's mesh scorer.
    pub fn recordInvalidGossipMessage(self: *Self, io: Io, peer_id: []const u8, topic: []const u8) void {
        self.gossipsub.state_mu.lockUncancelable(io);
        defer self.gossipsub.state_mu.unlock(io);
        self.gossipsub.router.recordInvalidMessage(peer_id, topic);
    }

    /// Mirror current gossipsub router scores into the peer manager's score state.
    pub fn syncGossipsubScores(self: *Self, io: Io, pm: *PeerManager, now_ms: u64) !void {
        const ScoredPeer = struct {
            peer_id: []const u8,
            score: f64,
        };

        const connected_peer_ids = try self.snapshotConnectedPeerIds(io, self.allocator);
        defer {
            for (connected_peer_ids) |peer_id| self.allocator.free(peer_id);
            self.allocator.free(connected_peer_ids);
        }

        var scored_peers = std.ArrayListUnmanaged(ScoredPeer).empty;
        defer scored_peers.deinit(self.allocator);

        for (connected_peer_ids) |peer_id| {
            self.gossipsub.state_mu.lockUncancelable(io);
            const score = self.gossipsub.router.peerScore(peer_id);
            self.gossipsub.state_mu.unlock(io);
            try scored_peers.append(self.allocator, .{
                .peer_id = peer_id,
                .score = score,
            });
        }

        std.mem.sort(ScoredPeer, scored_peers.items, {}, struct {
            fn lessThan(_: void, a: ScoredPeer, b: ScoredPeer) bool {
                return a.score > b.score;
            }
        }.lessThan);

        var ignores_remaining = pm.negativeGossipsubIgnoreCount();
        for (scored_peers.items) |scored_peer| {
            const ignore_negative = if (scored_peer.score < 0.0 and
                scored_peer.score > peer_scoring.NEGATIVE_GOSSIPSUB_IGNORE_THRESHOLD and
                ignores_remaining > 0)
            blk: {
                ignores_remaining -= 1;
                break :blk true;
            } else false;
            _ = pm.updateGossipsubScore(scored_peer.peer_id, scored_peer.score, ignore_negative, now_ms);
        }
    }

    /// Subscribe to a gossip subnet topic (e.g., attestation subnets).
    pub fn subscribeSubnet(self: *Self, io: Io, topic_type: GossipTopicType, subnet_id: u8) !void {
        try self.gossip_adapter.subscribeSubnet(io, topic_type, subnet_id);
    }

    /// Unsubscribe from a gossip subnet topic.
    pub fn unsubscribeSubnet(self: *Self, io: Io, topic_type: GossipTopicType, subnet_id: u8) !void {
        try self.gossip_adapter.unsubscribeSubnet(io, topic_type, subnet_id);
    }

    pub fn setPublishFork(self: *Self, new_fork_digest: [4]u8, new_fork_seq: ForkSeq) void {
        self.gossip_adapter.setPublishFork(new_fork_digest, new_fork_seq);
    }

    pub fn setActiveGossipForks(self: *Self, io: Io, forks: []const ActiveGossipFork) !void {
        try self.gossip_adapter.setActiveForks(io, forks);
    }

    /// Gracefully shut down (cancel background fibers, close QUIC engines).
    pub fn stop(self: *Self, io: Io) void {
        self.network.close(io);
        log.info("p2p service stopped", .{});
    }

    /// Release all owned resources.
    pub fn deinit(self: *Self, io: Io) void {
        self.gossip_adapter.deinit();
        // Req/resp permits complete during network shutdown, so the limiter must
        // outlive the network teardown path that returns those permits.
        self.network.deinit(io);
        self.gossipsub.deinit(io);
        self.req_resp_self_limiter.deinit();
        if (self.host_identity) |host_identity| {
            host_identity.deinit();
            self.allocator.destroy(host_identity);
        }
    }

    /// Schedule work on the switch background group. Use this for network work
    /// that must not block the node's main P2P/import loop.
    pub fn spawnBackground(self: *Self, io: Io, comptime func: anytype, args: anytype) void {
        switch (self.network) {
            inline else => |*network| {
                network.background.concurrent(io, func, args) catch |err| {
                    log.warn("background concurrency unavailable; falling back to cooperative async: {}", .{err});
                    network.background.async(io, func, args);
                };
            },
        }
    }

    /// Spawn a background fiber for the gossipsub heartbeat timer.
    fn startHeartbeat(self: *Self, io: Io) void {
        switch (self.network) {
            inline else => |*network| network.background.async(io, heartbeatLoop, .{ self.gossipsub, io }),
        }
    }

    fn heartbeatLoop(gs: *GossipsubService, io: Io) void {
        while (true) {
            const t: Io.Timeout = .{ .duration = .{
                .raw = Io.Duration.fromMilliseconds(700),
                .clock = .awake,
            } };
            t.sleep(io) catch return;
            // Update the gossipsub router's wall-clock time before each heartbeat.
            // Without this, PRUNE backoff timers and other time-based logic
            // see time_ms=0 and malfunction (backoff always expired, etc.).
            {
                gs.setTime(io, unixTimeMs(io));
            }
            gs.heartbeat(io) catch {};
        }
    }

    /// Return the bound server listen address.
    pub fn listenAddr(self: *const Self) ?std.Io.net.IpAddress {
        return self.network.listenAddrs();
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "P2pService: gossipsub unique peer stats deduplicate topic memberships" {
    const allocator = std.testing.allocator;

    var topics = std.StringHashMap(std.StringHashMap(void)).init(allocator);
    defer {
        var it = topics.valueIterator();
        while (it.next()) |peer_set| peer_set.deinit();
        topics.deinit();
    }
    var topic_blocks = std.StringHashMap(void).init(allocator);
    try topic_blocks.put("peer-1", {});
    try topic_blocks.put("peer-2", {});
    try topics.put("/eth2/00000000/beacon_block/ssz_snappy", topic_blocks);

    var topic_blobs = std.StringHashMap(void).init(allocator);
    try topic_blobs.put("peer-2", {});
    try topic_blobs.put("peer-3", {});
    try topics.put("/eth2/00000000/blob_sidecar_0/ssz_snappy", topic_blobs);

    var topic_attestations = std.StringHashMap(void).init(allocator);
    try topic_attestations.put("peer-1", {});
    try topic_attestations.put("peer-4", {});
    try topics.put("/eth2/00000000/beacon_attestation_1/ssz_snappy", topic_attestations);

    var mesh_topics = std.StringHashMap(std.StringHashMap(void)).init(allocator);
    defer {
        var it = mesh_topics.valueIterator();
        while (it.next()) |peer_set| peer_set.deinit();
        mesh_topics.deinit();
    }
    var mesh_blocks = std.StringHashMap(void).init(allocator);
    try mesh_blocks.put("peer-1", {});
    try mesh_topics.put("/eth2/00000000/beacon_block/ssz_snappy", mesh_blocks);

    var mesh_attestations = std.StringHashMap(void).init(allocator);
    try mesh_attestations.put("peer-1", {});
    try mesh_attestations.put("peer-4", {});
    try mesh_topics.put("/eth2/00000000/beacon_attestation_1/ssz_snappy", mesh_attestations);

    var tracked = std.StringHashMap(void).init(allocator);
    defer tracked.deinit();
    try tracked.put("/eth2/00000000/beacon_block/ssz_snappy", {});
    try tracked.put("/eth2/00000000/beacon_attestation_1/ssz_snappy", {});

    const stats = try computeUniqueGossipsubPeerStats(allocator, &topics, &mesh_topics, &tracked);
    try std.testing.expectEqual(@as(u64, 4), stats.topic_peers);
    try std.testing.expectEqual(@as(u64, 2), stats.mesh_peers);
    try std.testing.expectEqual(@as(u64, 1), stats.mesh_peers_by_topic[@intFromEnum(gossip_topics.GossipTopicType.beacon_block)]);
    try std.testing.expectEqual(@as(u64, 2), stats.mesh_peers_by_topic[@intFromEnum(gossip_topics.GossipTopicType.beacon_attestation)]);
    try std.testing.expectEqual(@as(u64, 2), stats.tracked_topics_with_peers);
    try std.testing.expectEqual(@as(u64, 3), stats.tracked_topic_peers);
}

test "P2pService: gossipsub unique peer stats ignore empty tracked topics" {
    const allocator = std.testing.allocator;

    var topics = std.StringHashMap(std.StringHashMap(void)).init(allocator);
    defer {
        var it = topics.valueIterator();
        while (it.next()) |peer_set| peer_set.deinit();
        topics.deinit();
    }
    const empty_topic = std.StringHashMap(void).init(allocator);
    try topics.put("/eth2/00000000/beacon_block/ssz_snappy", empty_topic);

    var mesh_topics = std.StringHashMap(std.StringHashMap(void)).init(allocator);
    defer mesh_topics.deinit();

    var tracked = std.StringHashMap(void).init(allocator);
    defer tracked.deinit();
    try tracked.put("/eth2/00000000/beacon_block/ssz_snappy", {});

    const stats = try computeUniqueGossipsubPeerStats(allocator, &topics, &mesh_topics, &tracked);
    try std.testing.expectEqual(@as(u64, 0), stats.topic_peers);
    try std.testing.expectEqual(@as(u64, 0), stats.mesh_peers);
    try std.testing.expectEqual(@as(u64, 0), stats.tracked_topics_with_peers);
    try std.testing.expectEqual(@as(u64, 0), stats.tracked_topic_peers);
}

test "P2pService: Eth2SwitchWithoutLightClient compiles with 14 protocols" {
    const protocols = [_]type{
        StatusProtocol,
        StatusV2Protocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
        MetadataV3Protocol,
        BlocksByRangeProtocol,
        BlocksByRootProtocol,
        BlobSidecarsByRangeProtocol,
        BlobSidecarsByRootProtocol,
        DataColumnsByRangeProtocol,
        DataColumnsByRootProtocol,
        GossipsubHandler,
        IdentifyHandler,
    };
    try std.testing.expectEqual(@as(usize, 14), protocols.len);
}

test "P2pService: Eth2SwitchWithLightClient compiles with 18 protocols" {
    // 16 req/resp + 1 gossipsub + 1 identify = 18 protocols.
    const protocols = [_]type{
        StatusProtocol,
        StatusV2Protocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
        MetadataV3Protocol,
        BlocksByRangeProtocol,
        BlocksByRootProtocol,
        BlobSidecarsByRangeProtocol,
        BlobSidecarsByRootProtocol,
        DataColumnsByRangeProtocol,
        DataColumnsByRootProtocol,
        LightClientBootstrapProtocol,
        LightClientUpdatesByRangeProtocol,
        LightClientFinalityUpdateProtocol,
        LightClientOptimisticUpdateProtocol,
        GossipsubHandler,
        IdentifyHandler,
    };
    try std.testing.expectEqual(@as(usize, 18), protocols.len);
}

test "P2pService: all eth2 protocol IDs are unique" {
    const ids = [_][]const u8{
        StatusProtocol.id,
        StatusV2Protocol.id,
        GoodbyeProtocol.id,
        PingProtocol.id,
        MetadataProtocol.id,
        MetadataV3Protocol.id,
        BlocksByRangeProtocol.id,
        BlocksByRootProtocol.id,
        BlobSidecarsByRangeProtocol.id,
        BlobSidecarsByRootProtocol.id,
        DataColumnsByRangeProtocol.id,
        DataColumnsByRootProtocol.id,
        LightClientBootstrapProtocol.id,
        LightClientUpdatesByRangeProtocol.id,
        LightClientFinalityUpdateProtocol.id,
        LightClientOptimisticUpdateProtocol.id,
        GossipsubHandler.id,
        IdentifyHandler.id,
    };
    for (ids, 0..) |id_a, i| {
        for (ids, 0..) |id_b, j| {
            if (i != j) {
                try std.testing.expect(!std.mem.eql(u8, id_a, id_b));
            }
        }
    }
}
