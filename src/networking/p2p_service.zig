//! P2P service integration layer for eth-p2p-z (quiche/zio runtime API).
//!
//! Bridges eth-p2p-z's RUNTIME Switch with lodestar-z's networking stack:
//! - `P2pService` owns a `quic.QuicEndpoint` + a `swarm.Switch`, registers all
//!   eth2 req/resp protocol handlers + identify + the gossipsub inbound service,
//!   and holds an `EthGossipAdapter` for subscribe/publish.
//! - Inbound gossip events are drained from the gossipsub `Service` and routed
//!   by the node's GossipHandler.
//! - Req/resp messages are dispatched by each `Eth2Protocol` handler into
//!   `req_resp_handler`.
//!
//! PORTING NOTE (option B): our eth-p2p-z branch exposes a RUNTIME Switch
//! (`swarm.Switch.init(alloc, io, *QuicEndpoint)` + `addProtocolService`), not
//! the comptime `Switch(.{ .transports, .protocols })` generic the ChainSafe
//! lsquic variant used. This file was rewritten to compose the runtime Switch
//! directly. The PUBLIC `P2pService` API (what `node/` calls) is preserved; the
//! internals were swapped. Methods whose full behaviour needs deep per-peer
//! Switch integration not yet surfaced by our branch (connected-peer snapshot,
//! per-protocol outbound dial, peer disconnect) are implemented as far as the
//! runtime API allows and otherwise return conservative defaults — enough to
//! compile the `networking` module and pass its unit tests. Live dial/listen
//! and gossip propagation are wired through the real endpoint/switch/service.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const libp2p = @import("zig-libp2p");
const quic_mod = libp2p.quic;
const identity_mod = libp2p.identity;
const gossipsub_mod = libp2p.gossipsub;
const compat = @import("gossipsub_compat.zig");
const GossipsubService = compat.Service;
const GossipsubConfig = compat.Config;
const GossipsubFrameDecoder = compat.FrameDecoder;
const GossipsubRpc = libp2p.protobuf.rpc;
const swarm_mod = libp2p.swarm;
const protocols_mod = libp2p.protocols;
const identify_mod = libp2p.identify;
const Multiaddr = @import("multiaddr").multiaddr.Multiaddr;
const PeerId = libp2p.PeerId;

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
pub const GossipEvent = compat.config.Event;
pub const GossipValidationResult = compat.config.ValidationResult;
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

/// [lodestar-compat] identify result surface. Our branch's identify protocol
/// does not yet retain per-peer identify results; this placeholder satisfies
/// `node`'s `identifyResult(...).agentVersion()` call site. `agentVersion()`
/// returns null until per-peer identify capture is wired through the runtime
/// Switch.
pub const IdentifyResult = struct {
    agent_version: ?[]const u8 = null,

    pub fn agentVersion(self: *const IdentifyResult) ?[]const u8 {
        return self.agent_version;
    }
};

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

fn buildTrackedSubscriptionAnnouncementFrame(
    allocator: Allocator,
    tracked_subscriptions: *const std.StringHashMap(void),
) !?[]const u8 {
    if (tracked_subscriptions.count() == 0) return null;

    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);

    var chunk: [64]?GossipsubRpc.RPC.SubOpts = undefined;
    var chunk_len: usize = 0;
    var iter = tracked_subscriptions.keyIterator();
    while (iter.next()) |key| {
        chunk[chunk_len] = .{ .subscribe = true, .topicid = key.* };
        chunk_len += 1;
        if (chunk_len == chunk.len) {
            var rpc_msg = GossipsubRpc.RPC{ .subscriptions = chunk[0..chunk_len] };
            const frame = try compat.encodeRpc(allocator, &rpc_msg);
            defer allocator.free(frame);
            try encoded.appendSlice(allocator, frame);
            chunk_len = 0;
        }
    }

    if (chunk_len != 0) {
        var rpc_msg = GossipsubRpc.RPC{ .subscriptions = chunk[0..chunk_len] };
        const frame = try compat.encodeRpc(allocator, &rpc_msg);
        defer allocator.free(frame);
        try encoded.appendSlice(allocator, frame);
    }

    return try encoded.toOwnedSlice(allocator);
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

/// The full ordered list of eth2 req/resp protocol handler types we register on
/// the runtime Switch. The light-client subset is gated at registration time.
const core_reqresp_protocols = [_]type{
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
};

const light_client_protocols = [_]type{
    LightClientBootstrapProtocol,
    LightClientUpdatesByRangeProtocol,
    LightClientFinalityUpdateProtocol,
    LightClientOptimisticUpdateProtocol,
};

// ─── Runtime network composition ──────────────────────────────────────────────

/// Owns the QUIC endpoint + Switch and the heap-allocated req/resp protocol
/// handler instances registered on it. Replaces the old comptime `Switch(.{...})`
/// + `Network` union.
const Net = struct {
    allocator: Allocator,
    endpoint: *quic_mod.QuicEndpoint,
    sw: *swarm_mod.Switch,
    identify_handler: *identify_mod.IdentifyHandler,
    /// Inbound /meshsub stream handler, registered on the Switch for every
    /// supported gossipsub version. Heap-owned for a stable address.
    gossip_handler: *compat.Handler,
    /// Background fiber group for non-blocking stream/identify tasks.
    background: std.Io.Group = .init,
    /// Last bound listen address, recorded after `listen`.
    bound_addr: ?std.Io.net.IpAddress = null,

    fn deinit(self: *Net, io: Io) void {
        self.background.cancel(io);
        self.sw.deinit();
        self.endpoint.deinit();
        self.identify_handler.deinit();
        self.allocator.destroy(self.identify_handler);
        self.allocator.destroy(self.gossip_handler);
    }

    fn close(self: *Net, io: Io) void {
        self.sw.closeListener(io);
    }

    fn listen(self: *Net, io: Io, listen_addr: Multiaddr) !void {
        _ = io;
        try self.sw.listen(listen_addr);
        self.bound_addr = self.endpoint.localAddr();
    }

    fn listenAddrs(self: *const Net) ?std.Io.net.IpAddress {
        return self.bound_addr;
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

    allocator: Allocator,
    net: Net,
    gossipsub: *GossipsubService,
    gossip_adapter: EthGossipAdapter,
    host_identity: ?*identity_mod.KeyPair,
    /// Heap-allocated req/resp protocol handler instances registered on the
    /// Switch (one per protocol id). Kept so they outlive the Switch and are
    /// freed on deinit.
    reqresp_handlers: std.ArrayListUnmanaged(ReqRespHandlerBox),
    req_resp_self_limiter: SelfRateLimiter,
    lifecycle_mutex: std.Io.Mutex = .init,
    stopped: bool = false,
    deinitialized: bool = false,

    /// Type-erased owner of a heap-allocated req/resp handler instance so the
    /// service can free them generically on teardown.
    const ReqRespHandlerBox = struct {
        ptr: *anyopaque,
        destroyFn: *const fn (Allocator, *anyopaque) void,

        fn destroy(self: ReqRespHandlerBox, allocator: Allocator) void {
            self.destroyFn(allocator, self.ptr);
        }
    };

    pub const GossipsubMetricsSnapshot = struct {
        outbound_streams: u64 = 0,
        tracked_subscriptions: u64 = 0,
        router_subscriptions: u64 = 0,
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

    pub fn hasSubscriptionTrackingDrift(snapshot: GossipsubMetricsSnapshot) bool {
        return snapshot.tracked_subscriptions != snapshot.router_subscriptions;
    }

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

        // Build the QUIC endpoint. With a host identity we bind TLS to it;
        // without one we synthesize an ephemeral key so the endpoint can still
        // be constructed (matches the documented "ephemeral host identity"
        // behaviour). The endpoint borrows the key, so it must outlive the
        // endpoint — `host_identity` (kept on Self) provides that lifetime; for
        // the ephemeral case we own a key for the service lifetime too.
        var ephemeral_key: ?*identity_mod.KeyPair = null;
        errdefer if (ephemeral_key) |k| {
            k.deinit();
            allocator.destroy(k);
        };
        const key_for_endpoint: *identity_mod.KeyPair = if (host_identity) |hk| hk else blk: {
            const k = try allocator.create(identity_mod.KeyPair);
            errdefer allocator.destroy(k);
            k.* = try identity_mod.KeyPair.generate(.SECP256K1);
            ephemeral_key = k;
            break :blk k;
        };

        const endpoint = try quic_mod.QuicEndpoint.initWithIdentity(allocator, io, key_for_endpoint, .{});
        errdefer endpoint.deinit();

        const sw = try swarm_mod.Switch.init(allocator, io, endpoint);
        errdefer sw.deinit();

        // Identify handler (heap-owned so its address is stable for the Switch
        // service registration that borrows it).
        const identify_handler = try allocator.create(identify_mod.IdentifyHandler);
        errdefer allocator.destroy(identify_handler);
        identify_handler.* = identify_mod.IdentifyHandler.initWithOptions(allocator, .{
            .protocol_version = "eth2/1.0.0",
            .agent_version = config.identify_agent_version orelse "eth-p2p-z/0.1.0",
            .protocols = if (config.disable_light_client_server)
                identify_supported_protocols_without_light_client
            else
                identify_supported_protocols_with_light_client,
        });
        errdefer identify_handler.deinit();

        var reqresp_handlers = std.ArrayListUnmanaged(ReqRespHandlerBox).empty;
        errdefer {
            for (reqresp_handlers.items) |box| box.destroy(allocator);
            reqresp_handlers.deinit(allocator);
        }

        // Register all core req/resp protocol handlers on the Switch.
        inline for (core_reqresp_protocols) |Protocol| {
            try registerReqRespProtocol(allocator, sw, Protocol, config, &reqresp_handlers);
        }
        if (!config.disable_light_client_server) {
            inline for (light_client_protocols) |Protocol| {
                try registerReqRespProtocol(allocator, sw, Protocol, config, &reqresp_handlers);
            }
        }

        // Register identify as a stream-handler service.
        try sw.addProtocolService(
            identify_mod.protocol_id,
            protocols_mod.streamHandlerService(
                identify_mod.IdentifyHandler,
                identify_mod.IdentifyHandler.run,
                identify_handler,
            ),
        );

        // Register the gossipsub inbound stream handler for every supported
        // /meshsub version. Without this a beacon peer (e.g. Lighthouse) opens a
        // /meshsub stream, finds no handler, and bans us with "does not support
        // gossipsub". The handler reads inbound RPC frames and ingests published
        // messages into the gossip event queue.
        const gossip_handler = try allocator.create(compat.Handler);
        errdefer allocator.destroy(gossip_handler);
        gossip_handler.* = .{ .svc = gossipsub };
        inline for (gossipsub_mod.supported_protocols) |meshsub_id| {
            try sw.addProtocolService(
                meshsub_id,
                protocols_mod.streamHandlerService(
                    compat.Handler,
                    compat.Handler.run,
                    gossip_handler,
                ),
            );
        }

        const gossip_adapter = EthGossipAdapter.init(
            allocator,
            gossipsub,
            config.fork_digest,
            config.fork_seq,
        );

        return .{
            .allocator = allocator,
            .net = .{
                .allocator = allocator,
                .endpoint = endpoint,
                .sw = sw,
                .identify_handler = identify_handler,
                .gossip_handler = gossip_handler,
            },
            .gossipsub = gossipsub,
            .gossip_adapter = gossip_adapter,
            .host_identity = if (host_identity) |hk| hk else ephemeral_key,
            .reqresp_handlers = reqresp_handlers,
            .req_resp_self_limiter = SelfRateLimiter.init(allocator),
        };
    }

    /// Heap-allocate a req/resp protocol handler instance and register it on the
    /// Switch as a stream-handler service for its inbound id. The handler's
    /// `handleInbound(io, *Stream, ctx)` is adapted to the Switch's `run` shape.
    fn registerReqRespProtocol(
        allocator: Allocator,
        sw: *swarm_mod.Switch,
        comptime Protocol: type,
        config: P2pConfig,
        boxes: *std.ArrayListUnmanaged(ReqRespHandlerBox),
    ) !void {
        const inst = try allocator.create(Protocol);
        errdefer allocator.destroy(inst);
        inst.* = Protocol.init(allocator, config.req_resp_context, config.req_resp_server_policy);

        const Adapter = struct {
            fn run(p: *Protocol, io: Io, stream: *quic_mod.Stream) anyerror!void {
                // The Switch supplies the negotiated stream; req/resp handlers
                // read the request, serve, and close. The inbound peer-id
                // context is not threaded through the runtime Switch here, so an
                // empty context is passed (handlers tolerate it).
                try p.handleInbound(io, stream, .{ .peer_id = @as([]const u8, &.{}) });
            }
            fn destroy(a: Allocator, ptr: *anyopaque) void {
                a.destroy(@as(*Protocol, @ptrCast(@alignCast(ptr))));
            }
        };

        try sw.addProtocolService(
            Protocol.id,
            protocols_mod.streamHandlerService(Protocol, Adapter.run, inst),
        );
        try boxes.append(allocator, .{ .ptr = inst, .destroyFn = &Adapter.destroy });
    }

    /// Start listening and subscribe to standard eth2 gossip topics.
    pub fn start(self: *Self, io: Io, listen_addr: Multiaddr) !void {
        // Set initial time for gossipsub router (PRUNE backoff, scoring).
        self.gossipsub.setTime(io, unixTimeMs(io));
        try self.net.listen(io, listen_addr);
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

    pub fn announceTrackedSubscriptionsToConnectedPeers(self: *Self, io: Io) void {
        self.gossipsub.state_mu.lockUncancelable(io);
        defer self.gossipsub.state_mu.unlock(io);

        if (self.gossipsub.outbound_streams.count() == 0) return;

        const frame = buildTrackedSubscriptionAnnouncementFrame(
            self.allocator,
            &self.gossipsub.tracked_subscriptions,
        ) catch |err| {
            log.warn("failed to encode tracked gossipsub subscription announcement: {}", .{err});
            return;
        } orelse return;
        defer self.allocator.free(frame);

        std.debug.assert(self.gossipsub.active_io == null);
        self.gossipsub.active_io = io;
        defer self.gossipsub.active_io = null;

        var peer_iter = self.gossipsub.outbound_streams.keyIterator();
        while (peer_iter.next()) |peer_key| {
            if (!self.gossipsub.sendRpc(peer_key.*, frame)) {
                log.warn("failed to announce tracked gossipsub subscriptions to peer {s}", .{peer_key.*});
            }
        }
    }

    pub fn gossipsubMetricsSnapshot(self: *Self, io: Io) GossipsubMetricsSnapshot {
        self.gossipsub.state_mu.lockUncancelable(io);
        defer self.gossipsub.state_mu.unlock(io);

        var snapshot: GossipsubMetricsSnapshot = .{
            .outbound_streams = @intCast(self.gossipsub.outbound_streams.count()),
            .tracked_subscriptions = @intCast(self.gossipsub.tracked_subscriptions.count()),
            .router_subscriptions = @intCast(self.gossipsub.router.subscriptions.count()),
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

    pub fn logGossipsubSubscriptionDiagnostics(self: *Self, io: Io) void {
        var tracked_sample: ?[]const u8 = null;
        var router_sample: ?[]const u8 = null;

        self.gossipsub.state_mu.lockUncancelable(io);
        defer self.gossipsub.state_mu.unlock(io);

        var tracked_iter = self.gossipsub.tracked_subscriptions.keyIterator();
        while (tracked_iter.next()) |topic_key| {
            if (tracked_sample == null) tracked_sample = topic_key.*;
        }

        var router_iter = self.gossipsub.router.subscriptions.keyIterator();
        while (router_iter.next()) |topic_key| {
            if (router_sample == null) router_sample = topic_key.*;
        }

        log.warn(
            "gossipsub subscription tracking drift: tracked_subscriptions={d} router_subscriptions={d} tracked_sample={s} router_sample={s}",
            .{
                self.gossipsub.tracked_subscriptions.count(),
                self.gossipsub.router.subscriptions.count(),
                tracked_sample orelse "<none>",
                router_sample orelse "<none>",
            },
        );
    }

    /// Dial a remote peer by QUIC multiaddr. Caller owns the returned peer ID.
    pub fn dial(self: *Self, io: Io, peer_addr: Multiaddr) ![]const u8 {
        _ = io;
        const conn = try self.net.sw.dial(peer_addr, .{});
        // NOTE: the Switch auto-starts inbound stream dispatch on every connection
        // (libp2p connections are bidirectional — the remote opens metadata/ping/
        // status/identify streams back to us). No explicit startInboundDispatcher
        // needed here; see Switch.auto_inbound_dispatch.
        // Return the remote peer-id in the raw-multihash []const u8 form used
        // throughout the networking layer. Caller owns the slice.
        var buf: [64]u8 = undefined;
        const pid = conn.peerId();
        const bytes = pid.toBytes(&buf) catch return self.allocator.dupe(u8, &.{});
        return self.allocator.dupe(u8, bytes);
    }

    /// Return whether the peer currently has an active transport connection.
    pub fn isPeerConnected(self: *Self, io: Io, peer_id: []const u8) bool {
        _ = io;
        const pid = PeerId.fromBytes(peer_id) catch return false;
        return self.net.sw.isConnected(pid);
    }

    /// Snapshot the currently connected peer IDs. Caller owns the returned slice and entries.
    pub fn snapshotConnectedPeerIds(self: *Self, io: Io, allocator: Allocator) ![][]const u8 {
        _ = io;
        const pids = try self.net.sw.snapshotPeerIds(allocator);
        defer allocator.free(pids);
        var out: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (out.items) |b| allocator.free(b);
            out.deinit(allocator);
        }
        var buf: [64]u8 = undefined;
        for (pids) |pid| {
            const bytes = try pid.toBytes(&buf);
            try out.append(allocator, try allocator.dupe(u8, bytes));
        }
        return out.toOwnedSlice(allocator);
    }

    /// Open a new outbound stream for a protocol to a connected peer.
    ///
    /// Gossipsub: opens a long-lived /meshsub stream and registers it with the
    /// gossip service as this peer's outbound sink (the router then frames RPCs
    /// onto it via sendRpc). Identify: opens the identify stream, reads the
    /// peer's pushed Identify message (the libp2p identify exchange), and closes.
    pub fn newStream(
        self: *Self,
        io: Io,
        peer_id: []const u8,
        comptime Protocol: type,
        ssz_payload: ?[]const u8,
    ) !void {
        _ = ssz_payload;
        const pid = PeerId.fromBytes(peer_id) catch return error.PeerNotConnected;
        const conn = self.net.sw.connectionForPeer(pid) orelse return error.PeerNotConnected;

        if (Protocol == compat.Handler) {
            const stream = try conn.openProtocolStream(Protocol.id, .{});
            self.gossipsub.handleOutbound(io, stream, .{ .peer_id = peer_id }) catch |err| {
                stream.close(io) catch {};
                return err;
            };
        } else if (Protocol == identify_mod.IdentifyHandler) {
            const stream = try conn.openProtocolStream(identify_mod.protocol_id, .{});
            defer stream.close(io) catch {};
            var owned = try identify_mod.readIdentify(self.allocator, io, stream);
            owned.deinit(self.allocator);
        } else {
            @compileError("newStream: unsupported protocol " ++ @typeName(Protocol));
        }
    }

    /// Open a negotiated outbound stream for a given protocol ID.
    ///
    /// Finds the live connection for `peer_id` and opens an outbound stream,
    /// negotiating `protocol_id` via multistream-select. Returns the raw QUIC
    /// stream handle; the caller (req/resp outbound flow) writes the request,
    /// reads the response, and closes it. This is what drives outbound Status /
    /// ping / metadata / blocks-by-range against the peer.
    pub fn dialProtocol(self: *Self, io: Io, peer_id: []const u8, protocol_id: []const u8) !*quic_mod.Stream {
        _ = io;
        const pid = PeerId.fromBytes(peer_id) catch return error.PeerNotConnected;
        const conn = self.net.sw.connectionForPeer(pid) orelse return error.PeerNotConnected;
        return conn.openProtocolStream(protocol_id, .{});
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
        try self.newStream(io, peer_id, compat.Handler, null);
    }

    /// Open an outbound gossipsub stream without blocking the caller.
    pub fn openGossipsubStreamAsync(self: *Self, io: Io, peer_id: []const u8) !void {
        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);
        self.net.background.concurrent(io, gossipsubStreamTask, .{ self, io, owned_peer_id }) catch |err| {
            log.debug("Failed to spawn concurrent gossipsub stream task: {}", .{err});
            self.net.background.async(io, gossipsubStreamTask, .{ self, io, owned_peer_id });
        };
    }

    fn gossipsubStreamTask(self: *Self, io: Io, peer_id: []u8) void {
        defer self.allocator.free(peer_id);
        self.openGossipsubStream(io, peer_id) catch |err| {
            log.debug("Failed to open outbound gossipsub stream to {s}: {}", .{ peer_id, err });
        };
    }

    /// Request libp2p identify data from a connected peer.
    pub fn requestIdentify(self: *Self, io: Io, peer_id: []const u8) !void {
        try self.newStream(io, peer_id, identify_mod.IdentifyHandler, null);
    }

    /// Request libp2p identify data without blocking the caller.
    pub fn requestIdentifyAsync(self: *Self, io: Io, peer_id: []const u8) !void {
        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);
        self.net.background.concurrent(io, identifyStreamTask, .{ self, io, owned_peer_id }) catch |err| {
            log.debug("Failed to spawn concurrent identify task: {}", .{err});
            self.net.background.async(io, identifyStreamTask, .{ self, io, owned_peer_id });
        };
    }

    fn identifyStreamTask(self: *Self, io: Io, peer_id: []u8) void {
        defer self.allocator.free(peer_id);
        self.requestIdentify(io, peer_id) catch |err| {
            log.debug("Failed to open outbound identify stream to {s}: {}", .{ peer_id, err });
        };
    }

    /// Gracefully close a connected peer transport.
    pub fn disconnectPeer(self: *Self, io: Io, peer_id: []const u8) bool {
        _ = io;
        const pid = PeerId.fromBytes(peer_id) catch return false;
        const conn = self.net.sw.connectionForPeer(pid) orelse return false;
        conn.close(0, "disconnect") catch return false;
        return true;
    }

    /// Return the latest identify result for a peer, if available.
    pub fn identifyResult(self: *Self, peer_id: []const u8) ?*const IdentifyResult {
        _ = self;
        _ = peer_id;
        return null;
    }

    /// Publish an SSZ message to a gossip topic.
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
        self.lifecycle_mutex.lockUncancelable(io);
        defer self.lifecycle_mutex.unlock(io);

        if (self.deinitialized) return;
        self.stopLocked(io);
    }

    /// Release all owned resources.
    pub fn deinit(self: *Self, io: Io) void {
        self.lifecycle_mutex.lockUncancelable(io);
        if (self.deinitialized) {
            self.lifecycle_mutex.unlock(io);
            return;
        }
        self.stopLocked(io);
        self.deinitialized = true;
        self.lifecycle_mutex.unlock(io);

        self.gossip_adapter.deinit();
        // Gossipsub holds no reference into the Switch in this facade, so order
        // is flexible. Tear down the network, then the gossipsub service.
        self.net.deinit(io);
        for (self.reqresp_handlers.items) |box| box.destroy(self.allocator);
        self.reqresp_handlers.deinit(self.allocator);
        self.gossipsub.deinit(io);
        self.req_resp_self_limiter.deinit();
        if (self.host_identity) |host_identity| {
            host_identity.deinit();
            self.allocator.destroy(host_identity);
        }
    }

    fn stopLocked(self: *Self, io: Io) void {
        if (self.stopped) return;
        self.net.close(io);
        self.stopped = true;
        log.info("p2p service stopped", .{});
    }

    /// Schedule work on the switch background group.
    pub fn spawnBackground(self: *Self, io: Io, comptime func: anytype, args: anytype) void {
        self.net.background.concurrent(io, func, args) catch |err| {
            log.warn("background concurrency unavailable; falling back to cooperative async: {}", .{err});
            self.net.background.async(io, func, args);
        };
    }

    /// Spawn a background fiber for the gossipsub heartbeat timer.
    fn startHeartbeat(self: *Self, io: Io) void {
        self.net.background.async(io, heartbeatLoop, .{ self.gossipsub, io });
    }

    fn heartbeatLoop(gs: *GossipsubService, io: Io) void {
        while (true) {
            const t: Io.Timeout = .{ .duration = .{
                .raw = Io.Duration.fromMilliseconds(700),
                .clock = .awake,
            } };
            t.sleep(io) catch return;
            gs.setTime(io, unixTimeMs(io));
            gs.heartbeat(io) catch {};
        }
    }

    /// Return the bound server listen address.
    pub fn listenAddr(self: *const Self) ?std.Io.net.IpAddress {
        return self.net.listenAddrs();
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "P2pService: tracked subscription announcement frame is null when there are no topics" {
    var tracked = std.StringHashMap(void).init(std.testing.allocator);
    defer tracked.deinit();

    const frame = try buildTrackedSubscriptionAnnouncementFrame(std.testing.allocator, &tracked);
    try std.testing.expect(frame == null);
}

test "P2pService: tracked subscription announcement frame encodes tracked topics" {
    var tracked = std.StringHashMap(void).init(std.testing.allocator);
    defer tracked.deinit();
    try tracked.put("/eth2/00000000/beacon_block/ssz_snappy", {});
    try tracked.put("/eth2/00000000/beacon_attestation_1/ssz_snappy", {});

    const frame = (try buildTrackedSubscriptionAnnouncementFrame(std.testing.allocator, &tracked)).?;
    defer std.testing.allocator.free(frame);

    var decoder = GossipsubFrameDecoder.init(std.testing.allocator);
    defer decoder.deinit();
    try decoder.feed(frame);

    const payload = (try decoder.next()) orelse return error.ExpectedFrame;
    defer std.testing.allocator.free(payload);

    var reader = try GossipsubRpc.RPCReader.init(payload);
    var saw_block = false;
    var saw_attestation = false;
    var count: usize = 0;
    while (reader.subscriptionsNext()) |sub| {
        try std.testing.expect(sub.getSubscribe());
        const topic = sub.getTopicid();
        if (std.mem.eql(u8, topic, "/eth2/00000000/beacon_block/ssz_snappy")) saw_block = true;
        if (std.mem.eql(u8, topic, "/eth2/00000000/beacon_attestation_1/ssz_snappy")) saw_attestation = true;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expect(saw_block);
    try std.testing.expect(saw_attestation);
    try std.testing.expect((try decoder.next()) == null);
}

test "P2pService: tracked subscription announcement frame chunks snapshots larger than 64 topics" {
    var tracked = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var iter = tracked.keyIterator();
        while (iter.next()) |topic| std.testing.allocator.free(topic.*);
        tracked.deinit();
    }

    for (0..65) |i| {
        const topic = try std.fmt.allocPrint(std.testing.allocator, "/eth2/00000000/beacon_attestation_{d}/ssz_snappy", .{i});
        try tracked.put(topic, {});
    }

    const frame = (try buildTrackedSubscriptionAnnouncementFrame(std.testing.allocator, &tracked)).?;
    defer std.testing.allocator.free(frame);

    var decoder = GossipsubFrameDecoder.init(std.testing.allocator);
    defer decoder.deinit();
    try decoder.feed(frame);

    var frame_count: usize = 0;
    var topic_count: usize = 0;
    while (try decoder.next()) |payload| {
        defer std.testing.allocator.free(payload);
        frame_count += 1;
        var reader = try GossipsubRpc.RPCReader.init(payload);
        while (reader.subscriptionsNext()) |sub| {
            try std.testing.expect(sub.getSubscribe());
            topic_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), frame_count);
    try std.testing.expectEqual(@as(usize, 65), topic_count);
}

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

test "P2pService: subscription tracking drift only checks local subscription state" {
    const clean: P2pService.GossipsubMetricsSnapshot = .{
        .tracked_subscriptions = 2,
        .router_subscriptions = 2,
        .known_topics = 19,
        .topic_peers = 19,
        .tracked_topics_with_peers = 0,
    };
    try std.testing.expect(!P2pService.hasSubscriptionTrackingDrift(clean));

    const drift: P2pService.GossipsubMetricsSnapshot = .{
        .tracked_subscriptions = 2,
        .router_subscriptions = 3,
        .known_topics = 19,
        .topic_peers = 19,
        .tracked_topics_with_peers = 0,
    };
    try std.testing.expect(P2pService.hasSubscriptionTrackingDrift(drift));
}

test "P2pService: core req/resp handler count is twelve" {
    try std.testing.expectEqual(@as(usize, 12), core_reqresp_protocols.len);
    try std.testing.expectEqual(@as(usize, 4), light_client_protocols.len);
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
        compat.Handler.id,
        identify_mod.protocol_id,
    };
    for (ids, 0..) |id_a, i| {
        for (ids, 0..) |id_b, j| {
            if (i != j) {
                try std.testing.expect(!std.mem.eql(u8, id_a, id_b));
            }
        }
    }
}
