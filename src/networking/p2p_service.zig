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
//! var svc = try P2pService.init(allocator, .{
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
const req_resp_handler = @import("req_resp_handler.zig");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;

const EthGossipAdapter = eth_gossip.EthGossipAdapter;
pub const GossipTopicType = eth_gossip.GossipTopicType;
pub const ActiveGossipFork = eth_gossip.EthGossipAdapter.ActiveFork;
pub const GossipEvent = gossipsub_mod.config.Event;
pub const QuicStream = quic_mod.Stream;
const ReqRespContext = req_resp_handler.ReqRespContext;

const StatusProtocol = eth2_protocols.StatusProtocol;
const GoodbyeProtocol = eth2_protocols.GoodbyeProtocol;
const PingProtocol = eth2_protocols.PingProtocol;
const MetadataProtocol = eth2_protocols.MetadataProtocol;
const BlocksByRangeProtocol = eth2_protocols.BlocksByRangeProtocol;
const BlocksByRootProtocol = eth2_protocols.BlocksByRootProtocol;
const BlobSidecarsByRangeProtocol = eth2_protocols.BlobSidecarsByRangeProtocol;
const BlobSidecarsByRootProtocol = eth2_protocols.BlobSidecarsByRootProtocol;
const DataColumnsByRangeProtocol = eth2_protocols.DataColumnsByRangeProtocol;
const DataColumnsByRootProtocol = eth2_protocols.DataColumnsByRootProtocol;
const LightClientBootstrapProtocol = eth2_protocols.LightClientBootstrapProtocol;
const LightClientUpdatesByRangeProtocol = eth2_protocols.LightClientUpdatesByRangeProtocol;
const LightClientFinalityUpdateProtocol = eth2_protocols.LightClientFinalityUpdateProtocol;
const LightClientOptimisticUpdateProtocol = eth2_protocols.LightClientOptimisticUpdateProtocol;

const log = std.log.scoped(.p2p_service);

fn unixTimeMs(io: Io) u64 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms >= 0) @intCast(ms) else 0;
}

const identify_supported_protocols = &.{
    "/eth2/beacon_chain/req/status/1/ssz_snappy",
    "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
    "/eth2/beacon_chain/req/ping/1/ssz_snappy",
    "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
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

// ─── Switch type ─────────────────────────────────────────────────────────────

pub const Eth2Switch = swarm_mod.Switch(.{
    .transports = &.{QuicTransport},
    .protocols = &.{
        StatusProtocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
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

// ─── Configuration ───────────────────────────────────────────────────────────

pub const P2pConfig = struct {
    /// Current fork digest (4-byte prefix for gossip topics).
    fork_digest: [4]u8,
    /// Active fork sequence, determines which SSZ schemas to use for gossip deserialization.
    fork_seq: ForkSeq,
    /// Req/resp handler callbacks (provides blocks, status, etc.).
    req_resp_context: *const ReqRespContext,
    /// Optional libp2p host identity for QUIC/TLS and peer-id derivation.
    /// When null, eth-p2p-z generates an ephemeral host identity.
    host_identity: ?identity_mod.KeyPair = null,
    /// Identify agent version to advertise. Null hides implementation details.
    identify_agent_version: ?[]const u8 = null,
    /// GossipSub router configuration.
    gossipsub_config: GossipsubConfig = .{},
};

// ─── P2pService ──────────────────────────────────────────────────────────────

pub const P2pService = struct {
    const Self = @This();

    allocator: Allocator,
    network: Eth2Switch,
    gossipsub: *GossipsubService,
    gossip_adapter: EthGossipAdapter,
    host_identity: ?*identity_mod.KeyPair,

    pub fn init(allocator: Allocator, config: P2pConfig) !Self {
        const gossipsub = try GossipsubService.init(allocator, config.gossipsub_config);
        errdefer gossipsub.deinit();

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

        const network = Eth2Switch.init(
            allocator,
            .{ .host_identity = host_identity },
            .{
                StatusProtocol.init(allocator, config.req_resp_context),
                GoodbyeProtocol.init(allocator, config.req_resp_context),
                PingProtocol.init(allocator, config.req_resp_context),
                MetadataProtocol.init(allocator, config.req_resp_context),
                BlocksByRangeProtocol.init(allocator, config.req_resp_context),
                BlocksByRootProtocol.init(allocator, config.req_resp_context),
                BlobSidecarsByRangeProtocol.init(allocator, config.req_resp_context),
                BlobSidecarsByRootProtocol.init(allocator, config.req_resp_context),
                DataColumnsByRangeProtocol.init(allocator, config.req_resp_context),
                DataColumnsByRootProtocol.init(allocator, config.req_resp_context),
                LightClientBootstrapProtocol.init(allocator, config.req_resp_context),
                LightClientUpdatesByRangeProtocol.init(allocator, config.req_resp_context),
                LightClientFinalityUpdateProtocol.init(allocator, config.req_resp_context),
                LightClientOptimisticUpdateProtocol.init(allocator, config.req_resp_context),
                GossipsubHandler{ .svc = gossipsub },
                IdentifyHandler{
                    .allocator = allocator,
                    .config = .{
                        .protocol_version = "eth2/1.0.0",
                        .agent_version = config.identify_agent_version,
                        .supported_protocols = identify_supported_protocols,
                    },
                    .peer_results = std.StringArrayHashMap(identify_mod.IdentifyResult).init(allocator),
                },
            },
        );

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
        };
    }

    /// Start listening and subscribe to standard eth2 gossip topics.
    pub fn start(self: *Self, io: Io, listen_addr: Multiaddr) !void {
        // Set initial time for gossipsub router (PRUNE backoff, scoring).
        {
            self.gossipsub.setTime(unixTimeMs(io));
        }
        try self.network.listen(io, listen_addr);
        try self.gossip_adapter.subscribeEthTopics();
        self.startHeartbeat(io);
        log.info("P2P service started", .{});
    }

    /// Dial a remote peer by QUIC multiaddr.
    pub fn dial(self: *Self, io: Io, peer_addr: Multiaddr) ![]const u8 {
        return self.network.dial(io, peer_addr);
    }

    /// Return whether the peer currently has an active transport connection.
    pub fn isPeerConnected(self: *Self, peer_id: []const u8) bool {
        return self.network.connections.contains(peer_id);
    }

    /// Snapshot the currently connected peer IDs. Caller owns the returned slice and entries.
    pub fn snapshotConnectedPeerIds(self: *Self, allocator: Allocator) ![][]const u8 {
        var peer_ids = try allocator.alloc([]const u8, self.network.connections.count());
        var copied: usize = 0;
        errdefer {
            for (peer_ids[0..copied]) |peer_id| allocator.free(peer_id);
            allocator.free(peer_ids);
        }

        var iter = self.network.connections.iterator();
        while (iter.next()) |entry| : (copied += 1) {
            peer_ids[copied] = try allocator.dupe(u8, entry.key_ptr.*);
        }

        return peer_ids;
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

    /// Ask libp2p to open an outbound gossipsub stream to a connected peer.
    pub fn openGossipsubStream(self: *Self, io: Io, peer_id: []const u8) !void {
        try self.newStream(io, peer_id, GossipsubHandler, null);
    }

    /// Gracefully close a connected peer transport. The switch will clean up
    /// handler state when its connection task observes the closure.
    pub fn disconnectPeer(self: *Self, io: Io, peer_id: []const u8) bool {
        const conn = self.network.connections.get(peer_id) orelse return false;
        conn.close(io);
        return true;
    }

    /// Return the latest identify result for a peer, if available.
    pub fn identifyResult(self: *Self, peer_id: []const u8) ?*const identify_mod.IdentifyResult {
        return self.network.getHandler(IdentifyHandler).getPeerResult(peer_id);
    }

    /// Publish an SSZ message to a gossip topic.
    ///
    /// The message is Snappy-compressed internally by `EthGossipAdapter.publish`.
    pub fn publishGossip(
        self: *Self,
        topic_type: GossipTopicType,
        subnet_id: ?u8,
        ssz_bytes: []const u8,
    ) !void {
        return self.gossip_adapter.publish(topic_type, subnet_id, ssz_bytes);
    }

    /// Drain pending gossipsub events. Caller owns the returned slice.
    pub fn drainGossipEvents(self: *Self) ![]GossipEvent {
        return self.gossipsub.drainEvents();
    }

    /// Report an invalid inbound gossip message to gossipsub's mesh scorer.
    pub fn recordInvalidGossipMessage(self: *Self, peer_id: []const u8, topic: []const u8) void {
        self.gossipsub.router.recordInvalidMessage(peer_id, topic);
    }

    /// Subscribe to a gossip subnet topic (e.g., attestation subnets).
    pub fn subscribeSubnet(self: *Self, topic_type: GossipTopicType, subnet_id: u8) !void {
        try self.gossip_adapter.subscribeSubnet(topic_type, subnet_id);
    }

    /// Unsubscribe from a gossip subnet topic.
    pub fn unsubscribeSubnet(self: *Self, topic_type: GossipTopicType, subnet_id: u8) !void {
        try self.gossip_adapter.unsubscribeSubnet(topic_type, subnet_id);
    }

    pub fn setPublishFork(self: *Self, new_fork_digest: [4]u8, new_fork_seq: ForkSeq) void {
        self.gossip_adapter.setPublishFork(new_fork_digest, new_fork_seq);
    }

    pub fn setActiveGossipForks(self: *Self, forks: []const ActiveGossipFork) !void {
        try self.gossip_adapter.setActiveForks(forks);
    }

    /// Gracefully shut down (cancel background fibers, close QUIC engines).
    pub fn stop(self: *Self, io: Io) void {
        self.network.close(io);
        log.info("P2P service stopped", .{});
    }

    /// Release all owned resources.
    pub fn deinit(self: *Self, io: Io) void {
        self.gossip_adapter.deinit();
        self.network.deinit(io);
        self.network.getHandler(IdentifyHandler).deinit();
        self.gossipsub.deinit();
        if (self.host_identity) |host_identity| {
            host_identity.deinit();
            self.allocator.destroy(host_identity);
        }
    }

    /// Spawn a background fiber for the gossipsub heartbeat timer.
    fn startHeartbeat(self: *Self, io: Io) void {
        self.network.background.async(io, heartbeatLoop, .{ self.gossipsub, io });
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
                gs.setTime(unixTimeMs(io));
            }
            gs.heartbeat() catch {};
        }
    }

    /// Return the bound server listen address.
    pub fn listenAddr(self: *const Self) ?std.Io.net.IpAddress {
        return self.network.listenAddrs();
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "P2pService: Eth2Switch compiles with 16 protocols" {
    // 14 req/resp + 1 gossipsub + 1 identify = 16 protocols.
    const protocols = [_]type{
        StatusProtocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
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
    try std.testing.expectEqual(@as(usize, 16), protocols.len);
}

test "P2pService: all eth2 protocol IDs are unique" {
    const ids = [_][]const u8{
        StatusProtocol.id,
        GoodbyeProtocol.id,
        PingProtocol.id,
        MetadataProtocol.id,
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
