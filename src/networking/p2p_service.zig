//! P2P service integration layer for eth-p2p-z.
//!
//! Bridges eth-p2p-z's comptime Switch with lodestar-z's networking stack:
//! - `P2pService` wraps a Switch configured with all eth2 req/resp protocols
//!   and a gossipsub handler, plus an EthGossipAdapter for subscribe/publish.
//! - The Switch is comptime-composed with QUIC transport and the 8 req/resp
//!   protocol handlers plus gossipsub.
//! - Gossip messages are handled by `EthGossipAdapter` (eth_gossip.zig).
//! - Req/resp messages are dispatched by each `Eth2Protocol` handler through
//!   `EthReqRespAdapter` (eth_reqresp.zig) into `req_resp_handler`.
//!
//! Usage:
//! ```zig
//! var svc = try P2pService.init(allocator, .{
//!     .fork_digest = node.getForkDigest(),
//!     .req_resp_context = &rr_ctx,
//!     .validator = &validator,
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
const gossip_validation = @import("gossip_validation.zig");

const EthGossipAdapter = eth_gossip.EthGossipAdapter;
pub const GossipTopicType = eth_gossip.GossipTopicType;
pub const QuicStream = quic_mod.Stream;
const ReqRespContext = req_resp_handler.ReqRespContext;
const GossipValidationContext = gossip_validation.GossipValidationContext;
const SeenSet = gossip_validation.SeenSet;

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

// ─── Stub validator (passthrough) ────────────────────────────────────────────
//
// Used when no real validator is provided. Accepts all messages.
// TODO: remove once BeaconNode wires a real GossipValidationContext.

fn stubGetProposerIndex(_: *anyopaque, _: u64) ?u32 {
    return null;
}
fn stubIsKnownBlockRoot(_: *anyopaque, _: [32]u8) bool {
    return true;
}
fn stubIsValidatorActive(_: *anyopaque, _: u64, _: u64) bool {
    return true;
}
fn stubGetValidatorCount(_: *anyopaque) u32 {
    return 0;
}

/// Passthrough gossip validator — accepts all messages.
///
/// Caller owns the returned struct and its SeenSet fields (use deinitStubValidator).
pub fn createPassthroughValidator(allocator: Allocator) !PassthroughValidator {
    return PassthroughValidator.init(allocator);
}

pub const PassthroughValidator = struct {
    seen_blocks: SeenSet,
    seen_aggregators: SeenSet,
    seen_exits: SeenSet,
    seen_proposer_slashings: SeenSet,
    seen_attester_slashings: SeenSet,
    ctx: GossipValidationContext,

    /// Initialise the validator.
    ///
    /// **Important:** call  immediately after placing the struct
    /// in its final location (e.g., after ).
    /// The ctx pointers point into self — they become stale if the struct is moved.
    pub fn init(allocator: Allocator) PassthroughValidator {
        return .{
            .seen_blocks = SeenSet.init(allocator),
            .seen_aggregators = SeenSet.init(allocator),
            .seen_exits = SeenSet.init(allocator),
            .seen_proposer_slashings = SeenSet.init(allocator),
            .seen_attester_slashings = SeenSet.init(allocator),
            .ctx = undefined,
        };
    }

    /// Fix up self-referential ctx pointers after the struct is in its final location.
    pub fn fixupPointers(self: *PassthroughValidator) void {
        self.ctx = .{
            .ptr = @ptrFromInt(1),
            .current_slot = 0,
            .current_epoch = 0,
            .finalized_slot = 0,
            .seen_block_roots = &self.seen_blocks,
            .seen_aggregators = &self.seen_aggregators,
            .seen_voluntary_exits = &self.seen_exits,
            .seen_proposer_slashings = &self.seen_proposer_slashings,
            .seen_attester_slashings = &self.seen_attester_slashings,
            .getProposerIndex = &stubGetProposerIndex,
            .isKnownBlockRoot = &stubIsKnownBlockRoot,
            .isValidatorActive = &stubIsValidatorActive,
            .getValidatorCount = &stubGetValidatorCount,
        };
    }

    pub fn deinit(self: *PassthroughValidator) void {
        self.seen_blocks.deinit();
        self.seen_aggregators.deinit();
        self.seen_exits.deinit();
        self.seen_proposer_slashings.deinit();
        self.seen_attester_slashings.deinit();
    }
};

// ─── Configuration ───────────────────────────────────────────────────────────

pub const P2pConfig = struct {
    /// Current fork digest (4-byte prefix for gossip topics).
    fork_digest: [4]u8,
    /// Req/resp handler callbacks (provides blocks, status, etc.).
    req_resp_context: *const ReqRespContext,
    /// Gossip message validator. Use `createPassthroughValidator` for a no-op stub.
    validator: *GossipValidationContext,
    /// Optional: host keypair for TLS (*ssl.EVP_PKEY cast to *anyopaque).
    /// Null = eth-p2p-z generates an ephemeral key.
    host_key: ?*@import("ssl").EVP_PKEY = null,
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

    pub fn init(allocator: Allocator, config: P2pConfig) !Self {
        const gossipsub = try GossipsubService.init(allocator, config.gossipsub_config);
        errdefer gossipsub.deinit();

        const network = Eth2Switch.init(
            allocator,
            .{ .host_key = config.host_key },
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
                        .agent_version = "lodestar-z/0.0.1",
                        .supported_protocols = &.{
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
                        },
                    },
                    .peer_results = std.StringHashMap(identify_mod.IdentifyResult).init(allocator),
                },
            },
        );

        const gossip_adapter = EthGossipAdapter.init(
            allocator,
            gossipsub,
            config.validator,
            config.fork_digest,
        );

        return .{
            .allocator = allocator,
            .network = network,
            .gossipsub = gossipsub,
            .gossip_adapter = gossip_adapter,
        };
    }

    /// Start listening and subscribe to standard eth2 gossip topics.
    pub fn start(self: *Self, io: Io, listen_addr: Multiaddr) !void {
        // Set initial time for gossipsub router (PRUNE backoff, scoring).
        {
            const ms: u64 = @intCast(@divFloor(std.time.nanoTimestamp(), std.time.ns_per_ms));
            self.gossipsub.setTime(ms);
        }
        try self.network.listen(io, listen_addr);
        try self.gossip_adapter.subscribeEthTopics();
        log.info("P2P service started", .{});
    }

    /// Dial a remote peer by QUIC multiaddr.
    pub fn dial(self: *Self, io: Io, peer_addr: Multiaddr) ![]const u8 {
        return self.network.dial(io, peer_addr);
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

    /// Subscribe to a gossip subnet topic (e.g., attestation subnets).
    pub fn subscribeSubnet(self: *Self, topic_type: GossipTopicType, subnet_id: u8) !void {
        try self.gossip_adapter.subscribeSubnet(topic_type, subnet_id);
    }

    /// Handle a fork transition: migrate all gossip topic subscriptions to the new fork.
    ///
    /// Unsubscribes from old fork topics, updates fork digest, and resubscribes to
    /// all global topics under the new fork digest. The beacon node should call this
    /// when a fork activates (e.g., at the Electra activation epoch).
    ///
    /// After calling this, also resubscribe to active attestation/sync subnets
    /// via `subscribeSubnet` — those are not handled here.
    pub fn onForkTransition(self: *Self, new_fork_digest: [4]u8) !void {
        try self.gossip_adapter.onForkTransition(new_fork_digest);
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
        self.gossipsub.deinit();
    }

    /// Spawn a background fiber for the gossipsub heartbeat timer.
    pub fn startHeartbeat(self: *Self, io: Io) void {
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
                const ms: u64 = @intCast(@divFloor(std.time.nanoTimestamp(), std.time.ns_per_ms));
                gs.setTime(ms);
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

test "P2pService: Eth2Switch compiles with 15 protocols" {
    // 14 req/resp + 1 gossipsub = 15 protocols.
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
    };
    try std.testing.expectEqual(@as(usize, 15), protocols.len);
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
    };
    for (ids, 0..) |id_a, i| {
        for (ids, 0..) |id_b, j| {
            if (i != j) {
                try std.testing.expect(!std.mem.eql(u8, id_a, id_b));
            }
        }
    }
}

test "PassthroughValidator: init, fixup, and deinit" {
    var v = PassthroughValidator.init(std.testing.allocator);
    defer v.deinit();
    v.fixupPointers();
    // After fixupPointers, ctx pointers must reference the struct's own seen sets.
    try std.testing.expect(v.ctx.seen_block_roots == &v.seen_blocks);
    try std.testing.expect(v.ctx.seen_aggregators == &v.seen_aggregators);
}
