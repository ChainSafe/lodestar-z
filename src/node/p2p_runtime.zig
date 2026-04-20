//! Node-owned P2P runtime orchestration.
//!
//! Keeps the beacon node's networking event loop, discovery/bootstrap,
//! gossip ingress, and sync transport plumbing out of `beacon_node.zig`.

const std = @import("std");
const log = std.log.scoped(.node);

const preset = @import("preset").preset;
const preset_root = @import("preset");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const db_mod = @import("db");
const ForkSeq = config_mod.ForkSeq;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const types = @import("consensus_types");
const fork_types = @import("fork_types");
const chain_mod = @import("chain");
const kzg_mod = @import("kzg");
const networking = @import("networking");
const DiscoveryService = networking.DiscoveryService;
const PeerManager = networking.PeerManager;
const SubnetService = networking.SubnetService;
const SubnetId = networking.SubnetId;
const ReqRespContext = networking.ReqRespContext;
const ConnectionDirection = networking.ConnectionDirection;
const GoodbyeReason = networking.GoodbyeReason;
const PeerAction = networking.PeerAction;
const peer_scoring = networking.peer_scoring;
const StatusMessage = networking.messages.StatusMessage;
const StatusMessageV2 = networking.messages.StatusMessageV2;
const MetadataV2 = networking.messages.MetadataV2;
const MetadataV3 = networking.messages.MetadataV3;
const DataColumnsByRootIdentifier = networking.messages.DataColumnsByRootIdentifier;
const DataColumnSidecarsByRootRequest = networking.messages.DataColumnSidecarsByRootRequest;
const AttnetsBitfield = networking.peer_info.AttnetsBitfield;
const SyncnetsBitfield = networking.peer_info.SyncnetsBitfield;
const ATTESTATION_SUBNET_COUNT = networking.peer_info.ATTESTATION_SUBNET_COUNT;
const SYNC_COMMITTEE_SUBNET_COUNT = networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT;
const discv5 = @import("discv5");
const libp2p = @import("zig-libp2p");
const Multiaddr = @import("multiaddr").Multiaddr;
const sync_mod = @import("sync");
const SyncService = sync_mod.SyncService;
const BatchBlock = sync_mod.BatchBlock;
const processor_mod = @import("processor");
const metrics_mod = @import("metrics.zig");
const BeaconMetrics = metrics_mod.BeaconMetrics;
const GossipHandler = @import("gossip_handler.zig").GossipHandler;
const gossip_ingress_mod = @import("gossip_ingress.zig");
const reqresp_callbacks_mod = @import("reqresp_callbacks.zig");
const gossip_node_callbacks_mod = @import("gossip_node_callbacks.zig");
const SyncCallbackCtx = @import("sync_bridge.zig").SyncCallbackCtx;

const BlobSidecar = types.deneb.BlobSidecar;
const BlobIdentifier = types.deneb.BlobIdentifier;
const DataColumnSidecar = types.fulu.DataColumnSidecar;
const Libp2pPeerId = @TypeOf((@as(libp2p.security.Session1, undefined)).remote_id);
const Libp2pPublicKey = @TypeOf((@as(libp2p.security.Session1, undefined)).remote_public_key);

const BYTES_PER_BLOB = kzg_mod.BYTES_PER_BLOB;
const MAX_COLUMNS = preset_root.NUMBER_OF_COLUMNS;
const INLINE_SECP256K1_PEER_ID_PREFIX = [_]u8{ 0x00, 0x25, 0x08, 0x02, 0x12, 0x21 };
const INLINE_SECP256K1_PEER_ID_LEN = INLINE_SECP256K1_PEER_ID_PREFIX.len + 33;

const SyncBlockMeta = chain_mod.PlannedBlockIngress;

const PeerStatusResponse = struct {
    status: StatusMessage.Type,
    earliest_available_slot: ?u64 = null,
};

const PeerMetadataResponse = struct {
    metadata: MetadataV2.Type,
    custody_group_count: ?u64 = null,
};

const ReqRespMaintenanceProtocol = peer_scoring.ReqRespProtocol;

const SlotRange = struct {
    start_slot: u64,
    count: u64,
};

const ValidatedBlockRangeChunk = struct {
    slot: u64,
    block_root: [32]u8,
};

const DiscoveryPeerIdentity = struct {
    node_id: [32]u8,
    pubkey: [33]u8,
};

const DiscoveryDialJob = struct {
    ma_str: []const u8,
    predicted_peer_id: []const u8,
    node_id: [32]u8,
    pubkey: [33]u8,
    started_at_ns: u64,

    fn toSuccess(self: DiscoveryDialJob, io: std.Io, peer_id: []const u8) DiscoveryDialCompletion {
        return .{ .success = .{
            .peer_id = peer_id,
            .predicted_peer_id = self.predicted_peer_id,
            .ma_str = self.ma_str,
            .node_id = self.node_id,
            .pubkey = self.pubkey,
            .elapsed_ns = elapsedSince(io, self.started_at_ns),
        } };
    }

    fn toFailure(self: DiscoveryDialJob, io: std.Io, err: anyerror) DiscoveryDialCompletion {
        return .{ .failure = .{
            .predicted_peer_id = self.predicted_peer_id,
            .ma_str = self.ma_str,
            .node_id = self.node_id,
            .err = err,
            .elapsed_ns = elapsedSince(io, self.started_at_ns),
        } };
    }
};

const OutboundDialAttemptResult = union(enum) {
    success: []const u8,
    failure: anyerror,
    canceled,
};

const OutboundDialEvent = union(enum) {
    dial: OutboundDialAttemptResult,
    timeout: TimeoutWaitResult,
};

fn freeOutboundDialEvent(allocator: std.mem.Allocator, event: OutboundDialEvent) void {
    switch (event) {
        .dial => |result| switch (result) {
            .success => |peer_id| allocator.free(peer_id),
            .failure, .canceled => {},
        },
        .timeout => {},
    }
}

fn completeReadyIngressAfterDataAvailability(
    ctx: *anyopaque,
    ready: chain_mod.ReadyBlockInput,
) anyerror!void {
    const self: *BeaconNode = @ptrCast(@alignCast(ctx));
    _ = try self.completeReadyIngress(ready, null);
}

fn handleDataAvailabilityReadyBlock(
    maybe_ready: ?chain_mod.ReadyBlockInput,
    ctx: *anyopaque,
    complete_fn: *const fn (ctx: *anyopaque, ready: chain_mod.ReadyBlockInput) anyerror!void,
) !void {
    if (maybe_ready) |ready| {
        try complete_fn(ctx, ready);
    }
}

fn timestampNowNs(io: std.Io) u64 {
    const now_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds();
    if (now_ns <= 0) return 0;
    return std.math.cast(u64, now_ns) orelse std.math.maxInt(u64);
}

fn elapsedSince(io: std.Io, started_at_ns: u64) u64 {
    const now = timestampNowNs(io);
    return now -| started_at_ns;
}

fn nsToSeconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}

const PeerReqRespJobKind = union(enum) {
    status_only,
    restatus,
    ping: struct {
        known_metadata_seq: u64,
    },
};

const PeerReqRespJob = struct {
    peer_id: []const u8,
    kind: PeerReqRespJobKind,
};

const OutboundHandshakeMode = enum {
    none,
    status_only,
};

const StatusReqRespPolicy = struct {
    disconnect_peer_on_failure: bool,
};

fn statusReqRespPolicy(kind: PeerReqRespJobKind) StatusReqRespPolicy {
    return switch (kind) {
        .status_only => .{
            // Align with Lodestar's peer manager: a failed outbound STATUS
            // request is not, by itself, grounds to evict the peer.
            .disconnect_peer_on_failure = false,
        },
        .restatus => .{
            .disconnect_peer_on_failure = false,
        },
        .ping => unreachable,
    };
}

fn statusReqRespFollowUpPing(kind: PeerReqRespJobKind) bool {
    return switch (kind) {
        // Lodestar sends STATUS and PING immediately on outbound connect.
        // We preserve our single in-flight req/resp invariant by issuing the
        // initial PING as soon as the first STATUS response proves the peer is usable.
        .status_only => true,
        .restatus,
        .ping,
        => false,
    };
}

fn peerNeedsMetadata(peer: *const networking.PeerInfo) bool {
    return !peer.metadata_known;
}

fn shouldRefreshMetadataAfterPing(
    peer: ?*const networking.PeerInfo,
    remote_seq: u64,
    known_metadata_seq: u64,
) bool {
    const resolved_peer = peer orelse return remote_seq != known_metadata_seq;
    return peerNeedsMetadata(resolved_peer) or remote_seq != known_metadata_seq;
}

const BlobFetchState = struct {
    existing: ?[]const u8 = null,
    sidecars: []?[]const u8,
    new_sidecars: std.ArrayListUnmanaged([]const u8) = .empty,

    fn init(
        allocator: std.mem.Allocator,
        blob_count: usize,
        existing: ?[]const u8,
    ) !BlobFetchState {
        const sidecars = try allocator.alloc(?[]const u8, blob_count);
        @memset(sidecars, null);

        if (existing) |bytes| {
            var offset: usize = 0;
            var index: usize = 0;
            while (offset + preset_root.BLOBSIDECAR_FIXED_SIZE <= bytes.len and index < sidecars.len) : ({
                offset += preset_root.BLOBSIDECAR_FIXED_SIZE;
                index += 1;
            }) {
                sidecars[index] = bytes[offset..][0..preset_root.BLOBSIDECAR_FIXED_SIZE];
            }
        }

        return .{
            .existing = existing,
            .sidecars = sidecars,
        };
    }

    fn deinit(self: *BlobFetchState, allocator: std.mem.Allocator) void {
        if (self.existing) |bytes| allocator.free(bytes);
        for (self.new_sidecars.items) |bytes| allocator.free(bytes);
        self.new_sidecars.deinit(allocator);
        allocator.free(self.sidecars);
        self.* = undefined;
    }

    fn setFetched(self: *BlobFetchState, allocator: std.mem.Allocator, index: usize, bytes: []const u8) !void {
        self.sidecars[index] = bytes;
        try self.new_sidecars.append(allocator, bytes);
    }

    fn aggregate(self: *const BlobFetchState, allocator: std.mem.Allocator) ![]u8 {
        var total_len: usize = 0;
        for (self.sidecars) |maybe_sidecar| {
            const sidecar = maybe_sidecar orelse return error.MissingBlobSidecar;
            total_len += sidecar.len;
        }

        const out = try allocator.alloc(u8, total_len);
        var offset: usize = 0;
        for (self.sidecars) |maybe_sidecar| {
            const sidecar = maybe_sidecar.?;
            @memcpy(out[offset..][0..sidecar.len], sidecar);
            offset += sidecar.len;
        }
        return out;
    }
};

fn parseIp4(raw: []const u8) ?[4]u8 {
    const addr = std.Io.net.IpAddress.parseIp4(raw, 0) catch return null;
    return switch (addr) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => null,
    };
}

fn parseIp6(raw: []const u8) ?[16]u8 {
    const addr = std.Io.net.IpAddress.parseIp6(raw, 0) catch return null;
    return switch (addr) {
        .ip4 => null,
        .ip6 => |ip6| ip6.bytes,
    };
}

fn formatListenMultiaddr(buf: []u8, host: []const u8, port: u16) ![]const u8 {
    _ = std.Io.net.IpAddress.parseIp4(host, 0) catch {
        _ = std.Io.net.IpAddress.parseIp6(host, 0) catch return error.InvalidListenAddress;
        return std.fmt.bufPrint(buf, "/ip6/{s}/udp/{d}/quic-v1", .{ host, port });
    };
    return std.fmt.bufPrint(buf, "/ip4/{s}/udp/{d}/quic-v1", .{ host, port });
}

fn formatDiscv5DialMultiaddr(buf: []u8, addr: discv5.Address, peer_id: ?[]const u8) ![]const u8 {
    return switch (addr) {
        .ip4 => |ip4| if (peer_id) |pid|
            std.fmt.bufPrint(buf, "/ip4/{d}.{d}.{d}.{d}/udp/{d}/quic-v1/p2p/{s}", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3], ip4.port, pid,
            })
        else
            std.fmt.bufPrint(buf, "/ip4/{d}.{d}.{d}.{d}/udp/{d}/quic-v1", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3], ip4.port,
            }),
        .ip6 => |ip6| if (peer_id) |pid|
            std.fmt.bufPrint(buf, "/ip6/{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}/udp/{d}/quic-v1/p2p/{s}", .{
                ip6.bytes[0],  ip6.bytes[1],  ip6.bytes[2],  ip6.bytes[3],
                ip6.bytes[4],  ip6.bytes[5],  ip6.bytes[6],  ip6.bytes[7],
                ip6.bytes[8],  ip6.bytes[9],  ip6.bytes[10], ip6.bytes[11],
                ip6.bytes[12], ip6.bytes[13], ip6.bytes[14], ip6.bytes[15],
                ip6.port,      pid,
            })
        else
            std.fmt.bufPrint(buf, "/ip6/{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}/udp/{d}/quic-v1", .{
                ip6.bytes[0],  ip6.bytes[1],  ip6.bytes[2],  ip6.bytes[3],
                ip6.bytes[4],  ip6.bytes[5],  ip6.bytes[6],  ip6.bytes[7],
                ip6.bytes[8],  ip6.bytes[9],  ip6.bytes[10], ip6.bytes[11],
                ip6.bytes[12], ip6.bytes[13], ip6.bytes[14], ip6.bytes[15],
                ip6.port,
            }),
    };
}

fn discoveryIdentityKnown(identity: DiscoveryPeerIdentity) bool {
    return !std.mem.eql(u8, &identity.pubkey, &([_]u8{0} ** 33));
}

fn discoveryPeerIdMatches(
    allocator: std.mem.Allocator,
    peer_id_bytes: []const u8,
    pubkey: [33]u8,
) !bool {
    const peer_data = try allocator.dupe(u8, pubkey[0..]);
    defer allocator.free(peer_data);

    var public_key = Libp2pPublicKey{
        .type = .SECP256K1,
        .data = peer_data,
    };

    const expected_peer_id = try Libp2pPeerId.fromPublicKey(allocator, &public_key);
    var expected_peer_id_buf: [128]u8 = undefined;
    const expected_peer_id_bytes = try expected_peer_id.toBytes(&expected_peer_id_buf);
    return std.mem.eql(u8, expected_peer_id_bytes, peer_id_bytes);
}

fn discoveryPeerIdBytesFromPubkey(
    allocator: std.mem.Allocator,
    pubkey: [33]u8,
) ![]u8 {
    const peer_data = try allocator.dupe(u8, pubkey[0..]);
    defer allocator.free(peer_data);

    var public_key = Libp2pPublicKey{
        .type = .SECP256K1,
        .data = peer_data,
    };

    const peer_id = try Libp2pPeerId.fromPublicKey(allocator, &public_key);
    var peer_id_buf: [128]u8 = undefined;
    const peer_id_bytes = try peer_id.toBytes(&peer_id_buf);
    return allocator.dupe(u8, peer_id_bytes);
}

fn nodeIdFromInlineSecp256k1PeerId(peer_id_bytes: []const u8) ?[32]u8 {
    if (peer_id_bytes.len != INLINE_SECP256K1_PEER_ID_LEN) return null;
    if (!std.mem.eql(u8, peer_id_bytes[0..INLINE_SECP256K1_PEER_ID_PREFIX.len], &INLINE_SECP256K1_PEER_ID_PREFIX)) {
        return null;
    }

    const pubkey_slice = peer_id_bytes[INLINE_SECP256K1_PEER_ID_PREFIX.len..INLINE_SECP256K1_PEER_ID_LEN];
    const pubkey: *const [33]u8 = @ptrCast(pubkey_slice.ptr);
    return discv5.enr.nodeIdFromCompressedPubkey(pubkey);
}

fn discoveryPeerIdTextFromPubkey(
    allocator: std.mem.Allocator,
    pubkey: [33]u8,
) ![]u8 {
    const peer_data = try allocator.dupe(u8, pubkey[0..]);
    defer allocator.free(peer_data);

    var public_key = Libp2pPublicKey{
        .type = .SECP256K1,
        .data = peer_data,
    };

    const peer_id = try Libp2pPeerId.fromPublicKey(allocator, &public_key);
    const text_buf = try allocator.alloc(u8, peer_id.toBase58Len());
    defer allocator.free(text_buf);
    const peer_id_text = try peer_id.toBase58(text_buf);
    return allocator.dupe(u8, peer_id_text);
}

test "discovery peer id helpers use raw libp2p peer id bytes" {
    const allocator = std.testing.allocator;
    const pubkey = [33]u8{
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
        0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
        0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };

    const peer_id_bytes = try discoveryPeerIdBytesFromPubkey(allocator, pubkey);
    defer allocator.free(peer_id_bytes);

    try std.testing.expect(peer_id_bytes.len > 0);
    try std.testing.expect(try discoveryPeerIdMatches(allocator, peer_id_bytes, pubkey));
}

test "discovery peer id helpers derive node id from inline secp256k1 peer id" {
    const allocator = std.testing.allocator;
    const pubkey = [33]u8{
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
        0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
        0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };

    const peer_id_bytes = try discoveryPeerIdBytesFromPubkey(allocator, pubkey);
    defer allocator.free(peer_id_bytes);

    const actual = nodeIdFromInlineSecp256k1PeerId(peer_id_bytes) orelse return error.TestUnexpectedResult;
    const expected = discv5.enr.nodeIdFromCompressedPubkey(&pubkey);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "status req/resp policy tolerates status transport failures" {
    const status_only = statusReqRespPolicy(.status_only);
    try std.testing.expect(!status_only.disconnect_peer_on_failure);

    const restatus = statusReqRespPolicy(.restatus);
    try std.testing.expect(!restatus.disconnect_peer_on_failure);

    try std.testing.expect(statusReqRespFollowUpPing(.status_only));
    try std.testing.expect(!statusReqRespFollowUpPing(.restatus));
    try std.testing.expect(!statusReqRespFollowUpPing(.{ .ping = .{ .known_metadata_seq = 0 } }));
}

fn successfulOutboundDialAttemptTask(allocator: std.mem.Allocator) OutboundDialAttemptResult {
    const peer_id = allocator.dupe(u8, "test-peer-id") catch |err| return .{ .failure = err };
    return .{ .success = peer_id };
}

fn sleepingOutboundDialAttemptTask(io: std.Io, delay_ms: u64) OutboundDialAttemptResult {
    const sleep_timeout: std.Io.Timeout = .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(@intCast(delay_ms)),
        .clock = .awake,
    } };
    sleep_timeout.sleep(io) catch |err| switch (err) {
        error.Canceled => return .canceled,
    };
    return .{ .failure = error.TestUnexpectedResult };
}

test "outbound dial helper returns successful dial before timeout" {
    const peer_id = try awaitOutboundDialAttemptWithTimeout(
        std.testing.allocator,
        std.testing.io,
        50,
        successfulOutboundDialAttemptTask,
        .{std.testing.allocator},
    );
    defer std.testing.allocator.free(peer_id);

    try std.testing.expectEqualStrings("test-peer-id", peer_id);
}

test "outbound dial helper times out hung dial attempts" {
    try std.testing.expectError(
        error.Timeout,
        awaitOutboundDialAttemptWithTimeout(
            std.testing.allocator,
            std.testing.io,
            5,
            sleepingOutboundDialAttemptTask,
            .{ std.testing.io, 50 },
        ),
    );
}

test "peerNeedsMetadata distinguishes unknown metadata from seq zero" {
    var peer = networking.PeerInfo{};
    try std.testing.expect(peerNeedsMetadata(&peer));

    peer.metadata_seq = 0;
    peer.metadata_known = true;
    try std.testing.expect(!peerNeedsMetadata(&peer));
}

test "shouldRefreshMetadataAfterPing requests metadata when unknown or seq advances" {
    var peer = networking.PeerInfo{};
    try std.testing.expect(shouldRefreshMetadataAfterPing(&peer, 0, 0));

    peer.metadata_known = true;
    try std.testing.expect(!shouldRefreshMetadataAfterPing(&peer, 0, 0));
    try std.testing.expect(shouldRefreshMetadataAfterPing(&peer, 1, 0));
    try std.testing.expect(!shouldRefreshMetadataAfterPing(null, 0, 0));
    try std.testing.expect(shouldRefreshMetadataAfterPing(null, 2, 1));
}

pub fn start(self: *BeaconNode, io: std.Io, listen_addr: []const u8, port: u16) !void {
    var ma_buf: [160]u8 = undefined;
    const ma_str = try formatListenMultiaddr(&ma_buf, listen_addr, port);
    const listen_multiaddr = try Multiaddr.fromString(self.allocator, ma_str);
    defer listen_multiaddr.deinit();

    const p2p_req_ctx = try self.allocator.create(reqresp_callbacks_mod.RequestContext);
    errdefer self.allocator.destroy(p2p_req_ctx);
    p2p_req_ctx.* = .{ .node = @ptrCast(self) };
    self.p2p_request_ctx = p2p_req_ctx;

    const req_resp_ctx = try self.allocator.create(ReqRespContext);
    errdefer self.allocator.destroy(req_resp_ctx);
    req_resp_ctx.* = reqresp_callbacks_mod.makeReqRespContext(p2p_req_ctx);
    self.p2p_req_resp_ctx = req_resp_ctx;

    const req_resp_server_policy = try self.allocator.create(networking.ReqRespServerPolicy);
    errdefer self.allocator.destroy(req_resp_server_policy);
    req_resp_server_policy.* = reqresp_callbacks_mod.makeReqRespServerPolicy(p2p_req_ctx);
    self.p2p_req_resp_policy = req_resp_server_policy;

    const req_resp_rate_limiter = try self.allocator.create(networking.RateLimiter);
    errdefer self.allocator.destroy(req_resp_rate_limiter);
    req_resp_rate_limiter.* = networking.RateLimiter.init(self.allocator);
    self.req_resp_rate_limiter = req_resp_rate_limiter;

    const network_slot = currentNetworkSlot(self, self.io) orelse self.currentHeadSlot();
    const fork_digest = self.config.networkingForkDigestAtSlot(network_slot, self.genesis_validators_root);

    var host_identity = self.node_identity.libp2pKeyPair();
    {
        const derived_peer_id = try host_identity.peerId(self.allocator);
        const base58_len = derived_peer_id.toBase58Len();
        const base58_buf = try self.allocator.alloc(u8, base58_len);
        defer self.allocator.free(base58_buf);
        const peer_id_text = try derived_peer_id.toBase58(base58_buf);
        if (!std.mem.eql(u8, peer_id_text, self.node_identity.peer_id)) {
            return error.PeerIdMismatch;
        }
    }

    self.p2p_service = try networking.p2p_service.P2pService.init(self.io, self.allocator, .{
        .fork_digest = fork_digest,
        .fork_seq = self.config.forkSeq(network_slot),
        .req_resp_context = req_resp_ctx,
        .req_resp_server_policy = req_resp_server_policy,
        .host_identity = host_identity,
        .identify_agent_version = self.identify_agent_version,
        .gossipsub_config = .{
            .mesh_degree = 8,
            .mesh_degree_lo = 6,
            .mesh_degree_hi = 12,
            .mesh_degree_lazy = 6,
            .heartbeat_interval_ms = 700,
            .signature_policy = .strict_no_sign,
            .publish_policy = .anonymous,
            .msg_id_fn = &networking.gossipMessageIdFn,
            .validation_mode = .manual,
        },
    });
    defer deinitService(self, io);

    var svc = &self.p2p_service.?;
    try svc.start(io, listen_multiaddr);
    try initSubnetService(self);
    subscribeInitialSubnets(self, io, svc);

    initPeerManager(self) catch |err| {
        log.warn("Failed to initialize peer manager: {}", .{err});
    };
    initDiscoveryService(self) catch |err| {
        log.warn("Failed to initialize discovery service: {}", .{err});
    };

    initGossipHandler(self);
    initSyncPipeline(self) catch |err| {
        log.warn("Failed to initialize sync pipeline: {}", .{err});
    };

    bootstrapBootnodes(self, io, svc);
    bootstrapDirectPeers(self, io, svc);
    runLoop(self, io, svc);
}

pub fn deinitService(self: *BeaconNode, io: std.Io) void {
    if (self.p2p_service) |*svc| {
        svc.deinit(io);
        self.p2p_service = null;
    }
}

pub fn deinitOwnedState(self: *BeaconNode) void {
    if (self.discovery_service) |ds| {
        ds.deinit();
        self.allocator.destroy(ds);
        self.discovery_service = null;
    }

    if (self.peer_manager) |pm| {
        pm.deinit();
        self.allocator.destroy(pm);
        self.peer_manager = null;
    }

    if (self.subnet_service) |svc| {
        svc.deinit();
        self.allocator.destroy(svc);
        self.subnet_service = null;
    }

    if (self.req_resp_rate_limiter) |limiter| {
        limiter.deinit();
        self.allocator.destroy(limiter);
        self.req_resp_rate_limiter = null;
    }
    if (self.p2p_req_resp_policy) |policy| {
        self.allocator.destroy(policy);
        self.p2p_req_resp_policy = null;
    }
    if (self.p2p_req_resp_ctx) |ctx| {
        self.allocator.destroy(ctx);
        self.p2p_req_resp_ctx = null;
    }
    if (self.p2p_request_ctx) |ctx| {
        self.allocator.destroy(ctx);
        self.p2p_request_ctx = null;
    }

    if (self.gossip_handler) |gh| {
        gh.deinit();
        self.gossip_handler = null;
    }

    if (self.sync_service_inst) |svc| {
        svc.deinit();
        self.allocator.destroy(svc);
        self.sync_service_inst = null;
    }
    if (self.sync_callback_ctx) |ctx| {
        ctx.deinit(self.allocator);
        self.allocator.destroy(ctx);
        self.sync_callback_ctx = null;
    }
}

pub fn processSyncBatches(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const cb_ctx = self.sync_callback_ctx orelse return;
    if (self.sync_service_inst == null) return;

    while (cb_ctx.popPendingRequest()) |req| {
        const peer_id = req.peerId();
        log.debug("Processing sync chain {d} batch {d}/gen {d}: slots {d}..{d} from peer {s}", .{
            req.chain_id,
            req.batch_id,
            req.generation,
            req.start_slot,
            req.start_slot + req.count - 1,
            peer_id,
        });

        if (self.peer_manager) |pm| {
            if (pm.getPeer(peer_id)) |peer| {
                if (peer.sync_info) |sync_info| {
                    if (sync_info.earliest_available_slot) |earliest_available_slot| {
                        if (req.start_slot < earliest_available_slot) {
                            log.debug("Batch {d}: peer {s} cannot serve requested range start_slot={d} earliest_available_slot={d}", .{
                                req.batch_id,
                                peer_id,
                                req.start_slot,
                                earliest_available_slot,
                            });
                            if (self.sync_service_inst) |sync_svc| {
                                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
                            }
                            continue;
                        }
                    }
                }
            }
        }

        const retained_blocks = if (self.sync_service_inst) |sync_svc|
            sync_svc.getBatchBlocks(req.chain_id, req.batch_id, req.generation)
        else
            null;
        if (retained_blocks == null) {
            log.debug("Batch {d}: stale request for generation {d}", .{ req.batch_id, req.generation });
            continue;
        }

        var fetched_blocks: ?[]BatchBlock = null;
        defer if (fetched_blocks) |owned_blocks| {
            for (owned_blocks) |blk| self.allocator.free(blk.block_bytes);
            self.allocator.free(owned_blocks);
        };

        const blocks = blk: {
            if (retained_blocks.?.len != 0) {
                break :blk retained_blocks.?;
            }

            const owned_blocks = fetchRawBlocksByRange(self, io, svc, peer_id, req.start_slot, req.count) catch |err| {
                noteSyncPeerGoneIfTransportClosed(self, io, svc, peer_id, err);
                reportReqRespFetchFailure(self, io, peer_id, .beacon_blocks_by_range, err);
                log.debug("Batch {d} fetch failed: {}", .{ req.batch_id, err });
                if (self.sync_service_inst) |sync_svc| {
                    sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
                }
                continue;
            };
            fetched_blocks = owned_blocks;
            break :blk owned_blocks;
        };

        if (blocks.len == 0) {
            log.debug("Batch {d}: empty response from peer", .{req.batch_id});
            if (self.sync_service_inst) |sync_svc| {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
            }
            continue;
        }

        ensureRangeSyncDataAvailability(self, io, svc, peer_id, blocks) catch |err| {
            log.debug("Batch {d}: DA prefetch deferred/failed: {}", .{ req.batch_id, err });
            if (self.sync_service_inst) |sync_svc| {
                switch (err) {
                    error.MissingDataColumnSidecar => sync_svc.onBatchDeferred(req.chain_id, req.batch_id, req.generation, blocks),
                    else => sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id),
                }
            }
            continue;
        };

        if (self.sync_service_inst) |sync_svc| {
            sync_svc.onBatchResponse(req.chain_id, req.batch_id, req.generation, blocks);
        }

        log.debug("Batch {d}: delivered {d} blocks to sync pipeline", .{
            req.batch_id,
            blocks.len,
        });
    }
}

pub fn processSyncByRootRequests(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const cb_ctx = self.sync_callback_ctx orelse return;

    while (cb_ctx.popPendingByRootRequest()) |req| {
        if (req.kind == .unknown_chain_header and !shouldDriveUnknownChainSync(self)) {
            continue;
        }

        const peer_id = req.peerId();
        const root = req.root;
        log.debug("processSyncByRoot: fetching {s} root {x:0>2}{x:0>2}{x:0>2}{x:0>2}... from peer {s}", .{
            @tagName(req.kind), root[0], root[1], root[2], root[3], peer_id,
        });

        const block_ssz = fetchBlockByRoot(self, io, svc, peer_id, root) catch |err| {
            reportReqRespFetchFailure(self, io, peer_id, .beacon_blocks_by_root, err);
            log.debug("processSyncByRoot: fetch failed for {s} root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                @tagName(req.kind), root[0], root[1], root[2], root[3], err,
            });
            switch (req.kind) {
                .unknown_block_parent => self.unknown_block_sync.onFetchFailed(root, peer_id),
                .unknown_block_gossip => self.onPendingUnknownBlockFetchFailed(root, peer_id),
                .unknown_chain_header => {},
            }
            continue;
        };
        defer self.allocator.free(block_ssz);

        switch (req.kind) {
            .unknown_block_parent => {
                ensureByRootDataAvailability(self, io, svc, peer_id, block_ssz) catch |err| {
                    log.debug("processSyncByRoot: DA prefetch failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                        root[0], root[1], root[2], root[3], err,
                    });
                    self.unknown_block_sync.onFetchFailed(root, peer_id);
                    continue;
                };

                const prepared = self.chainService().prepareRawPreparedBlockInput(block_ssz, .unknown_block_sync) catch |err| {
                    log.warn("processSyncByRoot: block preparation failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                        root[0], root[1], root[2], root[3], err,
                    });
                    self.unknown_block_sync.onFetchFailed(root, peer_id);
                    continue;
                };

                self.unknown_block_sync.onParentFetched(root, prepared) catch |err| {
                    log.warn("processSyncByRoot: onParentFetched error: {}", .{err});
                };
            },
            .unknown_block_gossip => {
                ensureByRootDataAvailability(self, io, svc, peer_id, block_ssz) catch |err| {
                    log.debug("processSyncByRoot: unknown-block-gossip DA prefetch failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                        root[0], root[1], root[2], root[3], err,
                    });
                    self.onPendingUnknownBlockFetchFailed(root, peer_id);
                    continue;
                };

                const prepared = self.chainService().prepareRawPreparedBlockInput(block_ssz, .unknown_block_sync) catch |err| {
                    log.warn("processSyncByRoot: unknown-block-gossip block preparation failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                        root[0], root[1], root[2], root[3], err,
                    });
                    self.onPendingUnknownBlockFetchFailed(root, peer_id);
                    continue;
                };

                self.onPendingUnknownBlockFetchAccepted(root);
                const import_result = self.importPreparedBlock(prepared) catch |err| {
                    log.warn("processSyncByRoot: unknown-block-gossip import failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                        root[0], root[1], root[2], root[3], err,
                    });
                    self.onPendingUnknownBlockFetchFailed(root, null);
                    continue;
                };

                switch (import_result) {
                    .pending => {},
                    .imported => {},
                    .ignored => {
                        if (self.chainQuery().isKnownBlockRoot(root)) {
                            self.processPendingChildren(root);
                        } else {
                            self.dropPendingUnknownBlock(root);
                        }
                    },
                }
            },
            .unknown_chain_header => {
                log.debug("dropping unknown-chain by-root response while unknown-chain sync is disabled root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                    root[0], root[1], root[2], root[3],
                });
            },
        }
    }
}

pub fn processPendingLinkedChainImports(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const cb_ctx = self.sync_callback_ctx orelse return;

    while (cb_ctx.popPendingLinkedChain()) |pending| {
        var owned = pending;
        defer owned.deinit(self.allocator);

        var peer_scratch: [64][]const u8 = undefined;
        const peer_ids = owned.peerIds(&peer_scratch);
        if (peer_ids.len == 0) continue;

        var raw_blocks: std.ArrayListUnmanaged(chain_mod.RawBlockBytes) = .empty;
        defer {
            for (raw_blocks.items) |raw_block| self.allocator.free(raw_block.bytes);
            raw_blocks.deinit(self.allocator);
        }

        var failed = false;
        for (owned.headers) |header| {
            const fetched = fetchBlockByRootFromPeers(self, io, svc, peer_ids, header.root) catch {
                log.debug("linked unknown-chain import: no connected peer has block at slot {d}", .{header.slot});
                failed = true;
                break;
            };

            ensureByRootDataAvailability(self, io, svc, fetched.peer_id, fetched.block_ssz) catch |err| {
                self.allocator.free(fetched.block_ssz);
                log.warn("linked unknown-chain import: DA prefetch failed at slot {d}: {}", .{ header.slot, err });
                failed = true;
                break;
            };

            raw_blocks.append(self.allocator, .{
                .slot = header.slot,
                .bytes = fetched.block_ssz,
            }) catch |err| {
                self.allocator.free(fetched.block_ssz);
                log.warn("linked unknown-chain import: failed to queue block at slot {d}: {}", .{ header.slot, err });
                failed = true;
                break;
            };
        }

        if (failed or raw_blocks.items.len != owned.headers.len) continue;

        self.processRangeSyncSegment(raw_blocks.items) catch |err| {
            log.warn("linked unknown-chain import failed: {}", .{err});
        };
    }
}

fn subscribeInitialSubnets(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const gossip_topics = networking.gossip_topics;

    if (self.node_options.subscribe_all_subnets) {
        var attestation_subnet: u8 = 0;
        while (attestation_subnet < gossip_topics.MAX_ATTESTATION_SUBNET_ID) : (attestation_subnet += 1) {
            svc.subscribeSubnet(io, .beacon_attestation, attestation_subnet) catch |err| {
                log.warn("Failed to subscribe to attestation subnet {d}: {}", .{ attestation_subnet, err });
            };
        }
        log.info("Subscribed to all {d} attestation subnets", .{gossip_topics.MAX_ATTESTATION_SUBNET_ID});
    } else {
        log.info("Attestation subnet gossip subscriptions will follow validator subnet demand", .{});
    }

    const custody_group_count = @min(
        self.chain_runtime.custody_columns.len,
        @as(usize, gossip_topics.MAX_DATA_COLUMN_SIDECAR_SUBNET_ID),
    );
    var data_column_subnet: u8 = 0;
    while (@as(usize, data_column_subnet) < custody_group_count) : (data_column_subnet += 1) {
        svc.subscribeSubnet(io, .data_column_sidecar, data_column_subnet) catch |err| {
            log.warn("Failed to subscribe to data column subnet {d}: {}", .{ data_column_subnet, err });
        };
    }
    log.info("Subscribed to {d} data column subnets (local custody groups)", .{custody_group_count});
}

fn setInitialSubnetSubscriptionsEnabled(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    enabled: bool,
) void {
    const gossip_topics = networking.gossip_topics;

    if (self.node_options.subscribe_all_subnets) {
        var attestation_subnet: u8 = 0;
        while (attestation_subnet < gossip_topics.MAX_ATTESTATION_SUBNET_ID) : (attestation_subnet += 1) {
            if (enabled) {
                svc.subscribeSubnet(io, .beacon_attestation, attestation_subnet) catch |err| {
                    log.warn("Failed to subscribe to attestation subnet {d}: {}", .{ attestation_subnet, err });
                };
            } else {
                svc.unsubscribeSubnet(io, .beacon_attestation, attestation_subnet) catch |err| {
                    log.warn("Failed to unsubscribe from attestation subnet {d}: {}", .{ attestation_subnet, err });
                };
            }
        }
    }

    const custody_group_count = @min(
        self.chain_runtime.custody_columns.len,
        @as(usize, gossip_topics.MAX_DATA_COLUMN_SIDECAR_SUBNET_ID),
    );
    var data_column_subnet: u8 = 0;
    while (@as(usize, data_column_subnet) < custody_group_count) : (data_column_subnet += 1) {
        if (enabled) {
            svc.subscribeSubnet(io, .data_column_sidecar, data_column_subnet) catch |err| {
                log.warn("Failed to subscribe to data column subnet {d}: {}", .{ data_column_subnet, err });
            };
        } else {
            svc.unsubscribeSubnet(io, .data_column_sidecar, data_column_subnet) catch |err| {
                log.warn("Failed to unsubscribe from data column subnet {d}: {}", .{ data_column_subnet, err });
            };
        }
    }
}

fn setSyncGossipCoreTopicsEnabled(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    enabled: bool,
) void {
    if (enabled) {
        svc.subscribeEthTopics(io) catch |err| {
            log.warn("Failed to subscribe gossip core topics: {}", .{err});
            return;
        };
        setInitialSubnetSubscriptionsEnabled(self, io, svc, true);
    } else {
        svc.unsubscribeEthTopics(io) catch |err| {
            log.warn("Failed to unsubscribe gossip core topics: {}", .{err});
            return;
        };
        setInitialSubnetSubscriptionsEnabled(self, io, svc, false);
    }
    log.info("gossip core topics {s}", .{if (enabled) "enabled" else "disabled"});
}

fn processPendingSyncGossipSubscriptionUpdates(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
) bool {
    const cb_ctx = self.sync_callback_ctx orelse return false;
    const enabled = cb_ctx.takePendingGossipEnabled() orelse return false;
    setSyncGossipCoreTopicsEnabled(self, io, svc, enabled);
    return true;
}

fn initSubnetService(self: *BeaconNode) !void {
    const svc = try self.allocator.create(SubnetService);
    errdefer self.allocator.destroy(svc);
    svc.* = SubnetService.init(self.allocator, self.node_identity.node_id);
    if (self.clock) |clock| {
        if (clock.currentSlot(self.io)) |slot| {
            svc.onSlot(slot);
        }
    }
    self.subnet_service = svc;
}

fn closeOwnedQuicStream(io: std.Io, stream: *networking.QuicStream) void {
    _ = io;
    // `deinit()` already closes the QUIC stream while holding a temporary
    // self-reference; calling `close()` first creates an avoidable race.
    stream.deinit();
}

const OpenedReqRespRequest = struct {
    permit: networking.ReqRespRequestPermit,
    stream: networking.QuicStream,
    metrics: ?*BeaconMetrics,
    method: networking.Method,
    started_ns: i128,
    request_payload_bytes: u64 = 0,
    response_payload_bytes: u64 = 0,
    response_chunks: u64 = 0,
    finished: bool = false,

    fn noteRequestPayload(self: *OpenedReqRespRequest, payload_bytes: usize) void {
        self.request_payload_bytes +|= @as(u64, @intCast(payload_bytes));
    }

    fn noteResponseChunk(self: *OpenedReqRespRequest, payload_bytes: usize) void {
        self.response_chunks +|= 1;
        self.response_payload_bytes +|= @as(u64, @intCast(payload_bytes));
    }

    fn finish(self: *OpenedReqRespRequest, io: std.Io, outcome: networking.ReqRespRequestOutcome) void {
        if (self.finished) return;
        self.finished = true;
        if (self.metrics) |metrics| {
            metrics.observeReqRespOutbound(
                self.method,
                outcome,
                reqRespElapsedSeconds(io, self.started_ns),
                self.request_payload_bytes,
                self.response_payload_bytes,
                self.response_chunks,
            );
        }
    }

    fn deinit(self: *OpenedReqRespRequest, io: std.Io) void {
        if (!self.finished) self.finish(io, .transport_error);
        closeOwnedQuicStream(io, &self.stream);
        self.permit.deinit(io);
    }
};

fn reqRespElapsedSeconds(io: std.Io, started_ns: i128) f64 {
    const now_ns = std.Io.Clock.awake.now(io).nanoseconds;
    const elapsed_ns = @max(now_ns - started_ns, 0);
    return @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

fn reqRespMethodFromSelfLimitMethod(method: networking.rate_limiter.SelfRateLimitMethod) networking.Method {
    return @enumFromInt(@intFromEnum(method));
}

fn responseCodeOutcome(code: networking.ResponseCode) networking.ReqRespRequestOutcome {
    return networking.ReqRespRequestOutcome.fromResponseCode(code);
}

fn openReqRespRequest(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    method: networking.rate_limiter.SelfRateLimitMethod,
    protocol_id: []const u8,
) !OpenedReqRespRequest {
    const started_ns = std.Io.Clock.awake.now(io).nanoseconds;
    const req_resp_method = reqRespMethodFromSelfLimitMethod(method);

    var permit = svc.acquireReqRespRequestPermit(io, peer_id, method) catch |err| {
        if (self.metrics) |metrics| {
            metrics.observeReqRespOutbound(
                req_resp_method,
                if (err == error.RequestSelfRateLimited) .self_rate_limited else .transport_error,
                reqRespElapsedSeconds(io, started_ns),
                0,
                0,
                0,
            );
        }
        return err;
    };
    errdefer permit.deinit(io);

    log.debug("Opening req/resp stream: method={s} protocol={s}", .{
        @tagName(method),
        protocol_id,
    });

    const stream = svc.dialProtocol(io, peer_id, protocol_id) catch |err| {
        if (self.metrics) |metrics| {
            metrics.observeReqRespOutbound(req_resp_method, .transport_error, reqRespElapsedSeconds(io, started_ns), 0, 0, 0);
        }
        return err;
    };
    return .{
        .permit = permit,
        .stream = stream,
        .metrics = self.metrics,
        .method = req_resp_method,
        .started_ns = started_ns,
    };
}

fn bootstrapBootnodes(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    if (self.bootstrap_peers.len == 0) return;

    log.info("dialing {d} bootstrap peer(s)", .{self.bootstrap_peers.len});
    for (self.bootstrap_peers) |enr_str| {
        dialBootnodeEnr(self, io, svc, enr_str) catch |err| {
            log.warn("failed to dial bootstrap peer: {}", .{err});
        };
    }
}

fn bootstrapDirectPeers(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    _ = io;
    _ = svc;
    const direct_peers = self.node_options.direct_peers;
    if (direct_peers.len == 0) return;

    self.next_direct_peer_index = 0;
    log.info("queuing {d} direct peer(s) for runtime bootstrap", .{direct_peers.len});
}

const active_p2p_tick_ns: u64 = std.time.ns_per_ms;
const idle_p2p_tick_ns: u64 = 25 * std.time.ns_per_ms;
const connectivity_maintenance_interval_ns: u64 = 100 * std.time.ns_per_ms;
const discovery_maintenance_interval_ns: u64 = 6 * std.time.ns_per_s;
// Match Lodestar's periodic ping/status timeout check cadence. Running this
// loop at 100ms causes repeated re-status storms after transient transport
// churn, which in turn destabilizes peer retention during sync.
const peer_maintenance_interval_ns: u64 = 10 * std.time.ns_per_s;
const metrics_sampling_interval_ns: u64 = std.time.ns_per_s;
const peer_manager_heartbeat_interval_ns: u64 = networking.peer_manager.HEARTBEAT_INTERVAL_MS * std.time.ns_per_ms;
const max_discovery_dials_per_tick: u32 = 4;
// Match Lodestar's libp2p connectionManager.dialTimeout so all outbound dial
// paths have the same bounded behavior.
const outbound_dial_timeout_ms: u64 = 30_000;
const optional_reqresp_timeout_ms: u64 = 3_000;

const TimeoutWaitResult = enum {
    fired,
    canceled,
};

fn waitTimeout(io: std.Io, timeout: std.Io.Timeout) TimeoutWaitResult {
    timeout.sleep(io) catch |err| switch (err) {
        error.Canceled => return .canceled,
    };
    return .fired;
}

fn shouldDriveUnknownChainSync(self: *const BeaconNode) bool {
    return self.unknownChainSyncEnabled();
}

fn runDiscoveryMaintenance(self: *BeaconNode) bool {
    const ds = self.discovery_service orelse return false;
    const pm = self.peer_manager orelse return false;
    ds.setConnectedPeers(pm.peerCount());
    ds.discoverPeers(pm);
    if (self.metrics) |metrics| {
        metrics.discovery_peers_known.set(@intCast(ds.knownPeerCount()));
    }
    return true;
}

fn runConnectivityMaintenance(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    var did_work = syncSubnetState(self, io, svc);

    did_work = bootstrapNextDirectPeer(self, io, svc) or did_work;

    if (self.discovery_service) |ds| {
        ds.poll();
        if (ds.takeLocalEnrChanged()) {
            refreshApiNodeIdentityFromDiscovery(self, ds) catch |err| {
                log.warn("Failed to refresh API node identity from discovery ENR: {}", .{err});
            };
            did_work = true;
        }
        did_work = dialDiscoveredPeers(self, io, svc, ds) or did_work;
    }

    return reconcilePeerConnections(self, io, svc) or did_work;
}

fn bootstrapNextDirectPeer(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const direct_peers = self.node_options.direct_peers;
    if (self.next_direct_peer_index >= direct_peers.len) return false;

    const pm = self.peer_manager orelse return false;
    // Keep dialing curated direct peers until startup has a small set of
    // connected or in-flight peers. A single transient peer is usually not
    // enough to cover PeerDAS column fetches after checkpoint sync.
    const connected_peers = pm.peerCount();
    const dialing_peers = pm.dialingPeerCount();
    const desired_startup_peers = sync_mod.sync_types.MIN_PEERS_TO_SYNC;
    if (connected_peers >= desired_startup_peers) return false;
    if (connected_peers + dialing_peers >= desired_startup_peers) return false;

    const addr_str = direct_peers[self.next_direct_peer_index];
    self.next_direct_peer_index += 1;

    log.debug("runtime direct peer bootstrap {d}/{d}: {s}", .{
        self.next_direct_peer_index,
        direct_peers.len,
        addr_str,
    });

    dialDirectPeer(self, io, svc, addr_str) catch |err| {
        log.warn("failed to dial direct peer {s}: {}", .{ addr_str, err });
    };
    return true;
}

fn currentNetworkSlot(self: *BeaconNode, io: std.Io) ?u64 {
    if (self.clock) |clock| {
        if (clock.currentSlot(io)) |slot| return slot;
    }
    return self.currentHeadSlot();
}

fn getDesiredActiveAttestationSubnets(self: *BeaconNode, subnet_service: *SubnetService) ![]SubnetId {
    if (!self.node_options.subscribe_all_subnets) {
        return subnet_service.getActiveAttestationSubnets();
    }

    const subnets = try self.allocator.alloc(SubnetId, ATTESTATION_SUBNET_COUNT);
    for (subnets, 0..) |*subnet, i| subnet.* = @intCast(i);
    return subnets;
}

fn bitsetFromSubnets(comptime BitSet: type, subnets: []const SubnetId) BitSet {
    var bits = BitSet.initEmpty();
    for (subnets) |subnet| bits.set(subnet);
    return bits;
}

fn attnetsBytesFromSubnets(subnets: []const SubnetId) [8]u8 {
    var bytes = [_]u8{0} ** 8;
    for (subnets) |subnet| {
        bytes[subnet / 8] |= @as(u8, 1) << @intCast(subnet % 8);
    }
    return bytes;
}

fn syncnetsBytesFromSubnets(subnets: []const SubnetId) [1]u8 {
    var bytes = [_]u8{0} ** 1;
    for (subnets) |subnet| {
        bytes[subnet / 8] |= @as(u8, 1) << @intCast(subnet % 8);
    }
    return bytes;
}

fn syncGossipForkState(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const slot = currentNetworkSlot(self, self.io) orelse return false;
    const epoch = computeEpochAtSlot(slot);
    const active = self.config.activeGossipForksAtEpoch(epoch, self.genesis_validators_root);

    var active_forks: [config_mod.ForkSeq.count]networking.p2p_service.ActiveGossipFork = undefined;
    for (active.asSlice(), 0..) |fork, i| {
        active_forks[i] = .{
            .fork_digest = fork.digest,
            .fork_seq = fork.fork_seq,
        };
    }

    svc.setActiveGossipForks(io, active_forks[0..active.count]) catch |err| {
        log.warn("Failed to update active gossip fork boundaries: {}", .{err});
        return false;
    };
    svc.setPublishFork(
        self.config.networkingForkDigestAtSlot(slot, self.genesis_validators_root),
        self.config.forkSeq(slot),
    );
    return true;
}

fn syncSubnetState(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const subnet_service = self.subnet_service orelse return false;
    const slot = currentNetworkSlot(self, self.io) orelse return false;
    var did_work = syncGossipForkState(self, io, svc);
    if (subnet_service.current_slot != slot) {
        subnet_service.onSlot(slot);
    }

    const active_attnets = getDesiredActiveAttestationSubnets(self, subnet_service) catch |err| {
        log.warn("Failed to collect active attestation subnet demand: {}", .{err});
        return false;
    };
    defer if (active_attnets.len > 0) self.allocator.free(active_attnets);

    const active_syncnets = subnet_service.getActiveSyncSubnets() catch |err| {
        log.warn("Failed to collect active sync subnet demand: {}", .{err});
        return false;
    };
    defer if (active_syncnets.len > 0) self.allocator.free(active_syncnets);

    var desired_gossip_attnets = if (self.node_options.subscribe_all_subnets)
        bitsetFromSubnets(networking.peer_info.AttnetsBitfield, active_attnets)
    else blk: {
        const gossip_attnets = subnet_service.getGossipAttestationSubnets() catch |err| {
            log.warn("Failed to collect gossip attestation subnets: {}", .{err});
            return false;
        };
        defer if (gossip_attnets.len > 0) self.allocator.free(gossip_attnets);
        break :blk bitsetFromSubnets(networking.peer_info.AttnetsBitfield, gossip_attnets);
    };
    const desired_gossip_syncnets = bitsetFromSubnets(networking.peer_info.SyncnetsBitfield, active_syncnets);

    var subnet: usize = 0;
    while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
        const should_subscribe = desired_gossip_attnets.isSet(subnet);
        const is_subscribed = self.gossip_attestation_subscriptions.isSet(subnet);
        if (should_subscribe == is_subscribed) continue;

        if (should_subscribe) {
            svc.subscribeSubnet(io, .beacon_attestation, @intCast(subnet)) catch |err| {
                log.warn("Failed to subscribe attestation subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_attestation_subscriptions.set(subnet);
        } else {
            svc.unsubscribeSubnet(io, .beacon_attestation, @intCast(subnet)) catch |err| {
                log.warn("Failed to unsubscribe attestation subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_attestation_subscriptions.unset(subnet);
        }
        did_work = true;
    }

    subnet = 0;
    while (subnet < SYNC_COMMITTEE_SUBNET_COUNT) : (subnet += 1) {
        const should_subscribe = desired_gossip_syncnets.isSet(subnet);
        const is_subscribed = self.gossip_sync_subscriptions.isSet(subnet);
        if (should_subscribe == is_subscribed) continue;

        if (should_subscribe) {
            svc.subscribeSubnet(io, .sync_committee, @intCast(subnet)) catch |err| {
                log.warn("Failed to subscribe sync subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_sync_subscriptions.set(subnet);
        } else {
            svc.unsubscribeSubnet(io, .sync_committee, @intCast(subnet)) catch |err| {
                log.warn("Failed to unsubscribe sync subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_sync_subscriptions.unset(subnet);
        }
        did_work = true;
    }

    const metadata_attnets = subnet_service.getMetadataAttestationSubnets() catch |err| {
        log.warn("Failed to collect metadata attestation subnets: {}", .{err});
        return false;
    };
    defer if (metadata_attnets.len > 0) self.allocator.free(metadata_attnets);

    const attnets_bytes = attnetsBytesFromSubnets(metadata_attnets);
    const syncnets_bytes = syncnetsBytesFromSubnets(active_syncnets);
    if (!std.mem.eql(u8, &self.api_node_identity.metadata.attnets, &attnets_bytes) or
        !std.mem.eql(u8, &self.api_node_identity.metadata.syncnets, &syncnets_bytes))
    {
        self.api_node_identity.metadata.attnets = attnets_bytes;
        self.api_node_identity.metadata.syncnets = syncnets_bytes;
        self.api_node_identity.metadata.seq_number +%= 1;
        if (self.api_node_identity.metadata.seq_number == 0) {
            self.api_node_identity.metadata.seq_number = 1;
        }

        if (self.discovery_service) |ds| {
            ds.updateSubnets(attnets_bytes, syncnets_bytes) catch |err| {
                log.warn("Failed to update local ENR subnet bitfields: {}", .{err});
            };
            refreshApiNodeIdentityFromDiscovery(self, ds) catch |err| {
                log.warn("Failed to refresh API node identity after subnet update: {}", .{err});
            };
        }
        did_work = true;
    }

    return did_work;
}

fn runPeerManagerHeartbeat(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const pm = self.peer_manager orelse return false;
    const now_ms = currentUnixTimeMs(io);
    const heartbeat_started_ns = timestampNowNs(io);

    if (self.subnet_service) |subnet_service| {
        var did_work = false;
        var housekeeping = pm.housekeeping(now_ms) catch |err| {
            log.warn("PeerManager housekeeping failed: {}", .{err});
            return false;
        };
        defer housekeeping.deinit(self.allocator);

        const active_attnets = getDesiredActiveAttestationSubnets(self, subnet_service) catch |err| {
            log.warn("Failed to read active attestation subnets for prioritization: {}", .{err});
            return false;
        };
        defer if (active_attnets.len > 0) self.allocator.free(active_attnets);

        const active_syncnets = subnet_service.getActiveSyncSubnets() catch |err| {
            log.warn("Failed to read active sync subnets for prioritization: {}", .{err});
            return false;
        };
        defer if (active_syncnets.len > 0) self.allocator.free(active_syncnets);

        var prioritization = pm.runPrioritization(active_attnets, active_syncnets) catch |err| {
            log.warn("PeerManager prioritization failed: {}", .{err});
            return false;
        };
        defer prioritization.deinit(self.allocator);
        pm.notePrioritizationMetrics(housekeeping.peers_to_disconnect.len, &prioritization);
        if (self.metrics) |metrics| {
            metrics.observePeerManagerHeartbeatDuration(nsToSeconds(timestampNowNs(io) - heartbeat_started_ns));
        }

        if (self.discovery_service) |ds| {
            ds.resetRequestedPeerDemand();
            for (prioritization.subnets_needing_peers) |query| {
                ds.requestSubnetPeers(switch (query.kind) {
                    .attestation => .attestation,
                    .sync_committee => .sync_committee,
                }, @intCast(query.subnet_id), @max(query.peers_needed, 1));
                did_work = true;
            }
            for (prioritization.custody_columns_needing_peers) |query| {
                ds.requestCustodyColumnPeers(query.column_index, @max(query.peers_needed, 1));
                did_work = true;
            }
            ds.requestMorePeers(prioritization.peers_to_discover);
            if (prioritization.peers_to_discover > 0) {
                did_work = true;
            }
            ds.discoverPeers(pm);
            did_work = true;
        }

        for (housekeeping.peers_to_disconnect) |peer_id| {
            sendGoodbyeAndDisconnect(self, io, svc, peer_id, heartbeatDisconnectReason(pm.getPeer(peer_id)));
            did_work = true;
        }
        for (prioritization.peers_to_disconnect) |disconnect| {
            if (containsPeerId(housekeeping.peers_to_disconnect, disconnect.peer_id)) continue;
            sendGoodbyeAndDisconnect(self, io, svc, disconnect.peer_id, heartbeatDisconnectReason(pm.getPeer(disconnect.peer_id)));
            did_work = true;
        }

        return did_work;
    }

    var did_work = false;
    svc.syncGossipsubScores(io, pm, now_ms) catch |err| {
        log.warn("Failed to mirror gossipsub scores into peer manager: {}", .{err});
    };
    if (self.req_resp_rate_limiter) |limiter| {
        limiter.pruneInactive(std.Io.Clock.awake.now(io).nanoseconds, networking.rate_limiter.INACTIVE_PEER_TIMEOUT_NS);
    }
    svc.pruneReqRespSelfLimiter(io);

    var actions = pm.heartbeat(now_ms) catch |err| {
        log.warn("PeerManager heartbeat failed: {}", .{err});
        return false;
    };
    defer actions.deinit(self.allocator);
    pm.noteHeartbeatMetrics(&actions);
    if (self.metrics) |metrics| {
        metrics.observePeerManagerHeartbeatDuration(nsToSeconds(timestampNowNs(io) - heartbeat_started_ns));
    }

    if (self.discovery_service) |ds| {
        ds.resetRequestedPeerDemand();
        for (actions.subnets_needing_peers) |subnet_id| {
            ds.requestSubnetPeers(.attestation, @intCast(subnet_id), 1);
            did_work = true;
        }
        ds.requestMorePeers(actions.peers_to_discover);
        if (actions.peers_to_discover > 0) {
            did_work = true;
        }
        ds.discoverPeers(pm);
        did_work = true;
    }

    for (actions.peers_to_disconnect) |peer_id| {
        sendGoodbyeAndDisconnect(self, io, svc, peer_id, heartbeatDisconnectReason(pm.getPeer(peer_id)));
        did_work = true;
    }

    return did_work;
}

fn runPeerManagerMaintenance(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const pm = self.peer_manager orelse return false;

    const now_ms = currentUnixTimeMs(io);
    var actions = pm.maintenance(now_ms, .{}) catch |err| {
        log.warn("PeerManager maintenance selection failed: {}", .{err});
        return false;
    };
    defer actions.deinit(self.allocator);

    if (actions.peers_to_restatus.len > 0 or actions.peers_to_ping.len > 0) {
        log.debug("Peer maintenance scheduled: restatus={d} ping={d}", .{
            actions.peers_to_restatus.len,
            actions.peers_to_ping.len,
        });
    }

    var did_work = false;

    for (actions.peers_to_restatus) |peer_id| {
        const peer = pm.getPeer(peer_id) orelse continue;
        if (peer.last_status_exchange_ms == 0) {
            did_work = schedulePeerReqResp(self, io, svc, peer_id, .status_only) or did_work;
            continue;
        }

        did_work = schedulePeerReqResp(self, io, svc, peer_id, .restatus) or did_work;
    }

    for (actions.peers_to_ping) |peer_id| {
        const peer = pm.getPeer(peer_id) orelse continue;
        did_work = schedulePeerReqResp(self, io, svc, peer_id, .{ .ping = .{
            .known_metadata_seq = peer.metadata_seq,
        } }) or did_work;
    }

    return did_work;
}

fn runRealtimeP2pTick(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    var did_work = false;

    did_work = drainCompletedDiscoveryDials(self, io, svc) or did_work;
    did_work = drainCompletedPeerReqResp(self, io, svc) or did_work;
    did_work = self.processPendingExecutionForkchoiceUpdates() or did_work;
    did_work = self.processPendingExecutionPayloadVerifications() or did_work;
    did_work = self.processPendingBlockStateWork() or did_work;
    did_work = self.processPendingGossipBlsBatch() or did_work;

    if (self.beacon_processor) |bp| {
        const dispatched = bp.tick(128);
        did_work = dispatched > 0 or did_work;
        if (dispatched > 0) {
            log.debug("Processor: dispatched {d} items ({d} queued)", .{
                dispatched,
                bp.totalQueued(),
            });
        }
        if (!did_work) {
            did_work = bp.totalQueued() > 0;
        }
    }

    did_work = self.drainCompletedGossipValidations(io, svc) or did_work;

    if (self.sync_service_inst) |sync_svc| {
        if (currentNetworkSlot(self, io)) |slot| sync_svc.onClockSlot(slot);
        sync_svc.tick() catch |err| {
            log.warn("SyncService.tick failed: {}", .{err});
        };
    }
    did_work = processPendingSyncStatusRefreshes(self, io, svc) or did_work;
    self.unknown_block_sync.tick();
    self.drivePendingUnknownBlockGossip();
    if (shouldDriveUnknownChainSync(self)) self.unknown_chain_sync.tick();
    did_work = self.drivePendingSyncSegments() or did_work;

    maybeHandleForkTransition(self, io, svc);

    did_work = processPendingSyncGossipSubscriptionUpdates(self, io, svc) or did_work;
    processSyncBatches(self, io, svc);
    processSyncByRootRequests(self, io, svc);
    if (shouldDriveUnknownChainSync(self)) self.unknown_chain_sync.tick();
    if (self.unknownChainSyncEnabled()) processPendingLinkedChainImports(self, io, svc);

    // Sync must not wait behind gossip ingress. During range sync gossip is
    // gated anyway, and once synced the next tick still drains gossip promptly.
    did_work = gossip_ingress_mod.processEvents(self, io, svc) > 0 or did_work;

    maybePrepareProposerPayload(self, io);
    pruneSyncCommitteePools(self);
    advanceChainClock(self, io);

    return did_work;
}

fn processPendingSyncStatusRefreshes(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
) bool {
    const cb_ctx = self.sync_callback_ctx orelse return false;

    var did_work = false;
    while (cb_ctx.popPendingReStatus()) |pending| {
        const peer_id = pending.peerId();
        if (self.peer_manager) |pm| {
            if (pm.getPeer(peer_id)) |peer| {
                if (peer.last_status_exchange_ms == 0) {
                    did_work = schedulePeerReqResp(self, io, svc, peer_id, .status_only) or did_work;
                    continue;
                }
            }
        }

        did_work = schedulePeerReqResp(self, io, svc, peer_id, .restatus) or did_work;
    }

    return did_work;
}

fn runLoop(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    log.debug("Starting P2P runtime loop", .{});
    const start_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds();
    var next_connectivity_maintenance_ns = start_ns;
    var next_discovery_maintenance_ns = start_ns;
    var next_peer_maintenance_ns = start_ns;
    var next_metrics_sampling_ns = start_ns;
    var next_peer_manager_heartbeat_ns = start_ns;
    while (!self.shutdown_requested.load(.acquire)) {
        const now_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds();
        var did_work = false;

        did_work = runRealtimeP2pTick(self, io, svc) or did_work;

        if (now_ns >= next_connectivity_maintenance_ns) {
            did_work = runConnectivityMaintenance(self, io, svc) or did_work;
            next_connectivity_maintenance_ns = now_ns + connectivity_maintenance_interval_ns;
        }
        if (now_ns >= next_discovery_maintenance_ns) {
            did_work = runDiscoveryMaintenance(self) or did_work;
            next_discovery_maintenance_ns = now_ns + discovery_maintenance_interval_ns;
        }
        if (now_ns >= next_peer_maintenance_ns) {
            did_work = runPeerManagerMaintenance(self, io, svc) or did_work;
            next_peer_maintenance_ns = now_ns + peer_maintenance_interval_ns;
        }
        if (now_ns >= next_peer_manager_heartbeat_ns) {
            did_work = runPeerManagerHeartbeat(self, io, svc) or did_work;
            next_peer_manager_heartbeat_ns = now_ns + peer_manager_heartbeat_interval_ns;
        }
        if (now_ns >= next_metrics_sampling_ns) {
            updateSyncMetrics(self);
            updateRuntimeMetrics(self, io);
            next_metrics_sampling_ns = now_ns + metrics_sampling_interval_ns;
        }

        const sleep_timeout: std.Io.Timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(@intCast(if (did_work) active_p2p_tick_ns else idle_p2p_tick_ns)),
            .clock = .awake,
        } };
        sleep_timeout.sleep(io) catch break;
    }
}

fn maybeHandleForkTransition(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const network_slot = currentNetworkSlot(self, io) orelse self.currentHeadSlot();
    const current_fork_seq = self.config.forkSeq(network_slot);
    const current_digest = self.config.networkingForkDigestAtSlot(
        network_slot,
        self.genesis_validators_root,
    );
    if (std.mem.eql(u8, &current_digest, &self.last_active_fork_digest)) return;

    if (!std.mem.eql(u8, &self.last_active_fork_digest, &[4]u8{ 0, 0, 0, 0 })) {
        const last_digest_hex = std.fmt.bytesToHex(&self.last_active_fork_digest, .lower);
        const current_digest_hex = std.fmt.bytesToHex(&current_digest, .lower);
        log.info("fork transition detected at slot {d}: {s} -> {s}", .{
            network_slot,
            &last_digest_hex,
            &current_digest_hex,
        });
    }
    _ = syncGossipForkState(self, io, svc);
    if (self.gossip_handler) |gh| {
        gh.updateForkSeq(current_fork_seq);
    }
    self.last_active_fork_digest = current_digest;
}

fn updateSyncMetrics(self: *BeaconNode) void {
    if (self.metrics) |metrics| {
        BeaconNode.publishSyncMetrics(metrics, self.currentComputedSyncStatus());
    }
}

fn updateChainRuntimeMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const snapshot = self.chain_runtime.metricsSnapshot();
    const previous = self.last_chain_metrics_snapshot;
    const head = self.getHead();
    const finalized = self.chainQuery().finalizedCheckpoint();
    const justified = self.chainQuery().justifiedCheckpoint();

    metrics.head_slot.set(head.slot);
    metrics.head_root.set(metrics_mod.rootMetricValue(head.root));
    metrics.finalized_epoch.set(finalized.epoch);
    metrics.justified_epoch.set(justified.epoch);
    metrics.block_state_cache_entries.set(snapshot.block_state_cache_entries);
    metrics.checkpoint_state_cache_entries.set(snapshot.checkpoint_state_cache_entries);
    metrics.checkpoint_state_datastore_entries.set(snapshot.checkpoint_state_datastore_entries);
    metrics.state_regen_queue_length.set(snapshot.queued_state_regen_queue_len);
    metrics.state_work_pending_jobs.set(snapshot.state_work_pending_jobs);
    metrics.state_work_completed_jobs.set(snapshot.state_work_completed_jobs);
    metrics.state_work_active_jobs.set(snapshot.state_work_active_jobs);
    metrics.state_work_last_execution_time_ns.set(snapshot.state_work_last_execution_time_ns);
    metrics.setForkChoiceSnapshot(.{
        .proto_array_nodes = snapshot.forkchoice_nodes,
        .proto_array_block_roots = snapshot.forkchoice_block_roots,
        .votes = snapshot.forkchoice_votes,
        .queued_attestation_slots = snapshot.forkchoice_queued_attestation_slots,
        .queued_attestations_previous_slot = @intCast(snapshot.forkchoice_queued_attestations_previous_slot),
        .validated_attestation_data_roots = snapshot.forkchoice_validated_attestation_data_roots,
        .equivocating_validators = snapshot.forkchoice_equivocating_validators,
        .proposer_boost_active = snapshot.forkchoice_proposer_boost_active,
    });
    metrics.setArchiveProgress(snapshot.archive_last_finalized_slot, snapshot.archive_last_archived_state_epoch);
    metrics.setArchiveOperationalSnapshot(
        snapshot.archive_last_slots_advanced,
        snapshot.archive_last_batch_ops,
        snapshot.archive_last_run_milliseconds,
    );
    metrics.setValidatorMonitorSnapshot(snapshot.validator_monitor_monitored_validators, snapshot.validator_monitor_last_processed_epoch);
    metrics.setProgressLag(
        archiveFinalizedSlotLag(self, snapshot.archive_last_finalized_slot),
        validatorMonitorEpochLag(self, snapshot.validator_monitor_monitored_validators, snapshot.validator_monitor_last_processed_epoch),
    );
    metrics.attestation_pool_groups.set(snapshot.attestation_pool_groups);
    metrics.aggregate_attestation_pool_groups.set(snapshot.aggregate_attestation_pool_groups);
    metrics.aggregate_attestation_pool_entries.set(snapshot.aggregate_attestation_pool_entries);
    metrics.voluntary_exit_pool_size.set(snapshot.voluntary_exit_pool_size);
    metrics.pending_exits.set(snapshot.voluntary_exit_pool_size);
    metrics.proposer_slashing_pool_size.set(snapshot.proposer_slashing_pool_size);
    metrics.attester_slashing_pool_size.set(snapshot.attester_slashing_pool_size);
    metrics.bls_to_execution_change_pool_size.set(snapshot.bls_to_execution_change_pool_size);
    metrics.sync_committee_message_pool_size.set(snapshot.sync_committee_message_pool_size);
    metrics.sync_contribution_pool_size.set(snapshot.sync_contribution_pool_size);
    metrics.proposer_cache_entries.set(snapshot.beacon_proposer_cache_entries);
    metrics.pending_block_ingress_size.set(snapshot.pending_block_ingress_size);
    metrics.pending_payload_envelope_ingress_size.set(snapshot.pending_payload_envelope_ingress_size);
    metrics.reprocess_queue_size.set(snapshot.reprocess_queue_size);
    metrics.da_blob_tracker_entries.set(snapshot.da_blob_tracker_entries);
    metrics.da_column_tracker_entries.set(snapshot.da_column_tracker_entries);
    metrics.da_pending_blocks.set(snapshot.da_pending_blocks);
    const custody_group_count: u64 = if (self.chain.da_manager) |dam|
        @intCast(dam.column_tracker.custody_columns.len)
    else
        0;
    metrics.custody_groups.set(custody_group_count);
    metrics.custody_groups_backfilled.set(if (self.getSyncStatus().is_syncing) 0 else custody_group_count);
    updateDerivedStateMetrics(self, metrics);

    metrics.pending_block_ingress_added_total.incrBy(monotonicDelta(
        snapshot.pending_block_ingress_added_total,
        if (previous) |prev| prev.pending_block_ingress_added_total else null,
    ));
    metrics.pending_block_ingress_replaced_total.incrBy(monotonicDelta(
        snapshot.pending_block_ingress_replaced_total,
        if (previous) |prev| prev.pending_block_ingress_replaced_total else null,
    ));
    metrics.pending_block_ingress_resolved_total.incrBy(monotonicDelta(
        snapshot.pending_block_ingress_resolved_total,
        if (previous) |prev| prev.pending_block_ingress_resolved_total else null,
    ));
    metrics.pending_block_ingress_removed_total.incrBy(monotonicDelta(
        snapshot.pending_block_ingress_removed_total,
        if (previous) |prev| prev.pending_block_ingress_removed_total else null,
    ));
    metrics.pending_block_ingress_pruned_total.incrBy(monotonicDelta(
        snapshot.pending_block_ingress_pruned_total,
        if (previous) |prev| prev.pending_block_ingress_pruned_total else null,
    ));
    metrics.pending_payload_envelope_ingress_added_total.incrBy(monotonicDelta(
        snapshot.pending_payload_envelope_ingress_added_total,
        if (previous) |prev| prev.pending_payload_envelope_ingress_added_total else null,
    ));
    metrics.pending_payload_envelope_ingress_replaced_total.incrBy(monotonicDelta(
        snapshot.pending_payload_envelope_ingress_replaced_total,
        if (previous) |prev| prev.pending_payload_envelope_ingress_replaced_total else null,
    ));
    metrics.pending_payload_envelope_ingress_removed_total.incrBy(monotonicDelta(
        snapshot.pending_payload_envelope_ingress_removed_total,
        if (previous) |prev| prev.pending_payload_envelope_ingress_removed_total else null,
    ));
    metrics.pending_payload_envelope_ingress_pruned_total.incrBy(monotonicDelta(
        snapshot.pending_payload_envelope_ingress_pruned_total,
        if (previous) |prev| prev.pending_payload_envelope_ingress_pruned_total else null,
    ));
    metrics.reprocess_queued_total.incrBy(monotonicDelta(
        snapshot.reprocess_queued_total,
        if (previous) |prev| prev.reprocess_queued_total else null,
    ));
    metrics.reprocess_released_total.incrBy(monotonicDelta(
        snapshot.reprocess_released_total,
        if (previous) |prev| prev.reprocess_released_total else null,
    ));
    metrics.reprocess_dropped_total.incrBy(monotonicDelta(
        snapshot.reprocess_dropped_total,
        if (previous) |prev| prev.reprocess_dropped_total else null,
    ));
    metrics.reprocess_pruned_total.incrBy(monotonicDelta(
        snapshot.reprocess_pruned_total,
        if (previous) |prev| prev.reprocess_pruned_total else null,
    ));
    metrics.da_pending_marked_total.incrBy(monotonicDelta(
        snapshot.da_pending_marked_total,
        if (previous) |prev| prev.da_pending_marked_total else null,
    ));
    metrics.da_pending_resolved_total.incrBy(monotonicDelta(
        snapshot.da_pending_resolved_total,
        if (previous) |prev| prev.da_pending_resolved_total else null,
    ));
    metrics.da_pending_pruned_total.incrBy(monotonicDelta(
        snapshot.da_pending_pruned_total,
        if (previous) |prev| prev.da_pending_pruned_total else null,
    ));

    metrics.archive_runs_total.incrBy(monotonicDelta(
        snapshot.archive_runs_total,
        if (previous) |prev| prev.archive_runs_total else null,
    ));
    metrics.archive_failures_total.incrBy(monotonicDelta(
        snapshot.archive_failures_total,
        if (previous) |prev| prev.archive_failures_total else null,
    ));
    metrics.archive_finalized_slots_advanced_total.incrBy(monotonicDelta(
        snapshot.archive_finalized_slots_advanced_total,
        if (previous) |prev| prev.archive_finalized_slots_advanced_total else null,
    ));
    metrics.archive_state_epochs_archived_total.incrBy(monotonicDelta(
        snapshot.archive_state_epochs_archived_total,
        if (previous) |prev| prev.archive_state_epochs_archived_total else null,
    ));
    metrics.archive_run_milliseconds_total.incrBy(monotonicDelta(
        snapshot.archive_run_milliseconds_total,
        if (previous) |prev| prev.archive_run_milliseconds_total else null,
    ));
    metrics.state_regen_cache_hits_total.incrBy(monotonicDelta(
        snapshot.queued_state_regen_cache_hits,
        if (previous) |prev| prev.queued_state_regen_cache_hits else null,
    ));
    metrics.store_beacon_block_cache_hit_total.incrBy(monotonicDelta(
        snapshot.queued_state_regen_cache_hits,
        if (previous) |prev| prev.queued_state_regen_cache_hits else null,
    ));
    metrics.state_data_cache_misses_total.incrBy(monotonicDelta(
        snapshot.queued_state_regen_cache_misses,
        if (previous) |prev| prev.queued_state_regen_cache_misses else null,
    ));
    metrics.state_regen_queue_hits_total.incrBy(monotonicDelta(
        snapshot.queued_state_regen_queue_hits,
        if (previous) |prev| prev.queued_state_regen_queue_hits else null,
    ));
    metrics.state_regen_dropped_total.incrBy(monotonicDelta(
        snapshot.queued_state_regen_dropped,
        if (previous) |prev| prev.queued_state_regen_dropped else null,
    ));
    metrics.state_work_submitted_total.incrBy(monotonicDelta(
        snapshot.state_work_submitted_total,
        if (previous) |prev| prev.state_work_submitted_total else null,
    ));
    metrics.state_work_rejected_total.incrBy(monotonicDelta(
        snapshot.state_work_rejected_total,
        if (previous) |prev| prev.state_work_rejected_total else null,
    ));
    metrics.state_work_success_total.incrBy(monotonicDelta(
        snapshot.state_work_success_total,
        if (previous) |prev| prev.state_work_success_total else null,
    ));
    metrics.state_work_failure_total.incrBy(monotonicDelta(
        snapshot.state_work_failure_total,
        if (previous) |prev| prev.state_work_failure_total else null,
    ));
    metrics.state_work_execution_time_ns_total.incrBy(monotonicDelta(
        snapshot.state_work_execution_time_ns_total,
        if (previous) |prev| prev.state_work_execution_time_ns_total else null,
    ));

    self.last_chain_metrics_snapshot = snapshot;
}

fn archiveFinalizedSlotLag(self: *BeaconNode, archived_finalized_slot: u64) u64 {
    const finalized_slot = self.currentFinalizedSlot();
    return finalized_slot -| archived_finalized_slot;
}

fn validatorMonitorEpochLag(
    self: *BeaconNode,
    monitored_validators: u64,
    last_processed_epoch: u64,
) u64 {
    if (monitored_validators == 0) return 0;
    const current_epoch = self.currentHeadSlot() / preset.SLOTS_PER_EPOCH;
    return current_epoch -| last_processed_epoch;
}

fn updateExecutionRuntimeMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const snapshot = self.execution_runtime.metricsSnapshot();

    metrics.execution_pending_forkchoice_updates.set(snapshot.pending_forkchoice_updates);
    metrics.execution_pending_payload_verifications.set(snapshot.pending_payload_verifications);
    metrics.execution_completed_forkchoice_updates.set(snapshot.completed_forkchoice_updates);
    metrics.execution_completed_payload_verifications.set(snapshot.completed_payload_verifications);
    metrics.execution_failed_payload_preparations.set(snapshot.failed_payload_preparations);
    metrics.execution_cached_payload.set(if (snapshot.has_cached_payload) 1 else 0);
    metrics.execution_offline.set(if (snapshot.el_offline) 1 else 0);
}

fn updatePeerManagerMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const snapshot = if (self.peer_manager) |pm|
        pm.metricsSnapshot()
    else
        networking.PeerManagerMetricsSnapshot{};
    const previous = self.last_peer_manager_metrics_snapshot;

    metrics.setPeerManagerSnapshot(snapshot);

    inline for (networking.peer_manager.metric_report_sources) |source| {
        inline for (networking.peer_manager.metric_peer_actions) |action| {
            const delta = monotonicDelta(
                snapshot.peerReportCount(source, action),
                if (previous) |prev| prev.peerReportCount(source, action) else null,
            );
            if (delta > 0) {
                metrics.incrPeerReport(source, action, delta);
            }
        }
    }

    inline for (networking.peer_manager.metric_goodbye_reasons) |reason| {
        const delta = monotonicDelta(
            snapshot.goodbyeReceivedCount(reason),
            if (previous) |prev| prev.goodbyeReceivedCount(reason) else null,
        );
        if (delta > 0) {
            metrics.incrPeerGoodbyeReceived(reason, delta);
        }
    }

    self.last_peer_manager_metrics_snapshot = snapshot;
}

fn updateStorageMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const snapshot = self.chain_runtime.storageMetricsSnapshot() catch |err| {
        log.warn("Failed to collect storage metrics snapshot: {}", .{err});
        return;
    };
    const previous = self.last_db_metrics_snapshot;
    metrics.setDbSnapshot(snapshot);
    inline for (db_mod.metrics.metric_operations) |operation| {
        const count_delta = monotonicDelta(
            snapshot.operationCount(operation),
            if (previous) |prev| prev.operationCount(operation) else null,
        );
        if (count_delta > 0) {
            metrics.db_operation_total.incrBy(.{ .operation = @tagName(operation) }, count_delta) catch {};
        }

        const time_delta = monotonicDelta(
            snapshot.operationTimeNs(operation),
            if (previous) |prev| prev.operationTimeNs(operation) else null,
        );
        if (time_delta > 0) {
            metrics.db_operation_time_ns_total.incrBy(.{ .operation = @tagName(operation) }, time_delta) catch {};
        }
    }
    self.last_db_metrics_snapshot = snapshot;
}

fn updateReqRespMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const inbound_peers = if (self.req_resp_rate_limiter) |limiter|
        limiter.peerCount()
    else
        0;
    const outbound_peers = if (self.p2p_service) |*svc|
        svc.reqRespSelfLimiterPeerCount(self.io)
    else
        0;
    metrics.setReqRespLimiterPeers(inbound_peers, outbound_peers);
}

fn updateProcessorMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const processor = self.beacon_processor orelse return;
    const snapshot = processor.metricsSnapshot();
    const previous = self.last_processor_metrics_snapshot;

    metrics.processor_queue_depth.set(.{ .queue = "total" }, snapshot.queue_depths.total) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_block_ingress" }, snapshot.queue_depths.gossip_block_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_blob_ingress" }, snapshot.queue_depths.gossip_blob_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_data_column_ingress" }, snapshot.queue_depths.gossip_data_column_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_attestation_ingress" }, snapshot.queue_depths.gossip_attestation_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_aggregate_ingress" }, snapshot.queue_depths.gossip_aggregate_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_sync_message_ingress" }, snapshot.queue_depths.gossip_sync_message_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_sync_contribution_ingress" }, snapshot.queue_depths.gossip_sync_contribution_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_voluntary_exit_ingress" }, snapshot.queue_depths.gossip_voluntary_exit_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_proposer_slashing_ingress" }, snapshot.queue_depths.gossip_proposer_slashing_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_attester_slashing_ingress" }, snapshot.queue_depths.gossip_attester_slashing_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_bls_to_exec_ingress" }, snapshot.queue_depths.gossip_bls_to_exec_ingress) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "gossip_blocks" }, snapshot.queue_depths.gossip_blocks) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "blob_sidecars" }, snapshot.queue_depths.blob_sidecars) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "data_column_sidecars" }, snapshot.queue_depths.data_column_sidecars) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "attestations" }, snapshot.queue_depths.attestations) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "aggregates" }, snapshot.queue_depths.aggregates) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "sync_messages" }, snapshot.queue_depths.sync_messages) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "sync_contributions" }, snapshot.queue_depths.sync_contributions) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "voluntary_exits" }, snapshot.queue_depths.voluntary_exits) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "proposer_slashings" }, snapshot.queue_depths.proposer_slashings) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "attester_slashings" }, snapshot.queue_depths.attester_slashings) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "bls_to_execution_changes" }, snapshot.queue_depths.bls_to_execution_changes) catch {};
    metrics.processor_queue_depth.set(.{ .queue = "pool_objects" }, snapshot.queue_depths.pool_objects) catch {};
    metrics.setGossipProcessorQueueDepth(.block, snapshot.queue_depths.gossip_blocks);
    metrics.setGossipProcessorQueueDepth(.blob_sidecar, snapshot.queue_depths.blob_sidecars);
    metrics.setGossipProcessorQueueDepth(.data_column_sidecar, snapshot.queue_depths.data_column_sidecars);
    metrics.setGossipProcessorQueueDepth(.attestation, snapshot.queue_depths.attestations);
    metrics.setGossipProcessorQueueDepth(.aggregate, snapshot.queue_depths.aggregates);
    metrics.setGossipProcessorQueueDepth(.sync_message, snapshot.queue_depths.sync_messages);
    metrics.setGossipProcessorQueueDepth(.sync_contribution, snapshot.queue_depths.sync_contributions);
    metrics.setGossipProcessorQueueDepth(.voluntary_exit, snapshot.queue_depths.voluntary_exits);
    metrics.setGossipProcessorQueueDepth(.proposer_slashing, snapshot.queue_depths.proposer_slashings);
    metrics.setGossipProcessorQueueDepth(.attester_slashing, snapshot.queue_depths.attester_slashings);
    metrics.setGossipProcessorQueueDepth(.bls_to_execution_change, snapshot.queue_depths.bls_to_execution_changes);
    metrics.setGossipProcessorQueueDepth(.pool_object, snapshot.queue_depths.pool_objects);

    metrics.processor_loop_iterations_total.incrBy(monotonicDelta(
        snapshot.loop_iterations,
        if (previous) |prev| prev.loop_iterations else null,
    ));
    metrics.processor_items_received_total.incrBy(monotonicDelta(
        snapshot.items_received,
        if (previous) |prev| prev.items_received else null,
    ));
    metrics.processor_items_dispatched_total.incrBy(monotonicDelta(
        snapshot.items_dispatched,
        if (previous) |prev| prev.items_dispatched else null,
    ));
    metrics.processor_items_dropped_full_total.incrBy(monotonicDelta(
        snapshot.items_dropped_full,
        if (previous) |prev| prev.items_dropped_full else null,
    ));
    metrics.processor_items_dropped_sync_total.incrBy(monotonicDelta(
        snapshot.items_dropped_sync,
        if (previous) |prev| prev.items_dropped_sync else null,
    ));

    inline for (std.meta.tags(processor_mod.WorkType)) |work_type| {
        const index = @intFromEnum(work_type);
        const processed_delta = monotonicDelta(
            snapshot.items_processed[index],
            if (previous) |prev| prev.items_processed[index] else null,
        );
        if (processed_delta > 0) {
            metrics.processor_items_processed_total.incrBy(
                .{ .work_type = @tagName(work_type) },
                processed_delta,
            ) catch {};
        }

        const time_delta = monotonicDelta(
            snapshot.processing_time_ns[index],
            if (previous) |prev| prev.processing_time_ns[index] else null,
        );
        if (time_delta > 0) {
            metrics.processor_processing_time_ns_total.incrBy(
                .{ .work_type = @tagName(work_type) },
                time_delta,
            ) catch {};
        }
    }

    self.last_processor_metrics_snapshot = snapshot;
}

fn updateGossipBlsMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const snapshot = self.gossipBlsPendingSnapshot();
    metrics.setGossipBlsPendingSnapshot(.attestation, snapshot.attestation_batches, snapshot.attestation_items);
    metrics.setGossipBlsPendingSnapshot(.aggregate, snapshot.aggregate_batches, snapshot.aggregate_items);
    metrics.setGossipBlsPendingSnapshot(.sync_message, snapshot.sync_message_batches, snapshot.sync_message_items);
}

fn updateHeadCatchupMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const head = self.getHead();
    const current_slot = if (self.clock) |clock| clock.currentSlot(self.io) else null;
    const head_lag_slots = if (current_slot) |slot| slot -| head.slot else 0;
    const current_ms = if (current_slot) |slot| self.currentTimeToHeadMs(slot, head.slot) else 0;
    metrics.setHeadCatchupSnapshot(head_lag_slots, self.headCatchupPendingCount(), current_ms);
}

fn currentPendingDiscoveryDials(self: *BeaconNode, io: std.Io) usize {
    self.discovery_dial_mutex.lockUncancelable(io);
    defer self.discovery_dial_mutex.unlock(io);
    return self.pending_discovery_dial_count;
}

fn updateDiscoveryMetrics(self: *BeaconNode, io: std.Io) void {
    const metrics = self.metrics orelse return;
    const snapshot: networking.discovery_service.DiscoveryStats = if (self.discovery_service) |ds|
        ds.getStats()
    else
        .{
            .known_peers = 0,
            .connected_peers = 0,
            .total_lookups = 0,
            .total_discovered = 0,
            .total_filtered_out = 0,
            .queued_peers = 0,
            .pending_subnet_queries = 0,
            .peers_to_connect = 0,
            .subnets_to_connect = [_]u64{0} ** networking.discovery_service.metric_requested_subnet_demand_kinds.len,
            .subnet_peers_to_connect = [_]u64{0} ** networking.discovery_service.metric_requested_subnet_demand_kinds.len,
            .enr_cache_size = 0,
            .enr_seq = 0,
            .lookup_request_counts = [_]u64{0} ** networking.discovery_service.metric_lookup_sources.len,
            .discovered_status_counts = [_]u64{0} ** networking.discovery_service.metric_discovered_statuses.len,
            .not_dial_reason_counts = [_]u64{0} ** networking.discovery_service.metric_not_dial_reasons.len,
        };
    const previous = self.last_discovery_stats;

    metrics.discovery_peers_known.set(@intCast(snapshot.known_peers));
    metrics.discovery_connected_peers.set(snapshot.connected_peers);
    metrics.discovery_queued_peers.set(@intCast(snapshot.queued_peers));
    metrics.discovery_pending_subnet_queries.set(@intCast(snapshot.pending_subnet_queries));
    metrics.discovery_peers_to_connect.set(snapshot.peers_to_connect);
    metrics.discovery_custody_group_peers_to_connect.set(snapshot.subnetPeersToConnect(.column));
    metrics.discovery_custody_groups_to_connect.set(snapshot.subnetCount(.column));
    metrics.discovery_enr_cache_size.set(@intCast(snapshot.enr_cache_size));
    metrics.discovery_enr_seq.set(snapshot.enr_seq);
    metrics.discovery_pending_dials.set(@intCast(currentPendingDiscoveryDials(self, io)));
    inline for (networking.discovery_service.metric_requested_subnet_demand_kinds) |kind| {
        const label = switch (kind) {
            .attnets => "attnets",
            .syncnets => "syncnets",
            .column => "column",
        };
        metrics.discovery_subnets_to_connect.set(.{ .type = label }, snapshot.subnetCount(kind)) catch {};
        metrics.discovery_subnet_peers_to_connect.set(.{ .type = label }, snapshot.subnetPeersToConnect(kind)) catch {};
    }
    metrics.discovery_lookups_total.incrBy(monotonicDelta(
        snapshot.total_lookups,
        if (previous) |prev| prev.total_lookups else null,
    ));
    metrics.discovery_discovered_total.incrBy(monotonicDelta(
        snapshot.total_discovered,
        if (previous) |prev| prev.total_discovered else null,
    ));
    metrics.discovery_filtered_total.incrBy(monotonicDelta(
        snapshot.total_filtered_out,
        if (previous) |prev| prev.total_filtered_out else null,
    ));
    inline for (networking.discovery_service.metric_lookup_sources) |source| {
        const delta = monotonicDelta(
            snapshot.lookupRequestCount(source),
            if (previous) |prev| prev.lookupRequestCount(source) else null,
        );
        if (delta > 0) {
            metrics.discovery_find_node_query_requests_total.incrBy(.{ .action = @tagName(source) }, delta) catch {};
        }
    }
    inline for (networking.discovery_service.metric_discovered_statuses) |status| {
        const delta = monotonicDelta(
            snapshot.discoveredStatusCount(status),
            if (previous) |prev| prev.discoveredStatusCount(status) else null,
        );
        if (delta > 0) {
            metrics.discovery_discovered_status_total_count.incrBy(.{ .status = @tagName(status) }, delta) catch {};
        }
    }
    inline for (networking.discovery_service.metric_not_dial_reasons) |reason| {
        const delta = monotonicDelta(
            snapshot.notDialReasonCount(reason),
            if (previous) |prev| prev.notDialReasonCount(reason) else null,
        );
        if (delta > 0) {
            metrics.discovery_not_dial_reason_total_count.incrBy(.{ .reason = @tagName(reason) }, delta) catch {};
        }
    }

    self.last_discovery_stats = snapshot;
}

fn updateP2pServiceMetrics(self: *BeaconNode, io: std.Io) void {
    const metrics = self.metrics orelse return;
    const snapshot: networking.P2pGossipsubMetricsSnapshot = if (self.p2p_service) |*svc| blk: {
        const current = svc.gossipsubMetricsSnapshot(io);
        if (networking.P2pService.hasSubscriptionTrackingDrift(current)) {
            const now_ns = timestampNowNs(io);
            if (now_ns -| self.last_gossipsub_subscription_drift_log_ns >= 30 * std.time.ns_per_s) {
                self.last_gossipsub_subscription_drift_log_ns = now_ns;
                svc.logGossipsubSubscriptionDiagnostics(io);
            }
        }
        break :blk current;
    } else .{};
    metrics.setGossipsubSnapshot(snapshot);
}

fn setRangeSyncTypeMetrics(
    metrics: *BeaconMetrics,
    sync_type: sync_mod.RangeSyncType,
    current: sync_mod.range_sync.TypeMetricsSnapshot,
    previous: ?sync_mod.range_sync.TypeMetricsSnapshot,
) void {
    const label = @tagName(sync_type);

    metrics.range_sync_active_chains.set(.{ .sync_type = label }, current.active_chains) catch {};
    metrics.range_sync_peers.set(.{ .sync_type = label }, current.peer_count) catch {};
    metrics.range_sync_target_slot.set(.{ .sync_type = label }, current.highest_target_slot) catch {};
    metrics.range_sync_validated_epochs.set(.{ .sync_type = label }, current.validated_epochs) catch {};
    metrics.range_sync_batches.set(.{ .sync_type = label }, current.batches_total) catch {};
    metrics.range_sync_batch_statuses.set(.{ .sync_type = label, .status = "awaiting_download" }, current.batch_statuses.awaiting_download) catch {};
    metrics.range_sync_batch_statuses.set(.{ .sync_type = label, .status = "downloading" }, current.batch_statuses.downloading) catch {};
    metrics.range_sync_batch_statuses.set(.{ .sync_type = label, .status = "awaiting_processing" }, current.batch_statuses.awaiting_processing) catch {};
    metrics.range_sync_batch_statuses.set(.{ .sync_type = label, .status = "processing" }, current.batch_statuses.processing) catch {};
    metrics.range_sync_batch_statuses.set(.{ .sync_type = label, .status = "awaiting_validation" }, current.batch_statuses.awaiting_validation) catch {};

    const prev: sync_mod.range_sync.TypeMetricsSnapshot = previous orelse .{};

    const download_requests_delta = monotonicDelta(current.cumulative.download_requests_total, prev.cumulative.download_requests_total);
    if (download_requests_delta > 0) metrics.range_sync_download_requests_total.incrBy(.{ .sync_type = label }, download_requests_delta) catch {};
    const download_success_delta = monotonicDelta(current.cumulative.download_success_total, prev.cumulative.download_success_total);
    if (download_success_delta > 0) metrics.range_sync_download_success_total.incrBy(.{ .sync_type = label }, download_success_delta) catch {};
    const download_error_delta = monotonicDelta(current.cumulative.download_error_total, prev.cumulative.download_error_total);
    if (download_error_delta > 0) metrics.range_sync_download_error_total.incrBy(.{ .sync_type = label }, download_error_delta) catch {};
    const download_deferred_delta = monotonicDelta(current.cumulative.download_deferred_total, prev.cumulative.download_deferred_total);
    if (download_deferred_delta > 0) metrics.range_sync_download_deferred_total.incrBy(.{ .sync_type = label }, download_deferred_delta) catch {};
    const download_time_delta = monotonicDelta(current.cumulative.download_time_ns_total, prev.cumulative.download_time_ns_total);
    if (download_time_delta > 0) metrics.range_sync_download_time_ns_total.incrBy(.{ .sync_type = label }, download_time_delta) catch {};
    const processing_success_delta = monotonicDelta(current.cumulative.processing_success_total, prev.cumulative.processing_success_total);
    if (processing_success_delta > 0) metrics.range_sync_processing_success_total.incrBy(.{ .sync_type = label }, processing_success_delta) catch {};
    const processing_error_delta = monotonicDelta(current.cumulative.processing_error_total, prev.cumulative.processing_error_total);
    if (processing_error_delta > 0) metrics.range_sync_processing_error_total.incrBy(.{ .sync_type = label }, processing_error_delta) catch {};
    const processing_time_delta = monotonicDelta(current.cumulative.processing_time_ns_total, prev.cumulative.processing_time_ns_total);
    if (processing_time_delta > 0) metrics.range_sync_processing_time_ns_total.incrBy(.{ .sync_type = label }, processing_time_delta) catch {};
    const processed_blocks_delta = monotonicDelta(current.cumulative.processed_blocks_total, prev.cumulative.processed_blocks_total);
    if (processed_blocks_delta > 0) metrics.range_sync_processed_blocks_total.incrBy(.{ .sync_type = label }, processed_blocks_delta) catch {};
}

const PendingRangeSyncSegmentMetrics = struct {
    pending_segments: u64 = 0,
    inflight_segments: u64 = 0,
    pending_blocks: u64 = 0,
    pending_remaining_blocks: u64 = 0,
};

fn updatePendingSyncSegmentMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;

    var finalized: PendingRangeSyncSegmentMetrics = .{};
    var head: PendingRangeSyncSegmentMetrics = .{};

    for (self.pending_sync_segments.items) |segment| {
        const current = switch (segment.sync_type) {
            .finalized => &finalized,
            .head => &head,
        };
        current.pending_segments += 1;
        if (segment.in_flight) current.inflight_segments += 1;
        current.pending_blocks += @intCast(segment.blocks.len);
        const next_index = @min(segment.next_index, segment.blocks.len);
        current.pending_remaining_blocks += @intCast(segment.blocks.len - next_index);
    }

    metrics.setRangeSyncPendingSnapshot(
        .finalized,
        finalized.pending_segments,
        finalized.inflight_segments,
        finalized.pending_blocks,
        finalized.pending_remaining_blocks,
    );
    metrics.setRangeSyncPendingSnapshot(
        .head,
        head.pending_segments,
        head.inflight_segments,
        head.pending_blocks,
        head.pending_remaining_blocks,
    );
}

fn updateSyncServiceMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const sync_svc = self.sync_service_inst orelse return;
    const snapshot = sync_svc.metricsSnapshot();
    const previous = self.last_sync_service_metrics_snapshot;

    metrics.sync_mode.set(@intFromEnum(snapshot.mode));
    metrics.setSyncModeState(snapshot.mode);
    metrics.sync_gossip_enabled.set(if (snapshot.gossip_state == .enabled) 1 else 0);
    metrics.sync_peer_count.set(snapshot.peer_count);
    metrics.sync_best_peer_slot.set(snapshot.best_peer_slot);
    metrics.sync_local_head_slot.set(snapshot.local_head_slot);
    metrics.sync_peer_distance.set(snapshot.best_peer_slot -| snapshot.local_head_slot);
    metrics.sync_local_finalized_epoch.set(snapshot.local_finalized_epoch);
    // Gossip/orphan recovery is driven by the node-owned UnknownBlockSync.
    // SyncService still has a stale internal instance, so its snapshot does
    // not reflect the live orphan queue.
    metrics.setUnknownBlockSnapshot(self.unknown_block_sync.metricsSnapshot());

    setRangeSyncTypeMetrics(
        metrics,
        .finalized,
        snapshot.range_sync.finalized,
        if (previous) |prev| prev.range_sync.finalized else null,
    );
    setRangeSyncTypeMetrics(
        metrics,
        .head,
        snapshot.range_sync.head,
        if (previous) |prev| prev.range_sync.head else null,
    );

    self.last_sync_service_metrics_snapshot = snapshot;
}

fn updateRuntimeMetrics(self: *BeaconNode, io: std.Io) void {
    if (self.metrics == null) return;
    updateChainRuntimeMetrics(self);
    updateProcessMetrics(self);
    updateExecutionRuntimeMetrics(self);
    updatePeerManagerMetrics(self);
    updateP2pServiceMetrics(self, io);
    updateProcessorMetrics(self);
    updateGossipBlsMetrics(self);
    updateDiscoveryMetrics(self, io);
    updateSyncServiceMetrics(self);
    updatePendingSyncSegmentMetrics(self);
    updateHeadCatchupMetrics(self);
    updateReqRespMetrics(self);
    updateStorageMetrics(self);
}

pub fn refreshScrapeMetrics(self: *BeaconNode) void {
    refreshScrapeSyncMetrics(self);
    refreshScrapeHeadCatchupMetrics(self);
}

fn refreshScrapeSyncMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    BeaconNode.publishSyncMetrics(metrics, self.scrapeComputedSyncStatus());
}

fn refreshScrapeHeadCatchupMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    const head_slot = self.latestHeadProgressForMetrics().slot;
    const current_slot = if (self.clock) |clock| clock.currentSlot(self.io) else null;
    const head_lag_slots = if (current_slot) |slot| slot -| head_slot else 0;
    const current_ms = if (current_slot) |slot| self.currentTimeToHeadMs(slot, head_slot) else 0;
    metrics.setHeadCatchupSnapshot(head_lag_slots, self.headCatchupPendingCount(), current_ms);
}

fn updateProcessMetrics(self: *BeaconNode) void {
    const metrics = self.metrics orelse return;
    metrics.process_cpu_seconds_total.set(currentProcessCpuSeconds());
    metrics.process_max_fds.set(currentProcessMaxFds());
}

fn currentProcessCpuSeconds() f64 {
    const usage = std.posix.getrusage(std.posix.rusage.SELF);
    return timevalSeconds(usage.utime) + timevalSeconds(usage.stime);
}

fn currentProcessMaxFds() u64 {
    const limits = std.posix.getrlimit(.NOFILE) catch return 0;
    return @intCast(limits.cur);
}

fn timevalSeconds(tv: anytype) f64 {
    return @as(f64, @floatFromInt(tv.sec)) + (@as(f64, @floatFromInt(tv.usec)) / 1_000_000.0);
}

fn updateDerivedStateMetrics(self: *BeaconNode, metrics: *BeaconMetrics) void {
    const cached = self.headState() orelse return;
    const head_state_root = self.chain.headStateRoot();
    if (self.last_state_metrics_root) |last_root| {
        if (std.mem.eql(u8, &last_root, &head_state_root)) return;
    }
    self.last_state_metrics_root = head_state_root;

    metrics.head_state_root.set(metrics_mod.rootMetricValue(head_state_root));

    const state_slot = cached.state.slot() catch return;
    const current_epoch = computeEpochAtSlot(state_slot);
    const validators_count = cached.state.validatorsCount() catch 0;

    var current_justified: types.phase0.Checkpoint.Type = undefined;
    if (cached.state.currentJustifiedCheckpoint(&current_justified)) |_| {
        metrics.current_justified_epoch.set(current_justified.epoch);
    } else |_| {}

    var previous_justified: types.phase0.Checkpoint.Type = undefined;
    if (cached.state.previousJustifiedCheckpoint(&previous_justified)) |_| {
        metrics.previous_justified_epoch.set(previous_justified.epoch);
        metrics.previous_justified_root.set(metrics_mod.rootMetricValue(previous_justified.root));
    } else |_| {}

    var finalized: types.phase0.Checkpoint.Type = undefined;
    if (cached.state.finalizedCheckpoint(&finalized)) |_| {
        metrics.head_state_finalized_root.set(metrics_mod.rootMetricValue(finalized.root));
    } else |_| {}

    metrics.current_active_validators.set(if (cached.epoch_cache.getActiveIndicesAtEpoch(current_epoch)) |indices|
        @intCast(indices.len)
    else
        0);
    metrics.current_validators.set(@intCast(validators_count));
    metrics.previous_validators.set(@intCast(validators_count));
    metrics.current_live_validators.set(currentLiveValidatorCount(self, cached, current_epoch));
    metrics.previous_live_validators.set(previousLiveValidatorCount(self, cached, current_epoch));
    metrics.pending_deposits.set(pendingDepositsCount(cached.state));
    metrics.pending_partial_withdrawals.set(pendingPartialWithdrawalsCount(cached.state));
    metrics.pending_consolidations.set(pendingConsolidationsCount(cached.state));
    metrics.processed_deposits_total.set(cached.state.eth1DepositIndex() catch 0);

    if (self.last_previous_epoch_orphaned_epoch == null or self.last_previous_epoch_orphaned_epoch.? != current_epoch) {
        metrics.previous_epoch_orphaned_blocks.set(countPreviousEpochOrphanedBlocks(self, current_epoch));
        self.last_previous_epoch_orphaned_epoch = current_epoch;
    }
}

fn currentLiveValidatorCount(
    self: *BeaconNode,
    cached: *state_transition.CachedBeaconState,
    current_epoch: u64,
) u64 {
    var current_participation = cached.state.currentEpochParticipation() catch return 0;
    const participation = current_participation.getAll(self.allocator) catch return 0;
    defer self.allocator.free(participation);
    return countParticipatingActiveValidators(
        cached.epoch_cache.getActiveIndicesAtEpoch(current_epoch),
        participation,
    );
}

fn previousLiveValidatorCount(
    self: *BeaconNode,
    cached: *state_transition.CachedBeaconState,
    current_epoch: u64,
) u64 {
    if (current_epoch == 0) return 0;
    var previous_participation = cached.state.previousEpochParticipation() catch return 0;
    const participation = previous_participation.getAll(self.allocator) catch return 0;
    defer self.allocator.free(participation);
    return countParticipatingActiveValidators(
        cached.epoch_cache.getActiveIndicesAtEpoch(current_epoch - 1),
        participation,
    );
}

fn countParticipatingActiveValidators(active_indices_opt: anytype, participation: []const u8) u64 {
    const active_indices = active_indices_opt orelse return 0;
    var count: u64 = 0;
    for (active_indices) |validator_index| {
        const index: usize = @intCast(validator_index);
        if (index < participation.len and participation[index] != 0) count += 1;
    }
    return count;
}

fn pendingDepositsCount(state: *fork_types.AnyBeaconState) u64 {
    var pending = state.pendingDeposits() catch return 0;
    return @intCast(pending.length() catch 0);
}

fn pendingPartialWithdrawalsCount(state: *fork_types.AnyBeaconState) u64 {
    var pending = state.pendingPartialWithdrawals() catch return 0;
    return @intCast(pending.length() catch 0);
}

fn pendingConsolidationsCount(state: *fork_types.AnyBeaconState) u64 {
    var pending = state.pendingConsolidations() catch return 0;
    return @intCast(pending.length() catch 0);
}

fn countPreviousEpochOrphanedBlocks(self: *BeaconNode, current_epoch: u64) u64 {
    if (current_epoch == 0) return 0;
    const fc = self.chain.forkChoice();
    const non_ancestors = fc.getAllNonAncestorBlocks(self.allocator, fc.head.block_root, fc.head.payload_status) catch
        return 0;
    defer self.allocator.free(non_ancestors);

    var count: u64 = 0;
    const previous_epoch = current_epoch - 1;
    for (non_ancestors) |block| {
        if (computeEpochAtSlot(block.slot) == previous_epoch) count += 1;
    }
    return count;
}

fn monotonicDelta(current: u64, previous: ?u64) u64 {
    const prev = previous orelse return current;
    return if (current >= prev) current - prev else current;
}

fn pruneSyncCommitteePools(self: *BeaconNode) void {
    const head_slot = self.currentHeadSlot();
    self.chainService().pruneSyncCommitteePools(head_slot);
}

const SlotStatusPhase = enum {
    synced,
    syncing,
    searching,
};

fn slotStatusPhase(sync: SyncStatus, connected_peers: u32) SlotStatusPhase {
    if (!sync.is_syncing) return .synced;
    return if (connected_peers == 0) .searching else .syncing;
}

fn executionStatusLabel(sync: SyncStatus) []const u8 {
    if (sync.el_offline) return "offline";
    return if (sync.is_optimistic) "syncing" else "valid";
}

fn logPerSlotStatus(self: *BeaconNode, current_slot: u64) void {
    const head = self.getHead();
    const finalized = self.chainQuery().finalizedCheckpoint();
    const sync = self.getSyncStatus();
    const connected_peers: u32 = if (self.peer_manager) |pm| pm.peerCount() else 0;
    const sync_snapshot = if (self.sync_service_inst) |sync_svc| sync_svc.metricsSnapshot() else null;
    const peer_sync_distance = if (sync_snapshot) |snapshot|
        snapshot.best_peer_slot -| snapshot.local_head_slot
    else
        0;
    const sync_mode = if (sync_snapshot) |snapshot| @tagName(snapshot.mode) else "none";
    const gossip_state = if (sync_snapshot) |snapshot| @tagName(snapshot.gossip_state) else "unknown";
    const exec_forkchoice = self.chainQuery().executionForkchoiceState(head.root);
    const exec_head = if (exec_forkchoice) |fc| fc.head_block_hash else std.mem.zeroes([32]u8);
    const ctx = .{
        current_slot,
        head.slot,
        current_slot -| head.slot,
        &std.fmt.bytesToHex(head.root[0..4], .lower),
        executionStatusLabel(sync),
        &std.fmt.bytesToHex(exec_head[0..4], .lower),
        finalized.epoch,
        &std.fmt.bytesToHex(finalized.root[0..4], .lower),
        connected_peers,
        sync.sync_distance,
        peer_sync_distance,
        sync_mode,
        gossip_state,
    };
    const fmt = "slot={d} head_slot={d} head_lag_slots={d} head_root={s}... exec_status={s} exec_head={s}... finalized_epoch={d} finalized_root={s}... peers={d} wall_sync_distance={d} peer_sync_distance={d} sync_mode={s} gossip_state={s}";

    switch (slotStatusPhase(sync, connected_peers)) {
        .synced => log.info("Synced " ++ fmt, ctx),
        .syncing => log.info("Syncing " ++ fmt, ctx),
        .searching => log.info("Searching " ++ fmt, ctx),
    }
}

fn advanceChainClock(self: *BeaconNode, io: std.Io) void {
    const clock = self.clock orelse return;
    const current_slot = clock.currentSlot(io) orelse return;
    const first_tracked_slot = if (self.last_slot_tick) |last_slot| last_slot + 1 else current_slot;

    if (self.last_slot_tick) |last_slot| {
        if (current_slot <= last_slot) return;
    }

    self.chainService().onSlot(current_slot);
    self.onPendingUnknownBlockSlot(current_slot);
    self.last_slot_tick = current_slot;
    self.noteHeadCatchupSlotsStarted(first_tracked_slot, current_slot);
    self.observeHeadCatchup(self.getHead().slot);
    logPerSlotStatus(self, current_slot);

    self.queueCurrentOptimisticHeadRevalidation();
}

fn dialBootnodeEnr(self: *BeaconNode, io: std.Io, svc: *networking.P2pService, enr_str: []const u8) !void {
    var s: []const u8 = enr_str;
    if (std.mem.startsWith(u8, s, "enr:")) s = s[4..];

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(s) catch |err| {
        log.err("ENR base64 calcSize failed: {} for input[0..@min(s.len,20)]={s}", .{ err, s[0..@min(s.len, 20)] });
        return error.InvalidEnr;
    };
    const raw = try self.allocator.alloc(u8, decoded_len);
    defer self.allocator.free(raw);
    std.base64.url_safe_no_pad.Decoder.decode(raw, s) catch |err| {
        log.err("ENR base64 decode failed: {}", .{err});
        return error.InvalidEnr;
    };

    var enr = try discv5.enr.decode(self.allocator, raw);
    defer enr.deinit();

    const dial_addr = preferredBootnodeDialAddress(self, &enr) orelse return error.NoDialableAddressInEnr;

    var bootnode_peer_id_text: ?[]u8 = null;
    defer if (bootnode_peer_id_text) |peer_id| self.allocator.free(peer_id);

    if (enr.pubkey) |pubkey| {
        bootnode_peer_id_text = try discoveryPeerIdTextFromPubkey(self.allocator, pubkey);
    }

    var ma_buf: [240]u8 = undefined;
    const ma_str = try formatDiscv5DialMultiaddr(&ma_buf, dial_addr, bootnode_peer_id_text);

    log.debug("Dialing bootnode at {s}", .{ma_str});

    const peer_id = try dialPeerWithTimeout(self, io, svc, ma_str, outbound_dial_timeout_ms);
    defer self.allocator.free(peer_id);

    log.debug("Connected to bootnode, peer_id: {s}", .{peer_id});
    _ = registerConnectedPeer(
        self,
        io,
        svc,
        peer_id,
        .outbound,
        if (enr.pubkey) |pubkey|
            .{ .node_id = discv5.enr.nodeIdFromCompressedPubkey(&pubkey), .pubkey = pubkey }
        else
            null,
        .none,
    );
}

fn dialDirectPeer(self: *BeaconNode, io: std.Io, svc: *networking.P2pService, addr_str: []const u8) !void {
    log.debug("Dialing direct peer at {s}", .{addr_str});

    const peer_id = try dialPeerWithTimeout(self, io, svc, addr_str, outbound_dial_timeout_ms);
    defer self.allocator.free(peer_id);

    log.debug("Connected to direct peer {s} via {s}", .{ peer_id, addr_str });
    _ = registerConnectedPeer(self, io, svc, peer_id, .outbound, null, .status_only);
}

fn initDiscoveryService(self: *BeaconNode) !void {
    const fork_digest = self.config.networkingForkDigestAtSlot(
        currentNetworkSlot(self, self.io) orelse self.currentHeadSlot(),
        self.genesis_validators_root,
    );

    const ds = try self.allocator.create(DiscoveryService);
    errdefer self.allocator.destroy(ds);
    // QUIC transport binds p2p_port on UDP, so discv5 must use a separate port
    // to avoid AddressInUse. Default to p2p_port + 1 when not explicitly set.
    const disc_port = self.node_options.discovery_port orelse self.node_options.p2p_port + 1;
    const disc_port6 = self.node_options.discovery_port6 orelse if (self.node_options.p2p_port6) |p6| p6 + 1 else null;
    const local_ip = if (self.node_options.p2p_host) |host|
        parseIp4(host) orelse return error.InvalidListenAddress
    else
        null;
    const local_ip6 = if (self.node_options.p2p_host6) |host|
        parseIp6(host) orelse return error.InvalidListenAddress
    else
        null;
    const enr_ip = if (self.node_options.enr_ip) |raw|
        parseIp4(raw) orelse return error.InvalidEnrAddress
    else
        null;
    const enr_ip6 = if (self.node_options.enr_ip6) |raw|
        parseIp6(raw) orelse return error.InvalidEnrAddress
    else
        null;

    ds.* = try DiscoveryService.init(self.io, self.allocator, .{
        .listen_port = disc_port,
        .listen_port6 = disc_port6,
        .secret_key = self.node_identity.secret_key,
        .local_ip = local_ip,
        .local_ip6 = local_ip6,
        .enr_ip = enr_ip,
        .enr_ip6 = enr_ip6,
        .enr_tcp = self.node_options.enr_tcp,
        .enr_udp = self.node_options.enr_udp,
        .enr_tcp6 = self.node_options.enr_tcp6,
        .enr_udp6 = self.node_options.enr_udp6,
        .p2p_port = self.node_options.p2p_port,
        .p2p_port6 = self.node_options.p2p_port6,
        .custody_group_count = @intCast(self.chain_runtime.custody_columns.len),
        .default_custody_group_count = self.config.chain.CUSTODY_REQUIREMENT,
        .fork_digest = fork_digest,
        .target_peers = self.node_options.target_peers,
        .bootnodes = self.discovery_bootnodes,
    });

    ds.seedBootnodes();
    self.discovery_service = ds;
    try refreshApiNodeIdentityFromDiscovery(self, ds);

    log.info("discovery service initialized (known_peers={d})", .{ds.knownPeerCount()});
}

fn refreshApiNodeIdentityFromDiscovery(self: *BeaconNode, ds: *DiscoveryService) !void {
    const raw_enr = ds.service.localEnr() orelse return;
    self.api_node_identity.metadata.seq_number = ds.service.localEnrSeq();
    const enr_buf = ds.buildLocalEnrString() catch |err| switch (err) {
        error.NoLocalEnr => return,
        else => return err,
    };
    errdefer self.allocator.free(enr_buf);

    if (self.api_node_identity.enr.len > 0) {
        self.allocator.free(self.api_node_identity.enr);
    }
    self.api_node_identity.enr = enr_buf;

    var parsed = try discv5.enr.decode(self.allocator, raw_enr);
    defer parsed.deinit();
    self.api_node_identity.metadata.attnets = parsed.attnets orelse [_]u8{0} ** 8;
    self.api_node_identity.metadata.syncnets = parsed.syncnets orelse [_]u8{0} ** 1;

    try refreshApiDiscoveryAddressesFromEnr(self, raw_enr);
}

fn refreshApiDiscoveryAddressesFromEnr(self: *BeaconNode, raw_enr: []const u8) !void {
    var parsed = try discv5.enr.decode(self.allocator, raw_enr);
    defer parsed.deinit();

    var addresses: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (addresses.items) |address| self.allocator.free(address);
        addresses.deinit(self.allocator);
    }

    if (parsed.ip) |ip4| {
        if (parsed.udp) |port| {
            try addresses.append(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "/ip4/{d}.{d}.{d}.{d}/udp/{d}/p2p/{s}",
                .{ ip4[0], ip4[1], ip4[2], ip4[3], port, self.api_node_identity.peer_id },
            ));
        }
    }
    if (parsed.ip6) |ip6| {
        if (parsed.udp6) |port| {
            try addresses.append(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "/ip6/{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}/udp/{d}/p2p/{s}",
                .{
                    ip6[0],  ip6[1],                         ip6[2],  ip6[3],
                    ip6[4],  ip6[5],                         ip6[6],  ip6[7],
                    ip6[8],  ip6[9],                         ip6[10], ip6[11],
                    ip6[12], ip6[13],                        ip6[14], ip6[15],
                    port,    self.api_node_identity.peer_id,
                },
            ));
        }
    }

    for (self.api_node_identity.discovery_addresses) |address| self.allocator.free(address);
    if (self.api_node_identity.discovery_addresses.len > 0) {
        self.allocator.free(self.api_node_identity.discovery_addresses);
    }
    self.api_node_identity.discovery_addresses = try addresses.toOwnedSlice(self.allocator);
}

fn preferredBootnodeDialAddress(self: *BeaconNode, enr: *const discv5.enr.Enr) ?discv5.Address {
    const addr_ip4 = if (enr.ip) |ip4|
        if (enr.quic) |port|
            discv5.Address{ .ip4 = .{ .bytes = ip4, .port = port } }
        else
            null
    else
        null;
    const addr_ip6 = if (enr.ip6) |ip6|
        if (enr.quic6) |port|
            discv5.Address{ .ip6 = .{ .bytes = ip6, .port = port } }
        else
            null
    else
        null;

    const wants_ip6 = self.node_options.p2p_host == null and self.node_options.p2p_host6 != null;
    if (wants_ip6) return addr_ip6 orelse addr_ip4;
    if (self.node_options.p2p_host != null and self.node_options.p2p_host6 == null) return addr_ip4 orelse addr_ip6;
    return addr_ip4 orelse addr_ip6;
}

fn preferredDiscoveredDialAddress(self: *BeaconNode, peer: *const networking.DiscoveredPeer) ?discv5.Address {
    const wants_ip6 = self.node_options.p2p_host == null and self.node_options.p2p_host6 != null;
    if (wants_ip6) return peer.addr_ip6 orelse peer.addr_ip4;
    if (self.node_options.p2p_host != null and self.node_options.p2p_host6 == null) return peer.addr_ip4 orelse peer.addr_ip6;
    return peer.addr_ip4 orelse peer.addr_ip6;
}

fn discoveryDialBudget(self: *BeaconNode) u32 {
    const pm = self.peer_manager orelse return max_discovery_dials_per_tick;
    const occupied_peers = pm.peerCount() + pm.dialingPeerCount();
    if (occupied_peers >= pm.config.max_peers) return 0;
    return @min(max_discovery_dials_per_tick, pm.config.max_peers - occupied_peers);
}

fn incrementPendingDiscoveryDials(self: *BeaconNode, io: std.Io) void {
    self.discovery_dial_mutex.lockUncancelable(io);
    self.pending_discovery_dial_count += 1;
    self.discovery_dial_mutex.unlock(io);
}

fn enqueueDiscoveryDialCompletion(self: *BeaconNode, io: std.Io, completion: DiscoveryDialCompletion) void {
    var owned = completion;
    self.discovery_dial_mutex.lockUncancelable(io);
    defer self.discovery_dial_mutex.unlock(io);

    self.pending_discovery_dial_count -|= 1;
    self.completed_discovery_dials.append(self.allocator, owned) catch |err| {
        log.warn("Failed to enqueue discovery dial completion: {}", .{err});
        owned.deinit(self.allocator);
    };
}

fn discoveryDialTask(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    job: DiscoveryDialJob,
) void {
    const peer_id = dialPeerWithTimeout(self, io, svc, job.ma_str, outbound_dial_timeout_ms) catch |err| {
        enqueueDiscoveryDialCompletion(self, io, job.toFailure(io, err));
        return;
    };

    enqueueDiscoveryDialCompletion(self, io, job.toSuccess(io, peer_id));
}

fn outboundDialAttemptTask(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    ma_str: []const u8,
) OutboundDialAttemptResult {
    const peer_addr = Multiaddr.fromString(self.allocator, ma_str) catch |err| {
        return .{ .failure = err };
    };
    defer peer_addr.deinit();

    const peer_id = svc.dial(io, peer_addr) catch |err| switch (err) {
        error.Canceled => return .canceled,
        else => return .{ .failure = err },
    };
    return .{ .success = peer_id };
}

fn awaitOutboundDialAttemptWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    timeout_ms: u64,
    comptime AttemptTask: anytype,
    attempt_args: anytype,
) ![]const u8 {
    var events_buf: [2]OutboundDialEvent = undefined;
    var select = std.Io.Select(OutboundDialEvent).init(io, &events_buf);
    errdefer while (select.cancel()) |event| {
        freeOutboundDialEvent(allocator, event);
    };

    try select.concurrent(.dial, AttemptTask, attempt_args);
    select.async(.timeout, waitTimeout, .{ io, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(@intCast(timeout_ms)),
        .clock = .awake,
    } } });

    while (true) {
        const event = try select.await();
        switch (event) {
            .dial => |result| {
                while (select.cancel()) |pending| {
                    freeOutboundDialEvent(allocator, pending);
                }
                return switch (result) {
                    .success => |peer_id| peer_id,
                    .failure => |err| err,
                    .canceled => error.Canceled,
                };
            },
            .timeout => |result| switch (result) {
                .fired => {
                    while (select.cancel()) |pending| {
                        freeOutboundDialEvent(allocator, pending);
                    }
                    return error.Timeout;
                },
                .canceled => {},
            },
        }
    }
}

fn dialPeerWithTimeout(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    ma_str: []const u8,
    timeout_ms: u64,
) ![]const u8 {
    return awaitOutboundDialAttemptWithTimeout(
        self.allocator,
        io,
        timeout_ms,
        outboundDialAttemptTask,
        .{ self, io, svc, ma_str },
    );
}

fn drainCompletedDiscoveryDials(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
) bool {
    var completions = std.ArrayListUnmanaged(DiscoveryDialCompletion).empty;
    self.discovery_dial_mutex.lockUncancelable(io);
    if (self.completed_discovery_dials.items.len > 0) {
        completions = self.completed_discovery_dials;
        self.completed_discovery_dials = .empty;
    }
    self.discovery_dial_mutex.unlock(io);
    defer {
        for (completions.items) |*completion| {
            completion.deinit(self.allocator);
        }
        completions.deinit(self.allocator);
    }

    if (completions.items.len == 0) return false;

    var did_work = false;
    const now_ms = currentUnixTimeMs(io);
    for (completions.items) |*completion| {
        switch (completion.*) {
            .success => |success| {
                if (self.peer_manager) |peer_manager| {
                    if (!std.mem.eql(u8, success.predicted_peer_id, success.peer_id)) {
                        notePeerDisconnected(self, peer_manager, success.predicted_peer_id, now_ms);
                    }
                }

                if (self.metrics) |metrics| {
                    metrics.discovery_dials_total.incr(.{ .outcome = "success" }) catch {};
                    metrics.discovery_dial_time_ns_total.incrBy(.{ .outcome = "success" }, success.elapsed_ns) catch {};
                }
                log.debug("Connected to discovered peer {s} via {s} elapsed_ms={d}", .{
                    success.peer_id,
                    success.ma_str,
                    success.elapsed_ns / std.time.ns_per_ms,
                });
                // Keep the initial outbound connect path lightweight. Fetching
                // metadata eagerly on first contact diverges from Lodestar and
                // increases the number of streams we burn on fragile peers.
                did_work = registerConnectedPeer(
                    self,
                    io,
                    svc,
                    success.peer_id,
                    .outbound,
                    .{ .node_id = success.node_id, .pubkey = success.pubkey },
                    .status_only,
                ) or did_work;
            },
            .failure => |failure| {
                if (self.discovery_service) |ds| {
                    ds.noteDialFailed(failure.node_id);
                }
                if (self.peer_manager) |peer_manager| {
                    notePeerDisconnected(self, peer_manager, failure.predicted_peer_id, now_ms);
                }
                if (self.metrics) |metrics| {
                    metrics.discovery_dials_total.incr(.{ .outcome = "failure" }) catch {};
                    metrics.discovery_dial_time_ns_total.incrBy(.{ .outcome = "failure" }, failure.elapsed_ns) catch {};
                    metrics.discovery_dial_error_total_count.incr(.{ .reason = @errorName(failure.err) }) catch {};
                }
                log.debug("Discovered peer dial failed via {s}: {} elapsed_ms={d}", .{
                    failure.ma_str,
                    failure.err,
                    failure.elapsed_ns / std.time.ns_per_ms,
                });
                did_work = true;
            },
        }
    }
    return did_work;
}

fn peerReqRespMetadataCompletion(metadata: PeerMetadataResponse) beacon_node_mod.PeerReqRespMetadata {
    return .{
        .metadata = metadata.metadata,
        .custody_group_count = metadata.custody_group_count,
    };
}

fn pendingPeerReqRespIndex(ids: []const []const u8, peer_id: []const u8) ?usize {
    for (ids, 0..) |pending_peer_id, i| {
        if (std.mem.eql(u8, pending_peer_id, peer_id)) return i;
    }
    return null;
}

fn markPendingPeerReqResp(self: *BeaconNode, io: std.Io, peer_id: []const u8) !bool {
    const owned_peer_id = try self.allocator.dupe(u8, peer_id);
    errdefer self.allocator.free(owned_peer_id);

    self.peer_reqresp_mutex.lockUncancelable(io);
    defer self.peer_reqresp_mutex.unlock(io);

    if (pendingPeerReqRespIndex(self.pending_peer_reqresp_ids.items, peer_id) != null) {
        self.allocator.free(owned_peer_id);
        return false;
    }

    try self.pending_peer_reqresp_ids.append(self.allocator, owned_peer_id);
    return true;
}

fn clearPendingPeerReqRespLocked(self: *BeaconNode, peer_id: []const u8) void {
    const index = pendingPeerReqRespIndex(self.pending_peer_reqresp_ids.items, peer_id) orelse return;
    const owned_peer_id = self.pending_peer_reqresp_ids.orderedRemove(index);
    self.allocator.free(owned_peer_id);
}

fn clearPendingPeerReqResp(self: *BeaconNode, io: std.Io, peer_id: []const u8) void {
    self.peer_reqresp_mutex.lockUncancelable(io);
    defer self.peer_reqresp_mutex.unlock(io);
    clearPendingPeerReqRespLocked(self, peer_id);
}

fn enqueuePeerReqRespCompletion(self: *BeaconNode, io: std.Io, completion: PeerReqRespCompletion) void {
    var owned = completion;
    self.peer_reqresp_mutex.lockUncancelable(io);
    defer self.peer_reqresp_mutex.unlock(io);

    self.completed_peer_reqresp.append(self.allocator, owned) catch |err| {
        const peer_id = owned.peerId();
        log.warn("Failed to enqueue peer req/resp completion for {f}: {}", .{ networking.fmtPeerId(peer_id), err });
        clearPendingPeerReqRespLocked(self, peer_id);
        owned.deinit(self.allocator);
    };
}

fn peerReqRespFailure(
    peer_id: []const u8,
    protocol: ReqRespMaintenanceProtocol,
    err: anyerror,
    disconnect_peer: bool,
) PeerReqRespCompletion {
    return .{ .failure = .{
        .peer_id = peer_id,
        .protocol = protocol,
        .err = err,
        .disconnect_peer = disconnect_peer,
    } };
}

fn peerReqRespTask(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    job: PeerReqRespJob,
) void {
    switch (job.kind) {
        .status_only, .restatus => {
            const policy = statusReqRespPolicy(job.kind);
            const peer_status = sendStatus(self, io, svc, job.peer_id) catch |err| {
                enqueuePeerReqRespCompletion(
                    self,
                    io,
                    peerReqRespFailure(job.peer_id, .status, err, policy.disconnect_peer_on_failure),
                );
                return;
            };

            enqueuePeerReqRespCompletion(self, io, .{ .status = .{
                .peer_id = job.peer_id,
                .status = peer_status.status,
                .earliest_available_slot = peer_status.earliest_available_slot,
                .metadata = null,
                .follow_up_ping = statusReqRespFollowUpPing(job.kind),
            } });
        },
        .ping => |ping| {
            const remote_seq = requestPeerPing(self, io, svc, job.peer_id) catch |err| {
                enqueuePeerReqRespCompletion(self, io, peerReqRespFailure(job.peer_id, .ping, err, false));
                return;
            };

            var metadata: ?beacon_node_mod.PeerReqRespMetadata = null;
            const should_refresh_metadata = if (self.peer_manager) |pm|
                shouldRefreshMetadataAfterPing(pm.getPeer(job.peer_id), remote_seq, ping.known_metadata_seq)
            else
                shouldRefreshMetadataAfterPing(null, remote_seq, ping.known_metadata_seq);
            if (should_refresh_metadata) {
                if (requestPeerMetadataWithTimeout(self, io, svc, job.peer_id, optional_reqresp_timeout_ms)) |peer_metadata| {
                    metadata = peerReqRespMetadataCompletion(peer_metadata);
                } else |err| {
                    log.debug("Peer metadata refresh failed for {f}: {}; keeping peer connected", .{
                        networking.fmtPeerId(job.peer_id),
                        err,
                    });
                }
            }

            enqueuePeerReqRespCompletion(self, io, .{ .ping = .{
                .peer_id = job.peer_id,
                .remote_seq = remote_seq,
                .metadata = metadata,
            } });
        },
    }
}

fn schedulePeerReqResp(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    kind: PeerReqRespJobKind,
) bool {
    if (!svc.isPeerConnected(io, peer_id)) return false;

    const marked = markPendingPeerReqResp(self, io, peer_id) catch |err| {
        log.warn("Failed to track pending peer req/resp work for {f}: {}", .{ networking.fmtPeerId(peer_id), err });
        return false;
    };
    if (!marked) return false;

    const owned_peer_id = self.allocator.dupe(u8, peer_id) catch |err| {
        clearPendingPeerReqResp(self, io, peer_id);
        log.warn("Failed to allocate peer req/resp job for {f}: {}", .{ networking.fmtPeerId(peer_id), err });
        return false;
    };

    if (self.peer_manager) |pm| switch (kind) {
        .status_only, .restatus => pm.markStatusAttempt(peer_id, currentUnixTimeMs(io)),
        .ping => {},
    };

    svc.spawnBackground(io, peerReqRespTask, .{ self, io, svc, PeerReqRespJob{
        .peer_id = owned_peer_id,
        .kind = kind,
    } });
    return true;
}

fn drainCompletedPeerReqResp(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
) bool {
    var completions = std.ArrayListUnmanaged(PeerReqRespCompletion).empty;
    self.peer_reqresp_mutex.lockUncancelable(io);
    if (self.completed_peer_reqresp.items.len > 0) {
        completions = self.completed_peer_reqresp;
        self.completed_peer_reqresp = .empty;
    }
    self.peer_reqresp_mutex.unlock(io);
    defer {
        for (completions.items) |*completion| {
            completion.deinit(self.allocator);
        }
        completions.deinit(self.allocator);
    }

    if (completions.items.len == 0) return false;

    var did_work = false;
    for (completions.items) |*completion| {
        clearPendingPeerReqResp(self, io, completion.peerId());
        switch (completion.*) {
            .status => |status| {
                const relevant = if (reqresp_callbacks_mod.handlePeerStatus(
                    self,
                    status.peer_id,
                    status.status,
                    status.earliest_available_slot,
                )) |_| false else true;
                if (!relevant) {
                    sendGoodbyeAndDisconnect(self, io, svc, status.peer_id, .irrelevant_network);
                } else if (status.metadata) |metadata| {
                    applyPeerMetadata(self, status.peer_id, .{
                        .metadata = metadata.metadata,
                        .custody_group_count = metadata.custody_group_count,
                    }, currentUnixTimeMs(io));
                }
                if (relevant and status.follow_up_ping) {
                    const known_metadata_seq = if (self.peer_manager) |pm|
                        if (pm.getPeer(status.peer_id)) |peer| peer.metadata_seq else 0
                    else
                        0;
                    did_work = schedulePeerReqResp(self, io, svc, status.peer_id, .{
                        .ping = .{ .known_metadata_seq = known_metadata_seq },
                    }) or did_work;
                }
                did_work = true;
            },
            .ping => |ping| {
                if (self.peer_manager) |pm| pm.markPingResponse(ping.peer_id, currentUnixTimeMs(io));
                if (ping.metadata) |metadata| {
                    applyPeerMetadata(self, ping.peer_id, .{
                        .metadata = metadata.metadata,
                        .custody_group_count = metadata.custody_group_count,
                    }, currentUnixTimeMs(io));
                }
                did_work = true;
            },
            .failure => |failure| {
                handleReqRespMaintenanceFailure(
                    self,
                    io,
                    svc,
                    failure.peer_id,
                    failure.protocol,
                    failure.err,
                    failure.disconnect_peer,
                );
                did_work = true;
            },
        }
    }
    return did_work;
}

fn dialDiscoveredPeers(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    ds: *DiscoveryService,
) bool {
    const dial_budget = discoveryDialBudget(self);
    if (dial_budget == 0) return false;

    const discovery_peer_manager = self.peer_manager orelse return false;
    const discovered_peers = ds.takeDiscoveredPeers(discovery_peer_manager, dial_budget);
    defer if (discovered_peers.len > 0) self.allocator.free(discovered_peers);
    if (discovered_peers.len > 0) {
        log.debug("dialDiscoveredPeers: evaluating {d} discovered peers", .{discovered_peers.len});
    }

    var did_work = false;
    const pm = discovery_peer_manager;
    const now_ms = currentUnixTimeMs(io);
    for (discovered_peers) |peer| {
        if (!peer.has_quic) {
            log.debug("dialDiscoveredPeers: skipping discovered peer without quic", .{});
            ds.noteNotDialReason(.transport_incompatible);
            continue;
        }
        const dial_addr = preferredDiscoveredDialAddress(self, &peer) orelse continue;

        const identity = DiscoveryPeerIdentity{ .node_id = peer.node_id, .pubkey = peer.pubkey };
        if (!discoveryIdentityKnown(identity)) {
            log.debug("dialDiscoveredPeers: skipping discovered peer without secp256k1 identity", .{});
            ds.noteNotDialReason(.no_secp256k1_pubkey);
            continue;
        }

        const predicted_peer_id = discoveryPeerIdBytesFromPubkey(self.allocator, peer.pubkey) catch |err| {
            log.debug("Failed to derive peer ID from discovered ENR: {}", .{err});
            ds.noteNotDialReason(.no_secp256k1_pubkey);
            continue;
        };

        const predicted_peer_id_text = discoveryPeerIdTextFromPubkey(self.allocator, peer.pubkey) catch |err| {
            log.debug("Failed to derive peer ID text from discovered ENR: {}", .{err});
            ds.noteNotDialReason(.no_secp256k1_pubkey);
            self.allocator.free(predicted_peer_id);
            continue;
        };
        defer self.allocator.free(predicted_peer_id_text);

        if (svc.isPeerConnected(io, predicted_peer_id)) {
            ds.noteNotDialReason(.already_connected);
            self.allocator.free(predicted_peer_id);
            continue;
        }

        if (pm.getPeer(predicted_peer_id)) |existing| {
            switch (existing.connection_state) {
                .banned, .dialing, .connected, .disconnecting => {
                    ds.noteNotDialReason(switch (existing.connection_state) {
                        .banned => .banned,
                        .dialing => .already_dialing,
                        .connected => .already_connected,
                        .disconnecting => .disconnecting,
                        else => unreachable,
                    });
                    self.allocator.free(predicted_peer_id);
                    continue;
                },
                .disconnected => {},
            }
        }

        var ma_buf: [240]u8 = undefined;
        const ma_str = formatDiscv5DialMultiaddr(&ma_buf, dial_addr, predicted_peer_id_text) catch {
            self.allocator.free(predicted_peer_id);
            continue;
        };
        const owned_ma_str = self.allocator.dupe(u8, ma_str) catch {
            self.allocator.free(predicted_peer_id);
            continue;
        };

        pm.onDialing(predicted_peer_id, now_ms) catch |err| {
            log.debug("Failed to mark discovered peer {s} as dialing: {}", .{ predicted_peer_id_text, err });
            ds.noteNotDialReason(.already_dialing);
            self.allocator.free(owned_ma_str);
            self.allocator.free(predicted_peer_id);
            continue;
        };

        ds.noteDialAttempt(&peer);
        ds.noteDialScheduled();
        if (self.metrics) |metrics| {
            metrics.discovery_total_dial_attempts.incr();
        }
        incrementPendingDiscoveryDials(self, io);
        svc.spawnBackground(io, discoveryDialTask, .{ self, io, svc, DiscoveryDialJob{
            .ma_str = owned_ma_str,
            .predicted_peer_id = predicted_peer_id,
            .node_id = peer.node_id,
            .pubkey = peer.pubkey,
            .started_at_ns = timestampNowNs(io),
        } });
        did_work = true;
    }

    return did_work;
}

fn reconcilePeerConnections(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const pm = self.peer_manager orelse return false;

    const connected_peer_ids = svc.snapshotConnectedPeerIds(io, self.allocator) catch |err| {
        log.debug("Failed to snapshot connected peers: {}", .{err});
        return false;
    };
    defer freeOwnedPeerIds(self.allocator, connected_peer_ids);

    var did_work = false;
    for (connected_peer_ids) |peer_id| {
        const maybe_peer = pm.getPeer(peer_id);
        if (maybe_peer) |peer| {
            switch (peer.connection_state) {
                .banned => {
                    sendGoodbyeAndDisconnect(self, io, svc, peer_id, .banned);
                    did_work = true;
                    continue;
                },
                .disconnecting => continue,
                .connected => {
                    if (peer.relevance == .irrelevant) {
                        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
                        did_work = true;
                        continue;
                    }
                    did_work = maybeRecordPeerIdentity(self, svc, peer_id) or did_work;
                    continue;
                },
                .dialing => {},
                .disconnected => {
                    if (peer.relevance == .irrelevant) {
                        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
                        did_work = true;
                        continue;
                    }
                },
            }
        }

        const direction = if (maybe_peer) |peer|
            peer.direction orelse .inbound
        else
            .inbound;
        did_work = registerConnectedPeer(self, io, svc, peer_id, direction, null, .status_only) or did_work;
    }

    const managed_peer_ids = pm.getConnectedPeerIds() catch |err| {
        log.debug("Failed to snapshot peer-manager peers: {}", .{err});
        return did_work;
    };
    defer freeOwnedPeerIds(self.allocator, managed_peer_ids);

    const now_ms = currentUnixTimeMs(io);
    for (managed_peer_ids) |peer_id| {
        if (containsPeerId(connected_peer_ids, peer_id)) continue;
        notePeerDisconnected(self, pm, peer_id, now_ms);
        if (self.metrics) |metrics| metrics.peer_disconnected_total.incr();
        did_work = true;
    }

    return did_work;
}

fn registerConnectedPeer(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    direction: ConnectionDirection,
    discovery_identity: ?DiscoveryPeerIdentity,
    handshake_mode: OutboundHandshakeMode,
) bool {
    const pm = self.peer_manager orelse return maybeRecordPeerIdentity(self, svc, peer_id);
    const now_ms = currentUnixTimeMs(io);
    const existing = pm.getPeer(peer_id);
    const was_connected = if (existing) |peer| peer.isConnected() else false;

    if (discovery_identity) |identity| {
        if (discoveryIdentityKnown(identity)) {
            const matches = discoveryPeerIdMatches(self.allocator, peer_id, identity.pubkey) catch |err| {
                log.debug("Failed to verify discovered ENR identity for peer {s}: {}", .{ peer_id, err });
                _ = svc.disconnectPeer(io, peer_id);
                return true;
            };
            if (!matches) {
                log.debug("Discovered ENR identity did not match connected peer {s}; dropping connection", .{peer_id});
                _ = svc.disconnectPeer(io, peer_id);
                return true;
            }
        }
    }

    if (existing) |peer| {
        if (peer.connection_state == .banned) {
            sendGoodbyeAndDisconnect(self, io, svc, peer_id, .banned);
            return true;
        }
        if (peer.connection_state == .disconnecting) {
            return false;
        }
    }

    const connect_direction = if (existing) |peer| peer.direction orelse direction else direction;
    const connected = pm.onPeerConnected(peer_id, connect_direction, now_ms) catch |err| {
        log.debug("Failed to register connected peer {s}: {}", .{ peer_id, err });
        return false;
    };
    if (connected == null) {
        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .banned);
        return true;
    }

    if (discovery_identity) |identity| {
        pm.updatePeerDiscoveryNodeId(peer_id, identity.node_id) catch |err| {
            log.debug("Failed to record discovery node ID for peer {s}: {}", .{ peer_id, err });
        };
    }
    recordPeerNodeIdFromPeerId(pm, peer_id);

    if (!was_connected) {
        if (discovery_identity) |identity| {
            if (self.discovery_service) |ds| {
                ds.notePeerConnected(identity.node_id);
            }
        }
    }

    var did_work = !was_connected;
    if (!was_connected) {
        if (self.sync_callback_ctx) |cb_ctx| cb_ctx.notePeerConnected(peer_id);
        if (self.metrics) |metrics| metrics.peer_connected_total.incr();
        svc.openGossipsubStreamAsync(io, peer_id) catch |err| {
            log.debug("Failed to open outbound gossipsub stream for {s}: {}", .{ peer_id, err });
        };
        // Match Lodestar's connect flow: kick off identify immediately so
        // agentVersion/client metrics are populated from the live connection.
        svc.requestIdentifyAsync(io, peer_id) catch |err| {
            log.debug("Failed to request identify for {s}: {}", .{ peer_id, err });
        };
        // Mirror Lodestar's connect path: prove fresh outbound peers with
        // STATUS immediately, but do not front-load metadata fetches on the
        // first successful transport connection.
        if (connect_direction == .outbound) {
            switch (handshake_mode) {
                .none => {},
                .status_only => did_work = schedulePeerReqResp(self, io, svc, peer_id, .status_only) or did_work,
            }
        }
    }

    did_work = maybeRecordPeerIdentity(self, svc, peer_id) or did_work;
    return did_work;
}

fn completePeerHandshake(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) bool {
    if (!bootstrapPeerStatusHandshake(self, io, svc, peer_id)) {
        return true;
    }

    if (requestPeerMetadataWithTimeout(self, io, svc, peer_id, optional_reqresp_timeout_ms)) |metadata| {
        applyPeerMetadata(self, peer_id, metadata, currentUnixTimeMs(io));
    } else |err| {
        log.debug("Peer metadata unavailable for {s}: {}; continuing handshake", .{ peer_id, err });
    }
    return true;
}

fn bootstrapPeerStatusHandshake(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) bool {
    const peer_status = sendStatus(self, io, svc, peer_id) catch |err| {
        handleReqRespMaintenanceFailure(self, io, svc, peer_id, .status, err, true);
        return false;
    };

    if (reqresp_callbacks_mod.handlePeerStatus(self, peer_id, peer_status.status, peer_status.earliest_available_slot)) |_| {
        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
        return false;
    }

    return true;
}

fn maybeRecordPeerIdentity(
    self: *BeaconNode,
    svc: *networking.P2pService,
    peer_id: []const u8,
) bool {
    const pm = self.peer_manager orelse return false;
    const peer = pm.getPeer(peer_id) orelse return false;
    if (peer.agent_version != null) return false;

    const identify_result = svc.identifyResult(peer_id) orelse return false;
    pm.updateAgentVersion(peer_id, identify_result.agentVersion()) catch |err| {
        log.debug("Failed to record identify result for peer {s}: {}", .{ peer_id, err });
        return false;
    };
    return true;
}

fn recordPeerNodeIdFromPeerId(pm: *PeerManager, peer_id: []const u8) void {
    const node_id = nodeIdFromInlineSecp256k1PeerId(peer_id) orelse return;
    pm.updatePeerDiscoveryNodeId(peer_id, node_id) catch |err| {
        log.debug("Failed to derive discovery node ID for peer {s}: {}", .{ peer_id, err });
    };
}

fn applyPeerMetadata(self: *BeaconNode, peer_id: []const u8, metadata: PeerMetadataResponse, now_ms: u64) void {
    const pm = self.peer_manager orelse return;
    recordPeerNodeIdFromPeerId(pm, peer_id);
    pm.updatePeerMetadata(
        peer_id,
        metadata.metadata.seq_number,
        attnetsFromMetadata(metadata.metadata.attnets.data),
        syncnetsFromMetadata(metadata.metadata.syncnets.data),
        metadata.custody_group_count,
    ) catch |err| {
        log.debug("Failed to update metadata for peer {s}: {}", .{ peer_id, err });
        return;
    };
    pm.notePeerSeen(peer_id, now_ms);

    if (pm.getPeer(peer_id)) |peer| {
        const custody_columns = peer.custody_columns orelse &.{};
        var local_overlap: usize = 0;
        for (self.chain_runtime.custody_columns) |column_index| {
            if (networking.custody.isCustodied(column_index, custody_columns)) {
                local_overlap += 1;
            }
        }

        log.debug(
            "Applied peer metadata {s}: seq={d} custody_group_count={any} custody_columns={d} local_overlap={d}/{d}",
            .{
                peer_id,
                metadata.metadata.seq_number,
                metadata.custody_group_count,
                custody_columns.len,
                local_overlap,
                self.chain_runtime.custody_columns.len,
            },
        );
    }
}

fn sendGoodbyeAndDisconnect(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    reason: GoodbyeReason,
) void {
    if (self.peer_manager) |pm| pm.onPeerDisconnecting(peer_id);
    sendGoodbye(self, io, svc, peer_id, reason) catch |err| {
        log.debug("Goodbye send failed for peer {s}: {}", .{ peer_id, err });
    };
    _ = svc.disconnectPeer(io, peer_id);
}

fn heartbeatDisconnectReason(maybe_peer: ?*const networking.PeerInfo) GoodbyeReason {
    const peer = maybe_peer orelse return .too_many_peers;
    return switch (peer.scoreState()) {
        .healthy => .too_many_peers,
        .disconnected, .banned => .score_too_low,
    };
}

fn notePeerDisconnected(self: *BeaconNode, pm: *PeerManager, peer_id: []const u8, now_ms: u64) void {
    pm.onPeerDisconnected(peer_id, now_ms);
    if (self.sync_callback_ctx) |cb_ctx| cb_ctx.notePeerDisconnected(peer_id);
    if (self.sync_service_inst) |sync_svc| sync_svc.onPeerDisconnect(peer_id);
    if (self.unknownChainSyncEnabled()) self.unknown_chain_sync.onPeerDisconnected(peer_id);
}

fn containsPeerId(peer_ids: []const []const u8, needle: []const u8) bool {
    for (peer_ids) |peer_id| {
        if (std.mem.eql(u8, peer_id, needle)) return true;
    }
    return false;
}

fn freeOwnedPeerIds(allocator: std.mem.Allocator, peer_ids: []const []const u8) void {
    for (peer_ids) |peer_id| allocator.free(peer_id);
    allocator.free(peer_ids);
}

fn initPeerManager(self: *BeaconNode) !void {
    if (self.peer_manager != null) return;

    const pm = try self.allocator.create(PeerManager);
    errdefer self.allocator.destroy(pm);
    pm.* = PeerManager.init(self.allocator, .{
        .target_peers = self.node_options.target_peers,
        .max_peers = networking.peer_manager.maxPeersForTarget(self.node_options.target_peers),
        .target_group_peers = self.node_options.target_group_peers,
        .local_custody_columns = self.chain_runtime.custody_columns,
    });
    self.peer_manager = pm;
    log.debug("Peer manager initialized (target_peers={d} target_group_peers={d})", .{
        pm.config.target_peers,
        pm.config.target_group_peers,
    });
}

fn initSyncPipeline(self: *BeaconNode) !void {
    const cb_ctx = self.sync_callback_ctx orelse blk: {
        const created = try self.allocator.create(SyncCallbackCtx);
        created.* = .{ .node = self };
        self.sync_callback_ctx = created;
        break :blk created;
    };
    self.unknown_block_sync.setCallbacks(cb_ctx.unknownBlockCallbacks());
    if (self.unknownChainSyncEnabled()) {
        self.unknown_chain_sync.setCallbacks(cb_ctx.unknownChainCallbacks());
        self.unknown_chain_sync.setForkChoice(cb_ctx.unknownChainForkChoiceQuery());
    }

    const finalized_epoch = self.chainQuery().finalizedCheckpoint().epoch;
    if (self.sync_service_inst) |sync_svc| {
        sync_svc.onHeadUpdate(self.currentHeadSlot());
        sync_svc.onFinalizedUpdate(finalized_epoch);
        return;
    }

    const sync_svc = try self.allocator.create(SyncService);
    sync_svc.* = SyncService.init(
        self.allocator,
        self.io,
        cb_ctx.syncServiceCallbacks(),
        self.currentHeadSlot(),
        finalized_epoch,
    );
    sync_svc.is_single_node = self.node_options.sync_is_single_node;
    if (sync_svc.is_single_node) {
        // Trigger mode recalculation so the service starts in .synced mode.
        sync_svc.onHeadUpdate(self.currentHeadSlot());
    }
    self.sync_service_inst = sync_svc;

    log.debug("Sync pipeline initialized (head_slot={d})", .{self.currentHeadSlot()});
}

fn ensureRangeSyncDataAvailability(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    blocks: []const BatchBlock,
) !void {
    const metas = try buildSyncBlockMetas(self, blocks);
    defer deinitSyncBlockMetas(self, metas);

    fetchBlobSidecarsByRangeForMetas(self, io, svc, peer_id, metas) catch |err| {
        reportReqRespFetchFailure(self, io, peer_id, .blob_sidecars_by_range, err);
        return err;
    };
    fetchDataColumnsByRangeForMetas(self, io, svc, peer_id, metas) catch |err| {
        reportReqRespFetchFailure(self, io, peer_id, .data_column_sidecars_by_range, err);
        return err;
    };
}

fn ensureByRootDataAvailability(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    block_bytes: []const u8,
) !void {
    var meta = try buildSyncBlockMeta(self, block_bytes, null);
    defer deinitSyncBlockMeta(self, &meta);

    switch (meta.block_data_plan) {
        .none => return,
        .blobs => |missing| {
            if (missing.len == 0) return;
            fetchBlobSidecarsByRootForMeta(self, io, svc, peer_id, meta, missing) catch |err| {
                reportReqRespFetchFailure(self, io, peer_id, .blob_sidecars_by_root, err);
                return err;
            };
        },
        .columns => |missing| {
            if (missing.len == 0) return;
            fetchDataColumnsByRootForMeta(self, io, svc, peer_id, meta) catch |err| {
                reportReqRespFetchFailure(self, io, peer_id, .data_column_sidecars_by_root, err);
                return err;
            };
        },
    }
}

fn buildSyncBlockMetas(self: *BeaconNode, blocks: []const BatchBlock) ![]SyncBlockMeta {
    const metas = try self.allocator.alloc(SyncBlockMeta, blocks.len);
    errdefer self.allocator.free(metas);

    var built: usize = 0;
    errdefer {
        for (metas[0..built]) |*meta| {
            deinitSyncBlockMeta(self, meta);
        }
    }

    for (blocks, 0..) |block, i| {
        metas[i] = try buildSyncBlockMeta(self, block.block_bytes, block.slot);
        built = i + 1;
    }

    return metas;
}

fn buildSyncBlockMeta(
    self: *BeaconNode,
    block_bytes: []const u8,
    slot_hint: ?u64,
) !SyncBlockMeta {
    return self.chainService().planRawBlockIngress(block_bytes, slot_hint);
}

fn deinitSyncBlockMetas(self: *BeaconNode, metas: []SyncBlockMeta) void {
    for (metas) |*meta| deinitSyncBlockMeta(self, meta);
    self.allocator.free(metas);
}

fn deinitSyncBlockMeta(self: *BeaconNode, meta: *SyncBlockMeta) void {
    meta.deinit(self.allocator);
}

fn fetchBlobSidecarsByRangeForMetas(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    metas: []const SyncBlockMeta,
) !void {
    var start_slot: u64 = std.math.maxInt(u64);
    var end_slot: u64 = 0;
    var have_pending = false;

    var states = try self.allocator.alloc(?BlobFetchState, metas.len);
    defer {
        for (states) |*maybe_state| {
            if (maybe_state.*) |*state| state.deinit(self.allocator);
        }
        self.allocator.free(states);
    }
    @memset(states, null);

    for (metas, 0..) |meta, i| {
        if (!needsBlobFetch(meta)) continue;
        have_pending = true;
        start_slot = @min(start_slot, meta.slot);
        end_slot = @max(end_slot, meta.slot);

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        const existing = try self.chainQuery().blobSidecarsByRoot(meta.block_root);
        states[i] = try BlobFetchState.init(self.allocator, blob_commitments.items.len, existing);
    }

    if (!have_pending) return;

    const protocol_id = "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .blob_sidecars_by_range, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    const request = networking.messages.BlobSidecarsByRangeRequest.Type{
        .start_slot = start_slot,
        .count = end_slot - start_slot + 1,
    };
    var req_ssz: [networking.messages.BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &req_ssz);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &req_ssz);
    outbound.noteRequestPayload(req_ssz.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        outbound.noteResponseChunk(decoded.ssz_bytes.len);
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            request_outcome = responseCodeOutcome(decoded.result);
            return responseCodeError(decoded.result);
        }
        errdefer self.allocator.free(decoded.ssz_bytes);

        var sidecar: BlobSidecar.Type = undefined;
        BlobSidecar.deserializeFromBytes(decoded.ssz_bytes, &sidecar) catch return error.MalformedBlobSidecar;

        const slot = sidecar.signed_block_header.message.slot;
        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.networkingForkDigestAtSlot(slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);

        const meta_index = findMetaIndexByRoot(metas, block_root) orelse return error.UnexpectedBlobSidecar;
        const meta = metas[meta_index];
        if (!needsBlobFetch(meta)) {
            self.allocator.free(decoded.ssz_bytes);
            continue;
        }

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        if (slot != meta.slot) return error.UnexpectedBlobSlot;
        if (sidecar.index >= blob_commitments.items.len) return error.InvalidBlobIndex;
        if (!std.mem.eql(u8, &blob_commitments.items[sidecar.index], &sidecar.kzg_commitment)) {
            return error.KzgCommitmentMismatch;
        }

        const blob_ptr: *const [BYTES_PER_BLOB]u8 = @ptrCast(&sidecar.blob);
        try self.chainService().verifyBlobSidecar(.{
            .blob = blob_ptr,
            .commitment = sidecar.kzg_commitment,
            .proof = sidecar.kzg_proof,
        });

        var state = &states[meta_index].?;
        if (state.sidecars[sidecar.index] != null) {
            self.allocator.free(decoded.ssz_bytes);
            continue;
        }
        try state.setFetched(self.allocator, sidecar.index, decoded.ssz_bytes);
    }

    for (metas, 0..) |meta, i| {
        if (!needsBlobFetch(meta)) continue;
        var state = &states[i].?;
        const aggregate = try state.aggregate(self.allocator);
        defer self.allocator.free(aggregate);

        const blob_indices = try self.allocator.alloc(u64, state.sidecars.len);
        defer self.allocator.free(blob_indices);
        for (blob_indices, 0..) |*blob_index, blob_i| blob_index.* = @intCast(blob_i);

        try handleDataAvailabilityReadyBlock(
            try self.chainService().ingestBlobSidecars(meta.block_root, meta.slot, aggregate, blob_indices),
            self,
            completeReadyIngressAfterDataAvailability,
        );
    }

    var last_err: ?anyerror = null;
    for (metas) |meta| {
        if (!needsBlobFetch(meta)) continue;
        if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) == .pending) {
            const missing = try self.chainService().missingBlobSidecars(self.allocator, meta.block_root);
            defer self.allocator.free(missing);
            if (missing.len == 0) continue;

            fetchBlobSidecarsByRootForMeta(self, io, svc, peer_id, meta, missing) catch |err| {
                last_err = err;
                continue;
            };

            if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) == .pending) {
                last_err = error.MissingBlobSidecar;
            }
        }
    }

    if (last_err) |err| return err;

    request_outcome = .success;
}

fn fetchBlobSidecarsByRootForMeta(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    meta: SyncBlockMeta,
    missing: []const u64,
) !void {
    if (missing.len == 0) return;

    const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
    const existing = try self.chainQuery().blobSidecarsByRoot(meta.block_root);
    var state = try BlobFetchState.init(self.allocator, blob_commitments.items.len, existing);
    defer state.deinit(self.allocator);

    const protocol_id = "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var request = networking.messages.BlobSidecarsByRootRequest.Type.empty;
    defer networking.messages.BlobSidecarsByRootRequest.deinit(self.allocator, &request);
    for (missing) |blob_index| {
        try request.append(self.allocator, .{
            .block_root = meta.block_root,
            .index = blob_index,
        });
    }

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .blob_sidecars_by_root, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    const request_bytes = try self.allocator.alloc(u8, networking.messages.BlobSidecarsByRootRequest.serializedSize(&request));
    defer self.allocator.free(request_bytes);
    _ = networking.messages.BlobSidecarsByRootRequest.serializeIntoBytes(&request, request_bytes);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.noteRequestPayload(request_bytes.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        outbound.noteResponseChunk(decoded.ssz_bytes.len);
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            request_outcome = responseCodeOutcome(decoded.result);
            return responseCodeError(decoded.result);
        }
        errdefer self.allocator.free(decoded.ssz_bytes);

        var sidecar: BlobSidecar.Type = undefined;
        BlobSidecar.deserializeFromBytes(decoded.ssz_bytes, &sidecar) catch return error.MalformedBlobSidecar;

        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.networkingForkDigestAtSlot(sidecar.signed_block_header.message.slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);
        if (!std.mem.eql(u8, &block_root, &meta.block_root)) return error.UnexpectedBlobSidecar;
        if (sidecar.signed_block_header.message.slot != meta.slot) return error.UnexpectedBlobSlot;
        if (sidecar.index >= blob_commitments.items.len) return error.InvalidBlobIndex;
        if (!std.mem.eql(u8, &blob_commitments.items[sidecar.index], &sidecar.kzg_commitment)) {
            return error.KzgCommitmentMismatch;
        }

        const blob_ptr: *const [BYTES_PER_BLOB]u8 = @ptrCast(&sidecar.blob);
        try self.chainService().verifyBlobSidecar(.{
            .blob = blob_ptr,
            .commitment = sidecar.kzg_commitment,
            .proof = sidecar.kzg_proof,
        });

        if (state.sidecars[sidecar.index] != null) {
            self.allocator.free(decoded.ssz_bytes);
            continue;
        }
        try state.setFetched(self.allocator, sidecar.index, decoded.ssz_bytes);
    }

    const aggregate = try state.aggregate(self.allocator);
    defer self.allocator.free(aggregate);

    const blob_indices = try self.allocator.alloc(u64, state.sidecars.len);
    defer self.allocator.free(blob_indices);
    for (blob_indices, 0..) |*blob_index, i| blob_index.* = @intCast(i);

    try handleDataAvailabilityReadyBlock(
        try self.chainService().ingestBlobSidecars(meta.block_root, meta.slot, aggregate, blob_indices),
        self,
        completeReadyIngressAfterDataAvailability,
    );

    if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) == .pending) {
        return error.MissingBlobSidecar;
    }

    request_outcome = .success;
}

fn verifyDataColumnSidecarWithMetrics(
    self: *BeaconNode,
    column_index: u64,
    commitments: []const [48]u8,
    cells: []const [kzg_mod.BYTES_PER_CELL]u8,
    proofs: []const [48]u8,
) !void {
    const started_ns = timestampNowNs(self.io);
    try self.chainService().verifyDataColumnSidecar(
        self.allocator,
        column_index,
        commitments,
        cells,
        proofs,
    );
    if (self.metrics) |metrics| {
        const finished_ns = timestampNowNs(self.io);
        const elapsed_ns = if (finished_ns > started_ns) finished_ns - started_ns else 0;
        metrics.observeDataColumnKzgVerification(@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    }
}

fn fetchDataColumnsByRangeForMetas(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    preferred_peer_id: []const u8,
    metas: []const SyncBlockMeta,
) !void {
    var attempted_peers = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (attempted_peers.items) |peer_id| self.allocator.free(peer_id);
        attempted_peers.deinit(self.allocator);
    }

    var last_err: ?anyerror = null;

    while (true) {
        const missing_before = try countMissingDataColumnsForMetas(self, metas);
        if (missing_before == 0) return;

        var request = (try buildDataColumnRangeRequest(self, metas)) orelse return;
        defer networking.messages.DataColumnSidecarsByRangeRequest.deinit(self.allocator, &request);

        const end_slot = request.start_slot +| (request.count -| 1);
        const selected_peer = try selectDataColumnFetchPeer(
            self,
            request.columns.items,
            request.start_slot,
            end_slot,
            preferred_peer_id,
            attempted_peers.items,
        ) orelse break;
        errdefer self.allocator.free(selected_peer);
        try attempted_peers.append(self.allocator, selected_peer);

        fetchDataColumnsByRangeOnce(self, io, svc, selected_peer, metas, &request) catch |err| {
            log.debug("Data column by-range fetch failed from peer {s}: {}", .{ selected_peer, err });
            last_err = err;
            continue;
        };

        const missing_after = try countMissingDataColumnsForMetas(self, metas);
        if (missing_after == 0) return;
        if (missing_after >= missing_before) continue;
    }

    fetchDataColumnsByRootForMetas(self, io, svc, preferred_peer_id, metas) catch |err| {
        last_err = err;
    };

    if (try countMissingDataColumnsForMetas(self, metas) == 0) return;
    return last_err orelse error.MissingDataColumnSidecar;
}

fn fetchDataColumnsByRangeOnce(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    metas: []const SyncBlockMeta,
    request: *const networking.messages.DataColumnSidecarsByRangeRequest.Type,
) !void {
    const protocol_id = "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .data_column_sidecars_by_range, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    const covered_columns = try dataColumnsCoveredByPeer(self, peer_id, request.columns.items);
    defer self.allocator.free(covered_columns);
    if (covered_columns.len == 0) return error.MissingDataColumnSidecar;

    var filtered_request = request.*;
    filtered_request.columns = .empty;
    defer networking.messages.DataColumnSidecarsByRangeRequest.deinit(self.allocator, &filtered_request);
    for (covered_columns) |column_index| {
        try filtered_request.columns.append(self.allocator, column_index);
    }

    const request_bytes = try self.allocator.alloc(u8, networking.messages.DataColumnSidecarsByRangeRequest.serializedSize(&filtered_request));
    defer self.allocator.free(request_bytes);
    _ = networking.messages.DataColumnSidecarsByRangeRequest.serializeIntoBytes(&filtered_request, request_bytes);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.noteRequestPayload(request_bytes.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var seen_columns = try self.allocator.alloc(std.StaticBitSet(MAX_COLUMNS), metas.len);
    defer self.allocator.free(seen_columns);
    for (seen_columns) |*bits| bits.* = std.StaticBitSet(MAX_COLUMNS).initEmpty();

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        outbound.noteResponseChunk(decoded.ssz_bytes.len);
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            request_outcome = responseCodeOutcome(decoded.result);
            return responseCodeError(decoded.result);
        }
        defer self.allocator.free(decoded.ssz_bytes);

        var sidecar = DataColumnSidecar.default_value;
        DataColumnSidecar.deserializeFromBytes(self.allocator, decoded.ssz_bytes, &sidecar) catch return error.MalformedDataColumnSidecar;
        defer DataColumnSidecar.deinit(self.allocator, &sidecar);

        const slot = sidecar.signed_block_header.message.slot;
        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.networkingForkDigestAtSlot(slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);

        const meta_index = findMetaIndexByRoot(metas, block_root) orelse return error.UnexpectedDataColumnSidecar;
        const meta = metas[meta_index];
        if (!needsColumnFetch(meta)) continue;

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        if (slot != meta.slot) return error.UnexpectedColumnSlot;
        if (sidecar.index >= MAX_COLUMNS) return error.InvalidColumnIndex;
        if (seen_columns[meta_index].isSet(@intCast(sidecar.index))) continue;
        seen_columns[meta_index].set(@intCast(sidecar.index));

        if (sidecar.kzg_commitments.items.len != blob_commitments.items.len) return error.KzgCommitmentLengthMismatch;
        if (sidecar.column.items.len != blob_commitments.items.len) return error.ColumnLengthMismatch;
        if (sidecar.kzg_proofs.items.len != blob_commitments.items.len) return error.ColumnProofLengthMismatch;

        for (blob_commitments.items, sidecar.kzg_commitments.items) |expected_commitment, actual_commitment| {
            if (!std.mem.eql(u8, &expected_commitment, &actual_commitment)) {
                return error.KzgCommitmentMismatch;
            }
        }

        try verifyDataColumnSidecarWithMetrics(
            self,
            sidecar.index,
            sidecar.kzg_commitments.items,
            sidecar.column.items,
            sidecar.kzg_proofs.items,
        );

        try handleDataAvailabilityReadyBlock(
            try self.chainService().ingestDataColumnSidecar(block_root, sidecar.index, slot, decoded.ssz_bytes),
            self,
            completeReadyIngressAfterDataAvailability,
        );
    }

    request_outcome = .success;
}

fn fetchDataColumnsByRootForMeta(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    preferred_peer_id: []const u8,
    meta: SyncBlockMeta,
) !void {
    var attempted_peers = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (attempted_peers.items) |peer_id| self.allocator.free(peer_id);
        attempted_peers.deinit(self.allocator);
    }

    var last_err: ?anyerror = null;

    while (true) {
        const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
        defer self.allocator.free(missing);
        if (missing.len == 0) return;

        const selected_peer = try selectDataColumnFetchPeer(
            self,
            missing,
            meta.slot,
            meta.slot,
            preferred_peer_id,
            attempted_peers.items,
        ) orelse break;
        errdefer self.allocator.free(selected_peer);
        try attempted_peers.append(self.allocator, selected_peer);

        fetchDataColumnsByRootOnce(self, io, svc, selected_peer, meta, missing) catch |err| {
            log.debug("Data column by-root fetch failed from peer {s}: {}", .{ selected_peer, err });
            last_err = err;
            continue;
        };

        if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) != .pending) {
            return;
        }
    }

    return last_err orelse error.MissingDataColumnSidecar;
}

const DataColumnByRootBatchRequest = struct {
    start_slot: u64,
    end_slot: u64,
    missing_columns: []u64,
    request_bytes: []u8,

    fn deinit(self: *DataColumnByRootBatchRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.missing_columns);
        allocator.free(self.request_bytes);
    }
};

fn fetchDataColumnsByRootForMetas(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    preferred_peer_id: []const u8,
    metas: []const SyncBlockMeta,
) !void {
    var attempted_peers = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (attempted_peers.items) |peer_id| self.allocator.free(peer_id);
        attempted_peers.deinit(self.allocator);
    }

    var last_err: ?anyerror = null;

    while (true) {
        const missing_before = try countMissingDataColumnsForMetas(self, metas);
        if (missing_before == 0) return;

        var request = (try buildDataColumnsByRootBatchRequest(self, metas, null)) orelse return;
        defer request.deinit(self.allocator);

        const selected_peer = try selectDataColumnFetchPeer(
            self,
            request.missing_columns,
            request.start_slot,
            request.end_slot,
            preferred_peer_id,
            attempted_peers.items,
        ) orelse break;
        errdefer self.allocator.free(selected_peer);
        try attempted_peers.append(self.allocator, selected_peer);

        const covered_columns = try dataColumnsCoveredByPeer(self, selected_peer, request.missing_columns);
        defer self.allocator.free(covered_columns);
        if (covered_columns.len == 0) {
            last_err = error.MissingDataColumnSidecar;
            continue;
        }

        var filtered_request = (try buildDataColumnsByRootBatchRequest(self, metas, covered_columns)) orelse {
            last_err = error.MissingDataColumnSidecar;
            continue;
        };
        defer filtered_request.deinit(self.allocator);

        fetchDataColumnsByRootOnceForMetas(self, io, svc, selected_peer, metas, filtered_request.request_bytes) catch |err| {
            log.debug("Data column by-root batch fetch failed from peer {s}: {}", .{ selected_peer, err });
            last_err = err;
            continue;
        };

        const missing_after = try countMissingDataColumnsForMetas(self, metas);
        if (missing_after == 0) return;
        if (missing_after >= missing_before) continue;
    }

    return last_err orelse error.MissingDataColumnSidecar;
}

fn buildDataColumnsByRootBatchRequest(
    self: *BeaconNode,
    metas: []const SyncBlockMeta,
    only_columns: ?[]const u64,
) !?DataColumnByRootBatchRequest {
    var requested_columns = std.StaticBitSet(MAX_COLUMNS).initEmpty();
    var start_slot: u64 = std.math.maxInt(u64);
    var end_slot: u64 = 0;
    var request: DataColumnSidecarsByRootRequest.Type = .empty;
    defer DataColumnSidecarsByRootRequest.deinit(self.allocator, &request);

    for (metas) |meta| {
        if (!needsColumnFetch(meta)) continue;

        const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
        defer self.allocator.free(missing);
        if (missing.len == 0) continue;

        var identifier: DataColumnsByRootIdentifier.Type = .{
            .block_root = meta.block_root,
            .columns = .empty,
        };
        errdefer DataColumnsByRootIdentifier.deinit(self.allocator, &identifier);

        for (missing) |column_index| {
            if (only_columns) |columns| {
                if (!containsColumnIndex(columns, column_index)) continue;
            }
            try identifier.columns.append(self.allocator, column_index);
            if (column_index < MAX_COLUMNS) {
                requested_columns.set(@intCast(column_index));
            }
        }

        if (identifier.columns.items.len == 0) {
            DataColumnsByRootIdentifier.deinit(self.allocator, &identifier);
            continue;
        }

        start_slot = @min(start_slot, meta.slot);
        end_slot = @max(end_slot, meta.slot);
        try request.append(self.allocator, identifier);
    }

    if (request.items.len == 0) return null;

    var missing_columns = std.ArrayListUnmanaged(u64).empty;
    defer missing_columns.deinit(self.allocator);
    for (0..MAX_COLUMNS) |column_index| {
        if (requested_columns.isSet(column_index)) {
            try missing_columns.append(self.allocator, @intCast(column_index));
        }
    }
    if (missing_columns.items.len == 0) return null;

    const request_bytes = try self.allocator.alloc(u8, DataColumnSidecarsByRootRequest.serializedSize(&request));
    errdefer self.allocator.free(request_bytes);
    _ = DataColumnSidecarsByRootRequest.serializeIntoBytes(&request, request_bytes);

    return .{
        .start_slot = start_slot,
        .end_slot = end_slot,
        .missing_columns = try missing_columns.toOwnedSlice(self.allocator),
        .request_bytes = request_bytes,
    };
}

fn fetchDataColumnsByRootOnceForMetas(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    metas: []const SyncBlockMeta,
    request_bytes: []const u8,
) !void {
    const protocol_id = "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .data_column_sidecars_by_root, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.noteRequestPayload(request_bytes.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var seen_columns = try self.allocator.alloc(std.StaticBitSet(MAX_COLUMNS), metas.len);
    defer self.allocator.free(seen_columns);
    for (seen_columns) |*bits| bits.* = std.StaticBitSet(MAX_COLUMNS).initEmpty();

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        outbound.noteResponseChunk(decoded.ssz_bytes.len);
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            request_outcome = responseCodeOutcome(decoded.result);
            return responseCodeError(decoded.result);
        }
        defer self.allocator.free(decoded.ssz_bytes);

        var sidecar = DataColumnSidecar.default_value;
        DataColumnSidecar.deserializeFromBytes(self.allocator, decoded.ssz_bytes, &sidecar) catch return error.MalformedDataColumnSidecar;
        defer DataColumnSidecar.deinit(self.allocator, &sidecar);

        const slot = sidecar.signed_block_header.message.slot;
        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.networkingForkDigestAtSlot(slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);

        const meta_index = findMetaIndexByRoot(metas, block_root) orelse return error.UnexpectedDataColumnSidecar;
        const meta = metas[meta_index];
        if (!needsColumnFetch(meta)) continue;

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        if (slot != meta.slot) return error.UnexpectedColumnSlot;
        if (sidecar.index >= MAX_COLUMNS) return error.InvalidColumnIndex;
        if (seen_columns[meta_index].isSet(@intCast(sidecar.index))) continue;
        seen_columns[meta_index].set(@intCast(sidecar.index));

        if (sidecar.kzg_commitments.items.len != blob_commitments.items.len) return error.KzgCommitmentLengthMismatch;
        if (sidecar.column.items.len != blob_commitments.items.len) return error.ColumnLengthMismatch;
        if (sidecar.kzg_proofs.items.len != blob_commitments.items.len) return error.ColumnProofLengthMismatch;

        for (blob_commitments.items, sidecar.kzg_commitments.items) |expected_commitment, actual_commitment| {
            if (!std.mem.eql(u8, &expected_commitment, &actual_commitment)) {
                return error.KzgCommitmentMismatch;
            }
        }

        try verifyDataColumnSidecarWithMetrics(
            self,
            sidecar.index,
            sidecar.kzg_commitments.items,
            sidecar.column.items,
            sidecar.kzg_proofs.items,
        );

        try handleDataAvailabilityReadyBlock(
            try self.chainService().ingestDataColumnSidecar(block_root, sidecar.index, slot, decoded.ssz_bytes),
            self,
            completeReadyIngressAfterDataAvailability,
        );
    }

    request_outcome = .success;
}

fn fetchDataColumnsByRootOnce(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    meta: SyncBlockMeta,
    missing: []const u64,
) !void {
    const covered_missing = try dataColumnsCoveredByPeer(self, peer_id, missing);
    defer self.allocator.free(covered_missing);
    if (covered_missing.len == 0) return error.MissingDataColumnSidecar;

    const protocol_id = "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .data_column_sidecars_by_root, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    var request: DataColumnSidecarsByRootRequest.Type = .empty;
    defer DataColumnSidecarsByRootRequest.deinit(self.allocator, &request);

    {
        var identifier: DataColumnsByRootIdentifier.Type = .{
            .block_root = meta.block_root,
            .columns = .empty,
        };
        errdefer DataColumnsByRootIdentifier.deinit(self.allocator, &identifier);
        try identifier.columns.appendSlice(self.allocator, covered_missing);
        try request.append(self.allocator, identifier);
    }

    const request_bytes = try self.allocator.alloc(u8, DataColumnSidecarsByRootRequest.serializedSize(&request));
    defer self.allocator.free(request_bytes);
    _ = DataColumnSidecarsByRootRequest.serializeIntoBytes(&request, request_bytes);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.noteRequestPayload(request_bytes.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var seen_columns = std.StaticBitSet(MAX_COLUMNS).initEmpty();
    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        outbound.noteResponseChunk(decoded.ssz_bytes.len);
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            request_outcome = responseCodeOutcome(decoded.result);
            return responseCodeError(decoded.result);
        }
        defer self.allocator.free(decoded.ssz_bytes);

        var sidecar = DataColumnSidecar.default_value;
        DataColumnSidecar.deserializeFromBytes(self.allocator, decoded.ssz_bytes, &sidecar) catch return error.MalformedDataColumnSidecar;
        defer DataColumnSidecar.deinit(self.allocator, &sidecar);

        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.networkingForkDigestAtSlot(sidecar.signed_block_header.message.slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);
        if (!std.mem.eql(u8, &block_root, &meta.block_root)) return error.UnexpectedDataColumnSidecar;
        if (sidecar.signed_block_header.message.slot != meta.slot) return error.UnexpectedColumnSlot;
        if (sidecar.index >= MAX_COLUMNS) return error.InvalidColumnIndex;
        if (seen_columns.isSet(@intCast(sidecar.index))) continue;
        seen_columns.set(@intCast(sidecar.index));

        if (sidecar.kzg_commitments.items.len != blob_commitments.items.len) return error.KzgCommitmentLengthMismatch;
        if (sidecar.column.items.len != blob_commitments.items.len) return error.ColumnLengthMismatch;
        if (sidecar.kzg_proofs.items.len != blob_commitments.items.len) return error.ColumnProofLengthMismatch;

        for (blob_commitments.items, sidecar.kzg_commitments.items) |expected_commitment, actual_commitment| {
            if (!std.mem.eql(u8, &expected_commitment, &actual_commitment)) {
                return error.KzgCommitmentMismatch;
            }
        }

        try verifyDataColumnSidecarWithMetrics(
            self,
            sidecar.index,
            sidecar.kzg_commitments.items,
            sidecar.column.items,
            sidecar.kzg_proofs.items,
        );

        try handleDataAvailabilityReadyBlock(
            try self.chainService().ingestDataColumnSidecar(block_root, sidecar.index, sidecar.signed_block_header.message.slot, decoded.ssz_bytes),
            self,
            completeReadyIngressAfterDataAvailability,
        );
    }

    request_outcome = .success;
}

fn buildDataColumnRangeRequest(
    self: *BeaconNode,
    metas: []const SyncBlockMeta,
) !?networking.messages.DataColumnSidecarsByRangeRequest.Type {
    var requested_columns = std.StaticBitSet(MAX_COLUMNS).initEmpty();
    var start_slot: u64 = std.math.maxInt(u64);
    var end_slot: u64 = 0;
    var have_pending = false;

    for (metas) |meta| {
        if (!needsColumnFetch(meta)) continue;
        const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
        defer self.allocator.free(missing);
        if (missing.len == 0) continue;

        have_pending = true;
        start_slot = @min(start_slot, meta.slot);
        end_slot = @max(end_slot, meta.slot);
        for (missing) |column_index| {
            if (column_index < MAX_COLUMNS) requested_columns.set(@intCast(column_index));
        }
    }

    if (!have_pending) return null;

    var request: networking.messages.DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = start_slot,
        .count = end_slot - start_slot + 1,
        .columns = .empty,
    };
    errdefer networking.messages.DataColumnSidecarsByRangeRequest.deinit(self.allocator, &request);

    for (0..MAX_COLUMNS) |column_index| {
        if (requested_columns.isSet(column_index)) {
            try request.columns.append(self.allocator, @intCast(column_index));
        }
    }
    if (request.columns.items.len == 0) return null;
    return request;
}

fn countMissingDataColumnsForMetas(self: *BeaconNode, metas: []const SyncBlockMeta) !usize {
    var count: usize = 0;
    for (metas) |meta| {
        if (!needsColumnFetch(meta)) continue;
        count += try countMissingDataColumnsForMeta(self, meta);
    }
    return count;
}

fn countMissingDataColumnsForMeta(self: *BeaconNode, meta: SyncBlockMeta) !usize {
    const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
    defer self.allocator.free(missing);
    return missing.len;
}

fn selectDataColumnFetchPeer(
    self: *BeaconNode,
    missing_columns: []const u64,
    start_slot: u64,
    end_slot: u64,
    preferred_peer_id: []const u8,
    excluded_peer_ids: []const []const u8,
) !?[]const u8 {
    if (self.peer_manager) |pm| {
        return try pm.selectDataColumnPeer(
            missing_columns,
            start_slot,
            end_slot,
            preferred_peer_id,
            excluded_peer_ids,
        );
    }

    if (containsPeerId(excluded_peer_ids, preferred_peer_id)) return null;
    return try self.allocator.dupe(u8, preferred_peer_id);
}

fn dataColumnsCoveredByPeer(
    self: *BeaconNode,
    peer_id: []const u8,
    columns: []const u64,
) ![]u64 {
    if (columns.len == 0) return self.allocator.alloc(u64, 0);

    if (self.peer_manager) |pm| {
        if (pm.getPeer(peer_id)) |peer| {
            if (peer.custody_columns) |custody_columns| {
                var covered = std.ArrayListUnmanaged(u64).empty;
                errdefer covered.deinit(self.allocator);
                for (columns) |column_index| {
                    if (networking.custody.isCustodied(column_index, custody_columns)) {
                        try covered.append(self.allocator, column_index);
                    }
                }
                return try covered.toOwnedSlice(self.allocator);
            }
        }
    }

    return try self.allocator.dupe(u64, columns);
}

fn containsColumnIndex(columns: []const u64, needle: u64) bool {
    for (columns) |column_index| {
        if (column_index == needle) return true;
    }
    return false;
}

fn needsBlobFetch(meta: SyncBlockMeta) bool {
    return switch (meta.block_data_plan) {
        .blobs => true,
        else => false,
    };
}

fn needsColumnFetch(meta: SyncBlockMeta) bool {
    return switch (meta.block_data_plan) {
        .columns => true,
        else => false,
    };
}

fn requiredColumnIndices(meta: SyncBlockMeta) []const u64 {
    return switch (meta.block_data_plan) {
        .columns => |indices| indices,
        else => &[_]u64{},
    };
}

fn findMetaIndexByRoot(metas: []const SyncBlockMeta, root: [32]u8) ?usize {
    for (metas, 0..) |meta, i| {
        if (std.mem.eql(u8, &meta.block_root, &root)) return i;
    }
    return null;
}

fn readSignedBeaconBlockSlot(bytes: []const u8) ?u64 {
    if (bytes.len < 4) return null;
    const msg_offset = std.mem.readInt(u32, bytes[0..4], .little);
    if (bytes.len < @as(usize, msg_offset) + 8) return null;
    return std.mem.readInt(u64, bytes[msg_offset..][0..8], .little);
}

fn responseCodeError(code: networking.ResponseCode) anyerror {
    return switch (code) {
        .success => unreachable,
        .invalid_request => error.InvalidRequestResponse,
        .server_error => error.ServerErrorResponse,
        .resource_unavailable => error.ResourceUnavailableResponse,
    };
}

const LinkedChainFetchResult = struct {
    peer_id: []const u8,
    block_ssz: []const u8,
};

fn fetchBlockByRootFromPeers(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_ids: []const []const u8,
    root: [32]u8,
) !LinkedChainFetchResult {
    for (peer_ids) |peer_id| {
        const block_ssz = fetchBlockByRoot(self, io, svc, peer_id, root) catch |err| {
            reportReqRespFetchFailure(self, io, peer_id, .beacon_blocks_by_root, err);
            continue;
        };
        return .{
            .peer_id = peer_id,
            .block_ssz = block_ssz,
        };
    }
    return error.NoConnectedPeerHasBlock;
}

fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
    const signature_size: usize = 96;
    const bls_sig_offset: usize = 4;
    const min_size = bls_sig_offset + signature_size + 8 + 8 + 32;
    if (block_bytes.len < min_size) return null;
    const message_offset = std.mem.readInt(u32, block_bytes[0..4], .little);
    if (message_offset != bls_sig_offset + signature_size) return null;
    if (block_bytes.len < message_offset + 8 + 8 + 32) return null;
    return std.mem.readInt(u64, block_bytes[message_offset..][0..8], .little);
}

fn readSignedBlockParentRootFromSsz(block_bytes: []const u8) ?[32]u8 {
    const signature_size: usize = 96;
    const bls_sig_offset: usize = 4;
    const min_size = bls_sig_offset + signature_size + 8 + 8 + 32;
    if (block_bytes.len < min_size) return null;
    const message_offset = std.mem.readInt(u32, block_bytes[0..4], .little);
    if (message_offset != bls_sig_offset + signature_size) return null;
    if (block_bytes.len < message_offset + 8 + 8 + 32) return null;
    var parent_root: [32]u8 = undefined;
    @memcpy(&parent_root, block_bytes[message_offset + 16 ..][0..32]);
    return parent_root;
}

fn fetchBlockByRoot(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    root: [32]u8,
) ![]const u8 {
    const protocol_id = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .beacon_blocks_by_root, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &root);
    outbound.noteRequestPayload(root.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse return error.NoBlockReturned;
    outbound.noteResponseChunk(decoded.ssz_bytes.len);
    if (decoded.result != .success) {
        self.allocator.free(decoded.ssz_bytes);
        request_outcome = responseCodeOutcome(decoded.result);
        return responseCodeError(decoded.result);
    }

    request_outcome = .success;
    return decoded.ssz_bytes;
}

fn fetchRawBlocksByRange(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    start_slot: u64,
    count: u64,
) ![]BatchBlock {
    const protocol_id = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .beacon_blocks_by_range, protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = start_slot,
        .count = count,
        .step = 1,
    };
    var req_ssz: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &req_ssz);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &req_ssz);
    outbound.noteRequestPayload(req_ssz.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var result: std.ArrayListUnmanaged(BatchBlock) = .empty;
    errdefer {
        for (result.items) |blk| self.allocator.free(blk.block_bytes);
        result.deinit(self.allocator);
    }

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();
    var blocks_received: u64 = 0;
    var previous_chunk: ?ValidatedBlockRangeChunk = null;

    while (blocks_received < count) {
        const decoded = reader.next(io, &outbound.stream) catch |err| {
            if (err == error.UnexpectedEof and result.items.len > 0) {
                log.debug("blocks-by-range from {s}: salvaging {d} block(s) after unexpected EOF", .{
                    peer_id,
                    result.items.len,
                });
                break;
            }
            return err;
        } orelse break;
        outbound.noteResponseChunk(decoded.ssz_bytes.len);
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            request_outcome = responseCodeOutcome(decoded.result);
            return responseCodeError(decoded.result);
        }

        const chunk = validateFetchedBlockRangeChunk(self, start_slot, count, previous_chunk, decoded.context_bytes, decoded.ssz_bytes) catch |err| {
            self.allocator.free(decoded.ssz_bytes);
            return err;
        };
        previous_chunk = chunk;

        try result.append(self.allocator, .{
            .slot = chunk.slot,
            .block_bytes = decoded.ssz_bytes,
        });
        blocks_received += 1;
    }

    if (blocks_received == count) {
        const extra = reader.next(io, &outbound.stream) catch |err| {
            if (err == error.UnexpectedEof) return error.MalformedBlockBytes;
            return err;
        };
        if (extra) |decoded| {
            defer self.allocator.free(decoded.ssz_bytes);
            if (decoded.result != .success) {
                request_outcome = responseCodeOutcome(decoded.result);
                return responseCodeError(decoded.result);
            }
            return error.ExtraBlocksByRangeResponse;
        }
    }

    request_outcome = .success;
    return result.toOwnedSlice(self.allocator);
}

fn validateFetchedBlockRangeChunk(
    self: *const BeaconNode,
    start_slot: u64,
    count: u64,
    previous_chunk: ?ValidatedBlockRangeChunk,
    context_bytes: ?[4]u8,
    ssz_bytes: []const u8,
) !ValidatedBlockRangeChunk {
    const slot = readSignedBeaconBlockSlot(ssz_bytes) orelse return error.MalformedBlockBytes;
    if (slot < start_slot) return error.BlockOutsideRequestedRange;
    if (slot - start_slot >= count) return error.BlockOutsideRequestedRange;
    if (previous_chunk) |prev| {
        if (slot <= prev.slot) return error.UnsortedBlockRangeResponse;
        const parent_root = readSignedBlockParentRootFromSsz(ssz_bytes) orelse return error.MalformedBlockBytes;
        try validateFetchedBlockRangeLink(prev.block_root, parent_root);
    }

    const chunk_context = context_bytes orelse return error.MissingContextBytes;
    const expected_digest = self.config.networkingForkDigestAtSlot(slot, self.genesis_validators_root);
    if (!std.mem.eql(u8, &chunk_context, &expected_digest)) return error.ForkDigestMismatch;

    return .{
        .slot = slot,
        .block_root = try readSignedBeaconBlockRootFromSsz(self, slot, ssz_bytes),
    };
}

fn validateFetchedBlockRangeLink(previous_block_root: [32]u8, parent_root: [32]u8) !void {
    if (!std.mem.eql(u8, &previous_block_root, &parent_root)) return error.ParentRootMismatch;
}

fn readSignedBeaconBlockRootFromSsz(self: *const BeaconNode, slot: u64, block_bytes: []const u8) ![32]u8 {
    var any_signed = try fork_types.AnySignedBeaconBlock.deserialize(
        self.allocator,
        .full,
        self.config.forkSeq(slot),
        block_bytes,
    );
    defer any_signed.deinit(self.allocator);

    var block_root: [32]u8 = undefined;
    try any_signed.beaconBlock().hashTreeRoot(self.allocator, &block_root);
    return block_root;
}

fn sendStatus(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !PeerStatusResponse {
    const current_fork_seq = self.config.forkSeq(currentNetworkSlot(self, io) orelse self.currentHeadSlot());
    const use_status_v2 = current_fork_seq.gte(.fulu);
    const status_protocol_id = if (use_status_v2)
        "/eth2/beacon_chain/req/status/2/ssz_snappy"
    else
        "/eth2/beacon_chain/req/status/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .status, status_protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    const our_status = self.getStatus();
    log.debug("Sending Status to {s}: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d} finalized_root={s} head_root={s} earliest_available_slot={d}", .{
        peer_id,
        our_status.fork_digest[0],
        our_status.fork_digest[1],
        our_status.fork_digest[2],
        our_status.fork_digest[3],
        our_status.head_slot,
        our_status.finalized_epoch,
        std.fmt.bytesToHex(our_status.finalized_root[0..4], .lower),
        std.fmt.bytesToHex(our_status.head_root[0..4], .lower),
        self.earliest_available_slot,
    });

    if (use_status_v2) {
        const our_status_v2: StatusMessageV2.Type = .{
            .fork_digest = our_status.fork_digest,
            .finalized_root = our_status.finalized_root,
            .finalized_epoch = our_status.finalized_epoch,
            .head_root = our_status.head_root,
            .head_slot = our_status.head_slot,
            .earliest_available_slot = self.earliest_available_slot,
        };
        var status_ssz: [StatusMessageV2.fixed_size]u8 = undefined;
        _ = StatusMessageV2.serializeIntoBytes(&our_status_v2, &status_ssz);
        try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &status_ssz);
        outbound.noteRequestPayload(status_ssz.len);
    } else {
        var status_ssz: [StatusMessage.fixed_size]u8 = undefined;
        _ = StatusMessage.serializeIntoBytes(&our_status, &status_ssz);
        try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &status_ssz);
        outbound.noteRequestPayload(status_ssz.len);
    }
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse {
        log.debug("Status: peer sent empty response", .{});
        return error.EmptyResponse;
    };
    outbound.noteResponseChunk(decoded.ssz_bytes.len);
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) {
        log.debug("Status response: error code {}", .{decoded.result});
        request_outcome = responseCodeOutcome(decoded.result);
        return responseCodeError(decoded.result);
    }

    if (use_status_v2) {
        var peer_status_v2: StatusMessageV2.Type = undefined;
        StatusMessageV2.deserializeFromBytes(decoded.ssz_bytes, &peer_status_v2) catch |err| {
            log.debug("StatusV2 SSZ deserialize error: {}", .{err});
            return err;
        };

        log.debug("Peer StatusV2 from {s}: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d} finalized_root={s} head_root={s} earliest_available_slot={d}", .{
            peer_id,
            peer_status_v2.fork_digest[0],
            peer_status_v2.fork_digest[1],
            peer_status_v2.fork_digest[2],
            peer_status_v2.fork_digest[3],
            peer_status_v2.head_slot,
            peer_status_v2.finalized_epoch,
            std.fmt.bytesToHex(peer_status_v2.finalized_root[0..4], .lower),
            std.fmt.bytesToHex(peer_status_v2.head_root[0..4], .lower),
            peer_status_v2.earliest_available_slot,
        });

        request_outcome = .success;
        return .{
            .status = .{
                .fork_digest = peer_status_v2.fork_digest,
                .finalized_root = peer_status_v2.finalized_root,
                .finalized_epoch = peer_status_v2.finalized_epoch,
                .head_root = peer_status_v2.head_root,
                .head_slot = peer_status_v2.head_slot,
            },
            .earliest_available_slot = peer_status_v2.earliest_available_slot,
        };
    }

    var peer_status: StatusMessage.Type = undefined;
    StatusMessage.deserializeFromBytes(decoded.ssz_bytes, &peer_status) catch |err| {
        log.debug("Status SSZ deserialize error: {}", .{err});
        return err;
    };

    log.debug("Peer Status from {s}: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d} finalized_root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
        peer_id,
        peer_status.fork_digest[0],
        peer_status.fork_digest[1],
        peer_status.fork_digest[2],
        peer_status.fork_digest[3],
        peer_status.head_slot,
        peer_status.finalized_epoch,
        peer_status.finalized_root[0],
        peer_status.finalized_root[1],
        peer_status.finalized_root[2],
        peer_status.finalized_root[3],
    });

    request_outcome = .success;
    return .{ .status = peer_status };
}

fn requestPeerPing(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !networking.messages.Ping.Type {
    const ping_protocol_id = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .ping, ping_protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    var ping_ssz: [networking.messages.Ping.fixed_size]u8 = undefined;
    const local_seq: networking.messages.Ping.Type = self.api_node_identity.metadata.seq_number;
    _ = networking.messages.Ping.serializeIntoBytes(&local_seq, &ping_ssz);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &ping_ssz);
    outbound.noteRequestPayload(ping_ssz.len);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse return error.EmptyResponse;
    outbound.noteResponseChunk(decoded.ssz_bytes.len);
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) {
        request_outcome = responseCodeOutcome(decoded.result);
        return responseCodeError(decoded.result);
    }

    var remote_seq: networking.messages.Ping.Type = undefined;
    try networking.messages.Ping.deserializeFromBytes(decoded.ssz_bytes, &remote_seq);
    request_outcome = .success;
    return remote_seq;
}

fn requestPeerMetadata(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !PeerMetadataResponse {
    const current_fork_seq = self.config.forkSeq(currentNetworkSlot(self, io) orelse self.currentHeadSlot());
    const use_metadata_v3 = current_fork_seq.gte(.fulu);

    if (!use_metadata_v3) {
        return requestPeerMetadataAttempt(self, io, svc, peer_id, "/eth2/beacon_chain/req/metadata/2/ssz_snappy", false);
    }

    return requestPeerMetadataAttempt(self, io, svc, peer_id, "/eth2/beacon_chain/req/metadata/3/ssz_snappy", true);
}

const MetadataRequestResult = union(enum) {
    success: PeerMetadataResponse,
    failure: anyerror,
    canceled,
};

const MetadataRequestEvent = union(enum) {
    metadata: MetadataRequestResult,
    timeout: TimeoutWaitResult,
};

fn requestPeerMetadataTask(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) MetadataRequestResult {
    const metadata = requestPeerMetadata(self, io, svc, peer_id) catch |err| switch (err) {
        error.Canceled => return .canceled,
        else => return .{ .failure = err },
    };
    return .{ .success = metadata };
}

fn requestPeerMetadataWithTimeout(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    timeout_ms: u64,
) !PeerMetadataResponse {
    var events_buf: [2]MetadataRequestEvent = undefined;
    var select = std.Io.Select(MetadataRequestEvent).init(io, &events_buf);
    errdefer while (select.cancel()) |_| {};

    try select.concurrent(.metadata, requestPeerMetadataTask, .{ self, io, svc, peer_id });
    select.async(.timeout, waitTimeout, .{ io, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(@intCast(timeout_ms)),
        .clock = .awake,
    } } });

    while (true) {
        const event = try select.await();
        switch (event) {
            .metadata => |result| {
                while (select.cancel()) |_| {}
                return switch (result) {
                    .success => |metadata| metadata,
                    .failure => |err| err,
                    .canceled => error.Canceled,
                };
            },
            .timeout => |result| switch (result) {
                .fired => {
                    while (select.cancel()) |_| {}
                    return error.Timeout;
                },
                .canceled => {},
            },
        }
    }
}

fn requestPeerMetadataAttempt(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    metadata_protocol_id: []const u8,
    expect_metadata_v3: bool,
) !PeerMetadataResponse {
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .metadata, metadata_protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &.{});
    outbound.noteRequestPayload(0);
    outbound.stream.closeWrite(io);
    request_outcome = .malformed_response;

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (reader.next(io, &outbound.stream) catch |err| {
        log.debug(
            "Metadata reader failed for {s}: {} buffered={d} eof={}",
            .{
                peer_id,
                err,
                reader.buffer.items.len,
                reader.reached_eof,
            },
        );
        return err;
    }) orelse {
        log.debug(
            "Metadata peer sent empty response for {s} buffered={d} eof={}",
            .{
                peer_id,
                reader.buffer.items.len,
                reader.reached_eof,
            },
        );
        return error.EmptyResponse;
    };
    outbound.noteResponseChunk(decoded.ssz_bytes.len);
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) {
        request_outcome = responseCodeOutcome(decoded.result);
        return responseCodeError(decoded.result);
    }

    if (expect_metadata_v3) {
        if (decoded.ssz_bytes.len == MetadataV2.fixed_size) {
            var metadata_v2_fallback: MetadataV2.Type = undefined;
            try MetadataV2.deserializeFromBytes(decoded.ssz_bytes, &metadata_v2_fallback);
            log.debug("Metadata V3 fallback to V2 for {s}", .{peer_id});
            request_outcome = .success;
            return .{
                .metadata = metadata_v2_fallback,
                .custody_group_count = 0,
            };
        }

        var metadata_v3: MetadataV3.Type = undefined;
        MetadataV3.deserializeFromBytes(decoded.ssz_bytes, &metadata_v3) catch |err| {
            log.debug(
                "Metadata V3 decode failed for {s}: {} ssz_len={d} bytes={x}",
                .{
                    peer_id,
                    err,
                    decoded.ssz_bytes.len,
                    decoded.ssz_bytes,
                },
            );
            return err;
        };
        log.debug(
            "Peer metadata v3 from {s}: seq={d} custody_group_count={d}",
            .{
                peer_id,
                metadata_v3.seq_number,
                metadata_v3.custody_group_count,
            },
        );
        request_outcome = .success;
        return .{
            .metadata = .{
                .seq_number = metadata_v3.seq_number,
                .attnets = metadata_v3.attnets,
                .syncnets = metadata_v3.syncnets,
            },
            .custody_group_count = metadata_v3.custody_group_count,
        };
    }

    var metadata: MetadataV2.Type = undefined;
    try MetadataV2.deserializeFromBytes(decoded.ssz_bytes, &metadata);
    request_outcome = .success;
    return .{ .metadata = metadata };
}

fn reportReqRespFetchFailure(
    self: *BeaconNode,
    io: std.Io,
    peer_id: []const u8,
    protocol: ReqRespMaintenanceProtocol,
    err: anyerror,
) void {
    if (self.metrics) |metrics| {
        metrics.incrReqRespMaintenanceError(
            reqRespMaintenanceMethod(protocol),
            reqRespMaintenanceErrorLabel(err),
        );
    }
    const pm = self.peer_manager orelse return;
    const action = peer_scoring.reqRespFailureAction(protocol, err) orelse return;
    _ = pm.reportPeer(peer_id, action, .rpc, currentUnixTimeMs(io));
}

fn reqRespMaintenanceMethod(protocol: ReqRespMaintenanceProtocol) networking.Method {
    return switch (protocol) {
        .status => .status,
        .goodbye => .goodbye,
        .ping => .ping,
        .metadata => .metadata,
        .beacon_blocks_by_range => .beacon_blocks_by_range,
        .beacon_blocks_by_root => .beacon_blocks_by_root,
        .blob_sidecars_by_range => .blob_sidecars_by_range,
        .blob_sidecars_by_root => .blob_sidecars_by_root,
        .data_column_sidecars_by_range => .data_column_sidecars_by_range,
        .data_column_sidecars_by_root => .data_column_sidecars_by_root,
    };
}

fn reqRespMaintenanceErrorLabel(err: anyerror) []const u8 {
    if (isReqRespTransportClosedError(err)) return "transport_closed";
    return switch (err) {
        error.RequestSelfRateLimited => "self_rate_limited",
        else => @errorName(err),
    };
}

fn isReqRespTransportClosedError(err: anyerror) bool {
    return switch (err) {
        error.PeerNotConnected,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.UnexpectedEof,
        error.EndOfStream,
        error.BrokenPipe,
        => true,
        else => false,
    };
}

fn noteSyncPeerGoneIfTransportClosed(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    err: anyerror,
) void {
    if (!isReqRespTransportClosedError(err)) return;

    if (svc.isPeerConnected(io, peer_id)) return;
    const pm = self.peer_manager orelse return;
    notePeerDisconnected(self, pm, peer_id, currentUnixTimeMs(io));
}

fn handleReqRespMaintenanceFailure(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    protocol: ReqRespMaintenanceProtocol,
    err: anyerror,
    disconnect_peer: bool,
) void {
    if (self.metrics) |metrics| {
        metrics.incrReqRespMaintenanceError(
            reqRespMaintenanceMethod(protocol),
            reqRespMaintenanceErrorLabel(err),
        );
    }
    log.debug("Peer maintenance {s} failed for {f}: {}", .{
        @tagName(protocol),
        networking.fmtPeerId(peer_id),
        err,
    });

    if (isReqRespTransportClosedError(err)) {
        noteSyncPeerGoneIfTransportClosed(self, io, svc, peer_id, err);
        log.debug("Peer maintenance {s} saw closed transport for {f}; deferring to transport state", .{
            @tagName(protocol),
            networking.fmtPeerId(peer_id),
        });
        return;
    }

    if (err == error.RequestSelfRateLimited) {
        log.debug("Local req/resp self rate limit hit for maintenance {s} to {f}", .{
            @tagName(protocol),
            networking.fmtPeerId(peer_id),
        });
        return;
    }

    const pm = self.peer_manager orelse {
        if (disconnect_peer) _ = svc.disconnectPeer(io, peer_id);
        return;
    };

    const now_ms = currentUnixTimeMs(io);
    const action = reqRespMaintenanceFailureAction(protocol, err) orelse {
        if (disconnect_peer) _ = svc.disconnectPeer(io, peer_id);
        return;
    };
    const score_state = pm.reportPeer(peer_id, action, .rpc, now_ms);
    if (!disconnect_peer) return;

    var reason: GoodbyeReason = .fault_error;
    if (score_state) |state| {
        switch (state) {
            .healthy => {},
            .disconnected => reason = .score_too_low,
            .banned => {
                pm.banPeer(peer_id, .medium, now_ms) catch |ban_err| {
                    log.warn("Failed to ban peer {f} after req/resp failure: {}", .{ networking.fmtPeerId(peer_id), ban_err });
                };
                reason = .banned;
            },
        }
    }

    sendGoodbyeAndDisconnect(self, io, svc, peer_id, reason);
}

fn reqRespMaintenanceFailureAction(protocol: ReqRespMaintenanceProtocol, err: anyerror) ?PeerAction {
    return peer_scoring.reqRespFailureAction(protocol, err);
}

fn sendGoodbye(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    reason: GoodbyeReason,
) !void {
    const goodbye_protocol_id = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(self, io, svc, peer_id, .goodbye, goodbye_protocol_id);
    defer outbound.deinit(io);
    var request_outcome: networking.ReqRespRequestOutcome = .transport_error;
    defer outbound.finish(io, request_outcome);

    var goodbye_ssz: [networking.messages.GoodbyeReason.fixed_size]u8 = undefined;
    const reason_code: networking.messages.GoodbyeReason.Type = @intFromEnum(reason);
    _ = networking.messages.GoodbyeReason.serializeIntoBytes(&reason_code, &goodbye_ssz);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &goodbye_ssz);
    outbound.noteRequestPayload(goodbye_ssz.len);
    outbound.stream.closeWrite(io);
    request_outcome = .success;
}

fn attnetsFromMetadata(bytes: [8]u8) AttnetsBitfield {
    var attnets = AttnetsBitfield.initEmpty();
    var subnet: u32 = 0;
    while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
        if ((bytes[subnet / 8] & (@as(u8, 1) << @intCast(subnet % 8))) != 0) {
            attnets.set(subnet);
        }
    }
    return attnets;
}

fn syncnetsFromMetadata(bytes: [1]u8) SyncnetsBitfield {
    var syncnets = SyncnetsBitfield.initEmpty();
    var subnet: u32 = 0;
    while (subnet < SYNC_COMMITTEE_SUBNET_COUNT) : (subnet += 1) {
        if ((bytes[subnet / 8] & (@as(u8, 1) << @intCast(subnet % 8))) != 0) {
            syncnets.set(subnet);
        }
    }
    return syncnets;
}

fn initGossipHandler(self: *BeaconNode) void {
    if (self.gossip_handler != null) return;

    const callbacks = gossip_node_callbacks_mod;
    const initial_fork_seq = if (currentNetworkSlot(self, self.io)) |slot|
        self.config.forkSeq(slot)
    else
        self.config.forkSeq(self.currentHeadSlot());
    self.gossip_handler = GossipHandler.create(
        self.allocator,
        self.io,
        @ptrCast(self),
        &callbacks.importBlockFromGossip,
        &callbacks.getForkSeqForSlot,
        &callbacks.getProposerIndex,
        &callbacks.isKnownBlockRoot,
        &callbacks.getKnownBlockInfo,
        &callbacks.getValidatorCount,
        &callbacks.resolveAttestation,
        &callbacks.resolveAggregate,
        &callbacks.isValidSyncCommitteeSubnet,
        .{
            .importSyncContributionFn = &callbacks.importSyncContribution,
            .importBlobSidecarFn = &callbacks.importBlobSidecar,
            .importDataColumnSidecarFn = &callbacks.importDataColumnSidecar,
            .verifySyncContributionSignatureFn = &callbacks.verifySyncContributionSignature,
            .verifyBlobSidecarFn = &callbacks.verifyBlobSidecar,
            .verifyDataColumnSidecarFn = &callbacks.verifyDataColumnSidecar,
            .getBlobSidecarSubnetCountFn = &callbacks.getBlobSidecarSubnetCountForSlot,
        },
    ) catch |err| {
        log.warn("Failed to create GossipHandler: {}", .{err});
        return;
    };

    if (self.gossip_handler) |gh| {
        gh.queueUnknownBlockFn = &callbacks.queueUnknownBlockFromGossip;
        gh.queueUnknownBlockAttestationFn = &callbacks.queueUnknownBlockAttestationFromGossip;
        gh.queueUnknownBlockAggregateFn = &callbacks.queueUnknownBlockAggregateFromGossip;
        gh.importResolvedAttestationFn = &callbacks.importResolvedAttestation;
        gh.importResolvedAggregateFn = &callbacks.importResolvedAggregate;
        gh.importVoluntaryExitFn = &callbacks.importVoluntaryExit;
        gh.importProposerSlashingFn = &callbacks.importProposerSlashing;
        gh.importAttesterSlashingFn = &callbacks.importAttesterSlashing;
        gh.importBlsChangeFn = &callbacks.importBlsChange;

        gh.verifyBlockSignatureFn = &callbacks.verifyBlockSignature;
        gh.verifyVoluntaryExitSignatureFn = &callbacks.verifyVoluntaryExitSignature;
        gh.verifyProposerSlashingSignatureFn = &callbacks.verifyProposerSlashingSignature;
        gh.verifyAttesterSlashingSignatureFn = &callbacks.verifyAttesterSlashingSignature;
        gh.verifyBlsChangeSignatureFn = &callbacks.verifyBlsChangeSignature;
        gh.verifyAttestationSignatureFn = &callbacks.verifyAttestationSignature;
        gh.verifyAggregateSignatureFn = &callbacks.verifyResolvedAggregateSignature;
        gh.verifySyncCommitteeSignatureFn = &callbacks.verifySyncCommitteeSignature;
        gh.importSyncCommitteeMessageFn = &callbacks.importSyncCommitteeMessage;

        gh.updateForkSeq(initial_fork_seq);
        gh.metrics = self.metrics;
        gh.beacon_processor = self.beacon_processor;
    }
}

fn currentUnixTimeMs(io: std.Io) u64 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}

fn maybePrepareProposerPayload(self: *BeaconNode, io: std.Io) void {
    const clock = self.clock orelse return;
    if (!self.hasExecutionEngine()) return;

    const current_slot = clock.currentSlot(io) orelse return;
    const next_slot = current_slot + 1;
    const head_root = self.currentHeadRoot();

    const head_state = self.headState() orelse return;
    _ = head_state.epoch_cache.getBeaconProposer(next_slot) catch return;

    const fee_recipient = self.chainQuery().proposerFeeRecipientForSlot(
        next_slot,
        self.node_options.suggested_fee_recipient,
    ) orelse return;
    self.refreshBuilderStatus(current_slot);
    if (self.execution_runtime.cachedPayloadFor(next_slot, head_root)) {
        return;
    }

    const timestamp = clock.slotStartSeconds(next_slot);
    const next_epoch = next_slot / preset.SLOTS_PER_EPOCH;
    const randao_index = next_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR;
    const prev_randao: [32]u8 = blk: {
        var mixes = head_state.state.randaoMixes() catch break :blk [_]u8{0} ** 32;
        const mix_ptr = mixes.getFieldRoot(randao_index) catch break :blk [_]u8{0} ** 32;
        break :blk mix_ptr.*;
    };

    self.preparePayload(
        next_slot,
        timestamp,
        prev_randao,
        fee_recipient,
        &.{},
        head_root,
    ) catch |err| {
        log.warn("preparePayload failed for slot {d}: {}", .{ next_slot, err });
    };
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
const DiscoveryDialCompletion = beacon_node_mod.DiscoveryDialCompletion;
const PeerReqRespCompletion = beacon_node_mod.PeerReqRespCompletion;
const SyncStatus = beacon_node_mod.SyncStatus;

test "validateFetchedBlockRangeLink accepts matching parent root" {
    const root = [_]u8{0xAB} ** 32;
    try validateFetchedBlockRangeLink(root, root);
}

test "validateFetchedBlockRangeLink rejects mismatched parent root" {
    try std.testing.expectError(
        error.ParentRootMismatch,
        validateFetchedBlockRangeLink([_]u8{0xAB} ** 32, [_]u8{0xCD} ** 32),
    );
}

test "handleDataAvailabilityReadyBlock forwards ready block into import callback" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const TestCtx = struct {
        allocator: std.mem.Allocator,
        called: usize = 0,

        fn complete(ptr: *anyopaque, ready: chain_mod.ReadyBlockInput) anyerror!void {
            const ctx: *@This() = @ptrCast(@alignCast(ptr));
            ctx.called += 1;
            var owned_ready = ready;
            owned_ready.deinit(ctx.allocator);
        }
    };

    const signed_block = try allocator.create(types.phase0.SignedBeaconBlock.Type);
    errdefer allocator.destroy(signed_block);
    signed_block.* = types.phase0.SignedBeaconBlock.default_value;

    const ready: chain_mod.ReadyBlockInput = .{
        .block = .{ .phase0 = signed_block },
        .source = .gossip,
        .block_root = [_]u8{0xAB} ** 32,
        .slot = 123,
        .da_status = .available,
        .block_data_plan = .none,
        .seen_timestamp_sec = 0,
        .peer = .{},
    };

    var ctx = TestCtx{ .allocator = allocator };
    try handleDataAvailabilityReadyBlock(ready, &ctx, TestCtx.complete);
    try testing.expectEqual(@as(usize, 1), ctx.called);
}

test "handleDataAvailabilityReadyBlock ignores null ready block" {
    const testing = std.testing;

    const TestCtx = struct {
        called: usize = 0,

        fn complete(ptr: *anyopaque, ready: chain_mod.ReadyBlockInput) anyerror!void {
            const ctx: *@This() = @ptrCast(@alignCast(ptr));
            var owned_ready = ready;
            _ = &owned_ready;
            ctx.called += 1;
        }
    };

    var ctx = TestCtx{};
    try handleDataAvailabilityReadyBlock(null, &ctx, TestCtx.complete);
    try testing.expectEqual(@as(usize, 0), ctx.called);
}
