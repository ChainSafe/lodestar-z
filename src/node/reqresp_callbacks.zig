//! Req/resp callbacks for the P2P req/resp protocol.
//!
//! Bridges the type-erased networking vtable to BeaconNode internals using
//! streaming payload emitters instead of eager slice materialization.

const std = @import("std");

const config_mod = @import("config");
const preset_root = @import("preset");
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const MetadataV2 = networking.messages.MetadataV2;
const ReqRespContext = networking.ReqRespContext;
const ReqRespServerPolicy = networking.ReqRespServerPolicy;
const ReqRespServerDecision = networking.ReqRespServerDecision;
const ReqRespRequestOutcome = networking.ReqRespRequestOutcome;
const Method = networking.Method;
const PayloadSink = networking.req_resp_handler.PayloadSink;
const SlotPayload = networking.req_resp_handler.SlotPayload;
const ForkSeq = config_mod.ForkSeq;

pub const RequestContext = struct {
    // Stored as *anyopaque to avoid a circular dependency in the type graph.
    node: *anyopaque,
};

pub fn makeReqRespContext(ctx: *RequestContext) ReqRespContext {
    return .{
        .ptr = @ptrCast(ctx),
        .getStatus = &reqRespGetStatus,
        .getMetadata = &reqRespGetMetadata,
        .getEarliestAvailableSlot = &reqRespGetEarliestAvailableSlot,
        .getCustodyGroupCount = &reqRespGetCustodyGroupCount,
        .getPingSequence = &reqRespGetPingSequence,
        .findBlockByRoot = &reqRespFindBlockByRoot,
        .streamBlocksByRange = &reqRespStreamBlocksByRange,
        .findBlobByRoot = &reqRespFindBlobByRoot,
        .streamBlobsByRange = &reqRespStreamBlobsByRange,
        .findDataColumnByRoot = &reqRespFindDataColumnByRoot,
        .streamDataColumnsByRange = &reqRespStreamDataColumnsByRange,
        .getCurrentForkSeq = &reqRespGetCurrentForkSeq,
        .getForkSeqForSlot = &reqRespGetForkSeqForSlot,
        .getForkDigest = &reqRespGetForkDigest,
        .onGoodbye = &reqRespOnGoodbye,
        .onPeerStatus = &reqRespOnPeerStatus,
        .onRequestCompleted = &reqRespOnRequestCompleted,
    };
}

pub fn makeReqRespServerPolicy(ctx: *RequestContext) ReqRespServerPolicy {
    return .{
        .ptr = @ptrCast(ctx),
        .allowInboundRequestFn = &reqRespAllowInboundRequest,
    };
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

fn requestNode(ptr: *anyopaque) *BeaconNode {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    return @ptrCast(@alignCast(ctx.node));
}

fn reqRespAllowInboundRequest(ptr: *anyopaque, peer_id: ?[]const u8, method: networking.Method, request_bytes: []const u8) ReqRespServerDecision {
    const node = requestNode(ptr);
    const peer_id_bytes = peer_id orelse return .allow;
    const limiter = node.req_resp_rate_limiter orelse return .allow;
    const protocol = networking.rate_limiter.methodToRateLimitProtocol(method) orelse return .allow;

    const result = limiter.allowRequestN(
        peer_id_bytes,
        protocol,
        networking.rate_limiter.requestTokenCost(method, request_bytes),
        monotonicTimeNs(node.io),
    ) catch |err| {
        std.log.debug("failed to apply req/resp rate limit for peer {s}: {}", .{ peer_id_bytes, err });
        return .allow;
    };
    if (result.isAllowed()) return .allow;

    if (result.isPeerDenied()) {
        if (node.peer_manager) |pm| {
            _ = pm.reportPeer(peer_id_bytes, .fatal, .rpc, wallTimeMs(node.io));
        }
        if (node.p2p_service) |*svc| {
            _ = svc.disconnectPeer(node.io, peer_id_bytes);
        }
        return .deny_peer;
    }
    return .deny_global;
}

fn reqRespGetStatus(ptr: *anyopaque) StatusMessage.Type {
    const node = requestNode(ptr);
    return node.getStatus();
}

fn reqRespGetMetadata(ptr: *anyopaque) MetadataV2.Type {
    const node = requestNode(ptr);
    return .{
        .seq_number = node.api_node_identity.metadata.seq_number,
        .attnets = .{ .data = node.api_node_identity.metadata.attnets },
        .syncnets = .{ .data = node.api_node_identity.metadata.syncnets },
    };
}

fn reqRespGetPingSequence(ptr: *anyopaque) u64 {
    const node = requestNode(ptr);
    return node.api_node_identity.metadata.seq_number;
}

fn reqRespGetEarliestAvailableSlot(ptr: *anyopaque) u64 {
    const node = requestNode(ptr);
    return node.earliest_available_slot;
}

fn reqRespGetCustodyGroupCount(ptr: *anyopaque) u64 {
    const node = requestNode(ptr);
    return node.config.chain.CUSTODY_REQUIREMENT;
}

fn reqRespFindBlockByRoot(ptr: *anyopaque, root: [32]u8, sink: *const PayloadSink) anyerror!void {
    const node = requestNode(ptr);
    const maybe_bytes = node.chainQuery().blockBytesByRoot(root) catch return;
    const bytes = maybe_bytes orelse return;
    defer node.allocator.free(bytes);

    try sink.write(.{
        .slot = readSignedBeaconBlockSlot(bytes) orelse 0,
        .ssz_payload = bytes,
    });
}

fn reqRespStreamBlocksByRange(ptr: *anyopaque, start_slot: u64, count: u64, sink: *const PayloadSink) anyerror!void {
    const node = requestNode(ptr);
    const query = node.chainQuery();

    const end_slot = std.math.add(u64, start_slot, count) catch return;
    var slot = @max(start_slot, node.earliest_available_slot);
    while (slot < end_slot) : (slot += 1) {
        const maybe_bytes = query.blockBytesAtSlot(slot) catch continue;
        const bytes = maybe_bytes orelse continue;
        defer node.allocator.free(bytes);

        try sink.write(.{
            .slot = readSignedBeaconBlockSlot(bytes) orelse slot,
            .ssz_payload = bytes,
        });
    }
}

fn reqRespFindBlobByRoot(ptr: *anyopaque, root: [32]u8, index: u64, sink: *const PayloadSink) anyerror!void {
    const node = requestNode(ptr);

    const maybe_bytes = node.chainQuery().blobSidecarsByRoot(root) catch return;
    const bytes = maybe_bytes orelse return;
    defer node.allocator.free(bytes);

    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;
    const start = index * sidecar_size;
    const end = start + sidecar_size;
    if (end > bytes.len) return;

    const blob = bytes[start..end];
    try sink.write(.{
        .slot = readBlobSidecarSlot(blob) orelse 0,
        .ssz_payload = blob,
    });
}

fn reqRespStreamBlobsByRange(ptr: *anyopaque, start_slot: u64, count: u64, sink: *const PayloadSink) anyerror!void {
    const node = requestNode(ptr);
    const query = node.chainQuery();
    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;

    const end_slot = std.math.add(u64, start_slot, count) catch return;
    var slot = start_slot;
    while (slot < end_slot) : (slot += 1) {
        const maybe_bytes = query.blobSidecarsAtSlot(slot) catch continue;
        const bytes = maybe_bytes orelse continue;
        defer node.allocator.free(bytes);

        var offset: usize = 0;
        while (offset + sidecar_size <= bytes.len) : (offset += sidecar_size) {
            const blob = bytes[offset..][0..sidecar_size];
            try sink.write(.{
                .slot = readBlobSidecarSlot(blob) orelse slot,
                .ssz_payload = blob,
            });
        }
    }
}

fn reqRespFindDataColumnByRoot(ptr: *anyopaque, root: [32]u8, index: u64, sink: *const PayloadSink) anyerror!void {
    const node = requestNode(ptr);

    const maybe_bytes = node.chainQuery().dataColumnByRoot(root, index) catch return;
    const bytes = maybe_bytes orelse return;
    defer node.allocator.free(bytes);

    try sink.write(.{
        .slot = readDataColumnSidecarSlot(bytes) orelse 0,
        .ssz_payload = bytes,
    });
}

fn reqRespStreamDataColumnsByRange(
    ptr: *anyopaque,
    start_slot: u64,
    count: u64,
    columns: []const u64,
    sink: *const PayloadSink,
) anyerror!void {
    const node = requestNode(ptr);
    const query = node.chainQuery();

    const end_slot = std.math.add(u64, start_slot, count) catch return;
    var slot = @max(start_slot, node.earliest_available_slot);
    while (slot < end_slot) : (slot += 1) {
        for (columns) |column_index| {
            const maybe_bytes = query.dataColumnAtSlot(slot, column_index) catch continue;
            const bytes = maybe_bytes orelse continue;
            defer node.allocator.free(bytes);

            try sink.write(.{
                .slot = readDataColumnSidecarSlot(bytes) orelse slot,
                .ssz_payload = bytes,
            });
        }
    }
}

fn reqRespGetCurrentForkSeq(ptr: *anyopaque) ForkSeq {
    const node = requestNode(ptr);
    return node.config.forkSeq(node.currentHeadSlot());
}

fn reqRespGetForkSeqForSlot(ptr: *anyopaque, slot: u64) ForkSeq {
    const node = requestNode(ptr);
    return node.config.forkSeq(slot);
}

fn reqRespGetForkDigest(ptr: *anyopaque, slot: u64) [4]u8 {
    const node = requestNode(ptr);
    return node.config.forkDigestAtSlot(slot, node.genesis_validators_root);
}

fn reqRespOnGoodbye(ptr: *anyopaque, peer_id: ?[]const u8, reason: u64) void {
    const node = requestNode(ptr);
    const effective_peer_id = peer_id orelse return;
    handlePeerGoodbye(node, effective_peer_id, reason);
}

fn reqRespOnPeerStatus(ptr: *anyopaque, peer_id: ?[]const u8, status: StatusMessage.Type, earliest_available_slot: ?u64) void {
    const node = requestNode(ptr);
    const effective_peer_id = peer_id orelse return;
    const irrelevance = handlePeerStatus(node, effective_peer_id, status, earliest_available_slot);
    if (irrelevance) |code| {
        std.log.debug("Peer {s} failed relevance check during inbound status handling: {s}", .{
            effective_peer_id,
            @tagName(code),
        });
    }
}

fn reqRespOnRequestCompleted(
    ptr: *anyopaque,
    method: Method,
    outcome: ReqRespRequestOutcome,
    response_time_seconds: f64,
) void {
    const node = requestNode(ptr);
    if (node.metrics) |metrics| {
        metrics.observeReqRespInbound(method, outcome, response_time_seconds);
    }
}

pub fn handlePeerStatus(
    node: *BeaconNode,
    peer_id: []const u8,
    status: StatusMessage.Type,
    earliest_available_slot: ?u64,
) ?networking.IrrelevantPeerCode {
    return handlePeerStatusAtTime(
        node,
        peer_id,
        status,
        earliest_available_slot,
        wallTimeMs(node.io),
    );
}

pub fn handlePeerStatusAtTime(
    node: *BeaconNode,
    peer_id: []const u8,
    status: StatusMessage.Type,
    earliest_available_slot: ?u64,
    now_ms: u64,
) ?networking.IrrelevantPeerCode {
    var irrelevance: ?networking.IrrelevantPeerCode = null;
    var registered_new_peer = false;

    if (node.peer_manager) |pm| {
        const existing = pm.getPeer(peer_id);
        if (existing == null or !existing.?.isConnected()) {
            const direction = if (existing) |info| info.direction orelse .inbound else .inbound;
            if ((pm.onPeerConnected(peer_id, direction, now_ms) catch null) != null) {
                registered_new_peer = true;
            }
        }

        irrelevance = pm.onPeerStatus(
            peer_id,
            status.fork_digest,
            status.finalized_root,
            status.finalized_epoch,
            status.head_root,
            status.head_slot,
            earliest_available_slot,
            localCachedStatus(node),
            node.config.forkSeq(node.currentHeadSlot()),
            node.currentHeadSlot(),
        );
        pm.markStatusExchange(peer_id, now_ms);
    }

    if (registered_new_peer) {
        if (node.metrics) |metrics| metrics.peer_connected_total.incr();
    }

    if (node.sync_service_inst) |sync_svc| {
        sync_svc.onPeerStatus(peer_id, status, earliest_available_slot) catch |err| {
            std.log.debug("sync service onPeerStatus failed: {}", .{err});
        };
    }
    node.unknown_chain_sync.onPeerConnected(peer_id, status.head_root) catch {};

    return irrelevance;
}

pub fn handlePeerGoodbye(node: *BeaconNode, peer_id: []const u8, reason: u64) void {
    if (node.peer_manager) |pm| {
        pm.onPeerGoodbye(peer_id, @enumFromInt(reason), wallTimeMs(node.io));
    }
    std.log.debug("Peer sent Goodbye {s} reason={d}", .{ peer_id, reason });
}

fn localCachedStatus(node: *const BeaconNode) networking.CachedStatus {
    const status = node.getStatus();
    return .{
        .fork_digest = status.fork_digest,
        .finalized_root = status.finalized_root,
        .finalized_epoch = status.finalized_epoch,
        .head_root = status.head_root,
        .head_slot = status.head_slot,
    };
}

fn wallTimeMs(io: std.Io) u64 {
    const now = std.Io.Clock.real.now(io);
    if (now.nanoseconds <= 0) return 0;
    const ns = std.math.cast(u64, now.nanoseconds) orelse std.math.maxInt(u64);
    return ns / std.time.ns_per_ms;
}

fn monotonicTimeNs(io: std.Io) i128 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

fn readSignedBeaconBlockSlot(bytes: []const u8) ?u64 {
    if (bytes.len < 4) return null;
    const msg_offset = std.mem.readInt(u32, bytes[0..4], .little);
    if (bytes.len < @as(usize, msg_offset) + 8) return null;
    return std.mem.readInt(u64, bytes[msg_offset..][0..8], .little);
}

fn readBlobSidecarSlot(bytes: []const u8) ?u64 {
    const slot_offset = 8 + (4096 * 32) + 48 + 48;
    if (bytes.len < slot_offset + 8) return null;
    return std.mem.readInt(u64, bytes[slot_offset..][0..8], .little);
}

fn readDataColumnSidecarSlot(bytes: []const u8) ?u64 {
    const slot_offset = 8 + 4 + 4 + 4;
    if (bytes.len < slot_offset + 8) return null;
    return std.mem.readInt(u64, bytes[slot_offset..][0..8], .little);
}
