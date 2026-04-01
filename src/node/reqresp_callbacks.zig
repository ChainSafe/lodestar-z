//! Req/resp callbacks for the P2P req/resp protocol.
//!
//! Bridges the type-erased networking vtable to BeaconNode internals using
//! streaming payload emitters instead of eager slice materialization.

const std = @import("std");

const preset_root = @import("preset");
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const ReqRespContext = networking.ReqRespContext;
const PayloadSink = networking.req_resp_handler.PayloadSink;
const SlotPayload = networking.req_resp_handler.SlotPayload;

pub const RequestContext = struct {
    // Stored as *anyopaque to avoid a circular dependency in the type graph.
    node: *anyopaque,
};

pub fn makeReqRespContext(ctx: *RequestContext) ReqRespContext {
    return .{
        .ptr = @ptrCast(ctx),
        .getStatus = &reqRespGetStatus,
        .getMetadata = &reqRespGetMetadata,
        .getPingSequence = &reqRespGetPingSequence,
        .findBlockByRoot = &reqRespFindBlockByRoot,
        .streamBlocksByRange = &reqRespStreamBlocksByRange,
        .findBlobByRoot = &reqRespFindBlobByRoot,
        .streamBlobsByRange = &reqRespStreamBlobsByRange,
        .findDataColumnByRoot = &reqRespFindDataColumnByRoot,
        .streamDataColumnsByRange = &reqRespStreamDataColumnsByRange,
        .getForkDigest = &reqRespGetForkDigest,
        .onGoodbye = &reqRespOnGoodbye,
        .onPeerStatus = &reqRespOnPeerStatus,
    };
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

fn requestNode(ptr: *anyopaque) *BeaconNode {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    return @ptrCast(@alignCast(ctx.node));
}

fn reqRespGetStatus(ptr: *anyopaque) StatusMessage.Type {
    const node = requestNode(ptr);
    return node.getStatus();
}

fn reqRespGetMetadata(ptr: *anyopaque) networking.messages.MetadataV2.Type {
    _ = ptr;
    return .{
        .seq_number = 0,
        .attnets = .{ .data = std.mem.zeroes([8]u8) },
        .syncnets = .{ .data = std.mem.zeroes([1]u8) },
    };
}

fn reqRespGetPingSequence(ptr: *anyopaque) u64 {
    _ = ptr;
    return 0;
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
    var slot = start_slot;
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
    var slot = start_slot;
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

fn reqRespGetForkDigest(ptr: *anyopaque, slot: u64) [4]u8 {
    const node = requestNode(ptr);
    return node.config.forkDigestAtSlot(slot, node.genesis_validators_root);
}

fn reqRespOnGoodbye(ptr: *anyopaque, peer_id: ?[]const u8, reason: u64) void {
    _ = ptr;
    _ = peer_id;
    _ = reason;
}

fn reqRespOnPeerStatus(ptr: *anyopaque, peer_id: ?[]const u8, status: StatusMessage.Type) void {
    const node = requestNode(ptr);
    const effective_peer_id = peer_id orelse "unknown";

    if (node.sync_service_inst) |sync_svc| {
        sync_svc.onPeerStatus(effective_peer_id, status) catch |err| {
            std.log.warn("SyncService.onPeerStatus failed: {}", .{err});
        };
    }
    node.unknown_chain_sync.onPeerConnected(effective_peer_id, status.head_root) catch {};
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
