//! Req/resp callbacks for the P2P req/resp protocol.
//!
//! Implements `ReqRespContext` callbacks that bridge the type-erased
//! vtable from the networking layer to BeaconNode internals.
//!
//! The `RequestContext` struct wraps a *BeaconNode and a scratch allocator.
//! All DB-fetched byte slices are allocated on the scratch arena and freed
//! after `handleRequest` copies them into response chunks.

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset_root = @import("preset");
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const ReqRespContext = networking.ReqRespContext;

/// Wraps a *BeaconNode + scratch arena for req/resp callbacks.
///
/// Lives on the stack of BeaconNode.onReqResp(). Each callback receives this
/// as `ptr: *anyopaque` and casts it back to access the node and scratch allocator.
pub const RequestContext = struct {
    // Note: *BeaconNode is declared as *anyopaque here to break the circular
    // dependency between this file and beacon_node.zig.
    // Cast back with: const node: *BeaconNode = @ptrCast(@alignCast(self.node));
    node: *anyopaque,
    /// Scratch allocator for temporary DB-fetched bytes.
    /// Freed by the arena after handleRequest returns.
    scratch: Allocator,
};

/// Build the ReqRespContext vtable wired to RequestContext callbacks.
pub fn makeReqRespContext(ctx: *RequestContext) ReqRespContext {
    return .{
        .ptr = @ptrCast(ctx),
        .getStatus = &reqRespGetStatus,
        .getMetadata = &reqRespGetMetadata,
        .getPingSequence = &reqRespGetPingSequence,
        .getBlockByRoot = &reqRespGetBlockByRoot,
        .getBlocksByRange = &reqRespGetBlocksByRange,
        .getBlobByRoot = &reqRespGetBlobByRoot,
        .getBlobsByRange = &reqRespGetBlobsByRange,
        .getDataColumnByRoot = &reqRespGetDataColumnByRoot,
        .getDataColumnsByRange = &reqRespGetDataColumnsByRange,
        .getForkDigest = &reqRespGetForkDigest,
        .onGoodbye = &reqRespOnGoodbye,
        .onPeerStatus = &reqRespOnPeerStatus,
    };
}

// ---------------------------------------------------------------------------
// Concrete callback implementations.
// Each casts `ptr` to `*RequestContext`, then accesses the node.
// ---------------------------------------------------------------------------

// Import BeaconNode lazily via the beacon_node module to avoid circular deps.
// We only use it for type-safe casts inside the callback bodies.
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

fn reqRespGetStatus(ptr: *anyopaque) StatusMessage.Type {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
    // Delegate to node.getStatus() which uses the FC checkpoint for finalized_root,
    // correctly handling skip slots where slot-based lookup would fail (C2 fix).
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

fn reqRespGetBlockByRoot(ptr: *anyopaque, root: [32]u8) ?[]const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

    const maybe_bytes = node.db.getBlock(root) catch return null;
    const bytes = maybe_bytes orelse return null;
    defer node.allocator.free(bytes);

    const copy = ctx.scratch.alloc(u8, bytes.len) catch return null;
    @memcpy(copy, bytes);
    return copy;
}

fn reqRespGetBlocksByRange(ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

    var results: std.ArrayList([]const u8) = .empty;

    const end_slot = std.math.add(u64, start_slot, count) catch return &.{};
    var slot: u64 = start_slot;
    while (slot < end_slot) : (slot += 1) {
        const root = node.head_tracker.getBlockRoot(slot) orelse continue;
        const maybe_bytes = node.db.getBlock(root) catch continue;
        const bytes = maybe_bytes orelse continue;
        defer node.allocator.free(bytes);

        const copy = ctx.scratch.alloc(u8, bytes.len) catch continue;
        @memcpy(copy, bytes);
        results.append(ctx.scratch, copy) catch continue;
    }

    return results.toOwnedSlice(ctx.scratch) catch &.{};
}

fn reqRespGetBlobByRoot(ptr: *anyopaque, root: [32]u8, index: u64) ?[]const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

    const maybe_bytes = node.db.getBlobSidecars(root) catch return null;
    const bytes = maybe_bytes orelse return null;
    defer node.allocator.free(bytes);

    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;
    const start = index * sidecar_size;
    const end = start + sidecar_size;
    if (end > bytes.len) return null;

    const copy = ctx.scratch.alloc(u8, sidecar_size) catch return null;
    @memcpy(copy, bytes[start..end]);
    return copy;
}

fn reqRespGetDataColumnByRoot(ptr: *anyopaque, root: [32]u8, index: u64) ?[]const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

    const maybe_bytes = node.db.getDataColumn(root, index) catch return null;
    const bytes = maybe_bytes orelse return null;
    defer node.allocator.free(bytes);

    const copy = ctx.scratch.alloc(u8, bytes.len) catch return null;
    @memcpy(copy, bytes);
    return copy;
}

fn reqRespGetDataColumnsByRange(ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

    var results: std.ArrayList([]const u8) = .empty;

    const end_slot = std.math.add(u64, start_slot, count) catch return &.{};
    var slot: u64 = start_slot;
    while (slot < end_slot) : (slot += 1) {
        const root = node.head_tracker.getBlockRoot(slot) orelse continue;
        var col_idx: u64 = 0;
        while (col_idx < 128) : (col_idx += 1) {
            const maybe_bytes = node.db.getDataColumn(root, col_idx) catch continue;
            const bytes = maybe_bytes orelse continue;
            defer node.allocator.free(bytes);

            const copy = ctx.scratch.alloc(u8, bytes.len) catch continue;
            @memcpy(copy, bytes);
            results.append(ctx.scratch, copy) catch continue;
        }
    }

    return results.toOwnedSlice(ctx.scratch) catch &.{};
}

fn reqRespGetBlobsByRange(ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

    var results: std.ArrayList([]const u8) = .empty;
    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;

    const end_slot = std.math.add(u64, start_slot, count) catch return &.{};
    var slot: u64 = start_slot;
    while (slot < end_slot) : (slot += 1) {
        const root = node.head_tracker.getBlockRoot(slot) orelse continue;
        const maybe_bytes = node.db.getBlobSidecars(root) catch continue;
        const bytes = maybe_bytes orelse continue;
        defer node.allocator.free(bytes);

        var offset: usize = 0;
        while (offset + sidecar_size <= bytes.len) : (offset += sidecar_size) {
            const copy = ctx.scratch.alloc(u8, sidecar_size) catch continue;
            @memcpy(copy, bytes[offset..][0..sidecar_size]);
            results.append(ctx.scratch, copy) catch continue;
        }
    }

    return results.toOwnedSlice(ctx.scratch) catch &.{};
}

fn reqRespGetForkDigest(ptr: *anyopaque, slot: u64) [4]u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
    return node.config.forkDigestAtSlot(slot, node.genesis_validators_root);
}

fn reqRespOnGoodbye(ptr: *anyopaque, reason: u64) void {
    _ = ptr;
    _ = reason;
}

fn reqRespOnPeerStatus(ptr: *anyopaque, status: StatusMessage.Type) void {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
    if (node.sync_service_inst) |sync_svc| {
        sync_svc.onPeerStatus("unknown", status) catch |err| {
            std.log.warn("SyncService.onPeerStatus failed: {}", .{err});
        };
    }
    node.unknown_chain_sync.onPeerConnected("unknown", status.head_root) catch {};
}
