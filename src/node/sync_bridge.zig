//! SyncBridge: bridges sync pipeline callbacks to the P2P transport.
//!
//! The sync state machine (RangeSyncManager) fires callbacks synchronously,
//! but P2P operations require cooperative I/O. `SyncCallbackCtx` queues
//! batch requests so the main loop can drain them via actual network calls.

const std = @import("std");
const sync_mod = @import("sync");
const SyncServiceCallbacks = sync_mod.SyncServiceCallbacks;
const BatchBlock = sync_mod.BatchBlock;

const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

pub const PendingBatchRequest = struct {
    batch_id: u32,
    start_slot: u64,
    count: u64,
    peer_id_buf: [128]u8,
    peer_id_len: u8,

    pub fn peerId(self: *const PendingBatchRequest) []const u8 {
        return self.peer_id_buf[0..self.peer_id_len];
    }
};

pub const SyncCallbackCtx = struct {
    /// Typed reference to the beacon node. The circular dependency is resolved
    /// by the lazy import of BeaconNode at the bottom of this file.
    node: *BeaconNode,

    /// Pending batch requests queued by the sync state machine.
    /// Drained by processSyncBatches() in the main loop.
    pending_requests: [32]PendingBatchRequest = undefined,
    pending_count: u8 = 0,

    /// Create a SyncServiceCallbacks that bridges to this context.
    pub fn syncServiceCallbacks(self: *SyncCallbackCtx) SyncServiceCallbacks {
        return .{
            .ptr = @ptrCast(self),
            .importBlockFn = &syncImportBlock,
            .requestBlocksByRangeFn = &syncRequestBlocksByRange,
            .requestBlockByRootFn = &syncRequestBlockByRoot,
            .reportPeerFn = &syncReportPeer,
            .getConnectedPeersFn = &syncGetConnectedPeers,
            .setGossipEnabledFn = &syncSetGossipEnabled,
        };
    }

    fn syncImportBlock(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node = ctx.node;
        const allocator = node.allocator;

        const fork_seq = node.config.forkSeq(node.head_tracker.head_slot);

        const any_signed = AnySignedBeaconBlock.deserialize(
            allocator, .full, fork_seq, block_bytes,
        ) catch |err| {
            std.log.warn("SyncCallbackCtx: block deserialize error: {}", .{err});
            return err;
        };
        defer any_signed.deinit(allocator);

        const result = node.importBlock(any_signed, .range_sync) catch |err| {
            if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
                std.log.warn("SyncCallbackCtx: import error: {}", .{err});
            }
            return err;
        };
        std.log.info("SyncCallbackCtx: imported slot={d}", .{result.slot});
    }

    fn syncRequestBlocksByRange(
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: u32,
        generation: u32,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) void {
        _ = chain_id;
        _ = generation;
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        if (ctx.pending_count >= 32) {
            std.log.warn("SyncCallbackCtx: pending request queue full, dropping batch {d}", .{batch_id});
            return;
        }
        var req = PendingBatchRequest{
            .batch_id = batch_id,
            .start_slot = start_slot,
            .count = count,
            .peer_id_buf = undefined,
            .peer_id_len = @intCast(@min(peer_id.len, 128)),
        };
        @memcpy(req.peer_id_buf[0..req.peer_id_len], peer_id[0..req.peer_id_len]);
        ctx.pending_requests[ctx.pending_count] = req;
        ctx.pending_count += 1;
        std.log.debug("SyncCallbackCtx: queued batch {d} slots {d}..{d} for peer {s}", .{
            batch_id, start_slot, start_slot + count - 1, peer_id,
        });
    }

    fn syncRequestBlockByRoot(_: *anyopaque, _: [32]u8, _: []const u8) void {
        // TODO: implement block-by-root request via P2P
    }

    fn syncReportPeer(_: *anyopaque, _: []const u8) void {
        // TODO: integrate with networking peer scoring
    }

    fn syncGetConnectedPeers(_: *anyopaque) []const []const u8 {
        // TODO: return connected peer IDs from networking PeerManager
        return &.{};
    }

    fn syncSetGossipEnabled(_: *anyopaque, enabled: bool) void {
        std.log.info("Gossip {s}", .{if (enabled) "enabled" else "disabled"});
    }
};

// BeaconNode is imported at the bottom to avoid circular dependency:
// beacon_node.zig imports sync_bridge.zig; sync_bridge.zig needs BeaconNode.
// Using a forward-reference struct pointer is not yet idiomatic in Zig, so
// we resolve it lazily via the bottom-of-file import.
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
