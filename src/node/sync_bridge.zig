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
    chain_id: u32,
    batch_id: u32,
    generation: u32,
    start_slot: u64,
    count: u64,
    peer_id_buf: [128]u8,
    peer_id_len: u8,

    pub fn peerId(self: *const PendingBatchRequest) []const u8 {
        return self.peer_id_buf[0..self.peer_id_len];
    }
};

pub const PendingByRootRequest = struct {
    root: [32]u8,
    peer_id_buf: [128]u8,
    peer_id_len: u8,

    pub fn peerId(self: *const PendingByRootRequest) []const u8 {
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
    pending_head: u8 = 0,
    pending_count: u8 = 0,

    /// Pending by-root requests queued by unknown block sync.
    /// Drained by processSyncBatches() in the main loop.
    pending_by_root_requests: [32]PendingByRootRequest = undefined,
    pending_by_root_head: u8 = 0,
    pending_by_root_count: u8 = 0,

    /// Scratch buffer for connected peer IDs (avoids allocation in hot path).
    peer_id_scratch: [64][]const u8 = undefined,

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

        const fork_seq = node.config.forkSeq(node.currentHeadSlot());

        const any_signed = AnySignedBeaconBlock.deserialize(
            allocator,
            .full,
            fork_seq,
            block_bytes,
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
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        if (ctx.pending_count >= 32) {
            std.log.warn("SyncCallbackCtx: pending request queue full, dropping batch {d}", .{batch_id});
            return;
        }
        var req = PendingBatchRequest{
            .chain_id = chain_id,
            .batch_id = batch_id,
            .generation = generation,
            .start_slot = start_slot,
            .count = count,
            .peer_id_buf = undefined,
            .peer_id_len = @intCast(@min(peer_id.len, 128)),
        };
        @memcpy(req.peer_id_buf[0..req.peer_id_len], peer_id[0..req.peer_id_len]);
        const write_index = (ctx.pending_head + ctx.pending_count) % ctx.pending_requests.len;
        ctx.pending_requests[write_index] = req;
        ctx.pending_count += 1;
        std.log.debug("SyncCallbackCtx: queued chain {d} batch {d}/gen {d} slots {d}..{d} for peer {s}", .{
            chain_id, batch_id, generation, start_slot, start_slot + count - 1, peer_id,
        });
    }

    fn syncRequestBlockByRoot(ptr: *anyopaque, root: [32]u8, peer_id: []const u8) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        if (ctx.pending_by_root_count >= 32) {
            std.log.warn("SyncCallbackCtx: by-root queue full, dropping root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                root[0], root[1], root[2], root[3],
            });
            return;
        }
        var req = PendingByRootRequest{
            .root = root,
            .peer_id_buf = undefined,
            .peer_id_len = @intCast(@min(peer_id.len, 128)),
        };
        @memcpy(req.peer_id_buf[0..req.peer_id_len], peer_id[0..req.peer_id_len]);
        const write_index = (ctx.pending_by_root_head + ctx.pending_by_root_count) % ctx.pending_by_root_requests.len;
        ctx.pending_by_root_requests[write_index] = req;
        ctx.pending_by_root_count += 1;
        std.log.debug("SyncCallbackCtx: queued by-root {x:0>2}{x:0>2}{x:0>2}{x:0>2}... for peer {s}", .{
            root[0], root[1], root[2], root[3], peer_id,
        });
    }

    pub fn popPendingRequest(self: *SyncCallbackCtx) ?PendingBatchRequest {
        if (self.pending_count == 0) return null;
        const req = self.pending_requests[self.pending_head];
        self.pending_head = @intCast((self.pending_head + 1) % self.pending_requests.len);
        self.pending_count -= 1;
        return req;
    }

    pub fn popPendingByRootRequest(self: *SyncCallbackCtx) ?PendingByRootRequest {
        if (self.pending_by_root_count == 0) return null;
        const req = self.pending_by_root_requests[self.pending_by_root_head];
        self.pending_by_root_head = @intCast((self.pending_by_root_head + 1) % self.pending_by_root_requests.len);
        self.pending_by_root_count -= 1;
        return req;
    }

    fn syncReportPeer(ptr: *anyopaque, peer_id: []const u8) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
        const pm = node.peer_manager orelse return;
        const now_ms = blk: {
            const ms = std.Io.Timestamp.now(node.io, .real).toMilliseconds();
            break :blk if (ms >= 0) @as(u64, @intCast(ms)) else 0;
        };
        _ = pm.reportPeer(peer_id, .mid_tolerance, .sync, now_ms);
        std.log.debug("SyncCallbackCtx: reported peer {s} for sync misbehavior", .{peer_id});
    }

    fn syncGetConnectedPeers(ptr: *anyopaque) []const []const u8 {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
        const pm = node.peer_manager orelse return &.{};
        // getBestPeers may fail (OOM); on failure return empty slice.
        const peers = pm.getBestPeers(64) catch return &.{};
        // Extract peer_id strings into the pre-allocated peer_id_scratch buffer.
        const n = @min(peers.len, ctx.peer_id_scratch.len);
        for (peers[0..n], 0..) |cp, i| {
            ctx.peer_id_scratch[i] = cp.peer_id;
        }
        node.allocator.free(peers);
        return ctx.peer_id_scratch[0..n];
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
