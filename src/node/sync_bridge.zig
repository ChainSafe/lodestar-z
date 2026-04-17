//! SyncBridge: bridges sync pipeline callbacks to the P2P transport.
//!
//! The sync state machine fires callbacks synchronously, but P2P operations
//! require cooperative I/O. `SyncCallbackCtx` queues sync/network work so the
//! main loop can drain it via the real node-owned transport path.

const std = @import("std");
const scoped_log = std.log.scoped(.sync_bridge);
const Allocator = std.mem.Allocator;
const chain_mod = @import("chain");
const networking = @import("networking");
const sync_mod = @import("sync");
const SyncServiceCallbacks = sync_mod.SyncServiceCallbacks;
const BatchBlock = sync_mod.BatchBlock;
const MinimalHeader = sync_mod.MinimalHeader;
const SyncPeerReportReason = sync_mod.SyncPeerReportReason;
const UnknownChainCallbacks = sync_mod.unknown_chain.Callbacks;
const UnknownChainForkChoiceQuery = sync_mod.unknown_chain.ForkChoiceQuery;
const PeerSet = sync_mod.unknown_chain.PeerSet;
const PeerEntry = PeerSet.PeerEntry;

pub const PendingByRootRequestKind = enum {
    unknown_block_parent,
    unknown_block_gossip,
    unknown_chain_header,
};

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
    kind: PendingByRootRequestKind,
    root: [32]u8,
    peer_id_buf: [128]u8,
    peer_id_len: u8,

    pub fn peerId(self: *const PendingByRootRequest) []const u8 {
        return self.peer_id_buf[0..self.peer_id_len];
    }
};

pub const PendingPeerStatusRefresh = struct {
    peer_id_buf: [128]u8,
    peer_id_len: u8,

    pub fn peerId(self: *const PendingPeerStatusRefresh) []const u8 {
        return self.peer_id_buf[0..self.peer_id_len];
    }
};

pub const PendingLinkedChainImport = struct {
    linking_root: [32]u8,
    headers: []MinimalHeader,
    peers: []PeerEntry,

    pub fn deinit(self: *PendingLinkedChainImport, allocator: Allocator) void {
        allocator.free(self.headers);
        allocator.free(self.peers);
        self.* = undefined;
    }

    pub fn peerIds(
        self: *const PendingLinkedChainImport,
        scratch: *[64][]const u8,
    ) []const []const u8 {
        const n = @min(self.peers.len, scratch.len);
        for (self.peers[0..n], 0..) |peer, i| {
            scratch[i] = peer.id();
        }
        return scratch[0..n];
    }
};

pub const SyncCallbackCtx = struct {
    /// Typed reference to the beacon node. The circular dependency is resolved
    /// by the lazy import of BeaconNode at the bottom of this file.
    node: *BeaconNode,

    /// Pending batch requests queued by the sync state machine.
    pending_requests: [32]PendingBatchRequest = undefined,
    pending_head: u8 = 0,
    pending_count: u8 = 0,

    /// Pending by-root requests queued by unknown block / unknown chain sync.
    pending_by_root_requests: [64]PendingByRootRequest = undefined,
    pending_by_root_head: u8 = 0,
    pending_by_root_count: u8 = 0,

    /// Pending linked unknown-chain imports, stored in forward order.
    pending_linked_chains: [16]PendingLinkedChainImport = undefined,
    pending_linked_head: u8 = 0,
    pending_linked_count: u8 = 0,

    /// Pending targeted STATUS refreshes requested by sync.
    pending_restatus: [64]PendingPeerStatusRefresh = undefined,
    pending_restatus_head: u8 = 0,
    pending_restatus_count: u8 = 0,

    /// Pending sync-driven gossip-core subscription state change.
    pending_gossip_enabled: ?bool = null,

    /// Fallback connected-peer registry for non-P2P runtimes such as sim tests.
    connected_peers: PeerSet = .empty,

    /// Scratch buffer for connected peer IDs (avoids allocation in hot path).
    peer_id_scratch: [64][]const u8 = undefined,

    pub fn deinit(self: *SyncCallbackCtx, allocator: Allocator) void {
        while (self.popPendingLinkedChain()) |pending| {
            var owned = pending;
            owned.deinit(allocator);
        }
        self.connected_peers.deinit(allocator);
        self.* = undefined;
    }

    pub fn notePeerConnected(self: *SyncCallbackCtx, peer_id: []const u8) void {
        _ = self.connected_peers.add(self.node.allocator, peer_id) catch {};
    }

    pub fn notePeerDisconnected(self: *SyncCallbackCtx, peer_id: []const u8) void {
        _ = self.connected_peers.remove(peer_id);
    }

    /// Create UnknownBlockSync callbacks that reuse the node-owned import path.
    pub fn unknownBlockCallbacks(self: *SyncCallbackCtx) sync_mod.UnknownBlockCallbacks {
        return .{
            .ptr = @ptrCast(self),
            .requestBlockByRootFn = &syncRequestBlockByRootUnknownBlock,
            .importBlockFn = &syncImportPreparedBlock,
            .hasBlockFn = &unknownBlockHasBlock,
            .getConnectedPeersFn = &syncGetConnectedPeers,
        };
    }

    pub fn unknownChainCallbacks(self: *SyncCallbackCtx) UnknownChainCallbacks {
        return .{
            .ptr = @ptrCast(self),
            .fetchBlockByRootFn = &unknownChainFetchBlockByRoot,
            .processLinkedChainFn = &unknownChainProcessLinkedChain,
        };
    }

    pub fn unknownChainForkChoiceQuery(self: *SyncCallbackCtx) UnknownChainForkChoiceQuery {
        return .{
            .ptr = @ptrCast(self),
            .hasBlockFn = &unknownChainHasBlock,
        };
    }

    /// Create a SyncServiceCallbacks that bridges to this context.
    pub fn syncServiceCallbacks(self: *SyncCallbackCtx) SyncServiceCallbacks {
        return .{
            .ptr = @ptrCast(self),
            .importBlockFn = &syncImportBlock,
            .importPreparedBlockFn = &syncImportPreparedBlock,
            .processChainSegmentFn = &syncProcessChainSegment,
            .requestBlocksByRangeFn = &syncRequestBlocksByRange,
            .requestBlockByRootFn = &syncRequestBlockByRootUnknownBlock,
            .reportPeerFn = &syncReportPeer,
            .hasBlockFn = &syncHasBlock,
            .peerCanServeRangeFn = &syncPeerCanServeRange,
            .getConnectedPeersFn = &syncGetConnectedPeers,
            .reStatusPeersFn = &syncReStatusPeers,
            .setGossipEnabledFn = &syncSetGossipEnabled,
        };
    }

    fn syncImportBlock(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node = ctx.node;

        const result = node.ingestRawBlockBytes(block_bytes, .unknown_block_sync) catch |err| {
            if (err != error.AlreadyKnown and err != error.WouldRevertFinalizedSlot) {
                scoped_log.debug("sync callback import error: {}", .{err});
            }
            return err;
        };
        switch (result) {
            .ignored => {},
            .queued => return error.ImportPending,
            .imported => |imported| {
                scoped_log.debug("SyncCallbackCtx: imported slot={d}", .{imported.slot});
            },
        }
    }

    fn syncImportPreparedBlock(ptr: *anyopaque, prepared: chain_mod.PreparedBlockInput) anyerror!void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node = ctx.node;

        const result = node.importPreparedBlock(prepared) catch |err| {
            if (err != error.AlreadyKnown and err != error.WouldRevertFinalizedSlot) {
                scoped_log.debug("sync prepared import error: {}", .{err});
            }
            return err;
        };
        switch (result) {
            .ignored => {},
            .pending => return error.ImportPending,
            .imported => |imported| {
                scoped_log.debug("SyncCallbackCtx: imported prepared slot={d}", .{imported.slot});
            },
        }
    }

    fn syncProcessChainSegment(
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: u32,
        generation: u32,
        blocks: []const BatchBlock,
        sync_type: sync_mod.RangeSyncType,
    ) anyerror!void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node = ctx.node;

        try node.enqueueSyncSegment(chain_id, batch_id, generation, blocks, sync_type);
        scoped_log.debug("SyncCallbackCtx: queued {d} {s} blocks for chain {d} batch {d}/gen {d}", .{
            blocks.len,
            @tagName(sync_type),
            chain_id,
            batch_id,
            generation,
        });
        return error.ProcessingPending;
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
        if (ctx.pending_count >= ctx.pending_requests.len) {
            scoped_log.warn("sync callback pending request queue full, dropping batch {d}", .{batch_id});
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
        scoped_log.debug("SyncCallbackCtx: queued chain {d} batch {d}/gen {d} slots {d}..{d} for peer {s}", .{
            chain_id, batch_id, generation, start_slot, start_slot + count - 1, peer_id,
        });
    }

    fn syncRequestBlockByRootUnknownBlock(ptr: *anyopaque, root: [32]u8, peer_id: []const u8) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        ctx.enqueueByRootRequest(.unknown_block_parent, root, peer_id);
    }

    pub fn enqueueUnknownBlockGossipRequestFn(ptr: *anyopaque, root: [32]u8, peer_id: []const u8) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        ctx.enqueueByRootRequest(.unknown_block_gossip, root, peer_id);
    }

    fn unknownBlockHasBlock(ptr: *anyopaque, root: [32]u8) bool {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        return ctx.node.chainQuery().isKnownBlockRoot(root);
    }

    fn unknownChainFetchBlockByRoot(ptr: *anyopaque, root: [32]u8, peer_id: []const u8) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        ctx.enqueueByRootRequest(.unknown_chain_header, root, peer_id);
    }

    fn unknownChainProcessLinkedChain(
        ptr: *anyopaque,
        linking_root: [32]u8,
        headers: []const MinimalHeader,
        peers: *const PeerSet,
    ) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        if (ctx.pending_linked_count >= ctx.pending_linked_chains.len) {
            scoped_log.warn("SyncCallbackCtx: linked-chain queue full, dropping chain of {d} headers", .{headers.len});
            return;
        }

        const allocator = ctx.node.allocator;
        const headers_copy = allocator.dupe(MinimalHeader, headers) catch {
            scoped_log.warn("SyncCallbackCtx: failed to copy linked chain headers", .{});
            return;
        };
        errdefer allocator.free(headers_copy);

        const peers_copy = allocator.dupe(PeerEntry, peers.peers.items) catch {
            allocator.free(headers_copy);
            scoped_log.warn("SyncCallbackCtx: failed to copy linked chain peers", .{});
            return;
        };

        const write_index = (ctx.pending_linked_head + ctx.pending_linked_count) % ctx.pending_linked_chains.len;
        ctx.pending_linked_chains[write_index] = .{
            .linking_root = linking_root,
            .headers = headers_copy,
            .peers = peers_copy,
        };
        ctx.pending_linked_count += 1;
    }

    fn unknownChainHasBlock(ptr: *anyopaque, root: [32]u8) bool {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const maybe_bytes = ctx.node.chainQuery().blockBytesByRoot(root) catch return false;
        if (maybe_bytes) |bytes| {
            ctx.node.allocator.free(bytes);
            return true;
        }
        return false;
    }

    fn enqueueByRootRequest(
        self: *SyncCallbackCtx,
        kind: PendingByRootRequestKind,
        root: [32]u8,
        peer_id: []const u8,
    ) void {
        if (self.pending_by_root_count >= self.pending_by_root_requests.len) {
            scoped_log.warn("sync callback by-root queue full, dropping root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                root[0], root[1], root[2], root[3],
            });
            return;
        }
        var req = PendingByRootRequest{
            .kind = kind,
            .root = root,
            .peer_id_buf = undefined,
            .peer_id_len = @intCast(@min(peer_id.len, 128)),
        };
        @memcpy(req.peer_id_buf[0..req.peer_id_len], peer_id[0..req.peer_id_len]);
        const write_index = (self.pending_by_root_head + self.pending_by_root_count) % self.pending_by_root_requests.len;
        self.pending_by_root_requests[write_index] = req;
        self.pending_by_root_count += 1;
        scoped_log.debug("SyncCallbackCtx: queued {s} by-root {x:0>2}{x:0>2}{x:0>2}{x:0>2}... for peer {s}", .{
            @tagName(kind), root[0], root[1], root[2], root[3], peer_id,
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

    pub fn popPendingLinkedChain(self: *SyncCallbackCtx) ?PendingLinkedChainImport {
        if (self.pending_linked_count == 0) return null;
        const pending = self.pending_linked_chains[self.pending_linked_head];
        self.pending_linked_head = @intCast((self.pending_linked_head + 1) % self.pending_linked_chains.len);
        self.pending_linked_count -= 1;
        return pending;
    }

    pub fn popPendingReStatus(self: *SyncCallbackCtx) ?PendingPeerStatusRefresh {
        if (self.pending_restatus_count == 0) return null;
        const pending = self.pending_restatus[self.pending_restatus_head];
        self.pending_restatus_head = @intCast((self.pending_restatus_head + 1) % self.pending_restatus.len);
        self.pending_restatus_count -= 1;
        return pending;
    }

    pub fn connectedPeerIds(self: *SyncCallbackCtx) []const []const u8 {
        return syncGetConnectedPeers(@ptrCast(self));
    }

    pub fn connectedPeerIdsFn(ptr: *anyopaque) []const []const u8 {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        return ctx.connectedPeerIds();
    }

    pub fn takePendingGossipEnabled(self: *SyncCallbackCtx) ?bool {
        const enabled = self.pending_gossip_enabled;
        self.pending_gossip_enabled = null;
        return enabled;
    }

    fn syncReportPeer(ptr: *anyopaque, peer_id: []const u8, reason: SyncPeerReportReason) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
        const pm = node.peer_manager orelse return;
        const now_ms = blk: {
            const ms = std.Io.Timestamp.now(node.io, .real).toMilliseconds();
            break :blk if (ms >= 0) @as(u64, @intCast(ms)) else 0;
        };
        const action: networking.PeerAction = switch (reason) {
            .download_error => .mid_tolerance,
            .processing_exhausted => .low_tolerance,
        };
        _ = pm.reportPeer(peer_id, action, .sync, now_ms);
        scoped_log.debug("SyncCallbackCtx: reported peer {s} for sync reason={s} action={s}", .{
            peer_id,
            @tagName(reason),
            @tagName(action),
        });
    }

    fn syncHasBlock(ptr: *anyopaque, root: [32]u8) bool {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
        return node.chain.hasCanonicalBlock(root);
    }

    fn syncGetConnectedPeers(ptr: *anyopaque) []const []const u8 {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));
        if (node.peer_manager) |pm| {
            if (pm.getConnectedPeers()) |peers| {
                defer node.allocator.free(peers);
                const n = @min(peers.len, ctx.peer_id_scratch.len);
                for (peers[0..n], 0..) |cp, i| {
                    ctx.peer_id_scratch[i] = cp.peer_id;
                }
                return ctx.peer_id_scratch[0..n];
            } else |_| {
                // Fall through to the bridge-local set if PeerManager cannot allocate.
            }
        }

        const n = @min(ctx.connected_peers.peers.items.len, ctx.peer_id_scratch.len);
        for (ctx.connected_peers.peers.items[0..n], 0..) |peer, i| {
            ctx.peer_id_scratch[i] = peer.id();
        }
        return ctx.peer_id_scratch[0..n];
    }

    fn syncPeerCanServeRange(
        ptr: *anyopaque,
        peer_id: []const u8,
        start_slot: u64,
        _: u64,
    ) bool {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node: *BeaconNode = @ptrCast(@alignCast(ctx.node));

        if (!node.config.forkSeq(start_slot).gte(.fulu)) return true;
        if (node.chain_runtime.custody_columns.len == 0) return true;

        const pm = node.peer_manager orelse return false;
        const peer = pm.getPeer(peer_id) orelse return false;
        if (peer.connection_state != .connected) return false;

        const peer_columns = peer.custody_columns orelse return false;

        for (node.chain_runtime.custody_columns) |column_index| {
            if (networking.custody.isCustodied(column_index, peer_columns)) return true;
        }
        return false;
    }

    fn syncReStatusPeers(ptr: *anyopaque, peer_ids: []const []const u8) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        for (peer_ids) |peer_id| {
            ctx.enqueuePeerStatusRefresh(peer_id);
        }
    }

    fn syncSetGossipEnabled(ptr: *anyopaque, enabled: bool) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        ctx.pending_gossip_enabled = enabled;
        scoped_log.info("gossip {s}", .{if (enabled) "enabled" else "disabled"});
    }

    fn enqueuePeerStatusRefresh(self: *SyncCallbackCtx, peer_id: []const u8) void {
        for (0..@as(usize, self.pending_restatus_count)) |offset| {
            const index = (@as(usize, self.pending_restatus_head) + offset) % self.pending_restatus.len;
            if (std.mem.eql(u8, self.pending_restatus[index].peerId(), peer_id)) return;
        }

        if (self.pending_restatus_count >= self.pending_restatus.len) {
            scoped_log.warn("sync callback restatus queue full, dropping peer {s}", .{peer_id});
            return;
        }

        var pending = PendingPeerStatusRefresh{
            .peer_id_buf = undefined,
            .peer_id_len = @intCast(@min(peer_id.len, 128)),
        };
        @memcpy(pending.peer_id_buf[0..pending.peer_id_len], peer_id[0..pending.peer_id_len]);

        const write_index = (@as(usize, self.pending_restatus_head) + @as(usize, self.pending_restatus_count)) % self.pending_restatus.len;
        self.pending_restatus[write_index] = pending;
        self.pending_restatus_count += 1;
        scoped_log.debug("SyncCallbackCtx: queued peer STATUS refresh for {s}", .{peer_id});
    }
};

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
