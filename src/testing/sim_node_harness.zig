//! SimNodeHarness: test harness wrapping BeaconNode with deterministic I/O.
//!
//! A "sim node" is just a BeaconNode driven by deterministic block generation
//! and invariant checking. This harness replaces SimBeaconNode by delegating
//! all state management to BeaconNode (which owns the STFN pipeline) and only
//! adding the test-specific concerns: block generation, invariant checking, and
//! simulated time.
//!
//! Usage:
//!   1. Create a bootstrapped BeaconNode.
//!   2. Create a SimNodeHarness wrapping the node.
//!   3. Call processSlot() / processSlots() / processWithScenario().
//!   4. Inspect stats and checker for correctness.

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");
const chain_mod = @import("chain");
const networking = @import("networking");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const BlockSource = chain_mod.BlockSource;
const BeaconBlocksByRangeRequest = networking.messages.BeaconBlocksByRangeRequest;
const StatusMessage = networking.messages.StatusMessage;
const freeResponseChunks = networking.freeResponseChunks;

const node_mod = @import("node");
const BeaconNode = node_mod.BeaconNode;
const SyncServicePtr = @typeInfo(@FieldType(BeaconNode, "sync_service_inst")).optional.child;
const BatchBlock = @typeInfo(@typeInfo(@TypeOf(BeaconNode.enqueueSyncSegment)).@"fn".params[4].type.?).pointer.child;
const reqresp_callbacks = node_mod.reqresp_callbacks_mod;
const BlockGenerator = @import("block_generator.zig").BlockGenerator;
const InvariantChecker = @import("invariant_checker.zig").InvariantChecker;
const SimIo = @import("sim_io.zig").SimIo;
const SlotClock = @import("sim_clock.zig").SlotClock;

pub const SlotResult = struct {
    slot: u64,
    block_processed: bool,
    epoch_transition: bool,
    state_root: [32]u8,
};

pub const ProducedBlockBytes = struct {
    slot: u64,
    epoch_transition: bool,
    bytes: []u8,
};

pub const SyncPeer = struct {
    peer_id: []const u8,
    node: *BeaconNode,
};

pub const Scenario = struct {
    /// Total slots to simulate.
    num_slots: u64,
    /// Probability of skipping a slot (0.0 - 1.0).
    skip_slot_rate: f64 = 0.0,
};

pub const SimNodeHarness = struct {
    allocator: Allocator,
    node: *BeaconNode,
    block_gen: BlockGenerator,
    checker: InvariantChecker,
    sim_io: SimIo,
    clock: SlotClock,

    // Stats
    slots_processed: u64 = 0,
    blocks_processed: u64 = 0,
    epochs_processed: u64 = 0,
    skip_prng: std.Random.DefaultPrng,
    /// Fraction of validators producing attestations [0.0 - 1.0].
    participation_rate: f64 = 0.0,

    /// Initialize a harness wrapping an already-initialized BeaconNode.
    ///
    /// The node must already be bootstrapped so that the clock and head state
    /// are set up. The seed controls block generation and skip-slot randomness.
    pub fn init(
        allocator: Allocator,
        node: *BeaconNode,
        seed: u64,
    ) SimNodeHarness {
        // Extract genesis_time_s and seconds_per_slot from the node's production
        // clock (node.SlotClock) and construct a sim_clock.SlotClock from them.
        // The two SlotClock types are structurally identical but distinct types
        // in Zig's type system because they live in different modules.
        const genesis_time_s: u64 = if (node.clock) |c| c.genesis_time_s else 0;
        const seconds_per_slot: u64 = if (node.clock) |c| c.seconds_per_slot else 12;
        const clk = SlotClock{
            .genesis_time_s = genesis_time_s,
            .seconds_per_slot = seconds_per_slot,
        };
        return .{
            .allocator = allocator,
            .node = node,
            .block_gen = BlockGenerator.init(allocator, seed +% 2),
            .checker = InvariantChecker.init(allocator),
            .sim_io = .{
                .prng = std.Random.DefaultPrng.init(seed),
                .monotonic_ns = genesis_time_s * std.time.ns_per_s,
                .realtime_ns = @as(i128, genesis_time_s) * std.time.ns_per_s,
            },
            .clock = clk,
            .skip_prng = std.Random.DefaultPrng.init(seed +% 3),
        };
    }

    pub fn deinit(self: *SimNodeHarness) void {
        self.checker.deinit();
    }

    /// Get the current head state from the node's chain query surface.
    /// Returns null if not found (shouldn't happen after initFromGenesis).
    pub fn getHeadState(self: *SimNodeHarness) ?*CachedBeaconState {
        return self.node.headState();
    }

    pub fn waitForNodeIdle(self: *SimNodeHarness) !void {
        switch (self.node.waitForAsyncIdle()) {
            .idle => {},
            .shutdown => return error.NodeShutdown,
        }
    }

    pub fn getHeadStateIdle(self: *SimNodeHarness) !*CachedBeaconState {
        try self.waitForNodeIdle();
        return self.getHeadState() orelse error.NoHeadState;
    }

    pub fn cloneHeadStateSnapshot(self: *SimNodeHarness) !*CachedBeaconState {
        var state_graph_lease = self.node.chainService().acquireStateGraphLease();
        defer state_graph_lease.release();
        const head_state = self.getHeadState() orelse return error.NoHeadState;
        return head_state.clone(self.allocator, .{ .transfer_cache = false });
    }

    pub fn currentSlot(self: *SimNodeHarness) !u64 {
        return self.node.currentHeadSlot();
    }

    pub fn simNowMs(self: *const SimNodeHarness) u64 {
        return self.sim_io.monotonic_ns / std.time.ns_per_ms;
    }

    pub fn advanceClockToSlot(self: *SimNodeHarness, target_slot: u64) void {
        self.sim_io.advanceToSlot(
            target_slot,
            self.clock.genesis_time_s,
            self.clock.seconds_per_slot,
        );
    }

    pub fn produceNextSlotBlockBytes(self: *SimNodeHarness) !ProducedBlockBytes {
        var post_state = try self.cloneHeadStateSnapshot();
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        const current_slot = try post_state.state.slot();
        const target_slot = current_slot + 1;
        const current_epoch = computeEpochAtSlot(current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);

        try state_transition.processSlots(
            self.allocator,
            post_state,
            target_slot,
            .{},
        );
        try post_state.state.commit();

        const signed_block = try self.block_gen.generateBlockWithOpts(post_state, target_slot, .{
            .participation_rate = self.participation_rate,
        });
        var any_signed = fork_types.AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        errdefer any_signed.deinit(self.allocator);

        const block_bytes = try any_signed.serialize(self.allocator);
        any_signed.deinit(self.allocator);

        post_state.deinit();
        self.allocator.destroy(post_state);

        return .{
            .slot = target_slot,
            .epoch_transition = target_epoch != current_epoch,
            .bytes = block_bytes,
        };
    }

    pub fn importExternalBlockBytes(
        self: *SimNodeHarness,
        block_bytes: []const u8,
        source: BlockSource,
    ) !bool {
        const ingress_result = try self.node.ingestRawBlockBytesTracked(block_bytes, source);
        switch (ingress_result) {
            .ignored => return false,
            .imported => return true,
            .queued => |ticket| {
                return switch (self.node.waitForTrackedBlockIngress(ticket)) {
                    .completed => |completion| switch (completion) {
                        .ignored => false,
                        .failed => |err| err,
                        .imported => true,
                    },
                    .shutdown => error.ImportShutdown,
                    .lost => error.ImportLost,
                };
            },
        }
    }

    pub fn syncBlocksByRangeFromPeer(
        self: *SimNodeHarness,
        peer: *BeaconNode,
        start_slot: u64,
        target_slot: u64,
    ) !u64 {
        if (target_slot < start_slot) return 0;

        const blocks = try fetchBlocksByRangeReqResp(
            self.allocator,
            peer,
            start_slot,
            target_slot - start_slot + 1,
        );
        defer {
            for (blocks) |blk| self.allocator.free(blk.block_bytes);
            self.allocator.free(blocks);
        }

        if (blocks.len == 0) return 0;

        const raw_blocks = try self.allocator.alloc(chain_mod.RawBlockBytes, blocks.len);
        defer self.allocator.free(raw_blocks);

        for (blocks, 0..) |blk, i| {
            raw_blocks[i] = .{
                .slot = blk.slot,
                .bytes = blk.block_bytes,
            };
        }

        try self.node.processRangeSyncSegment(raw_blocks);
        return @intCast(blocks.len);
    }

    pub fn connectPeer(self: *SimNodeHarness, peer: SyncPeer) !void {
        const our_status = self.node.getStatus();
        var request_bytes: [StatusMessage.fixed_size]u8 = undefined;
        _ = StatusMessage.serializeIntoBytes(&our_status, &request_bytes);

        const chunks = try peer.node.onReqResp(.status, &request_bytes);
        defer freeResponseChunks(peer.node.allocator, chunks);

        if (chunks.len != 1) return error.UnexpectedReqRespChunkCount;
        if (chunks[0].result != .success) return error.UnexpectedReqRespResponseCode;

        var peer_status: StatusMessage.Type = undefined;
        try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &peer_status);
        _ = reqresp_callbacks.handlePeerStatusAtTime(self.node, peer.peer_id, peer_status, null, self.simNowMs());
        if (self.node.sync_callback_ctx) |cb_ctx| cb_ctx.notePeerConnected(peer.peer_id);
    }

    pub fn disconnectPeer(self: *SimNodeHarness, peer_id: []const u8) void {
        if (self.node.peer_manager) |pm| {
            pm.onPeerDisconnected(peer_id, self.simNowMs());
        }
        if (self.node.sync_service_inst) |sync_svc| {
            sync_svc.onPeerDisconnect(peer_id);
        }
        if (self.node.sync_callback_ctx) |cb_ctx| cb_ctx.notePeerDisconnected(peer_id);
        if (self.node.unknownChainSyncEnabled()) self.node.unknown_chain_sync.onPeerDisconnected(peer_id);
    }

    pub fn driveSyncWithPeers(self: *SimNodeHarness, peers: []const SyncPeer) !bool {
        if (self.node.sync_service_inst == null) return false;

        var did_work_any = false;
        var iterations: usize = 0;
        while (iterations < 512) : (iterations += 1) {
            var did_work = false;

            did_work = self.node.processPendingExecutionForkchoiceUpdates() or did_work;
            did_work = self.node.processPendingExecutionPayloadVerifications() or did_work;
            did_work = self.node.processPendingBlockStateWork() or did_work;
            did_work = self.node.processPendingGossipBlsBatch() or did_work;

            if (self.node.beacon_processor) |bp| {
                const dispatched = bp.tick(128);
                did_work = dispatched > 0 or did_work;
            }

            if (self.node.sync_service_inst) |sync_svc| {
                try sync_svc.tick();
                self.node.unknown_block_sync.tick();
                if (self.node.unknownChainSyncEnabled()) self.node.unknown_chain_sync.tick();
                did_work = try self.processPendingSyncRequests(peers, sync_svc) or did_work;
                did_work = self.node.drivePendingSyncSegments() or did_work;
                if (self.node.unknownChainSyncEnabled()) self.node.unknown_chain_sync.tick();
                if (self.node.unknownChainSyncEnabled()) {
                    did_work = try self.processPendingLinkedChainImports(peers) or did_work;
                }
            }

            if (did_work) {
                did_work_any = true;
                continue;
            }

            break;
        }

        return did_work_any;
    }

    fn processPendingSyncRequests(
        self: *SimNodeHarness,
        peers: []const SyncPeer,
        sync_svc: SyncServicePtr,
    ) !bool {
        const cb_ctx = self.node.sync_callback_ctx orelse return false;
        var did_work = false;

        while (cb_ctx.popPendingRequest()) |req| {
            did_work = true;
            const peer = findSyncPeer(peers, req.peerId()) orelse {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, req.peerId());
                continue;
            };

            const blocks = fetchBlocksByRangeReqResp(
                self.allocator,
                peer.node,
                req.start_slot,
                req.count,
            ) catch {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, req.peerId());
                continue;
            };
            defer {
                for (blocks) |blk| self.allocator.free(blk.block_bytes);
                self.allocator.free(blocks);
            }

            if (blocks.len == 0) {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, req.peerId());
                continue;
            }

            sync_svc.onBatchResponse(req.chain_id, req.batch_id, req.generation, blocks);
        }

        while (cb_ctx.popPendingByRootRequest()) |req| {
            did_work = true;
            const peer = findSyncPeer(peers, req.peerId()) orelse {
                switch (req.kind) {
                    .unknown_block_parent => self.node.unknown_block_sync.onFetchFailed(req.root, req.peerId()),
                    .unknown_chain_header => {},
                }
                continue;
            };

            const block_bytes = fetchBlockByRootReqResp(self.allocator, peer.node, req.root) catch {
                switch (req.kind) {
                    .unknown_block_parent => self.node.unknown_block_sync.onFetchFailed(req.root, req.peerId()),
                    .unknown_chain_header => {},
                }
                continue;
            };
            defer self.allocator.free(block_bytes);

            switch (req.kind) {
                .unknown_block_parent => {
                    const prepared = self.node.chainService().prepareRawPreparedBlockInput(block_bytes, .unknown_block_sync) catch {
                        self.node.unknown_block_sync.onFetchFailed(req.root, req.peerId());
                        continue;
                    };
                    self.node.unknown_block_sync.onParentFetched(req.root, prepared) catch {
                        self.node.unknown_block_sync.onFetchFailed(req.root, req.peerId());
                    };
                },
                .unknown_chain_header => {
                    if (!self.node.unknownChainSyncEnabled()) continue;
                    const slot = readSignedBlockSlotFromSsz(block_bytes) orelse continue;
                    const parent_root = readSignedBlockParentRootFromSsz(block_bytes) orelse continue;
                    self.node.unknown_chain_sync.onUnknownBlockInput(slot, req.root, parent_root, req.peerId()) catch {};
                },
            }
        }

        return did_work;
    }

    fn processPendingLinkedChainImports(
        self: *SimNodeHarness,
        peers: []const SyncPeer,
    ) !bool {
        const cb_ctx = self.node.sync_callback_ctx orelse return false;
        var did_work = false;

        while (cb_ctx.popPendingLinkedChain()) |pending| {
            var owned = pending;
            defer owned.deinit(self.allocator);
            did_work = true;

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
                const fetched = fetchBlockByRootReqRespFromPeers(self.allocator, peers, peer_ids, header.root) catch {
                    failed = true;
                    break;
                };
                raw_blocks.append(self.allocator, .{
                    .slot = header.slot,
                    .bytes = fetched,
                }) catch |err| {
                    self.allocator.free(fetched);
                    return err;
                };
            }

            if (failed or raw_blocks.items.len != owned.headers.len) continue;

            self.node.processRangeSyncSegment(raw_blocks.items) catch {};
        }

        return did_work;
    }

    pub fn advanceEmptyToSlot(self: *SimNodeHarness, target_slot: u64) !void {
        try self.node.advanceSlot(target_slot);
    }

    fn findSyncPeer(peers: []const SyncPeer, peer_id: []const u8) ?SyncPeer {
        for (peers) |peer| {
            if (std.mem.eql(u8, peer.peer_id, peer_id)) return peer;
        }
        return null;
    }

    fn fetchBlockByRootReqRespFromPeers(
        allocator: std.mem.Allocator,
        peers: []const SyncPeer,
        peer_ids: []const []const u8,
        root: [32]u8,
    ) ![]u8 {
        for (peer_ids) |peer_id| {
            const peer = findSyncPeer(peers, peer_id) orelse continue;
            return fetchBlockByRootReqResp(allocator, peer.node, root) catch continue;
        }
        return error.NoConnectedPeerHasBlock;
    }

    fn fetchBlockByRootReqResp(
        allocator: std.mem.Allocator,
        peer: *BeaconNode,
        root: [32]u8,
    ) ![]u8 {
        var request_bytes: [32]u8 = root;
        const chunks = try peer.onReqResp(.beacon_blocks_by_root, &request_bytes);
        defer freeResponseChunks(peer.allocator, chunks);

        if (chunks.len != 1) return error.UnexpectedReqRespChunkCount;
        if (chunks[0].result != .success) return error.UnexpectedReqRespResponseCode;
        return allocator.dupe(u8, chunks[0].ssz_payload);
    }

    fn fetchBlocksByRangeReqResp(
        allocator: std.mem.Allocator,
        peer: *BeaconNode,
        start_slot: u64,
        count: u64,
    ) ![]BatchBlock {
        const request = BeaconBlocksByRangeRequest.Type{
            .start_slot = start_slot,
            .count = count,
            .step = 1,
        };
        var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
        _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

        const chunks = try peer.onReqResp(.beacon_blocks_by_range, &request_bytes);
        defer freeResponseChunks(peer.allocator, chunks);

        var blocks: std.ArrayListUnmanaged(BatchBlock) = .empty;
        errdefer {
            for (blocks.items) |blk| allocator.free(blk.block_bytes);
            blocks.deinit(allocator);
        }

        for (chunks) |chunk| {
            if (chunk.result != .success) return error.RangeSyncReqRespFailed;
            const slot = readSignedBlockSlotFromSsz(chunk.ssz_payload) orelse return error.InvalidReqRespBlock;
            try blocks.append(allocator, .{
                .slot = slot,
                .block_bytes = try allocator.dupe(u8, chunk.ssz_payload),
            });
        }

        return blocks.toOwnedSlice(allocator);
    }

    fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
        if (block_bytes.len < 108) return null;
        return std.mem.readInt(u64, block_bytes[100..108], .little);
    }

    fn readSignedBlockParentRootFromSsz(block_bytes: []const u8) ?[32]u8 {
        if (block_bytes.len < 140) return null;
        var parent_root: [32]u8 = undefined;
        @memcpy(&parent_root, block_bytes[116..148]);
        return parent_root;
    }

    pub fn observeCurrentHead(
        self: *SimNodeHarness,
        clock_slot: u64,
        block_processed: bool,
    ) !SlotResult {
        const new_head_state = try self.cloneHeadStateSnapshot();
        defer {
            new_head_state.deinit();
            self.allocator.destroy(new_head_state);
        }
        const observed_slot = try new_head_state.state.slot();

        self.sim_io.advanceToSlot(
            clock_slot,
            self.clock.genesis_time_s,
            self.clock.seconds_per_slot,
        );

        try self.checker.checkSlot(new_head_state.state);

        self.slots_processed += 1;
        if (block_processed) self.blocks_processed += 1;

        const previous_epoch = computeEpochAtSlot(clock_slot - 1);
        const current_epoch = computeEpochAtSlot(clock_slot);
        if (current_epoch != previous_epoch) self.epochs_processed += 1;

        const state_root = try new_head_state.state.hashTreeRoot();
        return .{
            .slot = observed_slot,
            .block_processed = block_processed,
            .epoch_transition = current_epoch != previous_epoch,
            .state_root = state_root.*,
        };
    }

    pub fn observeSlot(
        self: *SimNodeHarness,
        target_slot: u64,
        block_processed: bool,
    ) !SlotResult {
        const result = try self.observeCurrentHead(target_slot, block_processed);
        if (result.slot != target_slot) return error.UnexpectedHeadSlot;
        return result;
    }

    /// Advance the simulation by one slot.
    ///
    /// If `skip` is false, a block is generated and imported via the real raw
    /// block ingress path. If `skip` is true, the slot is advanced without a
    /// block via BeaconNode.advanceSlot.
    pub fn processSlot(self: *SimNodeHarness, skip: bool) !SlotResult {
        const current_slot = try self.currentSlot();
        const target_slot = current_slot + 1;

        if (skip) {
            try self.advanceEmptyToSlot(target_slot);
            return self.observeSlot(target_slot, false);
        }

        const produced = try self.produceNextSlotBlockBytes();
        defer self.allocator.free(produced.bytes);

        const imported = try self.importExternalBlockBytes(produced.bytes, .api);
        if (!imported) return error.BlockIgnored;

        return self.observeSlot(target_slot, true);
    }

    /// Process `count` consecutive slots. Each slot decides whether to
    /// skip based on skip_rate (0.0 = never skip).
    pub fn processSlots(self: *SimNodeHarness, count: u64, skip_rate: f64) !void {
        for (0..count) |_| {
            const should_skip = if (skip_rate > 0.0) blk: {
                const rand_val: f64 = @as(f64, @floatFromInt(self.skip_prng.random().int(u32))) /
                    @as(f64, @floatFromInt(std.math.maxInt(u32)));
                break :blk rand_val < skip_rate;
            } else false;

            _ = try self.processSlot(should_skip);
        }
    }

    /// Process until the end of the current epoch (triggers epoch transition).
    pub fn processToEpochBoundary(self: *SimNodeHarness) !void {
        const current_slot = try self.currentSlot();
        const current_epoch = computeEpochAtSlot(current_slot);
        const next_epoch_start = (current_epoch + 1) * preset.SLOTS_PER_EPOCH;
        const remaining = next_epoch_start - current_slot;
        try self.processSlots(remaining, 0.0);
    }

    /// Run a full scenario.
    pub fn processWithScenario(self: *SimNodeHarness, scenario: Scenario) !void {
        try self.processSlots(scenario.num_slots, scenario.skip_slot_rate);
    }
};
