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

const BeaconNode = @import("node").BeaconNode;
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

    pub fn currentSlot(self: *SimNodeHarness) !u64 {
        const head_state = self.getHeadState() orelse return error.NoHeadState;
        return head_state.state.slot();
    }

    pub fn produceNextSlotBlockBytes(self: *SimNodeHarness) !ProducedBlockBytes {
        const head_state = self.getHeadState() orelse return error.NoHeadState;
        const current_slot = try head_state.state.slot();
        const target_slot = current_slot + 1;
        const current_epoch = computeEpochAtSlot(current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);

        var post_state = try head_state.clone(
            self.allocator,
            .{ .transfer_cache = false },
        );
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

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

        const request = BeaconBlocksByRangeRequest.Type{
            .start_slot = start_slot,
            .count = target_slot - start_slot + 1,
        };
        var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
        _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

        const chunks = try peer.onReqResp(.beacon_blocks_by_range, &request_bytes);
        defer networking.freeResponseChunks(peer.allocator, chunks);

        const raw_blocks = try self.allocator.alloc(chain_mod.RawBlockBytes, chunks.len);
        defer self.allocator.free(raw_blocks);

        var raw_count: usize = 0;
        for (chunks) |chunk| {
            if (chunk.result != .success) return error.RangeSyncReqRespFailed;
            const slot = readSignedBlockSlotFromSsz(chunk.ssz_payload) orelse return error.InvalidReqRespBlock;
            raw_blocks[raw_count] = .{
                .slot = slot,
                .bytes = chunk.ssz_payload,
            };
            raw_count += 1;
        }

        if (raw_count == 0) return 0;
        try self.node.processRangeSyncSegment(raw_blocks[0..raw_count]);
        return raw_count;
    }

    pub fn syncMissingBlocksFromPeer(
        self: *SimNodeHarness,
        peer: *BeaconNode,
        target_slot: u64,
    ) !u64 {
        const current_slot = try self.currentSlot();
        if (current_slot >= target_slot) return 0;
        return self.syncBlocksByRangeFromPeer(peer, current_slot + 1, target_slot);
    }

    pub fn advanceEmptyToSlot(self: *SimNodeHarness, target_slot: u64) !void {
        try self.node.advanceSlot(target_slot);
    }

    fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
        if (block_bytes.len < 108) return null;
        return std.mem.readInt(u64, block_bytes[100..108], .little);
    }

    pub fn observeSlot(
        self: *SimNodeHarness,
        target_slot: u64,
        block_processed: bool,
    ) !SlotResult {
        const new_head_state = self.getHeadState() orelse return error.NoHeadState;
        const observed_slot = try new_head_state.state.slot();
        if (observed_slot != target_slot) return error.UnexpectedHeadSlot;

        self.sim_io.advanceToSlot(
            target_slot,
            self.clock.genesis_time_s,
            self.clock.seconds_per_slot,
        );

        try self.checker.checkSlot(new_head_state.state);

        self.slots_processed += 1;
        if (block_processed) self.blocks_processed += 1;

        const previous_epoch = computeEpochAtSlot(target_slot - 1);
        const current_epoch = computeEpochAtSlot(target_slot);
        if (current_epoch != previous_epoch) self.epochs_processed += 1;

        const state_root = try new_head_state.state.hashTreeRoot();
        return .{
            .slot = target_slot,
            .block_processed = block_processed,
            .epoch_transition = current_epoch != previous_epoch,
            .state_root = state_root.*,
        };
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
