//! SimNodeHarness: test harness wrapping BeaconNode with deterministic I/O.
//!
//! A "sim node" is just a BeaconNode driven by deterministic block generation
//! and invariant checking. This harness replaces SimBeaconNode by delegating
//! all state management to BeaconNode (which owns the STFN pipeline) and only
//! adding the test-specific concerns: block generation, invariant checking, and
//! simulated time.
//!
//! Usage:
//!   1. Create a BeaconNode and call initFromGenesis on it.
//!   2. Create a SimNodeHarness wrapping the node.
//!   3. Call processSlot() / processSlots() / processWithScenario().
//!   4. Inspect stats and checker for correctness.

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

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
    /// The node must have been initialized via initFromGenesis before this call
    /// so that the clock and head state are set up. The seed controls block
    /// generation and skip-slot randomness.
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

    /// Advance the simulation by one slot.
    ///
    /// If `skip` is false, a block is generated and applied via BeaconNode.importBlock.
    /// If `skip` is true, the slot is advanced without a block via BeaconNode.advanceSlot.
    pub fn processSlot(self: *SimNodeHarness, skip: bool) !SlotResult {
        const head_state = self.getHeadState() orelse return error.NoHeadState;
        const current_slot = try head_state.state.slot();
        const target_slot = current_slot + 1;
        const current_epoch = computeEpochAtSlot(current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);
        const is_epoch_transition = target_epoch != current_epoch;

        if (skip) {
            // Advance head state by one empty slot.
            try self.node.advanceSlot(target_slot);

            // Advance simulated time.
            self.sim_io.advanceToSlot(
                target_slot,
                self.clock.genesis_time_s,
                self.clock.seconds_per_slot,
            );

            // Check invariants on the new head state.
            const new_head_state = self.getHeadState() orelse return error.NoHeadState;
            try self.checker.checkSlot(new_head_state.state);

            self.slots_processed += 1;
            if (is_epoch_transition) self.epochs_processed += 1;

            const state_root = try new_head_state.state.hashTreeRoot();
            return .{
                .slot = target_slot,
                .block_processed = false,
                .epoch_transition = is_epoch_transition,
                .state_root = state_root.*,
            };
        }

        // ── Block production path ────────────────────────────────

        // Clone head state so we can advance it to look up the correct
        // proposer. BeaconNode.importBlock does the same clone internally,
        // but we need the post-advance epoch cache BEFORE building the block.
        //
        // Use a nested scope to ensure post_state cleanup errdefer does not
        // fire after we manually free it below (Zig errdefers cannot be cancelled).
        const signed_block = blk: {
            var post_state = try head_state.clone(
                self.allocator,
                .{ .transfer_cache = false },
            );
            errdefer {
                post_state.deinit();
                self.allocator.destroy(post_state);
            }

            // Advance to target slot (triggers epoch transition if needed).
            try state_transition.processSlots(
                self.allocator,
                post_state,
                target_slot,
                .{},
            );

            // Generate block using post-advance state (correct proposer / epoch cache).
            const blk_val = try self.block_gen.generateBlockWithOpts(post_state, target_slot, .{
                .participation_rate = self.participation_rate,
            });

            // Free the temporary post-state (BeaconNode.importBlock makes its own copy).
            post_state.deinit();
            self.allocator.destroy(post_state);

            break :blk blk_val;
        };

        defer {
            const types = @import("consensus_types");
            types.electra.SignedBeaconBlock.deinit(self.allocator, signed_block);
            self.allocator.destroy(signed_block);
        }

        // Import through BeaconNode's full pipeline.
        const any_signed = fork_types.AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        const result = try self.node.importBlock(any_signed, .api);

        // Advance simulated time.
        self.sim_io.advanceToSlot(
            target_slot,
            self.clock.genesis_time_s,
            self.clock.seconds_per_slot,
        );

        // Check invariants on the post-import head state.
        const new_head_state = self.getHeadState() orelse return error.NoHeadState;
        try self.checker.checkSlot(new_head_state.state);

        self.slots_processed += 1;
        self.blocks_processed += 1;
        if (is_epoch_transition) self.epochs_processed += 1;

        return .{
            .slot = result.slot,
            .block_processed = true,
            .epoch_transition = result.epoch_transition,
            .state_root = result.state_root,
        };
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
        const head_state = self.getHeadState() orelse return error.NoHeadState;
        const current_slot = try head_state.state.slot();
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
