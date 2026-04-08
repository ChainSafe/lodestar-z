//! Single-node deterministic beacon simulation.
//!
//! Ties together DST primitives (SimIo, SimStorage, SlotClock) with the
//! real state transition to run a fully deterministic beacon node
//! simulation.  Same seed = identical execution, guaranteed by the
//! invariant checker.
//!
//! Usage:
//!   1. Create a genesis CachedBeaconState (via TestCachedBeaconState).
//!   2. Init a SimBeaconNode with a seed.
//!   3. Call processSlot() / processSlots() / processWithScenario().
//!   4. Inspect stats and checker for correctness.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const BeaconBlock = fork_types.BeaconBlock;

const BlockGenerator = @import("block_generator.zig").BlockGenerator;
const BlockOpts = @import("block_generator.zig").BlockOpts;
const InvariantChecker = @import("invariant_checker.zig").InvariantChecker;
const SimIo = @import("sim_io.zig").SimIo;
const SlotClock = @import("sim_clock.zig").SlotClock;
const SimStorage = @import("sim_storage.zig").SimStorage;

const computeEpochAtSlot = state_transition.computeEpochAtSlot;

pub const SlotResult = struct {
    slot: u64,
    block_processed: bool,
    epoch_transition: bool,
    state_root: [32]u8,
};

pub const Scenario = struct {
    /// Total slots to simulate.
    num_slots: u64,
    /// Probability of skipping a slot (0.0 – 1.0).
    skip_slot_rate: f64 = 0.0,
};

pub const SimBeaconNode = struct {
    allocator: Allocator,
    sim_io: SimIo,
    clock: SlotClock,
    storage: SimStorage,

    /// Current head state — owned; deinit on teardown.
    head_state: *CachedBeaconState,

    block_gen: BlockGenerator,
    checker: InvariantChecker,

    // ── Stats ────────────────────────────────────────────────────
    slots_processed: u64 = 0,
    blocks_processed: u64 = 0,
    epochs_processed: u64 = 0,
    skip_prng: std.Random.DefaultPrng,
    /// Fraction of validators producing attestations [0.0 - 1.0].
    participation_rate: f64 = 0.0,

    pub fn init(
        allocator: Allocator,
        head_state: *CachedBeaconState,
        seed: u64,
    ) !SimBeaconNode {
        const genesis_time = try head_state.state.genesisTime();
        const sps = head_state.config.chain.SECONDS_PER_SLOT;

        var storage_prng = std.Random.DefaultPrng.init(seed +% 1);
        return .{
            .allocator = allocator,
            .sim_io = .{
                .prng = std.Random.DefaultPrng.init(seed),
                .monotonic_ns = genesis_time * std.time.ns_per_s,
                .realtime_ns = @as(i128, genesis_time) * std.time.ns_per_s,
            },
            .clock = .{ .genesis_time_s = genesis_time, .seconds_per_slot = sps },
            .storage = SimStorage.init(allocator, &storage_prng, .{}),
            .head_state = head_state,
            .block_gen = BlockGenerator.init(allocator, seed +% 2),
            .checker = InvariantChecker.init(allocator),
            .skip_prng = std.Random.DefaultPrng.init(seed +% 3),
        };
    }

    pub fn deinit(self: *SimBeaconNode) void {
        self.storage.deinit();
        self.checker.deinit();
        // head_state ownership is returned to caller — don't free here.
    }

    /// Advance the simulation by one slot.
    ///
    /// If `skip` is false, a block is generated and applied via the full
    /// state transition.  If `skip` is true the slot is advanced without
    /// a block (empty slot).
    pub fn processSlot(self: *SimBeaconNode, skip: bool) !SlotResult {
        const current_slot = try self.head_state.state.slot();
        const target_slot = current_slot + 1;
        const current_epoch = computeEpochAtSlot(current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);
        const is_epoch_transition = target_epoch != current_epoch;

        if (skip) {
            // Advance state by one slot without a block.
            try state_transition.processSlots(
                self.allocator,
                self.head_state,
                target_slot,
                .{},
            );

            // Advance simulated time.
            self.sim_io.advanceToSlot(
                target_slot,
                self.clock.genesis_time_s,
                self.clock.seconds_per_slot,
            );

            // Record invariants.
            try self.checker.checkSlot(self.head_state.state);

            self.slots_processed += 1;
            if (is_epoch_transition) self.epochs_processed += 1;

            const state_root = try self.head_state.state.hashTreeRoot();
            return .{
                .slot = target_slot,
                .block_processed = false,
                .epoch_transition = is_epoch_transition,
                .state_root = state_root.*,
            };
        }

        // ── Block production path ────────────────────────────────

        // Clone state so we can advance it to look up the correct proposer.
        // stateTransition does the same clone internally, but we need the
        // post-advance epoch cache BEFORE building the block.
        var post_state = try self.head_state.clone(
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

        // Generate a block using post-advance state (correct proposer).
        const signed_block = try self.block_gen.generateBlockWithOpts(post_state, target_slot, .{
            .participation_rate = self.participation_rate,
        });
        defer {
            types.electra.SignedBeaconBlock.deinit(self.allocator, signed_block);
            self.allocator.destroy(signed_block);
        }

        const any_signed = AnySignedBeaconBlock{ .full_electra = signed_block };

        // Now apply the block to the post-advance state via processBlock.
        const block = any_signed.beaconBlock();
        if (block.forkSeq() != post_state.state.forkSeq()) {
            return error.InvalidBlockForkForState;
        }

        switch (post_state.state.forkSeq()) {
            inline else => |f| {
                switch (block.blockType()) {
                    inline else => |bt| {
                        if (comptime bt == .blinded and (f.lt(.bellatrix) or f.gte(.gloas))) {
                            return error.InvalidBlockTypeForFork;
                        }
                        try state_transition.processBlock(
                            f,
                            self.allocator,
                            post_state.config,
                            post_state.epoch_cache,
                            post_state.state.castToFork(f),
                            &post_state.slashings_cache,
                            bt,
                            block.castToFork(bt, f),
                            .{
                                .execution_payload_status = .valid,
                                .data_availability_status = .available,
                            },
                            .{ .verify_signature = false },
                        );
                    },
                }
            },
        }

        // Commit tree changes (we skip state root verification).
        try post_state.state.commit();

        // Swap head state.
        self.head_state.deinit();
        self.allocator.destroy(self.head_state);
        self.head_state = post_state;

        // Advance simulated time.
        self.sim_io.advanceToSlot(
            target_slot,
            self.clock.genesis_time_s,
            self.clock.seconds_per_slot,
        );

        // Record invariants.
        try self.checker.checkSlot(self.head_state.state);

        self.slots_processed += 1;
        self.blocks_processed += 1;
        if (is_epoch_transition) self.epochs_processed += 1;

        const state_root = try self.head_state.state.hashTreeRoot();
        return .{
            .slot = target_slot,
            .block_processed = true,
            .epoch_transition = is_epoch_transition,
            .state_root = state_root.*,
        };
    }

    /// Process `count` consecutive slots.  Each slot decides whether to
    /// skip based on the scenario's skip rate (0.0 = never skip).
    pub fn processSlots(self: *SimBeaconNode, count: u64, skip_rate: f64) !void {
        for (0..count) |_| {
            const should_skip = if (skip_rate > 0.0) blk: {
                // Use a deterministic float from the skip PRNG.
                const rand_val: f64 = @as(f64, @floatFromInt(self.skip_prng.random().int(u32))) /
                    @as(f64, @floatFromInt(std.math.maxInt(u32)));
                break :blk rand_val < skip_rate;
            } else false;

            _ = try self.processSlot(should_skip);
        }
    }

    /// Process until the end of the current epoch (triggers epoch transition).
    pub fn processToEpochBoundary(self: *SimBeaconNode) !void {
        const current_slot = try self.head_state.state.slot();
        const current_epoch = computeEpochAtSlot(current_slot);
        const next_epoch_start = (current_epoch + 1) * preset.SLOTS_PER_EPOCH;
        const remaining = next_epoch_start - current_slot;
        try self.processSlots(remaining, 0.0);
    }

    /// Run a full scenario.
    pub fn processWithScenario(self: *SimBeaconNode, scenario: Scenario) !void {
        try self.processSlots(scenario.num_slots, scenario.skip_slot_rate);
    }
};
