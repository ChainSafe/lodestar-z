//! Deterministic simulation controller.
//!
//! Orchestrates multi-node simulations with deterministic slot advancement:
//!   tick clock → validators produce → gossip → nodes process → check invariants
//!
//! Sits above SimCluster, adding SimValidator integration and scenario support.
//! The controller owns the simulation lifecycle and provides higher-level
//! operations like advanceToEpoch, runUntilFinality, and runScenario.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");
const Node = @import("persistent_merkle_tree").Node;

const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

const node_pkg = @import("node");
const BeaconNode = node_pkg.BeaconNode;
const identity_mod = node_pkg.identity;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;
const SimValidator = @import("sim_validator.zig").SimValidator;
const SimNetwork = @import("sim_network.zig").SimNetwork;
const sim_network = @import("sim_network.zig");
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;
const Scenario = @import("scenario.zig").Scenario;
const Step = @import("scenario.zig").Step;
const Fault = @import("scenario.zig").Fault;
const Invariant = @import("scenario.zig").Invariant;

pub const ControllerConfig = struct {
    num_nodes: u8 = 4,
    validators_per_node: u64 = 16,
    seed: u64 = 42,
    /// Network fault configuration.
    network: sim_network.Config = .{},
    /// Total validator count for the test state.
    validator_count: usize = 64,
    /// Default participation rate for all validators.
    participation_rate: f64 = 1.0,
};

pub const FinalityResult = struct {
    slots_processed: u64,
    blocks_produced: u64,
    finalized_epoch: u64,
    safety_violations: u64,
    state_divergences: u64,
};

pub const SlotTickResult = struct {
    slot: u64,
    block_produced: bool,
    epoch_transition: bool,
};

pub const SimController = struct {
    allocator: Allocator,
    prng: std.Random.DefaultPrng,

    // Nodes
    nodes: []SimNodeHarness,
    beacon_nodes: []*BeaconNode,
    num_nodes: u8,

    // Validators (one per node)
    validators: []SimValidator,

    // Network
    net_prng: *std.Random.DefaultPrng,
    network: SimNetwork,

    // Invariant checker
    checker: ClusterInvariantChecker,

    // State
    current_slot: u64,
    total_slots: u64 = 0,
    total_blocks: u64 = 0,
    nodes_processed: []bool,

    // Proposer offline rate for skip logic
    proposer_offline_rate: f64 = 0.0,

    // Genesis resources (owned)
    primary_config: *config_mod.BeaconConfig,
    primary_pubkey_map: *state_transition.PubkeyIndexMap,
    primary_index_pubkey_cache: *state_transition.Index2PubkeyCache,
    primary_epoch_transition_cache: *state_transition.EpochTransitionCache,
    pool: *Node.Pool,

    // Config
    config: ControllerConfig,

    pub fn init(allocator: Allocator, config: ControllerConfig) !SimController {
        const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

        var cluster_prng = std.Random.DefaultPrng.init(config.seed);

        const net_prng = try allocator.create(std.Random.DefaultPrng);
        net_prng.* = std.Random.DefaultPrng.init(config.seed +% 100);

        const pool_nodes_per_sim_node: u32 = 500_000;
        const pool = try allocator.create(Node.Pool);
        pool.* = try Node.Pool.init(allocator, pool_nodes_per_sim_node * @as(u32, config.num_nodes));

        var primary = try TestCachedBeaconState.init(allocator, pool, config.validator_count);
        const start_slot = try primary.cached_state.state.slot();

        // Allocate arrays.
        const nodes = try allocator.alloc(SimNodeHarness, config.num_nodes);
        errdefer allocator.free(nodes);
        const beacon_nodes = try allocator.alloc(*BeaconNode, config.num_nodes);
        errdefer allocator.free(beacon_nodes);
        const validators = try allocator.alloc(SimValidator, config.num_nodes);
        errdefer allocator.free(validators);
        const nodes_processed = try allocator.alloc(bool, config.num_nodes);
        @memset(nodes_processed, false);

        // Node 0: from primary genesis state.
        const seed_0 = cluster_prng.random().int(u64);
        const bn0_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
        const bn0 = try BeaconNode.init(allocator, std.testing.io, primary.config, .{
            .node_identity = bn0_identity,
        });
        try bn0.initFromGenesis(primary.cached_state);
        beacon_nodes[0] = bn0;
        nodes[0] = SimNodeHarness.init(allocator, bn0, seed_0);
        nodes[0].participation_rate = config.participation_rate;

        // Distribute validators evenly across nodes.
        const total_validators: u64 = @intCast(config.validator_count);
        const per_node = total_validators / config.num_nodes;
        const remainder = total_validators % config.num_nodes;

        var vi_start: u64 = 0;
        for (0..config.num_nodes) |i| {
            const extra: u64 = if (i < remainder) 1 else 0;
            const vi_end = vi_start + per_node + extra;
            const val_seed = cluster_prng.random().int(u64);
            validators[i] = SimValidator.init(allocator, vi_start, vi_end, val_seed);
            validators[i].participation_rate = config.participation_rate;
            vi_start = vi_end;
        }

        // Nodes 1..N: clone genesis state.
        for (1..config.num_nodes) |i| {
            const genesis_state_0 = bn0.headState() orelse
                return error.NoGenesisState;
            const cloned = try genesis_state_0.clone(allocator, .{ .transfer_cache = false });

            const seed_i = cluster_prng.random().int(u64);
            const bn_i_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
            const bn_i = try BeaconNode.init(allocator, std.testing.io, primary.config, .{
                .node_identity = bn_i_identity,
            });
            try bn_i.initFromGenesis(cloned);
            beacon_nodes[i] = bn_i;
            nodes[i] = SimNodeHarness.init(allocator, bn_i, seed_i);
            nodes[i].participation_rate = config.participation_rate;
        }

        const checker = try ClusterInvariantChecker.init(allocator, config.num_nodes);

        return .{
            .allocator = allocator,
            .prng = cluster_prng,
            .nodes = nodes,
            .beacon_nodes = beacon_nodes,
            .num_nodes = config.num_nodes,
            .validators = validators,
            .net_prng = net_prng,
            .network = SimNetwork.init(allocator, net_prng, config.network),
            .checker = checker,
            .current_slot = start_slot,
            .nodes_processed = nodes_processed,
            .primary_config = primary.config,
            .primary_pubkey_map = primary.pubkey_index_map,
            .primary_index_pubkey_cache = primary.index_pubkey_cache,
            .primary_epoch_transition_cache = primary.epoch_transition_cache,
            .pool = pool,
            .config = config,
        };
    }

    pub fn deinit(self: *SimController) void {
        for (0..self.num_nodes) |i| {
            self.nodes[i].deinit();
            self.beacon_nodes[i].deinit();
        }

        self.primary_pubkey_map.deinit();
        self.allocator.destroy(self.primary_pubkey_map);
        self.primary_index_pubkey_cache.deinit();
        self.primary_epoch_transition_cache.deinit();
        state_transition.deinitStateTransition();
        self.allocator.destroy(self.primary_epoch_transition_cache);
        self.allocator.destroy(self.primary_index_pubkey_cache);
        self.allocator.destroy(self.primary_config);

        self.checker.deinit();
        self.network.deinit();
        self.allocator.destroy(self.net_prng);
        self.allocator.free(self.nodes);
        self.allocator.free(self.beacon_nodes);
        self.allocator.free(self.validators);
        self.allocator.free(self.nodes_processed);

        self.pool.deinit();
        self.allocator.destroy(self.pool);
    }

    /// Advance all nodes by one slot (with block production).
    pub fn advanceSlot(self: *SimController) !SlotTickResult {
        return self.advanceSlotImpl(false);
    }

    /// Advance one slot, skipping block production (empty slot).
    pub fn advanceSlotWithSkip(self: *SimController, force_skip: bool) !SlotTickResult {
        return self.advanceSlotImpl(force_skip);
    }

    /// Core slot advancement. All nodes process the slot synchronously.
    /// Each SimNodeHarness has its own BlockGenerator and handles
    /// proposer determination internally (via the epoch cache of the
    /// post-advance state). The controller does NOT try to determine
    /// the proposer upfront — that would require advancing state first.
    fn advanceSlotImpl(self: *SimController, force_skip: bool) !SlotTickResult {
        const target_slot = self.current_slot + 1;
        const current_epoch = computeEpochAtSlot(self.current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);
        const is_epoch_transition = target_epoch != current_epoch;

        // Decide whether to skip (proposer offline).
        const skip = force_skip or self.shouldSkip();

        @memset(self.nodes_processed, false);

        for (0..self.num_nodes) |i| {
            const result = try self.nodes[i].processSlot(skip);
            self.nodes_processed[i] = true;

            const fin_epoch = self.nodes[i].checker.finalized_epoch;
            try self.checker.recordNodeState(
                @intCast(i),
                result.slot,
                result.state_root,
                fin_epoch,
            );
        }

        try self.checker.checkTick(target_slot, self.nodes_processed);

        // Produce attestations from each node's validators and feed to fork choice.
        // Attestations for slot N are produced after the block for slot N is processed.
        if (!skip) {
            for (0..self.num_nodes) |i| {
                const head_state = self.nodes[i].getHeadState() orelse continue;
                var attestations = try self.validators[i].produceAttestations(
                    self.allocator,
                    head_state,
                    target_slot,
                );
                defer attestations.deinit(self.allocator);

                for (attestations.attestations.items) |*att| {
                    // Apply each attesting validator's vote to fork choice.
                    // In the real client, getAttestingIndices resolves committee → validators.
                    // Here we know the attester from SimValidator's committee walk.
                    const att_data = &att.data;
                    const committee = head_state.epoch_cache.getBeaconCommittee(
                        att_data.slot,
                        att_data.index,
                    ) catch continue;

                    for (committee, 0..) |vi, pos| {
                        // Check if this validator actually attested (bit set in aggregation_bits).
                        const is_set = att.aggregation_bits.get(pos) catch false;
                        if (is_set) {
                            self.beacon_nodes[i].chainService().applyAttestationVote(
                                @intCast(vi),
                                att_data.slot,
                                att_data.beacon_block_root,
                                att_data.target.epoch,
                            ) catch {};
                        }
                    }
                }
            }
        }

        self.current_slot = target_slot;
        self.total_slots += 1;
        if (!skip) self.total_blocks += 1;

        return .{
            .slot = target_slot,
            .block_produced = !skip,
            .epoch_transition = is_epoch_transition,
        };
    }

    fn shouldSkip(self: *SimController) bool {
        if (self.proposer_offline_rate <= 0.0) return false;
        const val: f64 = @as(f64, @floatFromInt(self.prng.random().int(u32))) /
            @as(f64, @floatFromInt(std.math.maxInt(u32)));
        return val < self.proposer_offline_rate;
    }

    /// Advance to a specific epoch (inclusive of the first slot of the epoch).
    pub fn advanceToEpoch(self: *SimController, target_epoch: u64) !void {
        const target_slot = target_epoch * preset.SLOTS_PER_EPOCH;
        while (self.current_slot < target_slot) {
            _ = try self.advanceSlot();
        }
    }

    /// Advance N slots.
    pub fn advanceSlots(self: *SimController, count: u64) !void {
        for (0..count) |_| {
            _ = try self.advanceSlot();
        }
    }

    /// Run until finality advances past epoch 0, or max_slots is reached.
    pub fn runUntilFinality(self: *SimController, max_slots: u64) !FinalityResult {
        for (0..max_slots) |_| {
            _ = try self.advanceSlot();

            for (self.checker.node_finalized_epochs[0..self.num_nodes]) |e| {
                if (e > 0) return self.getFinalityResult();
            }
        }
        return self.getFinalityResult();
    }

    /// Run a scenario.
    pub fn runScenario(self: *SimController, scenario: Scenario) !FinalityResult {
        for (scenario.steps) |step| {
            try self.executeStep(step);
        }
        return self.getFinalityResult();
    }

    /// Execute a single scenario step.
    pub fn executeStep(self: *SimController, step: Step) !void {
        switch (step) {
            .advance_slot => {
                _ = try self.advanceSlot();
            },
            .advance_to_epoch => |epoch| {
                try self.advanceToEpoch(epoch);
            },
            .skip_slot => {
                _ = try self.advanceSlotImpl(true);
            },
            .check_invariant => |invariant| {
                try self.checkInvariant(invariant);
            },
            .network_partition => |partition| {
                for (partition.group_a) |a| {
                    for (partition.group_b) |b| {
                        self.network.partition(a, b);
                    }
                }
            },
            .heal_partition => {
                self.network.healAll();
            },
            .disconnect_node => |node_id| {
                for (0..self.num_nodes) |i| {
                    if (i != node_id) {
                        self.network.partition(node_id, @intCast(i));
                    }
                }
            },
            .reconnect_node => |node_id| {
                for (0..self.num_nodes) |i| {
                    if (i != node_id) {
                        self.network.heal(node_id, @intCast(i));
                    }
                }
            },
            .inject_fault => |fault| {
                self.injectFault(fault);
            },
            .set_participation_rate => |rate| {
                for (self.validators) |*v| {
                    v.participation_rate = rate;
                }
                for (self.nodes) |*n| {
                    n.participation_rate = rate;
                }
            },
        }
    }

    /// Check a specific invariant.
    pub fn checkInvariant(self: *SimController, invariant: Invariant) !void {
        switch (invariant) {
            .finality_agreement => {
                if (self.num_nodes < 2) return;
                const first = self.checker.node_finalized_epochs[0];
                for (self.checker.node_finalized_epochs[1..self.num_nodes]) |e| {
                    if (e != first) return error.FinalityDisagreement;
                }
            },
            .safety => {
                if (self.checker.safety_violations > 0) return error.SafetyViolation;
            },
            .liveness => |max_gap_epochs| {
                const gap_slots = self.current_slot - self.checker.last_finality_advance_slot;
                const gap_epochs = gap_slots / preset.SLOTS_PER_EPOCH;
                if (gap_epochs > max_gap_epochs) return error.LivenessStall;
            },
            .head_agreement => {
                if (self.num_nodes < 2) return;
                const head_0 = self.nodes[0].getHeadState() orelse return error.NoHeadState;
                const root_0 = (try head_0.state.hashTreeRoot()).*;
                for (1..self.num_nodes) |i| {
                    const head_i = self.nodes[i].getHeadState() orelse continue;
                    const root_i = (try head_i.state.hashTreeRoot()).*;
                    if (!std.mem.eql(u8, &root_0, &root_i)) return error.HeadDisagreement;
                }
            },
            .head_freshness => |max_behind| {
                for (0..self.num_nodes) |i| {
                    const head_slot = self.beacon_nodes[i].getHead().slot;
                    if (self.current_slot > head_slot + max_behind) return error.HeadTooStale;
                }
            },
            .no_state_divergence => {
                if (self.checker.state_divergences > 0) return error.StateDivergence;
            },
        }
    }

    /// Inject a fault into the simulation.
    fn injectFault(self: *SimController, fault: Fault) void {
        switch (fault) {
            .missed_proposal => |node_idx| {
                if (node_idx < self.validators.len) {
                    self.validators[node_idx].skip_next_proposal = true;
                }
            },
            .missed_attestation => |node_idx| {
                if (node_idx < self.validators.len) {
                    self.validators[node_idx].skip_attestations = true;
                }
            },
            .message_drop_rate => |rate| {
                self.network.config.packet_loss_rate = rate;
            },
            .message_delay => |delay| {
                self.network.config.min_latency_ms = delay.min_ms;
                self.network.config.max_latency_ms = delay.max_ms;
            },
            .node_crash => |node_idx| {
                for (0..self.num_nodes) |i| {
                    if (i != node_idx) {
                        self.network.partition(node_idx, @intCast(i));
                    }
                }
            },
            .node_restart => |node_idx| {
                for (0..self.num_nodes) |i| {
                    if (i != node_idx) {
                        self.network.heal(node_idx, @intCast(i));
                    }
                }
            },
        }
    }

    pub fn getFinalityResult(self: *const SimController) FinalityResult {
        var max_finalized: u64 = 0;
        for (self.checker.node_finalized_epochs[0..self.num_nodes]) |e| {
            max_finalized = @max(max_finalized, e);
        }

        return .{
            .slots_processed = self.total_slots,
            .blocks_produced = self.total_blocks,
            .finalized_epoch = max_finalized,
            .safety_violations = self.checker.safety_violations,
            .state_divergences = self.checker.state_divergences,
        };
    }

    /// Get the current finalized epoch (max across all nodes).
    pub fn finalizedEpoch(self: *const SimController) u64 {
        var max_epoch: u64 = 0;
        for (self.checker.node_finalized_epochs[0..self.num_nodes]) |e| {
            max_epoch = @max(max_epoch, e);
        }
        return max_epoch;
    }
};
