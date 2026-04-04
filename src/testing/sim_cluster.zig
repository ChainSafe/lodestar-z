//! Multi-node deterministic cluster simulation.
//!
//! Ties together N SimNodeHarness instances (each wrapping a BeaconNode)
//! connected via SimNetwork with cluster-wide invariant checking.
//! Proves that identical blocks produce identical state roots across nodes,
//! and that network faults cause graceful degradation — never safety violations.
//!
//! V1 simplifications:
//!   - Single chain per node (no fork tracking).
//!   - Out-of-order / wrong-parent blocks are dropped.
//!   - Attestations are tracked but not processed through STFN.
//!   - Key value: N nodes × same blocks × same order = identical state roots.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

const node_pkg = @import("node");
const BeaconNode = node_pkg.BeaconNode;
const identity_mod = node_pkg.identity;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;
const sim_network = @import("sim_network.zig");
const SimNetwork = sim_network.SimNetwork;
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;

const computeEpochAtSlot = state_transition.computeEpochAtSlot;

pub const ClusterConfig = struct {
    num_nodes: u8 = 4,
    seed: u64 = 42,
    /// Network fault configuration.
    network: sim_network.Config = .{},
    /// Probability that the proposer is offline (skip slot) [0.0 - 1.0].
    proposer_offline_rate: f64 = 0.0,
    /// Number of validators in the test state.
    validator_count: usize = 64,
    /// Fraction of validators producing attestations [0.0 - 1.0].
    participation_rate: f64 = 0.0,
};

pub const TickResult = struct {
    slot: u64,
    proposer_node: u8,
    block_produced: bool,
    nodes_received_block: u8,
    epoch_transition: bool,
};

pub const RunResult = struct {
    slots_processed: u64,
    blocks_produced: u64,
    finalized_epoch: u64,
    safety_violations: u64,
    liveness_stalls: u64,
    state_divergences: u64,
};

pub const SimCluster = struct {
    allocator: Allocator,
    prng: std.Random.DefaultPrng,

    /// Heap-allocated so SimNetwork's pointer stays stable.
    net_prng: *std.Random.DefaultPrng,
    network: SimNetwork,

    /// Array of simulated node harnesses.
    nodes: []SimNodeHarness,
    num_nodes: u8,

    /// Global invariant checker (cross-node).
    checker: ClusterInvariantChecker,

    /// Current slot (last processed).
    current_slot: u64,

    /// Offline rate for proposers.
    proposer_offline_rate: f64,

    /// Attestation participation rate.
    participation_rate: f64,

    /// Stats.
    total_slots: u64 = 0,
    total_blocks: u64 = 0,

    /// Track which nodes processed each slot (for invariant checking).
    nodes_processed: []bool,

    /// Node 0 owns the primary TestCachedBeaconState ancillary resources.
    primary_config: *config_mod.BeaconConfig,
    primary_pubkey_map: *state_transition.PubkeyIndexMap,
    primary_index_pubkey_cache: *state_transition.Index2PubkeyCache,
    primary_epoch_transition_cache: *state_transition.EpochTransitionCache,

    /// BeaconNode pointers (owned, one per harness).
    beacon_nodes: []*BeaconNode,

    /// Node pool (must outlive states).
    pool: *Node.Pool,

    pub fn init(allocator: Allocator, config: ClusterConfig) !SimCluster {
        const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

        var cluster_prng = std.Random.DefaultPrng.init(config.seed);

        const net_prng = try allocator.create(std.Random.DefaultPrng);
        net_prng.* = std.Random.DefaultPrng.init(config.seed +% 100);

        // Create a shared merkle tree pool.
        const pool_nodes_per_sim_node: u32 = 500_000;
        const pool = try allocator.create(Node.Pool);
        pool.* = try Node.Pool.init(allocator, pool_nodes_per_sim_node * @as(u32, config.num_nodes));

        // Create primary genesis state.
        var primary = try TestCachedBeaconState.init(
            allocator,
            pool,
            config.validator_count,
        );

        const start_slot = try primary.cached_state.state.slot();

        // Allocate node arrays.
        const nodes = try allocator.alloc(SimNodeHarness, config.num_nodes);
        errdefer allocator.free(nodes);
        const beacon_nodes = try allocator.alloc(*BeaconNode, config.num_nodes);
        errdefer allocator.free(beacon_nodes);
        const nodes_processed = try allocator.alloc(bool, config.num_nodes);
        @memset(nodes_processed, false);

        // Node 0: initialize from primary genesis state.
        const seed_0 = cluster_prng.random().int(u64);
        const bn0_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
        var bn0_builder = try BeaconNode.Builder.init(allocator, std.testing.io, primary.config, .{
            .options = .{ .engine_mock = true },
            .node_identity = bn0_identity,
        });
        errdefer bn0_builder.deinit();
        const bn0 = try bn0_builder.finishGenesis(primary.cached_state);
        beacon_nodes[0] = bn0;
        nodes[0] = SimNodeHarness.init(allocator, bn0, seed_0);
        nodes[0].participation_rate = config.participation_rate;

        // Nodes 1..N: each gets a clone of the genesis state.
        for (1..config.num_nodes) |i| {
            // Get the genesis state from node 0's cache to clone it.
            const genesis_state_0 = bn0.headState() orelse
                return error.NoGenesisState;
            const cloned = try genesis_state_0.clone(allocator, .{ .transfer_cache = false });

            const seed_i = cluster_prng.random().int(u64);
            const bn_i_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
            var bn_i_builder = try BeaconNode.Builder.init(allocator, std.testing.io, primary.config, .{
                .options = .{ .engine_mock = true },
                .node_identity = bn_i_identity,
            });
            errdefer bn_i_builder.deinit();
            const bn_i = try bn_i_builder.finishGenesis(cloned);
            beacon_nodes[i] = bn_i;
            nodes[i] = SimNodeHarness.init(allocator, bn_i, seed_i);
            nodes[i].participation_rate = config.participation_rate;
        }

        const checker = try ClusterInvariantChecker.init(allocator, config.num_nodes);

        return .{
            .allocator = allocator,
            .prng = cluster_prng,
            .net_prng = net_prng,
            .network = SimNetwork.init(allocator, net_prng, config.network),
            .nodes = nodes,
            .num_nodes = config.num_nodes,
            .checker = checker,
            .current_slot = start_slot,
            .proposer_offline_rate = config.proposer_offline_rate,
            .participation_rate = config.participation_rate,
            .nodes_processed = nodes_processed,
            .primary_config = primary.config,
            .primary_pubkey_map = primary.pubkey_index_map,
            .primary_index_pubkey_cache = primary.index_pubkey_cache,
            .primary_epoch_transition_cache = primary.epoch_transition_cache,
            .beacon_nodes = beacon_nodes,
            .pool = pool,
        };
    }

    pub fn deinit(self: *SimCluster) void {
        // Free each harness (checker etc.) then its BeaconNode.
        for (0..self.num_nodes) |i| {
            self.nodes[i].deinit();
            self.beacon_nodes[i].deinit();
        }

        // Free primary TestCachedBeaconState ancillary resources.
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
        self.allocator.free(self.nodes_processed);

        self.pool.deinit();
        self.allocator.destroy(self.pool);
    }

    /// Advance all nodes by one slot.
    ///
    /// 1. Determine if proposer is offline (deterministic skip).
    /// 2. Each node processes the slot (block or skip).
    /// 3. Record state roots and check cluster invariants.
    pub fn tick(self: *SimCluster) !TickResult {
        const target_slot = self.current_slot + 1;
        const proposer_node: u8 = @intCast(target_slot % self.num_nodes);
        const current_epoch = computeEpochAtSlot(self.current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);
        const is_epoch_transition = target_epoch != current_epoch;

        const proposer_offline = self.shouldSkip();

        @memset(self.nodes_processed, false);

        if (proposer_offline) {
            for (0..self.num_nodes) |i| {
                const result = try self.nodes[i].processSlot(true);
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

            self.current_slot = target_slot;
            self.total_slots += 1;

            return .{
                .slot = target_slot,
                .proposer_node = proposer_node,
                .block_produced = false,
                .nodes_received_block = 0,
                .epoch_transition = is_epoch_transition,
            };
        }

        // ── Block production path ────────────────────────────────
        var nodes_received: u8 = 0;

        for (0..self.num_nodes) |i| {
            const result = try self.nodes[i].processSlot(false);
            self.nodes_processed[i] = true;
            nodes_received += 1;

            const fin_epoch = self.nodes[i].checker.finalized_epoch;
            try self.checker.recordNodeState(
                @intCast(i),
                result.slot,
                result.state_root,
                fin_epoch,
            );
        }

        try self.checker.checkTick(target_slot, self.nodes_processed);

        self.current_slot = target_slot;
        self.total_slots += 1;
        self.total_blocks += 1;

        return .{
            .slot = target_slot,
            .proposer_node = proposer_node,
            .block_produced = true,
            .nodes_received_block = nodes_received,
            .epoch_transition = is_epoch_transition,
        };
    }

    /// Run N slots.
    pub fn run(self: *SimCluster, num_slots: u64) !RunResult {
        for (0..num_slots) |_| {
            _ = try self.tick();
        }
        return self.getRunResult();
    }

    /// Run until finality advances past epoch 0, or max_slots is reached.
    pub fn runUntilFinality(self: *SimCluster, max_slots: u64) !RunResult {
        for (0..max_slots) |_| {
            _ = try self.tick();

            for (self.checker.node_finalized_epochs) |e| {
                if (e > 0) return self.getRunResult();
            }
        }
        return self.getRunResult();
    }

    /// Get the current RunResult.
    pub fn getRunResult(self: *const SimCluster) RunResult {
        var max_finalized: u64 = 0;
        for (self.checker.node_finalized_epochs) |e| {
            max_finalized = @max(max_finalized, e);
        }

        return .{
            .slots_processed = self.total_slots,
            .blocks_produced = self.total_blocks,
            .finalized_epoch = max_finalized,
            .safety_violations = self.checker.safety_violations,
            .liveness_stalls = self.checker.liveness_stalls,
            .state_divergences = self.checker.state_divergences,
        };
    }

    /// Create a network partition between two groups of nodes.
    pub fn partitionGroups(self: *SimCluster, group_a: []const u8, group_b: []const u8) void {
        for (group_a) |a| {
            for (group_b) |b| {
                self.network.partition(a, b);
            }
        }
    }

    /// Heal all network partitions.
    pub fn healAllPartitions(self: *SimCluster) void {
        self.network.healAll();
    }

    fn shouldSkip(self: *SimCluster) bool {
        if (self.proposer_offline_rate <= 0.0) return false;

        const val: f64 = @as(f64, @floatFromInt(self.prng.random().int(u32))) /
            @as(f64, @floatFromInt(std.math.maxInt(u32)));
        return val < self.proposer_offline_rate;
    }
};
