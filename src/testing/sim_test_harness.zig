//! Shared test harness for single-node deterministic simulation.
//!
//! Bootstraps a real BeaconNode against the same runtime-owned shared-state
//! graph contract used elsewhere in the codebase. The simulation harness owns
//! only the borrowed BeaconConfig pointer plus the node/sim wrappers.

const std = @import("std");
const config_mod = @import("config");
const active_preset = @import("preset").active_preset;
const state_transition = @import("state_transition");

const node_pkg = @import("node");
const BeaconNode = node_pkg.BeaconNode;
const identity_mod = node_pkg.identity;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;
const SharedStateGraph = @import("chain").SharedStateGraph;

const BeaconConfig = config_mod.BeaconConfig;
const CachedBeaconState = state_transition.CachedBeaconState;
const generateElectraState = state_transition.test_utils.generateElectraState;

const active_chain_config = if (active_preset == .mainnet)
    config_mod.mainnet.chain_config
else
    config_mod.minimal.chain_config;

pub fn createTestConfig(
    allocator: std.mem.Allocator,
    validator_count: usize,
) !*BeaconConfig {
    var temp_pool = try @import("persistent_merkle_tree").Node.Pool.init(allocator, 256 * 5);
    defer temp_pool.deinit();

    const temp_state = try generateElectraState(allocator, &temp_pool, active_chain_config, validator_count);
    defer {
        temp_state.deinit();
        allocator.destroy(temp_state);
    }

    const config = try allocator.create(BeaconConfig);
    errdefer allocator.destroy(config);
    config.* = BeaconConfig.init(active_chain_config, (try temp_state.genesisValidatorsRoot()).*);
    return config;
}

pub fn createPublishedGenesisState(
    allocator: std.mem.Allocator,
    shared_state_graph: *SharedStateGraph,
    validator_count: usize,
) !*CachedBeaconState {
    const raw_state = try generateElectraState(
        allocator,
        shared_state_graph.pool,
        active_chain_config,
        validator_count,
    );

    const validators = try raw_state.validatorsSlice(allocator);
    defer allocator.free(validators);
    try shared_state_graph.validator_pubkeys.syncFromValidators(validators);

    return state_transition.CachedBeaconState.createCachedBeaconState(
        allocator,
        raw_state,
        shared_state_graph.state_transition_metrics,
        shared_state_graph.validator_pubkeys.immutableData(shared_state_graph.config),
        .{
            .skip_sync_committee_cache = raw_state.forkSeq() == .phase0,
            .skip_sync_pubkeys = true,
        },
    );
}

pub const SimTestHarness = struct {
    allocator: std.mem.Allocator,
    config: *BeaconConfig,

    /// The underlying BeaconNode (owns state caches, DB, importer).
    node: *BeaconNode,

    /// The simulation harness driving the node.
    sim: SimNodeHarness,

    /// Default validator count for test states.
    pub const default_validator_count: usize = 64;

    /// Initialise a harness with default validator count (64).
    pub fn init(allocator: std.mem.Allocator, seed: u64) !SimTestHarness {
        return initWithValidators(allocator, seed, default_validator_count);
    }

    /// Initialise a harness with a specific validator count.
    pub fn initWithValidators(
        allocator: std.mem.Allocator,
        seed: u64,
        validator_count: usize,
    ) !SimTestHarness {
        const config = try createTestConfig(allocator, validator_count);
        errdefer allocator.destroy(config);

        const node_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
        var builder = try BeaconNode.Builder.init(allocator, std.testing.io, config, .{
            .options = .{ .engine_mock = true },
            .node_identity = node_identity,
        });
        errdefer builder.deinit();

        const genesis_state = try createPublishedGenesisState(
            allocator,
            builder.sharedStateGraph(),
            validator_count,
        );
        const node = try builder.finishGenesis(genesis_state);
        errdefer node.deinit();

        const sim = SimNodeHarness.init(allocator, node, seed);

        return .{
            .allocator = allocator,
            .config = config,
            .node = node,
            .sim = sim,
        };
    }

    pub fn deinit(self: *SimTestHarness) void {
        self.sim.deinit();
        self.node.deinit();
        state_transition.deinitStateTransition();
        self.allocator.destroy(self.config);
    }
};
