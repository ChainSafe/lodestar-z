//! Shared test harness for single-node deterministic simulation.
//!
//! Manages the lifecycle of TestCachedBeaconState resources alongside
//! a SimNodeHarness (wrapping BeaconNode), ensuring everything is freed
//! exactly once.
//!
//! Used by both single-node tests (sim_test.zig) and the multi-node
//! cluster (sim_cluster.zig) for the primary node's resources.

const std = @import("std");
const config_mod = @import("config");
const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;

const node_pkg = @import("node");
const BeaconNode = node_pkg.BeaconNode;
const identity_mod = node_pkg.identity;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

pub const SimTestHarness = struct {
    allocator: std.mem.Allocator,
    pool: *Node.Pool,

    /// Ancillary resources from TestCachedBeaconState that outlive the
    /// evolving state. Freed on deinit.
    config: *config_mod.BeaconConfig,
    pubkey_index_map: *state_transition.PubkeyIndexMap,
    index_pubkey_cache: *state_transition.Index2PubkeyCache,
    epoch_transition_cache: *state_transition.EpochTransitionCache,

    /// The underlying BeaconNode (owns state caches, DB, importer).
    node: *BeaconNode,

    /// The simulation harness driving the node.
    sim: SimNodeHarness,

    /// Default validator count for test states.
    pub const default_validator_count: usize = 64;

    /// Default pool node count — sized for multi-epoch single-node simulation.
    pub const default_pool_size: u32 = 500_000;

    /// Initialise a harness with default validator count (64).
    pub fn init(allocator: std.mem.Allocator, pool: *Node.Pool, seed: u64) !SimTestHarness {
        return initWithValidators(allocator, pool, seed, default_validator_count);
    }

    /// Initialise a harness with a specific validator count.
    pub fn initWithValidators(
        allocator: std.mem.Allocator,
        pool: *Node.Pool,
        seed: u64,
        validator_count: usize,
    ) !SimTestHarness {
        var test_state = try TestCachedBeaconState.init(allocator, pool, validator_count);

        // Create the BeaconNode and initialize from genesis.
        const node_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
        var builder = try BeaconNode.Builder.init(allocator, std.testing.io, test_state.config, .{
            .options = .{ .engine_mock = true },
            .node_identity = node_identity,
        });
        errdefer builder.deinit();

        // initFromGenesis takes ownership of the genesis state (caches it).
        // We pass the cached_state pointer — node will clone it into block_state_cache.
        // After this call, test_state.cached_state is owned by the node.
        const node = try builder.finishGenesis(test_state.cached_state);
        errdefer node.deinit();

        const sim = SimNodeHarness.init(allocator, node, seed);

        return .{
            .allocator = allocator,
            .pool = pool,
            .config = test_state.config,
            .pubkey_index_map = test_state.pubkey_index_map,
            .index_pubkey_cache = test_state.index_pubkey_cache,
            .epoch_transition_cache = test_state.epoch_transition_cache,
            .node = node,
            .sim = sim,
        };
    }

    pub fn deinit(self: *SimTestHarness) void {
        self.sim.deinit();
        // BeaconNode owns the cached states.
        self.node.deinit();

        // Free TestCachedBeaconState ancillary resources.
        self.pubkey_index_map.deinit();
        self.allocator.destroy(self.pubkey_index_map);
        self.index_pubkey_cache.deinit();
        self.epoch_transition_cache.deinit();
        state_transition.deinitStateTransition();
        self.allocator.destroy(self.epoch_transition_cache);
        self.allocator.destroy(self.index_pubkey_cache);
        self.allocator.destroy(self.config);
    }
};
