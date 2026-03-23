//! Shared test harness for single-node deterministic simulation.
//!
//! Manages the lifecycle of `TestCachedBeaconState` resources alongside a
//! `SimBeaconNode`, ensuring everything is freed exactly once even when the
//! sim replaces its head state during block processing.
//!
//! Used by both single-node tests (`sim_test.zig`) and the multi-node
//! cluster (`sim_cluster.zig`) for the primary node's resources.

const std = @import("std");
const config_mod = @import("config");
const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;

const SimBeaconNode = @import("sim_beacon_node.zig").SimBeaconNode;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

pub const SimTestHarness = struct {
    allocator: std.mem.Allocator,
    pool: *Node.Pool,

    /// Ancillary resources from `TestCachedBeaconState` that outlive the
    /// evolving state. Freed on deinit.
    config: *config_mod.BeaconConfig,
    pubkey_index_map: *state_transition.PubkeyIndexMap,
    index_pubkey_cache: *state_transition.Index2PubkeyCache,
    epoch_transition_cache: *state_transition.EpochTransitionCache,

    /// The simulation node.
    sim: SimBeaconNode,

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

        const sim = try SimBeaconNode.init(allocator, test_state.cached_state, seed);

        return .{
            .allocator = allocator,
            .pool = pool,
            .config = test_state.config,
            .pubkey_index_map = test_state.pubkey_index_map,
            .index_pubkey_cache = test_state.index_pubkey_cache,
            .epoch_transition_cache = test_state.epoch_transition_cache,
            .sim = sim,
        };
    }

    pub fn deinit(self: *SimTestHarness) void {
        // Free the sim's current head state (may differ from original).
        self.sim.head_state.deinit();
        self.allocator.destroy(self.sim.head_state);
        self.sim.deinit();

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
