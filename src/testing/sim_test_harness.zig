//! Shared test harness for single-node deterministic simulation.
//!
//! Bootstraps a real BeaconNode against the same runtime-owned shared-state
//! graph contract used elsewhere in the codebase. The simulation harness uses
//! a published anchor state, not a fake slot-0 genesis state, because the test
//! fixture is intentionally Electra-era and finalized. The harness owns only
//! the borrowed BeaconConfig pointer plus the node/sim wrappers.

const std = @import("std");
const config_mod = @import("config");
const active_preset = @import("preset").active_preset;
const preset = @import("preset").preset;
const consensus_types = @import("consensus_types");
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

pub fn createPublishedAnchorState(
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

    const raw_slot = try raw_state.slot();
    const anchor_slot = @divFloor(raw_slot, preset.SLOTS_PER_EPOCH) * preset.SLOTS_PER_EPOCH;
    try raw_state.setSlot(anchor_slot);

    var latest_header_view = try raw_state.latestBlockHeader();
    var latest_header = consensus_types.phase0.BeaconBlockHeader.default_value;
    try latest_header_view.toValue(undefined, &latest_header);
    latest_header.slot = anchor_slot;
    if (std.mem.eql(u8, &latest_header.state_root, &([_]u8{0} ** 32))) {
        latest_header.state_root = (try raw_state.hashTreeRoot()).*;
    }
    try raw_state.setLatestBlockHeader(&latest_header);

    var anchor_block_root: [32]u8 = undefined;
    try consensus_types.phase0.BeaconBlockHeader.hashTreeRoot(&latest_header, &anchor_block_root);

    var previous_justified = consensus_types.phase0.Checkpoint.default_value;
    try raw_state.previousJustifiedCheckpoint(&previous_justified);
    previous_justified.root = anchor_block_root;
    try raw_state.setPreviousJustifiedCheckpoint(&previous_justified);

    var current_justified = consensus_types.phase0.Checkpoint.default_value;
    try raw_state.currentJustifiedCheckpoint(&current_justified);
    current_justified.root = anchor_block_root;
    try raw_state.setCurrentJustifiedCheckpoint(&current_justified);

    var finalized = consensus_types.phase0.Checkpoint.default_value;
    try raw_state.finalizedCheckpoint(&finalized);
    finalized.root = anchor_block_root;
    try raw_state.setFinalizedCheckpoint(&finalized);
    try raw_state.commit();

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

pub fn finishBuilderFromPublishedAnchor(
    builder: *BeaconNode.Builder,
    anchor_state: *CachedBeaconState,
) !*BeaconNode {
    const anchor_slot = try anchor_state.state.slot();
    if (anchor_slot == 0) return builder.finishGenesis(anchor_state);
    return builder.finishCheckpoint(anchor_state);
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

        const anchor_state = try createPublishedAnchorState(
            allocator,
            builder.sharedStateGraph(),
            validator_count,
        );
        const node = try finishBuilderFromPublishedAnchor(&builder, anchor_state);
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
