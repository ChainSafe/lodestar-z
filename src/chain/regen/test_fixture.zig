const std = @import("std");
const Allocator = std.mem.Allocator;

const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const active_preset = @import("preset").active_preset;
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const SharedValidatorPubkeys = state_transition.SharedValidatorPubkeys;
const generateElectraState = state_transition.test_utils.generateElectraState;
const BlockStateCache = @import("block_state_cache.zig").BlockStateCache;
const CheckpointStateCache = @import("checkpoint_state_cache.zig").CheckpointStateCache;
const MemoryCPStateDatastore = @import("datastore.zig").MemoryCPStateDatastore;
const SharedStateGraph = @import("shared_state_graph.zig").SharedStateGraph;
const StateDisposer = @import("state_disposer.zig").StateDisposer;
const StateGraphGate = @import("state_graph_gate.zig").StateGraphGate;
const StateRegen = @import("state_regen.zig").StateRegen;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;

const active_chain_config = if (active_preset == .mainnet)
    config_mod.mainnet.chain_config
else
    config_mod.minimal.chain_config;

pub const RegenRuntimeFixture = struct {
    allocator: Allocator,
    shared_state_graph: *SharedStateGraph,
    block_cache: *BlockStateCache,
    cp_datastore: *MemoryCPStateDatastore,
    cp_cache: *CheckpointStateCache,
    mem_kv: *MemoryKVStore,
    db: *BeaconDB,
    regen: *StateRegen,
    published_state: *CachedBeaconState,

    pub fn init(allocator: Allocator, validator_count: usize) !RegenRuntimeFixture {
        const pool = try allocator.create(Node.Pool);
        errdefer allocator.destroy(pool);
        pool.* = try Node.Pool.init(allocator, 256 * 5);
        errdefer pool.deinit();

        const raw_state = try generateElectraState(allocator, pool, active_chain_config, validator_count);
        errdefer {
            raw_state.deinit();
            allocator.destroy(raw_state);
        }

        const config = try allocator.create(BeaconConfig);
        errdefer allocator.destroy(config);
        config.* = BeaconConfig.init(active_chain_config, (try raw_state.genesisValidatorsRoot()).*);

        const shared_pubkeys = try allocator.create(SharedValidatorPubkeys);
        errdefer allocator.destroy(shared_pubkeys);
        shared_pubkeys.* = SharedValidatorPubkeys.init(allocator);
        errdefer shared_pubkeys.deinit();

        const validators = try raw_state.validatorsSlice(allocator);
        defer allocator.free(validators);
        try shared_pubkeys.syncFromValidators(validators);

        const published_state = try CachedBeaconState.createCachedBeaconState(
            allocator,
            raw_state,
            state_transition.metrics.noop(),
            shared_pubkeys.immutableData(config),
            .{
                .skip_sync_committee_cache = raw_state.forkSeq() == .phase0,
                .skip_sync_pubkeys = true,
            },
        );
        errdefer {
            published_state.deinit();
            allocator.destroy(published_state);
        }

        const state_disposer = try allocator.create(StateDisposer);
        errdefer allocator.destroy(state_disposer);
        state_disposer.* = StateDisposer.init(allocator, std.testing.io);
        errdefer state_disposer.deinit();

        const state_graph_gate = try allocator.create(StateGraphGate);
        errdefer allocator.destroy(state_graph_gate);
        state_graph_gate.* = StateGraphGate.init(std.testing.io, state_disposer);

        const shared_state_graph = try allocator.create(SharedStateGraph);
        errdefer allocator.destroy(shared_state_graph);
        shared_state_graph.* = .{
            .config = config,
            .pool = pool,
            .validator_pubkeys = shared_pubkeys,
            .state_disposer = state_disposer,
            .gate = state_graph_gate,
            .state_transition_metrics = state_transition.metrics.noop(),
        };

        const block_cache = try allocator.create(BlockStateCache);
        errdefer allocator.destroy(block_cache);
        block_cache.* = BlockStateCache.init(allocator, 4, shared_state_graph.state_disposer);
        errdefer block_cache.deinit();

        const cp_datastore = try allocator.create(MemoryCPStateDatastore);
        errdefer allocator.destroy(cp_datastore);
        cp_datastore.* = MemoryCPStateDatastore.init(allocator);
        errdefer cp_datastore.deinit();

        const cp_cache = try allocator.create(CheckpointStateCache);
        errdefer allocator.destroy(cp_cache);
        cp_cache.* = CheckpointStateCache.init(
            allocator,
            cp_datastore.datastore(),
            block_cache,
            3,
            shared_state_graph.state_disposer,
            shared_state_graph.gate,
        );
        errdefer cp_cache.deinit();

        const mem_kv = try allocator.create(MemoryKVStore);
        errdefer allocator.destroy(mem_kv);
        mem_kv.* = MemoryKVStore.init(allocator);
        errdefer mem_kv.deinit();

        const db = try allocator.create(BeaconDB);
        errdefer allocator.destroy(db);
        db.* = BeaconDB.init(allocator, mem_kv.kvStore());
        errdefer db.close();

        const regen = try allocator.create(StateRegen);
        errdefer allocator.destroy(regen);
        regen.* = StateRegen.initForRuntime(
            allocator,
            block_cache,
            cp_cache,
            db,
            shared_state_graph,
        );

        return .{
            .allocator = allocator,
            .shared_state_graph = shared_state_graph,
            .block_cache = block_cache,
            .cp_datastore = cp_datastore,
            .cp_cache = cp_cache,
            .mem_kv = mem_kv,
            .db = db,
            .regen = regen,
            .published_state = published_state,
        };
    }

    pub fn deinit(self: *RegenRuntimeFixture) void {
        self.published_state.deinit();
        self.allocator.destroy(self.published_state);

        self.allocator.destroy(self.regen);

        self.cp_cache.deinit();
        self.allocator.destroy(self.cp_cache);

        self.cp_datastore.deinit();
        self.allocator.destroy(self.cp_datastore);

        self.block_cache.deinit();
        self.allocator.destroy(self.block_cache);

        self.db.close();
        self.allocator.destroy(self.db);

        self.mem_kv.deinit();
        self.allocator.destroy(self.mem_kv);

        self.allocator.destroy(self.shared_state_graph.gate);

        self.shared_state_graph.state_disposer.deinit();
        self.allocator.destroy(self.shared_state_graph.state_disposer);

        self.shared_state_graph.validator_pubkeys.deinit();
        self.allocator.destroy(self.shared_state_graph.validator_pubkeys);

        self.allocator.destroy(@constCast(self.shared_state_graph.config));

        self.shared_state_graph.pool.deinit();
        self.allocator.destroy(self.shared_state_graph.pool);

        self.allocator.destroy(self.shared_state_graph);

        state_transition.deinitStateTransition();
    }

    pub fn clonePublishedState(self: *RegenRuntimeFixture) !*CachedBeaconState {
        return self.published_state.clone(self.allocator, .{});
    }

    pub fn seedHeadState(self: *RegenRuntimeFixture) ![32]u8 {
        const state = try self.clonePublishedState();
        return self.regen.onNewBlock(state, true);
    }
};
