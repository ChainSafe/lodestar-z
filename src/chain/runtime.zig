//! Chain runtime — owns the hot chain subsystem graph.
//!
//! This is the production ownership boundary for chain state. `Chain` remains
//! the coordinator over these components, but the allocation and teardown of
//! the chain graph now lives in the chain module instead of `node/lifecycle`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const MemoryCPStateDatastore = state_transition.MemoryCPStateDatastore;
const StateRegen = state_transition.StateRegen;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;
const LmdbKVStore = db_mod.LmdbKVStore;

const Chain = @import("chain.zig").Chain;
const HeadTracker = @import("block_import.zig").HeadTracker;
const QueuedStateRegen = @import("queued_regen.zig").QueuedStateRegen;
const OpPool = @import("op_pool.zig").OpPool;
const SeenCache = @import("seen_cache.zig").SeenCache;
const sync_contribution_pool_mod = @import("sync_contribution_pool.zig");
const SyncContributionAndProofPool = sync_contribution_pool_mod.SyncContributionAndProofPool;
const SyncCommitteeMessagePool = sync_contribution_pool_mod.SyncCommitteeMessagePool;
const ValidatorMonitor = @import("validator_monitor.zig").ValidatorMonitor;
const BeaconProposerCache = @import("beacon_proposer_cache.zig").BeaconProposerCache;
const DataAvailabilityManager = @import("data_availability.zig").DataAvailabilityManager;
const PendingBlockIngress = @import("block_ingress.zig").PendingBlockIngress;
const PayloadEnvelopeIngress = @import("payload_envelope_ingress.zig").PayloadEnvelopeIngress;
const kzg_mod = @import("kzg");
const Kzg = kzg_mod.Kzg;

pub const RuntimeOptions = struct {
    max_block_states: u32 = 64,
    max_checkpoint_epochs: u32 = 3,
    verify_signatures: bool = false,
    validator_monitor_indices: []const u64 = &.{},
    custody_columns: []const u64 = &.{},
};

pub const StorageBackend = union(enum) {
    memory: *MemoryKVStore,
    lmdb: *LmdbKVStore,

    pub fn kvStore(self: StorageBackend) db_mod.KVStore {
        return switch (self) {
            .memory => |store| store.kvStore(),
            .lmdb => |store| store.kvStore(),
        };
    }

    pub fn deinit(self: StorageBackend, allocator: Allocator) void {
        switch (self) {
            .memory => |store| {
                store.deinit();
                allocator.destroy(store);
            },
            .lmdb => |store| {
                store.deinit();
                allocator.destroy(store);
            },
        }
    }
};

pub const Runtime = struct {
    allocator: Allocator,
    config: *const BeaconConfig,
    storage_backend: StorageBackend,
    db: *BeaconDB,
    cp_datastore: *MemoryCPStateDatastore,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    state_regen: *StateRegen,
    queued_regen: *QueuedStateRegen,
    head_tracker: *HeadTracker,
    op_pool: *OpPool,
    seen_cache: *SeenCache,
    sync_contribution_pool: *SyncContributionAndProofPool,
    sync_committee_message_pool: *SyncCommitteeMessagePool,
    beacon_proposer_cache: *BeaconProposerCache,
    custody_columns: []u64,
    kzg: *Kzg,
    da_manager: *DataAvailabilityManager,
    pending_block_ingress: *PendingBlockIngress,
    payload_envelope_ingress: *PayloadEnvelopeIngress,
    validator_monitor: ?*ValidatorMonitor = null,
    chain: *Chain,

    pub fn init(
        allocator: Allocator,
        config: *const BeaconConfig,
        storage_backend: StorageBackend,
        opts: RuntimeOptions,
    ) !*Runtime {
        const runtime = try allocator.create(Runtime);
        errdefer allocator.destroy(runtime);

        const db = try allocator.create(BeaconDB);
        errdefer allocator.destroy(db);
        db.* = BeaconDB.init(allocator, storage_backend.kvStore());
        errdefer db.close();

        const block_cache = try allocator.create(BlockStateCache);
        errdefer allocator.destroy(block_cache);
        block_cache.* = BlockStateCache.init(allocator, opts.max_block_states);
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
            opts.max_checkpoint_epochs,
        );
        errdefer cp_cache.deinit();

        const regen = try allocator.create(StateRegen);
        errdefer allocator.destroy(regen);
        regen.* = StateRegen.initWithDB(allocator, block_cache, cp_cache, db, null, null);

        const queued_regen = try allocator.create(QueuedStateRegen);
        errdefer allocator.destroy(queued_regen);
        queued_regen.* = QueuedStateRegen.init(allocator, regen);
        errdefer queued_regen.deinit();

        const head_tracker = try allocator.create(HeadTracker);
        errdefer allocator.destroy(head_tracker);
        head_tracker.* = HeadTracker.init(allocator, [_]u8{0} ** 32);
        errdefer head_tracker.deinit();

        const op_pool = try allocator.create(OpPool);
        errdefer allocator.destroy(op_pool);
        op_pool.* = OpPool.init(allocator);
        errdefer op_pool.deinit();

        const seen_cache = try allocator.create(SeenCache);
        errdefer allocator.destroy(seen_cache);
        seen_cache.* = SeenCache.init(allocator);
        errdefer seen_cache.deinit();

        const sync_contrib_pool = try allocator.create(SyncContributionAndProofPool);
        errdefer allocator.destroy(sync_contrib_pool);
        sync_contrib_pool.* = SyncContributionAndProofPool.init(allocator);
        errdefer sync_contrib_pool.deinit();

        const sync_msg_pool = try allocator.create(SyncCommitteeMessagePool);
        errdefer allocator.destroy(sync_msg_pool);
        sync_msg_pool.* = SyncCommitteeMessagePool.init(allocator);
        errdefer sync_msg_pool.deinit();

        const proposer_cache = try allocator.create(BeaconProposerCache);
        errdefer allocator.destroy(proposer_cache);
        proposer_cache.* = BeaconProposerCache.init(allocator);
        errdefer proposer_cache.deinit();

        const custody_columns = try allocator.dupe(u64, opts.custody_columns);
        errdefer allocator.free(custody_columns);

        const kzg = try allocator.create(Kzg);
        errdefer allocator.destroy(kzg);
        kzg.* = try Kzg.initBundled();
        errdefer kzg.deinit();

        const da_manager = try allocator.create(DataAvailabilityManager);
        errdefer allocator.destroy(da_manager);
        da_manager.* = DataAvailabilityManager.init(
            allocator,
            .{
                .min_epochs_for_blob_sidecars_requests = config.chain.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS,
            },
            custody_columns,
        );
        errdefer da_manager.deinit();

        const pending_block_ingress = try allocator.create(PendingBlockIngress);
        errdefer allocator.destroy(pending_block_ingress);
        pending_block_ingress.* = PendingBlockIngress.init(allocator);
        errdefer pending_block_ingress.deinit();

        const payload_envelope_ingress = try allocator.create(PayloadEnvelopeIngress);
        errdefer allocator.destroy(payload_envelope_ingress);
        payload_envelope_ingress.* = PayloadEnvelopeIngress.init(allocator);
        errdefer payload_envelope_ingress.deinit();

        const chain = try allocator.create(Chain);
        errdefer allocator.destroy(chain);
        chain.* = Chain.init(
            allocator,
            config,
            block_cache,
            cp_cache,
            regen,
            db,
            op_pool,
            seen_cache,
            head_tracker,
            proposer_cache,
        );
        errdefer chain.deinit();
        chain.verify_signatures = opts.verify_signatures;
        chain.queued_regen = queued_regen;
        chain.sync_contribution_pool = sync_contrib_pool;
        chain.sync_committee_message_pool = sync_msg_pool;
        chain.kzg = kzg;
        chain.da_manager = da_manager;
        chain.pending_block_ingress = pending_block_ingress;
        chain.payload_envelope_ingress = payload_envelope_ingress;

        runtime.* = .{
            .allocator = allocator,
            .config = config,
            .storage_backend = storage_backend,
            .db = db,
            .cp_datastore = cp_datastore,
            .block_state_cache = block_cache,
            .checkpoint_state_cache = cp_cache,
            .state_regen = regen,
            .queued_regen = queued_regen,
            .head_tracker = head_tracker,
            .op_pool = op_pool,
            .seen_cache = seen_cache,
            .sync_contribution_pool = sync_contrib_pool,
            .sync_committee_message_pool = sync_msg_pool,
            .beacon_proposer_cache = proposer_cache,
            .custody_columns = custody_columns,
            .kzg = kzg,
            .da_manager = da_manager,
            .pending_block_ingress = pending_block_ingress,
            .payload_envelope_ingress = payload_envelope_ingress,
            .chain = chain,
        };

        try runtime.setValidatorMonitor(opts.validator_monitor_indices);
        return runtime;
    }

    pub fn setValidatorMonitor(self: *Runtime, indices: []const u64) !void {
        if (self.validator_monitor) |vm| {
            vm.deinit();
            self.allocator.destroy(vm);
            self.validator_monitor = null;
            self.chain.validator_monitor = null;
        }

        if (indices.len == 0) return;

        const vm = try self.allocator.create(ValidatorMonitor);
        errdefer self.allocator.destroy(vm);
        vm.* = ValidatorMonitor.init(self.allocator, indices);
        self.validator_monitor = vm;
        self.chain.validator_monitor = vm;
    }

    pub fn deinit(self: *Runtime) void {
        self.chain.deinit();
        self.allocator.destroy(self.chain);

        if (self.validator_monitor) |vm| {
            vm.deinit();
            self.allocator.destroy(vm);
        }

        self.sync_committee_message_pool.deinit();
        self.allocator.destroy(self.sync_committee_message_pool);

        self.sync_contribution_pool.deinit();
        self.allocator.destroy(self.sync_contribution_pool);

        self.beacon_proposer_cache.deinit();
        self.allocator.destroy(self.beacon_proposer_cache);

        self.pending_block_ingress.deinit();
        self.allocator.destroy(self.pending_block_ingress);

        self.payload_envelope_ingress.deinit();
        self.allocator.destroy(self.payload_envelope_ingress);

        self.da_manager.deinit();
        self.allocator.destroy(self.da_manager);

        self.kzg.deinit();
        self.allocator.destroy(self.kzg);

        self.allocator.free(self.custody_columns);

        self.seen_cache.deinit();
        self.allocator.destroy(self.seen_cache);

        self.op_pool.deinit();
        self.allocator.destroy(self.op_pool);

        self.head_tracker.deinit();
        self.allocator.destroy(self.head_tracker);

        self.queued_regen.deinit();
        self.allocator.destroy(self.queued_regen);

        self.allocator.destroy(self.state_regen);

        self.checkpoint_state_cache.deinit();
        self.allocator.destroy(self.checkpoint_state_cache);

        self.block_state_cache.deinit();
        self.allocator.destroy(self.block_state_cache);

        self.cp_datastore.deinit();
        self.allocator.destroy(self.cp_datastore);

        self.db.close();
        self.allocator.destroy(self.db);

        self.storage_backend.deinit(self.allocator);
        self.allocator.destroy(self);
    }
};
