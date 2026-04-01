//! Beacon node construction, teardown, and bootstrap flows.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const MemoryCPStateDatastore = state_transition.MemoryCPStateDatastore;
const StateRegen = state_transition.StateRegen;
const bls_mod = @import("bls");
const BlsThreadPool = bls_mod.ThreadPool;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;
const LmdbKVStore = db_mod.LmdbKVStore;
const chain_mod = @import("chain");
const Chain = chain_mod.Chain;
const QueuedStateRegen = chain_mod.QueuedStateRegen;
const OpPool = chain_mod.OpPool;
const SeenCache = chain_mod.SeenCache;
const SyncContributionAndProofPool = chain_mod.SyncContributionAndProofPool;
const SyncCommitteeMessagePool = chain_mod.SyncCommitteeMessagePool;
const ValidatorMonitor = chain_mod.ValidatorMonitor;
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;
const ApiNodeIdentity = api_mod.types.NodeIdentity;
const identity_mod = @import("identity.zig");
const sync_mod = @import("sync");
const UnknownBlockSync = sync_mod.UnknownBlockSync;
const UnknownChainSync = sync_mod.UnknownChainSync;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const CheckpointWithPayloadStatus = fork_choice_mod.CheckpointWithPayloadStatus;
const execution_mod = @import("execution");
const EngineApi = execution_mod.EngineApi;
const MockEngine = execution_mod.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const IoHttpTransport = execution_mod.IoHttpTransport;
const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const QueueConfig = processor_mod.QueueConfig;
const SlotClock = @import("clock.zig").SlotClock;
const NodeOptions = @import("options.zig").NodeOptions;
const InitConfig = @import("beacon_node.zig").BeaconNode.InitConfig;

pub fn init(allocator: Allocator, io: std.Io, beacon_config: *const BeaconConfig, init_config: InitConfig) !*BeaconNode {
    const opts = init_config.options;
    const bls_thread_pool = try initBlsThreadPool(allocator, io);
    errdefer bls_thread_pool.deinit();

    var node_identity = init_config.node_identity;
    errdefer {
        node_identity.deinit();
    }
    const api_node_identity = try initApiNodeIdentity(allocator, opts, &node_identity);
    errdefer deinitApiNodeIdentity(allocator, api_node_identity);

    var kv_backend: BeaconNode.KVBackend = undefined;
    var kv_iface: db_mod.KVStore = undefined;

    if (init_config.db_path) |db_path| {
        const z_path = try allocator.dupeZ(u8, db_path);
        defer allocator.free(z_path);

        const lmdb_store = try allocator.create(LmdbKVStore);
        errdefer allocator.destroy(lmdb_store);

        lmdb_store.* = LmdbKVStore.open(allocator, z_path, .{
            .map_size = 256 * 1024 * 1024 * 1024,
        }) catch |err| {
            allocator.destroy(lmdb_store);
            return err;
        };
        errdefer lmdb_store.deinit();

        kv_backend = .{ .lmdb = lmdb_store };
        kv_iface = lmdb_store.kvStore();
    } else {
        const mem_store = try allocator.create(MemoryKVStore);
        errdefer allocator.destroy(mem_store);
        mem_store.* = MemoryKVStore.init(allocator);
        errdefer mem_store.deinit();

        kv_backend = .{ .memory = mem_store };
        kv_iface = mem_store.kvStore();
    }

    const db = try allocator.create(BeaconDB);
    errdefer allocator.destroy(db);
    db.* = BeaconDB.init(allocator, kv_iface);
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

    const sync_contrib_pool = try allocator.create(SyncContributionAndProofPool);
    errdefer allocator.destroy(sync_contrib_pool);
    sync_contrib_pool.* = SyncContributionAndProofPool.init(allocator);
    errdefer sync_contrib_pool.deinit();

    const sync_msg_pool = try allocator.create(SyncCommitteeMessagePool);
    errdefer allocator.destroy(sync_msg_pool);
    sync_msg_pool.* = SyncCommitteeMessagePool.init(allocator);
    errdefer sync_msg_pool.deinit();

    const seen_cache = try allocator.create(SeenCache);
    errdefer allocator.destroy(seen_cache);
    seen_cache.* = SeenCache.init(allocator);
    errdefer seen_cache.deinit();

    const chain_struct = try allocator.create(Chain);
    errdefer allocator.destroy(chain_struct);
    chain_struct.* = Chain.init(
        allocator,
        beacon_config,
        block_cache,
        cp_cache,
        regen,
        db,
        op_pool,
        seen_cache,
        head_tracker,
    );
    errdefer chain_struct.deinit();
    chain_struct.verify_signatures = opts.verify_signatures;
    chain_struct.queued_regen = queued_regen;

    const api_head = try allocator.create(api_mod.context.HeadTracker);
    errdefer allocator.destroy(api_head);
    api_head.* = .{
        .head_slot = 0,
        .head_root = [_]u8{0} ** 32,
        .head_state_root = [_]u8{0} ** 32,
        .finalized_slot = 0,
        .finalized_root = [_]u8{0} ** 32,
        .justified_slot = 0,
        .justified_root = [_]u8{0} ** 32,
    };

    const api_sync = try allocator.create(api_mod.context.SyncStatus);
    errdefer allocator.destroy(api_sync);
    api_sync.* = .{
        .head_slot = 0,
        .sync_distance = 0,
        .is_syncing = false,
        .is_optimistic = false,
        .el_offline = false,
    };

    const api_regen = try allocator.create(api_mod.context.StateRegen);
    errdefer allocator.destroy(api_regen);
    api_regen.* = .{};

    const event_bus_ptr = try allocator.create(api_mod.EventBus);
    errdefer allocator.destroy(event_bus_ptr);
    event_bus_ptr.* = api_mod.EventBus.init(allocator);

    const api_ctx = try allocator.create(ApiContext);
    errdefer allocator.destroy(api_ctx);
    api_ctx.* = .{
        .head_tracker = api_head,
        .regen = api_regen,
        .db = db,
        .node_identity = api_node_identity,
        .sync_status = api_sync,
        .beacon_config = beacon_config,
        .allocator = allocator,
        .event_bus = event_bus_ptr,
    };

    var mock_engine_ptr: ?*MockEngine = null;
    var http_engine_ptr: ?*HttpEngine = null;
    var io_transport_ptr: ?*IoHttpTransport = null;
    var engine: ?EngineApi = null;

    if (opts.engine_mock) {
        const mock = try allocator.create(MockEngine);
        errdefer allocator.destroy(mock);
        mock.* = MockEngine.init(allocator);
        errdefer mock.deinit();

        mock_engine_ptr = mock;
        engine = mock.engine();
        log.logger(.node).info("Execution engine: MockEngine (--engine-mock)", .{});
    } else if (opts.execution_urls.len > 0) {
        const transport = try allocator.create(IoHttpTransport);
        errdefer allocator.destroy(transport);
        transport.* = IoHttpTransport.init(allocator);
        transport.setIo(io);
        errdefer transport.deinit();
        io_transport_ptr = transport;

        const http_eng = try allocator.create(HttpEngine);
        errdefer allocator.destroy(http_eng);
        http_eng.* = HttpEngine.init(
            allocator,
            opts.execution_urls[0],
            init_config.jwt_secret,
            transport.transport(),
        );
        http_eng.setIo(io);
        errdefer http_eng.deinit();
        http_engine_ptr = http_eng;
        engine = http_eng.engine();
        std.log.info("Execution engine: HttpEngine -> {s}", .{opts.execution_urls[0]});
    } else {
        const mock = try allocator.create(MockEngine);
        errdefer allocator.destroy(mock);
        mock.* = MockEngine.init(allocator);
        errdefer mock.deinit();

        mock_engine_ptr = mock;
        engine = mock.engine();
        log.logger(.node).info("Execution engine: MockEngine (no --execution-url)", .{});
    }

    const node = try allocator.create(BeaconNode);
    errdefer allocator.destroy(node);
    node.* = .{
        .allocator = allocator,
        .config = beacon_config,
        .bootstrap_peers = init_config.bootstrap_peers,
        .discovery_bootnodes = init_config.discovery_bootnodes,
        .identify_agent_version = init_config.identify_agent_version,
        .node_options = opts,
        .db = db,
        .state_regen = regen,
        .queued_regen = queued_regen,
        .block_state_cache = block_cache,
        .checkpoint_state_cache = cp_cache,
        .head_tracker = head_tracker,
        .fork_choice = null,
        .op_pool = op_pool,
        .sync_contribution_pool = sync_contrib_pool,
        .sync_committee_message_pool = sync_msg_pool,
        .seen_cache = seen_cache,
        .chain = chain_struct,
        .clock = null,
        .io = io,
        .bls_thread_pool = bls_thread_pool,
        .node_identity = node_identity,
        .mock_engine = mock_engine_ptr,
        .http_engine = http_engine_ptr,
        .io_transport = io_transport_ptr,
        .engine_api = engine,
        .cp_datastore = cp_datastore,
        .kv_backend = kv_backend,
        .api_context = api_ctx,
        .api_head_tracker = api_head,
        .api_sync_status = api_sync,
        .api_node_identity = api_node_identity,
        .event_bus = event_bus_ptr,
        .unknown_block_sync = UnknownBlockSync.init(allocator),
        .unknown_chain_sync = UnknownChainSync.init(allocator),
    };
    errdefer deinit(node);

    if (opts.validator_monitor_indices.len > 0) {
        const vm = try allocator.create(ValidatorMonitor);
        vm.* = ValidatorMonitor.init(allocator, opts.validator_monitor_indices);
        node.validator_monitor = vm;
        chain_struct.validator_monitor = vm;
        log.logger(.node).info("Validator monitor: tracking {d} validators", .{opts.validator_monitor_indices.len});
    }

    node.api_bindings = try api_callbacks_mod.ApiBindings.init(allocator, node, beacon_config);

    const beacon_processor = try allocator.create(BeaconProcessor);
    beacon_processor.* = try BeaconProcessor.init(
        allocator,
        QueueConfig.default,
        &beacon_node_mod.processorHandlerCallback,
        @ptrCast(node),
    );
    node.beacon_processor = beacon_processor;

    log.logger(.node).info("beacon node initialized", .{});
    return node;
}

pub fn deinit(self: *BeaconNode) void {
    const allocator = self.allocator;

    self.chain.deinit();
    allocator.destroy(self.chain);

    self.seen_cache.deinit();
    allocator.destroy(self.seen_cache);

    self.op_pool.deinit();
    allocator.destroy(self.op_pool);

    if (self.sync_contribution_pool) |pool| {
        pool.deinit();
        allocator.destroy(pool);
    }
    if (self.sync_committee_message_pool) |pool| {
        pool.deinit();
        allocator.destroy(pool);
    }

    self.head_tracker.deinit();
    allocator.destroy(self.head_tracker);

    if (self.mock_engine) |me| {
        me.deinit();
        allocator.destroy(me);
    }

    if (self.http_engine) |he| {
        he.deinit();
        allocator.destroy(he);
    }

    if (self.io_transport) |pt| {
        pt.deinit();
        allocator.destroy(pt);
    }

    if (self.fork_choice) |fc| {
        fork_choice_mod.destroyFromAnchor(allocator, fc);
    }

    if (self.api_bindings) |bindings| {
        bindings.deinit(allocator);
        allocator.destroy(bindings);
    }

    deinitApiNodeIdentity(allocator, self.api_node_identity);
    self.node_identity.deinit();
    allocator.destroy(self.api_context.regen);
    allocator.destroy(self.api_context);
    allocator.destroy(self.api_head_tracker);
    allocator.destroy(self.api_sync_status);
    allocator.destroy(self.event_bus);

    self.queued_regen.deinit();
    allocator.destroy(self.queued_regen);
    allocator.destroy(self.state_regen);

    self.checkpoint_state_cache.deinit();
    allocator.destroy(self.checkpoint_state_cache);

    self.block_state_cache.deinit();
    allocator.destroy(self.block_state_cache);

    self.cp_datastore.deinit();
    allocator.destroy(self.cp_datastore);

    self.db.close();
    allocator.destroy(self.db);

    switch (self.kv_backend) {
        .memory => |mem| {
            mem.deinit();
            allocator.destroy(mem);
        },
        .lmdb => |lmdb_store| {
            lmdb_store.deinit();
            allocator.destroy(lmdb_store);
        },
    }

    if (self.beacon_processor) |bp| {
        allocator.destroy(bp);
    }

    p2p_runtime_mod.deinitOwnedState(self);

    self.unknown_block_sync.deinit();
    self.unknown_chain_sync.deinit();

    if (self.validator_monitor) |vm| {
        vm.deinit();
        allocator.destroy(vm);
    }

    self.bls_thread_pool.deinit();

    allocator.destroy(self);
}

fn initBlsThreadPool(allocator: Allocator, io: std.Io) !*BlsThreadPool {
    const cpu_count = std.Thread.getCpuCount() catch 4;
    const n_workers: u16 = @intCast(@max(@min(cpu_count / 2, BlsThreadPool.MAX_WORKERS), 1));
    const pool = try BlsThreadPool.init(allocator, io, .{ .n_workers = n_workers });
    log.logger(.node).info("BLS thread pool initialized with {d} workers", .{pool.n_workers});
    return pool;
}

fn initApiNodeIdentity(
    allocator: Allocator,
    opts: NodeOptions,
    node_identity: *const identity_mod.NodeIdentity,
) !*ApiNodeIdentity {
    const identity = try allocator.create(ApiNodeIdentity);
    errdefer allocator.destroy(identity);

    const p2p_addresses = try buildAdvertisedAddresses(allocator, opts, node_identity.peer_id, .p2p);
    errdefer freeAddressList(allocator, p2p_addresses);

    const discovery_addresses = try buildAdvertisedAddresses(allocator, opts, node_identity.peer_id, .discovery);
    errdefer freeAddressList(allocator, discovery_addresses);

    identity.* = .{
        .peer_id = try allocator.dupe(u8, node_identity.peer_id),
        .enr = try allocator.dupe(u8, node_identity.enr),
        .p2p_addresses = p2p_addresses,
        .discovery_addresses = discovery_addresses,
        .metadata = .{
            .seq_number = 1,
            .attnets = [_]u8{0} ** 8,
            .syncnets = [_]u8{0} ** 1,
        },
    };
    return identity;
}

fn deinitApiNodeIdentity(allocator: Allocator, identity: *ApiNodeIdentity) void {
    if (identity.peer_id.len > 0) allocator.free(identity.peer_id);
    if (identity.enr.len > 0) allocator.free(identity.enr);

    freeAddressList(allocator, identity.p2p_addresses);
    freeAddressList(allocator, identity.discovery_addresses);

    allocator.destroy(identity);
}

const AddressKind = enum {
    p2p,
    discovery,
};

fn buildAdvertisedAddresses(
    allocator: Allocator,
    opts: NodeOptions,
    peer_id: []const u8,
    kind: AddressKind,
) ![]const []const u8 {
    var addresses: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeAddressList(allocator, addresses.items);

    if (opts.enr_ip) |ip| {
        try appendAdvertisedAddress(allocator, &addresses, .ip4, ip, opts, peer_id, kind);
    } else if (!std.mem.eql(u8, opts.p2p_host, "0.0.0.0")) {
        try appendAdvertisedAddress(allocator, &addresses, .ip4, opts.p2p_host, opts, peer_id, kind);
    }

    if (opts.enr_ip6) |ip6| {
        try appendAdvertisedAddress(allocator, &addresses, .ip6, ip6, opts, peer_id, kind);
    }

    return addresses.toOwnedSlice(allocator);
}

const IpFamily = enum {
    ip4,
    ip6,
};

fn appendAdvertisedAddress(
    allocator: Allocator,
    addresses: *std.ArrayListUnmanaged([]const u8),
    family: IpFamily,
    ip: []const u8,
    opts: NodeOptions,
    peer_id: []const u8,
    kind: AddressKind,
) !void {
    const proto = switch (family) {
        .ip4 => "ip4",
        .ip6 => "ip6",
    };
    const transport = switch (kind) {
        .p2p => "tcp",
        .discovery => "udp",
    };
    const port = switch (kind) {
        .p2p => switch (family) {
            .ip4 => opts.enr_tcp orelse opts.p2p_port,
            .ip6 => opts.enr_tcp6 orelse opts.p2p_port,
        },
        .discovery => switch (family) {
            .ip4 => opts.enr_udp orelse opts.discovery_port orelse opts.p2p_port,
            .ip6 => opts.enr_udp6 orelse opts.discovery_port orelse opts.p2p_port,
        },
    };

    const address = try std.fmt.allocPrint(allocator, "/{s}/{s}/{s}/{d}/p2p/{s}", .{
        proto,
        ip,
        transport,
        port,
        peer_id,
    });
    try addresses.append(allocator, address);
}

fn freeAddressList(allocator: Allocator, addresses: []const []const u8) void {
    for (addresses) |address| allocator.free(address);
    if (addresses.len > 0) allocator.free(addresses);
}

pub fn initFromGenesis(self: *BeaconNode, genesis_state: *CachedBeaconState) !void {
    try genesis_state.state.commit();

    var genesis_header = try genesis_state.state.latestBlockHeader();
    const genesis_block_root = (try genesis_header.hashTreeRoot()).*;
    const genesis_slot = try genesis_state.state.slot();

    const state_root = try self.queued_regen.onNewBlock(genesis_state, true);

    try self.chain.registerGenesisRoot(genesis_block_root, state_root);
    try self.head_tracker.onBlock(genesis_block_root, genesis_slot, state_root);

    self.genesis_validators_root = (try genesis_state.state.genesisValidatorsRoot()).*;
    self.chain.genesis_validators_root = self.genesis_validators_root;
    log.logger(.node).info("initialized from genesis", .{
        .slot = genesis_slot,
        .genesis_validators_root = self.genesis_validators_root,
    });

    const genesis_time = try genesis_state.state.genesisTime();
    self.clock = SlotClock.fromGenesis(genesis_time, self.config.chain);
    self.chain.genesis_time_s = genesis_time;
    self.api_context.genesis_time = genesis_time;

    var genesis_justified_cp: types.phase0.Checkpoint.Type = undefined;
    try genesis_state.state.currentJustifiedCheckpoint(&genesis_justified_cp);
    var genesis_finalized_cp: types.phase0.Checkpoint.Type = undefined;
    try genesis_state.state.finalizedCheckpoint(&genesis_finalized_cp);

    const genesis_balances = genesis_state.epoch_cache.getEffectiveBalanceIncrements();
    const justified_root = genesis_block_root;
    const finalized_root = genesis_block_root;

    const fc_anchor = ProtoBlock{
        .slot = 0,
        .block_root = genesis_block_root,
        .parent_root = genesis_block_root,
        .state_root = state_root,
        .target_root = genesis_block_root,
        .justified_epoch = genesis_justified_cp.epoch,
        .justified_root = justified_root,
        .finalized_epoch = genesis_finalized_cp.epoch,
        .finalized_root = finalized_root,
        .unrealized_justified_epoch = genesis_justified_cp.epoch,
        .unrealized_justified_root = justified_root,
        .unrealized_finalized_epoch = genesis_finalized_cp.epoch,
        .unrealized_finalized_root = finalized_root,
        .extra_meta = .{ .pre_merge = {} },
        .timeliness = true,
    };

    const fc = try fork_choice_mod.initFromAnchor(
        self.allocator,
        self.config,
        fc_anchor,
        genesis_slot,
        CheckpointWithPayloadStatus.fromCheckpoint(.{
            .epoch = genesis_justified_cp.epoch,
            .root = justified_root,
        }, .full),
        CheckpointWithPayloadStatus.fromCheckpoint(.{
            .epoch = genesis_finalized_cp.epoch,
            .root = finalized_root,
        }, .full),
        genesis_balances.items,
        .{ .getFn = beacon_node_mod.dummyBalancesGetterFn },
        .{},
        .{},
    );

    if (self.fork_choice) |old_fc| {
        fork_choice_mod.destroyFromAnchor(self.allocator, old_fc);
    }
    self.fork_choice = fc;
    self.chain.fork_choice = fc;
    self.chain.genesis_validators_root = self.genesis_validators_root;

    self.api_head_tracker.head_slot = 0;
    self.api_head_tracker.head_root = genesis_block_root;
    self.api_head_tracker.head_state_root = state_root;
}

pub fn initFromCheckpoint(self: *BeaconNode, checkpoint_state: *CachedBeaconState) !void {
    try checkpoint_state.state.commit();
    const state_root = (try checkpoint_state.state.hashTreeRoot()).*;

    var cp_header = try checkpoint_state.state.latestBlockHeader();
    const header_slot = try cp_header.get("slot");
    const header_proposer = try cp_header.get("proposer_index");
    const header_parent = (try cp_header.getFieldRoot("parent_root")).*;
    const header_body = (try cp_header.getFieldRoot("body_root")).*;

    var header_state_root = (try cp_header.getFieldRoot("state_root")).*;
    if (std.mem.eql(u8, &header_state_root, &([_]u8{0} ** 32))) {
        header_state_root = state_root;
    }

    const cp_header_val = types.phase0.BeaconBlockHeader.Type{
        .slot = header_slot,
        .proposer_index = header_proposer,
        .parent_root = header_parent,
        .state_root = header_state_root,
        .body_root = header_body,
    };
    var anchor_block_root: [32]u8 = undefined;
    try types.phase0.BeaconBlockHeader.hashTreeRoot(&cp_header_val, &anchor_block_root);

    const cp_slot = try checkpoint_state.state.slot();

    std.log.info("Checkpoint anchor: slot={d} block_root=0x{s}...", .{
        cp_slot,
        &std.fmt.bytesToHex(anchor_block_root[0..8], .lower),
    });

    const cached_state_root = try self.queued_regen.onNewBlock(checkpoint_state, true);

    try self.chain.registerGenesisRoot(anchor_block_root, cached_state_root);
    try self.head_tracker.onBlock(anchor_block_root, cp_slot, cached_state_root);

    self.genesis_validators_root = (try checkpoint_state.state.genesisValidatorsRoot()).*;
    self.chain.genesis_validators_root = self.genesis_validators_root;
    std.log.info("Genesis validators root: 0x{s}...", .{
        &std.fmt.bytesToHex(self.genesis_validators_root[0..8], .lower),
    });

    const genesis_time = try checkpoint_state.state.genesisTime();
    self.clock = SlotClock.fromGenesis(genesis_time, self.config.chain);
    self.chain.genesis_time_s = genesis_time;
    self.api_context.genesis_time = genesis_time;

    var justified_cp: types.phase0.Checkpoint.Type = undefined;
    try checkpoint_state.state.currentJustifiedCheckpoint(&justified_cp);
    var finalized_cp: types.phase0.Checkpoint.Type = undefined;
    try checkpoint_state.state.finalizedCheckpoint(&finalized_cp);

    const balances = checkpoint_state.epoch_cache.getEffectiveBalanceIncrements();
    const cp_justified_root = anchor_block_root;
    const cp_finalized_root = anchor_block_root;

    const fc_anchor = ProtoBlock{
        .slot = cp_slot,
        .block_root = anchor_block_root,
        .parent_root = anchor_block_root,
        .state_root = cached_state_root,
        .target_root = anchor_block_root,
        .justified_epoch = justified_cp.epoch,
        .justified_root = cp_justified_root,
        .finalized_epoch = finalized_cp.epoch,
        .finalized_root = cp_finalized_root,
        .unrealized_justified_epoch = justified_cp.epoch,
        .unrealized_justified_root = cp_justified_root,
        .unrealized_finalized_epoch = finalized_cp.epoch,
        .unrealized_finalized_root = cp_finalized_root,
        .extra_meta = .{ .pre_merge = {} },
        .timeliness = true,
    };

    const fc = try fork_choice_mod.initFromAnchor(
        self.allocator,
        self.config,
        fc_anchor,
        cp_slot,
        CheckpointWithPayloadStatus.fromCheckpoint(.{
            .epoch = justified_cp.epoch,
            .root = cp_justified_root,
        }, .full),
        CheckpointWithPayloadStatus.fromCheckpoint(.{
            .epoch = finalized_cp.epoch,
            .root = cp_finalized_root,
        }, .full),
        balances.items,
        .{ .getFn = beacon_node_mod.dummyBalancesGetterFn },
        .{},
        .{},
    );

    if (self.fork_choice) |old_fc| {
        fork_choice_mod.destroyFromAnchor(self.allocator, old_fc);
    }
    self.fork_choice = fc;
    self.chain.fork_choice = fc;
    self.chain.genesis_validators_root = self.genesis_validators_root;

    self.api_head_tracker.head_slot = cp_slot;
    self.api_head_tracker.head_root = anchor_block_root;
    self.api_head_tracker.head_state_root = cached_state_root;
    self.api_head_tracker.finalized_slot = finalized_cp.epoch * preset.SLOTS_PER_EPOCH;
    self.api_head_tracker.justified_slot = justified_cp.epoch * preset.SLOTS_PER_EPOCH;

    log.logger(.node).info("initialized from checkpoint", .{
        .slot = cp_slot,
        .finalized_epoch = finalized_cp.epoch,
        .justified_epoch = justified_cp.epoch,
        .block_root = anchor_block_root,
    });
}

const log = @import("log");
const api_callbacks_mod = @import("api_callbacks.zig");
const p2p_runtime_mod = @import("p2p_runtime.zig");
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
const HeadTracker = beacon_node_mod.HeadTracker;
