//! Beacon node construction, teardown, and bootstrap flows.

const std = @import("std");
const Allocator = std.mem.Allocator;

const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const bls_mod = @import("bls");
const BlsThreadPool = bls_mod.ThreadPool;
const db_mod = @import("db");
const MemoryKVStore = db_mod.MemoryKVStore;
const LmdbKVStore = db_mod.LmdbKVStore;
const chain_mod = @import("chain");
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;
const ApiNodeIdentity = api_mod.types.NodeIdentity;
const identity_mod = @import("identity.zig");
const sync_mod = @import("sync");
const SyncService = sync_mod.SyncService;
const UnknownBlockSync = sync_mod.UnknownBlockSync;
const UnknownChainSync = sync_mod.UnknownChainSync;
const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const QueueConfig = processor_mod.QueueConfig;
const SlotClock = @import("clock.zig").SlotClock;
const NodeOptions = @import("options.zig").NodeOptions;
const BeaconNodeBuilder = @import("beacon_node.zig").BeaconNode.Builder;
const InitConfig = @import("beacon_node.zig").BeaconNode.InitConfig;
const execution_port_mod = @import("execution_port.zig");
const ExecutionRuntime = @import("execution_runtime.zig").ExecutionRuntime;
const networking = @import("networking");
const PeerManager = networking.PeerManager;
const custody_mod = networking.custody;

const BlsThreadPools = struct {
    block: *BlsThreadPool,
    gossip: *BlsThreadPool,
};

pub fn init(allocator: Allocator, io: std.Io, beacon_config: *const BeaconConfig, init_config: InitConfig) !*BeaconNode {
    const opts = init_config.options;
    const bls_thread_pools = try initBlsThreadPools(allocator, io);
    errdefer {
        bls_thread_pools.gossip.deinit();
        bls_thread_pools.block.deinit();
    }

    var node_identity = init_config.node_identity;
    var owns_node_identity = true;
    errdefer if (owns_node_identity) node_identity.deinit();

    const api_node_identity = try initApiNodeIdentity(allocator, opts, &node_identity);
    var owned_api_node_identity: ?*ApiNodeIdentity = api_node_identity;
    errdefer if (owned_api_node_identity) |identity| deinitApiNodeIdentity(allocator, identity);
    const custody_columns = try custody_mod.getCustodyColumns(
        allocator,
        node_identity.node_id,
        beacon_config.chain.CUSTODY_REQUIREMENT,
    );
    defer allocator.free(custody_columns);

    var storage_backend: chain_mod.StorageBackend = undefined;

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

        storage_backend = .{ .lmdb = lmdb_store };
    } else {
        const mem_store = try allocator.create(MemoryKVStore);
        errdefer allocator.destroy(mem_store);
        mem_store.* = MemoryKVStore.init(allocator);
        errdefer mem_store.deinit();

        storage_backend = .{ .memory = mem_store };
    }

    const chain_runtime = try chain_mod.Runtime.init(
        allocator,
        io,
        beacon_config,
        storage_backend,
        .{
            .max_block_states = opts.max_block_states,
            .max_checkpoint_epochs = opts.max_checkpoint_epochs,
            .verify_signatures = opts.verify_signatures,
            .block_bls_thread_pool = bls_thread_pools.block,
            .validator_monitor_indices = opts.validator_monitor_indices,
            .custody_columns = custody_columns,
            .state_transition_metrics = init_config.state_transition_metrics,
        },
    );
    var owned_chain_runtime: ?*chain_mod.Runtime = chain_runtime;
    errdefer if (owned_chain_runtime) |runtime| runtime.deinit();

    const chain_struct = chain_runtime.chain;

    const event_bus_ptr = try allocator.create(api_mod.EventBus);
    errdefer allocator.destroy(event_bus_ptr);
    event_bus_ptr.* = api_mod.EventBus.init(allocator);

    const api_ctx = try allocator.create(ApiContext);
    errdefer allocator.destroy(api_ctx);
    api_ctx.* = .{
        .node_identity = api_node_identity,
        .beacon_config = beacon_config,
        .allocator = allocator,
        .event_bus = event_bus_ptr,
    };

    const execution_runtime = try ExecutionRuntime.init(
        allocator,
        io,
        opts,
        init_config.jwt_secret,
    );
    var owned_execution_runtime: ?*ExecutionRuntime = execution_runtime;
    errdefer if (owned_execution_runtime) |runtime| runtime.deinit();

    const node = try allocator.create(BeaconNode);
    node.* = .{
        .allocator = allocator,
        .config = beacon_config,
        .bootstrap_peers = init_config.bootstrap_peers,
        .discovery_bootnodes = init_config.discovery_bootnodes,
        .identify_agent_version = init_config.identify_agent_version,
        .chain_runtime = chain_runtime,
        .node_options = opts,
        .chain = chain_struct,
        .clock = null,
        .io = io,
        .block_bls_thread_pool = bls_thread_pools.block,
        .gossip_bls_thread_pool = bls_thread_pools.gossip,
        .node_identity = node_identity,
        .execution_runtime = execution_runtime,
        .api_context = api_ctx,
        .api_node_identity = api_node_identity,
        .event_bus = event_bus_ptr,
        .metrics = init_config.metrics,
        .published_proposals = std.AutoHashMap(BeaconNode.PublishedProposalKey, [32]u8).init(allocator),
        .unknown_block_sync = UnknownBlockSync.init(allocator),
        .unknown_chain_sync = UnknownChainSync.init(allocator),
    };

    node.validator_monitor = chain_runtime.chain.validator_monitor;
    if (chain_runtime.chain.validator_monitor != null) {
        log.logger(.node).info("Validator monitor: tracking {d} validators", .{opts.validator_monitor_indices.len});
    }

    owns_node_identity = false;
    owned_api_node_identity = null;
    owned_chain_runtime = null;
    owned_execution_runtime = null;
    errdefer deinit(node);

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

pub fn initBuilder(
    allocator: Allocator,
    io: std.Io,
    beacon_config: *const BeaconConfig,
    init_config: InitConfig,
) !BeaconNodeBuilder {
    const opts = init_config.options;
    const bls_thread_pools = try initBlsThreadPools(allocator, io);
    errdefer {
        bls_thread_pools.gossip.deinit();
        bls_thread_pools.block.deinit();
    }

    var node_identity = init_config.node_identity;
    var owns_node_identity = true;
    errdefer if (owns_node_identity) node_identity.deinit();

    const api_node_identity = try initApiNodeIdentity(allocator, opts, &node_identity);
    var owned_api_node_identity: ?*ApiNodeIdentity = api_node_identity;
    errdefer if (owned_api_node_identity) |identity| deinitApiNodeIdentity(allocator, identity);
    const custody_columns = try custody_mod.getCustodyColumns(
        allocator,
        node_identity.node_id,
        beacon_config.chain.CUSTODY_REQUIREMENT,
    );
    defer allocator.free(custody_columns);

    var storage_backend: chain_mod.StorageBackend = undefined;

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

        storage_backend = .{ .lmdb = lmdb_store };
    } else {
        const mem_store = try allocator.create(MemoryKVStore);
        errdefer allocator.destroy(mem_store);
        mem_store.* = MemoryKVStore.init(allocator);
        errdefer mem_store.deinit();

        storage_backend = .{ .memory = mem_store };
    }

    var runtime_builder = try chain_mod.RuntimeBuilder.init(
        allocator,
        io,
        beacon_config,
        storage_backend,
        .{
            .max_block_states = opts.max_block_states,
            .max_checkpoint_epochs = opts.max_checkpoint_epochs,
            .verify_signatures = opts.verify_signatures,
            .block_bls_thread_pool = bls_thread_pools.block,
            .validator_monitor_indices = opts.validator_monitor_indices,
            .custody_columns = custody_columns,
            .state_transition_metrics = init_config.state_transition_metrics,
        },
    );
    var owns_runtime_builder = true;
    errdefer if (owns_runtime_builder) runtime_builder.deinit();

    const event_bus_ptr = try allocator.create(api_mod.EventBus);
    errdefer allocator.destroy(event_bus_ptr);
    event_bus_ptr.* = api_mod.EventBus.init(allocator);

    const api_ctx = try allocator.create(ApiContext);
    errdefer allocator.destroy(api_ctx);
    api_ctx.* = .{
        .node_identity = api_node_identity,
        .beacon_config = beacon_config,
        .allocator = allocator,
        .event_bus = event_bus_ptr,
    };

    const execution_runtime = try ExecutionRuntime.init(
        allocator,
        io,
        opts,
        init_config.jwt_secret,
    );
    var owned_execution_runtime: ?*ExecutionRuntime = execution_runtime;
    errdefer if (owned_execution_runtime) |runtime| runtime.deinit();

    owns_node_identity = false;
    owned_api_node_identity = null;
    owned_execution_runtime = null;
    owns_runtime_builder = false;

    return .{
        .allocator = allocator,
        .io = io,
        .config = beacon_config,
        .node_options = opts,
        .runtime_builder = runtime_builder,
        .block_bls_thread_pool = bls_thread_pools.block,
        .gossip_bls_thread_pool = bls_thread_pools.gossip,
        .node_identity = node_identity,
        .execution_runtime = execution_runtime,
        .api_context = api_ctx,
        .api_node_identity = api_node_identity,
        .event_bus = event_bus_ptr,
        .metrics = init_config.metrics,
        .bootstrap_peers = init_config.bootstrap_peers,
        .discovery_bootnodes = init_config.discovery_bootnodes,
        .identify_agent_version = init_config.identify_agent_version,
    };
}

pub fn deinitBuilder(self: *BeaconNodeBuilder) void {
    if (self.finished) return;

    self.execution_runtime.?.deinit();
    deinitApiNodeIdentity(self.allocator, self.api_node_identity.?);
    self.node_identity.?.deinit();
    self.allocator.destroy(self.api_context.?);
    self.allocator.destroy(self.event_bus.?);

    self.gossip_bls_thread_pool.deinit();
    self.block_bls_thread_pool.deinit();
    self.runtime_builder.deinit();

    self.finished = true;
}

fn finishBuilder(
    self: *BeaconNodeBuilder,
    finished_runtime: chain_mod.RuntimeBuilder.FinishedBootstrap,
) !*BeaconNode {
    if (self.finished) return error.AlreadyFinished;

    const allocator = self.allocator;
    const node = try allocator.create(BeaconNode);
    errdefer allocator.destroy(node);

    node.* = .{
        .allocator = allocator,
        .config = self.config,
        .bootstrap_peers = self.bootstrap_peers,
        .discovery_bootnodes = self.discovery_bootnodes,
        .identify_agent_version = self.identify_agent_version,
        .chain_runtime = finished_runtime.runtime,
        .node_options = self.node_options,
        .chain = finished_runtime.runtime.chain,
        .clock = null,
        .io = self.io,
        .block_bls_thread_pool = self.block_bls_thread_pool,
        .gossip_bls_thread_pool = self.gossip_bls_thread_pool,
        .node_identity = self.node_identity.?,
        .execution_runtime = self.execution_runtime.?,
        .api_context = self.api_context.?,
        .api_node_identity = self.api_node_identity.?,
        .event_bus = self.event_bus.?,
        .metrics = self.metrics,
        .published_proposals = std.AutoHashMap(BeaconNode.PublishedProposalKey, [32]u8).init(allocator),
        .unknown_block_sync = UnknownBlockSync.init(allocator),
        .unknown_chain_sync = UnknownChainSync.init(allocator),
    };

    errdefer deinit(node);

    node.validator_monitor = finished_runtime.runtime.chain.validator_monitor;
    if (finished_runtime.runtime.chain.validator_monitor != null) {
        log.logger(.node).info("Validator monitor: tracking {d} validators", .{self.node_options.validator_monitor_indices.len});
    }

    const beacon_processor = try allocator.create(BeaconProcessor);
    errdefer allocator.destroy(beacon_processor);
    beacon_processor.* = try BeaconProcessor.init(
        allocator,
        QueueConfig.default,
        &beacon_node_mod.processorHandlerCallback,
        @ptrCast(node),
    );
    node.beacon_processor = beacon_processor;

    self.node_identity = null;
    self.execution_runtime = null;
    self.api_context = null;
    self.api_node_identity = null;
    self.event_bus = null;
    self.finished = true;

    node.applyBootstrapOutcome(finished_runtime.outcome);
    try wireBootstrappedNode(node);

    log.logger(.node).info("beacon node initialized", .{});
    return node;
}

pub fn finishBuilderGenesis(self: *BeaconNodeBuilder, genesis_state: *CachedBeaconState) !*BeaconNode {
    const finished_runtime = try self.runtime_builder.finishGenesis(genesis_state);
    return finishBuilder(self, finished_runtime);
}

pub fn finishBuilderCheckpoint(self: *BeaconNodeBuilder, checkpoint_state: *CachedBeaconState) !*BeaconNode {
    const finished_runtime = try self.runtime_builder.finishCheckpoint(checkpoint_state);
    return finishBuilder(self, finished_runtime);
}

pub fn deinit(self: *BeaconNode) void {
    const allocator = self.allocator;

    self.execution_runtime.deinit();

    if (self.api_bindings) |bindings| {
        bindings.deinit(allocator);
        allocator.destroy(bindings);
    }

    deinitApiNodeIdentity(allocator, self.api_node_identity);
    self.node_identity.deinit();
    allocator.destroy(self.api_context);
    allocator.destroy(self.event_bus);

    self.flushPendingGossipBlsBatch();
    self.pending_gossip_bls_batches.deinit(allocator);
    self.queued_state_work_owners.deinit(allocator);
    self.completed_block_ingresses.deinit(allocator);
    for (self.waiting_execution_payloads.items) |*pending| {
        pending.deinit(allocator);
    }
    self.waiting_execution_payloads.deinit(allocator);
    for (self.pending_execution_payloads.items) |*pending| {
        pending.deinit(allocator);
    }
    self.pending_execution_payloads.deinit(allocator);
    for (self.pending_sync_segments.items) |*segment| {
        segment.deinit(allocator);
    }
    self.pending_sync_segments.deinit(allocator);

    if (self.beacon_processor) |bp| {
        bp.deinit();
        allocator.destroy(bp);
    }

    p2p_runtime_mod.deinitOwnedState(self);

    self.published_proposals.deinit();
    self.unknown_block_sync.deinit();
    self.unknown_chain_sync.deinit();

    self.gossip_bls_thread_pool.deinit();
    self.block_bls_thread_pool.deinit();
    self.chain_runtime.deinit();

    allocator.destroy(self);
}

fn initBlsThreadPools(allocator: Allocator, io: std.Io) !BlsThreadPools {
    const cpu_count = std.Thread.getCpuCount() catch 4;
    const pool_budget: usize = @max(@min(cpu_count / 2, BlsThreadPool.MAX_WORKERS), 1);
    const gossip_workers: u16 = @intCast(@max((pool_budget * 2) / 3, 1));
    const block_workers: u16 = @intCast(@max(pool_budget / 3, 1));

    const block_pool = try BlsThreadPool.init(allocator, io, .{ .n_workers = block_workers });
    errdefer block_pool.deinit();

    const gossip_pool = try BlsThreadPool.init(allocator, io, .{
        .n_workers = gossip_workers,
        .use_caller_thread = false,
        .max_async_verify_sets_jobs = @intCast(@min(@max(gossip_workers * 2, 4), BlsThreadPool.MAX_ASYNC_VERIFY_SETS_JOBS)),
    });
    errdefer gossip_pool.deinit();

    log.logger(.node).info("BLS thread pools initialized: block={d} gossip={d}", .{
        block_pool.n_workers,
        gossip_pool.n_workers,
    });

    return .{
        .block = block_pool,
        .gossip = gossip_pool,
    };
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
    } else if (opts.p2p_host) |host| {
        if (!std.mem.eql(u8, host, "0.0.0.0")) {
            try appendAdvertisedAddress(allocator, &addresses, .ip4, host, opts, peer_id, kind);
        }
    }

    if (opts.enr_ip6) |ip6| {
        try appendAdvertisedAddress(allocator, &addresses, .ip6, ip6, opts, peer_id, kind);
    } else if (opts.p2p_host6) |host6| {
        if (!std.mem.eql(u8, host6, "::")) {
            try appendAdvertisedAddress(allocator, &addresses, .ip6, host6, opts, peer_id, kind);
        }
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
            .ip6 => opts.enr_tcp6 orelse opts.p2p_port6 orelse opts.p2p_port,
        },
        .discovery => switch (family) {
            .ip4 => opts.enr_udp orelse opts.discovery_port orelse opts.p2p_port,
            .ip6 => opts.enr_udp6 orelse opts.discovery_port6 orelse opts.discovery_port orelse opts.p2p_port6 orelse opts.p2p_port,
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

fn wireBootstrappedNode(self: *BeaconNode) !void {
    self.chain.setExecutionPort(execution_port_mod.make(self));

    if (self.peer_manager == null) {
        const pm = try self.allocator.create(PeerManager);
        errdefer self.allocator.destroy(pm);
        pm.* = PeerManager.init(self.allocator, .{
            .target_peers = self.node_options.target_peers,
            .target_group_peers = self.node_options.target_group_peers,
            .local_custody_columns = self.chain_runtime.custody_columns,
        });
        self.peer_manager = pm;
    }

    const cb_ctx = self.sync_callback_ctx orelse blk: {
        const created = try self.allocator.create(SyncCallbackCtx);
        created.* = .{ .node = self };
        self.sync_callback_ctx = created;
        break :blk created;
    };
    self.unknown_block_sync.setCallbacks(cb_ctx.unknownBlockCallbacks());
    self.unknown_chain_sync.setCallbacks(cb_ctx.unknownChainCallbacks());
    self.unknown_chain_sync.setForkChoice(cb_ctx.unknownChainForkChoiceQuery());

    if (self.sync_service_inst == null) {
        const sync_svc = try self.allocator.create(SyncService);
        errdefer self.allocator.destroy(sync_svc);
        sync_svc.* = SyncService.init(
            self.allocator,
            cb_ctx.syncServiceCallbacks(),
            self.currentHeadSlot(),
            0,
        );
        sync_svc.is_single_node = self.node_options.sync_is_single_node;
        if (sync_svc.is_single_node) {
            sync_svc.onHeadUpdate(self.currentHeadSlot());
        }
        self.sync_service_inst = sync_svc;
    }

    if (self.api_bindings == null) {
        self.api_bindings = try api_callbacks_mod.ApiBindings.init(self.allocator, self, self.config);
    }
}

pub fn initFromGenesis(self: *BeaconNode, genesis_state: *CachedBeaconState) !void {
    const outcome = try self.chainService().bootstrapFromGenesis(genesis_state);
    self.applyBootstrapOutcome(outcome);
    try wireBootstrappedNode(self);

    log.logger(.node).info("initialized from genesis", .{
        .slot = outcome.snapshot.head.slot,
        .genesis_validators_root = self.genesis_validators_root,
    });
}

pub fn initFromCheckpoint(self: *BeaconNode, checkpoint_state: *CachedBeaconState) !void {
    const outcome = try self.chainService().bootstrapFromCheckpoint(checkpoint_state);
    self.applyBootstrapOutcome(outcome);
    try wireBootstrappedNode(self);

    log.logger(.node).info("initialized from checkpoint", .{
        .slot = outcome.snapshot.head.slot,
        .finalized_epoch = outcome.snapshot.finalized.epoch,
        .justified_epoch = outcome.snapshot.justified.epoch,
        .block_root = outcome.snapshot.head.root,
    });
}

const log = @import("log");
const api_callbacks_mod = @import("api_callbacks.zig");
const SyncCallbackCtx = @import("sync_bridge.zig").SyncCallbackCtx;
const p2p_runtime_mod = @import("p2p_runtime.zig");
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
