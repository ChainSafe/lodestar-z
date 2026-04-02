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
const UnknownBlockSync = sync_mod.UnknownBlockSync;
const UnknownChainSync = sync_mod.UnknownChainSync;
const execution_mod = @import("execution");
const EngineApi = execution_mod.EngineApi;
const MockEngine = execution_mod.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const HttpBuilder = execution_mod.HttpBuilder;
const IoHttpTransport = execution_mod.IoHttpTransport;
const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const QueueConfig = processor_mod.QueueConfig;
const SlotClock = @import("clock.zig").SlotClock;
const NodeOptions = @import("options.zig").NodeOptions;
const InitConfig = @import("beacon_node.zig").BeaconNode.InitConfig;
const custody_mod = @import("networking").custody;

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
        beacon_config,
        storage_backend,
        .{
            .max_block_states = opts.max_block_states,
            .max_checkpoint_epochs = opts.max_checkpoint_epochs,
            .verify_signatures = opts.verify_signatures,
            .block_bls_thread_pool = bls_thread_pools.block,
            .validator_monitor_indices = opts.validator_monitor_indices,
            .custody_columns = custody_columns,
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

    var mock_engine_ptr: ?*MockEngine = null;
    var http_engine_ptr: ?*HttpEngine = null;
    var io_transport_ptr: ?*IoHttpTransport = null;
    var engine: ?EngineApi = null;
    var http_builder_ptr: ?*HttpBuilder = null;
    var builder_transport_ptr: ?*IoHttpTransport = null;
    var builder_api: ?execution_mod.BuilderApi = null;

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
        transport.* = IoHttpTransport.init(allocator, io);
        errdefer transport.deinit();
        io_transport_ptr = transport;

        const http_eng = try allocator.create(HttpEngine);
        errdefer allocator.destroy(http_eng);
        var retry_config = execution_mod.RetryConfig{
            .max_retries = opts.execution_retries,
            .initial_backoff_ms = opts.execution_retry_delay_ms,
        };
        if (opts.execution_timeout_ms) |timeout_ms| {
            retry_config.default_timeout_ms = timeout_ms;
            retry_config.new_payload_timeout_ms = timeout_ms;
        }
        http_eng.* = HttpEngine.initWithRetry(
            allocator,
            io,
            opts.execution_urls[0],
            init_config.jwt_secret,
            transport.transport(),
            retry_config,
        );
        errdefer http_eng.deinit();
        http_engine_ptr = http_eng;
        engine = http_eng.engine();
        std.log.info(
            "Execution engine: HttpEngine -> {s} (retries={d} delay_ms={d} timeout_ms={d})",
            .{
                opts.execution_urls[0],
                opts.execution_retries,
                opts.execution_retry_delay_ms,
                retry_config.default_timeout_ms,
            },
        );
    } else {
        const mock = try allocator.create(MockEngine);
        errdefer allocator.destroy(mock);
        mock.* = MockEngine.init(allocator);
        errdefer mock.deinit();

        mock_engine_ptr = mock;
        engine = mock.engine();
        log.logger(.node).info("Execution engine: MockEngine (no --execution-url)", .{});
    }

    if (opts.builder_enabled) {
        const transport = try allocator.create(IoHttpTransport);
        errdefer allocator.destroy(transport);
        transport.* = IoHttpTransport.init(allocator, io);
        errdefer transport.deinit();
        builder_transport_ptr = transport;

        const http_builder = try allocator.create(HttpBuilder);
        errdefer allocator.destroy(http_builder);
        http_builder.* = HttpBuilder.init(
            allocator,
            opts.builder_url,
            transport.transport(),
            .{
                .timeout_ms = opts.builder_timeout_ms,
                .fault_inspection_window = execution_mod.builder.resolveFaultInspectionWindow(
                    io,
                    opts.builder_fault_inspection_window,
                ),
                .allowed_faults = opts.builder_allowed_faults,
            },
        );
        errdefer http_builder.deinit();
        http_builder_ptr = http_builder;
        builder_api = http_builder.builder();

        log.logger(.node).info("Execution builder: HttpBuilder -> {s} (timeout_ms={d} proposal_timeout_ms={d} fault_window={d} allowed_faults={d})", .{
            opts.builder_url,
            http_builder.request_timeout_ms,
            http_builder.proposal_timeout_ms,
            http_builder.fault_inspection_window,
            http_builder.allowed_faults,
        });
    }

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
        .mock_engine = mock_engine_ptr,
        .http_engine = http_engine_ptr,
        .io_transport = io_transport_ptr,
        .engine_api = engine,
        .http_builder = http_builder_ptr,
        .builder_transport = builder_transport_ptr,
        .builder_api = builder_api,
        .api_context = api_ctx,
        .api_node_identity = api_node_identity,
        .event_bus = event_bus_ptr,
        .published_proposals = std.AutoHashMap(BeaconNode.PublishedProposalKey, [32]u8).init(allocator),
        .unknown_block_sync = UnknownBlockSync.init(allocator),
        .unknown_chain_sync = UnknownChainSync.init(allocator),
    };

    node.validator_monitor = chain_runtime.validator_monitor;
    if (chain_runtime.validator_monitor != null) {
        log.logger(.node).info("Validator monitor: tracking {d} validators", .{opts.validator_monitor_indices.len});
    }

    owns_node_identity = false;
    owned_api_node_identity = null;
    owned_chain_runtime = null;
    errdefer deinit(node);

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

    if (self.mock_engine) |me| {
        me.deinit();
        allocator.destroy(me);
    }

    if (self.http_engine) |he| {
        he.deinit();
        allocator.destroy(he);
    }

    if (self.http_builder) |hb| {
        hb.deinit();
        allocator.destroy(hb);
    }

    if (self.io_transport) |pt| {
        pt.deinit();
        allocator.destroy(pt);
    }

    if (self.builder_transport) |pt| {
        pt.deinit();
        allocator.destroy(pt);
    }

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

pub fn initFromGenesis(self: *BeaconNode, genesis_state: *CachedBeaconState) !void {
    const outcome = try self.chainService().bootstrapFromGenesis(genesis_state);
    self.applyBootstrapOutcome(outcome);

    log.logger(.node).info("initialized from genesis", .{
        .slot = outcome.snapshot.head.slot,
        .genesis_validators_root = self.genesis_validators_root,
    });
}

pub fn initFromCheckpoint(self: *BeaconNode, checkpoint_state: *CachedBeaconState) !void {
    const outcome = try self.chainService().bootstrapFromCheckpoint(checkpoint_state);
    self.applyBootstrapOutcome(outcome);

    std.log.info("Genesis validators root: 0x{s}...", .{
        &std.fmt.bytesToHex(self.genesis_validators_root[0..8], .lower),
    });

    log.logger(.node).info("initialized from checkpoint", .{
        .slot = outcome.snapshot.head.slot,
        .finalized_epoch = outcome.snapshot.finalized.epoch,
        .justified_epoch = outcome.snapshot.justified.epoch,
        .block_root = outcome.snapshot.head.root,
    });
}

const log = @import("log");
const api_callbacks_mod = @import("api_callbacks.zig");
const p2p_runtime_mod = @import("p2p_runtime.zig");
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
const HeadTracker = beacon_node_mod.HeadTracker;
