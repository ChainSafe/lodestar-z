const std = @import("std");
const scoped_log = std.log.scoped(.beacon_command);

const Io = std.Io;
const Allocator = std.mem.Allocator;

const node_mod = @import("node");
const log_mod = @import("log");
const bootstrap = @import("bootstrap.zig");
const metrics_server = @import("metrics_server.zig");
const BeaconNode = node_mod.BeaconNode;
const BeaconMetrics = node_mod.BeaconMetrics;
const MetricsSurface = node_mod.MetricsSurface;
const StateTransitionMetrics = state_transition.metrics.StateTransitionMetrics;
const NodeOptions = node_mod.NodeOptions;
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const config_loader = config_mod.config_loader;
const state_transition = @import("state_transition");
const custody = @import("networking").custody;
const preset = @import("preset").preset;
const genesis_util = @import("../../genesis_util.zig");
const ShutdownHandler = @import("../../shutdown.zig").ShutdownHandler;
const sync_mod = @import("sync");
const checkpoint_sync = sync_mod.checkpoint_sync;
const common = @import("../../spec_common.zig");

const default_builder_url = "http://localhost:8661";

const RunContext = struct {
    node: *BeaconNode,
    api_port: u16,
    api_address: []const u8,
    api_cors_origin: ?[]const u8,
    p2p_port: u16,
    p2p_host: []const u8,
};

const ResolvedRunInputs = struct {
    network: node_mod.NetworkName,
    data_dir: []const u8,
    db_path_override: ?[]const u8,
    execution_urls: []const u8,
    execution_retries: u32,
    execution_retry_delay: u64,
    execution_timeout_ms: ?u64,
    jwt_secret_override: ?[]const u8,
    api_port: u16,
    api_address: []const u8,
    api_cors: ?[]const u8,
    log_level: common.CliLogLevel,
    log_file: ?[]const u8,
    log_format: log_mod.Format,
    log_file_level: common.CliLogLevel,
    log_file_daily_rotate: u16,
    p2p_host4: ?[]const u8,
    p2p_host6: ?[]const u8,
    p2p_port: u16,
    p2p_port6: ?u16,
    discovery_port: ?u16,
    discovery_port6: ?u16,
    bootnodes_file: ?[]const u8,
    cli_bootnodes: ?[]const u8,
    enr_ip: ?[]const u8,
    enr_tcp: ?u16,
    enr_udp: ?u16,
    enr_ip6: ?[]const u8,
    enr_tcp6: ?u16,
    enr_udp6: ?u16,
    target_peers: u32,
    target_group_peers: u32,
    direct_peers_raw: ?[]const u8,
    checkpoint_state: ?[]const u8,
    checkpoint_sync_url: ?[]const u8,
    weak_subjectivity_checkpoint: ?[]const u8,
    force_checkpoint_sync: bool,
    metrics_port: u16,
    metrics_address: []const u8,
    suggested_fee_recipient: ?[20]u8,
    graffiti: ?[32]u8,
    builder_enabled: bool,
    builder_url: ?[]const u8,
    builder_timeout_ms: ?u64,
    builder_boost_factor: u64,
    builder_fault_window: ?u64,
    builder_allowed_faults: ?u64,
    subscribe_all_subnets: bool,
    initial_custody_group_count: u64,
    engine_mock: bool,
    verify_signatures: bool,
    rest_enabled: bool,
    enable_discv5: bool,
    enable_mdns: bool,
    nat: bool,
    metrics_enabled: bool,
    sync_is_single_node: bool,
    persist_network_identity: bool,
    private_identify: bool,
    beacon_config: *const BeaconConfig,
    custom_beacon_config: ?*BeaconConfig = null,

    fn deinit(self: *ResolvedRunInputs, allocator: Allocator) void {
        if (self.custom_beacon_config) |cfg| allocator.destroy(cfg);
    }
};

const PreparedHandles = struct {
    file_transport: ?log_mod.FileTransport,
    direct_peers: []const []const u8,
    beacon_metrics: *BeaconMetrics,
    state_transition_metrics: *StateTransitionMetrics,
    metrics_runtime: ?metrics_server.Runtime,
    node_builder: *BeaconNode.Builder,
    p2p_bind_host: []const u8,
    p2p_bind_port: u16,

    fn deinit(self: *PreparedHandles, allocator: Allocator) void {
        self.node_builder.deinit();
        allocator.destroy(self.node_builder);
        self.beacon_metrics.deinit();
        allocator.destroy(self.beacon_metrics);
        self.state_transition_metrics.deinit();
        allocator.destroy(self.state_transition_metrics);
        if (self.direct_peers.len > 0) allocator.free(self.direct_peers);
        if (self.file_transport) |*ft| ft.close();
    }
};

fn unsupportedOption(name: []const u8, reason: []const u8) noreturn {
    scoped_log.err("{s} is not supported: {s}", .{ name, reason });
    std.process.exit(1);
}

fn rejectUnsupportedOptions(opts: anytype) void {
    if (opts.configFile != null) {
        unsupportedOption("--configFile", "use --params-file/--paramsFile or RC config instead");
    }
    if (opts.genesisStateFile != null) {
        unsupportedOption("--genesisStateFile", "use --checkpoint-state/--checkpointState instead");
    }
    if (opts.checkpoint_block != null) {
        unsupportedOption("--checkpoint-block", "paired checkpoint block import is not wired yet");
    }
    if (opts.unsafeCheckpointState != null) {
        unsupportedOption("--unsafeCheckpointState", "unsafe anchor-state startup is not implemented");
    }
    if (opts.ignoreWeakSubjectivityCheck) {
        unsupportedOption("--ignoreWeakSubjectivityCheck", "weak-subjectivity bypass is not implemented");
    }
    if (opts.lastPersistedCheckpointState) {
        unsupportedOption("--lastPersistedCheckpointState", "DB resume already happens automatically when safe state exists");
    }
    // --sync.isSingleNode / --sync-single-node: supported (devnet single-node mode)
    if (opts.sync_disable_range or opts.@"sync.disableRangeSync") {
        unsupportedOption("--sync-disable-range", "range-sync disabling is not wired yet");
    }
    if (opts.beaconDir != null) {
        unsupportedOption("--beaconDir", "use --data-dir/--dataDir and --dbDir instead");
    }
    if (opts.validatorMonitorLogs) {
        unsupportedOption("--validatorMonitorLogs", "validator monitor log promotion is not wired yet");
    }
    if (opts.attachToGlobalThis) {
        unsupportedOption("--attachToGlobalThis", "JavaScript-only debug attachment does not exist in Zig");
    }
    if (opts.disableLightClientServer) {
        unsupportedOption("--disableLightClientServer", "light client server toggling is not wired yet");
    }
    if (opts.jwt_id != null or opts.jwtId != null) {
        unsupportedOption("--jwt-id", "custom JWT claim ids are not wired yet");
    }
}

fn loadBeaconConfig(network: node_mod.NetworkName) *const BeaconConfig {
    return switch (network) {
        .mainnet => &config_mod.mainnet.config,
        .sepolia => &config_mod.sepolia.config,
        .goerli => unreachable,
        .holesky => &config_mod.hoodi.config,
        .hoodi => &config_mod.hoodi.config,
        .minimal => &config_mod.minimal.config,
    };
}

fn maybePromoteSyntheticMinimalBeaconConfig(
    allocator: Allocator,
    network: node_mod.NetworkName,
    beacon_config: *const BeaconConfig,
    custom_beacon_config: *?*BeaconConfig,
) *const BeaconConfig {
    if (network != .minimal) return beacon_config;
    if (beacon_config.chain.ELECTRA_FORK_EPOCH != std.math.maxInt(u64)) return beacon_config;

    var chain = beacon_config.chain;
    chain.ALTAIR_FORK_EPOCH = 0;
    chain.BELLATRIX_FORK_EPOCH = 0;
    chain.CAPELLA_FORK_EPOCH = 0;
    chain.DENEB_FORK_EPOCH = 0;
    chain.ELECTRA_FORK_EPOCH = 0;

    if (custom_beacon_config.*) |cfg| {
        cfg.* = BeaconConfig.init(chain, cfg.genesis_validator_root);
        return cfg;
    }

    const cfg = allocator.create(BeaconConfig) catch |err| {
        scoped_log.err("Failed to allocate synthetic minimal beacon config: {}", .{err});
        std.process.exit(1);
    };
    cfg.* = BeaconConfig.init(chain, beacon_config.genesis_validator_root);
    custom_beacon_config.* = cfg;
    scoped_log.info("adjusted minimal beacon config for synthetic Electra genesis", .{});
    return cfg;
}

fn readFile(io: Io, allocator: Allocator, path: []const u8) ![]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const s = try file.stat(io);
    const buf = try allocator.alloc(u8, s.size);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    if (n != s.size) return error.ShortRead;
    return buf;
}

fn parseOptionalPort(raw: ?[]const u8) ?u16 {
    const value = raw orelse return null;
    return std.fmt.parseInt(u16, value, 10) catch null;
}

fn parseU64OrExit(flag_name: []const u8, raw: []const u8) u64 {
    return std.fmt.parseInt(u64, raw, 10) catch {
        scoped_log.err("Invalid {s}: expected unsigned integer, got '{s}'", .{ flag_name, raw });
        std.process.exit(1);
    };
}

fn resolveEquivalentOption(
    combined_flag_name: []const u8,
    primary: ?[]const u8,
    secondary: ?[]const u8,
) ?[]const u8 {
    if (primary != null and secondary != null and !std.mem.eql(u8, primary.?, secondary.?)) {
        unsupportedOption(combined_flag_name, "conflicting values were provided");
    }
    return primary orelse secondary;
}

fn resolveBuilderUrl(opts: anytype) ?[]const u8 {
    const dashed = opts.builder_url;
    const dotted = opts.@"builder.url";
    const plural = opts.@"builder.urls";

    if (plural) |value| {
        if (std.mem.indexOfScalar(u8, value, ',') != null) {
            unsupportedOption(
                "--builder.urls",
                "multiple builder URLs are not supported; use an external relay multiplexer like mev-boost",
            );
        }
    }

    if (dashed != null and dotted != null and !std.mem.eql(u8, dashed.?, dotted.?)) {
        unsupportedOption("--builder-url/--builder.url", "conflicting builder URL values were provided");
    }
    if (dashed != null and plural != null and !std.mem.eql(u8, dashed.?, plural.?)) {
        unsupportedOption("--builder-url/--builder.urls", "conflicting builder URL values were provided");
    }
    if (dotted != null and plural != null and !std.mem.eql(u8, dotted.?, plural.?)) {
        unsupportedOption("--builder.url/--builder.urls", "conflicting builder URL values were provided");
    }

    return dotted orelse dashed orelse plural;
}

fn formatP2pListenMultiaddr(buf: []u8, host: []const u8, port: u16) ![]const u8 {
    _ = Io.net.IpAddress.parseIp4(host, 0) catch {
        _ = Io.net.IpAddress.parseIp6(host, 0) catch return error.InvalidListenAddress;
        return std.fmt.bufPrint(buf, "/ip6/{s}/udp/{d}/quic-v1", .{ host, port });
    };
    return std.fmt.bufPrint(buf, "/ip4/{s}/udp/{d}/quic-v1", .{ host, port });
}

fn slotClockLoop(io: Io, node: *BeaconNode) !void {
    const clock = node.clock orelse return error.ClockNotInitialized;

    scoped_log.debug("Entering slot clock loop", .{});

    while (!ShutdownHandler.shouldStop()) {
        const current_slot = clock.currentSlot(io) orelse {
            io.sleep(.{ .nanoseconds = std.time.ns_per_s }, .real) catch return;
            continue;
        };
        const next_slot_ns: i96 = @intCast(clock.slotStartNs(current_slot + 1));
        const now = std.Io.Clock.real.now(io);
        const now_ns: i96 = now.nanoseconds;
        if (next_slot_ns > now_ns) {
            const sleep_ns: u64 = @intCast(next_slot_ns - now_ns);
            io.sleep(.{ .nanoseconds = @intCast(sleep_ns) }, .real) catch return;
        }
    }
}

fn runApiServer(io: Io, ctx: *RunContext) void {
    ctx.node.startApi(io, ctx.api_address, ctx.api_port, ctx.api_cors_origin) catch |err| {
        scoped_log.err("API server failed: {}", .{err});
    };
}

fn runP2p(io: Io, ctx: *RunContext) void {
    ctx.node.startP2p(io, ctx.p2p_host, ctx.p2p_port) catch |err| {
        scoped_log.err("P2P networking failed: {}", .{err});
    };
}

fn runSlotClock(io: Io, node: *BeaconNode) void {
    slotClockLoop(io, node) catch |err| {
        scoped_log.err("Slot clock failed: {}", .{err});
    };
}

fn logHeadSummary(node: *BeaconNode) void {
    const head = node.getHead();
    scoped_log.info("Head: slot={d} root=0x{s}", .{ head.slot, &std.fmt.bytesToHex(head.root, .lower) });
    scoped_log.info("  finalized_epoch={d} justified_epoch={d}", .{ head.finalized_epoch, head.justified_epoch });
}

fn runBootstrappedNode(
    io: Io,
    node: *BeaconNode,
    api_port: u16,
    api_address: []const u8,
    api_cors_origin: ?[]const u8,
    p2p_bind_host: []const u8,
    p2p_bind_port: u16,
    metrics_runtime: ?*metrics_server.Runtime,
) !void {
    var run_ctx = RunContext{
        .node = node,
        .api_port = api_port,
        .api_address = api_address,
        .api_cors_origin = api_cors_origin,
        .p2p_port = p2p_bind_port,
        .p2p_host = p2p_bind_host,
    };

    if (metrics_runtime) |runtime| {
        try runtime.start();
    }
    defer if (metrics_runtime) |runtime| runtime.stop();

    scoped_log.info("starting services concurrently", .{});
    scoped_log.info("  REST API: http://{s}:{d}", .{ api_address, api_port });
    var p2p_multiaddr_buf: [160]u8 = undefined;
    const p2p_multiaddr = try formatP2pListenMultiaddr(&p2p_multiaddr_buf, p2p_bind_host, p2p_bind_port);
    scoped_log.info("  P2P:      {s}", .{p2p_multiaddr});

    var group: Io.Group = .init;
    group.async(io, runApiServer, .{ io, &run_ctx });
    group.async(io, runP2p, .{ io, &run_ctx });
    group.async(io, runSlotClock, .{ io, node });

    group.await(io) catch {};

    scoped_log.info("shutting down", .{});
    scoped_log.info("goodbye", .{});
}

pub fn run(io: Io, allocator: Allocator, opts: anytype) !void {
    return @call(.never_inline, runImpl, .{ io, allocator, opts });
}

fn resolveRunInputs(io: Io, allocator: Allocator, opts: anytype) ResolvedRunInputs {
    rejectUnsupportedOptions(opts);

    const network = opts.network.toNetworkName();
    const data_dir = opts.dataDir orelse opts.data_dir;
    const params_file = opts.paramsFile orelse opts.params_file;
    const db_path_override = opts.dbDir orelse opts.db_path;
    const execution_urls = opts.@"execution.urls" orelse opts.execution_urls;
    const execution_timeout_raw = resolveEquivalentOption(
        "--execution-timeout/--execution.timeout",
        opts.execution_timeout,
        opts.@"execution.timeout",
    );
    const execution_retries = opts.@"execution.retries" orelse opts.execution_retries;
    const execution_retry_delay = opts.@"execution.retryDelay" orelse 100;
    const jwt_secret_override = opts.jwtSecret orelse opts.jwt_secret;
    const api_port = opts.@"rest.port" orelse opts.api_port;
    const api_address = opts.@"rest.address" orelse opts.api_address;
    const api_cors = opts.@"rest.cors" orelse opts.api_cors;
    const log_level = opts.logLevel orelse opts.log_level;
    const log_file = opts.logFile orelse opts.log_file;
    const log_format = opts.logFormat orelse opts.log_format;
    const log_file_level = opts.logFileLevel orelse opts.log_file_level;
    const log_file_daily_rotate = opts.logFileDailyRotate orelse opts.log_file_daily_rotate;
    const p2p_host4 = opts.listenAddress orelse opts.p2p_host;
    const p2p_host6 = opts.listenAddress6 orelse opts.p2p_host6;
    const p2p_port = opts.port orelse opts.p2p_port;
    const p2p_port6 = opts.port6 orelse parseOptionalPort(opts.p2p_port6);
    const discovery_port: ?u16 = if (opts.discoveryPort) |port| blk: {
        break :blk port;
    } else if (opts.discovery_port) |port_str| blk: {
        break :blk std.fmt.parseInt(u16, port_str, 10) catch null;
    } else null;
    const discovery_port6 = opts.discoveryPort6;
    const bootnodes_file = opts.bootnodesFile;
    const cli_bootnodes = opts.bootnodes;
    const enr_ip = opts.@"enr.ip";
    const enr_tcp = opts.@"enr.tcp";
    const enr_udp = opts.@"enr.udp";
    const enr_ip6 = opts.@"enr.ip6";
    const enr_tcp6 = opts.@"enr.tcp6";
    const enr_udp6 = opts.@"enr.udp6";
    const target_peers = opts.targetPeers orelse opts.target_peers;
    const target_group_peers = opts.@"network.targetGroupPeers" orelse 6;
    const direct_peers_raw = opts.directPeers orelse opts.direct_peers;
    const checkpoint_state = opts.checkpointState orelse opts.checkpoint_state;
    const checkpoint_sync_url = opts.checkpointSyncUrl orelse opts.checkpoint_sync_url;
    const weak_subjectivity_checkpoint = opts.wssCheckpoint orelse opts.weak_subjectivity_checkpoint;
    const force_checkpoint_sync = opts.forceCheckpointSync or opts.force_checkpoint_sync;
    const metrics_port = opts.@"metrics.port" orelse opts.metrics_port;
    const metrics_address = opts.@"metrics.address" orelse opts.metrics_address;
    const suggest_fee_recipient = opts.suggestedFeeRecipient orelse opts.suggest_fee_recipient;
    const graffiti: ?[32]u8 = if (opts.graffiti) |graffiti_str| blk: {
        var g: [32]u8 = [_]u8{0} ** 32;
        const copy_len = @min(graffiti_str.len, 32);
        @memcpy(g[0..copy_len], graffiti_str[0..copy_len]);
        break :blk g;
    } else null;
    const builder_enabled = opts.builder;
    const builder_url = resolveBuilderUrl(opts);
    const builder_timeout_raw = resolveEquivalentOption(
        "--builder-timeout/--builder.timeout",
        opts.builder_timeout,
        opts.@"builder.timeout",
    );
    const builder_boost_factor_raw = opts.builder_boost_factor;
    const builder_fault_window_raw = resolveEquivalentOption(
        "--builder-fault-inspection-window/--builder.faultInspectionWindow",
        opts.builder_fault_window,
        opts.@"builder.faultInspectionWindow",
    );
    const builder_allowed_faults_raw = resolveEquivalentOption(
        "--builder-allowed-faults/--builder.allowedFaults",
        opts.builder_allowed_faults,
        opts.@"builder.allowedFaults",
    );
    const subscribe_all_subnets = opts.subscribeAllSubnets or opts.subscribe_all_subnets;
    const supernode = opts.supernode;
    const semi_supernode = opts.semiSupernode or opts.semi_supernode;
    const engine_mock = opts.@"execution.engineMock" or opts.engine_mock;
    const persist_network_identity = opts.persistNetworkIdentity orelse true;
    const private_identify = opts.private;
    if (std.mem.indexOfScalar(u8, execution_urls, ',') != null) {
        unsupportedOption(
            "--execution.urls",
            "multiple execution URLs are not supported yet; use one execution endpoint or an external load balancer",
        );
    }

    if (!builder_enabled and builder_url != null) {
        unsupportedOption("--builder.url", "add --builder to enable the external builder relay");
    }
    if (!builder_enabled and builder_boost_factor_raw != null) {
        unsupportedOption("--builder-boost-factor", "add --builder to enable builder bid selection");
    }
    if (!builder_enabled and builder_fault_window_raw != null) {
        unsupportedOption("--builder-fault-inspection-window", "add --builder to enable builder circuit-breaker tuning");
    }
    if (!builder_enabled and builder_allowed_faults_raw != null) {
        unsupportedOption("--builder-allowed-faults", "add --builder to enable builder circuit-breaker tuning");
    }
    const fee_recipient: ?[20]u8 = if (suggest_fee_recipient) |hex_str| blk: {
        const stripped = if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X'))
            hex_str[2..]
        else
            hex_str;
        if (stripped.len != 40) {
            scoped_log.err("Invalid --suggest-fee-recipient: expected 40 hex chars, got {d}", .{stripped.len});
            break :blk null;
        }
        var addr: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&addr, stripped) catch {
            scoped_log.err("Invalid --suggest-fee-recipient: bad hex encoding", .{});
            break :blk null;
        };
        break :blk addr;
    } else null;
    const builder_boost_factor = if (builder_boost_factor_raw) |raw|
        parseU64OrExit("--builder-boost-factor", raw)
    else
        @as(u64, 100);
    const execution_timeout_ms = if (execution_timeout_raw) |raw|
        parseU64OrExit("--execution-timeout", raw)
    else
        null;
    const builder_timeout_ms = if (builder_timeout_raw) |raw|
        parseU64OrExit("--builder-timeout", raw)
    else
        null;
    const builder_fault_window = if (builder_fault_window_raw) |raw|
        parseU64OrExit("--builder-fault-inspection-window", raw)
    else
        null;
    const builder_allowed_faults = if (builder_allowed_faults_raw) |raw|
        parseU64OrExit("--builder-allowed-faults", raw)
    else
        null;

    var custom_beacon_config: ?*BeaconConfig = null;
    var beacon_config: *const BeaconConfig = if (params_file) |config_path| blk: {
        scoped_log.info("loading custom network config from {s}", .{config_path});
        var arena = std.heap.ArenaAllocator.init(allocator);
        const config_arena = arena.allocator();
        const config_bytes = readFile(io, allocator, config_path) catch |err| {
            scoped_log.err("Failed to read config file '{s}': {}", .{ config_path, err });
            std.process.exit(1);
        };
        defer allocator.free(config_bytes);
        const base = loadBeaconConfig(network);
        const custom_chain_config = config_loader.loadConfigFromYaml(config_arena, config_bytes, &base.chain) catch |err| {
            scoped_log.err("Failed to parse config YAML '{s}': {}", .{ config_path, err });
            std.process.exit(1);
        };
        const cfg = allocator.create(BeaconConfig) catch |err| {
            scoped_log.err("Failed to allocate custom beacon config: {}", .{err});
            std.process.exit(1);
        };
        cfg.* = BeaconConfig.init(custom_chain_config, [_]u8{0} ** 32);
        custom_beacon_config = cfg;
        scoped_log.info("custom config loaded: SECONDS_PER_SLOT={d} CONFIG_NAME={s}", .{
            custom_chain_config.SECONDS_PER_SLOT,
            custom_chain_config.CONFIG_NAME,
        });
        break :blk cfg;
    } else loadBeaconConfig(network);

    beacon_config = maybePromoteSyntheticMinimalBeaconConfig(
        allocator,
        network,
        beacon_config,
        &custom_beacon_config,
    );

    const initial_custody_group_count = blk: {
        if (supernode) break :blk custody.NUMBER_OF_CUSTODY_GROUPS;
        if (semi_supernode) break :blk @max(
            beacon_config.chain.CUSTODY_REQUIREMENT,
            custody.NUMBER_OF_CUSTODY_GROUPS / 2,
        );
        break :blk beacon_config.chain.CUSTODY_REQUIREMENT;
    };

    return .{
        .network = network,
        .data_dir = data_dir,
        .db_path_override = db_path_override,
        .execution_urls = execution_urls,
        .execution_retries = execution_retries,
        .execution_retry_delay = execution_retry_delay,
        .execution_timeout_ms = execution_timeout_ms,
        .jwt_secret_override = jwt_secret_override,
        .api_port = api_port,
        .api_address = api_address,
        .api_cors = api_cors,
        .log_level = log_level,
        .log_file = log_file,
        .log_format = log_format,
        .log_file_level = log_file_level,
        .log_file_daily_rotate = log_file_daily_rotate,
        .p2p_host4 = p2p_host4,
        .p2p_host6 = p2p_host6,
        .p2p_port = p2p_port,
        .p2p_port6 = p2p_port6,
        .discovery_port = discovery_port,
        .discovery_port6 = discovery_port6,
        .bootnodes_file = bootnodes_file,
        .cli_bootnodes = cli_bootnodes,
        .enr_ip = enr_ip,
        .enr_tcp = enr_tcp,
        .enr_udp = enr_udp,
        .enr_ip6 = enr_ip6,
        .enr_tcp6 = enr_tcp6,
        .enr_udp6 = enr_udp6,
        .target_peers = target_peers,
        .target_group_peers = target_group_peers,
        .direct_peers_raw = direct_peers_raw,
        .checkpoint_state = checkpoint_state,
        .checkpoint_sync_url = checkpoint_sync_url,
        .weak_subjectivity_checkpoint = weak_subjectivity_checkpoint,
        .force_checkpoint_sync = force_checkpoint_sync,
        .metrics_port = metrics_port,
        .metrics_address = metrics_address,
        .suggested_fee_recipient = fee_recipient,
        .graffiti = graffiti,
        .builder_enabled = builder_enabled,
        .builder_url = builder_url,
        .builder_timeout_ms = builder_timeout_ms,
        .builder_boost_factor = builder_boost_factor,
        .builder_fault_window = builder_fault_window,
        .builder_allowed_faults = builder_allowed_faults,
        .subscribe_all_subnets = subscribe_all_subnets,
        .initial_custody_group_count = initial_custody_group_count,
        .engine_mock = engine_mock,
        .verify_signatures = opts.verify_signatures,
        .rest_enabled = opts.rest,
        .enable_discv5 = opts.discv5,
        .enable_mdns = opts.mdns,
        .nat = opts.nat,
        .metrics_enabled = opts.metrics,
        .sync_is_single_node = opts.sync_is_single_node or opts.@"sync.isSingleNode",
        .persist_network_identity = persist_network_identity,
        .private_identify = private_identify,
        .beacon_config = beacon_config,
        .custom_beacon_config = custom_beacon_config,
    };
}

fn runImpl(io: Io, allocator: Allocator, opts: anytype) !void {
    var inputs = resolveRunInputs(io, allocator, opts);
    defer inputs.deinit(allocator);
    return @call(.never_inline, runResolved, .{ io, allocator, &inputs });
}

fn runResolved(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs) !void {
    const handles = try allocator.create(PreparedHandles);
    var prepared = false;
    errdefer if (!prepared) allocator.destroy(handles);
    try prepareRunContext(io, allocator, inputs, handles);
    prepared = true;
    defer {
        handles.deinit(allocator);
        allocator.destroy(handles);
    }
    return @call(.never_inline, runFromPrepared, .{ io, allocator, inputs, handles });
}

fn prepareRunContext(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, handles: *PreparedHandles) !void {
    return @call(.never_inline, prepareRunContextImpl, .{ io, allocator, inputs, handles });
}

fn prepareRunContextImpl(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, handles: *PreparedHandles) !void {
    ShutdownHandler.installSignalHandlers();
    const startup = try allocator.create(StartupPrep);
    startup.* = .{};
    defer {
        startup.deinit(allocator);
        allocator.destroy(startup);
    }
    try @call(.never_inline, prepareRunContextStartup, .{ io, allocator, inputs, startup });
    const ready = try @call(.never_inline, prepareRunContextNode, .{ io, allocator, inputs, startup });
    defer {
        allocator.destroy(ready.metrics);
        allocator.destroy(ready);
    }

    handles.* = .{
        .file_transport = startup.file_transport,
        .direct_peers = startup.direct_peers,
        .beacon_metrics = ready.metrics.beacon_metrics,
        .state_transition_metrics = ready.metrics.state_transition_metrics,
        .metrics_runtime = ready.metrics.metrics_runtime,
        .node_builder = ready.node_builder,
        .p2p_bind_host = startup.p2p_bind_host,
        .p2p_bind_port = startup.p2p_bind_port,
    };
    startup.file_transport = null;
    startup.direct_peers = &.{};
    return;
}

const StartupPrep = struct {
    file_transport: ?log_mod.FileTransport = null,
    direct_peers: []const []const u8 = &.{},
    p2p_bind_host: []const u8 = "0.0.0.0",
    p2p_bind_port: u16 = 0,
    prepared_runtime: ?*bootstrap.PreparedRuntime = null,

    fn deinit(self: *StartupPrep, allocator: Allocator) void {
        if (self.prepared_runtime) |prepared_runtime| {
            prepared_runtime.deinit();
            allocator.destroy(prepared_runtime);
        }
        if (self.direct_peers.len > 0) allocator.free(self.direct_peers);
        if (self.file_transport) |*ft| ft.close();
    }
};

const NodeMetricsPrep = struct {
    beacon_metrics: *BeaconMetrics,
    state_transition_metrics: *StateTransitionMetrics,
    metrics_runtime: ?metrics_server.Runtime,

    fn deinit(self: *NodeMetricsPrep, allocator: Allocator) void {
        self.beacon_metrics.deinit();
        allocator.destroy(self.beacon_metrics);
        self.state_transition_metrics.deinit();
        allocator.destroy(self.state_transition_metrics);
    }
};

const NodeBuildPrep = struct {
    metrics: *NodeMetricsPrep,
    node_opts: *NodeOptions,
    init_config: *BeaconNode.InitConfig,
};

const NodeReadyContext = struct {
    metrics: *NodeMetricsPrep,
    node_builder: *BeaconNode.Builder,
};

fn prepareRunContextStartup(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, startup: *StartupPrep) !void {
    log_mod.configure(inputs.log_level.toLogLevel(), inputs.log_format);
    if (inputs.log_file != null) {
        prepareStartupFileTransport(io, inputs, startup);
    }
    logStartupConfig(inputs);

    try @call(.never_inline, prepareStartupPeers, .{ allocator, inputs, startup });
    return @call(.never_inline, prepareStartupRuntime, .{ io, allocator, inputs, startup });
}

fn logStartupConfig(inputs: *const ResolvedRunInputs) void {
    scoped_log.info("lodestar-z v{s} starting", .{common.VERSION});
    scoped_log.info("  network:    {s}", .{@tagName(inputs.network)});
    scoped_log.info("  api:        http://{s}:{d}", .{ inputs.api_address, inputs.api_port });
    if (inputs.p2p_host4) |host| scoped_log.info("  p2p4:       {s}:{d}", .{ host, inputs.p2p_port });
    if (inputs.p2p_host6) |host| scoped_log.info("  p2p6:       [{s}]:{d}", .{ host, inputs.p2p_port6 orelse inputs.p2p_port });
    if (inputs.p2p_host4 == null and inputs.p2p_host6 == null) {
        scoped_log.info("  p2p4:       0.0.0.0:{d}", .{inputs.p2p_port});
    }
    if (inputs.jwt_secret_override) |jwt| {
        scoped_log.info("  jwt-secret: {s}", .{jwt});
    }
    scoped_log.info("  custody-groups: {d}", .{inputs.initial_custody_group_count});
    scoped_log.info("  execution:  {s}", .{inputs.execution_urls});
    scoped_log.info("  execution retry: attempts={d} delay_ms={d}", .{ inputs.execution_retries, inputs.execution_retry_delay });
    if (inputs.execution_timeout_ms) |value| {
        scoped_log.info("  execution timeout: {d}ms", .{value});
    } else {
        scoped_log.info("  execution timeout: default", .{});
    }
    if (inputs.builder_enabled) {
        scoped_log.info("  builder:    {s} (boost={d})", .{ inputs.builder_url orelse default_builder_url, inputs.builder_boost_factor });
        if (inputs.builder_timeout_ms) |value| {
            scoped_log.info("  builder timeout: {d}ms", .{value});
        } else {
            scoped_log.info("  builder timeout: default", .{});
        }
    }
}

fn prepareStartupPeers(allocator: Allocator, inputs: *const ResolvedRunInputs, startup: *StartupPrep) !void {
    startup.direct_peers = if (inputs.direct_peers_raw) |raw| blk: {
        var list: std.ArrayListUnmanaged([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |addr| {
            const trimmed = std.mem.trim(u8, addr, " \t");
            if (trimmed.len > 0) try list.append(allocator, trimmed);
        }
        break :blk try list.toOwnedSlice(allocator);
    } else &.{};

    startup.p2p_bind_host = inputs.p2p_host4 orelse inputs.p2p_host6 orelse "0.0.0.0";
    startup.p2p_bind_port = if (inputs.p2p_host4 != null or inputs.p2p_host6 == null)
        inputs.p2p_port
    else
        inputs.p2p_port6 orelse inputs.p2p_port;
}

fn prepareStartupFileTransport(io: Io, inputs: *const ResolvedRunInputs, startup: *StartupPrep) void {
    const log_file_path = inputs.log_file orelse return;
    const file_level = inputs.log_file_level.toLogLevel();

    startup.file_transport = log_mod.FileTransport.init(io, log_file_path, file_level, .{
        .max_size_bytes = 100 * 1024 * 1024,
        .max_files = inputs.log_file_daily_rotate,
        .daily = inputs.log_file_daily_rotate > 0,
    });

    if (startup.file_transport) |*ft| {
        if (log_mod.setFileTransport(ft)) |_| {
            scoped_log.info("File logging enabled: {s} (level={s})", .{
                log_file_path, file_level.asText(),
            });
        } else |err| {
            scoped_log.err("Failed to start log file transport '{s}': {}", .{ log_file_path, err });
            startup.file_transport = null;
        }
    }
}

fn prepareStartupRuntime(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, startup: *StartupPrep) !void {
    const node_opts = NodeOptions{
        .verify_signatures = inputs.verify_signatures,
        .rest_enabled = inputs.rest_enabled,
        .rest_port = inputs.api_port,
        .rest_address = inputs.api_address,
        .rest_cors_origin = inputs.api_cors,
        .execution_urls = &.{inputs.execution_urls},
        .engine_mock = inputs.engine_mock,
        .execution_retries = inputs.execution_retries,
        .execution_retry_delay_ms = inputs.execution_retry_delay,
        .execution_timeout_ms = inputs.execution_timeout_ms,
        .builder_enabled = inputs.builder_enabled,
        .builder_url = inputs.builder_url orelse default_builder_url,
        .builder_timeout_ms = inputs.builder_timeout_ms,
        .builder_boost_factor = inputs.builder_boost_factor,
        .builder_fault_inspection_window = inputs.builder_fault_window,
        .builder_allowed_faults = inputs.builder_allowed_faults,
        .target_peers = inputs.target_peers,
        .target_group_peers = inputs.target_group_peers,
        .network = inputs.network,
        .p2p_host = inputs.p2p_host4,
        .p2p_host6 = inputs.p2p_host6,
        .p2p_port = inputs.p2p_port,
        .p2p_port6 = inputs.p2p_port6,
        .enable_discv5 = inputs.enable_discv5,
        .discovery_port = inputs.discovery_port,
        .discovery_port6 = inputs.discovery_port6,
        .direct_peers = startup.direct_peers,
        .enable_mdns = inputs.enable_mdns,
        .subscribe_all_subnets = inputs.subscribe_all_subnets,
        .initial_custody_group_count = inputs.initial_custody_group_count,
        .enr_ip = inputs.enr_ip,
        .enr_tcp = inputs.enr_tcp,
        .enr_udp = inputs.enr_udp,
        .enr_ip6 = inputs.enr_ip6,
        .enr_tcp6 = inputs.enr_tcp6,
        .enr_udp6 = inputs.enr_udp6,
        .nat = inputs.nat,
        .suggested_fee_recipient = inputs.suggested_fee_recipient,
        .graffiti = inputs.graffiti,
        .checkpoint_sync_url = inputs.checkpoint_sync_url,
        .sync_is_single_node = inputs.sync_is_single_node,
    };

    const prepared_runtime = try allocator.create(bootstrap.PreparedRuntime);
    errdefer allocator.destroy(prepared_runtime);
    prepared_runtime.* = try bootstrap.prepareRuntime(
        allocator,
        io,
        .{
            .network = inputs.network,
            .data_dir = inputs.data_dir,
            .db_path_override = inputs.db_path_override,
            .jwt_secret_override = inputs.jwt_secret_override,
            .cli_bootnodes = inputs.cli_bootnodes,
            .bootnodes_file = inputs.bootnodes_file,
            .node_options = node_opts,
            .needs_execution_auth = !inputs.engine_mock and inputs.execution_urls.len > 0,
            .persist_network_identity = inputs.persist_network_identity,
            .private = inputs.private_identify,
        },
    );
    startup.prepared_runtime = prepared_runtime;

    scoped_log.info("  data-dir:   {s}", .{prepared_runtime.paths.root});
    scoped_log.info("  bootstrap:  {d} explicit, {d} discovery", .{
        prepared_runtime.bootstrap_peers.len,
        prepared_runtime.discovery_bootnodes.len,
    });
}

fn prepareRunContextNode(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, startup: *StartupPrep) !*NodeReadyContext {
    const prep = try @call(.never_inline, prepareNodeBuildPrep, .{ io, allocator, inputs, startup });
    errdefer {
        prep.metrics.deinit(allocator);
        allocator.destroy(prep.metrics);
        allocator.destroy(prep.node_opts);
        allocator.destroy(prep.init_config);
        allocator.destroy(prep);
    }

    const node_builder = try @call(.never_inline, prepareNodeBuilder, .{ io, allocator, inputs.beacon_config, prep.init_config.* });
    errdefer node_builder.deinit();
    errdefer allocator.destroy(node_builder);

    const ready = try allocator.create(NodeReadyContext);
    ready.* = .{
        .metrics = prep.metrics,
        .node_builder = node_builder,
    };
    allocator.destroy(prep.node_opts);
    allocator.destroy(prep.init_config);
    allocator.destroy(prep);
    return ready;
}

fn prepareNodeBuildPrep(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, startup: *StartupPrep) !*NodeBuildPrep {
    const prep = try allocator.create(NodeBuildPrep);
    errdefer allocator.destroy(prep);

    prep.metrics = try allocator.create(NodeMetricsPrep);
    errdefer allocator.destroy(prep.metrics);
    try @call(.never_inline, prepareNodeMetrics, .{ io, allocator, inputs, prep.metrics });
    errdefer prep.metrics.deinit(allocator);

    prep.node_opts = try allocator.create(NodeOptions);
    errdefer allocator.destroy(prep.node_opts);
    fillNodeOptions(inputs, startup.direct_peers, prep.node_opts);

    prep.init_config = try allocator.create(BeaconNode.InitConfig);
    errdefer allocator.destroy(prep.init_config);
    prepareNodeInitConfig(startup.prepared_runtime.?, inputs, prep.metrics, prep.node_opts, prep.init_config);

    return prep;
}

fn fillNodeOptions(inputs: *const ResolvedRunInputs, direct_peers: []const []const u8, node_opts: *NodeOptions) void {
    node_opts.* = .{
        .verify_signatures = inputs.verify_signatures,
        .rest_enabled = inputs.rest_enabled,
        .rest_port = inputs.api_port,
        .rest_address = inputs.api_address,
        .rest_cors_origin = inputs.api_cors,
        .execution_urls = &.{inputs.execution_urls},
        .engine_mock = inputs.engine_mock,
        .execution_retries = inputs.execution_retries,
        .execution_retry_delay_ms = inputs.execution_retry_delay,
        .execution_timeout_ms = inputs.execution_timeout_ms,
        .builder_enabled = inputs.builder_enabled,
        .builder_url = inputs.builder_url orelse default_builder_url,
        .builder_timeout_ms = inputs.builder_timeout_ms,
        .builder_boost_factor = inputs.builder_boost_factor,
        .builder_fault_inspection_window = inputs.builder_fault_window,
        .builder_allowed_faults = inputs.builder_allowed_faults,
        .target_peers = inputs.target_peers,
        .target_group_peers = inputs.target_group_peers,
        .network = inputs.network,
        .p2p_host = inputs.p2p_host4,
        .p2p_host6 = inputs.p2p_host6,
        .p2p_port = inputs.p2p_port,
        .p2p_port6 = inputs.p2p_port6,
        .enable_discv5 = inputs.enable_discv5,
        .discovery_port = inputs.discovery_port,
        .discovery_port6 = inputs.discovery_port6,
        .direct_peers = direct_peers,
        .enable_mdns = inputs.enable_mdns,
        .subscribe_all_subnets = inputs.subscribe_all_subnets,
        .initial_custody_group_count = inputs.initial_custody_group_count,
        .enr_ip = inputs.enr_ip,
        .enr_tcp = inputs.enr_tcp,
        .enr_udp = inputs.enr_udp,
        .enr_ip6 = inputs.enr_ip6,
        .enr_tcp6 = inputs.enr_tcp6,
        .enr_udp6 = inputs.enr_udp6,
        .nat = inputs.nat,
        .suggested_fee_recipient = inputs.suggested_fee_recipient,
        .graffiti = inputs.graffiti,
        .checkpoint_sync_url = inputs.checkpoint_sync_url,
        .sync_is_single_node = inputs.sync_is_single_node,
    };
}

fn prepareNodeInitConfig(prepared_runtime: *bootstrap.PreparedRuntime, inputs: *const ResolvedRunInputs, metrics: *const NodeMetricsPrep, node_opts: *const NodeOptions, init_config: *BeaconNode.InitConfig) void {
    init_config.* = prepared_runtime.takeInitConfig(node_opts.*);
    init_config.metrics = if (inputs.metrics_enabled) metrics.beacon_metrics else null;
    init_config.state_transition_metrics = metrics.state_transition_metrics;
}

fn prepareNodeMetrics(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, metrics: *NodeMetricsPrep) !void {
    const beacon_metrics = try allocator.create(BeaconMetrics);
    errdefer allocator.destroy(beacon_metrics);
    beacon_metrics.* = BeaconMetrics.initNoop();
    errdefer beacon_metrics.deinit();

    const state_transition_metrics = try allocator.create(StateTransitionMetrics);
    errdefer allocator.destroy(state_transition_metrics);
    state_transition_metrics.* = StateTransitionMetrics.initNoop();
    errdefer state_transition_metrics.deinit();

    var metrics_surface = MetricsSurface{
        .beacon = beacon_metrics,
        .state_transition = state_transition_metrics,
    };
    var metrics_runtime: ?metrics_server.Runtime = null;
    if (inputs.metrics_enabled) {
        beacon_metrics.* = try BeaconMetrics.init(allocator);
        state_transition_metrics.* = try StateTransitionMetrics.init(allocator, io, .{});
        metrics_runtime = metrics_server.Runtime.init(
            io,
            allocator,
            &metrics_surface,
            .{
                .address = inputs.metrics_address,
                .port = inputs.metrics_port,
            },
        );
    }

    metrics.* = .{
        .beacon_metrics = beacon_metrics,
        .state_transition_metrics = state_transition_metrics,
        .metrics_runtime = metrics_runtime,
    };
}

fn prepareNodeBuilder(io: Io, allocator: Allocator, beacon_config: *const BeaconConfig, init_config: BeaconNode.InitConfig) !*BeaconNode.Builder {
    const node_builder = try allocator.create(BeaconNode.Builder);
    errdefer allocator.destroy(node_builder);
    node_builder.* = try BeaconNode.Builder.init(allocator, io, beacon_config, init_config);
    return node_builder;
}

fn runFromPrepared(io: Io, allocator: Allocator, inputs: *const ResolvedRunInputs, handles: *PreparedHandles) !void {
    scoped_log.info("beacon node bootstrap initialized", .{});
    scoped_log.info("  peer-id:    {s}", .{handles.node_builder.nodeIdentity().peer_id});
    scoped_log.info("  enr:        {s}", .{handles.node_builder.nodeIdentity().enr});

    const force_checkpoint = inputs.force_checkpoint_sync;

    if (inputs.checkpoint_sync_url) |sync_url| {
        scoped_log.info("checkpoint sync from URL: {s}", .{sync_url});

        const fetched = checkpoint_sync.fetchFinalizedState(allocator, io, sync_url) catch |err| {
            scoped_log.err("Failed to fetch checkpoint state from '{s}': {}", .{ sync_url, err });
            scoped_log.err("  Suggestions:", .{});
            scoped_log.err("    - Verify the URL is a beacon API endpoint", .{});
            scoped_log.err("    - Try: curl -s {s}/eth/v1/node/version", .{sync_url});
            scoped_log.err("    - Use --checkpoint-state <file> as alternative", .{});
            std.process.exit(1);
        };
        defer allocator.free(fetched.state_bytes);

        scoped_log.info("deserializing checkpoint state ({d} bytes, fork={s})...", .{
            fetched.state_bytes.len, fetched.fork_name,
        });

        const cp_state = state_transition.deserializePublishedState(
            allocator,
            handles.node_builder.sharedStateGraph().pool,
            inputs.beacon_config,
            handles.node_builder.sharedStateGraph().validator_pubkeys,
            fetched.state_bytes,
            handles.state_transition_metrics,
        ) catch |err| {
            scoped_log.err("Failed to deserialize checkpoint state: {}", .{err});
            scoped_log.err("  This may indicate a fork mismatch — check that the", .{});
            scoped_log.err("  remote node and this node are on the same network.", .{});
            std.process.exit(1);
        };

        if (inputs.weak_subjectivity_checkpoint) |ws_str| {
            const ws = checkpoint_sync.parseWeakSubjectivityCheckpoint(ws_str) catch |err| {
                scoped_log.err("Invalid --weak-subjectivity-checkpoint '{s}': {}", .{ ws_str, err });
                std.process.exit(1);
            };
            const cp_slot = cp_state.state.slot() catch 0;
            checkpoint_sync.validateWeakSubjectivityCheckpoint(ws, cp_slot, @as(u64, preset.SLOTS_PER_EPOCH)) catch {
                scoped_log.err("Weak subjectivity violation! The checkpoint state does not", .{});
                scoped_log.err("  match the expected root:epoch. Refusing to sync.", .{});
                scoped_log.err("  Expected: {s}", .{ws_str});
                std.process.exit(1);
            };
            scoped_log.info("Weak subjectivity checkpoint validated (epoch {d})", .{ws.epoch});
        }

        const cp_slot = cp_state.state.slot() catch 0;
        const node = try handles.node_builder.finishCheckpoint(cp_state);
        defer node.deinit();
        if (inputs.custom_beacon_config) |cfg| cfg.genesis_validator_root = node.genesis_validators_root;
        scoped_log.info("Initialized from checkpoint sync URL at slot {d}", .{cp_slot});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, inputs.api_port, inputs.api_address, inputs.api_cors, handles.p2p_bind_host, handles.p2p_bind_port, if (handles.metrics_runtime) |*runtime| runtime else null);
        return;
    } else if (inputs.checkpoint_state) |state_path| {
        scoped_log.info("loading checkpoint state from {s}", .{state_path});

        const cp_state = genesis_util.loadGenesisFromFile(
            allocator,
            handles.node_builder.sharedStateGraph().pool,
            inputs.beacon_config,
            handles.node_builder.sharedStateGraph().validator_pubkeys,
            io,
            state_path,
            handles.state_transition_metrics,
        ) catch |err| {
            scoped_log.err("Failed to load checkpoint state '{s}': {}", .{ state_path, err });
            std.process.exit(1);
        };

        if (inputs.weak_subjectivity_checkpoint) |ws_str| {
            const ws = checkpoint_sync.parseWeakSubjectivityCheckpoint(ws_str) catch |err| {
                scoped_log.err("Invalid --weak-subjectivity-checkpoint '{s}': {}", .{ ws_str, err });
                std.process.exit(1);
            };
            const cp_slot = cp_state.state.slot() catch 0;
            checkpoint_sync.validateWeakSubjectivityCheckpoint(ws, cp_slot, @as(u64, preset.SLOTS_PER_EPOCH)) catch {
                scoped_log.err("Weak subjectivity violation! Refusing to sync.", .{});
                std.process.exit(1);
            };
            scoped_log.info("Weak subjectivity checkpoint validated (epoch {d})", .{ws.epoch});
        }

        const cp_slot = cp_state.state.slot() catch 0;
        const node = if (cp_slot == 0)
            try handles.node_builder.finishGenesis(cp_state)
        else
            try handles.node_builder.finishCheckpoint(cp_state);
        defer node.deinit();
        if (inputs.custom_beacon_config) |cfg| cfg.genesis_validator_root = node.genesis_validators_root;
        scoped_log.info("Initialized from checkpoint file at slot {d}", .{cp_slot});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, inputs.api_port, inputs.api_address, inputs.api_cors, handles.p2p_bind_host, handles.p2p_bind_port, if (handles.metrics_runtime) |*runtime| runtime else null);
        return;
    } else if (if (!force_checkpoint) handles.node_builder.latestStateArchiveSlot() catch null else null) |db_slot| {
        scoped_log.info("found persisted state in DB at slot {d}, resuming", .{db_slot});

        const state_bytes = handles.node_builder.stateArchiveAtSlot(db_slot) catch |err| {
            scoped_log.err("Failed to read state from DB at slot {d}: {}", .{ db_slot, err });
            std.process.exit(1);
        } orelse {
            scoped_log.err("State archive at slot {d} unexpectedly empty", .{db_slot});
            std.process.exit(1);
        };
        defer allocator.free(state_bytes);

        const db_state = state_transition.deserializePublishedState(
            allocator,
            handles.node_builder.sharedStateGraph().pool,
            inputs.beacon_config,
            handles.node_builder.sharedStateGraph().validator_pubkeys,
            state_bytes,
            handles.state_transition_metrics,
        ) catch |err| {
            scoped_log.err("Failed to deserialize DB state at slot {d}: {}", .{ db_slot, err });
            scoped_log.err("  The database may be corrupted. Try --force-checkpoint-sync", .{});
            std.process.exit(1);
        };

        const node = try handles.node_builder.finishCheckpoint(db_state);
        defer node.deinit();
        if (inputs.custom_beacon_config) |cfg| cfg.genesis_validator_root = node.genesis_validators_root;
        scoped_log.info("Resumed from DB state at slot {d}", .{db_slot});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, inputs.api_port, inputs.api_address, inputs.api_cors, handles.p2p_bind_host, handles.p2p_bind_port, if (handles.metrics_runtime) |*runtime| runtime else null);
        return;
    } else if (inputs.network == .minimal) {
        scoped_log.info("generating minimal genesis state with 64 validators", .{});

        const genesis_state = genesis_util.createMinimalGenesis(
            allocator,
            handles.node_builder.sharedStateGraph().pool,
            inputs.beacon_config,
            handles.node_builder.sharedStateGraph().validator_pubkeys,
            64,
            handles.state_transition_metrics,
        ) catch |err| {
            scoped_log.err("Failed to generate minimal genesis state: {}", .{err});
            std.process.exit(1);
        };

        const node = try handles.node_builder.finishGenesis(genesis_state);
        defer node.deinit();
        if (inputs.custom_beacon_config) |cfg| cfg.genesis_validator_root = node.genesis_validators_root;
        scoped_log.info("Initialized from minimal genesis state", .{});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, inputs.api_port, inputs.api_address, inputs.api_cors, handles.p2p_bind_host, handles.p2p_bind_port, if (handles.metrics_runtime) |*runtime| runtime else null);
        return;
    } else {
        scoped_log.err("No beacon state available. Provide one of:", .{});
        scoped_log.err("  --checkpoint-sync-url <URL>  Sync from a beacon API endpoint", .{});
        scoped_log.err("  --checkpoint-state <FILE>    Load from an SSZ state file", .{});
        scoped_log.err("  --network minimal            Generate a test genesis state", .{});
        scoped_log.err("", .{});
        scoped_log.err("Or ensure --data-dir points to a directory with prior chain data.", .{});
        std.process.exit(1);
    }
}
