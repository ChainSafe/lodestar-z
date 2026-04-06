const std = @import("std");

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

fn unsupportedOption(name: []const u8, reason: []const u8) noreturn {
    std.log.err("{s} is not supported: {s}", .{ name, reason });
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

fn loadBeaconConfig(network: common.Network) *const BeaconConfig {
    return switch (network) {
        .mainnet => &config_mod.mainnet.config,
        .sepolia => &config_mod.sepolia.config,
        .holesky => &config_mod.hoodi.config,
        .hoodi => &config_mod.hoodi.config,
        .minimal => &config_mod.minimal.config,
    };
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
        std.log.err("Invalid {s}: expected unsigned integer, got '{s}'", .{ flag_name, raw });
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

    std.log.info("Entering slot clock loop...", .{});

    while (!ShutdownHandler.shouldStop()) {
        const current_slot = clock.currentSlot(io) orelse {
            io.sleep(.{ .nanoseconds = std.time.ns_per_s }, .real) catch return;
            continue;
        };

        const head = node.getHead();
        if (current_slot > head.slot) {
            std.log.info("slot {d} | head: {d} | finalized epoch: {d}", .{
                current_slot,
                head.slot,
                head.finalized_epoch,
            });
        }

        if (node.sync_service_inst) |sync_svc| {
            sync_svc.tick() catch |err| {
                std.log.warn("sync tick error: {}", .{err});
            };
        }

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
        std.log.err("API server failed: {}", .{err});
    };
}

fn runP2p(io: Io, ctx: *RunContext) void {
    ctx.node.startP2p(io, ctx.p2p_host, ctx.p2p_port) catch |err| {
        std.log.err("P2P networking failed: {}", .{err});
    };
}

fn runSlotClock(io: Io, node: *BeaconNode) void {
    slotClockLoop(io, node) catch |err| {
        std.log.err("Slot clock failed: {}", .{err});
    };
}

fn logHeadSummary(node: *BeaconNode) void {
    const head = node.getHead();
    std.log.info("Head: slot={d} root=0x{s}", .{ head.slot, &std.fmt.bytesToHex(head.root, .lower) });
    std.log.info("  finalized_epoch={d} justified_epoch={d}", .{ head.finalized_epoch, head.justified_epoch });
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

    std.log.info("Starting services concurrently...", .{});
    std.log.info("  REST API: http://{s}:{d}", .{ api_address, api_port });
    var p2p_multiaddr_buf: [160]u8 = undefined;
    const p2p_multiaddr = try formatP2pListenMultiaddr(&p2p_multiaddr_buf, p2p_bind_host, p2p_bind_port);
    std.log.info("  P2P:      {s}", .{p2p_multiaddr});

    var group: Io.Group = .init;
    group.async(io, runApiServer, .{ io, &run_ctx });
    group.async(io, runP2p, .{ io, &run_ctx });
    group.async(io, runSlotClock, .{ io, node });

    group.await(io) catch {};

    std.log.info("Shutting down...", .{});
    std.log.info("Goodbye.", .{});
}

pub fn run(io: Io, allocator: Allocator, opts: anytype) !void {
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
    const p2p_host4 = opts.listenAddress orelse opts.p2p_host;
    const p2p_host6 = opts.listenAddress6 orelse opts.p2p_host6;
    const p2p_port = opts.port orelse opts.p2p_port;
    const p2p_port6 = opts.port6 orelse parseOptionalPort(opts.p2p_port6);
    const bootnodes_file = opts.bootnodesFile;
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
    const log_level = opts.logLevel orelse opts.log_level;
    const log_file = opts.logFile orelse opts.log_file;
    const log_format = opts.logFormat orelse opts.log_format;
    const log_file_level = opts.logFileLevel orelse opts.log_file_level;
    const log_file_daily_rotate = opts.logFileDailyRotate orelse opts.log_file_daily_rotate;
    const subscribe_all_subnets = opts.subscribeAllSubnets or opts.subscribe_all_subnets;
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

    var custom_chain_config: config_mod.ChainConfig = undefined;
    var custom_beacon_config: BeaconConfig = undefined;
    const beacon_config: *const BeaconConfig = if (params_file) |config_path| blk: {
        std.log.info("Loading custom network config from: {s}", .{config_path});
        var arena = std.heap.ArenaAllocator.init(allocator);
        const config_arena = arena.allocator();
        const config_bytes = readFile(io, allocator, config_path) catch |err| {
            std.log.err("Failed to read config file '{s}': {}", .{ config_path, err });
            std.process.exit(1);
        };
        defer allocator.free(config_bytes);
        const base = loadBeaconConfig(opts.network);
        custom_chain_config = config_loader.loadConfigFromYaml(config_arena, config_bytes, &base.chain) catch |err| {
            std.log.err("Failed to parse config YAML '{s}': {}", .{ config_path, err });
            std.process.exit(1);
        };
        custom_beacon_config = BeaconConfig.init(custom_chain_config, [_]u8{0} ** 32);
        std.log.info("Custom config loaded: SECONDS_PER_SLOT={d} CONFIG_NAME={s}", .{
            custom_chain_config.SECONDS_PER_SLOT,
            custom_chain_config.CONFIG_NAME,
        });
        break :blk &custom_beacon_config;
    } else loadBeaconConfig(opts.network);

    ShutdownHandler.installSignalHandlers();

    std.log.info("lodestar-z v{s} starting", .{common.VERSION});
    std.log.info("  network:    {s}", .{@tagName(network)});
    std.log.info("  api:        http://{s}:{d}", .{ api_address, api_port });
    if (p2p_host4) |host| std.log.info("  p2p4:       {s}:{d}", .{ host, p2p_port });
    if (p2p_host6) |host| std.log.info("  p2p6:       [{s}]:{d}", .{ host, p2p_port6 orelse p2p_port });
    if (p2p_host4 == null and p2p_host6 == null) {
        std.log.info("  p2p4:       0.0.0.0:{d}", .{p2p_port});
    }
    if (jwt_secret_override) |jwt| {
        std.log.info("  jwt-secret: {s}", .{jwt});
    }
    std.log.info("  execution:  {s}", .{execution_urls});
    std.log.info("  execution retry: attempts={d} delay_ms={d}", .{ execution_retries, execution_retry_delay });
    if (execution_timeout_ms) |value| {
        std.log.info("  execution timeout: {d}ms", .{value});
    } else {
        std.log.info("  execution timeout: default", .{});
    }
    if (builder_enabled) {
        std.log.info("  builder:    {s} (boost={d})", .{ builder_url orelse default_builder_url, builder_boost_factor });
        if (builder_timeout_ms) |value| {
            std.log.info("  builder timeout: {d}ms", .{value});
        } else {
            std.log.info("  builder timeout: default", .{});
        }
    }

    const direct_peers: []const []const u8 = if (direct_peers_raw) |raw| blk: {
        var list: std.ArrayListUnmanaged([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |addr| {
            const trimmed = std.mem.trim(u8, addr, " \t");
            if (trimmed.len > 0) try list.append(allocator, trimmed);
        }
        break :blk try list.toOwnedSlice(allocator);
    } else &.{};
    defer if (direct_peers.len > 0) allocator.free(direct_peers);

    const discovery_port: ?u16 = if (opts.discoveryPort) |port| blk: {
        break :blk port;
    } else if (opts.discovery_port) |port_str| blk: {
        break :blk std.fmt.parseInt(u16, port_str, 10) catch null;
    } else null;
    const discovery_port6 = opts.discoveryPort6;
    const p2p_bind_host = p2p_host4 orelse p2p_host6 orelse "0.0.0.0";
    const p2p_bind_port = if (p2p_host4 != null or p2p_host6 == null)
        p2p_port
    else
        p2p_port6 orelse p2p_port;

    const fee_recipient: ?[20]u8 = if (suggest_fee_recipient) |hex_str| blk: {
        const stripped = if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X'))
            hex_str[2..]
        else
            hex_str;
        if (stripped.len != 40) {
            std.log.err("Invalid --suggest-fee-recipient: expected 40 hex chars, got {d}", .{stripped.len});
            break :blk null;
        }
        var addr: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&addr, stripped) catch {
            std.log.err("Invalid --suggest-fee-recipient: bad hex encoding", .{});
            break :blk null;
        };
        break :blk addr;
    } else null;

    const graffiti_bytes: ?[32]u8 = if (opts.graffiti) |graffiti_str| blk: {
        var g: [32]u8 = [_]u8{0} ** 32;
        const copy_len = @min(graffiti_str.len, 32);
        @memcpy(g[0..copy_len], graffiti_str[0..copy_len]);
        break :blk g;
    } else null;

    const node_opts = NodeOptions{
        .verify_signatures = opts.verify_signatures,
        .rest_enabled = opts.rest,
        .rest_port = api_port,
        .rest_address = api_address,
        .rest_cors_origin = api_cors,
        .execution_urls = &.{execution_urls},
        .engine_mock = engine_mock,
        .execution_retries = execution_retries,
        .execution_retry_delay_ms = execution_retry_delay,
        .execution_timeout_ms = execution_timeout_ms,
        .builder_enabled = builder_enabled,
        .builder_url = builder_url orelse default_builder_url,
        .builder_timeout_ms = builder_timeout_ms,
        .builder_boost_factor = builder_boost_factor,
        .builder_fault_inspection_window = builder_fault_window,
        .builder_allowed_faults = builder_allowed_faults,
        .target_peers = target_peers,
        .target_group_peers = target_group_peers,
        .network = network,
        .p2p_host = p2p_host4,
        .p2p_host6 = p2p_host6,
        .p2p_port = p2p_port,
        .p2p_port6 = p2p_port6,
        .enable_discv5 = opts.discv5,
        .discovery_port = discovery_port,
        .discovery_port6 = discovery_port6,
        .direct_peers = direct_peers,
        .enable_mdns = opts.mdns,
        .subscribe_all_subnets = subscribe_all_subnets,
        .enr_ip = enr_ip,
        .enr_tcp = enr_tcp,
        .enr_udp = enr_udp,
        .enr_ip6 = enr_ip6,
        .enr_tcp6 = enr_tcp6,
        .enr_udp6 = enr_udp6,
        .nat = opts.nat,
        .suggested_fee_recipient = fee_recipient,
        .graffiti = graffiti_bytes,
        .checkpoint_sync_url = checkpoint_sync_url,
        .sync_is_single_node = opts.sync_is_single_node or opts.@"sync.isSingleNode",
    };

    {
        log_mod.global = log_mod.GlobalLogger.init(log_level.toLogLevel(), log_format);
    }

    var file_transport: ?log_mod.FileTransport = null;
    if (log_file) |log_file_path| {
        const file_level = log_file_level.toLogLevel();

        file_transport = log_mod.FileTransport.init(io, log_file_path, file_level, .{
            .max_size_bytes = 100 * 1024 * 1024,
            .max_files = log_file_daily_rotate,
            .daily = log_file_daily_rotate > 0,
        });

        if (file_transport) |*ft| {
            if (log_mod.global.setFileTransport(ft)) |_| {
                std.log.info("File logging enabled: {s} (level={s})", .{
                    log_file_path, file_level.asText(),
                });
            } else |err| {
                std.log.err("Failed to start log file transport '{s}': {}", .{ log_file_path, err });
                file_transport = null;
            }
        }
    }
    defer if (file_transport) |*ft| ft.close();

    var prepared_runtime = try bootstrap.prepareRuntime(
        allocator,
        io,
        .{
            .network = network,
            .data_dir = data_dir,
            .db_path_override = db_path_override,
            .jwt_secret_override = jwt_secret_override,
            .cli_bootnodes = opts.bootnodes,
            .bootnodes_file = bootnodes_file,
            .node_options = node_opts,
            .needs_execution_auth = !engine_mock and execution_urls.len > 0,
            .persist_network_identity = persist_network_identity,
            .private = private_identify,
        },
    );
    defer prepared_runtime.deinit();
    std.log.info("  data-dir:   {s}", .{prepared_runtime.paths.root});
    std.log.info("  bootstrap:  {d} explicit, {d} discovery", .{
        prepared_runtime.bootstrap_peers.len,
        prepared_runtime.discovery_bootnodes.len,
    });

    var beacon_metrics = BeaconMetrics.initNoop();
    defer beacon_metrics.deinit();
    var state_transition_metrics = StateTransitionMetrics.initNoop();
    defer state_transition_metrics.deinit();
    var metrics_surface = MetricsSurface{
        .beacon = &beacon_metrics,
        .state_transition = &state_transition_metrics,
    };
    var metrics_runtime: ?metrics_server.Runtime = null;
    if (opts.metrics) {
        beacon_metrics = try BeaconMetrics.init(allocator);
        state_transition_metrics = try StateTransitionMetrics.init(allocator, io, .{});

        metrics_runtime = metrics_server.Runtime.init(
            io,
            allocator,
            &metrics_surface,
            .{
                .address = metrics_address,
                .port = metrics_port,
            },
        );
    }

    var init_config = prepared_runtime.takeInitConfig(node_opts);
    init_config.metrics = if (opts.metrics) &beacon_metrics else null;
    init_config.state_transition_metrics = &state_transition_metrics;

    var node_builder = try BeaconNode.Builder.init(allocator, io, beacon_config, init_config);
    defer node_builder.deinit();

    std.log.info("BeaconNode bootstrap initialized", .{});
    std.log.info("  peer-id:    {s}", .{node_builder.nodeIdentity().peer_id});
    std.log.info("  enr:        {s}", .{node_builder.nodeIdentity().enr});

    const force_checkpoint = force_checkpoint_sync;

    if (checkpoint_sync_url) |sync_url| {
        std.log.info("Checkpoint sync from URL: {s}", .{sync_url});

        const fetched = checkpoint_sync.fetchFinalizedState(allocator, io, sync_url) catch |err| {
            std.log.err("Failed to fetch checkpoint state from '{s}': {}", .{ sync_url, err });
            std.log.err("  Suggestions:", .{});
            std.log.err("    - Verify the URL is a beacon API endpoint", .{});
            std.log.err("    - Try: curl -s {s}/eth/v1/node/version", .{sync_url});
            std.log.err("    - Use --checkpoint-state <file> as alternative", .{});
            std.process.exit(1);
        };
        defer allocator.free(fetched.state_bytes);

        std.log.info("Deserializing checkpoint state ({d} bytes, fork={s})...", .{
            fetched.state_bytes.len, fetched.fork_name,
        });

        const cp_state = state_transition.deserializePublishedState(
            allocator,
            node_builder.sharedStateGraph().pool,
            beacon_config,
            node_builder.sharedStateGraph().validator_pubkeys,
            fetched.state_bytes,
            &state_transition_metrics,
        ) catch |err| {
            std.log.err("Failed to deserialize checkpoint state: {}", .{err});
            std.log.err("  This may indicate a fork mismatch — check that the", .{});
            std.log.err("  remote node and this node are on the same network.", .{});
            std.process.exit(1);
        };

        if (weak_subjectivity_checkpoint) |ws_str| {
            const ws = checkpoint_sync.parseWeakSubjectivityCheckpoint(ws_str) catch |err| {
                std.log.err("Invalid --weak-subjectivity-checkpoint '{s}': {}", .{ ws_str, err });
                std.process.exit(1);
            };
            const cp_slot = cp_state.state.slot() catch 0;
            checkpoint_sync.validateWeakSubjectivityCheckpoint(ws, cp_slot, @as(u64, preset.SLOTS_PER_EPOCH)) catch {
                std.log.err("Weak subjectivity violation! The checkpoint state does not", .{});
                std.log.err("  match the expected root:epoch. Refusing to sync.", .{});
                std.log.err("  Expected: {s}", .{ws_str});
                std.process.exit(1);
            };
            std.log.info("Weak subjectivity checkpoint validated (epoch {d})", .{ws.epoch});
        }

        const cp_slot = cp_state.state.slot() catch 0;
        const node = try node_builder.finishCheckpoint(cp_state);
        defer node.deinit();
        if (params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from checkpoint sync URL at slot {d}", .{cp_slot});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, api_port, api_address, api_cors, p2p_bind_host, p2p_bind_port, if (metrics_runtime) |*runtime| runtime else null);
        return;
    } else if (checkpoint_state) |state_path| {
        std.log.info("Loading checkpoint state from: {s}", .{state_path});

        const cp_state = genesis_util.loadGenesisFromFile(
            allocator,
            node_builder.sharedStateGraph().pool,
            beacon_config,
            node_builder.sharedStateGraph().validator_pubkeys,
            io,
            state_path,
            &state_transition_metrics,
        ) catch |err| {
            std.log.err("Failed to load checkpoint state '{s}': {}", .{ state_path, err });
            std.process.exit(1);
        };

        if (weak_subjectivity_checkpoint) |ws_str| {
            const ws = checkpoint_sync.parseWeakSubjectivityCheckpoint(ws_str) catch |err| {
                std.log.err("Invalid --weak-subjectivity-checkpoint '{s}': {}", .{ ws_str, err });
                std.process.exit(1);
            };
            const cp_slot = cp_state.state.slot() catch 0;
            checkpoint_sync.validateWeakSubjectivityCheckpoint(ws, cp_slot, @as(u64, preset.SLOTS_PER_EPOCH)) catch {
                std.log.err("Weak subjectivity violation! Refusing to sync.", .{});
                std.process.exit(1);
            };
            std.log.info("Weak subjectivity checkpoint validated (epoch {d})", .{ws.epoch});
        }

        const cp_slot = cp_state.state.slot() catch 0;
        const node = if (cp_slot == 0)
            try node_builder.finishGenesis(cp_state)
        else
            try node_builder.finishCheckpoint(cp_state);
        defer node.deinit();
        if (params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from checkpoint file at slot {d}", .{cp_slot});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, api_port, api_address, api_cors, p2p_bind_host, p2p_bind_port, if (metrics_runtime) |*runtime| runtime else null);
        return;
    } else if (if (!force_checkpoint) node_builder.latestStateArchiveSlot() catch null else null) |db_slot| {
        std.log.info("Found persisted state in DB at slot {d}, resuming...", .{db_slot});

        const state_bytes = node_builder.stateArchiveAtSlot(db_slot) catch |err| {
            std.log.err("Failed to read state from DB at slot {d}: {}", .{ db_slot, err });
            std.process.exit(1);
        } orelse {
            std.log.err("State archive at slot {d} unexpectedly empty", .{db_slot});
            std.process.exit(1);
        };
        defer allocator.free(state_bytes);

        const db_state = state_transition.deserializePublishedState(
            allocator,
            node_builder.sharedStateGraph().pool,
            beacon_config,
            node_builder.sharedStateGraph().validator_pubkeys,
            state_bytes,
            &state_transition_metrics,
        ) catch |err| {
            std.log.err("Failed to deserialize DB state at slot {d}: {}", .{ db_slot, err });
            std.log.err("  The database may be corrupted. Try --force-checkpoint-sync", .{});
            std.process.exit(1);
        };

        const node = try node_builder.finishCheckpoint(db_state);
        defer node.deinit();
        if (params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Resumed from DB state at slot {d}", .{db_slot});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, api_port, api_address, api_cors, p2p_bind_host, p2p_bind_port, if (metrics_runtime) |*runtime| runtime else null);
        return;
    } else if (network == .minimal) {
        std.log.info("Generating minimal genesis state with 64 validators...", .{});

        const genesis_state = genesis_util.createMinimalGenesis(
            allocator,
            node_builder.sharedStateGraph().pool,
            beacon_config,
            node_builder.sharedStateGraph().validator_pubkeys,
            64,
            &state_transition_metrics,
        ) catch |err| {
            std.log.err("Failed to generate minimal genesis state: {}", .{err});
            std.process.exit(1);
        };

        const node = try node_builder.finishGenesis(genesis_state);
        defer node.deinit();
        if (params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from minimal genesis state", .{});
        logHeadSummary(node);
        try runBootstrappedNode(io, node, api_port, api_address, api_cors, p2p_bind_host, p2p_bind_port, if (metrics_runtime) |*runtime| runtime else null);
        return;
    } else {
        std.log.err("No beacon state available. Provide one of:", .{});
        std.log.err("  --checkpoint-sync-url <URL>  Sync from a beacon API endpoint", .{});
        std.log.err("  --checkpoint-state <FILE>    Load from an SSZ state file", .{});
        std.log.err("  --network minimal            Generate a test genesis state", .{});
        std.log.err("", .{});
        std.log.err("Or ensure --data-dir points to a directory with prior chain data.", .{});
        std.process.exit(1);
    }
}
