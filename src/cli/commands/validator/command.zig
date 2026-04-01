const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const validator_mod = @import("validator");
const log_mod = @import("log");
const cli_paths = @import("../../paths.zig");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const config_loader = config_mod.config_loader;
const common = @import("../../spec_common.zig");
const ShutdownHandler = @import("../../shutdown.zig").ShutdownHandler;
const constants = @import("constants");
const preset = @import("preset").preset;

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
    const stat = try file.stat(io);
    const buf = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    if (n != stat.size) return error.ShortRead;
    return buf;
}

fn firstCsvValue(input: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, input, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len > 0) return trimmed;
    }
    return input;
}

fn splitCsvOwned(allocator: Allocator, raw: []const u8) ![]const []const u8 {
    var list = std.array_list.Managed([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        try list.append(try allocator.dupe(u8, trimmed));
    }

    return try list.toOwnedSlice();
}

fn freeOwnedStrings(allocator: Allocator, items: []const []const u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn parseFeeRecipient(input: ?[]const u8) ![20]u8 {
    var out: [20]u8 = [_]u8{0} ** 20;
    const raw = input orelse return out;
    const stripped = if (std.mem.startsWith(u8, raw, "0x") or std.mem.startsWith(u8, raw, "0X")) raw[2..] else raw;
    if (stripped.len != 40) return error.InvalidFeeRecipient;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

fn parseGraffiti(input: ?[]const u8) [32]u8 {
    var graffiti: [32]u8 = [_]u8{0} ** 32;
    if (input) |raw| {
        const copy_len = @min(raw.len, graffiti.len);
        @memcpy(graffiti[0..copy_len], raw[0..copy_len]);
    }
    return graffiti;
}

fn parseBuilderBoostFactor(input: ?[]const u8) !?u64 {
    const raw = input orelse return null;
    return try std.fmt.parseInt(u64, raw, 10);
}

fn buildSigningContext(beacon_config: *const BeaconConfig, genesis: validator_mod.api_client.GenesisResponse) validator_mod.SigningContext {
    var ctx = validator_mod.SigningContext{
        .genesis_validators_root = genesis.genesis_validators_root,
        .genesis_time_unix_secs = genesis.genesis_time,
        .seconds_per_slot = beacon_config.chain.SECONDS_PER_SLOT,
        .slots_per_epoch = preset.SLOTS_PER_EPOCH,
        .fork_schedule_len = beacon_config.forks_ascending_epoch_order.len,
        .fork_schedule = std.mem.zeroes([16]validator_mod.SigningContext.ForkEntry),
        .capella_fork_version = beacon_config.chain.CAPELLA_FORK_VERSION,
        .deneb_fork_epoch = beacon_config.chain.DENEB_FORK_EPOCH,
    };

    for (beacon_config.forks_ascending_epoch_order, 0..) |fork, i| {
        ctx.fork_schedule[i] = .{
            .epoch = fork.epoch,
            .version = fork.version,
        };
    }

    return ctx;
}

pub fn run(io: Io, allocator: Allocator, opts: anytype) !void {
    const network = opts.network.toNetworkName();
    const data_dir = opts.dataDir orelse opts.data_dir;
    const params_file = opts.paramsFile orelse opts.params_file;
    const beacon_nodes_raw = opts.beaconNodes orelse opts.server;
    const primary_beacon_url = if (beacon_nodes_raw) |raw| firstCsvValue(raw) else opts.beacon_url;
    const log_level = opts.logLevel orelse opts.log_level;
    const log_format = opts.logFormat orelse .human;
    const log_file = opts.logFile;
    const log_file_level = opts.logFileLevel orelse .debug;
    const log_file_daily_rotate = opts.logFileDailyRotate orelse 5;
    const external_signer_urls = opts.@"externalSigner.urls" orelse opts.@"externalSigner.url";

    log_mod.global = log_mod.GlobalLogger.init(log_level.toLogLevel(), log_format);

    var file_transport: ?log_mod.FileTransport = null;
    if (log_file) |log_file_path| {
        file_transport = log_mod.FileTransport.init(io, log_file_path, log_file_level.toLogLevel(), .{
            .max_size_bytes = 100 * 1024 * 1024,
            .max_files = log_file_daily_rotate,
            .daily = log_file_daily_rotate > 0,
        });
        if (file_transport) |*ft| {
            if (log_mod.global.setFileTransport(ft)) |_| {} else |err| {
                std.log.err("Failed to start log file transport '{s}': {}", .{ log_file_path, err });
                file_transport = null;
            }
        }
    }
    defer if (file_transport) |*ft| ft.close();

    var custom_chain_config: config_mod.ChainConfig = undefined;
    var custom_beacon_config: BeaconConfig = undefined;
    const base_beacon_config = loadBeaconConfig(opts.network);
    const beacon_config: *const BeaconConfig = if (params_file) |config_path| blk: {
        std.log.info("Loading custom network config from: {s}", .{config_path});
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const config_bytes = readFile(io, allocator, config_path) catch |err| {
            std.log.err("Failed to read config file '{s}': {}", .{ config_path, err });
            return err;
        };
        defer allocator.free(config_bytes);
        custom_chain_config = config_loader.loadConfigFromYaml(arena.allocator(), config_bytes, &base_beacon_config.chain) catch |err| {
            std.log.err("Failed to parse config YAML '{s}': {}", .{ config_path, err });
            return err;
        };
        custom_beacon_config = BeaconConfig.init(custom_chain_config, [_]u8{0} ** 32);
        break :blk &custom_beacon_config;
    } else base_beacon_config;

    var data_dir_info = try cli_paths.DataPaths.resolve(allocator, .{
        .data_dir = data_dir,
        .network = network,
    });
    defer data_dir_info.deinit();
    try data_dir_info.ensureDirs(io);

    const keystores_dir = opts.keystoresDir orelse data_dir_info.keystores;
    const secrets_dir = opts.secretsDir orelse data_dir_info.secrets;
    const validators_db_dir = if (opts.validatorsDbDir) |dir|
        try std.fs.path.join(allocator, &.{ dir, "slashing-protection.db" })
    else
        data_dir_info.slashing_protection;
    defer if (opts.validatorsDbDir != null) allocator.free(validators_db_dir);
    if (std.fs.path.dirname(validators_db_dir)) |parent| {
        try Io.Dir.cwd().createDirPath(io, parent);
    }

    var beacon_api = validator_mod.BeaconApiClient.init(allocator, primary_beacon_url);
    defer beacon_api.deinit();
    const genesis = beacon_api.getGenesis(io) catch |err| {
        std.log.err("Failed to fetch beacon genesis from {s}: {}", .{ primary_beacon_url, err });
        return err;
    };

    if (params_file != null) {
        custom_beacon_config.genesis_validator_root = genesis.genesis_validators_root;
    }

    const signing_ctx = buildSigningContext(beacon_config, genesis);

    var fallback_urls: [][]const u8 = &.{};
    defer if (fallback_urls.len > 0) freeOwnedStrings(allocator, fallback_urls);
    if (beacon_nodes_raw) |raw| {
        const urls = try splitCsvOwned(allocator, raw);
        if (urls.len > 1) {
            fallback_urls = try allocator.alloc([]const u8, urls.len - 1);
            for (urls[1..], 0..) |url, i| {
                fallback_urls[i] = try allocator.dupe(u8, url);
            }
        }
        freeOwnedStrings(allocator, urls);
    }

    if (opts.metrics or opts.@"metrics.port" != null or opts.@"metrics.address" != null) {
        std.log.warn("Validator metrics flags are accepted but metrics server wiring is not implemented yet.", .{});
    }
    if (opts.@"monitoring.endpoint" != null or opts.@"monitoring.interval" != null) {
        std.log.warn("Validator monitoring flags are accepted but monitoring service wiring is not implemented yet.", .{});
    }
    if (opts.importKeystores != null or opts.importKeystoresPassword != null) {
        std.log.warn("validator import flags are not wired into startup; use the validator keystore/secrets directories directly.", .{});
    }

    const web3signer_url = if (external_signer_urls) |raw| blk: {
        const first = firstCsvValue(raw);
        if (std.mem.indexOfScalar(u8, raw, ',')) |_| {
            std.log.warn("Multiple external signer URLs provided, using the first one: {s}", .{first});
        }
        break :blk first;
    } else null;

    const fee_recipient = parseFeeRecipient(opts.suggestedFeeRecipient) catch |err| {
        std.log.err("Invalid --suggestedFeeRecipient: {}", .{err});
        return err;
    };
    const builder_boost_factor = parseBuilderBoostFactor(opts.@"builder.boostFactor") catch |err| {
        std.log.err("Invalid --builder.boostFactor: {}", .{err});
        return err;
    };

    const vc_config = validator_mod.ValidatorConfig{
        .beacon_node_url = primary_beacon_url,
        .genesis_time = genesis.genesis_time,
        .genesis_validators_root = genesis.genesis_validators_root,
        .seconds_per_slot = beacon_config.chain.SECONDS_PER_SLOT,
        .slots_per_epoch = preset.SLOTS_PER_EPOCH,
        .epochs_per_sync_committee_period = preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
        .sync_committee_size = preset.SYNC_COMMITTEE_SIZE,
        .sync_committee_subnet_count = constants.SYNC_COMMITTEE_SUBNET_COUNT,
        .electra_fork_epoch = beacon_config.chain.ELECTRA_FORK_EPOCH,
        .doppelganger_protection = opts.doppelgangerProtection,
        .slashing_protection_path = validators_db_dir,
        .keystores_dir = keystores_dir,
        .secrets_dir = secrets_dir,
        .web3signer_url = web3signer_url,
        .beacon_node_fallback_urls = fallback_urls,
        .suggested_fee_recipient = fee_recipient,
        .gas_limit = opts.defaultGasLimit orelse 30_000_000,
        .graffiti = parseGraffiti(opts.graffiti),
        .builder_boost_factor = builder_boost_factor,
    };

    const client = try allocator.create(validator_mod.ValidatorClient);
    defer allocator.destroy(client);
    client.* = try validator_mod.ValidatorClient.init(io, allocator, vc_config, signing_ctx);
    defer client.deinit();

    ShutdownHandler.installSignalHandlers();

    const WatchCtx = struct {
        io: Io,
        client: *validator_mod.ValidatorClient,
        done: std.atomic.Value(bool),
    };

    const watch_ctx = try allocator.create(WatchCtx);
    defer allocator.destroy(watch_ctx);
    watch_ctx.* = .{
        .io = io,
        .client = client,
        .done = std.atomic.Value(bool).init(false),
    };

    const watcher = try std.Thread.spawn(.{}, struct {
        fn run(ctx: *WatchCtx) void {
            while (!ctx.done.load(.acquire)) {
                if (ShutdownHandler.shouldStop()) {
                    ctx.client.requestShutdown();
                    return;
                }
                ctx.io.sleep(.{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch return;
            }
        }
    }.run, .{watch_ctx});
    defer {
        watch_ctx.done.store(true, .release);
        watcher.join();
    }

    std.log.info("lodestar-z validator starting", .{});
    std.log.info("  network:      {s}", .{@tagName(network)});
    std.log.info("  beacon-node:  {s}", .{primary_beacon_url});
    std.log.info("  data-dir:     {s}", .{data_dir_info.root});
    std.log.info("  keystores:    {s}", .{keystores_dir});
    std.log.info("  secrets:      {s}", .{secrets_dir});
    std.log.info("  slashing-db:  {s}", .{validators_db_dir});
    if (web3signer_url) |url| {
        std.log.info("  web3signer:   {s}", .{url});
    }

    try client.start(io);
}
