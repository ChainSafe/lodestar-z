const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const validator_mod = @import("validator");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const config_loader = config_mod.config_loader;
const common = @import("../../spec_common.zig");
const constants = @import("constants");
const preset = @import("preset").preset;
const paths_mod = @import("paths.zig");

pub const PreparedRuntime = struct {
    network: common.Network,
    paths: paths_mod.Paths,
    primary_beacon_url: []const u8,
    fallback_urls: []const []const u8 = &.{},
    startup_signers: validator_mod.StartupSigners,
    validator_config: validator_mod.ValidatorConfig,
    signing_context: validator_mod.SigningContext,

    pub fn deinit(self: *PreparedRuntime, io: Io) void {
        self.startup_signers.deinit(io);
        freeOwnedStrings(self.paths.allocator, self.fallback_urls);
        self.paths.deinit();
    }

    pub fn validateSignerAvailability(self: *const PreparedRuntime) !void {
        const counts = self.startup_signers.counts();
        if (counts.total > 0) return;

        if (self.validator_config.web3signer_url) |url| {
            std.log.warn(
                "No validator keys loaded at startup; waiting for keys from external signer {s}",
                .{url},
            );
            return;
        }

        std.log.err("No local validator keystores found under {s}", .{self.paths.keystores_dir});
        std.log.err("Populate the keystores and secrets directories before starting the validator client.", .{});
        return error.NoValidatorsConfigured;
    }

    pub fn logStartup(self: *const PreparedRuntime) void {
        const counts = self.startup_signers.counts();

        std.log.info("lodestar-z validator starting", .{});
        std.log.info("  network:      {s}", .{@tagName(self.network.toNetworkName())});
        std.log.info("  beacon-node:  {s}", .{self.primary_beacon_url});
        std.log.info("  data-dir:     {s}", .{self.paths.root});
        std.log.info("  validator-db: {s}", .{self.paths.validators_db_dir});
        std.log.info("  keystores:    {s}", .{self.paths.keystores_dir});
        std.log.info("  secrets:      {s}", .{self.paths.secrets_dir});
        std.log.info("  slashing-db:  {s}", .{self.paths.slashing_protection_db});
        std.log.info("  validators:   {d} total ({d} local, {d} remote)", .{
            counts.total,
            counts.local,
            counts.remote,
        });
        if (self.validator_config.web3signer_url) |url| {
            std.log.info("  web3signer:   {s}", .{url});
        }
    }
};

pub fn prepareRuntime(io: Io, allocator: Allocator, opts: anytype) !PreparedRuntime {
    const network = opts.network;
    const data_dir = opts.dataDir orelse opts.data_dir;
    const params_file = opts.paramsFile orelse opts.params_file;
    const beacon_nodes_raw = opts.beaconNodes orelse opts.server;
    const primary_beacon_url = if (beacon_nodes_raw) |raw| firstCsvValue(raw) else opts.beacon_url;
    const external_signer_urls = opts.@"externalSigner.urls" orelse opts.@"externalSigner.url";

    var custom_chain_config: config_mod.ChainConfig = undefined;
    var custom_beacon_config: BeaconConfig = undefined;
    const base_beacon_config = loadBeaconConfig(network);
    const beacon_config: *const BeaconConfig = if (params_file) |config_path| blk: {
        std.log.info("Loading custom network config from: {s}", .{config_path});
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const config_bytes = readFileAlloc(io, allocator, config_path) catch |err| {
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

    var paths = try paths_mod.Paths.resolve(allocator, .{
        .data_dir = data_dir,
        .network = network,
        .validators_db_dir = opts.validatorsDbDir,
        .keystores_dir = opts.keystoresDir,
        .secrets_dir = opts.secretsDir,
        .remote_keys_dir = opts.remoteKeysDir,
        .proposer_dir = opts.proposerDir,
    });
    errdefer paths.deinit();
    try paths.ensureDirs(io);

    var startup_signers = validator_mod.StartupSigners{ .allocator = allocator };
    errdefer startup_signers.deinit(io);

    startup_signers = try validator_mod.loadLocalSigners(io, allocator, paths.keystores_dir, paths.secrets_dir, .{
        .force = opts.force,
    });
    if (external_signer_urls) |raw| {
        const url = firstCsvValue(raw);
        startup_signers.remote_pubkeys = try validator_mod.fetchRemoteSignerPubkeys(io, allocator, url);
    }

    var fallback_urls: []const []const u8 = &.{};
    errdefer freeOwnedStrings(allocator, fallback_urls);
    if (beacon_nodes_raw) |raw| {
        const urls = try splitCsvOwned(allocator, raw);
        defer freeOwnedStrings(allocator, urls);

        if (urls.len > 1) {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            errdefer {
                for (list.items) |item| allocator.free(item);
                list.deinit(allocator);
            }

            for (urls[1..]) |url| {
                try list.append(allocator, try allocator.dupe(u8, url));
            }
            fallback_urls = try list.toOwnedSlice(allocator);
        }
    }

    var beacon_api = if (fallback_urls.len > 0)
        validator_mod.BeaconApiClient{
            .allocator = allocator,
            .base_url = primary_beacon_url,
            .fallback_urls = fallback_urls,
            .active_url_idx = 0,
            .consecutive_failures = 0,
            .was_unreachable = false,
            .unreachable_since_ns = 0,
        }
    else
        validator_mod.BeaconApiClient.init(allocator, primary_beacon_url);
    defer beacon_api.deinit();

    const genesis = try waitForGenesis(io, &beacon_api, primary_beacon_url);

    if (params_file != null) {
        custom_beacon_config.genesis_validator_root = genesis.genesis_validators_root;
    }

    try ensureGenesisForkVersionMatches(beacon_config, genesis);
    const remote_spec = beacon_api.getConfigSpec(io) catch |err| {
        std.log.err("Failed to fetch beacon config spec from {s}: {}", .{ primary_beacon_url, err });
        return err;
    };
    try ensureConfigSpecMatches(beacon_config, remote_spec);
    try validator_mod.ensureGenesisMetadata(io, allocator, paths.metadata_file, genesis);

    const web3signer_url = if (external_signer_urls) |raw| blk: {
        break :blk firstCsvValue(raw);
    } else null;

    const fee_recipient = parseFeeRecipient(opts.suggestedFeeRecipient) catch |err| {
        std.log.err("Invalid --suggestedFeeRecipient: {}", .{err});
        return err;
    };
    const builder_boost_factor = parseBuilderBoostFactor(opts.@"builder.boostFactor") catch |err| {
        std.log.err("Invalid --builder.boostFactor: {}", .{err});
        return err;
    };

    return .{
        .network = network,
        .paths = paths,
        .primary_beacon_url = primary_beacon_url,
        .fallback_urls = fallback_urls,
        .startup_signers = startup_signers,
        .signing_context = buildSigningContext(beacon_config, genesis),
        .validator_config = .{
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
            .slashing_protection_path = paths.slashing_protection_db,
            .web3signer_url = web3signer_url,
            .beacon_node_fallback_urls = fallback_urls,
            .suggested_fee_recipient = fee_recipient,
            .gas_limit = opts.defaultGasLimit orelse 30_000_000,
            .graffiti = parseGraffiti(opts.graffiti),
            .builder_boost_factor = builder_boost_factor,
        },
    };
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

fn readFileAlloc(io: Io, allocator: Allocator, path: []const u8) ![]u8 {
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
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        try list.append(allocator, try allocator.dupe(u8, trimmed));
    }

    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn freeOwnedStrings(allocator: Allocator, items: []const []const u8) void {
    if (items.len == 0) return;
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

fn waitForGenesis(
    io: Io,
    beacon_api: *validator_mod.BeaconApiClient,
    beacon_url: []const u8,
) !validator_mod.api_client.GenesisResponse {
    var attempts: usize = 0;
    while (true) {
        const ShutdownHandler = @import("../../shutdown.zig").ShutdownHandler;
        if (ShutdownHandler.shouldStop()) return error.ShutdownRequested;

        const genesis = beacon_api.getGenesis(io) catch |err| {
            attempts += 1;
            if (attempts == 1 or attempts % 12 == 0) {
                std.log.warn("Waiting for beacon genesis from {s}: {s}", .{ beacon_url, @errorName(err) });
            }
            try io.sleep(.{ .nanoseconds = 5 * std.time.ns_per_s }, .real);
            continue;
        };

        if (attempts > 0) {
            std.log.info("Fetched beacon genesis from {s} after {d} retry attempt(s)", .{ beacon_url, attempts });
        }
        return genesis;
    }
}

fn ensureGenesisForkVersionMatches(
    beacon_config: *const BeaconConfig,
    genesis: validator_mod.api_client.GenesisResponse,
) !void {
    if (!std.mem.eql(u8, &beacon_config.chain.GENESIS_FORK_VERSION, &genesis.genesis_fork_version)) {
        std.log.err(
            "Beacon node genesis fork version mismatch expected=0x{s} actual=0x{s}",
            .{
                std.fmt.bytesToHex(&beacon_config.chain.GENESIS_FORK_VERSION, .lower),
                std.fmt.bytesToHex(&genesis.genesis_fork_version, .lower),
            },
        );
        return error.BeaconConfigMismatch;
    }
}

fn compareOptionalUintField(name: []const u8, expected: u64, actual: ?u64) !void {
    if (actual) |value| {
        if (value != expected) {
            std.log.err("Beacon node config mismatch field={s} expected={d} actual={d}", .{ name, expected, value });
            return error.BeaconConfigMismatch;
        }
    }
}

fn compareOptionalVersionField(name: []const u8, expected: [4]u8, actual: ?[4]u8) !void {
    if (actual) |value| {
        if (!std.mem.eql(u8, &expected, &value)) {
            std.log.err("Beacon node config mismatch field={s} expected=0x{s} actual=0x{s}", .{
                name,
                std.fmt.bytesToHex(&expected, .lower),
                std.fmt.bytesToHex(&value, .lower),
            });
            return error.BeaconConfigMismatch;
        }
    }
}

fn ensureConfigSpecMatches(
    beacon_config: *const BeaconConfig,
    spec: validator_mod.api_client.ConfigSpecResponse,
) !void {
    try compareOptionalVersionField("GENESIS_FORK_VERSION", beacon_config.chain.GENESIS_FORK_VERSION, spec.genesis_fork_version);
    try compareOptionalVersionField("ALTAIR_FORK_VERSION", beacon_config.chain.ALTAIR_FORK_VERSION, spec.altair_fork_version);
    try compareOptionalUintField("ALTAIR_FORK_EPOCH", beacon_config.chain.ALTAIR_FORK_EPOCH, spec.altair_fork_epoch);
    try compareOptionalVersionField("BELLATRIX_FORK_VERSION", beacon_config.chain.BELLATRIX_FORK_VERSION, spec.bellatrix_fork_version);
    try compareOptionalUintField("BELLATRIX_FORK_EPOCH", beacon_config.chain.BELLATRIX_FORK_EPOCH, spec.bellatrix_fork_epoch);
    try compareOptionalVersionField("CAPELLA_FORK_VERSION", beacon_config.chain.CAPELLA_FORK_VERSION, spec.capella_fork_version);
    try compareOptionalUintField("CAPELLA_FORK_EPOCH", beacon_config.chain.CAPELLA_FORK_EPOCH, spec.capella_fork_epoch);
    try compareOptionalVersionField("DENEB_FORK_VERSION", beacon_config.chain.DENEB_FORK_VERSION, spec.deneb_fork_version);
    try compareOptionalUintField("DENEB_FORK_EPOCH", beacon_config.chain.DENEB_FORK_EPOCH, spec.deneb_fork_epoch);
    try compareOptionalVersionField("ELECTRA_FORK_VERSION", beacon_config.chain.ELECTRA_FORK_VERSION, spec.electra_fork_version);
    try compareOptionalUintField("ELECTRA_FORK_EPOCH", beacon_config.chain.ELECTRA_FORK_EPOCH, spec.electra_fork_epoch);
    try compareOptionalUintField("SECONDS_PER_SLOT", beacon_config.chain.SECONDS_PER_SLOT, spec.seconds_per_slot);
    try compareOptionalUintField("MIN_GENESIS_TIME", beacon_config.chain.MIN_GENESIS_TIME, spec.min_genesis_time);
}

fn buildSigningContext(
    beacon_config: *const BeaconConfig,
    genesis: validator_mod.api_client.GenesisResponse,
) validator_mod.SigningContext {
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
