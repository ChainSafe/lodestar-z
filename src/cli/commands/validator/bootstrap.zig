const std = @import("std");
const scoped_log = std.log.scoped(.validator_bootstrap);
const yaml = @import("yaml");
const Yaml = yaml.Yaml;

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

const RemoteSignerSource = enum {
    none,
    persisted,
    pinned,
    fetch,
};

pub const KeymanagerConfig = struct {
    address: []const u8,
    port: u16,
    cors_origin: ?[]const u8,
    auth_enabled: bool,
    token_file: []const u8,
    header_limit: usize,
    body_limit: usize,
    stacktraces: bool,
    proposer_config_write_enabled: bool,
};

pub const MonitoringConfig = validator_mod.MonitoringOptions;

pub const PreparedRuntime = struct {
    network: common.Network,
    paths: paths_mod.Paths,
    beacon_config: BeaconConfig,
    primary_beacon_url: []const u8,
    fallback_urls: []const []const u8 = &.{},
    external_signer_urls: []const []const u8 = &.{},
    remote_signer_source: RemoteSignerSource = .none,
    external_signer_fetch_enabled: bool = false,
    keymanager: ?KeymanagerConfig = null,
    monitoring: ?MonitoringConfig = null,
    proposer_settings_file: ?[]const u8 = null,
    startup_signers: validator_mod.StartupSigners,
    validator_config: validator_mod.ValidatorConfig,
    signing_context: validator_mod.SigningContext,

    pub fn deinit(self: *PreparedRuntime, io: Io) void {
        self.startup_signers.deinit(io);
        if (self.validator_config.proposer_configs.len > 0) {
            self.paths.allocator.free(self.validator_config.proposer_configs);
        }
        freeOwnedStrings(self.paths.allocator, self.fallback_urls);
        freeOwnedStrings(self.paths.allocator, self.external_signer_urls);
        self.paths.deinit();
    }

    pub fn validateSignerAvailability(self: *const PreparedRuntime) !void {
        const counts = self.startup_signers.counts();
        if (counts.total > 0) return;

        if (self.keymanager != null and self.remote_signer_source == .fetch and self.external_signer_urls.len > 0) {
            scoped_log.warn(
                "No validator keys loaded at startup; waiting for keys from the keymanager API or {d} configured external signer(s)",
                .{self.external_signer_urls.len},
            );
            return;
        }

        if (self.keymanager != null) {
            scoped_log.warn("No validator keys loaded at startup; waiting for keys to be imported through the keymanager API", .{});
            return;
        }

        if (self.remote_signer_source == .fetch and self.external_signer_urls.len > 0) {
            scoped_log.warn(
                "No validator keys loaded at startup; waiting for keys from {d} configured external signer(s)",
                .{self.external_signer_urls.len},
            );
            return;
        }

        scoped_log.err("No local validator keystores found under {s}", .{self.paths.keystores_dir});
        scoped_log.err("Populate the keystores and secrets directories before starting the validator client.", .{});
        return error.NoValidatorsConfigured;
    }

    pub fn logStartup(self: *const PreparedRuntime) void {
        const counts = self.startup_signers.counts();

        scoped_log.info("lodestar-z validator starting", .{});
        scoped_log.info("  network:      {s}", .{@tagName(self.network.toNetworkName())});
        scoped_log.info("  beacon-node:  {s}", .{self.primary_beacon_url});
        scoped_log.info("  data-dir:     {s}", .{self.paths.root});
        scoped_log.info("  validator-db: {s}", .{self.paths.validators_db_dir});
        scoped_log.info("  keystores:    {s}", .{self.paths.keystores_dir});
        scoped_log.info("  secrets:      {s}", .{self.paths.secrets_dir});
        scoped_log.info("  slashing-db:  {s}", .{self.paths.slashing_protection_db});
        scoped_log.info("  builder selection: {s}", .{@tagName(self.validator_config.builder_selection)});
        scoped_log.info("  block publish validation: {s}", .{@tagName(self.validator_config.broadcast_validation)});
        if (self.validator_config.distributed) {
            scoped_log.info("  distributed validator mode: enabled", .{});
        }
        scoped_log.info("  validators:   {d} total ({d} local, {d} remote)", .{
            counts.total,
            counts.local,
            counts.remote,
        });
        if (self.external_signer_urls.len > 0) {
            scoped_log.info("  web3signers:  {d} endpoint(s)", .{self.external_signer_urls.len});
            scoped_log.info("  remote-mode:  {s}", .{
                switch (self.remote_signer_source) {
                    .fetch => "fetch",
                    .pinned => "pinned",
                    .persisted => "persisted remoteKeys",
                    .none => "none",
                },
            });
            for (self.external_signer_urls) |url| {
                scoped_log.info("    external-signer: {s}", .{url});
            }
        }
        if (self.keymanager) |keymanager| {
            scoped_log.info("  keymanager:   http://{s}:{d}", .{ keymanager.address, keymanager.port });
            if (!keymanager.proposer_config_write_enabled) {
                scoped_log.info("  keymanager proposer writes: disabled (owned by proposer settings file)", .{});
            }
        }
        if (self.monitoring) |monitoring| {
            scoped_log.info("  monitoring:   {s} every {d}ms", .{ monitoring.endpoint, monitoring.interval_ms });
            if (monitoring.collect_system_stats) {
                scoped_log.info("  monitoring system stats: enabled", .{});
            }
        }
        if (self.proposer_settings_file) |path| {
            scoped_log.info("  proposer settings: {s}", .{path});
        }
    }
};

pub fn prepareRuntime(io: Io, allocator: Allocator, opts: anytype) !PreparedRuntime {
    const network = opts.network;
    const data_dir = opts.dataDir orelse opts.data_dir;
    const params_file = opts.paramsFile orelse opts.params_file;
    const beacon_nodes_raw = opts.beaconNodes;
    const primary_beacon_url = if (beacon_nodes_raw) |raw| firstCsvValue(raw) else opts.beacon_url;
    const external_signer_urls_raw = opts.@"externalSigner.urls";

    var custom_chain_config: config_mod.ChainConfig = undefined;
    var custom_beacon_config: BeaconConfig = undefined;
    const base_beacon_config = loadBeaconConfig(network);
    const beacon_config: *const BeaconConfig = if (params_file) |config_path| blk: {
        scoped_log.info("loading custom network config from {s}", .{config_path});
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const config_bytes = readFileAlloc(io, allocator, config_path) catch |err| {
            scoped_log.err("Failed to read config file '{s}': {}", .{ config_path, err });
            return err;
        };
        defer allocator.free(config_bytes);
        custom_chain_config = config_loader.loadConfigFromYaml(arena.allocator(), config_bytes, &base_beacon_config.chain) catch |err| {
            scoped_log.err("Failed to parse config YAML '{s}': {}", .{ config_path, err });
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

    const persistence_paths: validator_mod.PersistencePaths = .{
        .keystores_dir = paths.keystores_dir,
        .secrets_dir = paths.secrets_dir,
        .remote_keys_dir = paths.remote_keys_dir,
        .proposer_dir = paths.proposer_dir,
    };

    if (opts.importKeystores) |raw_import_paths| {
        const import_paths = try splitCsvOwnedUnique(allocator, raw_import_paths);
        defer freeOwnedStrings(allocator, import_paths);

        if (import_paths.len == 0) {
            return error.NoImportKeystoresFound;
        }

        const password_file = opts.importKeystoresPassword orelse return error.MissingImportKeystorePassword;
        _ = validator_mod.importExternalKeystores(
            io,
            allocator,
            persistence_paths,
            import_paths,
            password_file,
        ) catch |err| {
            scoped_log.err("Failed to import startup keystores: {}", .{err});
            return err;
        };
    }

    const cli_default_proposer_config = try parseCliDefaultProposerConfig(opts);

    var external_signer_urls: []const []const u8 = if (external_signer_urls_raw) |raw|
        try splitCsvOwnedUnique(allocator, raw)
    else
        &.{};
    errdefer freeOwnedStrings(allocator, external_signer_urls);
    for (external_signer_urls) |url| {
        validator_mod.validateRemoteSignerUrl(url) catch |err| {
            scoped_log.err("Invalid external signer URL '{s}': {}", .{ url, err });
            return err;
        };
    }

    var startup_signers = validator_mod.StartupSigners{ .allocator = allocator };
    errdefer startup_signers.deinit(io);

    startup_signers = try validator_mod.loadLocalSigners(io, allocator, paths.keystores_dir, paths.secrets_dir, .{
        .force = opts.force,
        .cache_dir = paths.cache_dir,
        .disable_thread_pool = opts.disableKeystoresThreadPool,
    });
    const external_signer_fetch_enabled = opts.@"externalSigner.fetch";
    var remote_signer_source: RemoteSignerSource = .none;
    if ((external_signer_fetch_enabled or opts.@"externalSigner.pubkeys" != null) and
        try directoryHasEntries(io, paths.remote_keys_dir))
    {
        scoped_log.info(
            "Ignoring persisted remote signer definitions under {s} because explicit external signer options were provided",
            .{paths.remote_keys_dir},
        );
    }
    if (external_signer_fetch_enabled) {
        startup_signers.remote_signers = try validator_mod.fetchRemoteSignerKeys(io, allocator, external_signer_urls);
        remote_signer_source = .fetch;
    } else if (opts.@"externalSigner.pubkeys") |raw_pubkeys| {
        startup_signers.remote_signers = try loadPinnedRemoteSignerKeys(allocator, external_signer_urls, raw_pubkeys);
        remote_signer_source = .pinned;
    } else {
        startup_signers.remote_signers = try validator_mod.loadPersistedRemoteSignerKeys(io, allocator, paths.remote_keys_dir);
        if (startup_signers.remote_signers.len > 0) {
            external_signer_urls = try duplicateRemoteSignerUrls(allocator, startup_signers.remote_signers);
            remote_signer_source = .persisted;
        }
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

    var beacon_api = try validator_mod.BeaconApiClient.initWithOptions(allocator, io, .{
        .base_url = primary_beacon_url,
        .fallback_urls = fallback_urls,
        .request_timeout_ms = beacon_config.chain.SECONDS_PER_SLOT * std.time.ms_per_s,
    });
    defer beacon_api.deinit();

    const genesis = try waitForGenesis(io, &beacon_api, primary_beacon_url);

    if (params_file != null) {
        custom_beacon_config.genesis_validator_root = genesis.genesis_validators_root;
    }

    try ensureGenesisForkVersionMatches(beacon_config, genesis);
    const remote_spec = beacon_api.getConfigSpec(io) catch |err| {
        scoped_log.err("Failed to fetch beacon config spec from {s}: {}", .{ primary_beacon_url, err });
        return err;
    };
    defer {
        var spec = remote_spec;
        spec.deinit(allocator);
    }
    try ensureConfigSpecMatches(beacon_config, remote_spec);
    try validator_mod.ensureGenesisMetadata(io, allocator, paths.metadata_file, genesis);

    const external_signer_fetch_interval_ms = parseExternalSignerFetchInterval(opts.@"externalSigner.fetchInterval") catch |err| {
        scoped_log.err("Invalid --externalSigner.fetchInterval: {}", .{err});
        return err;
    };
    const keymanager_header_limit = parseKeymanagerHeaderLimit(opts.@"keymanager.headerLimit") catch |err| {
        scoped_log.err("Invalid --keymanager.headerLimit: {}", .{err});
        return err;
    };
    const keymanager_body_limit = parseKeymanagerBodyLimit(opts.@"keymanager.bodyLimit") catch |err| {
        scoped_log.err("Invalid --keymanager.bodyLimit: {}", .{err});
        return err;
    };
    const monitoring = parseMonitoringConfig(opts) catch |err| {
        scoped_log.err("Invalid --monitoring.* configuration: {}", .{err});
        return err;
    };

    var proposer_configs: []const validator_mod.ProposerConfigEntry = &.{};
    errdefer if (proposer_configs.len > 0) allocator.free(proposer_configs);

    var default_proposer_config = cliDefaultEffectiveProposerConfig(cli_default_proposer_config);

    if (opts.proposerSettingsFile) |path| {
        if (try directoryHasEntries(io, paths.proposer_dir)) {
            scoped_log.err(
                "Cannot use --proposerSettingsFile while persisted proposer configs exist under {s}. Clear that directory or remove --proposerSettingsFile.",
                .{paths.proposer_dir},
            );
            return error.ProposerSettingsConflict;
        }

        const parsed = loadProposerSettingsFile(io, allocator, path) catch |err| {
            scoped_log.err("Invalid --proposerSettingsFile '{s}': {}", .{ path, err });
            return err;
        };
        proposer_configs = parsed.proposer_configs;
        default_proposer_config = cliDefaultEffectiveProposerConfig(
            mergeProposerConfig(parsed.default_config, cli_default_proposer_config),
        );
    } else {
        proposer_configs = try validator_mod.readPersistedProposerConfigs(io, allocator, paths.proposer_dir);
    }

    const keymanager: ?KeymanagerConfig = if (opts.keymanager) .{
        .address = opts.@"keymanager.address" orelse "127.0.0.1",
        .port = opts.@"keymanager.port" orelse 5062,
        .cors_origin = opts.@"keymanager.cors" orelse "*",
        .auth_enabled = opts.@"keymanager.auth",
        .token_file = opts.@"keymanager.tokenFile" orelse paths.keymanager_token_file,
        .header_limit = keymanager_header_limit,
        .body_limit = keymanager_body_limit,
        .stacktraces = opts.@"keymanager.stacktraces",
        .proposer_config_write_enabled = opts.proposerSettingsFile == null,
    } else null;

    return .{
        .network = network,
        .paths = paths,
        .beacon_config = beacon_config.*,
        .primary_beacon_url = primary_beacon_url,
        .fallback_urls = fallback_urls,
        .external_signer_urls = external_signer_urls,
        .remote_signer_source = remote_signer_source,
        .external_signer_fetch_enabled = external_signer_fetch_enabled,
        .keymanager = keymanager,
        .monitoring = monitoring,
        .proposer_settings_file = opts.proposerSettingsFile,
        .startup_signers = startup_signers,
        .signing_context = buildSigningContext(beacon_config, genesis),
        .validator_config = .{
            .persistence = persistence_paths,
            .beacon_node_url = primary_beacon_url,
            .genesis_time = genesis.genesis_time,
            .genesis_validators_root = genesis.genesis_validators_root,
            .seconds_per_slot = beacon_config.chain.SECONDS_PER_SLOT,
            .slots_per_epoch = preset.SLOTS_PER_EPOCH,
            .epochs_per_sync_committee_period = preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
            .sync_committee_size = preset.SYNC_COMMITTEE_SIZE,
            .sync_committee_subnet_count = constants.SYNC_COMMITTEE_SUBNET_COUNT,
            .electra_fork_epoch = beacon_config.chain.ELECTRA_FORK_EPOCH,
            .gloas_fork_epoch = beacon_config.chain.GLOAS_FORK_EPOCH,
            .attestation_due_ms = beacon_config.getSlotComponentDurationMs(beacon_config.chain.ATTESTATION_DUE_BPS),
            .attestation_due_ms_gloas = beacon_config.getSlotComponentDurationMs(beacon_config.chain.ATTESTATION_DUE_BPS_GLOAS),
            .aggregate_due_ms = beacon_config.getSlotComponentDurationMs(beacon_config.chain.AGGREGATE_DUE_BPS),
            .aggregate_due_ms_gloas = beacon_config.getSlotComponentDurationMs(beacon_config.chain.AGGREGATE_DUE_BPS_GLOAS),
            .sync_message_due_ms = beacon_config.getSlotComponentDurationMs(beacon_config.chain.SYNC_MESSAGE_DUE_BPS),
            .sync_message_due_ms_gloas = beacon_config.getSlotComponentDurationMs(beacon_config.chain.SYNC_MESSAGE_DUE_BPS_GLOAS),
            .sync_contribution_due_ms = beacon_config.getSlotComponentDurationMs(beacon_config.chain.CONTRIBUTION_DUE_BPS),
            .sync_contribution_due_ms_gloas = beacon_config.getSlotComponentDurationMs(beacon_config.chain.CONTRIBUTION_DUE_BPS_GLOAS),
            .doppelganger_protection = opts.doppelgangerProtection,
            .slashing_protection_path = paths.slashing_protection_db,
            .external_signer_urls = external_signer_urls,
            .external_signer_fetch_enabled = external_signer_fetch_enabled,
            .external_signer_fetch_interval_ms = external_signer_fetch_interval_ms,
            .beacon_node_fallback_urls = fallback_urls,
            .proposer_configs = proposer_configs,
            .suggested_fee_recipient = default_proposer_config.fee_recipient,
            .gas_limit = default_proposer_config.gas_limit,
            .graffiti = default_proposer_config.graffiti,
            .builder_selection = default_proposer_config.builder_selection,
            .builder_boost_factor = default_proposer_config.builder_boost_factor,
            .strict_fee_recipient_check = default_proposer_config.strict_fee_recipient_check,
            .blinded_local = opts.blindedLocal,
            .broadcast_validation = opts.broadcastValidation orelse .gossip,
            .distributed = opts.distributed,
            .clock_skip_slots = opts.@"clock.skipSlots" orelse !opts.distributed,
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

fn splitCsvOwnedUnique(allocator: Allocator, raw: []const u8) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (sliceContainsString(list.items, trimmed)) continue;
        try list.append(allocator, try allocator.dupe(u8, trimmed));
    }

    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn sliceContainsString(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
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

fn parseExternalSignerFetchInterval(input: ?u64) !?u64 {
    const interval_ms = input orelse return null;
    if (interval_ms == 0) return error.InvalidExternalSignerFetchInterval;
    return interval_ms;
}

fn parseKeymanagerBodyLimit(input: ?u64) !usize {
    const bytes = input orelse return 20 * 1024 * 1024;
    if (bytes == 0) return error.InvalidKeymanagerBodyLimit;
    return std.math.cast(usize, bytes) orelse return error.InvalidKeymanagerBodyLimit;
}

fn parseKeymanagerHeaderLimit(input: ?u64) !usize {
    const bytes = input orelse return @import("api").HttpServer.default_max_header_bytes;
    if (bytes == 0) return error.InvalidKeymanagerHeaderLimit;
    return std.math.cast(usize, bytes) orelse return error.InvalidKeymanagerHeaderLimit;
}

fn parseMonitoringConfig(opts: anytype) !?MonitoringConfig {
    const endpoint = opts.@"monitoring.endpoint" orelse return null;
    if (endpoint.len == 0) return error.InvalidMonitoringEndpoint;

    const interval_ms = opts.@"monitoring.interval" orelse 60_000;
    if (interval_ms == 0) return error.InvalidMonitoringInterval;

    const initial_delay_ms = opts.@"monitoring.initialDelay" orelse 30_000;
    if (initial_delay_ms == 0) return error.InvalidMonitoringInitialDelay;

    const request_timeout_ms = opts.@"monitoring.requestTimeout" orelse 10_000;
    if (request_timeout_ms == 0) return error.InvalidMonitoringRequestTimeout;

    return .{
        .endpoint = endpoint,
        .interval_ms = interval_ms,
        .initial_delay_ms = initial_delay_ms,
        .request_timeout_ms = request_timeout_ms,
        .collect_system_stats = opts.@"monitoring.collectSystemStats",
    };
}

fn parseCliDefaultProposerConfig(opts: anytype) !validator_mod.ProposerConfig {
    var config = validator_mod.ProposerConfig{};

    if (opts.suggestedFeeRecipient != null) {
        config.fee_recipient = try parseFeeRecipient(opts.suggestedFeeRecipient);
    }
    if (opts.graffiti != null) {
        config.graffiti = parseGraffiti(opts.graffiti);
    }
    if (opts.defaultGasLimit) |gas_limit| {
        config.gas_limit = gas_limit;
    }
    if (opts.@"builder.selection") |selection| {
        config.builder_selection = selection;
    } else if (opts.builder) {
        config.builder_selection = .default;
    }
    if (opts.@"builder.boostFactor" != null) {
        config.builder_boost_factor = try parseBuilderBoostFactor(opts.@"builder.boostFactor");
    }
    if (opts.strictFeeRecipientCheck) {
        config.strict_fee_recipient_check = true;
    }

    return config;
}

fn cliDefaultEffectiveProposerConfig(config: validator_mod.ProposerConfig) validator_mod.EffectiveProposerConfig {
    return .{
        .fee_recipient = config.fee_recipient orelse [_]u8{0} ** 20,
        .graffiti = config.graffiti orelse [_]u8{0} ** 32,
        .gas_limit = config.gas_limit orelse 60_000_000,
        .builder_selection = config.builder_selection orelse .executiononly,
        .builder_boost_factor = config.builder_boost_factor orelse 100,
        .strict_fee_recipient_check = config.strict_fee_recipient_check orelse false,
    };
}

fn mergeProposerConfig(
    base: validator_mod.ProposerConfig,
    overrides: validator_mod.ProposerConfig,
) validator_mod.ProposerConfig {
    var merged = base;
    if (overrides.fee_recipient) |value| merged.fee_recipient = value;
    if (overrides.graffiti) |value| merged.graffiti = value;
    if (overrides.gas_limit) |value| merged.gas_limit = value;
    if (overrides.builder_selection) |value| merged.builder_selection = value;
    if (overrides.builder_boost_factor) |value| merged.builder_boost_factor = value;
    if (overrides.strict_fee_recipient_check) |value| merged.strict_fee_recipient_check = value;
    return merged;
}

const ParsedProposerSettingsFile = struct {
    default_config: validator_mod.ProposerConfig = .{},
    proposer_configs: []const validator_mod.ProposerConfigEntry = &.{},
};

fn loadProposerSettingsFile(
    io: Io,
    allocator: Allocator,
    path: []const u8,
) !ParsedProposerSettingsFile {
    const bytes = try readFileAlloc(io, allocator, path);
    defer allocator.free(bytes);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var doc = Yaml{ .source = bytes };
    try doc.load(arena.allocator());
    defer doc.deinit(arena.allocator());

    if (doc.docs.items.len == 0) return error.EmptyYaml;

    const root = try doc.docs.items[0].asMap();

    const default_config = if (root.get("default_config")) |value|
        try parseProposerSettingsSection(try value.asMap())
    else
        validator_mod.ProposerConfig{};

    var proposer_entries: std.ArrayListUnmanaged(validator_mod.ProposerConfigEntry) = .empty;
    errdefer proposer_entries.deinit(allocator);

    if (root.get("proposer_config")) |value| {
        const proposer_map = try value.asMap();
        try proposer_entries.ensureTotalCapacity(allocator, proposer_map.count());
        for (proposer_map.keys(), proposer_map.values()) |pubkey_text, section_value| {
            const pubkey = try parseValidatorPubkeyHex(pubkey_text);
            proposer_entries.appendAssumeCapacity(.{
                .pubkey = pubkey,
                .config = try parseProposerSettingsSection(try section_value.asMap()),
            });
        }
    }

    return .{
        .default_config = default_config,
        .proposer_configs = if (proposer_entries.items.len == 0)
            &.{}
        else
            try proposer_entries.toOwnedSlice(allocator),
    };
}

fn parseProposerSettingsSection(map: Yaml.Map) !validator_mod.ProposerConfig {
    var config = validator_mod.ProposerConfig{};

    if (map.get("graffiti")) |value| {
        config.graffiti = parseGraffiti(try scalarString(value));
    }
    if (map.get("strict_fee_recipient_check")) |value| {
        config.strict_fee_recipient_check = try parseYamlBool(value);
    }
    if (map.get("fee_recipient")) |value| {
        config.fee_recipient = try parseFeeRecipient(try scalarString(value));
    }
    if (map.get("builder")) |value| {
        const builder = try value.asMap();
        if (builder.get("selection")) |selection_value| {
            const selection_text = try scalarString(selection_value) orelse return error.InvalidProposerSettingsFile;
            config.builder_selection = try validator_mod.BuilderSelection.parse(selection_text);
        }
        if (builder.get("gas_limit")) |gas_value| {
            config.gas_limit = try parseYamlU64(gas_value);
        }
        if (builder.get("boost_factor")) |boost_value| {
            config.builder_boost_factor = try parseYamlU64(boost_value);
        }
    }

    return config;
}

fn scalarString(value: Yaml.Value) !?[]const u8 {
    const scalar = try value.asScalar();
    return std.mem.trim(u8, scalar, " \t\r\n'\"");
}

fn parseYamlBool(value: Yaml.Value) !bool {
    const scalar = try scalarString(value) orelse return error.InvalidProposerSettingsFile;
    if (std.ascii.eqlIgnoreCase(scalar, "true")) return true;
    if (std.ascii.eqlIgnoreCase(scalar, "false")) return false;
    return error.InvalidProposerSettingsFile;
}

fn parseYamlU64(value: Yaml.Value) !u64 {
    const scalar = try scalarString(value) orelse return error.InvalidProposerSettingsFile;
    return try std.fmt.parseInt(u64, scalar, 10);
}

fn parseValidatorPubkeyHex(raw: []const u8) ![48]u8 {
    const stripped = if (std.mem.startsWith(u8, raw, "0x") or std.mem.startsWith(u8, raw, "0X")) raw[2..] else raw;
    if (stripped.len != 96) return error.InvalidValidatorPubkey;
    var pubkey: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, stripped);
    return pubkey;
}

fn loadPinnedRemoteSignerKeys(
    allocator: Allocator,
    urls: []const []const u8,
    raw_pubkeys: []const u8,
) ![]validator_mod.RemoteSignerKeys {
    if (urls.len != 1) return error.InvalidExternalSignerConfiguration;

    try validator_mod.validateRemoteSignerUrl(urls[0]);

    var pubkeys = std.ArrayListUnmanaged([48]u8).empty;
    errdefer pubkeys.deinit(allocator);

    var seen = std.AutoHashMap([48]u8, void).init(allocator);
    defer seen.deinit();

    var it = std.mem.splitScalar(u8, raw_pubkeys, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;

        const pubkey = try validator_mod.parseRemoteSignerPubkey(trimmed);
        const entry = try seen.getOrPut(pubkey);
        if (entry.found_existing) continue;
        try pubkeys.append(allocator, pubkey);
    }

    if (pubkeys.items.len == 0) return error.InvalidExternalSignerConfiguration;

    const grouped = try allocator.alloc(validator_mod.RemoteSignerKeys, 1);
    errdefer allocator.free(grouped);
    grouped[0] = .{
        .url = try allocator.dupe(u8, urls[0]),
        .pubkeys = try pubkeys.toOwnedSlice(allocator),
    };
    return grouped;
}

fn duplicateRemoteSignerUrls(
    allocator: Allocator,
    groups: []const validator_mod.RemoteSignerKeys,
) ![]const []const u8 {
    if (groups.len == 0) return &.{};

    const urls = try allocator.alloc([]const u8, groups.len);
    var populated: usize = 0;
    errdefer {
        for (urls[0..populated]) |url| allocator.free(url);
        allocator.free(urls);
    }

    for (groups, 0..) |group, idx| {
        urls[idx] = try allocator.dupe(u8, group.url);
        populated += 1;
    }

    return urls;
}

fn directoryHasEntries(io: Io, path: []const u8) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |_| return true;
    return false;
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
                scoped_log.info("Waiting for beacon genesis from {s}: {s}", .{ beacon_url, @errorName(err) });
            }
            try io.sleep(.{ .nanoseconds = 5 * std.time.ns_per_s }, .real);
            continue;
        };

        if (attempts > 0) {
            scoped_log.info("Fetched beacon genesis from {s} after {d} retry attempt(s)", .{ beacon_url, attempts });
        }
        return genesis;
    }
}

fn ensureGenesisForkVersionMatches(
    beacon_config: *const BeaconConfig,
    genesis: validator_mod.api_client.GenesisResponse,
) !void {
    if (!std.mem.eql(u8, &beacon_config.chain.GENESIS_FORK_VERSION, &genesis.genesis_fork_version)) {
        scoped_log.err(
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
            scoped_log.err("Beacon node config mismatch field={s} expected={d} actual={d}", .{ name, expected, value });
            return error.BeaconConfigMismatch;
        }
    }
}

fn compareOptionalVersionField(name: []const u8, expected: [4]u8, actual: ?[4]u8) !void {
    if (actual) |value| {
        if (!std.mem.eql(u8, &expected, &value)) {
            scoped_log.err("Beacon node config mismatch field={s} expected=0x{s} actual=0x{s}", .{
                name,
                std.fmt.bytesToHex(&expected, .lower),
                std.fmt.bytesToHex(&value, .lower),
            });
            return error.BeaconConfigMismatch;
        }
    }
}

fn compareOptionalHexField(comptime name: []const u8, expected: anytype, actual: ?@TypeOf(expected)) !void {
    if (actual) |value| {
        if (!std.mem.eql(u8, &expected, &value)) {
            scoped_log.err("Beacon node config mismatch field={s} expected=0x{s} actual=0x{s}", .{
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
    try compareOptionalUintField("MIN_GENESIS_ACTIVE_VALIDATOR_COUNT", beacon_config.chain.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, spec.min_genesis_active_validator_count);
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
    try compareOptionalVersionField("FULU_FORK_VERSION", beacon_config.chain.FULU_FORK_VERSION, spec.fulu_fork_version);
    try compareOptionalUintField("FULU_FORK_EPOCH", beacon_config.chain.FULU_FORK_EPOCH, spec.fulu_fork_epoch);
    try compareOptionalVersionField("GLOAS_FORK_VERSION", beacon_config.chain.GLOAS_FORK_VERSION, spec.gloas_fork_version);
    try compareOptionalUintField("GLOAS_FORK_EPOCH", beacon_config.chain.GLOAS_FORK_EPOCH, spec.gloas_fork_epoch);
    try compareOptionalUintField("GENESIS_DELAY", beacon_config.chain.GENESIS_DELAY, spec.genesis_delay);
    try compareOptionalUintField("SECONDS_PER_SLOT", beacon_config.chain.SECONDS_PER_SLOT, spec.seconds_per_slot);
    try compareOptionalUintField("SLOT_DURATION_MS", beacon_config.chain.SLOT_DURATION_MS, spec.slot_duration_ms);
    try compareOptionalUintField("MIN_GENESIS_TIME", beacon_config.chain.MIN_GENESIS_TIME, spec.min_genesis_time);
    try compareOptionalUintField("MIN_VALIDATOR_WITHDRAWABILITY_DELAY", beacon_config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY, spec.min_validator_withdrawability_delay);
    try compareOptionalUintField("SHARD_COMMITTEE_PERIOD", beacon_config.chain.SHARD_COMMITTEE_PERIOD, spec.shard_committee_period);
    try compareOptionalUintField("ETH1_FOLLOW_DISTANCE", beacon_config.chain.ETH1_FOLLOW_DISTANCE, spec.eth1_follow_distance);
    try compareOptionalUintField("INACTIVITY_SCORE_BIAS", beacon_config.chain.INACTIVITY_SCORE_BIAS, spec.inactivity_score_bias);
    try compareOptionalUintField("INACTIVITY_SCORE_RECOVERY_RATE", beacon_config.chain.INACTIVITY_SCORE_RECOVERY_RATE, spec.inactivity_score_recovery_rate);
    try compareOptionalUintField("EJECTION_BALANCE", beacon_config.chain.EJECTION_BALANCE, spec.ejection_balance);
    try compareOptionalUintField("MIN_PER_EPOCH_CHURN_LIMIT", beacon_config.chain.MIN_PER_EPOCH_CHURN_LIMIT, spec.min_per_epoch_churn_limit);
    try compareOptionalUintField("MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT", beacon_config.chain.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, spec.max_per_epoch_activation_churn_limit);
    try compareOptionalUintField("CHURN_LIMIT_QUOTIENT", beacon_config.chain.CHURN_LIMIT_QUOTIENT, spec.churn_limit_quotient);
    try compareOptionalUintField("PROPOSER_REORG_CUTOFF_BPS", beacon_config.chain.PROPOSER_REORG_CUTOFF_BPS, spec.proposer_reorg_cutoff_bps);
    try compareOptionalUintField("ATTESTATION_DUE_BPS", beacon_config.chain.ATTESTATION_DUE_BPS, spec.attestation_due_bps);
    try compareOptionalUintField("ATTESTATION_DUE_BPS_GLOAS", beacon_config.chain.ATTESTATION_DUE_BPS_GLOAS, spec.attestation_due_bps_gloas);
    try compareOptionalUintField("AGGREGATE_DUE_BPS", beacon_config.chain.AGGREGATE_DUE_BPS, spec.aggregate_due_bps);
    try compareOptionalUintField("AGGREGATE_DUE_BPS_GLOAS", beacon_config.chain.AGGREGATE_DUE_BPS_GLOAS, spec.aggregate_due_bps_gloas);
    try compareOptionalUintField("SYNC_MESSAGE_DUE_BPS", beacon_config.chain.SYNC_MESSAGE_DUE_BPS, spec.sync_message_due_bps);
    try compareOptionalUintField("SYNC_MESSAGE_DUE_BPS_GLOAS", beacon_config.chain.SYNC_MESSAGE_DUE_BPS_GLOAS, spec.sync_message_due_bps_gloas);
    try compareOptionalUintField("CONTRIBUTION_DUE_BPS", beacon_config.chain.CONTRIBUTION_DUE_BPS, spec.contribution_due_bps);
    try compareOptionalUintField("CONTRIBUTION_DUE_BPS_GLOAS", beacon_config.chain.CONTRIBUTION_DUE_BPS_GLOAS, spec.contribution_due_bps_gloas);
    try compareOptionalUintField("BLOB_SIDECAR_SUBNET_COUNT", beacon_config.chain.BLOB_SIDECAR_SUBNET_COUNT, spec.blob_sidecar_subnet_count);
    try compareOptionalUintField("MAX_COMMITTEES_PER_SLOT", preset.MAX_COMMITTEES_PER_SLOT, spec.max_committees_per_slot);
    try compareOptionalUintField("TARGET_COMMITTEE_SIZE", preset.TARGET_COMMITTEE_SIZE, spec.target_committee_size);
    try compareOptionalUintField("MAX_VALIDATORS_PER_COMMITTEE", preset.MAX_VALIDATORS_PER_COMMITTEE, spec.max_validators_per_committee);
    try compareOptionalUintField("MAX_BLOBS_PER_BLOCK", beacon_config.chain.MAX_BLOBS_PER_BLOCK, spec.max_blobs_per_block);
    try compareOptionalUintField("MIN_DEPOSIT_AMOUNT", preset.MIN_DEPOSIT_AMOUNT, spec.min_deposit_amount);
    try compareOptionalUintField("MAX_EFFECTIVE_BALANCE", preset.MAX_EFFECTIVE_BALANCE, spec.max_effective_balance);
    try compareOptionalUintField("EFFECTIVE_BALANCE_INCREMENT", preset.EFFECTIVE_BALANCE_INCREMENT, spec.effective_balance_increment);
    try compareOptionalUintField("MIN_ATTESTATION_INCLUSION_DELAY", preset.MIN_ATTESTATION_INCLUSION_DELAY, spec.min_attestation_inclusion_delay);
    try compareOptionalUintField("SLOTS_PER_EPOCH", preset.SLOTS_PER_EPOCH, spec.slots_per_epoch);
    try compareOptionalUintField("MIN_SEED_LOOKAHEAD", preset.MIN_SEED_LOOKAHEAD, spec.min_seed_lookahead);
    try compareOptionalUintField("MAX_SEED_LOOKAHEAD", preset.MAX_SEED_LOOKAHEAD, spec.max_seed_lookahead);
    try compareOptionalUintField("EPOCHS_PER_ETH1_VOTING_PERIOD", preset.EPOCHS_PER_ETH1_VOTING_PERIOD, spec.epochs_per_eth1_voting_period);
    try compareOptionalUintField("SLOTS_PER_HISTORICAL_ROOT", preset.SLOTS_PER_HISTORICAL_ROOT, spec.slots_per_historical_root);
    try compareOptionalUintField("MIN_EPOCHS_TO_INACTIVITY_PENALTY", preset.MIN_EPOCHS_TO_INACTIVITY_PENALTY, spec.min_epochs_to_inactivity_penalty);
    try compareOptionalUintField("EPOCHS_PER_HISTORICAL_VECTOR", preset.EPOCHS_PER_HISTORICAL_VECTOR, spec.epochs_per_historical_vector);
    try compareOptionalUintField("EPOCHS_PER_SLASHINGS_VECTOR", preset.EPOCHS_PER_SLASHINGS_VECTOR, spec.epochs_per_slashings_vector);
    try compareOptionalUintField("HISTORICAL_ROOTS_LIMIT", preset.HISTORICAL_ROOTS_LIMIT, spec.historical_roots_limit);
    try compareOptionalUintField("VALIDATOR_REGISTRY_LIMIT", preset.VALIDATOR_REGISTRY_LIMIT, spec.validator_registry_limit);
    try compareOptionalUintField("BASE_REWARD_FACTOR", preset.BASE_REWARD_FACTOR, spec.base_reward_factor);
    try compareOptionalUintField("WHISTLEBLOWER_REWARD_QUOTIENT", preset.WHISTLEBLOWER_REWARD_QUOTIENT, spec.whistleblower_reward_quotient);
    try compareOptionalUintField("PROPOSER_REWARD_QUOTIENT", preset.PROPOSER_REWARD_QUOTIENT, spec.proposer_reward_quotient);
    try compareOptionalUintField("INACTIVITY_PENALTY_QUOTIENT", preset.INACTIVITY_PENALTY_QUOTIENT, spec.inactivity_penalty_quotient);
    try compareOptionalUintField("MIN_SLASHING_PENALTY_QUOTIENT", preset.MIN_SLASHING_PENALTY_QUOTIENT, spec.min_slashing_penalty_quotient);
    try compareOptionalUintField("PROPORTIONAL_SLASHING_MULTIPLIER", preset.PROPORTIONAL_SLASHING_MULTIPLIER, spec.proportional_slashing_multiplier);
    try compareOptionalUintField("MAX_PROPOSER_SLASHINGS", preset.MAX_PROPOSER_SLASHINGS, spec.max_proposer_slashings);
    try compareOptionalUintField("MAX_ATTESTER_SLASHINGS", preset.MAX_ATTESTER_SLASHINGS, spec.max_attester_slashings);
    try compareOptionalUintField("MAX_ATTESTATIONS", preset.MAX_ATTESTATIONS, spec.max_attestations);
    try compareOptionalUintField("MAX_DEPOSITS", preset.MAX_DEPOSITS, spec.max_deposits);
    try compareOptionalUintField("MAX_VOLUNTARY_EXITS", preset.MAX_VOLUNTARY_EXITS, spec.max_voluntary_exits);
    try compareOptionalUintField("SYNC_COMMITTEE_SIZE", preset.SYNC_COMMITTEE_SIZE, spec.sync_committee_size);
    try compareOptionalUintField("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD, spec.epochs_per_sync_committee_period);
    try compareOptionalUintField("INACTIVITY_PENALTY_QUOTIENT_ALTAIR", preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR, spec.inactivity_penalty_quotient_altair);
    try compareOptionalUintField("MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR", preset.MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR, spec.min_slashing_penalty_quotient_altair);
    try compareOptionalUintField("PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR", preset.PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR, spec.proportional_slashing_multiplier_altair);
    try compareOptionalUintField("BLOB_SIDECAR_SUBNET_COUNT_ELECTRA", beacon_config.chain.BLOB_SIDECAR_SUBNET_COUNT_ELECTRA, spec.blob_sidecar_subnet_count_electra);
    try compareOptionalUintField("MAX_BLOBS_PER_BLOCK_ELECTRA", beacon_config.chain.MAX_BLOBS_PER_BLOCK_ELECTRA, spec.max_blobs_per_block_electra);
    try compareBlobSchedule(beacon_config.chain.BLOB_SCHEDULE, spec.blob_schedule);
    try compareOptionalHexField("DEPOSIT_CONTRACT_ADDRESS", beacon_config.chain.DEPOSIT_CONTRACT_ADDRESS, spec.deposit_contract_address);
}

fn compareBlobSchedule(
    expected: []const config_mod.ChainConfig.BlobScheduleEntry,
    actual: []const validator_mod.api_client.ConfigSpecResponse.BlobScheduleEntry,
) !void {
    if (actual.len == 0) return;
    if (expected.len != actual.len) {
        scoped_log.err("Beacon node config mismatch field=BLOB_SCHEDULE expected_len={d} actual_len={d}", .{
            expected.len,
            actual.len,
        });
        return error.BeaconConfigMismatch;
    }

    for (expected, actual, 0..) |expected_entry, actual_entry, idx| {
        if (expected_entry.EPOCH != actual_entry.epoch) {
            scoped_log.err("Beacon node config mismatch field=BLOB_SCHEDULE[{d}].EPOCH expected={d} actual={d}", .{
                idx,
                expected_entry.EPOCH,
                actual_entry.epoch,
            });
            return error.BeaconConfigMismatch;
        }
        if (expected_entry.MAX_BLOBS_PER_BLOCK != actual_entry.max_blobs_per_block) {
            scoped_log.err("Beacon node config mismatch field=BLOB_SCHEDULE[{d}].MAX_BLOBS_PER_BLOCK expected={d} actual={d}", .{
                idx,
                expected_entry.MAX_BLOBS_PER_BLOCK,
                actual_entry.max_blobs_per_block,
            });
            return error.BeaconConfigMismatch;
        }
    }
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

const testing = std.testing;

test "splitCsvOwnedUnique trims and deduplicates values" {
    const items = try splitCsvOwnedUnique(testing.allocator, " http://a ,http://b,http://a ,, http://b ");
    defer freeOwnedStrings(testing.allocator, items);

    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("http://a", items[0]);
    try testing.expectEqualStrings("http://b", items[1]);
}

test "loadPinnedRemoteSignerKeys parses and deduplicates pubkeys" {
    const urls: []const []const u8 = &.{"http://signer.example:9000"};
    const grouped = try loadPinnedRemoteSignerKeys(
        testing.allocator,
        urls,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    defer {
        for (grouped) |*item| item.deinit(testing.allocator);
        testing.allocator.free(grouped);
    }

    try testing.expectEqual(@as(usize, 1), grouped.len);
    try testing.expectEqualStrings("http://signer.example:9000", grouped[0].url);
    try testing.expectEqual(@as(usize, 2), grouped[0].pubkeys.len);
}

test "loadProposerSettingsFile parses default and per-validator overrides" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const config_bytes =
        \\default_config:
        \\  graffiti: hello
        \\  strict_fee_recipient_check: true
        \\  fee_recipient: "0x1111111111111111111111111111111111111111"
        \\  builder:
        \\    gas_limit: 123456
        \\    boost_factor: 250
        \\proposer_config:
        \\  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
        \\    graffiti: world
        \\    fee_recipient: "0x2222222222222222222222222222222222222222"
    ;

    try tmp.dir.writeFile(.{ .sub_path = "proposer.yaml", .data = config_bytes });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "proposer.yaml");
    defer testing.allocator.free(path);

    const parsed = try loadProposerSettingsFile(testing.io, testing.allocator, path);
    defer if (parsed.proposer_configs.len > 0) testing.allocator.free(parsed.proposer_configs);

    try testing.expectEqualStrings("hello", std.mem.trimRight(u8, &parsed.default_config.graffiti.?, "\x00"));
    try testing.expect(parsed.default_config.strict_fee_recipient_check.?);
    try testing.expectEqual(@as(u64, 123456), parsed.default_config.gas_limit.?);
    try testing.expectEqual(@as(u64, 250), parsed.default_config.builder_boost_factor.?);
    try testing.expectEqual(@as(usize, 1), parsed.proposer_configs.len);
    try testing.expectEqualStrings("world", std.mem.trimRight(u8, &parsed.proposer_configs[0].config.graffiti.?, "\x00"));
}
