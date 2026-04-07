const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const validator_mod = @import("validator");
const log_mod = @import("log");
const ShutdownHandler = @import("../../shutdown.zig").ShutdownHandler;
const common = @import("../../spec_common.zig");
const bootstrap = @import("bootstrap.zig");
const keymanager_server = @import("keymanager_server.zig");
const metrics_server = @import("metrics_server.zig");
const monitoring_runtime = @import("monitoring_runtime.zig");

fn unsupportedOption(message: []const u8) error{UnsupportedValidatorOption}!void {
    std.log.err("{s}", .{message});
    std.log.err("Current validator-client simplifications are documented in src/validator/DESIGN.md.", .{});
    return error.UnsupportedValidatorOption;
}

fn countCsvValues(input: []const u8) usize {
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, input, ',');
    while (it.next()) |part| {
        if (std.mem.trim(u8, part, " \t\r\n").len > 0) count += 1;
    }
    return count;
}

fn rejectUnsupportedOptions(opts: anytype) !void {
    if (!opts.metrics and (opts.@"metrics.port" != null or opts.@"metrics.address" != null)) {
        return unsupportedOption("Validator metrics overrides require --metrics. Add --metrics or remove --metrics.port and --metrics.address.");
    }
    if (opts.@"monitoring.endpoint" == null and
        (opts.@"monitoring.interval" != null or
            opts.@"monitoring.initialDelay" != null or
            opts.@"monitoring.requestTimeout" != null or
            opts.@"monitoring.collectSystemStats"))
    {
        return unsupportedOption("Validator monitoring overrides require --monitoring.endpoint. Add --monitoring.endpoint or remove the --monitoring.* overrides.");
    }
    if (!opts.keymanager and
        (opts.@"keymanager.tokenFile" != null or
            opts.@"keymanager.port" != null or
            opts.@"keymanager.address" != null or
            opts.@"keymanager.cors" != null or
            opts.@"keymanager.bodyLimit" != null or
            opts.@"keymanager.stacktraces" or
            opts.@"keymanager.auth" != true))
    {
        return unsupportedOption("Validator keymanager options require --keymanager. Add --keymanager or remove the --keymanager.* overrides.");
    }
    if (opts.importKeystores == null and opts.importKeystoresPassword != null) {
        return unsupportedOption("--importKeystoresPassword requires --importKeystores.");
    }
    if (opts.importKeystores != null and opts.importKeystoresPassword == null) {
        return unsupportedOption("--importKeystores requires --importKeystoresPassword pointing to the shared keystore password file.");
    }
    const external_signer_urls = opts.@"externalSigner.urls";
    if (external_signer_urls) |raw| {
        const url_count = countCsvValues(raw);
        if (url_count == 0) {
            return unsupportedOption("--externalSigner.urls requires at least one non-empty signer URL.");
        }
        if (!opts.@"externalSigner.fetch" and opts.@"externalSigner.pubkeys" == null) {
            return unsupportedOption("--externalSigner.urls requires either --externalSigner.fetch or --externalSigner.pubkeys.");
        }
        if (opts.@"externalSigner.fetch" and opts.@"externalSigner.pubkeys" != null) {
            return unsupportedOption("--externalSigner.fetch conflicts with --externalSigner.pubkeys.");
        }
        if (opts.@"externalSigner.pubkeys" != null and url_count > 1) {
            return unsupportedOption("--externalSigner.pubkeys currently supports exactly one external signer URL.");
        }
        if (opts.@"externalSigner.pubkeys") |pubkeys| {
            if (countCsvValues(pubkeys) == 0) {
                return unsupportedOption("--externalSigner.pubkeys requires at least one non-empty validator pubkey.");
            }
        }
    } else {
        if (opts.@"externalSigner.fetch") {
            return unsupportedOption("--externalSigner.fetch requires --externalSigner.urls.");
        }
        if (opts.@"externalSigner.pubkeys" != null) {
            return unsupportedOption("--externalSigner.pubkeys requires --externalSigner.urls.");
        }
    }
}

pub fn run(io: Io, allocator: Allocator, opts: anytype) !void {
    const log_level = opts.logLevel orelse opts.log_level;
    const log_format = opts.logFormat orelse .human;
    const log_file = opts.logFile;
    const log_file_level = opts.logFileLevel orelse .debug;
    const log_file_daily_rotate = opts.logFileDailyRotate orelse 5;

    log_mod.global = log_mod.GlobalLogger.init(log_level.toLogLevel(), log_format);
    try rejectUnsupportedOptions(opts);
    ShutdownHandler.installSignalHandlers();

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

    var prepared = try bootstrap.prepareRuntime(io, allocator, opts);
    defer prepared.deinit(io);
    try prepared.validateSignerAvailability();

    var metrics = if (opts.metrics or prepared.monitoring != null)
        try validator_mod.ValidatorMetrics.init(allocator)
    else
        validator_mod.ValidatorMetrics.initNoop();
    defer metrics.deinit();

    const client = try validator_mod.ValidatorClient.init(
        io,
        allocator,
        .{
            .config = prepared.validator_config,
            .signing_context = prepared.signing_context,
            .startup_signers = prepared.startup_signers,
            .metrics = &metrics,
        },
    );
    prepared.startup_signers = .{ .allocator = allocator };
    defer client.destroy();

    const WatchCtx = struct {
        io: Io,
        client: *validator_mod.ValidatorClient,
        done: std.atomic.Value(bool),
    };

    var watch_ctx = WatchCtx{
        .io = io,
        .client = client,
        .done = std.atomic.Value(bool).init(false),
    };
    var watcher = try io.concurrent(struct {
        fn run(ctx: *WatchCtx) anyerror!void {
            while (!ctx.done.load(.acquire)) {
                if (ShutdownHandler.shouldStop()) {
                    ctx.client.requestShutdown();
                    return;
                }
                try ctx.io.sleep(.{ .nanoseconds = 100 * std.time.ns_per_ms }, .real);
            }
        }
    }.run, .{&watch_ctx});
    defer {
        watch_ctx.done.store(true, .release);
        _ = watcher.cancel(io) catch |err| switch (err) {
            error.Canceled => {},
            else => std.log.debug("validator shutdown watcher exited during shutdown: {s}", .{@errorName(err)}),
        };
    }

    prepared.logStartup();

    var metrics_runtime: ?metrics_server.Runtime = null;
    errdefer if (metrics_runtime) |*runtime| runtime.stop();
    if (opts.metrics) {
        metrics_runtime = metrics_server.Runtime.init(
            io,
            allocator,
            &metrics,
            .{
                .address = opts.@"metrics.address" orelse metrics_server.default_address,
                .port = opts.@"metrics.port" orelse metrics_server.default_port,
            },
        );
        try metrics_runtime.?.start();
        std.log.info(
            "validator metrics listening on http://{s}:{d}/metrics",
            .{
                opts.@"metrics.address" orelse metrics_server.default_address,
                opts.@"metrics.port" orelse metrics_server.default_port,
            },
        );
    }
    defer if (metrics_runtime) |*runtime| runtime.stop();

    var monitoring: ?monitoring_runtime.Runtime = null;
    errdefer if (monitoring) |*runtime| runtime.stop();
    if (prepared.monitoring) |monitoring_config| {
        monitoring = try monitoring_runtime.Runtime.init(
            io,
            allocator,
            client,
            &metrics,
            monitoring_config,
            common.VERSION,
        );
        try monitoring.?.start();
        std.log.info(
            "validator monitoring sending to {s} every {d}ms",
            .{ monitoring_config.endpoint, monitoring_config.interval_ms },
        );
    }
    defer if (monitoring) |*runtime| runtime.stop();

    var keymanager: ?keymanager_server.Runtime = null;
    errdefer if (keymanager) |*km| {
        km.stop();
        km.deinit();
    };
    if (prepared.keymanager) |keymanager_config| {
        if (!keymanager_config.proposer_config_write_enabled) {
            std.log.info(
                "Validator keymanager proposer policy writes are disabled while --proposerSettingsFile owns proposer settings",
                .{},
            );
        }
        keymanager = try keymanager_server.Runtime.init(
            io,
            allocator,
            client,
            &metrics,
            &prepared.beacon_config,
            .{
                .address = keymanager_config.address,
                .port = keymanager_config.port,
                .cors_origin = keymanager_config.cors_origin,
                .auth_enabled = keymanager_config.auth_enabled,
                .token_file = keymanager_config.token_file,
                .header_limit = keymanager_config.header_limit,
                .body_limit = keymanager_config.body_limit,
                .stacktraces = keymanager_config.stacktraces,
                .proposer_config_write_enabled = keymanager_config.proposer_config_write_enabled,
            },
        );
        try keymanager.?.start();
    }
    defer if (keymanager) |*km| {
        km.stop();
        km.deinit();
    };

    try client.start();
}
