const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const validator_mod = @import("validator");
const log_mod = @import("log");
const ShutdownHandler = @import("../../shutdown.zig").ShutdownHandler;
const bootstrap = @import("bootstrap.zig");
const keymanager_server = @import("keymanager_server.zig");

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
    if (opts.metrics or opts.@"metrics.port" != null or opts.@"metrics.address" != null) {
        return unsupportedOption("Validator metrics flags are not implemented yet. Remove --metrics, --metrics.port, and --metrics.address.");
    }
    if (opts.@"monitoring.endpoint" != null or opts.@"monitoring.interval" != null) {
        return unsupportedOption("Validator monitoring flags are not implemented yet. Remove --monitoring.endpoint and --monitoring.interval.");
    }
    if (opts.@"keymanager.headerLimit" != null or opts.@"keymanager.stacktraces") {
        return unsupportedOption("Validator keymanager header-limit and stacktrace options are not implemented yet. Remove --keymanager.headerLimit and --keymanager.stacktraces.");
    }
    if (!opts.keymanager and
        (opts.@"keymanager.tokenFile" != null or
            opts.@"keymanager.port" != null or
            opts.@"keymanager.address" != null or
            opts.@"keymanager.cors" != null or
            opts.@"keymanager.bodyLimit" != null or
            opts.@"keymanager.auth" != true))
    {
        return unsupportedOption("Validator keymanager options require --keymanager. Add --keymanager or remove the --keymanager.* overrides.");
    }
    if (opts.importKeystores != null or opts.importKeystoresPassword != null) {
        return unsupportedOption("Validator keystore import at startup is not implemented yet. Populate the keystores and secrets directories directly instead.");
    }
    if (opts.proposerSettingsFile != null) {
        return unsupportedOption("Validator proposer settings files are not implemented yet. Remove --proposerSettingsFile.");
    }
    if (opts.strictFeeRecipientCheck) {
        return unsupportedOption("Validator strict fee recipient checks are not implemented yet. Remove --strictFeeRecipientCheck.");
    }
    if (opts.builder or opts.@"builder.selection" != null) {
        return unsupportedOption("Validator builder selection policy flags are not implemented yet. Remove --builder and --builder.selection.");
    }
    if (opts.broadcastValidation != null or opts.blindedLocal) {
        return unsupportedOption("Validator broadcast validation and blinded-local flags are not implemented yet. Remove --broadcastValidation and --blindedLocal.");
    }
    if (opts.distributed) {
        return unsupportedOption("Distributed validator mode is not implemented yet. Remove --distributed.");
    }
    const external_signer_urls = opts.@"externalSigner.urls" orelse opts.@"externalSigner.url";
    if (external_signer_urls) |raw| {
        const url_count = countCsvValues(raw);
        if (url_count == 0) {
            return unsupportedOption("--externalSigner.url or --externalSigner.urls requires at least one non-empty signer URL.");
        }
        if (!opts.@"externalSigner.fetch" and opts.@"externalSigner.pubkeys" == null) {
            return unsupportedOption("--externalSigner.url(s) requires either --externalSigner.fetch or --externalSigner.pubkeys.");
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
            return unsupportedOption("--externalSigner.fetch requires --externalSigner.url or --externalSigner.urls.");
        }
        if (opts.@"externalSigner.pubkeys" != null) {
            return unsupportedOption("--externalSigner.pubkeys requires --externalSigner.url or --externalSigner.urls.");
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

    const client = try validator_mod.ValidatorClient.init(
        io,
        allocator,
        prepared.validator_config,
        prepared.signing_context,
        prepared.startup_signers,
    );
    prepared.startup_signers = .{ .allocator = allocator };
    defer client.destroy();

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

    prepared.logStartup();

    var keymanager: ?keymanager_server.Runtime = null;
    if (prepared.keymanager) |keymanager_config| {
        keymanager = try keymanager_server.Runtime.init(
            io,
            allocator,
            client,
            &prepared.beacon_config,
            .{
                .address = keymanager_config.address,
                .port = keymanager_config.port,
                .cors_origin = keymanager_config.cors_origin,
                .auth_enabled = keymanager_config.auth_enabled,
                .token_file = keymanager_config.token_file,
                .body_limit = keymanager_config.body_limit,
            },
        );
        errdefer if (keymanager) |*km| km.deinit();
        try keymanager.?.start();
    }
    defer if (keymanager) |*km| {
        km.stop();
        km.deinit();
    };

    try client.start();
}
