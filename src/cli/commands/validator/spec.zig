const cli = @import("zig_cli");
const common = @import("../../spec_common.zig");
const log_mod = @import("log");

pub const spec = cli.command(.{
    .description = "Run the validator client",
    .options = .{
        .beacon_url = cli.option([]const u8, .{
            .long = "beacon-url",
            .description = "Beacon node REST API URL",
            .env = "LODESTAR_Z_BEACON_URL",
        }, "http://localhost:5052"),
        .beaconNodes = cli.option(?[]const u8, .{
            .long = "beaconNodes",
            .description = "Comma-separated beacon node API URLs",
        }, null),
        .server = cli.option(?[]const u8, .{
            .long = "server",
            .description = "Backward-compatible alias for beaconNodes",
        }, null),
        .keystoresDir = cli.option(?[]const u8, .{
            .long = "keystoresDir",
            .description = "Directory for storing validator keystores",
        }, null),
        .secretsDir = cli.option(?[]const u8, .{
            .long = "secretsDir",
            .description = "Directory for storing validator keystore secrets",
        }, null),
        .validatorsDbDir = cli.option(?[]const u8, .{
            .long = "validatorsDbDir",
            .description = "Data directory for validator databases",
        }, null),
        .graffiti = cli.option(?[]const u8, .{
            .long = "graffiti",
            .description = "Validator graffiti string",
            .env = "LODESTAR_Z_GRAFFITI",
        }, null),
        .suggestedFeeRecipient = cli.option(?[]const u8, .{
            .long = "suggestedFeeRecipient",
            .description = "Default fee recipient address for validator registrations",
        }, null),
        .defaultGasLimit = cli.option(?u64, .{
            .long = "defaultGasLimit",
            .description = "Suggested gas limit for builder registrations",
        }, null),
        .doppelgangerProtection = cli.flag(.{
            .long = "doppelgangerProtection",
            .description = "Enable doppelganger protection",
        }),
        .@"builder.boostFactor" = cli.option(?[]const u8, .{
            .long = "builder.boostFactor",
            .description = "Builder boost factor percentage",
            .group = "builder",
        }, null),
        .@"externalSigner.urls" = cli.option(?[]const u8, .{
            .long = "externalSigner.urls",
            .description = "External signer URL. Current implementation supports exactly one URL when used with --externalSigner.fetch",
            .group = "externalSigner",
        }, null),
        .@"externalSigner.url" = cli.option(?[]const u8, .{
            .long = "externalSigner.url",
            .description = "External signer URL. Current implementation supports exactly one URL when used with --externalSigner.fetch",
            .group = "externalSigner",
        }, null),
        .@"externalSigner.pubkeys" = cli.option(?[]const u8, .{
            .long = "externalSigner.pubkeys",
            .description = "Compatibility flag only. Explicit remote-signer pubkey lists are not implemented yet",
            .group = "externalSigner",
        }, null),
        .@"externalSigner.fetch" = cli.flag(.{
            .long = "externalSigner.fetch",
            .description = "Fetch validator pubkeys from the external signer. This is the only currently supported remote-signer mode",
            .group = "externalSigner",
        }),
        .@"externalSigner.fetchInterval" = cli.option(?u64, .{
            .long = "externalSigner.fetchInterval",
            .description = "Compatibility flag only. Custom external signer fetch intervals are not implemented yet",
            .group = "externalSigner",
        }, null),
        .importKeystores = cli.option(?[]const u8, .{
            .long = "importKeystores",
            .description = "Compatibility flag only. Startup keystore import is not implemented yet",
        }, null),
        .importKeystoresPassword = cli.option(?[]const u8, .{
            .long = "importKeystoresPassword",
            .description = "Compatibility flag only. Startup keystore import is not implemented yet",
        }, null),
        .metrics = cli.flag(.{
            .long = "metrics",
            .description = "Compatibility flag only. Validator metrics server is not implemented yet",
            .group = "metrics",
        }),
        .@"metrics.port" = cli.option(?u16, .{
            .long = "metrics.port",
            .description = "Compatibility flag only. Validator metrics server is not implemented yet",
            .group = "metrics",
        }, null),
        .@"metrics.address" = cli.option(?[]const u8, .{
            .long = "metrics.address",
            .description = "Compatibility flag only. Validator metrics server is not implemented yet",
            .group = "metrics",
        }, null),
        .@"monitoring.endpoint" = cli.option(?[]const u8, .{
            .long = "monitoring.endpoint",
            .description = "Compatibility flag only. Validator monitoring is not implemented yet",
            .group = "monitoring",
        }, null),
        .@"monitoring.interval" = cli.option(?u64, .{
            .long = "monitoring.interval",
            .description = "Compatibility flag only. Validator monitoring is not implemented yet",
            .group = "monitoring",
        }, null),
        .logFile = cli.option(?[]const u8, .{
            .long = "logFile",
            .description = "Path to output all logs to a persistent log file",
            .group = "logging",
        }, null),
        .logFileLevel = cli.option(?common.CliLogLevel, .{
            .long = "logFileLevel",
            .description = "Logging verbosity level for file output",
            .group = "logging",
        }, null),
        .logFileDailyRotate = cli.option(?u16, .{
            .long = "logFileDailyRotate",
            .description = "Daily rotate log files, set to 0 to disable rotation",
            .group = "logging",
        }, null),
        .logFormat = cli.option(?log_mod.GlobalLogger.Format, .{
            .long = "logFormat",
            .description = "Log output format",
            .group = "logging",
        }, null),
    },
});
