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
        .remoteKeysDir = cli.option(?[]const u8, .{
            .long = "remoteKeysDir",
            .description = "Directory for validator remote signer definitions",
        }, null),
        .proposerDir = cli.option(?[]const u8, .{
            .long = "proposerDir",
            .description = "Directory for validator proposer configs",
        }, null),
        .force = cli.flag(.{
            .long = "force",
            .description = "Load local keystores even if another process already holds their ownership lock",
        }),
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
        .proposerSettingsFile = cli.option(?[]const u8, .{
            .long = "proposerSettingsFile",
            .description = "YAML file with default and per-validator proposer settings",
        }, null),
        .strictFeeRecipientCheck = cli.flag(.{
            .long = "strictFeeRecipientCheck",
            .description = "Reject produced blocks whose execution payload fee recipient does not match the configured validator policy",
        }),
        .builder = cli.flag(.{
            .long = "builder",
            .description = "Compatibility flag only. Builder selection policy is not implemented yet",
            .group = "builder",
        }),
        .@"builder.selection" = cli.option(?[]const u8, .{
            .long = "builder.selection",
            .description = "Compatibility flag only. Builder selection policy is not implemented yet",
            .group = "builder",
        }, null),
        .@"builder.boostFactor" = cli.option(?[]const u8, .{
            .long = "builder.boostFactor",
            .description = "Builder boost factor percentage",
            .group = "builder",
        }, null),
        .broadcastValidation = cli.option(?[]const u8, .{
            .long = "broadcastValidation",
            .description = "Compatibility flag only. Broadcast validation controls are not implemented yet",
        }, null),
        .blindedLocal = cli.flag(.{
            .long = "blindedLocal",
            .description = "Request locally produced validator blocks in blinded form when the beacon node can provide them",
        }),
        .distributed = cli.flag(.{
            .long = "distributed",
            .description = "Compatibility flag only. Distributed validator mode is not implemented yet",
        }),
        .keymanager = cli.flag(.{
            .long = "keymanager",
            .description = "Enable the validator keymanager API server",
            .group = "keymanager",
        }),
        .@"keymanager.auth" = cli.option(bool, .{
            .long = "keymanager.auth",
            .description = "Enable bearer-token authentication for the validator keymanager API",
            .group = "keymanager",
        }, true),
        .@"keymanager.tokenFile" = cli.option(?[]const u8, .{
            .long = "keymanager.tokenFile",
            .description = "Path to the validator keymanager bearer token file",
            .group = "keymanager",
        }, null),
        .@"keymanager.port" = cli.option(?u16, .{
            .long = "keymanager.port",
            .description = "Port for the validator keymanager API server",
            .group = "keymanager",
        }, null),
        .@"keymanager.address" = cli.option(?[]const u8, .{
            .long = "keymanager.address",
            .description = "Bind address for the validator keymanager API server",
            .group = "keymanager",
        }, null),
        .@"keymanager.cors" = cli.option(?[]const u8, .{
            .long = "keymanager.cors",
            .description = "CORS Access-Control-Allow-Origin value for the validator keymanager API server",
            .group = "keymanager",
        }, null),
        .@"keymanager.bodyLimit" = cli.option(?u64, .{
            .long = "keymanager.bodyLimit",
            .description = "Maximum request body size in bytes for the validator keymanager API server",
            .group = "keymanager",
        }, null),
        .@"keymanager.headerLimit" = cli.option(?u64, .{
            .long = "keymanager.headerLimit",
            .description = "Maximum accepted request-header size in bytes for the validator keymanager API server",
            .group = "keymanager",
        }, null),
        .@"keymanager.stacktraces" = cli.flag(.{
            .long = "keymanager.stacktraces",
            .description = "Compatibility flag only. Keymanager stacktrace responses are not implemented yet",
            .group = "keymanager",
        }),
        .@"externalSigner.urls" = cli.option(?[]const u8, .{
            .long = "externalSigner.urls",
            .description = "Comma-separated external signer URLs used for remote validator signing",
            .group = "externalSigner",
        }, null),
        .@"externalSigner.url" = cli.option(?[]const u8, .{
            .long = "externalSigner.url",
            .description = "Backward-compatible alias for externalSigner.urls",
            .group = "externalSigner",
        }, null),
        .@"externalSigner.pubkeys" = cli.option(?[]const u8, .{
            .long = "externalSigner.pubkeys",
            .description = "Comma-separated validator pubkeys pinned to the configured external signer URL (supports exactly one URL)",
            .group = "externalSigner",
        }, null),
        .@"externalSigner.fetch" = cli.flag(.{
            .long = "externalSigner.fetch",
            .description = "Fetch validator pubkeys from the configured external signer URL(s) and refresh them periodically",
            .group = "externalSigner",
        }),
        .@"externalSigner.fetchInterval" = cli.option(?u64, .{
            .long = "externalSigner.fetchInterval",
            .description = "Refresh interval in milliseconds for fetching validator pubkeys from external signers (defaults to once per epoch)",
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
