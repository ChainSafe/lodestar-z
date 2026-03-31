const cli = @import("zig_cli");
const common = @import("../../spec_common.zig");
const log_mod = @import("log");

pub const spec = cli.command(.{
    .description = "Run the beacon node",
    .options = .{
        .execution_urls = cli.option([]const u8, .{
            .long = "execution-url",
            .description = "URL to execution engine JSON-RPC API",
            .env = "LODESTAR_Z_EXECUTION_URL",
            .group = "execution",
        }, "http://localhost:8551"),
        .execution_timeout = cli.option(?[]const u8, .{
            .long = "execution-timeout",
            .description = "Timeout in ms for execution engine API",
            .env = "LODESTAR_Z_EXECUTION_TIMEOUT",
            .group = "execution",
        }, null),
        .execution_retries = cli.option(u16, .{
            .long = "execution-retries",
            .description = "Number of retries for execution engine API calls",
            .env = "LODESTAR_Z_EXECUTION_RETRIES",
            .group = "execution",
        }, 3),
        .jwt_secret = cli.option(?[]const u8, .{
            .long = "jwt-secret",
            .description = "Path to JWT secret file for EL authentication",
            .env = "LODESTAR_Z_JWT_SECRET",
            .group = "execution",
        }, null),
        .jwt_id = cli.option(?[]const u8, .{
            .long = "jwt-id",
            .description = "Optional identifier for JWT token claims",
            .env = "LODESTAR_Z_JWT_ID",
            .group = "execution",
        }, null),
        .engine_mock = cli.flag(.{
            .long = "engine-mock",
            .description = "Use mock execution engine (development only)",
            .group = "execution",
        }),

        .rest = cli.flag(.{
            .long = "rest",
            .description = "Enable the REST HTTP API",
            .group = "api",
        }),
        .api_port = cli.option(u16, .{
            .long = "api-port",
            .short = 'p',
            .description = "REST API listen port",
            .env = "LODESTAR_Z_API_PORT",
            .group = "api",
        }, 5052),
        .api_address = cli.option([]const u8, .{
            .long = "api-address",
            .description = "REST API listen address",
            .env = "LODESTAR_Z_API_ADDRESS",
            .group = "api",
        }, "127.0.0.1"),
        .api_cors = cli.option(?[]const u8, .{
            .long = "api-cors",
            .description = "CORS Access-Control-Allow-Origin header value",
            .env = "LODESTAR_Z_API_CORS",
            .group = "api",
        }, null),
        .api_swagger = cli.flag(.{
            .long = "api-swagger",
            .description = "Enable Swagger UI at /documentation",
            .group = "api",
        }),

        .p2p_port = cli.option(u16, .{
            .long = "p2p-port",
            .description = "P2P TCP/UDP listen port",
            .env = "LODESTAR_Z_P2P_PORT",
            .group = "network",
        }, 9000),
        .p2p_host = cli.option([]const u8, .{
            .long = "p2p-host",
            .description = "P2P listen address (IPv4)",
            .env = "LODESTAR_Z_P2P_HOST",
            .group = "network",
        }, "0.0.0.0"),
        .p2p_host6 = cli.option(?[]const u8, .{
            .long = "p2p-host6",
            .description = "P2P listen address (IPv6)",
            .env = "LODESTAR_Z_P2P_HOST6",
            .group = "network",
        }, null),
        .p2p_port6 = cli.option(?[]const u8, .{
            .long = "p2p-port6",
            .description = "P2P TCP/UDP listen port (IPv6)",
            .env = "LODESTAR_Z_P2P_PORT6",
            .group = "network",
        }, null),
        .discovery_port = cli.option(?[]const u8, .{
            .long = "discovery-port",
            .description = "UDP port for discv5 discovery (defaults to p2p-port)",
            .env = "LODESTAR_Z_DISCOVERY_PORT",
            .group = "network",
        }, null),
        .bootnodes = cli.option(?[]const u8, .{
            .long = "bootnodes",
            .description = "Comma-separated list of bootnode ENRs",
            .env = "LODESTAR_Z_BOOTNODES",
            .group = "network",
        }, null),
        .target_peers = cli.option(u16, .{
            .long = "target-peers",
            .description = "Target number of connected peers",
            .env = "LODESTAR_Z_TARGET_PEERS",
            .group = "network",
        }, 50),
        .subscribe_all_subnets = cli.flag(.{
            .long = "subscribe-all-subnets",
            .description = "Subscribe to all attestation subnets",
            .group = "network",
        }),
        .disable_peer_scoring = cli.flag(.{
            .long = "disable-peer-scoring",
            .description = "Disable peer scoring (for testing/devnets)",
            .group = "network",
        }),
        .discv5 = cli.flag(.{
            .long = "discv5",
            .description = "Enable discv5 peer discovery",
            .group = "network",
        }),
        .mdns = cli.flag(.{
            .long = "mdns",
            .description = "Enable mDNS local peer discovery",
            .group = "network",
        }),
        .direct_peers = cli.option(?[]const u8, .{
            .long = "direct-peers",
            .description = "Comma-separated direct peer multiaddrs or ENRs",
            .env = "LODESTAR_Z_DIRECT_PEERS",
            .group = "network",
        }, null),

        .checkpoint_state = cli.option(?[]const u8, .{
            .long = "checkpoint-state",
            .description = "Path to checkpoint state SSZ file",
            .env = "LODESTAR_Z_CHECKPOINT_STATE",
            .group = "sync",
        }, null),
        .checkpoint_block = cli.option(?[]const u8, .{
            .long = "checkpoint-block",
            .description = "Path to checkpoint block SSZ file",
            .env = "LODESTAR_Z_CHECKPOINT_BLOCK",
            .group = "sync",
        }, null),
        .checkpoint_sync_url = cli.option(?[]const u8, .{
            .long = "checkpoint-sync-url",
            .description = "URL to fetch checkpoint state from a beacon API",
            .env = "LODESTAR_Z_CHECKPOINT_SYNC_URL",
            .group = "sync",
        }, null),
        .force_checkpoint_sync = cli.flag(.{
            .long = "force-checkpoint-sync",
            .description = "Force checkpoint sync even if DB has recent state",
            .group = "sync",
        }),
        .weak_subjectivity_checkpoint = cli.option(?[]const u8, .{
            .long = "weak-subjectivity-checkpoint",
            .description = "Weak subjectivity checkpoint (root:epoch format)",
            .env = "LODESTAR_Z_WS_CHECKPOINT",
            .group = "sync",
        }, null),
        .sync_is_single_node = cli.flag(.{
            .long = "sync-single-node",
            .description = "Consider node synced without peers (single-node devnets only)",
            .group = "sync",
        }),
        .sync_disable_range = cli.flag(.{
            .long = "sync-disable-range",
            .description = "Disable range sync (debugging only)",
            .group = "sync",
        }),

        .metrics = cli.flag(.{
            .long = "metrics",
            .description = "Enable Prometheus metrics HTTP server",
            .group = "metrics",
        }),
        .metrics_port = cli.option(u16, .{
            .long = "metrics-port",
            .description = "Metrics HTTP server listen port",
            .env = "LODESTAR_Z_METRICS_PORT",
            .group = "metrics",
        }, 8008),
        .metrics_address = cli.option([]const u8, .{
            .long = "metrics-address",
            .description = "Metrics HTTP server listen address",
            .env = "LODESTAR_Z_METRICS_ADDRESS",
            .group = "metrics",
        }, "127.0.0.1"),

        .verify_signatures = cli.flag(.{
            .long = "verify-signatures",
            .description = "Enable BLS signature verification",
            .group = "chain",
        }),
        .safe_slots_to_import = cli.option(?[]const u8, .{
            .long = "safe-slots-to-import-optimistically",
            .description = "Slots threshold for optimistic import",
            .env = "LODESTAR_Z_SAFE_SLOTS_TO_IMPORT",
            .group = "chain",
        }, null),
        .suggest_fee_recipient = cli.option(?[]const u8, .{
            .long = "suggest-fee-recipient",
            .description = "Default fee recipient address (0x-prefixed hex)",
            .env = "LODESTAR_Z_SUGGESTED_FEE_RECIPIENT",
            .group = "chain",
        }, null),
        .graffiti = cli.option(?[]const u8, .{
            .long = "graffiti",
            .description = "Custom graffiti string for block production (max 32 bytes UTF-8)",
            .env = "LODESTAR_Z_GRAFFITI",
            .group = "chain",
        }, null),
        .emit_payload_attributes = cli.flag(.{
            .long = "emit-payload-attributes",
            .description = "SSE emit execution payloadAttributes before every slot",
            .group = "chain",
        }),
        .archive_state_epoch_freq = cli.option(u16, .{
            .long = "archive-state-epoch-frequency",
            .description = "Minimum epochs between archived states",
            .env = "LODESTAR_Z_ARCHIVE_STATE_FREQ",
            .group = "chain",
        }, 1024),
        .prune_history = cli.flag(.{
            .long = "prune-history",
            .description = "Prune historical blocks and state",
            .group = "chain",
        }),

        .builder = cli.flag(.{
            .long = "builder",
            .description = "Enable external block builder",
            .group = "builder",
        }),
        .builder_url = cli.option(?[]const u8, .{
            .long = "builder-url",
            .description = "URL for external block builder API",
            .env = "LODESTAR_Z_BUILDER_URL",
            .group = "builder",
        }, null),
        .builder_timeout = cli.option(?[]const u8, .{
            .long = "builder-timeout",
            .description = "Timeout in ms for builder API HTTP client",
            .env = "LODESTAR_Z_BUILDER_TIMEOUT",
            .group = "builder",
        }, null),
        .builder_fault_window = cli.option(?[]const u8, .{
            .long = "builder-fault-inspection-window",
            .description = "Window to inspect missed slots for builder circuit breaker",
            .env = "LODESTAR_Z_BUILDER_FAULT_WINDOW",
            .group = "builder",
        }, null),
        .builder_allowed_faults = cli.option(?[]const u8, .{
            .long = "builder-allowed-faults",
            .description = "Allowed faults in fault window for builder circuit breaker",
            .env = "LODESTAR_Z_BUILDER_ALLOWED_FAULTS",
            .group = "builder",
        }, null),
        .builder_boost_factor = cli.option(?[]const u8, .{
            .long = "builder-boost-factor",
            .description = "Percentage multiplier for builder bid preference (100 = no boost)",
            .env = "LODESTAR_Z_BUILDER_BOOST_FACTOR",
            .group = "builder",
        }, null),

        .monitoring_endpoint = cli.option(?[]const u8, .{
            .long = "monitoring-endpoint",
            .description = "Remote monitoring service endpoint URL",
            .env = "LODESTAR_Z_MONITORING_ENDPOINT",
            .group = "monitoring",
        }, null),
        .monitoring_interval = cli.option(?[]const u8, .{
            .long = "monitoring-interval",
            .description = "Interval in ms between sending client stats",
            .env = "LODESTAR_Z_MONITORING_INTERVAL",
            .group = "monitoring",
        }, null),

        .log_file = cli.option(?[]const u8, .{
            .long = "log-file",
            .description = "Path to persistent log file",
            .env = "LODESTAR_Z_LOG_FILE",
            .group = "logging",
        }, null),
        .log_format = cli.option(log_mod.GlobalLogger.Format, .{
            .long = "log-format",
            .description = "Log output format",
            .env = "LODESTAR_Z_LOG_FORMAT",
            .group = "logging",
        }, .human),
        .log_file_level = cli.option(common.CliLogLevel, .{
            .long = "log-file-level",
            .description = "Log level for file output",
            .env = "LODESTAR_Z_LOG_FILE_LEVEL",
            .group = "logging",
        }, .debug),
        .log_file_daily_rotate = cli.option(u16, .{
            .long = "log-file-daily-rotate",
            .description = "Number of daily rotated log files to keep (0 to disable)",
            .env = "LODESTAR_Z_LOG_FILE_ROTATE",
            .group = "logging",
        }, 5),

        .supernode = cli.flag(.{
            .long = "supernode",
            .description = "Subscribe to and custody all data column sidecar subnets",
            .group = "network",
        }),
        .semi_supernode = cli.flag(.{
            .long = "semi-supernode",
            .description = "Subscribe to and custody half of data column sidecar subnets",
            .group = "network",
        }),
    },
});
