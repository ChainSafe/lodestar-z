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
        .@"execution.urls" = cli.option(?[]const u8, .{
            .long = "execution.urls",
            .description = "Comma-separated execution engine JSON-RPC API URLs",
            .group = "execution",
        }, null),
        .execution_timeout = cli.option(?[]const u8, .{
            .long = "execution-timeout",
            .description = "Timeout in ms for execution engine API",
            .env = "LODESTAR_Z_EXECUTION_TIMEOUT",
            .group = "execution",
        }, null),
        .@"execution.timeout" = cli.option(?[]const u8, .{
            .long = "execution.timeout",
            .description = "Timeout in ms for execution engine API",
            .group = "execution",
        }, null),
        .execution_retries = cli.option(u16, .{
            .long = "execution-retries",
            .description = "Number of retries for execution engine API calls",
            .env = "LODESTAR_Z_EXECUTION_RETRIES",
            .group = "execution",
        }, 3),
        .@"execution.retries" = cli.option(?u16, .{
            .long = "execution.retries",
            .description = "Number of retries for execution engine API calls",
            .group = "execution",
        }, null),
        .@"execution.retryDelay" = cli.option(?u16, .{
            .long = "execution.retryDelay",
            .description = "Delay between execution engine retries in milliseconds",
            .group = "execution",
        }, null),
        .jwt_secret = cli.option(?[]const u8, .{
            .long = "jwt-secret",
            .description = "Path to JWT secret file for EL authentication",
            .env = "LODESTAR_Z_JWT_SECRET",
            .group = "execution",
        }, null),
        .jwtSecret = cli.option(?[]const u8, .{
            .long = "jwtSecret",
            .description = "Path to JWT secret file for EL authentication",
            .group = "execution",
        }, null),
        .jwt_id = cli.option(?[]const u8, .{
            .long = "jwt-id",
            .description = "Optional identifier for JWT token claims",
            .env = "LODESTAR_Z_JWT_ID",
            .group = "execution",
        }, null),
        .jwtId = cli.option(?[]const u8, .{
            .long = "jwtId",
            .description = "Optional identifier for JWT token claims",
            .group = "execution",
        }, null),
        .engine_mock = cli.flag(.{
            .long = "engine-mock",
            .description = "Use mock execution engine (development only)",
            .group = "execution",
        }),
        .@"execution.engineMock" = cli.flag(.{
            .long = "execution.engineMock",
            .description = "Use mock execution engine (development only)",
            .group = "execution",
        }),

        .rest = cli.flag(.{
            .long = "rest",
            .description = "Enable the REST HTTP API",
            .group = "api",
        }),
        .@"rest.namespace" = cli.option(?[]const u8, .{
            .long = "rest.namespace",
            .description = "Comma-separated REST namespaces to expose",
            .group = "api",
        }, null),
        .@"api.maxGindicesInProof" = cli.option(?u32, .{
            .long = "api.maxGindicesInProof",
            .description = "Limit max number of gindices in a single proof request",
            .group = "api",
        }, null),
        .api_port = cli.option(u16, .{
            .long = "api-port",
            .short = 'p',
            .description = "REST API listen port",
            .env = "LODESTAR_Z_API_PORT",
            .group = "api",
        }, 5052),
        .@"rest.port" = cli.option(?u16, .{
            .long = "rest.port",
            .description = "REST API listen port",
            .group = "api",
        }, null),
        .api_address = cli.option([]const u8, .{
            .long = "api-address",
            .description = "REST API listen address",
            .env = "LODESTAR_Z_API_ADDRESS",
            .group = "api",
        }, "127.0.0.1"),
        .@"rest.address" = cli.option(?[]const u8, .{
            .long = "rest.address",
            .description = "REST API listen address",
            .group = "api",
        }, null),
        .api_cors = cli.option(?[]const u8, .{
            .long = "api-cors",
            .description = "CORS Access-Control-Allow-Origin header value",
            .env = "LODESTAR_Z_API_CORS",
            .group = "api",
        }, null),
        .@"rest.cors" = cli.option(?[]const u8, .{
            .long = "rest.cors",
            .description = "CORS Access-Control-Allow-Origin header value",
            .group = "api",
        }, null),
        .api_swagger = cli.flag(.{
            .long = "api-swagger",
            .description = "Enable Swagger UI at /documentation",
            .group = "api",
        }),
        .@"rest.swaggerUI" = cli.flag(.{
            .long = "rest.swaggerUI",
            .description = "Enable Swagger UI at /documentation",
            .group = "api",
        }),
        .@"rest.headerLimit" = cli.option(?u32, .{
            .long = "rest.headerLimit",
            .description = "Maximum request header length in bytes",
            .group = "api",
        }, null),
        .@"rest.bodyLimit" = cli.option(?u32, .{
            .long = "rest.bodyLimit",
            .description = "Maximum request body size in bytes",
            .group = "api",
        }, null),
        .@"rest.stacktraces" = cli.flag(.{
            .long = "rest.stacktraces",
            .description = "Return stacktraces in HTTP error responses",
            .group = "api",
        }),

        .p2p_port = cli.option(u16, .{
            .long = "p2p-port",
            .description = "P2P TCP/UDP listen port",
            .env = "LODESTAR_Z_P2P_PORT",
            .group = "network",
        }, 9000),
        .port = cli.option(?u16, .{
            .long = "port",
            .description = "P2P TCP/UDP listen port",
            .group = "network",
        }, null),
        .p2p_host = cli.option(?[]const u8, .{
            .long = "p2p-host",
            .description = "P2P listen address (IPv4); omit to disable IPv4 if IPv6 is configured",
            .env = "LODESTAR_Z_P2P_HOST",
            .group = "network",
        }, null),
        .listenAddress = cli.option(?[]const u8, .{
            .long = "listenAddress",
            .description = "P2P listen address (IPv4)",
            .group = "network",
        }, null),
        .p2p_host6 = cli.option(?[]const u8, .{
            .long = "p2p-host6",
            .description = "P2P listen address (IPv6); omit to disable IPv6",
            .env = "LODESTAR_Z_P2P_HOST6",
            .group = "network",
        }, null),
        .listenAddress6 = cli.option(?[]const u8, .{
            .long = "listenAddress6",
            .description = "P2P listen address (IPv6)",
            .group = "network",
        }, null),
        .p2p_port6 = cli.option(?[]const u8, .{
            .long = "p2p-port6",
            .description = "P2P TCP/UDP listen port (IPv6)",
            .env = "LODESTAR_Z_P2P_PORT6",
            .group = "network",
        }, null),
        .port6 = cli.option(?u16, .{
            .long = "port6",
            .description = "P2P TCP/UDP listen port (IPv6)",
            .group = "network",
        }, null),
        .discovery_port = cli.option(?[]const u8, .{
            .long = "discovery-port",
            .description = "UDP port for discv5 discovery (defaults to p2p-port)",
            .env = "LODESTAR_Z_DISCOVERY_PORT",
            .group = "network",
        }, null),
        .discoveryPort = cli.option(?u16, .{
            .long = "discoveryPort",
            .description = "UDP port for discv5 discovery",
            .group = "network",
        }, null),
        .discoveryPort6 = cli.option(?u16, .{
            .long = "discoveryPort6",
            .description = "IPv6 UDP port for discv5 discovery",
            .group = "network",
        }, null),
        .bootnodes = cli.option(?[]const u8, .{
            .long = "bootnodes",
            .description = "Comma-separated list of bootnode ENRs",
            .env = "LODESTAR_Z_BOOTNODES",
            .group = "network",
        }, null),
        .bootnodesFile = cli.option(?[]const u8, .{
            .long = "bootnodesFile",
            .description = "Bootnodes file path",
            .group = "network",
        }, null),
        .target_peers = cli.option(u16, .{
            .long = "target-peers",
            .description = "Target number of connected peers",
            .env = "LODESTAR_Z_TARGET_PEERS",
            .group = "network",
        }, 50),
        .targetPeers = cli.option(?u16, .{
            .long = "targetPeers",
            .description = "Target number of connected peers",
            .group = "network",
        }, null),
        .subscribe_all_subnets = cli.flag(.{
            .long = "subscribe-all-subnets",
            .description = "Subscribe to all attestation subnets",
            .group = "network",
        }),
        .subscribeAllSubnets = cli.flag(.{
            .long = "subscribeAllSubnets",
            .description = "Subscribe to all attestation subnets",
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
        .directPeers = cli.option(?[]const u8, .{
            .long = "directPeers",
            .description = "Comma-separated direct peer multiaddrs or ENRs",
            .group = "network",
        }, null),
        .@"network.maxPeers" = cli.option(?u16, .{
            .long = "network.maxPeers",
            .description = "Maximum number of peer connections allowed",
            .group = "network",
        }, null),
        .@"network.allowPublishToZeroPeers" = cli.flag(.{
            .long = "network.allowPublishToZeroPeers",
            .description = "Allow publishing when no peers are connected",
            .group = "network",
        }),
        .@"network.targetGroupPeers" = cli.option(?u16, .{
            .long = "network.targetGroupPeers",
            .description = "Target peers per custody group",
            .group = "network",
        }, null),

        .checkpoint_state = cli.option(?[]const u8, .{
            .long = "checkpoint-state",
            .description = "Path to checkpoint state SSZ file",
            .env = "LODESTAR_Z_CHECKPOINT_STATE",
            .group = "sync",
        }, null),
        .checkpointState = cli.option(?[]const u8, .{
            .long = "checkpointState",
            .description = "Path or URL to checkpoint state SSZ file",
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
        .checkpointSyncUrl = cli.option(?[]const u8, .{
            .long = "checkpointSyncUrl",
            .description = "URL to fetch checkpoint state from a beacon API",
            .group = "sync",
        }, null),
        .force_checkpoint_sync = cli.flag(.{
            .long = "force-checkpoint-sync",
            .description = "Force checkpoint sync even if DB has recent state",
            .group = "sync",
        }),
        .forceCheckpointSync = cli.flag(.{
            .long = "forceCheckpointSync",
            .description = "Force checkpoint sync even if DB has recent state",
            .group = "sync",
        }),
        .weak_subjectivity_checkpoint = cli.option(?[]const u8, .{
            .long = "weak-subjectivity-checkpoint",
            .description = "Weak subjectivity checkpoint (root:epoch format)",
            .env = "LODESTAR_Z_WS_CHECKPOINT",
            .group = "sync",
        }, null),
        .wssCheckpoint = cli.option(?[]const u8, .{
            .long = "wssCheckpoint",
            .description = "Weak subjectivity checkpoint (root:epoch format)",
            .group = "sync",
        }, null),
        .ignoreWeakSubjectivityCheck = cli.flag(.{
            .long = "ignoreWeakSubjectivityCheck",
            .description = "Ignore weak subjectivity check failures",
            .group = "sync",
        }),
        .sync_is_single_node = cli.flag(.{
            .long = "sync-single-node",
            .description = "Consider node synced without peers (single-node devnets only)",
            .group = "sync",
        }),
        .@"sync.isSingleNode" = cli.flag(.{
            .long = "sync.isSingleNode",
            .description = "Consider node synced without peers (single-node devnets only)",
            .group = "sync",
        }),
        .sync_disable_range = cli.flag(.{
            .long = "sync-disable-range",
            .description = "Disable range sync (debugging only)",
            .group = "sync",
        }),
        .@"sync.disableRangeSync" = cli.flag(.{
            .long = "sync.disableRangeSync",
            .description = "Disable range sync (debugging only)",
            .group = "sync",
        }),
        .@"sync.disableProcessAsChainSegment" = cli.flag(.{
            .long = "sync.disableProcessAsChainSegment",
            .description = "Disable processing block ranges as chain segments",
            .group = "sync",
        }),
        .@"sync.backfillBatchSize" = cli.option(?u32, .{
            .long = "sync.backfillBatchSize",
            .description = "Batch size for backfill sync",
            .group = "sync",
        }, null),
        .@"sync.slotImportTolerance" = cli.option(?u32, .{
            .long = "sync.slotImportTolerance",
            .description = "Slot tolerance before triggering range sync",
            .group = "sync",
        }, null),

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
        .@"metrics.port" = cli.option(?u16, .{
            .long = "metrics.port",
            .description = "Metrics HTTP server listen port",
            .group = "metrics",
        }, null),
        .metrics_address = cli.option([]const u8, .{
            .long = "metrics-address",
            .description = "Metrics HTTP server listen address",
            .env = "LODESTAR_Z_METRICS_ADDRESS",
            .group = "metrics",
        }, "127.0.0.1"),
        .@"metrics.address" = cli.option(?[]const u8, .{
            .long = "metrics.address",
            .description = "Metrics HTTP server listen address",
            .group = "metrics",
        }, null),

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
        .suggestedFeeRecipient = cli.option(?[]const u8, .{
            .long = "suggestedFeeRecipient",
            .description = "Default fee recipient address (0x-prefixed hex)",
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
        .emitPayloadAttributes = cli.flag(.{
            .long = "emitPayloadAttributes",
            .description = "SSE emit execution payloadAttributes before every slot",
            .group = "chain",
        }),
        .archive_state_epoch_freq = cli.option(u16, .{
            .long = "archive-state-epoch-frequency",
            .description = "Minimum epochs between archived states",
            .env = "LODESTAR_Z_ARCHIVE_STATE_FREQ",
            .group = "chain",
        }, 1024),
        .@"chain.archiveStateEpochFrequency" = cli.option(?u16, .{
            .long = "chain.archiveStateEpochFrequency",
            .description = "Minimum epochs between archived states",
            .group = "chain",
        }, null),
        .prune_history = cli.flag(.{
            .long = "prune-history",
            .description = "Prune historical blocks and state",
            .group = "chain",
        }),
        .@"chain.pruneHistory" = cli.flag(.{
            .long = "chain.pruneHistory",
            .description = "Prune historical blocks and state",
            .group = "chain",
        }),
        .@"chain.maxBlockStates" = cli.option(?u32, .{
            .long = "chain.maxBlockStates",
            .description = "Max block states to cache in memory",
            .group = "chain",
        }, null),
        .@"chain.maxCPStateEpochsInMemory" = cli.option(?u32, .{
            .long = "chain.maxCPStateEpochsInMemory",
            .description = "Max checkpoint state epochs to cache in memory",
            .group = "chain",
        }, null),
        .@"chain.maxCPStateEpochsOnDisk" = cli.option(?u32, .{
            .long = "chain.maxCPStateEpochsOnDisk",
            .description = "Max checkpoint state epochs to cache on disk",
            .group = "chain",
        }, null),

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
        .@"builder.url" = cli.option(?[]const u8, .{
            .long = "builder.url",
            .description = "URL for external block builder API",
            .group = "builder",
        }, null),
        .@"builder.urls" = cli.option(?[]const u8, .{
            .long = "builder.urls",
            .description = "URL for external block builder API",
            .group = "builder",
        }, null),
        .builder_timeout = cli.option(?[]const u8, .{
            .long = "builder-timeout",
            .description = "Timeout in ms for builder API HTTP client",
            .env = "LODESTAR_Z_BUILDER_TIMEOUT",
            .group = "builder",
        }, null),
        .@"builder.timeout" = cli.option(?[]const u8, .{
            .long = "builder.timeout",
            .description = "Timeout in ms for builder API HTTP client",
            .group = "builder",
        }, null),
        .builder_fault_window = cli.option(?[]const u8, .{
            .long = "builder-fault-inspection-window",
            .description = "Window to inspect missed slots for builder circuit breaker",
            .env = "LODESTAR_Z_BUILDER_FAULT_WINDOW",
            .group = "builder",
        }, null),
        .@"builder.faultInspectionWindow" = cli.option(?[]const u8, .{
            .long = "builder.faultInspectionWindow",
            .description = "Window to inspect missed slots for builder circuit breaker",
            .group = "builder",
        }, null),
        .builder_allowed_faults = cli.option(?[]const u8, .{
            .long = "builder-allowed-faults",
            .description = "Allowed faults in fault window for builder circuit breaker",
            .env = "LODESTAR_Z_BUILDER_ALLOWED_FAULTS",
            .group = "builder",
        }, null),
        .@"builder.allowedFaults" = cli.option(?[]const u8, .{
            .long = "builder.allowedFaults",
            .description = "Allowed faults in fault window for builder circuit breaker",
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
        .@"monitoring.endpoint" = cli.option(?[]const u8, .{
            .long = "monitoring.endpoint",
            .description = "Remote monitoring service endpoint URL",
            .group = "monitoring",
        }, null),
        .monitoring_interval = cli.option(?[]const u8, .{
            .long = "monitoring-interval",
            .description = "Interval in ms between sending client stats",
            .env = "LODESTAR_Z_MONITORING_INTERVAL",
            .group = "monitoring",
        }, null),
        .@"monitoring.interval" = cli.option(?[]const u8, .{
            .long = "monitoring.interval",
            .description = "Interval in ms between sending client stats",
            .group = "monitoring",
        }, null),
        .@"monitoring.initialDelay" = cli.option(?[]const u8, .{
            .long = "monitoring.initialDelay",
            .description = "Initial delay before sending monitoring stats",
            .group = "monitoring",
        }, null),
        .@"monitoring.requestTimeout" = cli.option(?[]const u8, .{
            .long = "monitoring.requestTimeout",
            .description = "Timeout for monitoring requests in milliseconds",
            .group = "monitoring",
        }, null),
        .@"monitoring.collectSystemStats" = cli.flag(.{
            .long = "monitoring.collectSystemStats",
            .description = "Enable collecting system stats for monitoring",
            .group = "monitoring",
        }),

        .log_file = cli.option(?[]const u8, .{
            .long = "log-file",
            .description = "Path to persistent log file",
            .env = "LODESTAR_Z_LOG_FILE",
            .group = "logging",
        }, null),
        .logFile = cli.option(?[]const u8, .{
            .long = "logFile",
            .description = "Path to persistent log file",
            .group = "logging",
        }, null),
        .log_format = cli.option(log_mod.GlobalLogger.Format, .{
            .long = "log-format",
            .description = "Log output format",
            .env = "LODESTAR_Z_LOG_FORMAT",
            .group = "logging",
        }, .human),
        .logFormat = cli.option(?log_mod.GlobalLogger.Format, .{
            .long = "logFormat",
            .description = "Log output format",
            .group = "logging",
        }, null),
        .log_file_level = cli.option(common.CliLogLevel, .{
            .long = "log-file-level",
            .description = "Log level for file output",
            .env = "LODESTAR_Z_LOG_FILE_LEVEL",
            .group = "logging",
        }, .debug),
        .logFileLevel = cli.option(?common.CliLogLevel, .{
            .long = "logFileLevel",
            .description = "Log level for file output",
            .group = "logging",
        }, null),
        .log_file_daily_rotate = cli.option(u16, .{
            .long = "log-file-daily-rotate",
            .description = "Number of daily rotated log files to keep (0 to disable)",
            .env = "LODESTAR_Z_LOG_FILE_ROTATE",
            .group = "logging",
        }, 5),
        .logFileDailyRotate = cli.option(?u16, .{
            .long = "logFileDailyRotate",
            .description = "Number of daily rotated log files to keep (0 to disable)",
            .group = "logging",
        }, null),

        .configFile = cli.option(?[]const u8, .{
            .long = "configFile",
            .description = "Deprecated beacon node configuration file path",
            .group = "beacon",
        }, null),
        .genesisStateFile = cli.option(?[]const u8, .{
            .long = "genesisStateFile",
            .description = "Path or URL to a genesis state file in SSZ format",
            .group = "beacon",
        }, null),
        .unsafeCheckpointState = cli.option(?[]const u8, .{
            .long = "unsafeCheckpointState",
            .description = "Unfinalized checkpoint state to start syncing from",
            .group = "beacon",
        }, null),
        .lastPersistedCheckpointState = cli.flag(.{
            .long = "lastPersistedCheckpointState",
            .description = "Use the last safe persisted checkpoint state",
            .group = "beacon",
        }),
        .dbDir = cli.option(?[]const u8, .{
            .long = "dbDir",
            .description = "Beacon DB directory override",
            .group = "beacon",
        }, null),
        .beaconDir = cli.option(?[]const u8, .{
            .long = "beaconDir",
            .description = "Beacon root directory",
            .group = "beacon",
        }, null),
        .persistNetworkIdentity = cli.option(?bool, .{
            .long = "persistNetworkIdentity",
            .description = "Whether to reuse the same peer-id across restarts",
            .group = "beacon",
        }, null),
        .private = cli.flag(.{
            .long = "private",
            .description = "Do not send implementation details over p2p identify protocol",
            .group = "beacon",
        }),
        .validatorMonitorLogs = cli.flag(.{
            .long = "validatorMonitorLogs",
            .description = "Log validator monitor events as info",
            .group = "beacon",
        }),
        .attachToGlobalThis = cli.flag(.{
            .long = "attachToGlobalThis",
            .description = "Attach the beacon node to globalThis",
            .group = "beacon",
        }),
        .disableLightClientServer = cli.flag(.{
            .long = "disableLightClientServer",
            .description = "Disable light client server",
            .group = "beacon",
        }),
        .@"enr.ip" = cli.option(?[]const u8, .{
            .long = "enr.ip",
            .description = "Override ENR IPv4 entry",
            .group = "enr",
        }, null),
        .@"enr.tcp" = cli.option(?u16, .{
            .long = "enr.tcp",
            .description = "Override ENR TCP entry",
            .group = "enr",
        }, null),
        .@"enr.udp" = cli.option(?u16, .{
            .long = "enr.udp",
            .description = "Override ENR UDP entry",
            .group = "enr",
        }, null),
        .@"enr.ip6" = cli.option(?[]const u8, .{
            .long = "enr.ip6",
            .description = "Override ENR IPv6 entry",
            .group = "enr",
        }, null),
        .@"enr.tcp6" = cli.option(?u16, .{
            .long = "enr.tcp6",
            .description = "Override ENR IPv6 TCP entry",
            .group = "enr",
        }, null),
        .@"enr.udp6" = cli.option(?u16, .{
            .long = "enr.udp6",
            .description = "Override ENR IPv6 UDP entry",
            .group = "enr",
        }, null),
        .nat = cli.flag(.{
            .long = "nat",
            .description = "Allow configuration of non-local addresses",
            .group = "enr",
        }),
    },
});
