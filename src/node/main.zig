//! lodestar-z: Ethereum consensus client in Zig.
//!
//! A Zig re-implementation of the Lodestar Ethereum consensus client.
//! CLI interface provides full parity with TS Lodestar's option set.
//!
//! Usage:
//!   lodestar-z <COMMAND> [OPTIONS]
//!
//! Commands:
//!   beacon      Run the beacon node
//!   validator   Run the validator client
//!   dev         Run in development mode
//!   bootnode    Run a discv5 bootnode
//!
//! Global Options:
//!   --network <name>      Target network (mainnet|sepolia|holesky|hoodi|minimal)
//!   --preset <name>       Consensus preset
//!   --data-dir <path>     Root data directory
//!   --rc-config <path>    RC config file (YAML/JSON)
//!   --log-level <level>   Logging verbosity

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const cli = @import("zig_cli");

const node_mod = @import("node");
const BeaconNode = node_mod.BeaconNode;
const NodeOptions = node_mod.NodeOptions;
const NetworkName = node_mod.NetworkName;

const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const config_loader = config_mod.config_loader;

const state_transition = @import("state_transition");
const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;

const genesis_util = @import("genesis_util.zig");
const sync_mod = @import("sync");
const checkpoint_sync = sync_mod.checkpoint_sync;
const ShutdownHandler = node_mod.ShutdownHandler;

// ============================================================================
// Version
// ============================================================================

const VERSION = "0.1.0";

// ============================================================================
// Network type — shared with NodeOptions
// ============================================================================

const Network = enum {
    mainnet,
    sepolia,
    holesky,
    hoodi,
    minimal,

    fn toNetworkName(self: @This()) NetworkName {
        return switch (self) {
            .mainnet => .mainnet,
            .sepolia => .sepolia,
            .holesky => .holesky,
            .hoodi => .hoodi,
            .minimal => .minimal,
        };
    }
};

// ============================================================================
// Log level enum — mirrors TS Lodestar LogLevel
// ============================================================================

const LogLevel = enum {
    @"error",
    warn,
    info,
    verbose,
    debug,
    trace,
    // TODO: wire to scoped log level system
};

// ============================================================================
// Log format enum
// ============================================================================

const LogFormat = enum {
    human,
    json,
    // TODO: wire to log formatter
};

// ============================================================================
// CLI Spec — full parity with TS Lodestar
// ============================================================================

const app_spec = cli.app(.{
    .name = "lodestar-z",
    .version = VERSION,
    .description = "Ethereum consensus client in Zig",
    .commands = .{
        // ── beacon ───────────────────────────────────────────────
        .beacon = cli.command(.{
            .description = "Run the beacon node",
            .options = .{
                // ── Execution Engine ─────────────────────────────
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
                }, null), // TODO: wire to NodeOptions

                .execution_retries = cli.option(u16, .{
                    .long = "execution-retries",
                    .description = "Number of retries for execution engine API calls",
                    .env = "LODESTAR_Z_EXECUTION_RETRIES",
                    .group = "execution",
                }, 3), // TODO: wire to NodeOptions

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
                }, null), // TODO: wire to NodeOptions

                .engine_mock = cli.flag(.{
                    .long = "engine-mock",
                    .description = "Use mock execution engine (development only)",
                    .group = "execution",
                }),

                // ── REST API ─────────────────────────────────────
                .rest = cli.flag(.{
                    .long = "rest",
                    .description = "Enable the REST HTTP API",
                    .group = "api",
                }), // TODO: wire to enable/disable API server

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
                }, null), // TODO: wire to API server

                .api_swagger = cli.flag(.{
                    .long = "api-swagger",
                    .description = "Enable Swagger UI at /documentation",
                    .group = "api",
                }), // TODO: wire to API server

                // ── P2P Network ──────────────────────────────────
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
                }, null), // TODO: wire to NodeOptions

                .p2p_port6 = cli.option(?[]const u8, .{
                    .long = "p2p-port6",
                    .description = "P2P TCP/UDP listen port (IPv6)",
                    .env = "LODESTAR_Z_P2P_PORT6",
                    .group = "network",
                }, null), // TODO: wire to NodeOptions

                .discovery_port = cli.option(?[]const u8, .{
                    .long = "discovery-port",
                    .description = "UDP port for discv5 discovery (defaults to p2p-port)",
                    .env = "LODESTAR_Z_DISCOVERY_PORT",
                    .group = "network",
                }, null), // TODO: wire to NodeOptions

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
                }), // TODO: wire to NodeOptions

                .disable_peer_scoring = cli.flag(.{
                    .long = "disable-peer-scoring",
                    .description = "Disable peer scoring (for testing/devnets)",
                    .group = "network",
                }), // TODO: wire to NodeOptions

                .discv5 = cli.flag(.{
                    .long = "discv5",
                    .description = "Enable discv5 peer discovery",
                    .group = "network",
                }), // TODO: wire — currently always enabled

                .mdns = cli.flag(.{
                    .long = "mdns",
                    .description = "Enable mDNS local peer discovery",
                    .group = "network",
                }), // TODO: wire to NodeOptions

                .direct_peers = cli.option(?[]const u8, .{
                    .long = "direct-peers",
                    .description = "Comma-separated direct peer multiaddrs or ENRs",
                    .env = "LODESTAR_Z_DIRECT_PEERS",
                    .group = "network",
                }, null), // TODO: wire to NodeOptions

                // ── Sync ─────────────────────────────────────────
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
                }, null), // TODO: implement checkpoint sync from URL

                .force_checkpoint_sync = cli.flag(.{
                    .long = "force-checkpoint-sync",
                    .description = "Force checkpoint sync even if DB has recent state",
                    .group = "sync",
                }), // TODO: wire to sync module

                .weak_subjectivity_checkpoint = cli.option(?[]const u8, .{
                    .long = "weak-subjectivity-checkpoint",
                    .description = "Weak subjectivity checkpoint (root:epoch format)",
                    .env = "LODESTAR_Z_WS_CHECKPOINT",
                    .group = "sync",
                }, null), // TODO: wire to sync module

                .sync_is_single_node = cli.flag(.{
                    .long = "sync-single-node",
                    .description = "Consider node synced without peers (single-node devnets only)",
                    .group = "sync",
                }), // TODO: wire to NodeOptions

                .sync_disable_range = cli.flag(.{
                    .long = "sync-disable-range",
                    .description = "Disable range sync (debugging only)",
                    .group = "sync",
                }), // TODO: wire to NodeOptions

                // ── Metrics ──────────────────────────────────────
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

                // ── Chain ────────────────────────────────────────
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
                }, null), // TODO: wire to NodeOptions

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
                }), // TODO: wire to NodeOptions

                .archive_state_epoch_freq = cli.option(u16, .{
                    .long = "archive-state-epoch-frequency",
                    .description = "Minimum epochs between archived states",
                    .env = "LODESTAR_Z_ARCHIVE_STATE_FREQ",
                    .group = "chain",
                }, 1024), // TODO: wire to NodeOptions

                .prune_history = cli.flag(.{
                    .long = "prune-history",
                    .description = "Prune historical blocks and state",
                    .group = "chain",
                }), // TODO: wire to NodeOptions

                // ── Builder / MEV ────────────────────────────────
                .builder = cli.flag(.{
                    .long = "builder",
                    .description = "Enable external block builder",
                    .group = "builder",
                }), // TODO: wire to NodeOptions

                .builder_url = cli.option(?[]const u8, .{
                    .long = "builder-url",
                    .description = "URL for external block builder API",
                    .env = "LODESTAR_Z_BUILDER_URL",
                    .group = "builder",
                }, null), // TODO: wire to NodeOptions

                .builder_timeout = cli.option(?[]const u8, .{
                    .long = "builder-timeout",
                    .description = "Timeout in ms for builder API HTTP client",
                    .env = "LODESTAR_Z_BUILDER_TIMEOUT",
                    .group = "builder",
                }, null), // TODO: wire to NodeOptions

                .builder_fault_window = cli.option(?[]const u8, .{
                    .long = "builder-fault-inspection-window",
                    .description = "Window to inspect missed slots for builder circuit breaker",
                    .env = "LODESTAR_Z_BUILDER_FAULT_WINDOW",
                    .group = "builder",
                }, null), // TODO: wire to NodeOptions

                .builder_allowed_faults = cli.option(?[]const u8, .{
                    .long = "builder-allowed-faults",
                    .description = "Allowed faults in fault window for builder circuit breaker",
                    .env = "LODESTAR_Z_BUILDER_ALLOWED_FAULTS",
                    .group = "builder",
                }, null), // TODO: wire to NodeOptions

                .builder_boost_factor = cli.option(?[]const u8, .{
                    .long = "builder-boost-factor",
                    .description = "Percentage multiplier for builder bid preference (100 = no boost)",
                    .env = "LODESTAR_Z_BUILDER_BOOST_FACTOR",
                    .group = "builder",
                }, null), // TODO: wire to NodeOptions

                // ── Monitoring ───────────────────────────────────
                .monitoring_endpoint = cli.option(?[]const u8, .{
                    .long = "monitoring-endpoint",
                    .description = "Remote monitoring service endpoint URL",
                    .env = "LODESTAR_Z_MONITORING_ENDPOINT",
                    .group = "monitoring",
                }, null), // TODO: wire to NodeOptions

                .monitoring_interval = cli.option(?[]const u8, .{
                    .long = "monitoring-interval",
                    .description = "Interval in ms between sending client stats",
                    .env = "LODESTAR_Z_MONITORING_INTERVAL",
                    .group = "monitoring",
                }, null), // TODO: wire to NodeOptions

                // ── Logging (beacon-specific) ────────────────────
                .log_file = cli.option(?[]const u8, .{
                    .long = "log-file",
                    .description = "Path to persistent log file",
                    .env = "LODESTAR_Z_LOG_FILE",
                    .group = "logging",
                }, null), // TODO: wire to log output

                .log_format = cli.option(LogFormat, .{
                    .long = "log-format",
                    .description = "Log output format",
                    .env = "LODESTAR_Z_LOG_FORMAT",
                    .group = "logging",
                }, .human), // TODO: wire to log formatter

                .log_file_level = cli.option(LogLevel, .{
                    .long = "log-file-level",
                    .description = "Log level for file output",
                    .env = "LODESTAR_Z_LOG_FILE_LEVEL",
                    .group = "logging",
                }, .debug), // TODO: wire to log file output

                .log_file_daily_rotate = cli.option(u16, .{
                    .long = "log-file-daily-rotate",
                    .description = "Number of daily rotated log files to keep (0 to disable)",
                    .env = "LODESTAR_Z_LOG_FILE_ROTATE",
                    .group = "logging",
                }, 5), // TODO: wire to log rotation

                // ── Node flags ───────────────────────────────────
                .supernode = cli.flag(.{
                    .long = "supernode",
                    .description = "Subscribe to and custody all data column sidecar subnets",
                    .group = "network",
                }), // TODO: wire to NodeOptions

                .semi_supernode = cli.flag(.{
                    .long = "semi-supernode",
                    .description = "Subscribe to and custody half of data column sidecar subnets",
                    .group = "network",
                }), // TODO: wire to NodeOptions
            },
        }),

        // ── validator ────────────────────────────────────────────
        .validator = cli.command(.{
            .description = "Run the validator client",
            .options = .{
                .beacon_url = cli.option([]const u8, .{
                    .long = "beacon-url",
                    .description = "Beacon node REST API URL",
                    .env = "LODESTAR_Z_BEACON_URL",
                }, "http://localhost:5052"),

                .graffiti = cli.option(?[]const u8, .{
                    .long = "graffiti",
                    .description = "Validator graffiti string",
                    .env = "LODESTAR_Z_GRAFFITI",
                }, null),
                // TODO: implement validator client
            },
        }),

        // ── dev ──────────────────────────────────────────────────
        .dev = cli.command(.{
            .description = "Run in development mode (local devnet)",
            .options = .{
                .num_validators = cli.option(u16, .{
                    .long = "validators",
                    .description = "Number of validators for dev mode genesis",
                    .env = "LODESTAR_Z_DEV_VALIDATORS",
                }, 64),
                // TODO: implement dev mode
            },
        }),

        // ── bootnode ─────────────────────────────────────────────
        .bootnode = cli.command(.{
            .description = "Run a standalone discv5 bootnode",
            .options = .{
                .listen_address = cli.option([]const u8, .{
                    .long = "listenAddress",
                    .description = "IPv4 address to listen for discv5 connections",
                    .env = "LODESTAR_Z_BOOTNODE_LISTEN_ADDRESS",
                }, "0.0.0.0"),
                .bn_port = cli.option(u16, .{
                    .long = "port",
                    .description = "UDP port for bootnode discv5",
                    .env = "LODESTAR_Z_BOOTNODE_PORT",
                }, 9000),
                .listen_address6 = cli.option(?[]const u8, .{
                    .long = "listenAddress6",
                    .description = "IPv6 address to listen for discv5 connections",
                    .env = "LODESTAR_Z_BOOTNODE_LISTEN_ADDRESS6",
                }, null),
                .port6 = cli.option(?u16, .{
                    .long = "port6",
                    .description = "IPv6 UDP port for bootnode discv5",
                    .env = "LODESTAR_Z_BOOTNODE_PORT6",
                }, null),
                .bootnodes = cli.option(?[]const u8, .{
                    .long = "bootnodes",
                    .description = "Comma-separated list of bootnode ENRs",
                    .env = "LODESTAR_Z_BOOTNODE_BOOTNODES",
                }, null),
                .bootnodes_file = cli.option(?[]const u8, .{
                    .long = "bootnodesFile",
                    .description = "File path with bootnode ENRs (one per line)",
                    .env = "LODESTAR_Z_BOOTNODE_BOOTNODES_FILE",
                }, null),
                .enr_ip = cli.option(?[]const u8, .{
                    .long = "enr.ip",
                    .description = "Override ENR IP entry",
                    .env = "LODESTAR_Z_BOOTNODE_ENR_IP",
                }, null),
                .enr_ip6 = cli.option(?[]const u8, .{
                    .long = "enr.ip6",
                    .description = "Override ENR IPv6 entry",
                    .env = "LODESTAR_Z_BOOTNODE_ENR_IP6",
                }, null),
                .enr_udp = cli.option(?u16, .{
                    .long = "enr.udp",
                    .description = "Override ENR UDP port entry",
                    .env = "LODESTAR_Z_BOOTNODE_ENR_UDP",
                }, null),
                .enr_udp6 = cli.option(?u16, .{
                    .long = "enr.udp6",
                    .description = "Override ENR IPv6 UDP port entry",
                    .env = "LODESTAR_Z_BOOTNODE_ENR_UDP6",
                }, null),
                .persist_network_identity = cli.option(bool, .{
                    .long = "persistNetworkIdentity",
                    .description = "Persist peer-id and ENR across restarts",
                    .env = "LODESTAR_Z_BOOTNODE_PERSIST_IDENTITY",
                }, true),
                .nat = cli.option(bool, .{
                    .long = "nat",
                    .description = "Allow ENR configuration of non-local addresses",
                    .env = "LODESTAR_Z_BOOTNODE_NAT",
                }, false),
            },
        }),
    },
    .global_options = .{
        .network = cli.option(Network, .{
            .long = "network",
            .short = 'n',
            .description = "Ethereum consensus network",
            .env = "LODESTAR_Z_NETWORK",
        }, .mainnet),

        .preset = cli.option(?[]const u8, .{
            .long = "preset",
            .description = "Consensus preset override",
            .env = "LODESTAR_Z_PRESET",
        }, null), // TODO: wire to preset loading

        .data_dir = cli.option([]const u8, .{
            .long = "data-dir",
            .short = 'd',
            .description = "Root data directory",
            .env = "LODESTAR_Z_DATA_DIR",
        }, ""),

        .db_path = cli.option(?[]const u8, .{
            .long = "db-path",
            .description = "Override beacon database directory (default: <data-dir>/beacon-node/db)",
            .env = "LODESTAR_Z_DB_PATH",
        }, null),

        .params_file = cli.option(?[]const u8, .{
            .long = "params-file",
            .description = "Network config params YAML file",
            .env = "LODESTAR_Z_PARAMS_FILE",
        }, null),

        .rc_config = cli.option(?[]const u8, .{
            .long = "rc-config",
            .description = "RC config file path (YAML/JSON)",
            .env = "LODESTAR_Z_RC_CONFIG",
        }, null),

        .log_level = cli.option(LogLevel, .{
            .long = "log-level",
            .short = 'l',
            .description = "Logging verbosity level",
            .env = "LODESTAR_Z_LOG_LEVEL",
        }, .info),
    },
});

// ============================================================================
// RC Config resolver (YAML-based)
// ============================================================================

/// Global state for the RC config resolver.
/// We store the parsed YAML map here so the resolver function can access it.
var rc_config_map: ?std.StringHashMap([]const u8) = null;
var rc_config_arena: ?std.heap.ArenaAllocator = null;

fn rcConfigResolver(name: []const u8) ?[]const u8 {
    const map = rc_config_map orelse return null;
    return map.get(name);
}

/// Load an RC config YAML file and populate the resolver map.
/// Keys are the CLI option long names (e.g., "api-port", "network").
fn loadRcConfig(allocator: Allocator, io: Io, path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    const arena_alloc = arena.allocator();

    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    const content = try arena_alloc.alloc(u8, stat.size);
    const n = try file.readPositionalAll(io, content, 0);
    if (n != stat.size) return error.ShortRead;

    // Parse YAML to extract top-level string key-value pairs.
    // We use a simple line-by-line parser for flat YAML config files:
    //   key: value
    var map = std.StringHashMap([]const u8).init(arena_alloc);
    var lines = std.mem.splitScalar(u8, content[0..n], '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const key = std.mem.trim(u8, trimmed[0..colon], " \t");
            const val = std.mem.trim(u8, trimmed[colon + 1 ..], " \t\"'");
            if (key.len > 0 and val.len > 0) {
                try map.put(key, val);
            }
        }
    }

    rc_config_arena = arena;
    rc_config_map = map;
}

// ============================================================================
// Helpers
// ============================================================================

/// Load the BeaconConfig for the selected network.
fn loadBeaconConfig(network: Network) *const BeaconConfig {
    return switch (network) {
        .mainnet => &config_mod.mainnet.config,
        .sepolia => &config_mod.sepolia.config,
        .holesky => &config_mod.hoodi.config,
        .hoodi => &config_mod.hoodi.config,
        .minimal => &config_mod.minimal.config,
    };
}

/// Read a file's entire contents into a newly-allocated slice.
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

// ============================================================================
// Concurrent service tasks
// ============================================================================

const RunContext = struct {
    node: *BeaconNode,
    api_port: u16,
    api_address: []const u8,
    p2p_port: u16,
    p2p_host: []const u8,
};

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
    ctx.node.startApi(io, ctx.api_address, ctx.api_port) catch |err| {
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

// ============================================================================
// Beacon node runner
// ============================================================================

fn runBeacon(
    io: Io,
    allocator: Allocator,
    opts: anytype,
) !void {
    const network = opts.network.toNetworkName();

    // Load beacon configuration.
    var custom_chain_config: config_mod.ChainConfig = undefined;
    var custom_beacon_config: BeaconConfig = undefined;
    const beacon_config: *const BeaconConfig = if (opts.params_file) |config_path| blk: {
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

    // Parse bootnodes
    const bootnodes: []const []const u8 = if (opts.bootnodes) |raw| blk: {
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |enr| {
            const trimmed = std.mem.trim(u8, enr, " \t");
            if (trimmed.len > 0) try list.append(allocator, trimmed);
        }
        break :blk try list.toOwnedSlice(allocator);
    } else &.{};
    defer if (bootnodes.len > 0) allocator.free(bootnodes);

    std.log.info("lodestar-z v{s} starting", .{VERSION});
    std.log.info("  network:    {s}", .{@tagName(network)});
    std.log.info("  data-dir:   {s}", .{if (opts.data_dir.len > 0) opts.data_dir else "(in-memory)"});
    std.log.info("  api:        http://{s}:{d}", .{ opts.api_address, opts.api_port });
    std.log.info("  p2p:        {s}:{d}", .{ opts.p2p_host, opts.p2p_port });
    if (opts.jwt_secret) |jwt| {
        std.log.info("  jwt-secret: {s}", .{jwt});
    }
    std.log.info("  execution:  {s}", .{opts.execution_urls});

    // Ensure data directory tree exists using DataDir path resolution.
    if (opts.data_dir.len > 0) {
        var dd = try node_mod.DataDir.resolve(allocator, NodeOptions{
            .data_dir = opts.data_dir,
            .network = network,
            .db_path = opts.db_path,
        });
        defer dd.deinit();
        try dd.ensureDirs(io);
        std.log.info("  data directory ready: {s}", .{opts.data_dir});
    }

    // Create PMT node pool.
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    // Parse direct peers
    const direct_peers: []const []const u8 = if (opts.direct_peers) |raw| blk: {
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |addr| {
            const trimmed = std.mem.trim(u8, addr, " \t");
            if (trimmed.len > 0) try list.append(allocator, trimmed);
        }
        break :blk try list.toOwnedSlice(allocator);
    } else &.{};
    defer if (direct_peers.len > 0) allocator.free(direct_peers);

    // Parse discovery port (defaults to p2p_port)
    const discovery_port: ?u16 = if (opts.discovery_port) |port_str| blk: {
        break :blk std.fmt.parseInt(u16, port_str, 10) catch null;
    } else null;

    // Parse suggested fee recipient from 0x-prefixed hex string to [20]u8.
    const fee_recipient: ?[20]u8 = if (opts.suggest_fee_recipient) |hex_str| blk: {
        // Strip optional "0x" prefix.
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

    // Parse graffiti: UTF-8 string → [32]u8 zero-padded
    const graffiti_bytes: ?[32]u8 = if (opts.graffiti) |graffiti_str| blk: {
        var g: [32]u8 = [_]u8{0} ** 32;
        const copy_len = @min(graffiti_str.len, 32);
        @memcpy(g[0..copy_len], graffiti_str[0..copy_len]);
        break :blk g;
    } else null;

    // Build NodeOptions from parsed CLI args.
    const node_opts = NodeOptions{
        .data_dir = opts.data_dir,
        .db_path = opts.db_path,
        .bootnodes = bootnodes,
        .verify_signatures = opts.verify_signatures,
        .rest_enabled = opts.rest,
        .rest_port = opts.api_port,
        .rest_address = opts.api_address,
        .execution_urls = &.{opts.execution_urls},
        .jwt_secret_path = opts.jwt_secret,
        .engine_mock = opts.engine_mock,
        .target_peers = opts.target_peers,
        .network = network,
        .p2p_host = opts.p2p_host,
        .p2p_port = opts.p2p_port,
        .enable_discv5 = opts.discv5,
        .discovery_port = discovery_port,
        .direct_peers = direct_peers,
        .enable_mdns = opts.mdns,
        .subscribe_all_subnets = opts.subscribe_all_subnets,
        .suggested_fee_recipient = fee_recipient,
        .graffiti = graffiti_bytes,
        .metrics_enabled = opts.metrics,
        .metrics_port = opts.metrics_port,
        .metrics_address = opts.metrics_address,
        .checkpoint_sync_url = opts.checkpoint_sync_url,
    };

    // Create the BeaconNode.
    const node = try BeaconNode.init(allocator, beacon_config, node_opts);
    defer node.deinit();

    std.log.info("BeaconNode initialized", .{});

    // ================================================================
    // State initialization — priority order (matches TS Lodestar):
    //   1. --checkpoint-sync-url  → fetch finalized state from URL
    //   2. --checkpoint-state     → load from SSZ file
    //   3. DB has persisted state → resume from previous run
    //   4. --network minimal      → generate minimal genesis
    //   5. Fail with helpful error
    //
    // --force-checkpoint-sync skips case 3 (forces re-sync from URL/file).
    // --weak-subjectivity-checkpoint validates the chosen state.
    // ================================================================

    // Wire Io early — needed for HTTP checkpoint sync.
    node.setIo(io);

    const force_checkpoint = opts.force_checkpoint_sync;

    // Case 1: Checkpoint sync from URL.
    if (opts.checkpoint_sync_url) |sync_url| {
        std.log.info("Checkpoint sync from URL: {s}", .{sync_url});

        // Fetch finalized state.
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

        const cp_state = state_transition.deserializeState(
            allocator, &pool, beacon_config, fetched.state_bytes,
        ) catch |err| {
            std.log.err("Failed to deserialize checkpoint state: {}", .{err});
            std.log.err("  This may indicate a fork mismatch — check that the", .{});
            std.log.err("  remote node and this node are on the same network.", .{});
            std.process.exit(1);
        };

        // Validate weak subjectivity checkpoint if provided.
        if (opts.weak_subjectivity_checkpoint) |ws_str| {
            const ws = checkpoint_sync.parseWeakSubjectivityCheckpoint(ws_str) catch |err| {
                std.log.err("Invalid --weak-subjectivity-checkpoint '{s}': {}", .{ ws_str, err });
                std.process.exit(1);
            };
            const cp_slot = cp_state.state.slot() catch 0;
            checkpoint_sync.validateWeakSubjectivityCheckpoint(
                ws, cp_slot, @as(u64, preset.SLOTS_PER_EPOCH),
            ) catch {
                std.log.err("Weak subjectivity violation! The checkpoint state does not", .{});
                std.log.err("  match the expected root:epoch. Refusing to sync.", .{});
                std.log.err("  Expected: {s}", .{ws_str});
                std.process.exit(1);
            };
            std.log.info("Weak subjectivity checkpoint validated (epoch {d})", .{ws.epoch});
        }

        try node.initFromCheckpoint(cp_state);
        if (opts.params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from checkpoint sync URL at slot {d}", .{cp_state.state.slot() catch 0});

    // Case 2: Checkpoint state from file.
    } else if (opts.checkpoint_state) |state_path| {
        std.log.info("Loading checkpoint state from: {s}", .{state_path});

        const cp_state = genesis_util.loadGenesisFromFile(
            allocator, &pool, beacon_config, io, state_path,
        ) catch |err| {
            std.log.err("Failed to load checkpoint state '{s}': {}", .{ state_path, err });
            std.process.exit(1);
        };

        // Validate weak subjectivity checkpoint if provided.
        if (opts.weak_subjectivity_checkpoint) |ws_str| {
            const ws = checkpoint_sync.parseWeakSubjectivityCheckpoint(ws_str) catch |err| {
                std.log.err("Invalid --weak-subjectivity-checkpoint '{s}': {}", .{ ws_str, err });
                std.process.exit(1);
            };
            const cp_slot = cp_state.state.slot() catch 0;
            checkpoint_sync.validateWeakSubjectivityCheckpoint(
                ws, cp_slot, @as(u64, preset.SLOTS_PER_EPOCH),
            ) catch {
                std.log.err("Weak subjectivity violation! Refusing to sync.", .{});
                std.process.exit(1);
            };
            std.log.info("Weak subjectivity checkpoint validated (epoch {d})", .{ws.epoch});
        }

        const cp_slot = cp_state.state.slot() catch 0;
        if (cp_slot == 0) {
            // Genesis state — use initFromGenesis.
            try node.initFromGenesis(cp_state);
        } else {
            // Non-genesis checkpoint — use initFromCheckpoint.
            try node.initFromCheckpoint(cp_state);
        }
        if (opts.params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from checkpoint file at slot {d}", .{cp_slot});

    // Case 3: Resume from DB (unless --force-checkpoint-sync).
    } else if (if (!force_checkpoint) node.db.getLatestStateArchiveSlot() catch null else null) |db_slot| {
        std.log.info("Found persisted state in DB at slot {d}, resuming...", .{db_slot});

        const state_bytes = node.db.getStateArchive(db_slot) catch |err| {
            std.log.err("Failed to read state from DB at slot {d}: {}", .{ db_slot, err });
            std.process.exit(1);
        } orelse {
            std.log.err("State archive at slot {d} unexpectedly empty", .{db_slot});
            std.process.exit(1);
        };
        defer allocator.free(state_bytes);

        const db_state = state_transition.deserializeState(
            allocator, &pool, beacon_config, state_bytes,
        ) catch |err| {
            std.log.err("Failed to deserialize DB state at slot {d}: {}", .{ db_slot, err });
            std.log.err("  The database may be corrupted. Try --force-checkpoint-sync", .{});
            std.process.exit(1);
        };

        try node.initFromCheckpoint(db_state);
        if (opts.params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Resumed from DB state at slot {d}", .{db_slot});

    // Case 4: Minimal genesis (development).
    } else if (network == .minimal) {
        std.log.info("Generating minimal genesis state with 64 validators...", .{});

        const genesis_state = genesis_util.createMinimalGenesis(
            allocator, &pool, 64,
        ) catch |err| {
            std.log.err("Failed to generate minimal genesis state: {}", .{err});
            std.process.exit(1);
        };

        try node.initFromGenesis(genesis_state);
        if (opts.params_file != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from minimal genesis state", .{});

    // Case 5: No state source — fail with helpful error.
    } else {
        std.log.err("No beacon state available. Provide one of:", .{});
        std.log.err("  --checkpoint-sync-url <URL>  Sync from a beacon API endpoint", .{});
        std.log.err("  --checkpoint-state <FILE>    Load from an SSZ state file", .{});
        std.log.err("  --network minimal            Generate a test genesis state", .{});
        std.log.err("", .{});
        std.log.err("Or ensure --data-dir points to a directory with prior chain data.", .{});
        std.process.exit(1);
    }

    // Log initial head state.
    {
        const head = node.getHead();
        std.log.info("Head: slot={d} root=0x{s}", .{ head.slot, &std.fmt.bytesToHex(head.root, .lower) });
        std.log.info("  finalized_epoch={d} justified_epoch={d}", .{ head.finalized_epoch, head.justified_epoch });
    }

    // Build run context and start services.
    var run_ctx = RunContext{
        .node = node,
        .api_port = opts.api_port,
        .api_address = opts.api_address,
        .p2p_port = opts.p2p_port,
        .p2p_host = opts.p2p_host,
    };

    // Io was already wired in the state initialization section above.

    std.log.info("Starting services concurrently...", .{});
    std.log.info("  REST API: http://{s}:{d}", .{ opts.api_address, opts.api_port });
    std.log.info("  P2P:      /ip4/{s}/udp/{d}/quic-v1", .{ opts.p2p_host, opts.p2p_port });

    var group: Io.Group = .init;
    group.async(io, runApiServer, .{ io, &run_ctx });
    group.async(io, runP2p, .{ io, &run_ctx });
    group.async(io, runSlotClock, .{ io, node });

    group.await(io) catch {};

    std.log.info("Shutting down...", .{});
    std.log.info("Goodbye.", .{});
}

// ============================================================================
// Entry point
// ============================================================================

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    // Pre-scan args for --rc-config before main parse.
    {
        var scanner = init.minimal.args.iterate();
        _ = scanner.skip(); // skip argv[0]
        while (scanner.next()) |arg| {
            if (std.mem.eql(u8, arg, "--rc-config")) {
                if (scanner.next()) |config_path| {
                    loadRcConfig(allocator, io, config_path) catch |err| {
                        std.log.err("Failed to load RC config '{s}': {}", .{ config_path, err });
                        std.process.exit(1);
                    };
                    std.log.info("Loaded RC config from: {s}", .{config_path});
                }
                break;
            }
        }
    }

    // Parse CLI with the zig-cli library.
    // Resolution order: CLI args > env vars > RC config resolver > defaults.
    var args_iter = init.minimal.args.iterate();
    const result = if (rc_config_map != null)
        cli.parseAppWithResolver(app_spec, &args_iter, allocator, rcConfigResolver)
    else
        cli.parseApp(app_spec, &args_iter, allocator);

    const parsed = result catch |err| switch (err) {
        error.HelpRequested, error.VersionRequested => return,
        else => {
            std.debug.print("Try 'lodestar-z --help' for usage information.\n", .{});
            std.process.exit(1);
        },
    };

    switch (parsed) {
        .beacon => |opts| {
            try runBeacon(io, allocator, opts);
        },
        .validator => {
            std.log.info("Validator client not yet implemented.", .{});
            // TODO: implement validator client
        },
        .dev => |opts| {
            std.log.info("Dev mode not yet implemented. Would start with {d} validators.", .{opts.num_validators});
            // TODO: implement dev mode
        },
        .bootnode => |opts| {
            try node_mod.bootnode.run(io, allocator, .{
                .listen_address = opts.listen_address,
                .port = opts.bn_port,
                .listen_address6 = opts.listen_address6,
                .port6 = opts.port6,
                .bootnodes = opts.bootnodes,
                .bootnodes_file = opts.bootnodes_file,
                .enr_ip = opts.enr_ip,
                .enr_ip6 = opts.enr_ip6,
                .enr_udp = opts.enr_udp,
                .enr_udp6 = opts.enr_udp6,
                .persist_network_identity = opts.persist_network_identity,
                .nat = opts.nat,
                .data_dir = opts.data_dir,
                .network = @tagName(opts.network),
            });
        },
    }

    // Cleanup RC config arena if allocated.
    if (rc_config_arena) |*arena| {
        arena.deinit();
    }
}
