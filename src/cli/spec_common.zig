const cli = @import("zig_cli");
const log_mod = @import("log");
const node_mod = @import("node");
const NetworkName = node_mod.NetworkName;

pub const VERSION = "0.1.0";

pub const Network = enum {
    mainnet,
    sepolia,
    holesky,
    hoodi,
    minimal,

    pub fn toNetworkName(self: @This()) NetworkName {
        return switch (self) {
            .mainnet => .mainnet,
            .sepolia => .sepolia,
            .holesky => .holesky,
            .hoodi => .hoodi,
            .minimal => .minimal,
        };
    }
};

pub const CliLogLevel = enum {
    @"error",
    warn,
    info,
    verbose,
    debug,
    trace,

    pub fn toLogLevel(self: @This()) log_mod.Level {
        return switch (self) {
            .@"error" => .err,
            .warn => .warn,
            .info => .info,
            .verbose => .verbose,
            .debug => .debug,
            .trace => .trace,
        };
    }
};

pub const global_options = .{
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
    }, null),

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

    .log_level = cli.option(CliLogLevel, .{
        .long = "log-level",
        .short = 'l',
        .description = "Logging verbosity level",
        .env = "LODESTAR_Z_LOG_LEVEL",
    }, .info),
};
