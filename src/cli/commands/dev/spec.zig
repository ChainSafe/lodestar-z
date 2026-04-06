const cli = @import("zig_cli");

pub const spec = cli.command(.{
    .description = "Run in development mode (local devnet)",
    .options = .{
        .num_validators = cli.option(u16, .{
            .long = "validators",
            .description = "Number of validators for dev mode genesis",
            .env = "LODESTAR_Z_DEV_VALIDATORS",
        }, 64),
        .genesisValidators = cli.option(?u16, .{
            .long = "genesisValidators",
            .description = "Create genesis with this many interop validators",
        }, null),
        .genesisEth1Hash = cli.option(?[]const u8, .{
            .long = "genesisEth1Hash",
            .description = "Create genesis with this eth1 hash",
        }, null),
        .startValidators = cli.option(?[]const u8, .{
            .long = "startValidators",
            .description = "Inclusive validator index ranges to start, e.g. 0..7",
        }, null),
        .genesisTime = cli.option(?u64, .{
            .long = "genesisTime",
            .description = "genesis_time to initialize interop genesis state",
        }, null),
        .reset = cli.option(bool, .{
            .long = "reset",
            .description = "Delete chain and validator directories before starting",
        }, false),
        .dumpTestnetFiles = cli.option(?[]const u8, .{
            .long = "dumpTestnetFiles",
            .description = "Dump testnet files and exit",
        }, null),
    },
});
