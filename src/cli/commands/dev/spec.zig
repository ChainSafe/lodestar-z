const cli = @import("zig_cli");

pub const spec = cli.command(.{
    .description = "Run in development mode (local devnet)",
    .options = .{
        .num_validators = cli.option(u16, .{
            .long = "validators",
            .description = "Number of validators for dev mode genesis",
            .env = "LODESTAR_Z_DEV_VALIDATORS",
        }, 64),
    },
});
