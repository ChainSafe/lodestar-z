const cli = @import("zig_cli");

pub const spec = cli.command(.{
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
    },
});
