const cli = @import("zig_cli");

pub const spec = cli.command(.{
    .description = "Run lightclient",
    .options = .{
        .beacon_api_url = cli.option(?[]const u8, .{
            .long = "beacon-api-url",
            .description = "URL to a beacon node that supports the light client API",
        }, null),
        .beaconApiUrl = cli.option(?[]const u8, .{
            .long = "beaconApiUrl",
            .description = "URL to a beacon node that supports the light client API",
        }, null),
        .checkpoint_root = cli.option(?[]const u8, .{
            .long = "checkpoint-root",
            .description = "Checkpoint root hex string to sync the light client from",
        }, null),
        .checkpointRoot = cli.option(?[]const u8, .{
            .long = "checkpointRoot",
            .description = "Checkpoint root hex string to sync the light client from",
        }, null),
    },
});
