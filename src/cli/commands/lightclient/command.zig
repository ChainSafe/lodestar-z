const std = @import("std");

pub fn run(opts: anytype) !void {
    const beacon_api_url = opts.beaconApiUrl orelse opts.beacon_api_url;
    const checkpoint_root = opts.checkpointRoot orelse opts.checkpoint_root;

    if (beacon_api_url == null or checkpoint_root == null) {
        std.log.err("lightclient requires --beaconApiUrl/--beacon-api-url and --checkpointRoot/--checkpoint-root", .{});
        return error.MissingValue;
    }

    std.log.info("Light client CLI surface is wired, runtime is not yet implemented.", .{});
}
