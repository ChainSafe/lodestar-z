const std = @import("std");
const scoped_log = std.log.scoped(.lightclient_command);

pub fn run(opts: anytype) !void {
    const beacon_api_url = opts.beaconApiUrl orelse opts.beacon_api_url;
    const checkpoint_root = opts.checkpointRoot orelse opts.checkpoint_root;

    if (beacon_api_url == null or checkpoint_root == null) {
        scoped_log.err("lightclient requires --beaconApiUrl/--beacon-api-url and --checkpointRoot/--checkpoint-root", .{});
        return error.MissingValue;
    }

    scoped_log.warn("light client CLI surface is wired, but the runtime is not yet implemented", .{});
}
