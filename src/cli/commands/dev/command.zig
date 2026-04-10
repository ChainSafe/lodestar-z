const std = @import("std");
const scoped_log = std.log.scoped(.dev_command);

pub fn run(opts: anytype) !void {
    const num_validators = opts.genesisValidators orelse opts.num_validators;
    scoped_log.warn("dev mode is not yet implemented; it would start with {d} validators", .{num_validators});
}
