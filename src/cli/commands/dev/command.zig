const std = @import("std");

pub fn run(opts: anytype) !void {
    const num_validators = opts.genesisValidators orelse opts.num_validators;
    std.log.info("Dev mode not yet implemented. Would start with {d} validators.", .{num_validators});
}
