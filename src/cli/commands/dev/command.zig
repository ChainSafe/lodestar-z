const std = @import("std");

pub fn run(opts: anytype) !void {
    const num_validators = opts.genesisValidators orelse opts.num_validators;
    std.log.warn("dev mode is not yet implemented; it would start with {d} validators", .{num_validators});
}
