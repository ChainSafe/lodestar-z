const std = @import("std");

pub fn run(opts: anytype) !void {
    std.log.info("Dev mode not yet implemented. Would start with {d} validators.", .{opts.num_validators});
}
