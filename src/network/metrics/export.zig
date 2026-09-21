const std = @import("std");
const policy = @import("../gossipsub/topic_policy.zig");
pub const histogram = @import("histogram.zig");
pub const registry = @import("registry.zig");
const prom = registry;

pub const Context = @import("context.zig").Context;
pub const interval_ms = 1_000;
pub const fixed_text_capacity = 1024 * 1024;

pub fn textCapacity(boundaries: []const policy.Boundary) usize {
    std.debug.assert(boundaries.len <= policy.boundary_max);
    var topics: usize = 0;
    for (boundaries) |*boundary| for (boundary.rules) |rule| {
        topics += rule.count;
    };
    std.debug.assert(topics <= policy.topic_max);
    // Three bounded-label gauge samples per topic, including maximum integer and epoch widths.
    return fixed_text_capacity + topics * 768;
}

pub fn write(context: *const Context, writer: *std.Io.Writer) prom.Error!void {
    var encoder: prom.Encoder = .{ .writer = writer };
    try @import("collectors.zig").registry.collect(context, &encoder);
}
