const std = @import("std");
const t = @import("types.zig");
test "peer options reject incompatible bounds before allocation" {
    try (t.Options{}).validate();
    inline for (.{
        t.Options{ .capacity = 0 },
        t.Options{ .capacity = 4097 },
        t.Options{ .outbound_reserve = 512 },
        t.Options{ .max_peers = 513 },
        t.Options{ .max_peers = 257, .engine_capacity = 512 },
        t.Options{ .engine_capacity = 95 },
        t.Options{ .target_peers = 97 },
        t.Options{ .min_outbound = 65 },
    }) |options| try std.testing.expectError(error.InvalidOptions, options.validate());
    try std.testing.expectError(
        error.InvalidForkContext,
        (t.ForkContext{ .custody_groups = 0 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidForkContext,
        (t.ForkContext{ .custody_groups = 129 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidForkContext,
        (t.ForkContext{ .custody_groups = 3 }).validate(),
    );
}
