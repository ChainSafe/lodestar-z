//! Tests for `path.zig`.

const std = @import("std");
const Gindex = @import("persistent_merkle_tree").Gindex;
const types = @import("root.zig");
const PathType = @import("path.zig").PathType;
const getPathGindex = @import("path.zig").getPathGindex;

test "PathType" {
    const Root = types.ByteVectorType(32);
    const Checkpoint = types.FixedContainerType(struct {
        slot: types.UintType(64),
        root: Root,
    });

    _ = PathType(Checkpoint, "slot");
}

test "getPathGindex" {
    const Root = types.ByteVectorType(32);
    const Checkpoint = types.FixedContainerType(struct {
        epoch: types.UintType(64),
        root: Root,
    });

    try std.testing.expectEqual(@as(Gindex.Uint, 2), @intFromEnum(getPathGindex(Checkpoint, "epoch")));
    try std.testing.expectEqual(@as(Gindex.Uint, 3), @intFromEnum(getPathGindex(Checkpoint, "root")));

    const BeaconState = types.FixedContainerType(struct {
        slot: types.UintType(64),
        finalized_checkpoint: Checkpoint,
    });

    try std.testing.expectEqual(@as(Gindex.Uint, 7), @intFromEnum(getPathGindex(BeaconState, "finalized_checkpoint.root")));

    const Balances = types.FixedListType(types.UintType(64), 4, .{});
    const SimpleState = types.VariableContainerType(struct {
        slot: types.UintType(64),
        balances: Balances,
    });

    try std.testing.expectEqual(@as(Gindex.Uint, 6), @intFromEnum(getPathGindex(SimpleState, "balances.0")));
}
