const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;

pub fn processParticipationFlagUpdates(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
) !void {
    if (comptime fork.lt(.altair)) return;
    try state.rotateEpochParticipation();
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

test "processParticipationFlagUpdates - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 10_000);
    defer test_state.deinit();

    try processParticipationFlagUpdates(
        .electra,
        test_state.cached_state.state.castToFork(.electra),
    );
}
