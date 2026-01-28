const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;

pub fn processParticipationFlagUpdates(
    comptime fork: ForkSeq,
    state: *BeaconState(fork),
) !void {
    if (comptime fork.lt(.altair)) return;
    try state.rotateEpochParticipation();
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

test "processParticipationFlagUpdates - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processParticipationFlagUpdates(
        .electra,
        test_state.cached_state.state.castToFork(.electra),
    );
}
