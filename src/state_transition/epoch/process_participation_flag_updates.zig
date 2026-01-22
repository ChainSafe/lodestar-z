const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;

pub fn processParticipationFlagUpdates(cached_state: *CachedBeaconState) !void {
    const state = cached_state.state;

    if (state.forkSeq().lt(.altair)) return;
    try state.rotateEpochParticipation();
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

test "processParticipationFlagUpdates - sanity" {
    const allocator = std.testing.allocator;
    const validator_count_arr = &.{ 256, 10_000 };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    inline for (validator_count_arr) |validator_count| {
        var test_state = try TestCachedBeaconState.init(allocator, &pool, validator_count);
        defer test_state.deinit();
        try processParticipationFlagUpdates(test_state.cached_state);
    }
    defer @import("../root.zig").deinitStateTransition();
}
