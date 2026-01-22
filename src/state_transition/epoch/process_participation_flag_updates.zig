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
    const validator_count_arr = &.{ 256, 10_000 };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    inline for (validator_count_arr) |validator_count| {
        var test_state = try TestCachedBeaconState.init(allocator, &pool, validator_count);
        defer test_state.deinit();
        const state = test_state.cached_state.state;
        switch (state.forkSeq()) {
            inline else => |f| {
                try processParticipationFlagUpdates(f, &@field(state, f));
            },
        }
    }
    defer @import("../root.zig").deinitStateTransition();
}
