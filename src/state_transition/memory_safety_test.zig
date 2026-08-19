const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("test_utils/root.zig").TestCachedBeaconState;
const deserializeContainerOverrideFieldsWithRanges =
    @import("ssz_container.zig").deserializeContainerOverrideFieldsWithRanges;
const processRewardsAndPenalties =
    @import("epoch/process_rewards_and_penalties.zig").processRewardsAndPenalties;

test "deserializeContainerOverrideFields... cleans up pool nodes on error" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
    defer pool.deinit();

    const U64 = ssz.UintType(64);
    const U64List = ssz.FixedListType(U64, 4, .{});
    const Fields = struct {
        a: U64,
        b: U64List,
    };
    const ContainerST = ssz.VariableContainerType(Fields);

    // Valid offsets for `b`, but `b` payload length is 1 which is not divisible by 8.
    var bytes: [13]u8 = undefined;
    @memset(&bytes, 0);
    std.mem.writeInt(u32, bytes[8..12], 12, .little);

    const baseline_in_use = pool.getNodesInUse();
    const ranges = try ContainerST.readFieldRanges(bytes[0..]);
    try std.testing.expectError(
        error.UnexpectedRemainder,
        deserializeContainerOverrideFieldsWithRanges(
            allocator,
            &pool,
            ContainerST,
            bytes[0..],
            &ranges,
            .{},
        ),
    );
    try std.testing.expectEqual(baseline_in_use, pool.getNodesInUse());
}

test "processRewardsAndPenalties - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processRewardsAndPenalties(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );

    // Verify replacing the old cached balances does not leak.
    try processRewardsAndPenalties(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );
}

test "CachedBeaconState.clone()" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();
    // test clone() api works fine with no memory leak
    const cloned_cached_state = try test_state.cached_state.clone(allocator, .{});
    defer {
        cloned_cached_state.deinit();
        allocator.destroy(cloned_cached_state);
    }
}
