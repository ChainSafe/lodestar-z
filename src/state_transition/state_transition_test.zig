//! Tests for `state_transition.zig`.

const std = @import("std");
const types = @import("consensus_types");
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const deinitReusedEpochTransitionCache = @import("cache/epoch_transition_cache.zig").deinitReusedEpochTransitionCache;
const TestCachedBeaconState = @import("test_utils/root.zig").TestCachedBeaconState;
const generateElectraBlock = @import("test_utils/generate_block.zig").generateElectraBlock;
const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TransitionOpts = @import("state_transition.zig").TransitionOpts;
const stateTransition = @import("state_transition.zig").stateTransition;

const TestCase = struct {
    transition_opt: TransitionOpts,
    expect_error: bool,
};

test "state transition - electra block" {
    const test_cases = [_]TestCase{
        .{ .transition_opt = .{}, .expect_error = true },
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = true }, .expect_error = true },
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = false, .verify_state_root = true }, .expect_error = true },
        // this runs through epoch transition + process block without verifications
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = false, .verify_state_root = false }, .expect_error = false },
    };

    inline for (test_cases) |tc| {
        const allocator = std.testing.allocator;
        const pool_size = 180_000;
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
        defer pool.deinit();

        var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
        defer test_state.deinit();

        var electra_block = types.electra.SignedBeaconBlock.default_value;
        try generateElectraBlock(allocator, test_state.cached_state, &electra_block);
        defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

        const signed_beacon_block = AnySignedBeaconBlock{ .full_electra = &electra_block };

        // this returns the error so no need to handle returned post_state
        // TODO: if blst can publish BlstError.BadEncoding, can just use testing.expectError
        // testing.expectError(blst.c.BLST_BAD_ENCODING, stateTransition(allocator, test_state.cached_state, signed_block, .{ .verify_signatures = true }));
        const res = stateTransition(
            allocator,
            std.testing.io,
            test_state.cached_state,
            signed_beacon_block,
            tc.transition_opt,
        );
        if (tc.expect_error) {
            if (res) |_| {
                try testing.expect(false);
            } else |_| {}
        } else {
            if (res) |post_state| {
                defer {
                    post_state.deinit();
                    allocator.destroy(post_state);
                }
            } else |_| {
                try testing.expect(false);
            }
        }
    }

    deinitReusedEpochTransitionCache(std.testing.io);
}

test "state transition - a rejected block leaves the pre-state unchanged" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 180_000 });
    defer pool.deinit();
    defer deinitReusedEpochTransitionCache(std.testing.io);

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_beacon_block = AnySignedBeaconBlock{ .full_electra = &electra_block };

    // Snapshot the pre-state just before the transition.
    const before = (try test_state.cached_state.state.hashTreeRoot()).*;
    const before_slot = try test_state.cached_state.state.slot();

    // Full verification rejects this block (it isn't validly signed). stateTransition advances
    // and mutates a clone, then discards it on error — so the original state must come out
    // untouched: same root, same slot. (This is the invariant behind the "mutate then reject"
    // findings; the mutations only ever land on the thrown-away clone.)
    const res = stateTransition(allocator, std.testing.io, test_state.cached_state, signed_beacon_block, .{});
    if (res) |post| {
        post.deinit();
        allocator.destroy(post);
        try testing.expect(false); // expected the block to be rejected
    } else |_| {}

    const after = (try test_state.cached_state.state.hashTreeRoot()).*;
    try testing.expectEqualSlices(u8, &before, &after);
    try testing.expectEqual(before_slot, try test_state.cached_state.state.slot());
}
