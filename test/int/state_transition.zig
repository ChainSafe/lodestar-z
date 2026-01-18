const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const generateElectraBlock = state_transition.test_utils.generateElectraBlock;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const ZERO_HASH = @import("constants").ZERO_HASH;

const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;
const stateTransition = state_transition.state_transition.stateTransition;
const TransitionOpt = state_transition.state_transition.TransitionOpt;
const SignedBeaconBlock = state_transition.state_transition.SignedBeaconBlock;
const CachedBeaconState = state_transition.CachedBeaconState;
const SignedBlock = state_transition.SignedBlock;

const TestCase = struct {
    transition_opt: TransitionOpt,
    expect_error: bool,
};

test "state transition - electra block" {
    const test_cases = [_]TestCase{
        .{ .transition_opt = .{ .verify_signatures = true }, .expect_error = true },
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = true }, .expect_error = true },
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = false, .verify_state_root = true }, .expect_error = true },
        // this runs through epoch transition + process block without verifications
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = false, .verify_state_root = false }, .expect_error = false },
    };
    inline for (test_cases) |tc| {
        const allocator = std.testing.allocator;

        var pool = try Node.Pool.init(allocator, 1024);
        defer pool.deinit();
        var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
        defer test_state.deinit();
        const electra_block_ptr = try allocator.create(types.electra.SignedBeaconBlock.Type);
        try generateElectraBlock(allocator, test_state.cached_state, electra_block_ptr);
        defer {
            types.electra.SignedBeaconBlock.deinit(allocator, electra_block_ptr);
            allocator.destroy(electra_block_ptr);
        }

        const signed_beacon_block = SignedBeaconBlock{ .electra = electra_block_ptr };
        const signed_block = SignedBlock{ .regular = signed_beacon_block };

        // this returns the error so no need to handle returned post_state
        // TODO: if blst can publish BlstError.BadEncoding, can just use testing.expectError
        // testing.expectError(blst.c.BLST_BAD_ENCODING, stateTransition(allocator, test_state.cached_state, signed_block, .{ .verify_signatures = true }));
        const res = stateTransition(allocator, test_state.cached_state, signed_block, tc.transition_opt);
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

    defer state_transition.deinitStateTransition();
}
