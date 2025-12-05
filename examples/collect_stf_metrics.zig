const std = @import("std");
const state_transition = @import("state_transition");
const types = @import("consensus_types");

const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const generateElectraBlock = state_transition.test_utils.generateElectraBlock;

const SignedBeaconBlock = state_transition.state_transition.SignedBeaconBlock;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const SignedBlock = state_transition.SignedBlock;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    defer test_state.deinit();
    const electra_block_ptr = try allocator.create(types.electra.SignedBeaconBlock.Type);
    try generateElectraBlock(allocator, test_state.cached_state, electra_block_ptr);
    defer {
        types.electra.SignedBeaconBlock.deinit(allocator, electra_block_ptr);
        allocator.destroy(electra_block_ptr);
    }

    const signed_beacon_block = SignedBeaconBlock{ .electra = electra_block_ptr };
    const signed_block = SignedBlock{ .regular = signed_beacon_block };

    try state_transition.metrics.initializeMetrics(allocator, .{});
    defer state_transition.metrics.deinitMetrics(&state_transition.metrics.state_transition);

    const post_state = try state_transition.stateTransition(
        allocator,
        test_state.cached_state,
        signed_block,
        .{
            .verify_signatures = false,
            .verify_proposer = false,
            .verify_state_root = false,
        },
    );
    defer post_state.deinit();

    const writer = std.io.getStdOut().writer();
    try state_transition.writeMetrics(writer);
}
