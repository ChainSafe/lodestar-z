const std = @import("std");
const types = @import("consensus_types");

const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const SignedBlock = @import("../types/block.zig").SignedBlock;
const SignedBeaconBlock = @import("../state_transition.zig").SignedBeaconBlock;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const randaoRevealSignatureSet = @import("./randao.zig").randaoRevealSignatureSet;
const proposerSlashingsSignatureSets = @import("./proposer_slashings.zig").proposerSlashingsSignatureSets;

pub fn blockSignatureSets(
    state: CachedBeaconState,
    signed_block: SignedBlock,
) SingleSignatureSet {
    _ = state;
    _ = signed_block;
}

test "blockSignatureSets" {
    const allocator = std.testing.allocator;
    const validator_count = 256;
    const test_state = try TestCachedBeaconState.init(allocator, validator_count);

    const signature_sets = try std.ArrayList(SingleSignatureSet).init(allocator);

    const block = &types.electra.SignedBeaconBlock.default_value;
    const signed_beacon_block = SignedBeaconBlock{ .electra = block };
    const signed_block = SignedBlock{ .regular = &signed_beacon_block };

    proposerSlashingsSignatureSets(test_state.cached_state, signed_block, signature_sets);

    blockSignatureSets(test_state.state, signed_block);
}
