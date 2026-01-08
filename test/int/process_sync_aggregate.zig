test "process sync aggregate - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 256);
    defer test_state.deinit();

    const state = test_state.cached_state.state;
    const config = test_state.cached_state.config;
    const previous_slot = state.slot() - 1;
    const root_signed = try state_transition.getBlockRootAtSlot(state, previous_slot);
    const domain = try config.getDomain(state.slot(), c.DOMAIN_SYNC_COMMITTEE, previous_slot);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.primitive.Root, &root_signed, domain, &signing_root);

    const committee_indices = @as(*const [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex, @ptrCast(test_state.cached_state.getEpochCache().current_sync_committee_indexed.get().getValidatorIndices()));
    // validator 0 signs
    const sig0 = try state_transition.test_utils.interopSign(committee_indices[0], &signing_root);
    // validator 1 signs
    const sig1 = try state_transition.test_utils.interopSign(committee_indices[1], &signing_root);
    const agg_sig = try blst.AggregateSignature.aggregate(&.{ sig0, sig1 }, true);

    var sync_aggregate: types.electra.SyncAggregate.Type = types.electra.SyncAggregate.default_value;
    sync_aggregate.sync_committee_signature = agg_sig.toSignature().compress();
    try sync_aggregate.sync_committee_bits.set(0, true);
    // don't set bit 1 yet

    const res = processSyncAggregate(allocator, test_state.cached_state, &sync_aggregate, true);
    try std.testing.expect(res == error.SyncCommitteeSignatureInvalid);

    // now set bit 1
    try sync_aggregate.sync_committee_bits.set(1, true);
    try processSyncAggregate(allocator, test_state.cached_state, &sync_aggregate, true);
}

const std = @import("std");
const types = @import("consensus_types");
const blst = @import("blst");
const preset = @import("preset").preset;
const c = @import("constants");

const Allocator = std.mem.Allocator;
const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;

const state_transition = @import("state_transition");
const processSyncAggregate = state_transition.processSyncAggregate;
const Root = types.primitive.Root.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Block = state_transition.Block;
const SignedBlock = state_transition.SignedBlock;
const BeaconBlock = state_transition.BeaconBlock;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const computeSigningRoot = state_transition.computeSigningRoot;
const G2_POINT_AT_INFINITY = @import("constants").G2_POINT_AT_INFINITY;
