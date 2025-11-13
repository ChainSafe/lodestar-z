test "process sync aggregate - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    defer test_state.deinit();

    var sync_aggregate: types.electra.SyncAggregate.Type = types.electra.SyncAggregate.default_value;
    sync_aggregate.sync_committee_signature = G2_POINT_AT_INFINITY;
    var body: types.electra.BeaconBlockBody.Type = types.electra.BeaconBlockBody.default_value;
    body.sync_aggregate = sync_aggregate;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    message.body = body;

    var beacon_block: types.electra.SignedBeaconBlock.Type = types.electra.SignedBeaconBlock.default_value;
    beacon_block.message = message;
    const signed_beacon_block = SignedBeaconBlock{ .electra = &beacon_block };
    const block = SignedBlock{ .regular = &signed_beacon_block };

    try processSyncAggregate(allocator, test_state.cached_state, &block, true);
}

const std = @import("std");
const types = @import("consensus_types");
const config = @import("config");

const Allocator = std.mem.Allocator;
const TestCachedBeaconStateAllForks = @import("state_transition").test_utils.TestCachedBeaconStateAllForks;

const state_transition = @import("state_transition");
const processSyncAggregate = state_transition.processSyncAggregate;
const SignedBlock = state_transition.SignedBlock;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const G2_POINT_AT_INFINITY = @import("constants").G2_POINT_AT_INFINITY;
