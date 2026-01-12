const std = @import("std");
const types = @import("consensus_types");
const Eth1Data = types.phase0.Eth1Data.Type;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const preset = @import("preset").preset;

pub fn processEth1Data(allocator: std.mem.Allocator, cached_state: *CachedBeaconState, eth1_data: *const Eth1Data) !void {
    const state = cached_state.state;
    if (try becomesNewEth1Data(allocator, state, eth1_data)) {
        try state.setEth1Data(eth1_data);
    }

    try state.appendEth1DataVote(eth1_data);
}

pub fn becomesNewEth1Data(allocator: std.mem.Allocator, state: *BeaconState, new_eth1_data: *const Eth1Data) !bool {
    const SLOTS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD * preset.SLOTS_PER_EPOCH;

    // If there are not more than 50% votes, then we do not have to count to find a winner.
    var state_eth1_data_votes_view = try state.eth1DataVotes();
    const state_eth1_data_votes_len = try state_eth1_data_votes_view.length();
    if ((state_eth1_data_votes_len + 1) * 2 <= SLOTS_PER_ETH1_VOTING_PERIOD) return false;

    // Nothing to do if the state already has this as eth1data (happens a lot after majority vote is in)
    var state_eth1_data_view = try state.eth1Data();
    var state_eth1_data: Eth1Data = undefined;
    try state_eth1_data_view.toValue(allocator, &state_eth1_data);
    if (isEqualEth1DataView(&state_eth1_data, new_eth1_data)) return false;

    // Close to half the EPOCHS_PER_ETH1_VOTING_PERIOD it can be expensive to do so many comparisions.
    // `eth1DataVotes.getAllReadonly()` navigates the tree once to fetch all the LeafNodes efficiently.
    // Then isEqualEth1DataView compares cached roots (HashObject as of Jan 2022) which is much cheaper
    // than doing structural equality, which requires tree -> value conversions
    var same_votes_count: usize = 0;
    for (0..state_eth1_data_votes_len) |i| {
        var state_eth1_data_vote_view = try state_eth1_data_votes_view.get(i);
        var state_eth1_data_vote: Eth1Data = undefined;
        try state_eth1_data_vote_view.toValue(allocator, &state_eth1_data_vote);
        if (isEqualEth1DataView(&state_eth1_data_vote, new_eth1_data)) {
            same_votes_count += 1;
        }
    }

    // The +1 is to account for the `eth1Data` supplied to the function.
    if ((same_votes_count + 1) * 2 > SLOTS_PER_ETH1_VOTING_PERIOD) {
        return true;
    }

    return false;
}

// TODO: should have a different implement in TreeView
fn isEqualEth1DataView(a: *const Eth1Data, b: *const Eth1Data) bool {
    return types.phase0.Eth1Data.equals(a, b);
}
