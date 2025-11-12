const std = @import("std");
const ct = @import("consensus_types");
const Eth1Data = ct.phase0.Eth1Data.Type;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const preset = @import("preset").preset;

pub fn processEth1Data(allocator: std.mem.Allocator, cached_state: *const CachedBeaconStateAllForks, eth1_data: *const Eth1Data) !void {
    const state = cached_state.state;
    if (becomesNewEth1Data(cached_state, eth1_data)) {
        const state_eth1_data = state.eth1Data();
        state_eth1_data.* = eth1_data.*;
    }

    try state.eth1DataVotes().append(allocator, eth1_data.*);
}

pub fn becomesNewEth1Data(cached_state: *const CachedBeaconStateAllForks, new_eth1_data: *const Eth1Data) bool {
    const state = cached_state.state;
    const SLOTS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD * preset.SLOTS_PER_EPOCH;

    // If there are not more than 50% votes, then we do not have to count to find a winner.
    const state_eth1_data_votes = state.eth1DataVotes().items;
    if ((state_eth1_data_votes.len + 1) * 2 <= SLOTS_PER_ETH1_VOTING_PERIOD) {
        return false;
    }

    // Nothing to do if the state already has this as eth1data (happens a lot after majority vote is in)
    if (isEqualEth1DataView(state.eth1Data(), new_eth1_data)) {
        return false;
    }

    // Close to half the EPOCHS_PER_ETH1_VOTING_PERIOD it can be expensive to do so many comparisions.
    // `eth1DataVotes.getAllReadonly()` navigates the tree once to fetch all the LeafNodes efficiently.
    // Then isEqualEth1DataView compares cached roots (HashObject as of Jan 2022) which is much cheaper
    // than doing structural equality, which requires tree -> value conversions
    var same_votes_count: usize = 0;
    for (state_eth1_data_votes) |state_eth1_data_vote| {
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
    return ct.phase0.Eth1Data.equals(a, b);
}
