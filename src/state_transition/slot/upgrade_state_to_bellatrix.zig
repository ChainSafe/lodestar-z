const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ssz = @import("consensus_types");

pub fn upgradeStateToBellatrix(_: Allocator, cached_state: *CachedBeaconState) !void {
    var altair_state = cached_state.state;
    if (altair_state.forkSeq() != .altair) {
        return error.StateIsNotAltair;
    }

    // Get underlying node and cast altair tree to bellatrix tree
    //
    // An altair BeaconState tree can be safely casted to a bellatrix BeaconState tree because:
    // - All new fields are appended at the end
    //
    // altair                        | op  | bellatrix
    // ----------------------------- | --- | ------------
    // genesis_time                  | -   | genesis_time
    // genesis_validators_root       | -   | genesis_validators_root
    // slot                          | -   | slot
    // fork                          | -   | fork
    // latest_block_header           | -   | latest_block_header
    // block_roots                   | -   | block_roots
    // state_roots                   | -   | state_roots
    // historical_roots              | -   | historical_roots
    // eth1_data                     | -   | eth1_data
    // eth1_data_votes               | -   | eth1_data_votes
    // eth1_deposit_index            | -   | eth1_deposit_index
    // validators                    | -   | validators
    // balances                      | -   | balances
    // randao_mixes                  | -   | randao_mixes
    // slashings                     | -   | slashings
    // previous_epoch_participation  | -   | previous_epoch_participation
    // current_epoch_participation   | -   | current_epoch_participation
    // justification_bits            | -   | justification_bits
    // previous_justified_checkpoint | -   | previous_justified_checkpoint
    // current_justified_checkpoint  | -   | current_justified_checkpoint
    // finalized_checkpoint          | -   | finalized_checkpoint
    // inactivity_scores             | -   | inactivity_scores
    // current_sync_committee        | -   | current_sync_committee
    // next_sync_committee           | -   | next_sync_committee
    // -                             | new | latest_execution_payload_header

    const state = try altair_state.upgradeUnsafe();
    defer altair_state.deinit();

    try state.setFork(.{
        .previous_version = altair_state.fork().getValue("current_version"),
        .current_version = cached_state.config.chain.BELLATRIX_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    });
}
