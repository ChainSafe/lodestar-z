const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ct = @import("consensus_types");
const toExecutionPayloadHeader = @import("../types/execution_payload.zig").toExecutionPayloadHeader;

pub fn upgradeStateToCapella(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    // Get underlying node and cast bellatrix tree to capella tree
    //
    // An bellatrix BeaconState tree can be safely casted to a capella BeaconState tree because:
    // - Deprecated fields are replaced by new fields at the exact same indexes
    // - All new fields are appended at the end
    //
    // bellatrix                        | op    | capella
    // -------------------------------- | ----  | ------------
    // genesis_time                     | -     | genesis_time
    // genesis_validators_root          | -     | genesis_validators_root
    // slot                             | -     | slot
    // fork                             | -     | fork
    // latest_block_header              | -     | latest_block_header
    // block_roots                      | -     | block_roots
    // state_roots                      | -     | state_roots
    // historical_roots                 | frozen| historical_roots
    // eth1_data                        | -     | eth1_data
    // eth1_data_votes                  | -     | eth1_data_votes
    // eth1_deposit_index               | -     | eth1_deposit_index
    // validators                       | -     | validators
    // balances                         | -     | balances
    // randao_mixes                     | -     | randao_mixes
    // slashings                        | -     | slashings
    // previous_epoch_participation     | -     | previous_epoch_participation
    // current_epoch_participation      | -     | current_epoch_participation
    // justification_bits               | -     | justification_bits
    // previous_justified_checkpoint    | -     | previous_justified_checkpoint
    // current_justified_checkpoint     | -     | current_justified_checkpoint
    // finalized_checkpoint             | -     | finalized_checkpoint
    // inactivity_scores                | -     | inactivity_scores
    // current_sync_committee           | -     | current_sync_committee
    // next_sync_committee              | -     | next_sync_committee
    // latest_execution_payload_header  | diff  | latest_execution_payload_header
    // -                                | new   | next_withdrawal_index
    // -                                | new   | next_withdrawal_validator_index
    // -                                | new   | historical_summaries

    var bellatrix_state = cached_state.state;
    if (bellatrix_state.forkSeq() != .bellatrix) {
        return error.StateIsNotBellatrix;
    }

    const state = try bellatrix_state.upgradeUnsafe();
    state.forkPtr().* = .{
        .previous_version = bellatrix_state.fork().getValue("current_version"),
        .current_version = cached_state.config.chain.CAPELLA_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    var capella_latest_execution_payload_header = ct.capella.ExecutionPayloadHeader.default_value;
    const bellatrix_latest_execution_payload_header = try bellatrix_state.latestExecutionPayloadHeader(allocator);
    defer bellatrix_latest_execution_payload_header.deinit(allocator);
    if (bellatrix_latest_execution_payload_header != .bellatrix) {
        return error.UnexpectedLatestExecutionPayloadHeaderType;
    }

    toExecutionPayloadHeader(
        allocator,
        ct.capella.ExecutionPayloadHeader.Type,
        bellatrix_latest_execution_payload_header.bellatrix,
        &capella_latest_execution_payload_header,
    );
    // new in capella
    capella_latest_execution_payload_header.withdrawals_root = [_]u8{0} ** 32;

    state.setLatestExecutionPayloadHeader(allocator, .{
        .capella = &capella_latest_execution_payload_header,
    });
}
