const std = @import("std");
const testing = std.testing;
const state_transition = @import("./state_transition.zig");
const process_justification_and_finalization = @import("./epoch/process_justification_and_finalization.zig");
const process_inactivity_updates = @import("./epoch/process_inactivity_updates.zig");
const process_registry_updates = @import("./epoch/process_registry_updates.zig");
const process_slashings = @import("./epoch/process_slashings.zig");
const process_rewards_and_penalties = @import("./epoch/process_rewards_and_penalties.zig");
const process_eth1_data_reset = @import("./epoch/process_eth1_data_reset.zig");
const process_pending_deposits = @import("./epoch/process_pending_deposits.zig");
const process_pending_consolidations = @import("./epoch/process_pending_consolidations.zig");
const process_effective_balance_updates = @import("./epoch/process_effective_balance_updates.zig");
const process_slashings_reset = @import("./epoch/process_slashings_reset.zig");
const process_randao_mixes_reset = @import("./epoch/process_randao_mixes_reset.zig");
const process_historical_summaries_update = @import("./epoch/process_historical_summaries_update.zig");
const process_participation_flag_updates = @import("./epoch/process_participation_flag_updates.zig");
const process_sync_committee_updates = @import("./epoch/process_sync_committee_updates.zig");
const process_proposer_lookahead = @import("./epoch/process_proposer_lookahead.zig");
const process_epoch = @import("./epoch/process_epoch.zig");

test {
    testing.refAllDecls(process_justification_and_finalization);
    testing.refAllDecls(process_rewards_and_penalties);
    testing.refAllDecls(process_inactivity_updates);
    testing.refAllDecls(process_slashings);
    testing.refAllDecls(process_registry_updates);
    testing.refAllDecls(process_eth1_data_reset);
    testing.refAllDecls(process_pending_deposits);
    testing.refAllDecls(process_pending_consolidations);
    testing.refAllDecls(process_effective_balance_updates);
    testing.refAllDecls(process_slashings_reset);
    testing.refAllDecls(process_randao_mixes_reset);
    testing.refAllDecls(process_historical_summaries_update);
    testing.refAllDecls(process_participation_flag_updates);
    testing.refAllDecls(process_sync_committee_updates);
    testing.refAllDecls(process_proposer_lookahead);
    testing.refAllDecls(process_epoch);
    testing.refAllDecls(state_transition);

    testing.refAllDecls(@import("./process_block_header.zig"));
    testing.refAllDecls(@import("./process_withdrawals.zig"));
    testing.refAllDecls(@import("./process_execution_payload.zig"));
    testing.refAllDecls(@import("./process_randao.zig"));
    testing.refAllDecls(@import("./process_eth1_data.zig"));
    testing.refAllDecls(@import("./process_operations.zig"));
    testing.refAllDecls(@import("./process_sync_aggregate.zig"));
    testing.refAllDecls(@import("./process_blob_kzg_commitments.zig"));
}
