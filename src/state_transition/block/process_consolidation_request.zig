const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const FAR_FUTURE_EPOCH = @import("constants").FAR_FUTURE_EPOCH;
const ConsolidationRequest = types.electra.ConsolidationRequest.Type;
const PendingConsolidation = types.electra.PendingConsolidation.Type;
const hasEth1WithdrawalCredential = @import("../utils/capella.zig").hasEth1WithdrawalCredential;
const electra_utils = @import("../utils/electra.zig");
const hasCompoundingWithdrawalCredential = electra_utils.hasCompoundingWithdrawalCredential;
const hasExecutionWithdrawalCredential = electra_utils.hasExecutionWithdrawalCredential;
const isPubkeyKnown = electra_utils.isPubkeyKnown;
const switchToCompoundingValidator = electra_utils.switchToCompoundingValidator;
const computeConsolidationEpochAndUpdateChurn = @import("../utils/epoch.zig").computeConsolidationEpochAndUpdateChurn;
const validator_utils = @import("../validator.zig");
const getConsolidationChurnLimit = validator_utils.getConsolidationChurnLimit;
const getPendingBalanceToWithdraw = validator_utils.getPendingBalanceToWithdraw;
const isActiveValidator = validator_utils.isActiveValidator;

// TODO Electra: Clean up necessary as there is a lot of overlap with isValidSwitchToCompoundRequest
pub fn processConsolidationRequest(
    allocator: std.mem.Allocator,
    cached_state: *CachedBeaconStateAllForks,
    consolidation: *const ConsolidationRequest,
) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;

    const source_pubkey = consolidation.source_pubkey;
    const target_pubkey = consolidation.target_pubkey;
    const source_address = consolidation.source_address;

    if (!isPubkeyKnown(cached_state, source_pubkey)) return;
    if (!isPubkeyKnown(cached_state, target_pubkey)) return;

    const source_index = epoch_cache.pubkey_to_index.get(&source_pubkey) orelse return;
    const target_index = epoch_cache.pubkey_to_index.get(&target_pubkey) orelse return;

    if (isValidSwitchToCompoundRequest(cached_state, consolidation)) {
        try switchToCompoundingValidator(allocator, cached_state, source_index);
        // Early return since we have already switched validator to compounding
        return;
    }

    // Verify that source != target, so a consolidation cannot be used as an exit.
    if (source_index == target_index) {
        return;
    }

    // If the pending consolidations queue is full, consolidation requests are ignored
    if (state.pendingConsolidations().items.len >= preset.PENDING_CONSOLIDATIONS_LIMIT) {
        return;
    }

    // If there is too little available consolidation churn limit, consolidation requests are ignored
    if (getConsolidationChurnLimit(epoch_cache) <= preset.MIN_ACTIVATION_BALANCE) {
        return;
    }

    const source_validator = &state.validators().items[source_index];
    const target_validator = &state.validators().items[target_index];
    const source_withdrawal_address = source_validator.withdrawal_credentials[12..];
    const current_epoch = epoch_cache.epoch;

    // Verify source withdrawal credentials
    const has_correct_credential = hasExecutionWithdrawalCredential(source_validator.withdrawal_credentials);
    const is_correct_source_address = std.mem.eql(u8, source_withdrawal_address, &source_address);
    if (!(has_correct_credential and is_correct_source_address)) {
        return;
    }

    // Verify that target has compounding withdrawal credentials
    if (!hasCompoundingWithdrawalCredential(target_validator.withdrawal_credentials)) {
        return;
    }

    // Verify the source and the target are active
    if (!isActiveValidator(source_validator, current_epoch) or !isActiveValidator(target_validator, current_epoch)) {
        return;
    }

    // Verify exits for source and target have not been initiated
    if (source_validator.exit_epoch != FAR_FUTURE_EPOCH or target_validator.exit_epoch != FAR_FUTURE_EPOCH) {
        return;
    }

    // Verify the source has been active long enough
    if (current_epoch < source_validator.activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD) {
        return;
    }

    // Verify the source has no pending withdrawals in the queue
    if (getPendingBalanceToWithdraw(cached_state.state, source_index) > 0) {
        return;
    }

    // Initiate source validator exit and append pending consolidation
    // TODO Electra: See if we can get rid of big int
    const exit_epoch = computeConsolidationEpochAndUpdateChurn(cached_state, source_validator.effective_balance);
    source_validator.exit_epoch = exit_epoch;
    source_validator.withdrawable_epoch = exit_epoch + config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

    const pending_consolidation = PendingConsolidation{
        .source_index = source_index,
        .target_index = target_index,
    };
    try state.pendingConsolidations().append(allocator, pending_consolidation);
}

fn isValidSwitchToCompoundRequest(cached_state: *const CachedBeaconStateAllForks, consolidation: *const ConsolidationRequest) bool {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();

    // this check is mainly to make the compiler happy, pubkey is checked by the consumer already
    const source_index = epoch_cache.pubkey_to_index.get(&consolidation.source_pubkey) orelse return false;
    const target_index = epoch_cache.pubkey_to_index.get(&consolidation.target_pubkey) orelse return false;

    // Switch to compounding requires source and target be equal
    if (source_index != target_index) {
        return false;
    }

    const source_validator = state.validators().items[source_index];
    const source_withdrawal_address = source_validator.withdrawal_credentials[12..];

    // Verify request has been authorized
    if (std.mem.eql(u8, source_withdrawal_address, &consolidation.source_address) == false) {
        return false;
    }

    // Verify source withdrawal credentials
    if (!hasEth1WithdrawalCredential(source_validator.withdrawal_credentials)) {
        return false;
    }

    // Verify the source is active
    if (!isActiveValidator(&source_validator, epoch_cache.epoch)) {
        return false;
    }

    // Verify exit for source has not been initiated
    if (source_validator.exit_epoch != FAR_FUTURE_EPOCH) {
        return false;
    }

    return true;
}
