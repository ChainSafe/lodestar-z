const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
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
const validator_utils = @import("../utils/validator.zig");
const getConsolidationChurnLimit = validator_utils.getConsolidationChurnLimit;
const getPendingBalanceToWithdraw = validator_utils.getPendingBalanceToWithdraw;
const isActiveValidatorView = validator_utils.isActiveValidatorView;

// TODO Electra: Clean up necessary as there is a lot of overlap with isValidSwitchToCompoundRequest
pub fn processConsolidationRequest(
    cached_state: *CachedBeaconState,
    consolidation: *const ConsolidationRequest,
) !void {
    var state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;

    const source_pubkey = consolidation.source_pubkey;
    const target_pubkey = consolidation.target_pubkey;
    const source_address = consolidation.source_address;

    if (!(try isPubkeyKnown(cached_state, source_pubkey))) return;
    if (!(try isPubkeyKnown(cached_state, target_pubkey))) return;

    const source_index = epoch_cache.pubkey_to_index.get(source_pubkey) orelse return;
    const target_index = epoch_cache.pubkey_to_index.get(target_pubkey) orelse return;

    if (try isValidSwitchToCompoundRequest(cached_state, consolidation)) {
        try switchToCompoundingValidator(cached_state, source_index);
        // Early return since we have already switched validator to compounding
        return;
    }

    // Verify that source != target, so a consolidation cannot be used as an exit.
    if (source_index == target_index) {
        return;
    }

    // If the pending consolidations queue is full, consolidation requests are ignored
    var pending_consolidations = try state.pendingConsolidations();
    if (try pending_consolidations.length() >= preset.PENDING_CONSOLIDATIONS_LIMIT) {
        return;
    }

    // If there is too little available consolidation churn limit, consolidation requests are ignored
    if (getConsolidationChurnLimit(epoch_cache) <= preset.MIN_ACTIVATION_BALANCE) {
        return;
    }

    var validators = try state.validators();
    var source_validator = try validators.get(@intCast(source_index));
    var target_validator = try validators.get(@intCast(target_index));
    const source_withdrawal_credentials = try source_validator.getRoot("withdrawal_credentials");
    const target_withdrawal_credentials = try target_validator.getRoot("withdrawal_credentials");
    const source_withdrawal_address = source_withdrawal_credentials[12..];
    const current_epoch = epoch_cache.epoch;

    // Verify source withdrawal credentials
    const has_correct_credential = hasExecutionWithdrawalCredential(source_withdrawal_credentials);
    const is_correct_source_address = std.mem.eql(u8, source_withdrawal_address, &source_address);
    if (!(has_correct_credential and is_correct_source_address)) {
        return;
    }

    // Verify that target has compounding withdrawal credentials
    if (!hasCompoundingWithdrawalCredential(target_withdrawal_credentials)) {
        return;
    }

    // Verify the source and the target are active
    if (!(try isActiveValidatorView(&source_validator, current_epoch)) or !(try isActiveValidatorView(&target_validator, current_epoch))) {
        return;
    }

    // Verify exits for source and target have not been initiated
    const source_exit_epoch = try source_validator.get("exit_epoch");
    const target_exit_epoch = try target_validator.get("exit_epoch");
    if (source_exit_epoch != FAR_FUTURE_EPOCH or target_exit_epoch != FAR_FUTURE_EPOCH) {
        return;
    }

    // Verify the source has been active long enough
    const source_activation_epoch = try source_validator.get("activation_epoch");
    if (current_epoch < source_activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD) {
        return;
    }

    // Verify the source has no pending withdrawals in the queue
    if (try getPendingBalanceToWithdraw(state, source_index) > 0) {
        return;
    }

    // Initiate source validator exit and append pending consolidation
    // TODO Electra: See if we can get rid of big int
    const effective_balance = try source_validator.get("effective_balance");
    const exit_epoch = try computeConsolidationEpochAndUpdateChurn(cached_state, effective_balance);
    try source_validator.set("exit_epoch", exit_epoch);
    try source_validator.set("withdrawable_epoch", exit_epoch + config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY);

    const pending_consolidation = PendingConsolidation{
        .source_index = source_index,
        .target_index = target_index,
    };
    try pending_consolidations.pushValue(&pending_consolidation);
}

fn isValidSwitchToCompoundRequest(cached_state: *const CachedBeaconState, consolidation: *const ConsolidationRequest) !bool {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();

    // this check is mainly to make the compiler happy, pubkey is checked by the consumer already
    const source_index = epoch_cache.pubkey_to_index.get(consolidation.source_pubkey) orelse return false;
    const target_index = epoch_cache.pubkey_to_index.get(consolidation.target_pubkey) orelse return false;

    // Switch to compounding requires source and target be equal
    if (source_index != target_index) {
        return false;
    }

    var validators = try state.validators();
    var source_validator = try validators.get(@intCast(source_index));
    const source_withdrawal_credentials = try source_validator.getRoot("withdrawal_credentials");
    const source_withdrawal_address = source_withdrawal_credentials[12..];

    // Verify request has been authorized
    if (std.mem.eql(u8, source_withdrawal_address, &consolidation.source_address) == false) {
        return false;
    }

    // Verify source withdrawal credentials
    if (!hasEth1WithdrawalCredential(source_withdrawal_credentials)) {
        return false;
    }

    // Verify the source is active
    if (!try isActiveValidatorView(&source_validator, epoch_cache.epoch)) {
        return false;
    }

    // Verify exit for source has not been initiated
    if (try source_validator.get("exit_epoch") != FAR_FUTURE_EPOCH) {
        return false;
    }

    return true;
}
