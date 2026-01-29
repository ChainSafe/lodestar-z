const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const c = @import("constants");
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const getPendingBalanceToWithdraw = @import("../utils/validator.zig").getPendingBalanceToWithdraw;
const isActiveValidatorView = @import("../utils/validator.zig").isActiveValidatorView;
const verifyVoluntaryExitSignature = @import("../signature_sets/voluntary_exits.zig").verifyVoluntaryExitSignature;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;

const FAR_FUTURE_EPOCH = c.FAR_FUTURE_EPOCH;

pub const VoluntaryExitValidity = enum {
    valid,
    inactive,
    already_exited,
    early_epoch,
    short_time_active,
    pending_withdrawals,
    invalid_signature,
};

pub fn processVoluntaryExit(cached_state: *CachedBeaconState, signed_voluntary_exit: *const SignedVoluntaryExit, verify_signature: bool) !void {
    const validity = try getVoluntaryExitValidity(cached_state, signed_voluntary_exit, verify_signature);
    if (validity != .valid) {
        return error.InvalidVoluntaryExit;
    }

    var validators = try cached_state.state.validators();
    var validator = try validators.get(@intCast(signed_voluntary_exit.message.validator_index));
    try initiateValidatorExit(cached_state, &validator);
}

pub fn getVoluntaryExitValidity(cached_state: *CachedBeaconState, signed_voluntary_exit: *const SignedVoluntaryExit, verify_signature: bool) !VoluntaryExitValidity {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = cached_state.config.chain;
    const voluntary_exit = signed_voluntary_exit.message;

    var validators = try state.validators();
    const validators_len = try validators.length();
    if (voluntary_exit.validator_index >= validators_len) {
        return .inactive;
    }

    var validator = try validators.get(@intCast(voluntary_exit.validator_index));
    const current_epoch = epoch_cache.epoch;

    // verify the validator is active
    if (!try isActiveValidatorView(&validator, current_epoch)) {
        return .inactive;
    }

    // verify exit has not been initiated
    const exit_epoch = try validator.get("exit_epoch");
    if (exit_epoch != FAR_FUTURE_EPOCH) {
        return .already_exited;
    }

    // exits must specify an epoch when they become valid; they are not valid before then
    if (current_epoch < voluntary_exit.epoch) {
        return .early_epoch;
    }

    // verify the validator had been active long enough
    const activation_epoch = try validator.get("activation_epoch");
    if (current_epoch < activation_epoch + config.SHARD_COMMITTEE_PERIOD) {
        return .short_time_active;
    }

    // only exit validator if it has no pending withdrawals in the queue (Electra+)
    if (state.forkSeq().gte(.electra)) {
        if (try getPendingBalanceToWithdraw(state, voluntary_exit.validator_index) != 0) {
            return .pending_withdrawals;
        }
    }

    // verify signature
    if (verify_signature) {
        if (!try verifyVoluntaryExitSignature(cached_state, signed_voluntary_exit)) {
            return .invalid_signature;
        }
    }

    return .valid;
}

pub fn isValidVoluntaryExit(cached_state: *CachedBeaconState, signed_voluntary_exit: *const SignedVoluntaryExit, verify_signature: bool) !bool {
    return try getVoluntaryExitValidity(cached_state, signed_voluntary_exit, verify_signature) == .valid;
}

// TODO: unit test
