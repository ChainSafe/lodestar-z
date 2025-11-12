const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ssz = @import("consensus_types");
const c = @import("constants");
const SignedVoluntaryExit = ssz.phase0.SignedVoluntaryExit.Type;
const isActiveValidator = @import("../utils/validator.zig").isActiveValidator;
const getPendingBalanceToWithdraw = @import("../utils/validator.zig").getPendingBalanceToWithdraw;
const verifyVoluntaryExitSignature = @import("../signature_sets/voluntary_exits.zig").verifyVoluntaryExitSignature;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;

const FAR_FUTURE_EPOCH = c.FAR_FUTURE_EPOCH;

pub fn processVoluntaryExit(cached_state: *CachedBeaconStateAllForks, signed_voluntary_exit: *const SignedVoluntaryExit, verify_signature: bool) !void {
    if (!try isValidVoluntaryExit(cached_state, signed_voluntary_exit, verify_signature)) {
        return error.InvalidVoluntaryExit;
    }
    const validator = &cached_state.state.validators().items[signed_voluntary_exit.message.validator_index];
    try initiateValidatorExit(cached_state, validator);
}

pub fn isValidVoluntaryExit(cached_state: *CachedBeaconStateAllForks, signed_voluntary_exit: *const SignedVoluntaryExit, verify_signature: bool) !bool {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = cached_state.config.chain;
    const voluntary_exit = signed_voluntary_exit.message;

    if (voluntary_exit.validator_index >= state.validators().items.len) {
        return false;
    }

    const validator = state.validators().items[voluntary_exit.validator_index];
    const current_epoch = epoch_cache.epoch;

    return (
        // verify the validator is active
        isActiveValidator(&validator, current_epoch) and
            // verify exit has not been initiated
            validator.exit_epoch == FAR_FUTURE_EPOCH and
            // exits must specify an epoch when they become valid; they are not valid before then
            current_epoch >= voluntary_exit.epoch and
            // verify the validator had been active long enough
            current_epoch >= validator.activation_epoch + config.SHARD_COMMITTEE_PERIOD and
            (if (state.isPostElectra()) getPendingBalanceToWithdraw(cached_state.state, voluntary_exit.validator_index) == 0 else true) and
            // verify signature
            if (verify_signature) try verifyVoluntaryExitSignature(cached_state, signed_voluntary_exit) else true);
}

// TODO: unit test
