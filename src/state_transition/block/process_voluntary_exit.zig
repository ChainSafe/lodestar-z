const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const types = @import("consensus_types");
const c = @import("constants");
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const getPendingBalanceToWithdraw = @import("../utils/validator.zig").getPendingBalanceToWithdraw;
const isActiveValidatorView = @import("../utils/validator.zig").isActiveValidatorView;
const verifyVoluntaryExitSignature = @import("../signature_sets/voluntary_exits.zig").verifyVoluntaryExitSignature;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;

const FAR_FUTURE_EPOCH = c.FAR_FUTURE_EPOCH;

pub fn processVoluntaryExit(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    signed_voluntary_exit: *const SignedVoluntaryExit,
    verify_signature: bool,
) !void {
    if (!try isValidVoluntaryExit(fork, config, epoch_cache, state, signed_voluntary_exit, verify_signature)) {
        return error.InvalidVoluntaryExit;
    }

    var validators = try state.validators();
    var validator = try validators.get(@intCast(signed_voluntary_exit.message.validator_index));
    try initiateValidatorExit(fork, config, epoch_cache, state, &validator);
}

pub fn isValidVoluntaryExit(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    signed_voluntary_exit: *const SignedVoluntaryExit,
    verify_signature: bool,
) !bool {
    const voluntary_exit = signed_voluntary_exit.message;

    var validators = try state.validators();
    const validators_len = try validators.length();
    if (voluntary_exit.validator_index >= validators_len) {
        return false;
    }

    var validator = try validators.get(@intCast(voluntary_exit.validator_index));
    const current_epoch = epoch_cache.epoch;

    const activation_epoch = try validator.get("activation_epoch");
    const exit_epoch = try validator.get("exit_epoch");
    return (
        // verify the validator is active
        (try isActiveValidatorView(&validator, current_epoch)) and
            // verify exit has not been initiated
            exit_epoch == FAR_FUTURE_EPOCH and
            // exits must specify an epoch when they become valid; they are not valid before then
            current_epoch >= voluntary_exit.epoch and
            // verify the validator had been active long enough
            current_epoch >= activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD and
            (if (state.forkSeq().gte(.electra)) try getPendingBalanceToWithdraw(state, voluntary_exit.validator_index) == 0 else true) and
            // verify signature
            if (verify_signature) try verifyVoluntaryExitSignature(fork, config, epoch_cache, state, signed_voluntary_exit) else true);
}

// TODO: unit test
