const std = @import("std");
const preset = @import("preset").preset;
const MIN_EPOCHS_TO_INACTIVITY_PENALTY = preset.MIN_EPOCHS_TO_INACTIVITY_PENALTY;
const computePreviousEpoch = @import("./epoch.zig").computePreviousEpoch;

pub fn getFinalityDelay(current_epoch: u64, finalized_epoch: u64) u64 {
    const previous_epoch = computePreviousEpoch(current_epoch);
    std.debug.assert(previous_epoch >= finalized_epoch);

    // previous_epoch = epoch - 1
    return previous_epoch - finalized_epoch;
}

/// If the chain has not been finalized for >4 epochs, the chain enters an "inactivity leak" mode,
/// where inactive validators get progressively penalized more and more, to reduce their influence
/// until blocks get finalized again. See here (https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md#inactivity-quotient) for what the inactivity leak is, what it's for and how
/// it works.
pub fn isInInactivityLeak(current_epoch: u64, finalized_epoch: u64) bool {
    return getFinalityDelay(current_epoch, finalized_epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY;
}
