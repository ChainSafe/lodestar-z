const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const preset = @import("preset").preset;
const MIN_EPOCHS_TO_INACTIVITY_PENALTY = preset.MIN_EPOCHS_TO_INACTIVITY_PENALTY;
const computePreviousEpoch = @import("./epoch.zig").computePreviousEpoch;

pub fn getFinalityDelay(cached_state: *const CachedBeaconStateAllForks) u64 {
    const previous_epoch = computePreviousEpoch(cached_state.getEpochCache().epoch);
    std.debug.assert(previous_epoch >= cached_state.state.finalizedCheckpoint().epoch);

    // previous_epoch = epoch - 1
    return previous_epoch - cached_state.state.finalizedCheckpoint().epoch;
}

/// If the chain has not been finalized for >4 epochs, the chain enters an "inactivity leak" mode,
/// where inactive validators get progressively penalized more and more, to reduce their influence
/// until blocks get finalized again. See here (https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md#inactivity-quotient) for what the inactivity leak is, what it's for and how
/// it works.
pub fn isInInactivityLeak(state: *const CachedBeaconStateAllForks) bool {
    return getFinalityDelay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY;
}
