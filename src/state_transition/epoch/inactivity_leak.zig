//! Utility function to calculate if a validator is in "inactivity leak" mode.
const std = @import("std");
const preset = @import("preset").preset;
const MIN_EPOCHS_TO_INACTIVITY_PENALTY = preset.MIN_EPOCHS_TO_INACTIVITY_PENALTY;
const computePreviousEpoch = @import("../utils/epoch.zig").computePreviousEpoch;

fn getFinalityDelay(current_epoch: u64, finalized_epoch: u64) u64 {
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

test "getFinalityDelay" {
    // current_epoch=10, finalized_epoch=5: previous=9, delay=9-5=4
    try std.testing.expectEqual(@as(u64, 4), getFinalityDelay(10, 5));
    // current_epoch=10, finalized_epoch=9: previous=9, delay=0
    try std.testing.expectEqual(@as(u64, 0), getFinalityDelay(10, 9));
    // current_epoch=10, finalized_epoch=0: previous=9, delay=9
    try std.testing.expectEqual(@as(u64, 9), getFinalityDelay(10, 0));
    // edge: current_epoch=1, finalized_epoch=0: previous=0, delay=0
    try std.testing.expectEqual(@as(u64, 0), getFinalityDelay(1, 0));
}

test "isInInactivityLeak" {
    // MIN_EPOCHS_TO_INACTIVITY_PENALTY = 4
    // Not in leak: delay <= 4
    try std.testing.expect(!isInInactivityLeak(10, 9)); // delay=0
    try std.testing.expect(!isInInactivityLeak(10, 5)); // delay=4 (not strictly greater)

    // In leak: delay > 4
    try std.testing.expect(isInInactivityLeak(10, 4)); // delay=5
    try std.testing.expect(isInInactivityLeak(10, 0)); // delay=9
    try std.testing.expect(isInInactivityLeak(100, 0)); // delay=99
}
