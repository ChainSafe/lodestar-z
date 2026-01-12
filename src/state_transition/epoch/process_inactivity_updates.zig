const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;

const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const isInInactivityLeak = @import("../utils/finality.zig").isInInactivityLeak;
const attester_status_utils = @import("../utils/attester_status.zig");
const hasMarkers = attester_status_utils.hasMarkers;

pub fn processInactivityUpdates(cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    if (cached_state.getEpochCache().epoch == GENESIS_EPOCH) {
        return;
    }

    const state = cached_state.state;
    const config = cached_state.config.chain;
    const INACTIVITY_SCORE_BIAS = config.INACTIVITY_SCORE_BIAS;
    const INACTIVITY_SCORE_RECOVERY_RATE = config.INACTIVITY_SCORE_RECOVERY_RATE;
    const flags = cache.flags;
    const is_in_activity_leak = try isInInactivityLeak(cached_state);

    // this avoids importing FLAG_ELIGIBLE_ATTESTER inside the for loop, check the compiled code
    const FLAG_PREV_TARGET_ATTESTER_UNSLASHED = attester_status_utils.FLAG_PREV_TARGET_ATTESTER_UNSLASHED;
    const FLAG_ELIGIBLE_ATTESTER = attester_status_utils.FLAG_ELIGIBLE_ATTESTER;

    // TODO for TreeView, we may want to convert to value and back
    var inactivity_scores = try state.inactivityScores();
    for (0..flags.len) |i| {
        const flag = flags[i];
        if (hasMarkers(flag, FLAG_ELIGIBLE_ATTESTER)) {
            var inactivity_score = try inactivity_scores.get(i);

            const prev_inactivity_score = inactivity_score;
            if (hasMarkers(flag, FLAG_PREV_TARGET_ATTESTER_UNSLASHED)) {
                inactivity_score -= @min(1, inactivity_score);
            } else {
                inactivity_score += INACTIVITY_SCORE_BIAS;
            }
            if (!is_in_activity_leak) {
                inactivity_score -= @min(INACTIVITY_SCORE_RECOVERY_RATE, inactivity_score);
            }
            if (inactivity_score != prev_inactivity_score) {
                try inactivity_scores.set(i, inactivity_score);
            }
        }
    }
}

test "processInactivityUpdates - sanity" {
    try @import("../test_utils/test_runner.zig").TestRunner(processInactivityUpdates, .{
        .alloc = false,
        .err_return = true,
        .void_return = true,
    }).testProcessEpochFn();
    defer @import("../state_transition.zig").deinitStateTransition();
}
