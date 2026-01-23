const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const isInInactivityLeak = @import("../utils/finality.zig").isInInactivityLeak;
const attester_status_utils = @import("../utils/attester_status.zig");
const hasMarkers = attester_status_utils.hasMarkers;
const Node = @import("persistent_merkle_tree").Node;

pub fn processInactivityUpdates(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    cache: *const EpochTransitionCache,
) !void {
    if (epoch_cache.epoch == GENESIS_EPOCH) {
        return;
    }

    const INACTIVITY_SCORE_BIAS = config.chain.INACTIVITY_SCORE_BIAS;
    const INACTIVITY_SCORE_RECOVERY_RATE = config.chain.INACTIVITY_SCORE_RECOVERY_RATE;
    const flags = cache.flags;
    const is_in_activity_leak = isInInactivityLeak(epoch_cache.epoch, try state.finalizedEpoch());

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

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processInactivityUpdates - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processInactivityUpdates(
        .electra,
        test_state.cached_state.config,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
