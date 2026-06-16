const std = @import("std");

const preset = @import("preset").preset;
const types = @import("consensus_types");

const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("cache/epoch_cache.zig").EpochCache;

const validator = @import("./utils/validator.zig");

const Epoch = types.primitive.Epoch.Type;

/// 10% safety decay.
const SAFETY_DECAY: u64 = 10;

/// Gwei per ETH (10^9).
const ETH_TO_GWEI: u64 = 1_000_000_000;

/// Returns the epoch of the latest weak subjectivity checkpoint for the given state.
/// Default safety decay is 10% (0.1).
pub fn getLatestWeakSubjectivityCheckpointEpoch(epoch_cache: *const EpochCache) Epoch {
    return epoch_cache.epoch -| computeWeakSubjectivityPeriodCachedState(epoch_cache);
}

/// Returns the weak subjectivity period for the current state, using cached
/// values from `EpochCache`. Pre-Electra and Electra+ use different formulas.
pub fn computeWeakSubjectivityPeriodCachedState(epoch_cache: *const EpochCache) u64 {
    const config = epoch_cache.config;
    const fork = config.forkSeq(epoch_cache.epoch * preset.SLOTS_PER_EPOCH);
    const active_validator_count = epoch_cache.current_shuffling.get().active_indices.len;

    if (fork.gte(.electra)) {
        return computeWeakSubjectivityPeriodFromConstituentsElectra(
            epoch_cache.total_active_balance_increments,
            validator.getBalanceChurnLimitFromCache(epoch_cache),
            config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
        );
    }

    return computeWeakSubjectivityPeriodFromConstituentsPhase0(
        active_validator_count,
        epoch_cache.total_active_balance_increments,
        validator.getChurnLimit(config, active_validator_count),
        config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
    );
}

/// Pre-Electra WS period.
///
/// Math operates on integers; intermediates fit in u128 for mainnet to avoid overflow on
/// `N * (t * (200 + 12 * D) - T * (200 + 3 * D))`.
pub fn computeWeakSubjectivityPeriodFromConstituentsPhase0(
    active_validator_count: usize,
    total_balance_by_increment: u64,
    churn_limit: usize,
    min_withdrawability_delay: u64,
) u64 {
    std.debug.assert(active_validator_count > 0);
    std.debug.assert(churn_limit > 0);

    const N: u128 = @intCast(active_validator_count);
    // NOTE: `total_balance_by_increment` is total balance measured in `EFFECTIVE_BALANCE_INCREMENT` units.
    // The formula needs t = (avg effective balance per validator) in ETH.
    // That equals total_balance_by_increment / N only because
    // EFFECTIVE_BALANCE_INCREMENT == ETH_TO_GWEI (both 1e9 Gwei) in the spec.
    // If they ever diverge, this needs scaling.
    comptime std.debug.assert(preset.EFFECTIVE_BALANCE_INCREMENT == ETH_TO_GWEI);
    const t: u128 = @divFloor(@as(u128, total_balance_by_increment), N);
    const T: u128 = preset.MAX_EFFECTIVE_BALANCE / ETH_TO_GWEI;
    const delta: u128 = @intCast(churn_limit);
    const Delta: u128 = @as(u128, preset.MAX_DEPOSITS) * preset.SLOTS_PER_EPOCH;
    const D: u128 = SAFETY_DECAY;

    var ws_period: u64 = min_withdrawability_delay;

    const lhs = T * (200 + 3 * D);
    const rhs = t * (200 + 12 * D);
    if (lhs < rhs) {
        const epochs_for_validator_set_churn: u64 = @intCast(@divFloor(
            N * (rhs - lhs),
            600 * delta * (2 * t + T),
        ));
        const epochs_for_balance_top_ups: u64 = @intCast(@divFloor(
            N * (200 + 3 * D),
            600 * Delta,
        ));
        ws_period += @max(epochs_for_validator_set_churn, epochs_for_balance_top_ups);
    } else {
        // Realistically, division by zero due to t < T will almost never happen.
        //
        // Napkin math:
        // if (big if) T = 32, t ∈ [0, 32]
        // if T - t = 0, then lhs = 32 * 230 = 7360 < rhs = 32 * 320 = 10240,
        // so we will never enter this branch.
        //
        // Still, let's assert t < T as a sanity check.
        std.debug.assert(t < T);
        ws_period += @intCast(@divFloor(
            3 * N * D * t,
            200 * Delta * (T - t),
        ));
    }

    return ws_period;
}

/// Electra+ WS period.
pub fn computeWeakSubjectivityPeriodFromConstituentsElectra(
    total_balance_by_increment: u64,
    /// Not the same as `churn_limit` above — measured in Gwei, computed via `getBalanceChurnLimitFromCache`.
    balance_churn_limit: u64,
    min_withdrawability_delay: u64,
) u64 {
    std.debug.assert(balance_churn_limit > 0);

    const t: u128 = total_balance_by_increment;
    const delta: u128 = balance_churn_limit;
    const epochs_for_validator_set_churn: u64 = @intCast(@divFloor(
        SAFETY_DECAY * t * preset.EFFECTIVE_BALANCE_INCREMENT,
        2 * delta * 100,
    ));

    return min_withdrawability_delay + epochs_for_validator_set_churn;
}

test "computeWeakSubjectivityPeriodFromConstituentsPhase0 - mainnet table" {
    // Ported from packages/state-transition/test/unit/util/weakSubjectivity.test.ts
    const config = &@import("config").mainnet.config;
    const min_delay = config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

    const Case = struct { avg_balance: u64, val_count: usize, ws_period: u64 };
    const cases = [_]Case{
        .{ .avg_balance = 28, .val_count = 32768, .ws_period = 504 },
        .{ .avg_balance = 28, .val_count = 65536, .ws_period = 752 },
        .{ .avg_balance = 28, .val_count = 131072, .ws_period = 1248 },
        .{ .avg_balance = 28, .val_count = 262144, .ws_period = 2241 },
        .{ .avg_balance = 28, .val_count = 524288, .ws_period = 2241 },
        .{ .avg_balance = 28, .val_count = 1048576, .ws_period = 2241 },
        .{ .avg_balance = 32, .val_count = 32768, .ws_period = 665 },
        .{ .avg_balance = 32, .val_count = 65536, .ws_period = 1075 },
        .{ .avg_balance = 32, .val_count = 131072, .ws_period = 1894 },
        .{ .avg_balance = 32, .val_count = 262144, .ws_period = 3532 },
        .{ .avg_balance = 32, .val_count = 524288, .ws_period = 3532 },
        .{ .avg_balance = 32, .val_count = 1048576, .ws_period = 3532 },
    };

    for (cases) |c| {
        const total_balance_by_increment: u64 = c.avg_balance * @as(u64, @intCast(c.val_count));
        const churn = validator.getChurnLimit(config, c.val_count);
        const got = computeWeakSubjectivityPeriodFromConstituentsPhase0(
            c.val_count,
            total_balance_by_increment,
            churn,
            min_delay,
        );
        try std.testing.expectEqual(c.ws_period, got);
    }
}

test "computeWeakSubjectivityPeriodFromConstituentsElectra - mainnet table" {
    // Ported from packages/state-transition/test/unit/util/weakSubjectivity.test.ts
    // Values from https://github.com/ethereum/consensus-specs/blob/8ebb5e80862641287d7e8db2bbf69fa31612640b/specs/electra/weak-subjectivity.md#weak-subjectivity-period
    const config = &@import("config").mainnet.config;
    const min_delay = config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

    const Case = struct { total_balance_increment: u64, ws_period: u64 };
    const cases = [_]Case{
        .{ .total_balance_increment = 1_048_576, .ws_period = 665 },
        .{ .total_balance_increment = 2_097_152, .ws_period = 1075 },
        .{ .total_balance_increment = 4_194_304, .ws_period = 1894 },
        .{ .total_balance_increment = 8_388_608, .ws_period = 3532 },
        .{ .total_balance_increment = 16_777_216, .ws_period = 3532 },
        .{ .total_balance_increment = 33_554_432, .ws_period = 3532 },
    };

    for (cases) |c| {
        const balance_churn = validator.getBalanceChurnLimit(
            c.total_balance_increment,
            config.chain.CHURN_LIMIT_QUOTIENT,
            config.chain.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
        );
        const got = computeWeakSubjectivityPeriodFromConstituentsElectra(
            c.total_balance_increment,
            balance_churn,
            min_delay,
        );
        try std.testing.expectEqual(c.ws_period, got);
    }
}
