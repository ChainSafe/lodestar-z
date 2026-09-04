//! Tests for `weak_subjectivity.zig`.

const std = @import("std");
const validator = @import("./utils/validator.zig");
const computeWeakSubjectivityPeriodFromConstituentsElectra = @import("weak_subjectivity.zig").computeWeakSubjectivityPeriodFromConstituentsElectra;
const computeWeakSubjectivityPeriodFromConstituentsPhase0 = @import("weak_subjectivity.zig").computeWeakSubjectivityPeriodFromConstituentsPhase0;

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
