//! Lodestar-z custom API handlers.
//!
//! Non-standard endpoints under `/eth/v1/lodestar/*` for lodestar-z-specific
//! features. These are not part of the Ethereum Beacon API spec.

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;

/// GET /eth/v1/lodestar/validator_monitor
///
/// Returns JSON with monitored validator summaries including:
/// - Per-validator balance, effectiveness score, attestation stats
/// - Epoch summaries
///
/// Returns error.ValidatorMonitorNotConfigured if the monitor is not enabled.
pub fn getValidatorMonitor(ctx: *ApiContext) !HandlerResult(types.ValidatorMonitorData) {
    const cb = ctx.validator_monitor orelse return error.ValidatorMonitorNotConfigured;
    const data = try cb.getMonitorStatusFn(cb.ptr, ctx.allocator);
    return .{ .data = data };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getValidatorMonitor returns error when not configured" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // No validator_monitor callback configured → should error
    const result = getValidatorMonitor(&tc.ctx);
    try std.testing.expectError(error.ValidatorMonitorNotConfigured, result);
}

test "getValidatorMonitor returns typed data when configured" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getStatus(_: *anyopaque, allocator: std.mem.Allocator) anyerror!types.ValidatorMonitorData {
            const validators = try allocator.alloc(types.ValidatorMonitorValidator, 1);
            validators[0] = .{
                .index = 7,
                .balance_gwei = 32_000_000_000,
                .effective_balance_gwei = 32_000_000_000,
                .balance_delta_gwei = 12,
                .effectiveness_score = 0.875,
                .attestation_included = true,
                .attestation_delay = 1,
                .head_correct = true,
                .source_correct = true,
                .target_correct = true,
                .block_proposed = false,
                .sync_participated = true,
                .cumulative_reward_gwei = 42,
                .total_attestations_included = 9,
                .total_attestations_expected = 10,
                .inclusion_delay_histogram = .{ 1, 2, 3, 4 },
            };
            const epoch_summaries = try allocator.alloc(types.ValidatorMonitorEpochSummary, 1);
            epoch_summaries[0] = .{
                .epoch = 12,
                .validators_monitored = 1,
                .attestation_hit_rate = 0.9,
                .head_accuracy_rate = 0.8,
                .source_accuracy_rate = 0.7,
                .target_accuracy_rate = 0.6,
                .avg_inclusion_delay = 1.5,
                .blocks_proposed = 0,
                .blocks_expected = 1,
                .sync_participation_rate = 0.5,
                .total_balance_delta_gwei = 12,
            };
            return .{ .validators = validators, .epoch_summaries = epoch_summaries };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.validator_monitor = .{
        .ptr = &dummy,
        .getMonitorStatusFn = &MockCb.getStatus,
    };

    const result = try getValidatorMonitor(&tc.ctx);
    defer tc.ctx.allocator.free(result.data.validators);
    defer tc.ctx.allocator.free(result.data.epoch_summaries);

    try std.testing.expectEqual(@as(usize, 1), result.data.validators.len);
    try std.testing.expectEqual(@as(u64, 7), result.data.validators[0].index);
    try std.testing.expectEqual(@as(usize, 1), result.data.epoch_summaries.len);
    try std.testing.expectEqual(@as(u64, 12), result.data.epoch_summaries[0].epoch);
}
