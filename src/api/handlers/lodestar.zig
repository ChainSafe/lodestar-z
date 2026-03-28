//! Lodestar-z custom API handlers.
//!
//! Non-standard endpoints under `/eth/v1/lodestar/*` for lodestar-z-specific
//! features. These are not part of the Ethereum Beacon API spec.

const std = @import("std");
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
pub fn getValidatorMonitor(ctx: *ApiContext) !HandlerResult([]const u8) {
    const cb = ctx.validator_monitor orelse return error.ValidatorMonitorNotConfigured;
    const json = try cb.getMonitorStatusFn(cb.ptr, ctx.allocator);
    return .{ .data = json };
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
