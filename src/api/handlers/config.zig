//! Config API handlers.
//!
//! Pure functions implementing the `/eth/v1/config/*` Beacon API endpoints.
//! These return chain configuration data (spec constants, fork schedule).

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const config_mod = @import("config");
const ChainConfig = config_mod.ChainConfig;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;

/// GET /eth/v1/config/spec
///
/// Returns the live chain config backing this node. The HTTP layer is
/// responsible for rendering it in Beacon API spec JSON form.
pub const SpecData = *const ChainConfig;

pub fn getSpec(ctx: *ApiContext) HandlerResult(SpecData) {
    return .{ .data = &ctx.beacon_config.chain };
}

/// GET /eth/v1/config/fork_schedule
///
/// Returns the fork schedule — an ordered list of past and future forks.
/// The returned slice is heap-allocated and must be freed by the caller.
pub fn getForkSchedule(ctx: *ApiContext) HandlerResult([]const types.ForkScheduleEntry) {
    const forks = ctx.beacon_config.forks_ascending_epoch_order;
    var list: std.ArrayListUnmanaged(types.ForkScheduleEntry) = .empty;
    for (forks) |fork| {
        if (fork.epoch < std.math.maxInt(u64)) {
            list.append(ctx.allocator, .{
                .previous_version = fork.prev_version,
                .current_version = fork.version,
                .epoch = fork.epoch,
            }) catch return .{ .data = &[_]types.ForkScheduleEntry{} };
        }
    }
    return .{
        .data = list.toOwnedSlice(ctx.allocator) catch &[_]types.ForkScheduleEntry{},
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getSpec returns live chain config" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getSpec(&tc.ctx);
    try std.testing.expectEqualStrings("mainnet", resp.data.CONFIG_NAME);
    try std.testing.expectEqual(@as(u64, 14), resp.data.SECONDS_PER_ETH1_BLOCK);
}

test "getForkSchedule returns non-empty schedule" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getForkSchedule(&tc.ctx);
    defer std.testing.allocator.free(resp.data);
    try std.testing.expect(resp.data.len > 0);
}

test "getForkSchedule entries are ordered by epoch" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getForkSchedule(&tc.ctx);
    defer std.testing.allocator.free(resp.data);
    if (resp.data.len > 1) {
        for (0..resp.data.len - 1) |i| {
            try std.testing.expect(resp.data[i].epoch <= resp.data[i + 1].epoch);
        }
    }
}
