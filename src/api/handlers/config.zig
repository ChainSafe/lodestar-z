//! Config API handlers.
//!
//! Pure functions implementing the `/eth/v1/config/*` Beacon API endpoints.
//! These return chain configuration data (spec constants, fork schedule).

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;

/// GET /eth/v1/config/spec
///
/// Returns a map of all chain configuration values.
///
/// The Beacon API returns this as a flat JSON object with string keys/values.
/// Since the full spec has ~100 fields, we return the ChainConfig struct
/// which the JSON encoder can serialize. The HTTP layer can flatten this
/// into the string-keyed format the spec requires.
pub fn getSpec(ctx: *ApiContext) HandlerResult(SpecData) {
    return .{
        .data = .{
            .config_name = ctx.beacon_config.chain.CONFIG_NAME,
            .genesis_fork_version = ctx.beacon_config.chain.GENESIS_FORK_VERSION,
            .altair_fork_version = ctx.beacon_config.chain.ALTAIR_FORK_VERSION,
            .altair_fork_epoch = ctx.beacon_config.chain.ALTAIR_FORK_EPOCH,
            .bellatrix_fork_version = ctx.beacon_config.chain.BELLATRIX_FORK_VERSION,
            .bellatrix_fork_epoch = ctx.beacon_config.chain.BELLATRIX_FORK_EPOCH,
            .capella_fork_version = ctx.beacon_config.chain.CAPELLA_FORK_VERSION,
            .capella_fork_epoch = ctx.beacon_config.chain.CAPELLA_FORK_EPOCH,
            .deneb_fork_version = ctx.beacon_config.chain.DENEB_FORK_VERSION,
            .deneb_fork_epoch = ctx.beacon_config.chain.DENEB_FORK_EPOCH,
            .electra_fork_version = ctx.beacon_config.chain.ELECTRA_FORK_VERSION,
            .electra_fork_epoch = ctx.beacon_config.chain.ELECTRA_FORK_EPOCH,
            .seconds_per_slot = ctx.beacon_config.chain.SECONDS_PER_SLOT,
            .min_genesis_time = ctx.beacon_config.chain.MIN_GENESIS_TIME,
        },
    };
}

/// Subset of chain config values exposed via the /config/spec endpoint.
/// Full config serialization will be added when the JSON flattening layer exists.
pub const SpecData = struct {
    config_name: []const u8,
    genesis_fork_version: [4]u8,
    altair_fork_version: [4]u8,
    altair_fork_epoch: u64,
    bellatrix_fork_version: [4]u8,
    bellatrix_fork_epoch: u64,
    capella_fork_version: [4]u8,
    capella_fork_epoch: u64,
    deneb_fork_version: [4]u8,
    deneb_fork_epoch: u64,
    electra_fork_version: [4]u8,
    electra_fork_epoch: u64,
    seconds_per_slot: u64,
    min_genesis_time: u64,
};

/// GET /eth/v1/config/fork_schedule
///
/// Returns the fork schedule — an ordered list of past and future forks.
/// The returned slice is heap-allocated and must be freed by the caller.
pub fn getForkSchedule(ctx: *ApiContext) HandlerResult([]const types.ForkScheduleEntry) {
    // Build entries from the config's ascending fork order.
    // Allocate on ctx.allocator so concurrent requests don't share a mutable buffer.
    const forks = ctx.beacon_config.forks_ascending_epoch_order;
    const schedule = ctx.allocator.alloc(types.ForkScheduleEntry, ForkSeq.count) catch {
        return .{ .data = &[_]types.ForkScheduleEntry{} };
    };
    var count: usize = 0;
    for (forks) |fork| {
        if (fork.epoch < std.math.maxInt(u64)) {
            schedule[count] = .{
                .previous_version = fork.prev_version,
                .current_version = fork.version,
                .epoch = fork.epoch,
            };
            count += 1;
        }
    }
    return .{
        .data = schedule[0..count],
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getSpec returns config name" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getSpec(&tc.ctx);
    try std.testing.expectEqualStrings("mainnet", resp.data.config_name);
}

test "getForkSchedule returns non-empty schedule" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getForkSchedule(&tc.ctx);
    // Mainnet has at least genesis fork (phase0)
    try std.testing.expect(resp.data.len > 0);
}

test "getForkSchedule entries are ordered by epoch" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getForkSchedule(&tc.ctx);
    if (resp.data.len > 1) {
        for (0..resp.data.len - 1) |i| {
            try std.testing.expect(resp.data[i].epoch <= resp.data[i + 1].epoch);
        }
    }
}
