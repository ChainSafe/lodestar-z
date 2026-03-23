//! Node API handlers.
//!
//! Pure functions implementing the `/eth/v1/node/*` Beacon API endpoints.
//! These are the simplest handlers — most just read from the ApiContext
//! without needing chain state.

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;

/// GET /eth/v1/node/identity
///
/// Returns the node's network identity: peer ID, ENR, listening addresses.
pub fn getIdentity(ctx: *ApiContext) types.ApiResponse(types.NodeIdentity) {
    return .{
        .data = ctx.node_identity,
    };
}

/// GET /eth/v1/node/version
///
/// Returns the node's version string in the format: `lodestar-z/v{version}/{os}-{arch}`.
pub fn getVersion(_: *ApiContext) types.ApiResponse(types.NodeVersion) {
    return .{
        .data = .{
            .version = "lodestar-z/v0.0.1/zig-linux-x86_64",
        },
    };
}

/// GET /eth/v1/node/syncing
///
/// Returns the current sync status of the node.
pub fn getSyncing(ctx: *ApiContext) types.ApiResponse(types.SyncingStatus) {
    const sync = ctx.sync_status;
    return .{
        .data = .{
            .head_slot = sync.head_slot,
            .sync_distance = sync.sync_distance,
            .is_syncing = sync.is_syncing,
            .is_optimistic = sync.is_optimistic,
            .el_offline = sync.el_offline,
        },
    };
}

/// GET /eth/v1/node/health
///
/// Returns a health status code:
/// - 200: ready (synced)
/// - 206: syncing
/// - 503: not initialized
pub fn getHealth(ctx: *ApiContext) types.HealthStatus {
    if (ctx.sync_status.is_syncing) return .syncing;
    if (ctx.sync_status.head_slot == 0) return .not_initialized;
    return .ready;
}

/// GET /eth/v1/node/peers
///
/// Returns the list of connected peers.
/// Note: Peer tracking is not yet implemented; returns an empty list.
pub fn getPeers(_: *ApiContext) types.ApiResponse([]const types.PeerInfo) {
    return .{
        .data = &[_]types.PeerInfo{},
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getIdentity returns node identity" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getIdentity(&tc.ctx);
    try std.testing.expectEqualStrings("test-peer-id", resp.data.peer_id);
}

test "getVersion returns version string" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getVersion(&tc.ctx);
    try std.testing.expect(std.mem.startsWith(u8, resp.data.version, "lodestar-z/"));
}

test "getSyncing reflects sync status" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = true;
    tc.ctx.sync_status.sync_distance = 100;
    const resp = getSyncing(&tc.ctx);
    try std.testing.expect(resp.data.is_syncing);
    try std.testing.expectEqual(@as(u64, 100), resp.data.sync_distance);
}

test "getHealth returns syncing when syncing" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = true;
    try std.testing.expectEqual(types.HealthStatus.syncing, getHealth(&tc.ctx));
}

test "getHealth returns not_initialized when head_slot is 0" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = false;
    tc.ctx.sync_status.head_slot = 0;
    try std.testing.expectEqual(types.HealthStatus.not_initialized, getHealth(&tc.ctx));
}

test "getHealth returns ready when synced" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = false;
    tc.ctx.sync_status.head_slot = 1000;
    try std.testing.expectEqual(types.HealthStatus.ready, getHealth(&tc.ctx));
}

test "getPeers returns empty list" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPeers(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}
