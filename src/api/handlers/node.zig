//! Node API handlers.
//!
//! Pure functions implementing the `/eth/v1/node/*` Beacon API endpoints.
//! These are the simplest handlers — most just read from the ApiContext
//! without needing chain state.

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;

/// GET /eth/v1/node/identity
///
/// Returns the node's network identity: peer ID, ENR, listening addresses.
pub fn getIdentity(ctx: *ApiContext) HandlerResult(types.NodeIdentity) {
    return .{
        .data = ctx.node_identity,
    };
}

/// GET /eth/v1/node/version
///
/// Returns the node's version string in the format: `lodestar-z/v{version}/{os}-{arch}`.
pub fn getVersion(_: *ApiContext) HandlerResult(types.NodeVersion) {
    return .{
        .data = .{
            .version = "lodestar-z/v0.0.1/zig-linux-x86_64",
        },
    };
}

/// GET /eth/v1/node/syncing
///
/// Returns the current sync status of the node.
pub fn getSyncing(ctx: *ApiContext) HandlerResult(types.SyncingStatus) {
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
pub fn getHealth(ctx: *ApiContext) HandlerResult(void) {
    const status: u16 = if (ctx.sync_status.is_syncing)
        206
    else if (ctx.sync_status.head_slot == 0)
        503
    else
        200;
    return .{ .data = {}, .status = status };
}

/// GET /eth/v1/node/peers
///
/// Returns the list of connected peers with their state, direction, and agent.
/// Uses the PeerDBCallback if wired; returns empty list otherwise.
pub fn getPeers(ctx: *ApiContext) HandlerResult([]const types.PeerInfo) {
    const cb = ctx.peer_db orelse return .{
        .data = &[_]types.PeerInfo{},
    };

    const entries = cb.getConnectedPeersFn(cb.ptr, ctx.allocator) catch return .{
        .data = &[_]types.PeerInfo{},
    };
    defer ctx.allocator.free(entries);

    // Convert PeerEntry to PeerInfo for JSON response.
    const infos = ctx.allocator.alloc(types.PeerInfo, entries.len) catch {
        return .{ .data = &[_]types.PeerInfo{} };
    };

    for (entries, 0..) |entry, i| {
        infos[i] = .{
            .peer_id = entry.peer_id,
            .enr = null,
            .last_seen_p2p_address = "",
            .state = entry.state,
            .direction = entry.direction,
        };
    }

    return .{
        .data = infos,
    };
}

/// GET /eth/v1/node/peer_count
///
/// Returns aggregate counts of peers in each connection state.
/// Uses the PeerDBCallback if wired; returns zeros otherwise.
pub fn getPeerCount(ctx: *ApiContext) HandlerResult(types.PeerCount) {
    const cb = ctx.peer_db orelse return .{
        .data = .{
            .disconnected = 0,
            .connecting = 0,
            .connected = 0,
            .disconnecting = 0,
        },
    };

    const counts = cb.getPeerCountsFn(cb.ptr);
    return .{
        .data = .{
            .disconnected = counts.disconnected,
            .connecting = counts.connecting,
            .connected = counts.connected,
            .disconnecting = counts.disconnecting,
        },
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

test "getHealth returns syncing (206) when syncing" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = true;
    const result = getHealth(&tc.ctx);
    try std.testing.expectEqual(@as(u16, 206), result.status);
}

test "getHealth returns not_initialized (503) when head_slot is 0" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = false;
    tc.ctx.sync_status.head_slot = 0;
    const result = getHealth(&tc.ctx);
    try std.testing.expectEqual(@as(u16, 503), result.status);
}

test "getHealth returns ready (200) when synced" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.sync_status.is_syncing = false;
    tc.ctx.sync_status.head_slot = 1000;
    const result = getHealth(&tc.ctx);
    try std.testing.expectEqual(@as(u16, 200), result.status);
}

test "getPeers returns empty list when no peer_db" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPeers(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "getPeerCount returns zero counts when no peer_db" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPeerCount(&tc.ctx);
    try std.testing.expectEqual(@as(u64, 0), resp.data.connected);
    try std.testing.expectEqual(@as(u64, 0), resp.data.disconnected);
}

test "getPeers returns peers from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockPeerDB = struct {
        fn getConnectedPeers(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]context.PeerEntry {
            _ = ptr;
            const entries = try allocator.alloc(context.PeerEntry, 2);
            entries[0] = .{
                .peer_id = "peer-1",
                .state = .connected,
                .direction = .inbound,
                .agent = "Lighthouse/v4.5.0",
            };
            entries[1] = .{
                .peer_id = "peer-2",
                .state = .connected,
                .direction = .outbound,
                .agent = null,
            };
            return entries;
        }

        fn getPeerCounts(ptr: *anyopaque) context.PeerCounts {
            _ = ptr;
            return .{
                .connected = 2,
                .disconnected = 1,
                .connecting = 0,
                .disconnecting = 0,
            };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.peer_db = .{
        .ptr = &dummy,
        .getConnectedPeersFn = &MockPeerDB.getConnectedPeers,
        .getPeerCountsFn = &MockPeerDB.getPeerCounts,
    };

    const resp = getPeers(&tc.ctx);
    defer tc.ctx.allocator.free(resp.data);
    try std.testing.expectEqual(@as(usize, 2), resp.data.len);
    try std.testing.expectEqualStrings("peer-1", resp.data[0].peer_id);
    try std.testing.expectEqual(types.PeerDirection.outbound, resp.data[1].direction);
}

test "getPeerCount returns real counts from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockPeerDB = struct {
        fn getConnectedPeers(_: *anyopaque, _: std.mem.Allocator) anyerror![]context.PeerEntry {
            return &[_]context.PeerEntry{};
        }
        fn getPeerCounts(_: *anyopaque) context.PeerCounts {
            return .{
                .connected = 5,
                .disconnected = 3,
                .connecting = 1,
                .disconnecting = 0,
            };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.peer_db = .{
        .ptr = &dummy,
        .getConnectedPeersFn = &MockPeerDB.getConnectedPeers,
        .getPeerCountsFn = &MockPeerDB.getPeerCounts,
    };

    const resp = getPeerCount(&tc.ctx);
    try std.testing.expectEqual(@as(u64, 5), resp.data.connected);
    try std.testing.expectEqual(@as(u64, 3), resp.data.disconnected);
    try std.testing.expectEqual(@as(u64, 1), resp.data.connecting);
}

/// GET /eth/v1/node/peers/{peer_id}
///
/// Returns info about a specific peer.
pub fn getPeer(ctx: *ApiContext, peer_id: []const u8) !HandlerResult(types.PeerDetail) {
    const cb = ctx.peer_db orelse return error.PeerNotFound;

    const entries = try cb.getConnectedPeersFn(cb.ptr, ctx.allocator);
    defer ctx.allocator.free(entries);

    for (entries) |entry| {
        if (std.mem.eql(u8, entry.peer_id, peer_id)) {
            return .{
                .data = .{
                    .peer_id = entry.peer_id,
                    .enr = null,
                    .last_seen_p2p_address = "",
                    .state = entry.state,
                    .direction = entry.direction,
                },
                .meta = .{},
            };
        }
    }

    return error.PeerNotFound;
}
