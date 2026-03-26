//! Sync-facing peer manager adapter.
//!
//! This is a thin wrapper that provides the sync subsystem's expected API
//! on top of the comprehensive networking PeerManager. The sync module
//! only cares about a subset of peer management: status tracking, best
//! peer selection, and peer counts.
//!
//! The real peer management (connection state machine, scoring, banning,
//! subnet tracking, heartbeat) lives in `src/networking/peer_manager.zig`.
//! This adapter translates between the sync-specific types (PeerSyncInfo,
//! StatusMessage) and the networking types (SyncInfo, PeerInfo).

const std = @import("std");
const Allocator = std.mem.Allocator;
const messages = @import("networking").messages;
const StatusMessage = messages.StatusMessage;
const sync_types = @import("sync_types.zig");
const PeerSyncInfo = sync_types.PeerSyncInfo;

const networking = @import("networking");
const NetPeerManager = networking.peer_manager.PeerManager;
const PeerManagerConfig = networking.PeerManagerConfig;
const SyncInfo = networking.SyncInfo;

/// Sync-facing peer manager.
///
/// Wraps the networking PeerManager to provide the API expected by
/// SyncService and RangeSyncManager. Existing callers don't need to change.
pub const PeerManager = struct {
    allocator: Allocator,
    /// The underlying comprehensive peer manager.
    inner: NetPeerManager,

    pub fn init(allocator: Allocator) PeerManager {
        return .{
            .allocator = allocator,
            .inner = NetPeerManager.init(allocator, .{}),
        };
    }

    /// Init with custom config (for testing or custom target-peers).
    pub fn initWithConfig(allocator: Allocator, config: PeerManagerConfig) PeerManager {
        return .{
            .allocator = allocator,
            .inner = NetPeerManager.init(allocator, config),
        };
    }

    pub fn deinit(self: *PeerManager) void {
        self.inner.deinit();
    }

    /// Update (or insert) peer status from a Status handshake message.
    /// This is the primary entry point from the sync layer.
    pub fn updatePeerStatus(
        self: *PeerManager,
        peer_id: []const u8,
        status: StatusMessage.Type,
    ) !void {
        // Ensure the peer exists in the DB. For sync purposes, we treat
        // a Status message as confirmation of connectivity.
        const now_ms = currentTimeMs();
        _ = try self.inner.onPeerConnected(peer_id, .outbound, now_ms);
        self.inner.updatePeerStatus(
            peer_id,
            status.head_slot,
            status.head_root,
            status.finalized_epoch,
            status.finalized_root,
        );
    }

    /// Remove a disconnected peer.
    pub fn removePeer(self: *PeerManager, peer_id: []const u8) void {
        self.inner.onPeerDisconnected(peer_id, currentTimeMs());
    }

    /// Return up to `count` peers with the highest head slot.
    /// Caller owns the returned slice.
    pub fn getBestPeers(self: *PeerManager, count: usize) ![]PeerSyncInfo {
        const connected = try self.inner.getBestPeers(@intCast(@min(count, std.math.maxInt(u32))));
        defer self.allocator.free(connected);

        if (connected.len == 0) return &[_]PeerSyncInfo{};

        const result = try self.allocator.alloc(PeerSyncInfo, connected.len);
        for (connected, 0..) |cp, i| {
            const si = cp.info.sync_info orelse continue;
            result[i] = .{
                .peer_id = cp.peer_id,
                .head_slot = si.head_slot,
                .head_root = si.head_root,
                .finalized_epoch = si.finalized_epoch,
                .finalized_root = si.finalized_root,
            };
        }
        return result;
    }

    /// Highest head_slot among all tracked peers.
    pub fn getHighestPeerSlot(self: *PeerManager) u64 {
        return self.inner.getHighestPeerSlot();
    }

    /// Select the best sync target: peer with the highest head slot.
    pub fn getSyncTarget(self: *PeerManager) ?PeerSyncInfo {
        const target = self.inner.getSyncTarget() orelse return null;
        return .{
            .peer_id = target.peer_id,
            .head_slot = target.sync_info.head_slot,
            .head_root = target.sync_info.head_root,
            .finalized_epoch = target.sync_info.finalized_epoch,
            .finalized_root = target.sync_info.finalized_root,
        };
    }

    /// Number of tracked peers.
    pub fn peerCount(self: *const PeerManager) usize {
        return @intCast(self.inner.peerCount());
    }

    /// Access the underlying networking PeerManager for advanced operations.
    pub fn getNetworkPeerManager(self: *PeerManager) *NetPeerManager {
        return &self.inner;
    }

    /// Get the current time in milliseconds (monotonic clock).
    fn currentTimeMs() u64 {
        var ts: std.os.linux.timespec = undefined;
        const result = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
        if (result != 0) return 0;
        return @intCast(@as(i64, ts.sec) * 1000 + @divFloor(@as(i64, ts.nsec), 1_000_000));
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "PeerManager adapter: add, update, and remove peers" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    // Add two peers.
    try pm.updatePeerStatus("peer_a", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 320,
    });
    try pm.updatePeerStatus("peer_b", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 500,
    });

    try std.testing.expectEqual(@as(usize, 2), pm.peerCount());
    try std.testing.expectEqual(@as(u64, 500), pm.getHighestPeerSlot());

    // Update peer_a to a higher slot.
    try pm.updatePeerStatus("peer_a", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 15,
        .head_root = [_]u8{0xCC} ** 32,
        .head_slot = 600,
    });

    try std.testing.expectEqual(@as(usize, 2), pm.peerCount());
    try std.testing.expectEqual(@as(u64, 600), pm.getHighestPeerSlot());

    // Remove peer_b.
    pm.removePeer("peer_b");
    try std.testing.expectEqual(@as(usize, 1), pm.peerCount());
    try std.testing.expectEqual(@as(u64, 600), pm.getHighestPeerSlot());
}

test "PeerManager adapter: getBestPeers returns sorted" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    const slots = [_]u64{ 100, 300, 200 };
    const ids = [_][]const u8{ "p1", "p2", "p3" };

    for (ids, slots) |id, slot| {
        try pm.updatePeerStatus(id, .{
            .fork_digest = .{ 0, 0, 0, 0 },
            .finalized_root = [_]u8{0} ** 32,
            .finalized_epoch = 0,
            .head_root = [_]u8{0} ** 32,
            .head_slot = slot,
        });
    }

    const best = try pm.getBestPeers(2);
    defer allocator.free(best);

    try std.testing.expectEqual(@as(usize, 2), best.len);
    try std.testing.expectEqual(@as(u64, 300), best[0].head_slot);
    try std.testing.expectEqual(@as(u64, 200), best[1].head_slot);
}

test "PeerManager adapter: getSyncTarget picks highest slot" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    try std.testing.expect(pm.getSyncTarget() == null);

    try pm.updatePeerStatus("slow", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 100,
    });
    try pm.updatePeerStatus("fast", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 999,
    });

    const target = pm.getSyncTarget().?;
    try std.testing.expectEqual(@as(u64, 999), target.head_slot);
}

test "PeerManager adapter: empty manager returns defaults" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    try std.testing.expectEqual(@as(u64, 0), pm.getHighestPeerSlot());
    try std.testing.expect(pm.getSyncTarget() == null);
    try std.testing.expectEqual(@as(usize, 0), pm.peerCount());

    const best = try pm.getBestPeers(5);
    try std.testing.expectEqual(@as(usize, 0), best.len);
}
