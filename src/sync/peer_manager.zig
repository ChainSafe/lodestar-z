//! Peer sync status tracker.
//!
//! Maintains a map of connected peers and their chain view (from Status
//! handshakes). Provides queries for the sync manager: best peers to
//! request from, highest known slot, sync target selection.

const std = @import("std");
const Allocator = std.mem.Allocator;
const messages = @import("networking").messages;
const StatusMessage = messages.StatusMessage;
const sync_types = @import("sync_types.zig");
const PeerSyncInfo = sync_types.PeerSyncInfo;

pub const PeerManager = struct {
    allocator: Allocator,
    /// Keyed by peer_id (owned slices). Values hold their own owned peer_id copy.
    peers: std.StringHashMap(PeerSyncInfo),

    pub fn init(allocator: Allocator) PeerManager {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(PeerSyncInfo).init(allocator),
        };
    }

    pub fn deinit(self: *PeerManager) void {
        // Free owned keys. The value peer_id aliases the key, so only free once.
        var it = self.peers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.peers.deinit();
    }

    /// Update (or insert) peer status from a Status handshake message.
    pub fn updatePeerStatus(
        self: *PeerManager,
        peer_id: []const u8,
        status: StatusMessage.Type,
    ) !void {
        const result = try self.peers.getOrPut(peer_id);

        if (!result.found_existing) {
            // New peer — allocate owned key, set it as both map key and value peer_id.
            const owned_id = try self.allocator.dupe(u8, peer_id);
            result.key_ptr.* = owned_id;
            result.value_ptr.* = .{
                .peer_id = owned_id,
                .head_slot = status.head_slot,
                .head_root = status.head_root,
                .finalized_epoch = status.finalized_epoch,
                .finalized_root = status.finalized_root,
            };
        } else {
            // Existing peer — update value in place, key already owned.
            result.value_ptr.head_slot = status.head_slot;
            result.value_ptr.head_root = status.head_root;
            result.value_ptr.finalized_epoch = status.finalized_epoch;
            result.value_ptr.finalized_root = status.finalized_root;
        }
    }

    /// Remove a disconnected peer. Frees the owned key.
    pub fn removePeer(self: *PeerManager, peer_id: []const u8) void {
        if (self.peers.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Return up to `count` peers with the highest head slot.
    /// Caller owns the returned slice (but not the PeerSyncInfo contents — those
    /// are still owned by the PeerManager).
    pub fn getBestPeers(self: *PeerManager, count: usize) ![]PeerSyncInfo {
        const peer_count = self.peers.count();
        if (peer_count == 0) return &[_]PeerSyncInfo{};

        // Collect all peers into a sortable slice.
        var all = try self.allocator.alloc(PeerSyncInfo, peer_count);
        defer self.allocator.free(all);

        var idx: usize = 0;
        var it = self.peers.valueIterator();
        while (it.next()) |v| {
            all[idx] = v.*;
            idx += 1;
        }

        // Sort descending by head_slot.
        std.mem.sort(PeerSyncInfo, all[0..idx], {}, struct {
            fn cmp(_: void, a: PeerSyncInfo, b_peer: PeerSyncInfo) bool {
                return a.head_slot > b_peer.head_slot;
            }
        }.cmp);

        const result_count = @min(count, idx);
        const result = try self.allocator.alloc(PeerSyncInfo, result_count);
        @memcpy(result, all[0..result_count]);
        return result;
    }

    /// Highest head_slot among all tracked peers.
    pub fn getHighestPeerSlot(self: *PeerManager) u64 {
        var max_slot: u64 = 0;
        var it = self.peers.valueIterator();
        while (it.next()) |v| {
            if (v.head_slot > max_slot) max_slot = v.head_slot;
        }
        return max_slot;
    }

    /// Select the best sync target: peer with the highest head slot.
    pub fn getSyncTarget(self: *PeerManager) ?PeerSyncInfo {
        var best: ?PeerSyncInfo = null;
        var it = self.peers.valueIterator();
        while (it.next()) |v| {
            if (best == null or v.head_slot > best.?.head_slot) {
                best = v.*;
            }
        }
        return best;
    }

    /// Number of tracked peers.
    pub fn peerCount(self: *const PeerManager) usize {
        return self.peers.count();
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "PeerManager: add, update, and remove peers" {
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

test "PeerManager: getBestPeers returns sorted by head_slot descending" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    // Add peers with varying slots.
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

test "PeerManager: getSyncTarget picks highest slot peer" {
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

test "PeerManager: empty manager returns defaults" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    try std.testing.expectEqual(@as(u64, 0), pm.getHighestPeerSlot());
    try std.testing.expect(pm.getSyncTarget() == null);
    try std.testing.expectEqual(@as(usize, 0), pm.peerCount());

    const best = try pm.getBestPeers(5);
    try std.testing.expectEqual(@as(usize, 0), best.len);
}
