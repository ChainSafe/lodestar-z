const std = @import("std");
const constants = @import("constants.zig");
const Peers = @import("peers.zig").Peers;
const PeerRef = @import("peers.zig").Ref;
const PeerScore = @import("score.zig").PeerScore;
const Handle = @import("../quic/engine.zig").Handle;
const MessageId = @import("topic.zig").MessageId;

pub const Promise = struct {
    id: MessageId,
    peer: PeerRef,
    token: u64,
    connection: Handle,
    expiry: ?u64 = null,
};

pub const Recovery = struct {
    promises: []Promise,
    len: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !Recovery {
        return .{ .promises = try allocator.alloc(Promise, constants.promises_cap) };
    }

    pub fn deinit(self: *Recovery, allocator: std.mem.Allocator, peers: *Peers) void {
        self.clear(peers);
        allocator.free(self.promises);
        self.* = undefined;
    }

    pub fn clear(self: *Recovery, peers: *Peers) void {
        for (self.promises[0..self.len]) |promise| peers.release(promise.peer);
        self.len = 0;
    }

    pub fn available(self: *const Recovery) usize {
        return self.promises.len - self.len;
    }

    pub fn memoryBytes(self: *const Recovery) usize {
        return self.promises.len * @sizeOf(Promise);
    }

    pub fn add(self: *Recovery, peers: *Peers, id: MessageId, peer: PeerRef, connection: Handle, token: u64) void {
        std.debug.assert(self.available() > 0);
        peers.retain(peer);
        self.promises[self.len] = .{ .id = id, .peer = peer, .connection = connection, .token = token };
        self.len += 1;
    }

    pub fn resolve(self: *Recovery, peers: *Peers, id: MessageId) void {
        var index: usize = 0;
        for (0..self.promises.len) |_| {
            if (index == self.len) break;
            if (std.mem.eql(u8, &self.promises[index].id, &id)) {
                self.remove(peers, index);
            } else index += 1;
        }
    }

    pub fn cancel(self: *Recovery, peers: *Peers, connection: Handle, local_pressure: bool) u64 {
        var removed: u64 = 0;
        var index: usize = 0;
        for (0..self.promises.len) |_| {
            if (index == self.len) break;
            const p = self.promises[index];
            if (std.meta.eql(p.connection, connection) and (local_pressure or p.expiry == null)) {
                self.remove(peers, index);
                removed += 1;
            } else index += 1;
        }
        return removed;
    }

    pub fn controlSent(self: *Recovery, connection: Handle, token: u64, followup_ms: u64, now_ms: u64) void {
        std.debug.assert(followup_ms > 0 and followup_ms <= 86_400_000);
        for (self.promises[0..self.len]) |*p| {
            if (p.expiry == null and p.token == token and std.meta.eql(p.connection, connection)) {
                p.expiry = now_ms +| followup_ms;
            }
        }
    }

    pub fn expire(self: *Recovery, peers: *Peers, scores: *PeerScore, now_ms: u64) u64 {
        var broken: u64 = 0;
        var index: usize = 0;
        for (0..self.promises.len) |_| {
            if (index == self.len) break;
            const p = self.promises[index];
            // Each promise pins attribution until removal, preventing identity-slot reuse.
            std.debug.assert(peers.matches(p.peer));
            if (p.expiry != null and now_ms >= p.expiry.?) {
                broken += 1;
                scores.penalize(p.peer.index, 1);
                peers.rows[p.peer.index].negative = true;
                self.remove(peers, index);
            } else index += 1;
        }
        return broken;
    }

    pub fn nextExpiry(self: *const Recovery) ?u64 {
        var next: ?u64 = null;
        for (self.promises[0..self.len]) |promise| if (promise.expiry) |expiry| {
            next = @min(next orelse expiry, expiry);
        };
        return next;
    }

    fn remove(self: *Recovery, peers: *Peers, index: usize) void {
        std.debug.assert(index < self.len);
        peers.release(self.promises[index].peer);
        self.len -= 1;
        self.promises[index] = self.promises[self.len];
    }
};

test "recovery receipts bind connection generation and token and release only cancelled pins" {
    const allocator = std.testing.allocator;
    var peers = try Peers.initCapacity(allocator, 10_000, 2, 1);
    defer peers.deinit(allocator);
    var recovery = try Recovery.init(allocator);
    defer recovery.deinit(allocator, &peers);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const next_connection: Handle = .{ .index = 0, .generation = 2 };
    const metadata: @import("peers.zig").Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    recovery.add(&peers, [_]u8{1} ** 20, peer, connection, 7);
    recovery.add(&peers, [_]u8{2} ** 20, peer, connection, 8);
    recovery.controlSent(next_connection, 7, 3000, 10);
    recovery.controlSent(connection, 6, 3000, 10);
    try std.testing.expect(recovery.nextExpiry() == null);
    recovery.controlSent(connection, 7, 3000, 20);
    try std.testing.expectEqual(@as(?u64, 3020), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 0), recovery.cancel(&peers, next_connection, true));
    try std.testing.expectEqual(@as(u64, 1), recovery.cancel(&peers, connection, false));
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    recovery.controlSent(connection, 7, 3000, 200);
    recovery.controlSent(connection, 8, 3000, 200);
    try std.testing.expectEqual(@as(?u64, 3020), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 1), recovery.cancel(&peers, connection, true));
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
    try std.testing.expectEqual(@as(usize, constants.promises_cap), recovery.available());
    recovery.controlSent(connection, 7, 3000, 300);
    try std.testing.expect(recovery.nextExpiry() == null);
}

test "recovery capacity resolves every matching attribution and deinit releases remaining pins" {
    const allocator = std.testing.allocator;
    var peers = try Peers.initCapacity(allocator, 10_000, 2, 1);
    defer peers.deinit(allocator);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const metadata: @import("peers.zig").Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    {
        var recovery = try Recovery.init(allocator);
        defer recovery.deinit(allocator, &peers);
        for (0..constants.promises_cap) |_| recovery.add(&peers, [_]u8{1} ** 20, peer, connection, 7);
        try std.testing.expectEqual(@as(usize, 0), recovery.available());
        recovery.resolve(&peers, [_]u8{1} ** 20);
        try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
        recovery.add(&peers, [_]u8{2} ** 20, peer, connection, 8);
    }
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}
