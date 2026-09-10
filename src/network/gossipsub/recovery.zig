const std = @import("std");
const constants = @import("constants.zig");
const Peers = @import("peer_book.zig").PeerBook;
const PeerRef = @import("peer_book.zig").Ref;
const PeerScore = @import("score.zig").PeerScore;
const Handle = @import("../quic/engine.zig").Handle;
const MessageId = @import("topic.zig").MessageId;
const assert = std.debug.assert;
const none = std.math.maxInt(u16);

pub const promises_per_peer = constants.max_ihave_per_heartbeat * constants.gossip_ids_max;

const Request = struct { id: MessageId = undefined, next: u16 = none };
pub const Batch = struct {
    peer: PeerRef,
    token: u64,
    connection: Handle,
    head: u16 = none,
    count: u16 = 0,
    sample: u16 = none,
    expiry: ?u64 = null,
    sent_at_ms: u64 = 0,
};

pub const Recovery = struct {
    requests: []Request,
    batches: []Batch,
    free: u16 = 0,
    len: usize = 0,
    batch_len: usize = 0,
    metrics: @import("metrics.zig").Recovery = .{},

    pub fn init(allocator: std.mem.Allocator) !Recovery {
        comptime assert(promises_per_peer < constants.promises_cap and constants.promises_cap < none);
        const requests = try allocator.alloc(Request, constants.promises_cap);
        errdefer allocator.free(requests);
        const batches = try allocator.alloc(Batch, constants.promises_cap);
        var result: Recovery = .{ .requests = requests, .batches = batches };
        result.resetFree();
        return result;
    }

    pub fn deinit(self: *Recovery, allocator: std.mem.Allocator, peers: *Peers) void {
        self.clear(peers);
        allocator.free(self.requests);
        allocator.free(self.batches);
        self.* = undefined;
    }

    pub fn clear(self: *Recovery, peers: *Peers) void {
        for (self.batches[0..self.batch_len]) |batch| peers.release(batch.peer);
        self.len = 0;
        self.batch_len = 0;
        self.resetFree();
    }

    fn resetFree(self: *Recovery) void {
        for (self.requests, 0..) |*request, i| request.* = .{ .next = if (i + 1 < self.requests.len) @intCast(i + 1) else none };
        self.free = 0;
    }

    pub fn available(self: *const Recovery) usize {
        return self.requests.len - self.len;
    }

    pub fn select(self: *const Recovery, peer: PeerRef, ids: []MessageId) error{PeerCapacity}!usize {
        assert(ids.len <= constants.gossip_ids_max);
        std.sort.heap(MessageId, ids, {}, lessThan);
        var unique: usize = 0;
        for (ids) |id| {
            if (unique > 0 and std.mem.eql(u8, &ids[unique - 1], &id)) continue;
            ids[unique] = id;
            unique += 1;
        }
        var requested = std.StaticBitSet(constants.gossip_ids_max).initEmpty();
        var pending: usize = 0;
        for (self.batches[0..self.batch_len]) |batch| {
            if (!std.meta.eql(batch.peer, peer)) continue;
            pending += batch.count;
            var slot = batch.head;
            for (0..batch.count) |_| {
                const request = self.requests[slot];
                if (std.sort.binarySearch(MessageId, ids[0..unique], &request.id, compare)) |index| requested.set(index);
                slot = request.next;
            }
            assert(slot == none);
        }
        if (pending >= promises_per_peer) return error.PeerCapacity;
        const capacity = @min(self.available(), promises_per_peer - pending);
        var count: usize = 0;
        for (ids[0..unique], 0..) |id, index| {
            if (count == capacity) break;
            if (requested.isSet(index)) continue;
            ids[count] = id;
            count += 1;
        }
        return count;
    }

    fn lessThan(_: void, left: MessageId, right: MessageId) bool {
        return std.mem.lessThan(u8, &left, &right);
    }

    fn compare(left: *const MessageId, right: MessageId) std.math.Order {
        return std.mem.order(u8, left, &right);
    }

    pub fn memoryBytes(self: *const Recovery) usize {
        return self.requests.len * @sizeOf(Request) + self.batches.len * @sizeOf(Batch);
    }

    pub fn add(self: *Recovery, peers: *Peers, id: MessageId, peer: PeerRef, connection: Handle, token: u64) void {
        self.addBatch(peers, &.{id}, peer, connection, token, 0);
    }

    pub fn addBatch(self: *Recovery, peers: *Peers, ids: []const MessageId, peer: PeerRef, connection: Handle, token: u64, sample: usize) void {
        assert(ids.len > 0 and ids.len <= constants.gossip_ids_max and ids.len <= self.available() and sample < ids.len);
        const batch = &self.batches[self.batch_len];
        batch.* = .{ .peer = peer, .connection = connection, .token = token, .count = @intCast(ids.len) };
        for (ids, 0..) |id, i| {
            const slot = self.free;
            assert(slot != none);
            self.free = self.requests[slot].next;
            self.requests[slot] = .{ .id = id, .next = batch.head };
            batch.head = slot;
            if (i == sample) batch.sample = slot;
        }
        peers.retain(peer);
        self.len += ids.len;
        self.batch_len += 1;
    }

    pub const Receipt = struct { now_ms: u64, duplicate: bool = false };

    pub fn resolve(self: *Recovery, peers: *Peers, id: MessageId, receipt: ?Receipt) void {
        var index: usize = 0;
        const batches = self.batch_len;
        for (0..batches) |_| {
            if (index == self.batch_len) break;
            const batch = &self.batches[index];
            var link = &batch.head;
            const count = batch.count;
            for (0..count) |_| {
                const slot = link.*;
                const request = &self.requests[slot];
                if (!std.mem.eql(u8, &request.id, &id)) {
                    link = &request.next;
                    continue;
                }
                if (receipt) |received| if (batch.expiry != null) {
                    self.metrics.resolved +|= 1;
                    self.metrics.resolved_duplicate +|= @intFromBool(received.duplicate);
                    self.metrics.delivery.observe(received.now_ms -| batch.sent_at_ms);
                };
                link.* = request.next;
                if (batch.sample == slot) batch.sample = none;
                batch.count -= 1;
                self.releaseRequest(slot);
            }
            if (batch.count == 0) self.remove(peers, index) else index += 1;
        }
    }

    pub fn cancel(self: *Recovery, peers: *Peers, connection: Handle, local_pressure: bool) u64 {
        var removed: u64 = 0;
        var index: usize = 0;
        const count = self.batch_len;
        for (0..count) |_| {
            if (index == self.batch_len) break;
            const batch = self.batches[index];
            if (std.meta.eql(batch.connection, connection) and (local_pressure or batch.expiry == null)) {
                removed += batch.count;
                self.remove(peers, index);
            } else index += 1;
        }
        return removed;
    }

    pub fn controlSent(self: *Recovery, connection: Handle, token: u64, followup_ms: u64, now_ms: u64) void {
        assert(followup_ms > 0 and followup_ms <= 86_400_000);
        for (self.batches[0..self.batch_len]) |*batch| {
            if (batch.expiry == null and batch.token == token and std.meta.eql(batch.connection, connection)) {
                batch.expiry = now_ms +| followup_ms;
                batch.sent_at_ms = now_ms;
                self.metrics.sent +|= batch.count;
                self.metrics.batches_sent +|= 1;
            }
        }
    }

    pub fn expire(self: *Recovery, peers: *Peers, now_ms: u64) u64 {
        var broken: u64 = 0;
        var index: usize = 0;
        const count = self.batch_len;
        for (0..count) |_| {
            if (index == self.batch_len) break;
            const batch = self.batches[index];
            assert(peers.matches(batch.peer));
            if (batch.expiry != null and now_ms >= batch.expiry.?) {
                self.metrics.expired_ids +|= batch.count;
                if (batch.sample != none) {
                    broken += 1;
                    peers.penalize(batch.peer, 1);
                    peers.scores.penalties.broken_promise +|= 1;
                }
                self.remove(peers, index);
            } else index += 1;
        }
        return broken;
    }

    pub fn nextExpiry(self: *const Recovery) ?u64 {
        var next: ?u64 = null;
        for (self.batches[0..self.batch_len]) |batch| if (batch.expiry) |expiry| {
            next = @min(next orelse expiry, expiry);
        };
        return next;
    }

    fn releaseRequest(self: *Recovery, slot: u16) void {
        self.requests[slot].next = self.free;
        self.free = slot;
        self.len -= 1;
    }

    fn remove(self: *Recovery, peers: *Peers, index: usize) void {
        assert(index < self.batch_len);
        const batch = self.batches[index];
        var slot = batch.head;
        for (0..batch.count) |_| {
            const next = self.requests[slot].next;
            self.releaseRequest(slot);
            slot = next;
        }
        assert(slot == none);
        peers.release(batch.peer);
        self.batch_len -= 1;
        self.batches[index] = self.batches[self.batch_len];
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
    const metadata: @import("peer_book.zig").Metadata = .{
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
    try std.testing.expectEqual(@as(u64, 0), recovery.metrics.sent);
    recovery.controlSent(connection, 7, 3000, 20);
    try std.testing.expectEqual(@as(?u64, 3020), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 0), recovery.cancel(&peers, next_connection, true));
    try std.testing.expectEqual(@as(u64, 1), recovery.cancel(&peers, connection, false));
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    recovery.controlSent(connection, 7, 3000, 200);
    recovery.controlSent(connection, 8, 3000, 200);
    try std.testing.expectEqual(@as(?u64, 3020), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.sent);
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
    const metadata: @import("peer_book.zig").Metadata = .{
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
        recovery.resolve(&peers, [_]u8{1} ** 20, .{ .now_ms = 100 });
        try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
        try std.testing.expectEqual(@as(u64, 0), recovery.metrics.resolved);
        recovery.add(&peers, [_]u8{2} ** 20, peer, connection, 8);
    }
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}

test "recovery metrics distinguish incoming delivery from queued and locally resolved requests" {
    const allocator = std.testing.allocator;
    var peers = try Peers.initCapacity(allocator, 10_000, 2, 1);
    defer peers.deinit(allocator);
    var recovery = try Recovery.init(allocator);
    defer recovery.deinit(allocator, &peers);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const metadata: @import("peer_book.zig").Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    const id = [_]u8{1} ** 20;
    recovery.add(&peers, id, peer, connection, 1);
    recovery.add(&peers, id, peer, connection, 2);
    recovery.controlSent(connection, 1, 3000, 100);
    recovery.controlSent(connection, 1, 3000, 200);
    recovery.resolve(&peers, id, .{ .now_ms = 600 });
    recovery.resolve(&peers, id, .{ .now_ms = 700 });
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.sent);
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.resolved);
    try std.testing.expectEqual(@as(u64, 0), recovery.metrics.resolved_duplicate);
    try std.testing.expectEqual(@as(u128, 500), recovery.metrics.delivery.sum_ms);
    recovery.add(&peers, id, peer, connection, 3);
    recovery.controlSent(connection, 3, 3000, 1000);
    recovery.resolve(&peers, id, .{ .now_ms = 1100, .duplicate = true });
    recovery.add(&peers, id, peer, connection, 4);
    recovery.controlSent(connection, 4, 3000, 1200);
    recovery.resolve(&peers, id, null);
    try std.testing.expectEqual(@as(u64, 3), recovery.metrics.sent);
    try std.testing.expectEqual(@as(u64, 2), recovery.metrics.resolved);
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.resolved_duplicate);
    try std.testing.expectEqual(@as(u64, 2), recovery.metrics.delivery.count);
    try std.testing.expectEqual(@as(u128, 600), recovery.metrics.delivery.sum_ms);
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}

test "recovery batches pin identity once and score one randomly selected promise" {
    const a = std.testing.allocator;
    var peers = try Peers.initCapacity(a, 10000, 2, 1);
    defer peers.deinit(a);
    var recovery = try Recovery.init(a);
    defer recovery.deinit(a, &peers);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const metadata: @import("peer_book.zig").Metadata = .{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    var ids: [constants.gossip_ids_max]MessageId = undefined;
    for (&ids, 0..) |*id, i| id.* = @splat(@intCast(i));
    recovery.addBatch(&peers, &ids, peer, connection, 1, 64);
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    try std.testing.expectEqual(@as(u64, 0), recovery.expire(&peers, 20000));
    recovery.controlSent(connection, 1, 3000, 20000);
    try std.testing.expectEqual(@as(u64, 1), recovery.expire(&peers, 23000));
    try std.testing.expectEqual(@as(u64, 1), peers.scores.penalties.broken_promise);
    try std.testing.expectEqual(@as(u64, 128), recovery.metrics.expired_ids);
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
    recovery.addBatch(&peers, &ids, peer, connection, 2, 64);
    recovery.controlSent(connection, 2, 3000, 24000);
    recovery.resolve(&peers, ids[64], .{ .now_ms = 25000 });
    try std.testing.expectEqual(@as(usize, 127), recovery.len);
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    try std.testing.expectEqual(@as(u64, 0), recovery.expire(&peers, 27000));
    try std.testing.expectEqual(@as(u64, 1), peers.scores.penalties.broken_promise);
    try std.testing.expectEqual(@as(u64, 255), recovery.metrics.expired_ids);
    try std.testing.expectEqual(@as(u64, 2), recovery.metrics.batches_sent);
    try std.testing.expectEqual(@as(usize, constants.promises_cap), recovery.available());
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}
