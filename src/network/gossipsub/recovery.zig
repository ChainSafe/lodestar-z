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
    expiry: u64,
    sent_at_ms: ?u64 = null,
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

    pub const Selection = struct { count: usize, capacity: usize };

    pub fn filterPending(self: *const Recovery, peer: PeerRef, ids: []MessageId) error{PeerCapacity}!Selection {
        assert(ids.len <= constants.max_ihave_ids_per_heartbeat);
        std.sort.heap(MessageId, ids, {}, lessThan);
        var unique: usize = 0;
        for (ids) |id| {
            if (unique > 0 and std.mem.eql(u8, &ids[unique - 1], &id)) continue;
            ids[unique] = id;
            unique += 1;
        }
        var requested = std.StaticBitSet(constants.max_ihave_ids_per_heartbeat).initEmpty();
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
            if (requested.isSet(index)) continue;
            ids[count] = id;
            count += 1;
        }
        return .{ .count = count, .capacity = capacity };
    }

    pub fn resolveWork(self: *const Recovery) usize {
        return self.len * (@sizeOf(Request) + @sizeOf(MessageId)) + self.batch_len * @sizeOf(Batch);
    }

    pub fn selectionWork(ids: usize, batches: usize, requests: usize) usize {
        assert(ids <= constants.max_ihave_ids_per_heartbeat and batches <= constants.promises_cap and requests <= constants.promises_cap);
        const levels = std.math.log2_int_ceil(usize, @max(ids, 2));
        // Heap construction and removal visit at most 3n/2 paths. Each level
        // compares two ID pairs and swaps three IDs. Include deduplication,
        // compaction, binary-search comparisons and the batch/bitset scans.
        return 16 * ids * (levels + 1) * @sizeOf(MessageId) +
            requests * (levels + 1) * 2 * @sizeOf(MessageId) +
            batches * @sizeOf(Batch) + @sizeOf(std.StaticBitSet(constants.max_ihave_ids_per_heartbeat));
    }

    fn lessThan(_: void, left: MessageId, right: MessageId) bool {
        return std.mem.lessThan(u8, &left, &right);
    }

    fn compare(left: *const MessageId, right: MessageId) std.math.Order {
        return std.mem.order(u8, left, &right);
    }

    pub fn backingBytes() usize {
        return constants.promises_cap * (@sizeOf(Request) + @sizeOf(Batch));
    }

    /// Commit a nonempty subset admitted by filterPending, without intervening recovery mutation.
    pub fn requestBatch(self: *Recovery, peers: *Peers, outbox: *@import("outbox.zig").Outbox, ids: []const MessageId, peer: PeerRef, connection: Handle, random: std.Random, followup_ms: u64, now: u64) error{OutboxFull}!void {
        assert(ids.len > 0 and ids.len <= constants.gossip_ids_max and ids.len <= self.available());
        const index = self.batch_len;
        self.addBatch(peers, ids, peer, connection, 0, random.uintLessThan(usize, ids.len), now +| followup_ms);
        const token = outbox.submit(&.{ .iwant = ids }, now) orelse {
            self.remove(peers, index);
            return error.OutboxFull;
        };
        self.batches[index].token = token;
    }

    pub fn add(self: *Recovery, peers: *Peers, id: MessageId, peer: PeerRef, connection: Handle, token: u64, expiry: u64) void {
        self.addBatch(peers, &.{id}, peer, connection, token, 0, expiry);
    }

    pub fn addBatch(self: *Recovery, peers: *Peers, ids: []const MessageId, peer: PeerRef, connection: Handle, token: u64, sample: usize, expiry: u64) void {
        assert(ids.len > 0 and ids.len <= constants.gossip_ids_max and ids.len <= self.available() and sample < ids.len);
        const batch = &self.batches[self.batch_len];
        batch.* = .{ .peer = peer, .connection = connection, .token = token, .expiry = expiry, .count = @intCast(ids.len) };
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
                if (receipt) |received| if (batch.sent_at_ms) |sent_at_ms| {
                    self.metrics.resolved +|= 1;
                    self.metrics.resolved_duplicate +|= @intFromBool(received.duplicate);
                    self.metrics.delivery.observe(received.now_ms -| sent_at_ms);
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
            if (std.meta.eql(batch.connection, connection) and (local_pressure or batch.sent_at_ms == null)) {
                removed += batch.count;
                self.remove(peers, index);
            } else index += 1;
        }
        return removed;
    }

    pub fn controlSent(self: *Recovery, connection: Handle, token: u64, followup_ms: u64, now_ms: u64) void {
        assert(followup_ms > 0 and followup_ms <= 86_400_000);
        for (self.batches[0..self.batch_len]) |*batch| {
            if (batch.sent_at_ms == null and now_ms < batch.expiry and batch.token == token and std.meta.eql(batch.connection, connection)) {
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
            if (now_ms >= batch.expiry) {
                self.metrics.expired_ids +|= batch.count;
                if (batch.sent_at_ms != null and batch.sample != none) {
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
        for (self.batches[0..self.batch_len]) |batch| {
            next = @min(next orelse batch.expiry, batch.expiry);
        }
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

test {
    _ = @import("recovery_test.zig");
}
