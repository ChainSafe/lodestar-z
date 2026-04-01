//! Kademlia k-bucket routing table for discv5

const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;
const Address = @import("udp_socket.zig").Address;

pub const K = 16;
pub const NUM_BUCKETS = 256;
pub const BUCKET_PENDING_TIMEOUT_MS: u64 = 60_000;

/// Connectivity state used for bucket ordering and eviction.
pub const EntryStatus = enum {
    connected,
    disconnected,
    pending,
};

pub const Entry = struct {
    node_id: NodeId,
    addr: Address,
    last_seen: i64,
    status: EntryStatus,
};

pub const KBucket = struct {
    entries: [K]Entry,
    count: usize,
    first_connected_index: ?usize,
    pending: ?Entry,
    pending_inserted_at_ns: i64,

    pub fn init() KBucket {
        return .{
            .entries = undefined,
            .count = 0,
            .first_connected_index = null,
            .pending = null,
            .pending_inserted_at_ns = 0,
        };
    }

    pub fn insert(self: *KBucket, entry: Entry) bool {
        if (self.pending) |pending| {
            if (std.mem.eql(u8, &pending.node_id, &entry.node_id)) {
                self.pending = entry;
                self.pending_inserted_at_ns = entry.last_seen;
                return true;
            }
        }

        for (self.entries[0..self.count], 0..) |existing, i| {
            if (!std.mem.eql(u8, &existing.node_id, &entry.node_id)) continue;
            if (i == 0 and entry.status == .connected) {
                self.clearPending();
            }
            _ = self.removeAt(i);
            self.insertOrdered(entry);
            return true;
        }

        if (self.count < K) {
            self.insertOrdered(entry);
            return true;
        }

        if (entry.status == .connected or entry.status == .pending) {
            if (self.first_connected_index != 0) {
                self.pending = entry;
                self.pending_inserted_at_ns = entry.last_seen;
                return false;
            }
        }

        return false;
    }

    pub fn remove(self: *KBucket, node_id: *const NodeId) bool {
        if (self.pending) |pending| {
            if (std.mem.eql(u8, &pending.node_id, node_id)) {
                self.clearPending();
                return true;
            }
        }

        for (self.entries[0..self.count], 0..) |e, i| {
            if (!std.mem.eql(u8, &e.node_id, node_id)) continue;
            _ = self.removeAt(i);
            self.maybeInsertPending();
            return true;
        }
        return false;
    }

    pub fn applyPendingIfExpired(self: *KBucket, now_ns: i64, timeout_ms: u64) bool {
        const pending = self.pending orelse return false;
        const elapsed_ns: i128 = @as(i128, now_ns) - @as(i128, self.pending_inserted_at_ns);
        const timeout_ns: i128 = @as(i128, timeout_ms) * std.time.ns_per_ms;
        if (elapsed_ns < timeout_ns) return false;

        self.clearPending();

        if (self.count < K) {
            self.insertOrdered(pending);
            return true;
        }

        if (self.first_connected_index == 0) {
            return false;
        }

        _ = self.removeAt(0);
        self.insertOrdered(pending);
        return true;
    }

    fn clearPending(self: *KBucket) void {
        self.pending = null;
        self.pending_inserted_at_ns = 0;
    }

    fn maybeInsertPending(self: *KBucket) void {
        if (self.count >= K) return;
        const pending = self.pending orelse return;
        self.clearPending();
        self.insertOrdered(pending);
    }

    fn removeAt(self: *KBucket, index: usize) Entry {
        const removed = self.entries[index];
        if (index + 1 < self.count) {
            std.mem.copyForwards(Entry, self.entries[index .. self.count - 1], self.entries[index + 1 .. self.count]);
        }
        self.count -= 1;

        switch (removed.status) {
            .connected => {
                if (self.first_connected_index) |first| {
                    if (first >= self.count) self.first_connected_index = null;
                }
            },
            .disconnected, .pending => {
                if (self.first_connected_index) |*first| {
                    first.* -= 1;
                }
            },
        }

        return removed;
    }

    fn insertOrdered(self: *KBucket, entry: Entry) void {
        switch (entry.status) {
            .connected => {
                self.entries[self.count] = entry;
                if (self.first_connected_index == null) {
                    self.first_connected_index = self.count;
                }
            },
            .disconnected, .pending => {
                const insert_at = self.first_connected_index orelse self.count;
                if (insert_at < self.count) {
                    std.mem.copyBackwards(Entry, self.entries[insert_at + 1 .. self.count + 1], self.entries[insert_at..self.count]);
                }
                self.entries[insert_at] = entry;
                if (self.first_connected_index) |*first| {
                    first.* += 1;
                }
                self.count += 1;
                return;
            },
        }
        self.count += 1;
    }
};

/// XOR distance bit index: returns 0..255 or null if equal
pub fn logDistance(a: *const NodeId, b: *const NodeId) ?u8 {
    for (a, b, 0..) |ab, bb, i| {
        const xor = ab ^ bb;
        if (xor != 0) {
            const bit = @as(u8, 7) - @as(u8, @intCast(@clz(xor)));
            return @as(u8, @intCast((31 - i) * 8)) + bit;
        }
    }
    return null;
}

/// Raw XOR of two NodeIds
pub fn xorDistance(a: *const NodeId, b: *const NodeId) NodeId {
    var result: NodeId = undefined;
    for (result[0..], a, b) |*r, aa, bb| {
        r.* = aa ^ bb;
    }
    return result;
}

pub const RoutingTable = struct {
    local_id: NodeId,
    buckets: [NUM_BUCKETS]KBucket,
    alloc: Allocator,

    pub fn init(alloc: Allocator, local_id: NodeId) RoutingTable {
        var rt = RoutingTable{
            .local_id = local_id,
            .buckets = undefined,
            .alloc = alloc,
        };
        for (&rt.buckets) |*b| b.* = KBucket.init();
        return rt;
    }

    pub fn deinit(self: *RoutingTable) void {
        _ = self;
    }

    pub fn insert(self: *RoutingTable, entry: Entry) bool {
        const dist = logDistance(&self.local_id, &entry.node_id) orelse return false;
        return self.buckets[dist].insert(entry);
    }

    pub fn remove(self: *RoutingTable, node_id: *const NodeId) bool {
        const dist = logDistance(&self.local_id, node_id) orelse return false;
        return self.buckets[dist].remove(node_id);
    }

    pub fn prunePending(self: *RoutingTable, now_ns: i64, timeout_ms: u64) void {
        for (&self.buckets) |*bucket| {
            _ = bucket.applyPendingIfExpired(now_ns, timeout_ms);
        }
    }

    pub fn findClosest(self: *const RoutingTable, target: *const NodeId, n: usize, out: []Entry) usize {
        var candidates: [NUM_BUCKETS * K]Entry = undefined;
        var total: usize = 0;
        for (&self.buckets) |*bucket| {
            for (bucket.entries[0..bucket.count]) |e| {
                candidates[total] = e;
                total += 1;
            }
        }

        const ctx = struct {
            target: *const NodeId,
            fn lessThan(ctx_: @This(), a: Entry, b: Entry) bool {
                const da = xorDistance(ctx_.target, &a.node_id);
                const db = xorDistance(ctx_.target, &b.node_id);
                return std.mem.lessThan(u8, &da, &db);
            }
        }{ .target = target };

        std.mem.sort(Entry, candidates[0..total], ctx, @TypeOf(ctx).lessThan);

        const result_count = @min(n, total);
        @memcpy(out[0..result_count], candidates[0..result_count]);
        return result_count;
    }

    pub fn getBucket(self: *const RoutingTable, distance: u8) []const Entry {
        return self.buckets[distance].entries[0..self.buckets[distance].count];
    }

    pub fn nodeCount(self: *const RoutingTable) usize {
        var total: usize = 0;
        for (&self.buckets) |*b| total += b.count;
        return total;
    }
};

// =========== Tests ===========

test "kbucket: logDistance" {
    const a: NodeId = [_]u8{0} ** 32;
    var b: NodeId = [_]u8{0} ** 32;

    try std.testing.expect(logDistance(&a, &b) == null);

    b[31] = 1;
    try std.testing.expectEqual(@as(?u8, 0), logDistance(&a, &b));

    b[31] = 0x80;
    try std.testing.expectEqual(@as(?u8, 7), logDistance(&a, &b));

    b = [_]u8{0} ** 32;
    b[0] = 0x80;
    try std.testing.expectEqual(@as(?u8, 255), logDistance(&a, &b));
}

test "kbucket: routing table insert/find" {
    const alloc = std.testing.allocator;
    const local: NodeId = [_]u8{0xaa} ** 32;
    var rt = RoutingTable.init(alloc, local);
    defer rt.deinit();

    for (1..10) |i| {
        var node_id: NodeId = [_]u8{0xaa} ** 32;
        node_id[31] = @intCast(i);
        const entry = Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0x2328 } },
            .last_seen = 0,
            .status = .connected,
        };
        _ = rt.insert(entry);
    }

    try std.testing.expectEqual(@as(usize, 9), rt.nodeCount());

    const target: NodeId = [_]u8{0xbb} ** 32;
    var out: [16]Entry = undefined;
    const found = rt.findClosest(&target, 5, &out);
    try std.testing.expect(found <= 5);
}

test "kbucket: full bucket stores pending connected entry until timeout" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .disconnected,
        });
    }
    try std.testing.expectEqual(@as(usize, K), bucket.count);

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xff} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } },
        .last_seen = std.time.ns_per_ms,
        .status = .connected,
    });
    try std.testing.expect(!inserted);
    try std.testing.expect(bucket.pending != null);
    try std.testing.expectEqualDeep([_]u8{0xff} ** 32, bucket.pending.?.node_id);

    try std.testing.expect(bucket.applyPendingIfExpired(std.time.ns_per_ms * 2, 1));
    try std.testing.expect(bucket.pending == null);
    try std.testing.expectEqualDeep([_]u8{0xff} ** 32, bucket.entries[K - 1].node_id);
    try std.testing.expectEqual(@as(usize, K), bucket.count);
}

test "kbucket: full bucket does not evict connected peers" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .connected,
        });
    }

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xee} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 0 } },
        .last_seen = -1,
        .status = .pending,
    });
    try std.testing.expect(!inserted);
    try std.testing.expect(bucket.pending == null);
}

test "kbucket: updating existing node does not grow bucket" {
    var bucket = KBucket.init();
    const node_id: NodeId = [_]u8{0x42} ** 32;

    try std.testing.expect(bucket.insert(.{
        .node_id = node_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0x2328 } },
        .last_seen = 1,
        .status = .pending,
    }));
    try std.testing.expect(bucket.insert(.{
        .node_id = node_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0x2329 } },
        .last_seen = 2,
        .status = .connected,
    }));

    try std.testing.expectEqual(@as(usize, 1), bucket.count);
    try std.testing.expectEqualDeep(@as(Address, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0x2329 } }), bucket.entries[0].addr);
    try std.testing.expectEqual(EntryStatus.connected, bucket.entries[0].status);
}

test "kbucket: reconnecting oldest entry clears pending replacement" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .disconnected,
        });
    }

    const pending_id: NodeId = [_]u8{0xaa} ** 32;
    try std.testing.expect(!bucket.insert(.{
        .node_id = pending_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 1 } },
        .last_seen = 100,
        .status = .connected,
    }));
    try std.testing.expect(bucket.pending != null);

    const oldest_id = bucket.entries[0].node_id;
    try std.testing.expect(bucket.insert(.{
        .node_id = oldest_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 2 } },
        .last_seen = 101,
        .status = .connected,
    }));

    try std.testing.expect(bucket.pending == null);
    try std.testing.expectEqual(EntryStatus.connected, bucket.entries[K - 1].status);
}
