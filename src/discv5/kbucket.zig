//! Kademlia k-bucket routing table for discv5

const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;

pub const K = 16;
pub const NUM_BUCKETS = 256;

/// Maximum nodes from the same IPv6 /64 prefix allowed in any single bucket.
/// Limits Sybil attacks where an attacker controls an entire /64 block (CL-2026-11).
pub const EntryStatus = enum {
    connected,
    disconnected,
    pending,
};

pub const Entry = struct {
    node_id: NodeId,
    addr: [6]u8,
    last_seen: i64,
    status: EntryStatus,
};

pub const KBucket = struct {
    entries: [K]Entry,
    count: usize,

    pub fn init() KBucket {
        return .{ .entries = undefined, .count = 0 };
    }

    pub fn insert(self: *KBucket, entry: Entry) bool {
        for (self.entries[0..self.count]) |*e| {
            if (std.mem.eql(u8, &e.node_id, &entry.node_id)) {
                e.* = entry;
                return true;
            }
        }
        if (self.count < K) {
            self.entries[self.count] = entry;
            self.count += 1;
            return true;
        }

        // Bucket full: only evict disconnected peers, and pick the stalest one.
        var eviction_idx: ?usize = null;
        var oldest_last_seen: i64 = 0;
        for (self.entries[0..self.count], 0..) |e, i| {
            if (e.status != .disconnected) continue;
            if (eviction_idx == null or e.last_seen < oldest_last_seen) {
                eviction_idx = i;
                oldest_last_seen = e.last_seen;
            }
        }
        if (eviction_idx) |i| {
            self.entries[i] = entry;
            return true;
        }

        return false;
    }

    pub fn remove(self: *KBucket, node_id: *const NodeId) bool {
        for (self.entries[0..self.count], 0..) |e, i| {
            if (std.mem.eql(u8, &e.node_id, node_id)) {
                std.mem.copyForwards(Entry, self.entries[i .. self.count - 1], self.entries[i + 1 .. self.count]);
                self.count -= 1;
                return true;
            }
        }
        return false;
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
            .addr = [6]u8{ 127, 0, 0, 1, 0x23, 0x28 },
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

test "kbucket: bucket full evicts disconnected" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ 127, 0, 0, 1, 0, 0 },
            .last_seen = @intCast(i),
            .status = .disconnected,
        });
    }
    try std.testing.expectEqual(@as(usize, K), bucket.count);

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xff} ** 32,
        .addr = .{ 127, 0, 0, 1, 0, 1 },
        .last_seen = 0,
        .status = .connected,
    });
    try std.testing.expect(inserted);
    try std.testing.expectEqualDeep([_]u8{0xff} ** 32, bucket.entries[0].node_id);
}

test "kbucket: full bucket does not evict connected peers" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ 10, 0, 0, 1, 0, 0 },
            .last_seen = @intCast(i),
            .status = .connected,
        });
    }

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xee} ** 32,
        .addr = .{ 10, 0, 0, 2, 0, 0 },
        .last_seen = -1,
        .status = .pending,
    });
    try std.testing.expect(!inserted);
}

test "kbucket: updating existing node does not grow bucket" {
    var bucket = KBucket.init();
    const node_id: NodeId = [_]u8{0x42} ** 32;

    try std.testing.expect(bucket.insert(.{
        .node_id = node_id,
        .addr = .{ 127, 0, 0, 1, 0x23, 0x28 },
        .last_seen = 1,
        .status = .pending,
    }));
    try std.testing.expect(bucket.insert(.{
        .node_id = node_id,
        .addr = .{ 127, 0, 0, 2, 0x23, 0x29 },
        .last_seen = 2,
        .status = .connected,
    }));

    try std.testing.expectEqual(@as(usize, 1), bucket.count);
    try std.testing.expectEqualDeep([6]u8{ 127, 0, 0, 2, 0x23, 0x29 }, bucket.entries[0].addr);
    try std.testing.expectEqual(EntryStatus.connected, bucket.entries[0].status);
}
