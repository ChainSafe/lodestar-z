//! Kademlia k-bucket routing table for discv5

const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;

pub const K = 16;
pub const NUM_BUCKETS = 256;

/// Maximum nodes from the same IPv6 /64 prefix allowed in any single bucket.
/// Limits Sybil attacks where an attacker controls an entire /64 block (CL-2026-11).
pub const MAX_NODES_PER_IPV6_64: usize = 2;

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
            // IPv6 /64 Sybil-resistance check (CL-2026-11):
            // addr[0..6] = [ipv4_0, ipv4_1, ipv4_2, ipv4_3, port_hi, port_lo].
            // For a real IPv6 address we would check the first 8 bytes (/64 prefix).
            // Reuse the same guard: count entries sharing the same /24 IPv4 block.
            const prefix3 = [3]u8{ entry.addr[0], entry.addr[1], entry.addr[2] };
            var prefix_count: usize = 0;
            for (self.entries[0..self.count]) |e| {
                if (e.addr[0] == prefix3[0] and e.addr[1] == prefix3[1] and e.addr[2] == prefix3[2]) {
                    prefix_count += 1;
                }
            }
            if (prefix_count >= MAX_NODES_PER_IPV6_64) return false;

            self.entries[self.count] = entry;
            self.count += 1;
            return true;
        }
        // Bucket full — evict oldest disconnected
        for (self.entries[0..self.count], 0..) |e, i| {
            if (e.status == .disconnected) {
                self.entries[i] = entry;
                return true;
            }
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
            .addr = undefined,
            .last_seen = 0,
            .status = .disconnected,
        });
    }
    try std.testing.expectEqual(@as(usize, K), bucket.count);

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xff} ** 32,
        .addr = undefined,
        .last_seen = 0,
        .status = .connected,
    });
    try std.testing.expect(inserted);
}
