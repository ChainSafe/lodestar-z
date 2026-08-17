//! Kademlia k-bucket routing table for discv5

const std = @import("std");
const enr_mod = @import("enr.zig");
const NodeId = enr_mod.NodeId;
const Address = std.Io.net.IpAddress;

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
    pubkey: [33]u8 = [_]u8{0} ** 33,
    addr: Address,
    enr: enr_mod.RawEnr = .{},
    enr_seq: u64 = 0,
    last_seen: i64,
    status: EntryStatus,
    /// Whether this ENR may be relayed in FINDNODE responses. Set for locally
    /// trusted entries and after authenticated traffic verifies a discovered peer.
    relay_eligible: bool = false,
    /// Set when the embedding application explicitly configured this node.
    locally_trusted: bool = false,

    pub fn enrBytes(self: *const Entry) []const u8 {
        return self.enr.slice();
    }
};

pub const InsertOutcome = struct {
    inserted: bool,
    pending_eviction: ?Entry = null,
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
        return self.insertDetailed(entry).inserted;
    }

    pub fn insertDetailed(self: *KBucket, entry: Entry) InsertOutcome {
        if (self.pending) |pending| {
            if (std.mem.eql(u8, &pending.node_id, &entry.node_id)) {
                self.pending = entry;
                self.pending_inserted_at_ns = entry.last_seen;
                return .{ .inserted = true };
            }
        }

        for (self.entries[0..self.count], 0..) |existing, i| {
            if (!std.mem.eql(u8, &existing.node_id, &entry.node_id)) continue;
            if (i == 0 and entry.status == .connected) {
                self.clearPending();
            }
            _ = self.removeAt(i);
            self.insertOrdered(entry);
            return .{ .inserted = true };
        }

        if (self.count < K) {
            self.insertOrdered(entry);
            return .{ .inserted = true };
        }

        if (entry.status == .connected or entry.status == .pending) {
            if (self.first_connected_index != 0 and self.pending == null) {
                const pending_eviction = self.entries[0];
                self.pending = entry;
                self.pending_inserted_at_ns = entry.last_seen;
                return .{ .inserted = false, .pending_eviction = pending_eviction };
            }
        }

        return .{ .inserted = false };
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

    pub fn get(self: *const KBucket, node_id: *const NodeId) ?*const Entry {
        for (self.entries[0..self.count]) |*entry| {
            if (std.mem.eql(u8, &entry.node_id, node_id)) return entry;
        }
        return null;
    }

    pub fn getWithPending(self: *const KBucket, node_id: *const NodeId) ?*const Entry {
        if (self.get(node_id)) |entry| return entry;
        if (self.pending) |*pending| {
            if (std.mem.eql(u8, &pending.node_id, node_id)) return pending;
        }
        return null;
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
            @memmove(self.entries[index .. self.count - 1], self.entries[index + 1 .. self.count]);
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
                    @memmove(self.entries[insert_at + 1 .. self.count + 1], self.entries[insert_at..self.count]);
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
    buckets: *[NUM_BUCKETS]KBucket,

    pub fn init(alloc: std.mem.Allocator, local_id: NodeId) !RoutingTable {
        const buckets = try alloc.create([NUM_BUCKETS]KBucket);
        for (buckets) |*bucket| {
            bucket.* = KBucket.init();
        }
        return .{
            .local_id = local_id,
            .buckets = buckets,
        };
    }

    pub fn deinit(self: *RoutingTable, alloc: std.mem.Allocator) void {
        alloc.destroy(self.buckets);
        self.* = undefined;
    }

    pub fn insert(self: *RoutingTable, entry: Entry) bool {
        return self.insertDetailed(entry).inserted;
    }

    pub fn insertDetailed(self: *RoutingTable, entry: Entry) InsertOutcome {
        const dist = logDistance(&self.local_id, &entry.node_id) orelse return .{ .inserted = false };
        return self.buckets[dist].insertDetailed(entry);
    }

    pub fn remove(self: *RoutingTable, node_id: *const NodeId) bool {
        const dist = logDistance(&self.local_id, node_id) orelse return false;
        return self.buckets[dist].remove(node_id);
    }

    pub fn getEntry(self: *const RoutingTable, node_id: *const NodeId) ?*const Entry {
        const dist = logDistance(&self.local_id, node_id) orelse return null;
        return self.buckets[dist].get(node_id);
    }

    pub fn getEntryWithPending(self: *const RoutingTable, node_id: *const NodeId) ?*const Entry {
        const dist = logDistance(&self.local_id, node_id) orelse return null;
        return self.buckets[dist].getWithPending(node_id);
    }

    pub fn prunePending(self: *RoutingTable, now_ns: i64, timeout_ms: u64) void {
        for (self.buckets) |*bucket| {
            _ = bucket.applyPendingIfExpired(now_ns, timeout_ms);
        }
    }

    pub fn findClosest(self: *const RoutingTable, target: *const NodeId, comptime n: usize, out: *[n]Entry) usize {
        var count: usize = 0;
        if (n == 0) return 0;

        for (self.buckets) |*bucket| {
            for (bucket.entries[0..bucket.count]) |e| {
                insertClosest(target, e, out[0..], &count);
            }
        }

        return count;
    }

    pub fn getBucket(self: *const RoutingTable, distance: u8) []const Entry {
        return self.buckets[distance].entries[0..self.buckets[distance].count];
    }

    pub fn nodeCount(self: *const RoutingTable) usize {
        var total: usize = 0;
        for (self.buckets) |*b| total += b.count;
        return total;
    }
};

fn insertClosest(target: *const NodeId, candidate: Entry, out: []Entry, count: *usize) void {
    const candidate_distance = xorDistance(target, &candidate.node_id);

    var insert_at = count.*;
    for (out[0..count.*], 0..) |entry, i| {
        const entry_distance = xorDistance(target, &entry.node_id);
        if (std.mem.lessThan(u8, &candidate_distance, &entry_distance)) {
            insert_at = i;
            break;
        }
    }

    if (insert_at >= out.len) return;

    const new_count = if (count.* < out.len) count.* + 1 else count.*;
    if (insert_at + 1 < new_count) {
        @memmove(out[insert_at + 1 .. new_count], out[insert_at .. new_count - 1]);
    }
    out[insert_at] = candidate;
    count.* = new_count;
}

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
    var rt = try RoutingTable.init(alloc, local);
    defer rt.deinit(alloc);

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
    var out: [5]Entry = undefined;
    const found = rt.findClosest(&target, 5, &out);
    try std.testing.expect(found <= 5);
}

test "kbucket: routing table findClosest uses bounded stack storage" {
    const alloc = std.testing.allocator;
    const local: NodeId = [_]u8{0xff} ** 32;
    var rt = try RoutingTable.init(alloc, local);
    defer rt.deinit(alloc);

    for ([_]u8{ 4, 1, 3, 2 }) |last_byte| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = last_byte;
        try std.testing.expect(rt.insert(.{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = last_byte } },
            .last_seen = 0,
            .status = .connected,
        }));
    }

    const target: NodeId = [_]u8{0} ** 32;
    var out: [3]Entry = undefined;
    const found = rt.findClosest(&target, 3, &out);

    try std.testing.expectEqual(@as(usize, 3), found);
    try std.testing.expectEqual(@as(u8, 1), out[0].node_id[31]);
    try std.testing.expectEqual(@as(u8, 2), out[1].node_id[31]);
    try std.testing.expectEqual(@as(u8, 3), out[2].node_id[31]);
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
