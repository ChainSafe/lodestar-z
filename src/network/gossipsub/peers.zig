const std = @import("std");
const constants = @import("constants.zig");
const types = @import("../types.zig");
const Handle = @import("../quic/engine.zig").Handle;
const PeerId = @import("../wire/peer_id.zig").PeerId;
const assert = std.debug.assert;

pub const capacity = 512;
pub const outbound_reserve = 32;
pub const Ref = struct { index: u16, generation: u64 };
pub const Backoff = struct { until: u64 = 0, pruned_at: u64 = 0, topic_generation: u64 = 0 };
pub const Ip = [16]u8;
pub const Metadata = struct {
    identity: PeerId,
    address: types.Address,
    direction: types.Direction,
};
pub const Row = struct {
    generation: u64 = 0,
    occupied: bool = false,
    identity: PeerId = undefined,
    connection: ?Handle = null,
    address: Ip = [_]u8{0} ** 16,
    direction: types.Direction = .inbound,
    pins: u32 = 0,
    retain_until: u64 = 0,
    disconnected_at: u64 = 0,
    negative: bool = false,
    direct: bool = false,
};
pub const Admission = union(enum) {
    admitted: struct { peer: Ref, fresh: bool, penalty_evicted: bool },
    duplicate,
    capacity,
};

pub const Peers = struct {
    rows: []Row,
    backoffs: []Backoff,
    retention_ms: u64,

    pub fn init(a: std.mem.Allocator, retention_ms: u64) !Peers {
        assert(retention_ms > 0);
        const rows = try a.alloc(Row, capacity);
        errdefer a.free(rows);
        @memset(rows, .{});
        const backoffs = try a.alloc(Backoff, capacity * constants.topics_cap);
        @memset(backoffs, .{});
        return .{ .rows = rows, .backoffs = backoffs, .retention_ms = retention_ms };
    }

    pub fn deinit(self: *Peers, a: std.mem.Allocator) void {
        a.free(self.backoffs);
        a.free(self.rows);
        self.* = undefined;
    }

    pub fn matches(self: *const Peers, ref: Ref) bool {
        return ref.index < self.rows.len and self.rows[ref.index].occupied and
            self.rows[ref.index].generation == ref.generation;
    }

    pub fn find(self: *const Peers, identity: *const PeerId) ?Ref {
        for (self.rows, 0..) |*row, i| {
            if (row.occupied and row.identity.eql(identity)) return .{ .index = @intCast(i), .generation = row.generation };
        }
        return null;
    }

    pub fn admit(self: *Peers, conn: Handle, metadata: *const Metadata, now: u64) Admission {
        var expired: ?usize = null;
        if (self.find(&metadata.identity)) |ref| {
            const row = &self.rows[ref.index];
            if (row.connection != null) return .duplicate;
            if (row.pins > 0 or now < row.retain_until) {
                self.connect(row, conn, metadata);
                return .{ .admitted = .{ .peer = ref, .fresh = false, .penalty_evicted = false } };
            }
            if (row.generation != std.math.maxInt(u64)) expired = ref.index;
            row.occupied = false;
        }
        const index = expired orelse self.reclaimable(metadata.direction, now) orelse return .capacity;
        const row = &self.rows[index];
        assert(row.connection == null and row.pins == 0);
        const penalty_evicted = row.occupied and row.negative and now < row.retain_until;
        @memset(self.backoffs[index * constants.topics_cap ..][0..constants.topics_cap], .{});
        row.* = .{ .generation = row.generation + 1, .occupied = true, .identity = metadata.identity };
        self.connect(row, conn, metadata);
        return .{ .admitted = .{
            .peer = .{ .index = @intCast(index), .generation = row.generation },
            .fresh = true,
            .penalty_evicted = penalty_evicted,
        } };
    }

    fn connect(_: *Peers, row: *Row, conn: Handle, metadata: *const Metadata) void {
        row.connection = conn;
        row.address = normalize(metadata.address);
        row.direction = metadata.direction;
    }

    fn reclaimable(self: *const Peers, direction: types.Direction, now: u64) ?usize {
        var reusable: ?usize = null;
        var negative: ?usize = null;
        const limit: usize = if (direction == .outbound) capacity else capacity - outbound_reserve;
        for (self.rows[0..limit], 0..) |row, i| {
            if (row.connection != null or row.pins != 0 or row.generation == std.math.maxInt(u64)) continue;
            if (!row.occupied or now >= row.retain_until) return i;
            if (!row.negative) {
                if (reusable == null or row.disconnected_at < self.rows[reusable.?].disconnected_at) reusable = i;
            } else if (negative == null or row.disconnected_at < self.rows[negative.?].disconnected_at) negative = i;
        }
        return reusable orelse if (direction == .outbound) negative else null;
    }

    pub fn disconnect(self: *Peers, ref: Ref, now: u64, negative: bool) void {
        assert(self.matches(ref));
        const row = &self.rows[ref.index];
        assert(row.connection != null);
        row.connection = null;
        row.disconnected_at = now;
        row.retain_until = now +| self.retention_ms;
        row.negative = negative;
        // Topic reclamation cannot reuse a generation while its backoff is live.
        for (self.backoffs[@as(usize, ref.index) * constants.topics_cap ..][0..constants.topics_cap]) |entry| {
            row.retain_until = @max(row.retain_until, entry.until);
            if (entry.topic_generation != 0 and now < entry.until) row.negative = true;
        }
    }

    pub fn retain(self: *Peers, ref: Ref) void {
        assert(self.matches(ref));
        assert(self.rows[ref.index].pins < std.math.maxInt(u32));
        self.rows[ref.index].pins += 1;
    }

    pub fn release(self: *Peers, ref: Ref) void {
        assert(self.matches(ref));
        assert(self.rows[ref.index].pins > 0);
        self.rows[ref.index].pins -= 1;
    }

    pub fn backoff(self: *Peers, ref: Ref, topic: u16) *Backoff {
        assert(self.matches(ref));
        assert(topic < constants.topics_cap);
        return &self.backoffs[@as(usize, ref.index) * constants.topics_cap + topic];
    }

    pub fn addBackoff(self: *Peers, ref: Ref, topic: u16, generation: u64, now: u64, duration_ms: u64) void {
        const entry = self.backoff(ref, topic);
        if (entry.topic_generation != generation) entry.* = .{ .topic_generation = generation };
        entry.until = @max(entry.until, now +| @min(duration_ms, 3_600_000));
        entry.pruned_at = now;
        self.rows[ref.index].negative = true;
    }

    pub fn backedOff(self: *Peers, ref: Ref, topic: u16, generation: u64, now: u64) bool {
        const entry = self.backoff(ref, topic);
        return entry.topic_generation == generation and now < entry.until;
    }

    pub fn migrate(self: *Peers, conn: Handle, address: types.Address) void {
        for (self.rows) |*row| {
            if (row.connection) |current| if (std.meta.eql(current, conn)) {
                row.address = normalize(address);
                return;
            };
        }
    }

    pub fn ipCount(self: *const Peers, ref: Ref, allowlist: []const Ip) u16 {
        assert(self.matches(ref));
        assert(allowlist.len <= 32);
        const row = &self.rows[ref.index];
        if (row.connection == null) return 0;
        for (allowlist) |ip| if (std.mem.eql(u8, &ip, &row.address)) return 0;
        var count: u16 = 0;
        for (self.rows) |other| {
            if (other.connection != null and std.mem.eql(u8, &row.address, &other.address)) count += 1;
        }
        return count;
    }
};

/// Full IP grouping, ignoring ports and scopes. Mapped IPv6 and IPv4 share one group.
pub fn normalize(address: types.Address) Ip {
    return switch (address) {
        .ip4 => |ip| [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ ip.octets,
        .ip6 => |ip| ip.octets,
    };
}

test "gossip policy peers retain identity and reserve outbound recovery under negative churn" {
    var peers = try Peers.init(std.testing.allocator, 10_000);
    defer peers.deinit(std.testing.allocator);
    var metadata: Metadata = .{ .identity = undefined, .address = .unspecified, .direction = .inbound };
    for (0..capacity) |i| {
        metadata.identity.bytes = [_]u8{0} ** @import("../wire/peer_id.zig").length;
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        if (i == capacity - outbound_reserve) {
            try std.testing.expectEqual(Admission.capacity, peers.admit(.{ .index = 0, .generation = 1 }, &metadata, i));
            metadata.direction = .outbound;
        }
        const result = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, i).admitted;
        peers.disconnect(result.peer, i, true);
    }
    metadata.identity.bytes[2] = 1;
    metadata.direction = .inbound;
    try std.testing.expectEqual(Admission.capacity, peers.admit(.{ .index = 0, .generation = 1 }, &metadata, 1000));
    const pinned: Ref = .{ .index = 0, .generation = peers.rows[0].generation };
    peers.retain(pinned);
    metadata.direction = .outbound;
    const fallback = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, 1000).admitted;
    try std.testing.expect(fallback.penalty_evicted);
    try std.testing.expectEqual(@as(u16, 1), fallback.peer.index);
    try std.testing.expectEqual(Admission.duplicate, peers.admit(.{ .index = 1, .generation = 1 }, &metadata, 1001));
    peers.disconnect(fallback.peer, 1001, true);
    const resumed = peers.admit(.{ .index = 2, .generation = 1 }, &metadata, 1002).admitted;
    try std.testing.expect(!resumed.fresh);
    try std.testing.expectEqual(fallback.peer, resumed.peer);
    peers.release(pinned);
}

test "gossip policy IP colocation normalizes ports mapping and current path generation" {
    var peers = try Peers.init(std.testing.allocator, 100);
    defer peers.deinit(std.testing.allocator);
    const first_conn: Handle = .{ .index = 0, .generation = 1 };
    const first: Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } }, .direction = .inbound };
    var second = first;
    second.identity.bytes[0] = 2;
    second.address = .{ .ip6 = .{ .octets = normalize(first.address), .port = 2 } };
    const a = peers.admit(first_conn, &first, 0).admitted.peer;
    const b = peers.admit(.{ .index = 1, .generation = 1 }, &second, 0).admitted.peer;
    try std.testing.expectEqual(@as(u16, 2), peers.ipCount(a, &.{}));
    try std.testing.expectEqual(@as(u16, 2), peers.ipCount(b, &.{}));
    try std.testing.expectEqual(@as(u16, 0), peers.ipCount(a, &.{normalize(first.address)}));
    try std.testing.expectEqual(Admission.duplicate, peers.admit(.{ .index = 2, .generation = 1 }, &first, 0));
    peers.migrate(.{ .index = 0, .generation = 2 }, .unspecified);
    try std.testing.expectEqual(@as(u16, 2), peers.ipCount(a, &.{}));
    peers.migrate(first_conn, .unspecified);
    try std.testing.expectEqual(@as(u16, 1), peers.ipCount(a, &.{}));
    try std.testing.expectEqual(@as(u16, 1), peers.ipCount(b, &.{}));
}

test "gossip policy identity generation exhaustion cannot revive stale references" {
    var peers = try Peers.init(std.testing.allocator, 100);
    defer peers.deinit(std.testing.allocator);
    peers.rows[0].generation = std.math.maxInt(u64);
    const metadata: Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
    const first = peers.admit(.{ .index = 0, .generation = 1 }, &metadata, 0).admitted.peer;
    try std.testing.expectEqual(@as(u16, 1), first.index);
    peers.disconnect(first, 0, true);
    const next = peers.admit(.{ .index = 0, .generation = 2 }, &metadata, 100).admitted.peer;
    try std.testing.expectEqual(first.index, next.index);
    try std.testing.expectEqual(first.generation + 1, next.generation);
    try std.testing.expect(!peers.matches(first));
}

test "gossip policy review I1 live backoff prevents immediate inbound eviction" {
    var peers = try Peers.init(std.testing.allocator, 100_000);
    defer peers.deinit(std.testing.allocator);
    var metadata: Metadata = .{ .identity = .{ .bytes = [_]u8{0} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
    const connection: Handle = .{ .index = 0, .generation = 1 };
    for (0..capacity - outbound_reserve) |i| {
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        const ref = peers.admit(connection, &metadata, i).admitted.peer;
        if (i == 0) peers.addBackoff(ref, 0, 1, 0, 60_000);
        peers.disconnect(ref, i, i != 0);
    }
    const original: Ref = .{ .index = 0, .generation = peers.rows[0].generation };
    metadata.identity.bytes[2] = 1;
    try std.testing.expectEqual(Admission.capacity, peers.admit(connection, &metadata, 1000));
    try std.testing.expect(peers.backedOff(original, 0, 1, 1000));
    metadata.identity = peers.rows[0].identity;
    const resumed = peers.admit(connection, &metadata, 1000).admitted;
    try std.testing.expect(!resumed.fresh);
    try std.testing.expectEqual(original, resumed.peer);
    try std.testing.expect(peers.backedOff(original, 0, 1, 1000));
    peers.disconnect(resumed.peer, 1000, false);
    metadata.direction = .outbound;
    metadata.identity.bytes[2] = 1;
    for (0..outbound_reserve) |i| {
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        const ref = peers.admit(connection, &metadata, 1001 + i).admitted.peer;
        peers.disconnect(ref, 1001 + i, true);
    }
    metadata.identity.bytes[2] = 2;
    const fallback = peers.admit(connection, &metadata, 1100).admitted;
    try std.testing.expect(fallback.penalty_evicted);
    try std.testing.expect(fallback.peer.index != 0);
    try std.testing.expect(peers.backedOff(original, 0, 1, 1100));
}
