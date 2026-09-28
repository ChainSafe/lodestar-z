const std = @import("std");
const constants = @import("constants.zig");
const types = @import("../types.zig");
const Handle = @import("../quic/engine.zig").Handle;
const PeerId = @import("../wire/peer_id.zig").PeerId;
const assert = std.debug.assert;

pub const capacity = constants.retained_peers_cap;
pub const outbound_reserve = 32;
pub const Ref = struct { index: u16, generation: u64 };
pub const Backoff = struct { until: u64 = 0, topic_generation: u64 = 0 };
pub const Ip = [16]u8;
pub const Metadata = struct {
    identity: PeerId,
    address: types.Address,
    direction: types.Direction,
    direct: bool = false,
};
pub const Row = struct {
    generation: u64 = 0,
    occupied: bool = false,
    identity: PeerId = undefined,
    connection: ?Handle = null,
    address: Ip = [_]u8{0} ** 16,
    direction: types.Direction = .inbound,
    pins: u32 = 0,
    ip_peers: u16 = 0,
    retain_until: u64 = 0,
    large_frame_denied_until: u64 = 0,
    disconnected_at: u64 = 0,
    negative: bool = false,
    direct: bool = false,
};
pub const Admission = union(enum) {
    admitted: struct { peer: Ref, fresh: bool },
    duplicate,
    capacity,
};

pub const PeerBook = struct {
    scores: @import("score.zig").PeerScore,
    ip_allowlist: [32]Ip = undefined,
    ip_allowlist_len: u8 = 0,
    rows: []Row,
    backoffs: []Backoff,
    retention_ms: u64,
    reserved: u16,

    pub fn init(a: std.mem.Allocator, options: *const @import("options.zig").Options) !PeerBook {
        const retention_ms = options.retained_score_ms;
        const count = options.retained_capacity;
        const reserved = options.retained_outbound_reserve;
        if (options.ip_allowlist.len > 32) return error.InvalidLimits;
        if (count == 0 or count > capacity or reserved >= count) return error.InvalidLimits;
        assert(retention_ms > 0);
        const rows = try a.alloc(Row, count);
        errdefer a.free(rows);
        @memset(rows, .{});
        const backoffs = try a.alloc(Backoff, @as(usize, count) * constants.topics_cap);
        errdefer a.free(backoffs);
        @memset(backoffs, .{});
        const scores = try @import("score.zig").PeerScore.init(a, options.score_params, count);
        var book: PeerBook = .{ .rows = rows, .backoffs = backoffs, .scores = scores, .retention_ms = retention_ms, .reserved = reserved };
        @memcpy(book.ip_allowlist[0..options.ip_allowlist.len], options.ip_allowlist);
        book.ip_allowlist_len = @intCast(options.ip_allowlist.len);
        return book;
    }

    pub fn deinit(self: *PeerBook, a: std.mem.Allocator) void {
        self.scores.deinit(a);
        a.free(self.backoffs);
        a.free(self.rows);
        self.* = undefined;
    }

    pub fn matches(self: *const PeerBook, ref: Ref) bool {
        return ref.index < self.rows.len and self.rows[ref.index].occupied and
            self.rows[ref.index].generation == ref.generation;
    }

    pub fn find(self: *const PeerBook, identity: *const PeerId) ?Ref {
        for (self.rows, 0..) |*row, i| {
            if (row.occupied and row.identity.eql(identity)) return .{ .index = @intCast(i), .generation = row.generation };
        }
        return null;
    }

    pub fn admit(self: *PeerBook, conn: Handle, metadata: *const Metadata, now: u64) Admission {
        var expired: ?usize = null;
        if (self.find(&metadata.identity)) |ref| {
            const row = &self.rows[ref.index];
            if (row.connection != null) return .duplicate;
            if (row.pins > 0 or now < row.retain_until) {
                self.connect(ref.index, conn, metadata, now);
                return .{ .admitted = .{ .peer = ref, .fresh = false } };
            }
            if (row.generation != std.math.maxInt(u64)) expired = ref.index;
            row.occupied = false;
        }
        const index = expired orelse self.reclaimable(metadata.direction, now) orelse return .capacity;
        const row = &self.rows[index];
        assert(row.connection == null and row.pins == 0);
        @memset(self.backoffs[index * constants.topics_cap ..][0..constants.topics_cap], .{});
        row.* = .{ .generation = row.generation + 1, .occupied = true, .identity = metadata.identity };
        self.scores.resetPeer(@intCast(index));
        self.connect(@intCast(index), conn, metadata, now);
        return .{ .admitted = .{
            .peer = .{ .index = @intCast(index), .generation = row.generation },
            .fresh = true,
        } };
    }

    fn connect(self: *PeerBook, index: u16, conn: Handle, metadata: *const Metadata, now: u64) void {
        const row = &self.rows[index];
        self.scores.setConnected(index, true, now);
        row.connection = conn;
        row.address = normalize(metadata.address);
        row.direction = metadata.direction;
        row.direct = metadata.direct;
        self.addIp(index);
    }

    fn reclaimable(self: *const PeerBook, direction: types.Direction, now: u64) ?usize {
        var reusable: ?usize = null;
        var negative: ?usize = null;
        const limit: usize = if (direction == .outbound) self.rows.len else self.rows.len - self.reserved;
        for (self.rows[0..limit], 0..) |row, i| {
            if (row.connection != null or row.pins != 0 or row.generation == std.math.maxInt(u64)) continue;
            if (!row.occupied or now >= row.retain_until) return i;
            if (!row.negative) {
                if (reusable == null or row.disconnected_at < self.rows[reusable.?].disconnected_at) reusable = i;
            } else if (negative == null or row.disconnected_at < self.rows[negative.?].disconnected_at) negative = i;
        }
        return reusable orelse negative;
    }

    pub fn disconnect(self: *PeerBook, ref: Ref, now: u64) void {
        assert(self.matches(ref));
        const row = &self.rows[ref.index];
        assert(row.connection != null);
        self.scores.setConnected(ref.index, false, now);
        self.removeIp(ref.index);
        row.connection = null;
        row.disconnected_at = now;
        row.retain_until = now +| self.retention_ms;
        row.negative = self.score(ref, now) < 0;
        // Topic reclamation cannot reuse a generation while its backoff is live.
        for (self.backoffs[@as(usize, ref.index) * constants.topics_cap ..][0..constants.topics_cap]) |entry| {
            row.retain_until = @max(row.retain_until, entry.until);
            if (entry.topic_generation != 0 and now < entry.until) row.negative = true;
        }
    }

    pub fn score(self: *PeerBook, ref: Ref, now: u64) f64 {
        return self.scores.score(ref.index, now, self.scorePopulation(ref));
    }

    fn scorePopulation(self: *const PeerBook, ref: Ref) u16 {
        assert(self.matches(ref));
        if (self.scores.params.ip_colocation_weight == 0) return 0;
        return self.ipCount(ref, self.ip_allowlist[0..self.ip_allowlist_len]);
    }

    pub fn snapshot(self: *const PeerBook, ref: Ref, now: u64) f64 {
        return self.scores.snapshot(ref.index, now, self.scorePopulation(ref));
    }

    pub fn snapshotWeights(self: *const PeerBook, ref: Ref, now: u64, out: *@import("score.zig").Breakdown) f64 {
        return self.scores.snapshotWeights(ref.index, now, self.scorePopulation(ref), out);
    }

    pub fn backingBytes(count: usize) usize {
        return count * (@sizeOf(Row) + constants.topics_cap * @sizeOf(Backoff)) + @import("score.zig").PeerScore.backingBytes(count);
    }

    pub fn invalid(self: *PeerBook, ref: Ref, topic: u16) void {
        assert(self.matches(ref));
        self.scores.invalid(ref.index, topic);
        self.rows[ref.index].negative = true;
    }

    pub fn penalize(self: *PeerBook, ref: Ref, violation: @import("score.zig").Penalty) void {
        assert(self.matches(ref));
        self.scores.penalizeFor(ref.index, violation);
        self.rows[ref.index].negative = true;
    }

    pub fn refresh(self: *PeerBook, now: u64) void {
        for (self.rows, 0..) |row, i| {
            if (!row.occupied) continue;
            const ref: Ref = .{ .index = @intCast(i), .generation = row.generation };
            if (row.connection == null) {
                var useful = self.score(ref, now) < 0;
                for (self.backoffs[i * constants.topics_cap ..][0..constants.topics_cap]) |entry| {
                    if (now < entry.until) useful = true;
                }
                self.rows[i].negative = useful;
            }
            if (row.connection == null and row.pins == 0 and now >= row.retain_until) {
                self.scores.resetPeer(@intCast(i));
                self.rows[i].occupied = false;
                @memset(self.backoffs[i * constants.topics_cap ..][0..constants.topics_cap], .{});
            }
        }
        self.scores.refresh(now);
    }

    pub fn retain(self: *PeerBook, ref: Ref) void {
        assert(self.matches(ref));
        assert(self.rows[ref.index].pins < std.math.maxInt(u32));
        self.rows[ref.index].pins += 1;
    }

    pub fn release(self: *PeerBook, ref: Ref) void {
        assert(self.matches(ref));
        assert(self.rows[ref.index].pins > 0);
        self.rows[ref.index].pins -= 1;
    }

    pub fn backoff(self: *PeerBook, ref: Ref, topic: u16) *Backoff {
        assert(self.matches(ref));
        assert(topic < constants.topics_cap);
        return &self.backoffs[@as(usize, ref.index) * constants.topics_cap + topic];
    }

    pub fn addBackoff(self: *PeerBook, ref: Ref, topic: u16, generation: u64, now: u64, duration_ms: u64) void {
        const entry = self.backoff(ref, topic);
        if (entry.topic_generation != generation) entry.* = .{ .topic_generation = generation };
        entry.until = @max(entry.until, now +| @min(duration_ms, 3_600_000));
        self.rows[ref.index].negative = true;
    }

    pub fn backedOff(self: *PeerBook, ref: Ref, topic: u16, generation: u64, now: u64) bool {
        const entry = self.backoff(ref, topic);
        return entry.topic_generation == generation and now < entry.until;
    }

    pub fn migrate(self: *PeerBook, conn: Handle, address: types.Address) void {
        for (self.rows, 0..) |*row, index| {
            if (row.connection) |current| if (std.meta.eql(current, conn)) {
                self.removeIp(index);
                row.address = normalize(address);
                self.addIp(index);
                return;
            };
        }
    }

    fn addIp(self: *PeerBook, index: usize) void {
        const row = &self.rows[index];
        assert(row.connection != null and row.ip_peers == 0);
        for (self.rows, 0..) |*other, i| {
            if (other.connection == null or !std.mem.eql(u8, &row.address, &other.address)) continue;
            row.ip_peers += 1;
            if (i != index) other.ip_peers += 1;
        }
    }

    fn removeIp(self: *PeerBook, index: usize) void {
        const row = &self.rows[index];
        assert(row.connection != null and row.ip_peers > 0);
        for (self.rows, 0..) |*other, i| {
            if (i == index or other.connection == null or !std.mem.eql(u8, &row.address, &other.address)) continue;
            assert(other.ip_peers > 0);
            other.ip_peers -= 1;
        }
        row.ip_peers = 0;
    }

    pub fn ipCount(self: *const PeerBook, ref: Ref, allowlist: []const Ip) u16 {
        assert(self.matches(ref));
        assert(allowlist.len <= 32);
        const row = &self.rows[ref.index];
        if (row.connection == null) return 0;
        for (allowlist) |ip| if (std.mem.eql(u8, &ip, &row.address)) return 0;
        return row.ip_peers;
    }
};

/// Full IP grouping, ignoring ports and scopes. Mapped IPv6 and IPv4 share one group.
pub fn normalize(address: types.Address) Ip {
    return switch (address) {
        .ip4 => |ip| [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ ip.octets,
        .ip6 => |ip| ip.octets,
    };
}

test {
    _ = @import("peer_book_test.zig");
}
