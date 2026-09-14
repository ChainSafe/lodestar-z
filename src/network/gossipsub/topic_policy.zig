const std = @import("std");
const constants = @import("constants.zig");
const topic = @import("topic.zig");
const PeerSet = @import("sessions.zig").PeerSet;
const assert = std.debug.assert;

pub const boundary_max = 64;
pub const topics_per_boundary_max = 333;
pub const topic_max = boundary_max * topics_per_boundary_max;
pub const Kind = topic.Kind;
pub const kind_count = @typeInfo(Kind).@"enum".fields.len;
pub const Rule = struct { count: u16 = 0, ssz_min: u32 = 0, ssz_max: u32 = 0 };
pub const Boundary = struct { digest: [4]u8, rules: [kind_count]Rule = @splat(.{}) };
pub const Match = struct { ordinal: u16, rule: Rule };
pub const Error = error{InvalidTopicPolicy};

pub fn validate(boundaries: []const Boundary) Error!u16 {
    if (boundaries.len == 0 or boundaries.len > boundary_max) return error.InvalidTopicPolicy;
    var count: u16 = 0;
    for (boundaries, 0..) |*boundary, index| {
        for (boundaries[0..index]) |*prior| if (std.mem.eql(u8, &prior.digest, &boundary.digest)) return error.InvalidTopicPolicy;
        const before = count;
        for (boundary.rules, 0..) |rule, k| {
            const kind: Kind = @enumFromInt(k);
            if (rule.count > kind.countMax() or rule.ssz_min > rule.ssz_max or rule.ssz_max > constants.MAX_PAYLOAD_SIZE or
                (rule.count == 0 and (rule.ssz_min != 0 or rule.ssz_max != 0))) return error.InvalidTopicPolicy;
            count = std.math.add(u16, count, rule.count) catch return error.InvalidTopicPolicy;
        }
        if (count == before) return error.InvalidTopicPolicy;
    }
    assert(count <= topic_max);
    return count;
}

pub const Namespace = struct {
    boundaries: []const Boundary,
    offsets: []const [kind_count]u16,
    subscriptions: []u64,
    topic_count: u16,
    connected_capacity: u16,
    words_per_peer: usize,

    pub fn init(a: std.mem.Allocator, input: []const Boundary, connected_capacity: u16) (std.mem.Allocator.Error || Error)!Namespace {
        const count = try validate(input);
        if (connected_capacity == 0 or connected_capacity > constants.peers_cap) return error.InvalidTopicPolicy;
        const words_per_peer = (@as(usize, count) + 63) / 64;
        const word_count = subscriptionWords(count, connected_capacity);
        const boundaries = try a.dupe(Boundary, input);
        errdefer a.free(boundaries);

        const offsets = try a.alloc([kind_count]u16, input.len);
        errdefer a.free(offsets);

        const subscriptions = try a.alloc(u64, word_count);
        errdefer a.free(subscriptions);

        var offset: u16 = 0;
        for (boundaries, offsets) |*boundary, *starts| {
            for (boundary.rules, starts) |rule, *start| {
                start.* = offset;
                offset += rule.count;
            }
        }
        assert(offset == count);
        @memset(subscriptions, 0);
        return .{ .boundaries = boundaries, .offsets = offsets, .subscriptions = subscriptions, .topic_count = count, .connected_capacity = connected_capacity, .words_per_peer = words_per_peer };
    }

    pub fn deinit(self: *Namespace, a: std.mem.Allocator) void {
        a.free(self.subscriptions);
        a.free(self.offsets);
        a.free(self.boundaries);
        self.* = undefined;
    }

    pub fn allocatedBytes(self: *const Namespace) usize {
        return self.boundaries.len * @sizeOf(Boundary) + self.offsets.len * @sizeOf([kind_count]u16) + self.subscriptions.len * @sizeOf(u64);
    }

    pub fn backingBytes(input: []const Boundary, connected_capacity: u16) usize {
        var count: usize = 0;
        for (input) |*boundary| for (boundary.rules) |rule| {
            count += rule.count;
        };
        return input.len * (@sizeOf(Boundary) + @sizeOf([kind_count]u16)) +
            subscriptionWords(count, connected_capacity) * @sizeOf(u64);
    }

    fn subscriptionWords(topics: usize, peers: u16) usize {
        assert(topics <= topic_max and peers <= constants.peers_cap);
        return @as(usize, peers) * ((topics + 63) / 64);
    }

    pub fn lookup(self: *const Namespace, name: []const u8) ?Match {
        const parsed = topic.parseCanonical(name) orelse return null;
        const k = @intFromEnum(parsed.name.kind);
        for (self.boundaries, self.offsets) |*boundary, *starts| {
            if (!std.mem.eql(u8, &boundary.digest, &parsed.digest)) continue;
            const rule = boundary.rules[k];
            if (parsed.name.subnet >= rule.count) return null;
            return .{ .ordinal = starts[k] + parsed.name.subnet, .rule = rule };
        }
        return null;
    }

    pub fn setSubscription(self: *Namespace, peer: u16, ordinal: u16, subscribed_value: bool) void {
        assert(peer < self.connected_capacity and ordinal < self.topic_count);
        const word = &self.subscriptions[@as(usize, peer) * self.words_per_peer + ordinal / 64];
        const mask = @as(u64, 1) << @as(u6, @intCast(ordinal % 64));
        if (subscribed_value) word.* |= mask else word.* &= ~mask;
    }

    pub fn subscribed(self: *const Namespace, peer: u16, ordinal: u16) bool {
        assert(peer < self.connected_capacity and ordinal < self.topic_count);
        return self.subscriptions[@as(usize, peer) * self.words_per_peer + ordinal / 64] & (@as(u64, 1) << @as(u6, @intCast(ordinal % 64))) != 0;
    }

    pub fn clearPeer(self: *Namespace, peer: u16) void {
        assert(peer < self.connected_capacity);
        @memset(self.subscriptions[@as(usize, peer) * self.words_per_peer ..][0..self.words_per_peer], 0);
    }

    pub fn initializeSubscribers(self: *const Namespace, ordinal: u16, out: *PeerSet) void {
        assert(ordinal < self.topic_count);
        out.* = .initEmpty();
        for (0..self.connected_capacity) |peer| if (self.subscribed(@intCast(peer), ordinal)) out.set(peer);
    }
};
