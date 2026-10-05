const std = @import("std");
const constants = @import("constants.zig");
const topic = @import("topic.zig");
const PeerSet = @import("sessions.zig").PeerSet;
const assert = std.debug.assert;
const ForkSeq = @import("config").ForkSeq;

pub const boundary_max = 64;
pub const topics_per_boundary_max = 333;
pub const topic_max = boundary_max * topics_per_boundary_max;
pub const Kind = topic.Kind;
pub const kind_count = @typeInfo(Kind).@"enum".fields.len;
pub const Rule = struct { count: u16 = 0, ssz_min: u32 = 0, ssz_max: u32 = 0 };
pub const Boundary = struct { digest: [4]u8, fork: ?ForkSeq = null, epoch: u64 = 0, rules: [kind_count]Rule = @splat(.{}) };
pub const Match = struct { ordinal: u16, rule: Rule };
pub const Error = error{InvalidTopicPolicy};

pub const Subnets = struct {
    attnets: u64 = 0,
    syncnets: u4 = 0,
    columns: std.StaticBitSet(128) = .empty,
    column_subnet_count: u16 = 0,

    pub fn add(self: *Subnets, name: topic.Name) void {
        switch (name.kind) {
            .beacon_attestation => self.attnets |= @as(u64, 1) << @intCast(name.subnet),
            .sync_committee => self.syncnets |= @as(u4, 1) << @intCast(name.subnet),
            .data_column_sidecar => self.columns.set(name.subnet),
            else => {},
        }
    }
};

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
    subscriber_counts: []u16,
    subscription_count: usize = 0,
    topic_count: u16,
    connected_capacity: u16,
    words_per_peer: usize,
    revision: u64 = 0,

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

        const subscriber_counts = try a.alloc(u16, count);
        errdefer a.free(subscriber_counts);
        @memset(subscriber_counts, 0);

        var offset: u16 = 0;
        for (boundaries, offsets) |*boundary, *starts| {
            for (boundary.rules, starts) |rule, *start| {
                start.* = offset;
                offset += rule.count;
            }
        }
        assert(offset == count);
        @memset(subscriptions, 0);
        return .{ .boundaries = boundaries, .offsets = offsets, .subscriptions = subscriptions, .subscriber_counts = subscriber_counts, .topic_count = count, .connected_capacity = connected_capacity, .words_per_peer = words_per_peer };
    }

    pub fn deinit(self: *Namespace, a: std.mem.Allocator) void {
        a.free(self.subscriber_counts);
        a.free(self.subscriptions);
        a.free(self.offsets);
        a.free(self.boundaries);
        self.* = undefined;
    }

    pub fn allocatedBytes(self: *const Namespace) usize {
        return self.boundaries.len * @sizeOf(Boundary) + self.offsets.len * @sizeOf([kind_count]u16) + self.subscriptions.len * @sizeOf(u64) + self.subscriber_counts.len * @sizeOf(u16);
    }

    pub fn backingBytes(input: []const Boundary, connected_capacity: u16) usize {
        var count: usize = 0;
        for (input) |*boundary| for (boundary.rules) |rule| {
            count += rule.count;
        };
        return input.len * (@sizeOf(Boundary) + @sizeOf([kind_count]u16)) +
            subscriptionWords(count, connected_capacity) * @sizeOf(u64) + count * @sizeOf(u16);
    }

    fn subscriptionWords(topics: usize, peers: u16) usize {
        assert(topics <= topic_max and peers <= constants.peers_cap);
        return @as(usize, peers) * ((topics + 63) / 64);
    }

    pub fn lookup(self: *const Namespace, name: []const u8) ?Match {
        return self.lookupCanonical(topic.parseCanonical(name) orelse return null);
    }

    pub fn lookupCanonical(self: *const Namespace, parsed: topic.Canonical) ?Match {
        const k = @intFromEnum(parsed.name.kind);
        for (self.boundaries, self.offsets) |*boundary, *starts| {
            if (!std.mem.eql(u8, &boundary.digest, &parsed.digest)) continue;
            const rule = boundary.rules[k];
            if (parsed.name.subnet >= rule.count) return null;
            return .{ .ordinal = starts[k] + parsed.name.subnet, .rule = rule };
        }
        return null;
    }

    pub fn topicAt(self: *const Namespace, ordinal: u16) topic.Canonical {
        assert(ordinal < self.topic_count);
        for (self.boundaries, self.offsets) |*boundary, *starts| {
            for (boundary.rules, starts, 0..) |rule, start, k| {
                if (ordinal >= start and ordinal - start < rule.count)
                    return .{ .digest = boundary.digest, .name = .{ .kind = @enumFromInt(k), .subnet = ordinal - start } };
            }
        }
        unreachable;
    }

    pub fn setSubscription(self: *Namespace, peer: u16, ordinal: u16, subscribed_value: bool) void {
        assert(peer < self.connected_capacity and ordinal < self.topic_count);
        const word = &self.subscriptions[@as(usize, peer) * self.words_per_peer + ordinal / 64];
        const mask = @as(u64, 1) << @as(u6, @intCast(ordinal % 64));
        if ((word.* & mask != 0) == subscribed_value) return;
        if (subscribed_value) {
            assert(self.subscriber_counts[ordinal] < self.connected_capacity);
            word.* |= mask;
            self.subscriber_counts[ordinal] += 1;
            self.subscription_count += 1;
        } else {
            assert(self.subscriber_counts[ordinal] > 0 and self.subscription_count > 0);
            word.* &= ~mask;
            self.subscriber_counts[ordinal] -= 1;
            self.subscription_count -= 1;
        }
        self.revision +|= 1;
    }

    pub fn subscribed(self: *const Namespace, peer: u16, ordinal: u16) bool {
        assert(peer < self.connected_capacity and ordinal < self.topic_count);
        return self.subscriptions[@as(usize, peer) * self.words_per_peer + ordinal / 64] & (@as(u64, 1) << @as(u6, @intCast(ordinal % 64))) != 0;
    }

    pub fn clearPeer(self: *Namespace, peer: u16) void {
        assert(peer < self.connected_capacity);
        const words = self.subscriptions[@as(usize, peer) * self.words_per_peer ..][0..self.words_per_peer];
        if (std.mem.allEqual(u64, words, 0)) return;
        for (words, 0..) |bits, index| {
            var remaining = bits;
            for (0..64) |_| {
                if (remaining == 0) break;
                const ordinal = index * 64 + @as(usize, @ctz(remaining));
                assert(ordinal < self.topic_count and self.subscriber_counts[ordinal] > 0);
                self.subscriber_counts[ordinal] -= 1;
                self.subscription_count -= 1;
                remaining &= remaining - 1;
            }
        }
        @memset(words, 0);
        self.revision +|= 1;
    }

    pub fn subnets(self: *const Namespace, peer: u16, digest: [4]u8) Subnets {
        assert(peer < self.connected_capacity);
        var result: Subnets = .{};
        for (self.boundaries, self.offsets) |*boundary, *starts| {
            if (!std.mem.eql(u8, &boundary.digest, &digest)) continue;
            result.column_subnet_count = boundary.rules[@intFromEnum(Kind.data_column_sidecar)].count;
            inline for (.{ Kind.beacon_attestation, Kind.sync_committee, Kind.data_column_sidecar }) |kind| {
                const k = @intFromEnum(kind);
                for (0..boundary.rules[k].count) |subnet| {
                    if (self.subscribed(peer, starts[k] + @as(u16, @intCast(subnet))))
                        result.add(.{ .kind = kind, .subnet = @intCast(subnet) });
                }
            }
            break;
        }
        return result;
    }

    pub fn initializeSubscribers(self: *const Namespace, ordinal: u16, out: *PeerSet) void {
        assert(ordinal < self.topic_count);
        out.* = .empty;
        for (0..self.connected_capacity) |peer| if (self.subscribed(@intCast(peer), ordinal)) out.set(peer);
    }
};

test {
    _ = @import("topic_policy_lifecycle_test.zig");
    _ = @import("topic_policy_test.zig");
}
