//! TS-compatible discv5 packet rate limiter.

const std = @import("std");
const Allocator = std.mem.Allocator;

const lru = @import("lru.zig");
const Address = std.Io.net.IpAddress;

pub const RateLimiterQuota = struct {
    /// How often `max_tokens` fully replenish, in milliseconds.
    replenish_all_every_ms: u64,
    /// Instantaneous burst token limit.
    max_tokens: u32,
};

pub const Config = struct {
    global_quota: RateLimiterQuota,
    by_ip_quota: RateLimiterQuota,
    /// State keyed by packet source IP is attacker-controlled, so keep it
    /// bounded even when a peer sprays many spoofed or rotating addresses.
    by_ip_state_capacity: usize = 4096,
    banned_ip_capacity: usize = 4096,
};

pub const Stats = struct {
    rate_limit_hit_ip_total: u64 = 0,
    rate_limit_hit_total: u64 = 0,
};

const banned_ip_duration_ms: u64 = 60_000;

pub const IpKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    pub fn fromAddress(addr: Address) IpKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }
};

pub fn RateLimiterGcra(comptime Key: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        tat_per_key: lru.LruCache(Key, f64),
        tau_ms: f64,
        token_interval_ms: f64,
        ttl_ms: u64,

        pub fn fromQuota(allocator: Allocator, quota: RateLimiterQuota, capacity: usize) !Self {
            if (quota.max_tokens == 0) return error.InvalidRateLimiterQuota;
            if (quota.replenish_all_every_ms == 0) return error.InvalidRateLimiterQuota;
            const tau_ms: f64 = @floatFromInt(quota.replenish_all_every_ms);
            const max_tokens: f64 = @floatFromInt(quota.max_tokens);
            return .{
                .allocator = allocator,
                .tat_per_key = try lru.LruCache(Key, f64).init(allocator, capacity),
                .tau_ms = tau_ms,
                .token_interval_ms = tau_ms / max_tokens,
                .ttl_ms = quota.replenish_all_every_ms,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tat_per_key.deinit(self.allocator);
        }

        pub fn allows(self: *Self, key: Key, tokens: u32, ms_since_start: u64) bool {
            const additional_time = self.token_interval_ms * @as(f64, @floatFromInt(tokens));
            if (additional_time > self.tau_ms) return false;

            const now: f64 = @floatFromInt(ms_since_start);
            const now_ns = timestampMsToNs(ms_since_start);
            const tat = self.tat_per_key.get(key, now_ns) orelse now;

            const earliest_time = tat + additional_time - self.tau_ms;
            if (now < earliest_time) return false;

            self.tat_per_key.put(key, @max(now, tat) + additional_time, self.ttl_ms, now_ns);
            return true;
        }

        pub fn prune(self: *Self, now_ms: u64) void {
            self.tat_per_key.pruneExpired(timestampMsToNs(now_ms));
        }
    };
}

pub const RateLimiter = struct {
    allocator: Allocator,
    global: RateLimiterGcra(u8),
    by_ip: RateLimiterGcra(IpKey),
    banned_ips: lru.LruCache(IpKey, u8),
    expected_responses_by_ip: std.AutoHashMap(IpKey, u32),
    stats: Stats = .{},

    pub fn init(allocator: Allocator, config: Config) !RateLimiter {
        var global = try RateLimiterGcra(u8).fromQuota(allocator, config.global_quota, 1);
        errdefer global.deinit();

        var by_ip = try RateLimiterGcra(IpKey).fromQuota(allocator, config.by_ip_quota, config.by_ip_state_capacity);
        errdefer by_ip.deinit();

        var banned_ips = try lru.LruCache(IpKey, u8).init(allocator, config.banned_ip_capacity);
        errdefer banned_ips.deinit(allocator);

        return .{
            .allocator = allocator,
            .global = global,
            .by_ip = by_ip,
            .banned_ips = banned_ips,
            .expected_responses_by_ip = std.AutoHashMap(IpKey, u32).init(allocator),
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.global.deinit();
        self.by_ip.deinit();
        self.banned_ips.deinit(self.allocator);
        self.expected_responses_by_ip.deinit();
    }

    pub fn allowEncodedPacket(self: *RateLimiter, addr: Address, now_ms: u64) bool {
        const ip = IpKey.fromAddress(addr);
        const now_ns = timestampMsToNs(now_ms);
        // Correlated responses must remain admissible even if unauthenticated
        // spoofed traffic has exhausted or temporarily banned the peer's IP.
        if (self.expectsResponseFromIP(ip)) return true;
        if (self.banned_ips.get(ip, now_ns) != null) return false;

        if (!self.by_ip.allows(ip, 1, now_ms)) {
            self.stats.rate_limit_hit_ip_total += 1;
            self.banned_ips.put(ip, 1, banned_ip_duration_ms, now_ns);
            return false;
        }

        if (!self.global.allows(0, 1, now_ms)) {
            self.stats.rate_limit_hit_total += 1;
            return false;
        }

        return true;
    }

    pub fn addExpectedResponse(self: *RateLimiter, addr: Address) !void {
        const ip = IpKey.fromAddress(addr);
        const entry = try self.expected_responses_by_ip.getOrPut(ip);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
    }

    pub fn removeExpectedResponse(self: *RateLimiter, addr: Address) void {
        const ip = IpKey.fromAddress(addr);
        const current = self.expected_responses_by_ip.getPtr(ip) orelse return;
        if (current.* > 1) {
            current.* -= 1;
        } else {
            _ = self.expected_responses_by_ip.remove(ip);
        }
    }

    pub fn statsSnapshot(self: *const RateLimiter) Stats {
        return self.stats;
    }

    fn expectsResponseFromIP(self: *const RateLimiter, ip: IpKey) bool {
        return self.expected_responses_by_ip.contains(ip);
    }
};

fn timestampMsToNs(ms: u64) i64 {
    const ns = @as(i128, ms) * std.time.ns_per_ms;
    return if (ns > std.math.maxInt(i64)) std.math.maxInt(i64) else @intCast(ns);
}

test "GCRA allows burst then replenishes over time" {
    var limiter = try RateLimiterGcra(IpKey).fromQuota(std.testing.allocator, .{
        .replenish_all_every_ms = 1_000,
        .max_tokens = 2,
    }, 16);
    defer limiter.deinit();

    const ip = IpKey.fromAddress(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } });
    try std.testing.expect(limiter.allows(ip, 1, 0));
    try std.testing.expect(limiter.allows(ip, 1, 0));
    try std.testing.expect(!limiter.allows(ip, 1, 0));
    try std.testing.expect(limiter.allows(ip, 1, 500));
}

test "rate limiter bans IP on per-IP quota hit" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });
    defer limiter.deinit();

    const addr = Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9000 } };
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 0));
    limiter.addExpectedResponse(addr) catch unreachable;
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    limiter.removeExpectedResponse(addr);
    try std.testing.expect(!limiter.allowEncodedPacket(addr, banned_ip_duration_ms - 1));
    try std.testing.expect(limiter.allowEncodedPacket(addr, banned_ip_duration_ms));

    const stats = limiter.statsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), stats.rate_limit_hit_ip_total);
}

test "rate limiter expected response bypasses quotas" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });
    defer limiter.deinit();

    const addr = Address{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 9000 } };
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    limiter.addExpectedResponse(addr) catch unreachable;
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    limiter.removeExpectedResponse(addr);
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 0));
}

test "rate limiter bounds source IP state" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_state_capacity = 2,
        .banned_ip_capacity = 2,
    });
    defer limiter.deinit();

    for (0..8) |i| {
        const addr = Address{ .ip4 = .{
            .bytes = .{ 198, 51, 100, @intCast(i + 1) },
            .port = 9000,
        } };
        try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
        try std.testing.expect(!limiter.allowEncodedPacket(addr, 0));
        try std.testing.expect(limiter.by_ip.tat_per_key.count() <= 2);
        try std.testing.expect(limiter.banned_ips.count() <= 2);
    }
}
