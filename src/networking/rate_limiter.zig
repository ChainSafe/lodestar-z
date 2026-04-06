//! Per-peer request rate limiting for the Ethereum consensus req/resp protocol.
//!
//! Implements a token bucket algorithm per peer per protocol, with:
//! - Per-peer per-protocol rate limiting
//! - Global rate limiting across all peers
//! - Backpressure mode: returns how long to wait instead of just rejecting
//! - Response-count-based token consumption (range requests consume more)
//! - Score penalty integration for repeated rate limit violations
//!
//! Time is passed explicitly (now_ns: i128) to keep this module free of I/O
//! dependencies and easily testable.
//!
//! Reference:
//! - https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#rate-limiting
//! - Lighthouse: https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/rpc/rate_limiter.rs

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const req_resp_protocol = @import("protocol.zig");
const log = std.log.scoped(.rate_limiter);

// ── Protocol enum ─────────────────────────────────────────────────────────────

/// Req/resp protocol identifiers for rate limiting.
pub const Protocol = enum {
    status,
    goodbye,
    ping,
    metadata,
    beacon_blocks_by_range,
    beacon_blocks_by_root,
    blob_sidecars_by_range,
    blob_sidecars_by_root,
    data_column_sidecars_by_range,
    data_column_sidecars_by_root,

    pub const COUNT = std.meta.fields(Protocol).len;
};

/// Convert a req/resp Method to the corresponding rate-limit Protocol.
///
/// Returns null for methods that are not rate-limited (light client protocols,
/// which are low-traffic and currently unmetered).
pub fn methodToRateLimitProtocol(method: req_resp_protocol.Method) ?Protocol {
    return switch (method) {
        .status => .status,
        .goodbye => .goodbye,
        .ping => .ping,
        .metadata => .metadata,
        .beacon_blocks_by_range => .beacon_blocks_by_range,
        .beacon_blocks_by_root => .beacon_blocks_by_root,
        .blob_sidecars_by_range => .blob_sidecars_by_range,
        .blob_sidecars_by_root => .blob_sidecars_by_root,
        .data_column_sidecars_by_range => .data_column_sidecars_by_range,
        .data_column_sidecars_by_root => .data_column_sidecars_by_root,
        // Light client protocols are currently unrated.
        .light_client_bootstrap,
        .light_client_updates_by_range,
        .light_client_finality_update,
        .light_client_optimistic_update,
        => null,
    };
}

// ── Rate limit result ─────────────────────────────────────────────────────────

/// Result of a rate limit check.
pub const RateLimitResult = union(enum) {
    /// Request is allowed.
    allowed,
    /// Request is denied. Contains the delay in nanoseconds before the
    /// request could be retried (backpressure information).
    denied: i128,

    pub fn isAllowed(self: RateLimitResult) bool {
        return self == .allowed;
    }
};

// ── Token bucket ──────────────────────────────────────────────────────────────

/// Token bucket for a single (peer, protocol) pair.
pub const TokenBucket = struct {
    /// Current number of tokens (fractional to support sub-second replenishment).
    tokens: f64,
    /// Maximum burst capacity (tokens).
    burst: f64,
    /// Replenishment rate (tokens per nanosecond).
    rate_per_ns: f64,
    /// Last time tokens were replenished (nanoseconds, arbitrary epoch).
    last_refill_ns: i128,

    pub fn init(burst: f64, rate_per_second: f64, now_ns: i128) TokenBucket {
        return .{
            .tokens = burst,
            .burst = burst,
            .rate_per_ns = rate_per_second / @as(f64, @floatFromInt(std.time.ns_per_s)),
            .last_refill_ns = now_ns,
        };
    }

    /// Attempt to consume `count` tokens. Returns true if allowed.
    pub fn tryConsume(self: *TokenBucket, now_ns: i128) bool {
        return self.tryConsumeN(1, now_ns);
    }

    /// Attempt to consume `count` tokens. Returns true if allowed.
    pub fn tryConsumeN(self: *TokenBucket, count: u32, now_ns: i128) bool {
        self.refill(now_ns);
        const needed: f64 = @floatFromInt(count);
        if (self.tokens >= needed) {
            self.tokens -= needed;
            return true;
        }
        return false;
    }

    /// Check if `count` tokens are available without consuming.
    pub fn canConsume(self: *TokenBucket, count: u32, now_ns: i128) bool {
        self.refill(now_ns);
        return self.tokens >= @as(f64, @floatFromInt(count));
    }

    /// Calculate how many nanoseconds until `count` tokens are available.
    /// Returns 0 if tokens are already available.
    pub fn timeUntilAvailable(self: *TokenBucket, count: u32, now_ns: i128) i128 {
        self.refill(now_ns);
        const needed: f64 = @as(f64, @floatFromInt(count));
        if (self.tokens >= needed) return 0;
        const deficit = needed - self.tokens;
        if (self.rate_per_ns <= 0) return std.math.maxInt(i128); // Never replenishes
        return @intFromFloat(@ceil(deficit / self.rate_per_ns));
    }

    /// Attempt to consume tokens, returning backpressure information.
    pub fn tryConsumeWithBackpressure(self: *TokenBucket, count: u32, now_ns: i128) RateLimitResult {
        self.refill(now_ns);
        const needed: f64 = @as(f64, @floatFromInt(count));
        if (self.tokens >= needed) {
            self.tokens -= needed;
            return .allowed;
        }
        const deficit = needed - self.tokens;
        const wait_ns: i128 = if (self.rate_per_ns > 0)
            @intFromFloat(@ceil(deficit / self.rate_per_ns))
        else
            std.math.maxInt(i128);
        return .{ .denied = wait_ns };
    }

    /// Replenish tokens based on elapsed time.
    fn refill(self: *TokenBucket, now_ns: i128) void {
        const elapsed_ns = now_ns - self.last_refill_ns;
        if (elapsed_ns <= 0) return;

        const new_tokens = @as(f64, @floatFromInt(elapsed_ns)) * self.rate_per_ns;
        self.tokens = @min(self.burst, self.tokens + new_tokens);
        self.last_refill_ns = now_ns;
    }

    /// Current token count (after refill).
    pub fn currentTokens(self: *TokenBucket, now_ns: i128) f64 {
        self.refill(now_ns);
        return self.tokens;
    }
};

// ── Rate limit configuration ──────────────────────────────────────────────────

/// Rate limit configuration for a single protocol.
pub const ProtocolRateConfig = struct {
    /// Tokens replenished per second.
    rate_per_second: f64,
    /// Maximum burst (initial tokens and max accumulation).
    burst: u32,
};

/// Default rate limits derived from the Ethereum consensus spec.
///
/// Source: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#rate-limiting
pub const DEFAULT_RATE_CONFIGS = blk: {
    var configs: [Protocol.COUNT]ProtocolRateConfig = undefined;

    // Status: 5 requests/minute, burst 5
    configs[@intFromEnum(Protocol.status)] = .{ .rate_per_second = 5.0 / 60.0, .burst = 5 };

    // Goodbye: 1 request/minute, burst 1
    configs[@intFromEnum(Protocol.goodbye)] = .{ .rate_per_second = 1.0 / 60.0, .burst = 1 };

    // Ping: 2 requests/minute, burst 2
    configs[@intFromEnum(Protocol.ping)] = .{ .rate_per_second = 2.0 / 60.0, .burst = 2 };

    // Metadata: 2 requests/minute, burst 2
    configs[@intFromEnum(Protocol.metadata)] = .{ .rate_per_second = 2.0 / 60.0, .burst = 2 };

    // BeaconBlocksByRange: 10 requests/minute, burst 10
    configs[@intFromEnum(Protocol.beacon_blocks_by_range)] = .{ .rate_per_second = 10.0 / 60.0, .burst = 10 };

    // BeaconBlocksByRoot: 128 requests/minute, burst 128
    configs[@intFromEnum(Protocol.beacon_blocks_by_root)] = .{ .rate_per_second = 128.0 / 60.0, .burst = 128 };

    // BlobSidecarsByRange: 10 requests/minute, burst 10
    configs[@intFromEnum(Protocol.blob_sidecars_by_range)] = .{ .rate_per_second = 10.0 / 60.0, .burst = 10 };

    // BlobSidecarsByRoot: 128 requests/minute, burst 128
    configs[@intFromEnum(Protocol.blob_sidecars_by_root)] = .{ .rate_per_second = 128.0 / 60.0, .burst = 128 };

    // DataColumnSidecarsByRange: 10 requests/minute, burst 10
    configs[@intFromEnum(Protocol.data_column_sidecars_by_range)] = .{ .rate_per_second = 10.0 / 60.0, .burst = 10 };

    // DataColumnSidecarsByRoot: 128 requests/minute, burst 128
    configs[@intFromEnum(Protocol.data_column_sidecars_by_root)] = .{ .rate_per_second = 128.0 / 60.0, .burst = 128 };

    break :blk configs;
};

/// Global rate limit configuration.
pub const GlobalRateConfig = struct {
    /// Total requests per second across all peers.
    rate_per_second: f64 = 500.0,
    /// Maximum burst across all peers.
    burst: u32 = 1000,
};

// ── Per-peer bucket set ───────────────────────────────────────────────────────

/// One token bucket per protocol for a single peer.
pub const PeerBuckets = struct {
    buckets: [Protocol.COUNT]TokenBucket,

    pub fn init(configs: []const ProtocolRateConfig, now_ns: i128) PeerBuckets {
        var buckets: [Protocol.COUNT]TokenBucket = undefined;
        for (configs, 0..) |cfg, i| {
            buckets[i] = TokenBucket.init(@floatFromInt(cfg.burst), cfg.rate_per_second, now_ns);
        }
        return .{ .buckets = buckets };
    }

    pub fn tryConsume(self: *PeerBuckets, protocol: Protocol, now_ns: i128) bool {
        return self.buckets[@intFromEnum(protocol)].tryConsume(now_ns);
    }

    /// Attempt to consume `count` tokens for a protocol.
    /// Used for range requests that consume tokens proportional to response count.
    pub fn tryConsumeN(self: *PeerBuckets, protocol: Protocol, count: u32, now_ns: i128) bool {
        return self.buckets[@intFromEnum(protocol)].tryConsumeN(count, now_ns);
    }

    /// Check with backpressure info.
    pub fn tryConsumeWithBackpressure(self: *PeerBuckets, protocol: Protocol, count: u32, now_ns: i128) RateLimitResult {
        return self.buckets[@intFromEnum(protocol)].tryConsumeWithBackpressure(count, now_ns);
    }
};

// ── RateLimiter ───────────────────────────────────────────────────────────────

/// Per-peer request rate limiter for req/resp protocols.
///
/// Features:
/// - Per-peer per-protocol token bucket rate limiting
/// - Global rate limit across all peers
/// - Backpressure mode: returns wait time instead of just allow/deny
/// - Response-count-based consumption for range requests
/// - Rate limit hit counting for score penalty integration
///
/// Time (now_ns) is passed explicitly to all methods. The caller is responsible
/// for providing a monotonic timestamp in nanoseconds.
///
/// Peers are identified by a u64 numeric id.
pub const RateLimiter = struct {
    allocator: Allocator,
    /// Per-peer bucket sets.
    peers: std.AutoHashMap(u64, PeerBuckets),
    /// Rate limit configuration per protocol.
    configs: [Protocol.COUNT]ProtocolRateConfig,
    /// Global rate limit bucket (across all peers).
    global_bucket: TokenBucket,
    /// Per-peer rate limit hit counter (for score penalty integration).
    hit_counts: std.AutoHashMap(u64, u32),
    /// Stats: total requests allowed / denied.
    total_allowed: u64,
    total_denied: u64,
    /// Total requests denied by global limit specifically.
    total_global_denied: u64,

    pub fn init(allocator: Allocator) RateLimiter {
        return initWithConfigs(allocator, &DEFAULT_RATE_CONFIGS, .{});
    }

    pub fn initWithConfigs(
        allocator: Allocator,
        configs: []const ProtocolRateConfig,
        global_config: GlobalRateConfig,
    ) RateLimiter {
        var cfg: [Protocol.COUNT]ProtocolRateConfig = undefined;
        @memcpy(&cfg, configs);
        return .{
            .allocator = allocator,
            .peers = std.AutoHashMap(u64, PeerBuckets).init(allocator),
            .configs = cfg,
            .global_bucket = TokenBucket.init(
                @floatFromInt(global_config.burst),
                global_config.rate_per_second,
                0,
            ),
            .hit_counts = std.AutoHashMap(u64, u32).init(allocator),
            .total_allowed = 0,
            .total_denied = 0,
            .total_global_denied = 0,
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.peers.deinit();
        self.hit_counts.deinit();
    }

    /// Check whether a request from the given peer on the given protocol is allowed.
    ///
    /// Consumes a token if allowed. `now_ns` is a monotonic nanosecond timestamp.
    /// Returns false if rate limited (by either per-peer or global limit).
    pub fn allowRequest(self: *RateLimiter, peer_id: u64, protocol: Protocol, now_ns: i128) !bool {
        return (try self.allowRequestN(peer_id, protocol, 1, now_ns)).isAllowed();
    }

    /// Check whether a request consuming `count` tokens is allowed.
    ///
    /// For range requests, `count` should be the expected number of response items.
    /// This follows Lighthouse's approach where BlocksByRange(count=64) consumes
    /// 64 tokens instead of 1.
    pub fn allowRequestN(
        self: *RateLimiter,
        peer_id: u64,
        protocol: Protocol,
        count: u32,
        now_ns: i128,
    ) !RateLimitResult {
        // Check global limit first.
        const global_result = self.global_bucket.tryConsumeWithBackpressure(count, now_ns);
        if (!global_result.isAllowed()) {
            self.total_denied += 1;
            self.total_global_denied += 1;
            try self.recordHit(peer_id);
            log.warn("global rate limit exceeded for peer {} on protocol {s}", .{
                peer_id,
                @tagName(protocol),
            });
            return global_result;
        }

        // Check per-peer limit.
        const entry = try self.peers.getOrPut(peer_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = PeerBuckets.init(&self.configs, now_ns);
        }

        const peer_result = entry.value_ptr.tryConsumeWithBackpressure(protocol, count, now_ns);
        if (peer_result.isAllowed()) {
            self.total_allowed += 1;
        } else {
            // Refund global tokens since peer limit denied.
            self.global_bucket.tokens = @min(
                self.global_bucket.burst,
                self.global_bucket.tokens + @as(f64, @floatFromInt(count)),
            );
            self.total_denied += 1;
            try self.recordHit(peer_id);
            log.warn("rate limit exceeded for peer {} on protocol {s}", .{
                peer_id,
                @tagName(protocol),
            });
        }
        return peer_result;
    }

    /// Record a rate limit hit for score penalty tracking.
    fn recordHit(self: *RateLimiter, peer_id: u64) !void {
        const entry = try self.hit_counts.getOrPut(peer_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = 0;
        }
        entry.value_ptr.* += 1;
    }

    /// Get the number of rate limit hits for a peer since last reset.
    /// Used by the scoring system to apply penalties for repeated violations.
    pub fn getHitCount(self: *const RateLimiter, peer_id: u64) u32 {
        return self.hit_counts.get(peer_id) orelse 0;
    }

    /// Reset hit counts (called periodically by peer manager heartbeat).
    pub fn resetHitCounts(self: *RateLimiter) void {
        self.hit_counts.clearRetainingCapacity();
    }

    /// Called when a response is received (hook for future response-based limiting).
    /// Reserved for extension.
    pub fn onResponse(self: *RateLimiter, peer_id: u64, protocol: Protocol) void {
        _ = self;
        _ = peer_id;
        _ = protocol;
    }

    /// Remove disconnected peers from the limiter to free memory.
    pub fn prune(self: *RateLimiter, disconnected_peers: []const u64) void {
        for (disconnected_peers) |peer_id| {
            if (self.peers.remove(peer_id)) {
                log.debug("pruned rate limiter state for peer {}", .{peer_id});
            }
            _ = self.hit_counts.remove(peer_id);
        }
    }

    /// Remove a single peer.
    pub fn removePeer(self: *RateLimiter, peer_id: u64) void {
        _ = self.peers.remove(peer_id);
        _ = self.hit_counts.remove(peer_id);
    }

    /// Number of tracked peers.
    pub fn peerCount(self: *const RateLimiter) usize {
        return self.peers.count();
    }

    /// Check current token count for a (peer, protocol) pair without consuming.
    pub fn tokenCount(self: *RateLimiter, peer_id: u64, protocol: Protocol, now_ns: i128) f64 {
        const buckets = self.peers.getPtr(peer_id) orelse {
            return @floatFromInt(self.configs[@intFromEnum(protocol)].burst);
        };
        return buckets.buckets[@intFromEnum(protocol)].currentTokens(now_ns);
    }

    /// Current global bucket tokens.
    pub fn globalTokenCount(self: *RateLimiter, now_ns: i128) f64 {
        return self.global_bucket.currentTokens(now_ns);
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "TokenBucket: initial tokens equals burst" {
    var bucket = TokenBucket.init(10.0, 1.0, 0);
    try testing.expectEqual(@as(f64, 10.0), bucket.currentTokens(0));
}

test "TokenBucket: consume decrements tokens" {
    var bucket = TokenBucket.init(5.0, 1.0, 0);

    try testing.expect(bucket.tryConsume(0));
    try testing.expect(bucket.tryConsume(0));
    try testing.expectEqual(@as(f64, 3.0), bucket.currentTokens(0));
}

test "TokenBucket: empty bucket denies requests" {
    var bucket = TokenBucket.init(1.0, 0.001, 0);

    try testing.expect(bucket.tryConsume(0));
    try testing.expect(!bucket.tryConsume(0));
}

test "TokenBucket: tokens replenish over time" {
    var bucket = TokenBucket.init(1.0, 1.0, 0); // 1 token/sec

    try testing.expect(bucket.tryConsume(0));
    try testing.expect(!bucket.tryConsume(0));

    const later_ns: i128 = 2 * std.time.ns_per_s;
    try testing.expect(bucket.tryConsume(later_ns));
}

test "TokenBucket: tokens capped at burst" {
    var bucket = TokenBucket.init(5.0, 10.0, 0);

    const later_ns: i128 = 1000 * std.time.ns_per_s;
    const tokens = bucket.currentTokens(later_ns);
    try testing.expectEqual(@as(f64, 5.0), tokens);
}

test "TokenBucket: consume N tokens" {
    var bucket = TokenBucket.init(10.0, 1.0, 0);

    try testing.expect(bucket.tryConsumeN(5, 0));
    try testing.expectEqual(@as(f64, 5.0), bucket.currentTokens(0));
    try testing.expect(!bucket.tryConsumeN(6, 0));
    try testing.expect(bucket.tryConsumeN(5, 0));
}

test "TokenBucket: backpressure returns wait time" {
    var bucket = TokenBucket.init(1.0, 1.0, 0); // 1 token/sec

    // Consume the only token.
    const r1 = bucket.tryConsumeWithBackpressure(1, 0);
    try testing.expectEqual(RateLimitResult.allowed, r1);

    // Next request is denied with wait time.
    const r2 = bucket.tryConsumeWithBackpressure(1, 0);
    switch (r2) {
        .denied => |wait_ns| {
            // Should need to wait ~1 second (1 token at 1/sec).
            try testing.expect(wait_ns > 0);
            try testing.expect(wait_ns <= std.time.ns_per_s);
        },
        .allowed => return error.TestUnexpectedResult,
    }
}

test "TokenBucket: timeUntilAvailable" {
    var bucket = TokenBucket.init(2.0, 1.0, 0); // 2 burst, 1/sec

    // Full bucket — available immediately.
    try testing.expectEqual(@as(i128, 0), bucket.timeUntilAvailable(2, 0));

    // Consume all.
    _ = bucket.tryConsumeN(2, 0);

    // Need to wait for 1 token.
    const wait = bucket.timeUntilAvailable(1, 0);
    try testing.expect(wait > 0);
    try testing.expect(wait <= std.time.ns_per_s);
}

test "RateLimiter: allows requests within burst" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const allowed = try limiter.allowRequest(42, .status, 0);
        try testing.expect(allowed);
    }
    const denied = try limiter.allowRequest(42, .status, 0);
    try testing.expect(!denied);
}

test "RateLimiter: different peers are independent" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try limiter.allowRequest(1, .status, 0);
    }
    try testing.expect(!(try limiter.allowRequest(1, .status, 0)));
    try testing.expect(try limiter.allowRequest(2, .status, 0));
}

test "RateLimiter: different protocols are independent" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try limiter.allowRequest(1, .status, 0);
    }
    try testing.expect(!(try limiter.allowRequest(1, .status, 0)));
    try testing.expect(try limiter.allowRequest(1, .ping, 0));
}

test "RateLimiter: prune removes peers" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    _ = try limiter.allowRequest(1, .ping, 0);
    _ = try limiter.allowRequest(2, .ping, 0);
    try testing.expectEqual(@as(usize, 2), limiter.peerCount());

    const disconnected = [_]u64{1};
    limiter.prune(&disconnected);
    try testing.expectEqual(@as(usize, 1), limiter.peerCount());
}

test "RateLimiter: replenishment over time" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    _ = try limiter.allowRequest(1, .ping, 0);
    _ = try limiter.allowRequest(1, .ping, 0);
    try testing.expect(!(try limiter.allowRequest(1, .ping, 0)));

    const two_minutes_ns: i128 = 2 * 60 * std.time.ns_per_s;
    try testing.expect(try limiter.allowRequest(1, .ping, two_minutes_ns));
}

test "RateLimiter: global rate limit" {
    // Create limiter with very low global limit.
    var limiter = RateLimiter.initWithConfigs(
        testing.allocator,
        &DEFAULT_RATE_CONFIGS,
        .{ .rate_per_second = 1.0, .burst = 3 },
    );
    defer limiter.deinit();

    // 3 requests from different peers should all succeed (within global burst).
    try testing.expect((try limiter.allowRequestN(1, .status, 1, 0)).isAllowed());
    try testing.expect((try limiter.allowRequestN(2, .status, 1, 0)).isAllowed());
    try testing.expect((try limiter.allowRequestN(3, .status, 1, 0)).isAllowed());

    // 4th request should be denied by global limit even though per-peer has tokens.
    const result = try limiter.allowRequestN(4, .status, 1, 0);
    try testing.expect(!result.isAllowed());
    try testing.expect(limiter.total_global_denied > 0);
}

test "RateLimiter: backpressure provides wait time" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    // Exhaust status tokens (burst = 5).
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try limiter.allowRequestN(1, .status, 1, 0);
    }

    // Next request should be denied with backpressure info.
    const result = try limiter.allowRequestN(1, .status, 1, 0);
    switch (result) {
        .denied => |wait_ns| {
            try testing.expect(wait_ns > 0);
        },
        .allowed => return error.TestUnexpectedResult,
    }
}

test "RateLimiter: multi-token consumption for range requests" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    // beacon_blocks_by_range has burst=10.
    // Consume 8 tokens at once.
    try testing.expect((try limiter.allowRequestN(1, .beacon_blocks_by_range, 8, 0)).isAllowed());

    // Only 2 tokens left — requesting 5 should fail.
    try testing.expect(!(try limiter.allowRequestN(1, .beacon_blocks_by_range, 5, 0)).isAllowed());

    // But 2 should still work.
    try testing.expect((try limiter.allowRequestN(1, .beacon_blocks_by_range, 2, 0)).isAllowed());
}

test "RateLimiter: hit count tracking" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    // Exhaust status tokens.
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try limiter.allowRequest(1, .status, 0);
    }

    // Hit rate limit 3 times.
    _ = try limiter.allowRequest(1, .status, 0);
    _ = try limiter.allowRequest(1, .status, 0);
    _ = try limiter.allowRequest(1, .status, 0);

    try testing.expectEqual(@as(u32, 3), limiter.getHitCount(1));
    try testing.expectEqual(@as(u32, 0), limiter.getHitCount(2));

    // Reset should clear counts.
    limiter.resetHitCounts();
    try testing.expectEqual(@as(u32, 0), limiter.getHitCount(1));
}

test "RateLimiter: global token count" {
    var limiter = RateLimiter.initWithConfigs(
        testing.allocator,
        &DEFAULT_RATE_CONFIGS,
        .{ .rate_per_second = 10.0, .burst = 100 },
    );
    defer limiter.deinit();

    try testing.expectEqual(@as(f64, 100.0), limiter.globalTokenCount(0));

    _ = try limiter.allowRequest(1, .status, 0);
    try testing.expectEqual(@as(f64, 99.0), limiter.globalTokenCount(0));
}
