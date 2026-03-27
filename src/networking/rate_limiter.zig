//! Per-peer request rate limiting for the Ethereum consensus req/resp protocol.
//!
//! Implements a token bucket algorithm per peer per protocol. Each peer starts with
//! a full bucket of tokens. Each request consumes one token. Tokens replenish at a
//! configured rate over time.
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

    /// Attempt to consume one token. Returns true if allowed.
    pub fn tryConsume(self: *TokenBucket, now_ns: i128) bool {
        self.refill(now_ns);
        if (self.tokens >= 1.0) {
            self.tokens -= 1.0;
            return true;
        }
        return false;
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
};

// ── RateLimiter ───────────────────────────────────────────────────────────────

/// Per-peer request rate limiter for req/resp protocols.
///
/// Time (now_ns) is passed explicitly to all methods. The caller is responsible
/// for providing a monotonic timestamp in nanoseconds (e.g., from std.Io.Clock).
///
/// Peers are identified by a u64 numeric id.
pub const RateLimiter = struct {
    allocator: Allocator,
    /// Per-peer bucket sets.
    peers: std.AutoHashMap(u64, PeerBuckets),
    /// Rate limit configuration per protocol.
    configs: [Protocol.COUNT]ProtocolRateConfig,
    /// Stats: total requests allowed / denied.
    total_allowed: u64,
    total_denied: u64,

    pub fn init(allocator: Allocator) RateLimiter {
        return initWithConfigs(allocator, &DEFAULT_RATE_CONFIGS);
    }

    pub fn initWithConfigs(allocator: Allocator, configs: []const ProtocolRateConfig) RateLimiter {
        var cfg: [Protocol.COUNT]ProtocolRateConfig = undefined;
        @memcpy(&cfg, configs);
        return .{
            .allocator = allocator,
            .peers = std.AutoHashMap(u64, PeerBuckets).init(allocator),
            .configs = cfg,
            .total_allowed = 0,
            .total_denied = 0,
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.peers.deinit();
    }

    /// Check whether a request from the given peer on the given protocol is allowed.
    ///
    /// Consumes a token if allowed. `now_ns` is a monotonic nanosecond timestamp.
    /// Returns false if rate limited.
    pub fn allowRequest(self: *RateLimiter, peer_id: u64, protocol: Protocol, now_ns: i128) !bool {
        const entry = try self.peers.getOrPut(peer_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = PeerBuckets.init(&self.configs, now_ns);
        }

        const allowed = entry.value_ptr.tryConsume(protocol, now_ns);
        if (allowed) {
            self.total_allowed += 1;
        } else {
            self.total_denied += 1;
            log.warn("rate limit exceeded for peer {} on protocol {s}", .{
                peer_id,
                @tagName(protocol),
            });
        }
        return allowed;
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
        }
    }

    /// Remove a single peer.
    pub fn removePeer(self: *RateLimiter, peer_id: u64) void {
        _ = self.peers.remove(peer_id);
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

    // Consume initial token.
    try testing.expect(bucket.tryConsume(0));
    try testing.expect(!bucket.tryConsume(0));

    // Simulate 2 seconds elapsed.
    const later_ns: i128 = 2 * std.time.ns_per_s;
    try testing.expect(bucket.tryConsume(later_ns));
}

test "TokenBucket: tokens capped at burst" {
    var bucket = TokenBucket.init(5.0, 10.0, 0);

    // Simulate a long time — should cap at burst=5.
    const later_ns: i128 = 1000 * std.time.ns_per_s;
    const tokens = bucket.currentTokens(later_ns);
    try testing.expectEqual(@as(f64, 5.0), tokens);
}

test "RateLimiter: allows requests within burst" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    // Status burst is 5.
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const allowed = try limiter.allowRequest(42, .status, 0);
        try testing.expect(allowed);
    }
    // 6th should be denied.
    const denied = try limiter.allowRequest(42, .status, 0);
    try testing.expect(!denied);
}

test "RateLimiter: different peers are independent" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    // Exhaust peer 1's status tokens.
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try limiter.allowRequest(1, .status, 0);
    }
    try testing.expect(!(try limiter.allowRequest(1, .status, 0)));

    // Peer 2 should still have tokens.
    try testing.expect(try limiter.allowRequest(2, .status, 0));
}

test "RateLimiter: different protocols are independent" {
    var limiter = RateLimiter.init(testing.allocator);
    defer limiter.deinit();

    // Exhaust status.
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try limiter.allowRequest(1, .status, 0);
    }
    try testing.expect(!(try limiter.allowRequest(1, .status, 0)));

    // Ping should be unaffected.
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

    // Exhaust ping tokens (burst = 2).
    _ = try limiter.allowRequest(1, .ping, 0);
    _ = try limiter.allowRequest(1, .ping, 0);
    try testing.expect(!(try limiter.allowRequest(1, .ping, 0)));

    // After 2 minutes, should have replenished (rate = 2/min, 2 min = 4 tokens, cap 2).
    const two_minutes_ns: i128 = 2 * 60 * std.time.ns_per_s;
    try testing.expect(try limiter.allowRequest(1, .ping, two_minutes_ns));
}
