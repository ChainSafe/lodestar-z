//! Storage for the protocol's per-peer session state.
//!
//! Owns the three caches that back session establishment — established
//! sessions, in-flight WHOAREYOU challenges, and the per-source WHOAREYOU rate
//! limiter — and centralizes their TTL/eviction policy so the protocol handlers
//! deal in endpoints and timestamps rather than cache mechanics.

const std = @import("std");
const scoped_log = std.log.scoped(.discv5_protocol);
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Address = Io.net.IpAddress;

const lru = @import("../lru.zig");
const request_tracker = @import("request_tracker.zig");
const protocol_state = @import("state.zig");

const Endpoint = request_tracker.Endpoint;
const EndpointContext = request_tracker.EndpointContext;
const SessionRecord = protocol_state.SessionRecord;
const ActiveChallenge = protocol_state.ActiveChallenge;
const AddressKey = protocol_state.AddressKey;
const WhoareyouRateEntry = protocol_state.WhoareyouRateEntry;

const SessionCache = lru.LruCacheWithContext(Endpoint, SessionRecord, EndpointContext);
const ChallengeCache = lru.LruCacheWithContext(Endpoint, ActiveChallenge, EndpointContext);
const WhoareyouRateCache = lru.LruCache(AddressKey, WhoareyouRateEntry);

pub const Config = struct {
    session_cache_capacity: u32,
    session_timeout_ms: u64,
    challenge_cache_capacity: usize,
    challenge_timeout_ms: u64,
    whoareyou_rate_capacity: usize,
    whoareyou_rate_ttl_ms: u64,
    max_whoareyou_per_sec: u32,
};

pub const SessionStore = struct {
    sessions: SessionCache,
    challenges: ChallengeCache,
    whoareyou_rate: WhoareyouRateCache,
    config: Config,

    pub fn init(alloc: Allocator, config: Config) !SessionStore {
        var sessions = try SessionCache.init(alloc, config.session_cache_capacity);
        errdefer sessions.deinit(alloc);
        var challenges = try ChallengeCache.init(alloc, config.challenge_cache_capacity);
        errdefer challenges.deinit(alloc);
        const whoareyou_rate = try WhoareyouRateCache.init(alloc, config.whoareyou_rate_capacity);
        return .{
            .sessions = sessions,
            .challenges = challenges,
            .whoareyou_rate = whoareyou_rate,
            .config = config,
        };
    }

    pub fn deinit(self: *SessionStore, alloc: Allocator) void {
        self.sessions.deinit(alloc);
        self.challenges.deinit(alloc);
        self.whoareyou_rate.deinit(alloc);
    }

    pub fn getSession(self: *SessionStore, endpoint: Endpoint, now_ns: i64) ?SessionRecord {
        return self.sessions.get(endpoint, now_ns);
    }

    pub fn putSession(self: *SessionStore, endpoint: Endpoint, session: SessionRecord, now_ns: i64) void {
        self.sessions.put(endpoint, session, self.config.session_timeout_ms, now_ns);
    }

    pub fn removeSession(self: *SessionStore, endpoint: Endpoint) bool {
        return self.sessions.remove(endpoint);
    }

    pub fn sessionCount(self: *SessionStore, now_ns: i64) usize {
        self.sessions.pruneExpired(now_ns);
        return self.sessions.count();
    }

    pub fn getChallenge(self: *SessionStore, endpoint: Endpoint, now_ns: i64) ?ActiveChallenge {
        return self.challenges.get(endpoint, now_ns);
    }

    pub fn putChallenge(self: *SessionStore, endpoint: Endpoint, challenge: ActiveChallenge, now_ns: i64) void {
        self.challenges.put(endpoint, challenge, self.config.challenge_timeout_ms, now_ns);
    }

    pub fn removeChallenge(self: *SessionStore, endpoint: Endpoint) bool {
        return self.challenges.remove(endpoint);
    }

    /// Token-bucket gate for outbound WHOAREYOU responses, keyed by source
    /// address. WHOAREYOU is sent before peer authentication and can be
    /// triggered by spoofed source IPs, so the rate state is bounded by the
    /// underlying TTL/LRU cache (CL-2020-08).
    pub fn allowWhoareyou(self: *SessionStore, dest: Address, now_ns: i64) bool {
        const key = AddressKey.fromAddress(dest);
        var entry = self.whoareyou_rate.get(key, now_ns) orelse WhoareyouRateEntry{
            .count = 0,
            .window_start_ns = now_ns,
        };

        if (now_ns - entry.window_start_ns >= std.time.ns_per_s) {
            entry = .{ .count = 1, .window_start_ns = now_ns };
        } else {
            if (entry.count >= self.config.max_whoareyou_per_sec) {
                scoped_log.debug("WHOAREYOU rate limit hit for {any}", .{dest});
                return false;
            }
            entry.count += 1;
        }

        self.whoareyou_rate.put(key, entry, self.config.whoareyou_rate_ttl_ms, now_ns);
        return true;
    }
};
