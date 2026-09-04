//! A SessionStore holds session keys and pending WHOAREYOU challenges. Both are keyed by node ID
//! and observed address, so a peer that moves has to handshake again.

const std = @import("std");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

const SessionStore = @This();

pub const session_capacity_max: usize = 2_048;
pub const challenge_capacity_max: usize = 256;
pub const first_nonce_counter: u32 = 1;

pub const InitError = std.mem.Allocator.Error || error{InvalidCapacity};
pub const Error = error{NonceExhausted};

pub const Session = struct {
    read_key: [16]u8,
    write_key: [16]u8,
    nonce_counter: u32 = 0,
};

pub const Outbound = struct {
    write_key: [16]u8,
    nonce: [constants.nonce_size]u8,
};

pub const KnownIdentity = struct {
    sequence: u64,
    public_key: [33]u8,
};

pub const Challenge = struct {
    data: [constants.whoareyou_packet_size]u8,
    sent_at_ms: u64,
    /// What the engine knew about the peer when it issued the challenge. Verification uses this
    /// instead of consulting routing later.
    known: ?KnownIdentity,
};

const SessionEntry = struct {
    value: Session,
    alternate_read_key: ?[16]u8 = null,
    last_used_ms: u64,
};

const SessionMap = std.AutoHashMapUnmanaged(types.Endpoint, SessionEntry);

const ChallengeEntry = struct {
    peer: types.Endpoint,
    value: Challenge,
};

sessions: SessionMap,
session_capacity: u32,
challenges: []?ChallengeEntry,

pub fn init(
    self: *SessionStore,
    allocator: std.mem.Allocator,
    session_capacity: usize,
    challenge_capacity: usize,
) InitError!void {
    if (session_capacity == 0 or session_capacity > session_capacity_max)
        return InitError.InvalidCapacity;
    if (challenge_capacity == 0 or challenge_capacity > challenge_capacity_max)
        return InitError.InvalidCapacity;

    var sessions: SessionMap = .empty;
    try sessions.ensureTotalCapacity(allocator, @intCast(session_capacity));
    errdefer sessions.deinit(allocator);
    const challenges = try allocator.alloc(?ChallengeEntry, challenge_capacity);

    @memset(challenges, null);
    self.* = .{
        .sessions = sessions,
        .session_capacity = @intCast(session_capacity),
        .challenges = challenges,
    };
}

pub fn deinit(self: *SessionStore, allocator: std.mem.Allocator) void {
    var iterator = self.sessions.valueIterator();
    while (iterator.next()) |entry| clearSession(entry);
    self.sessions.deinit(allocator);
    allocator.free(self.challenges);
    self.* = undefined;
}

pub fn hasSession(self: *const SessionStore, peer: types.Endpoint) bool {
    return self.sessions.contains(peer);
}

pub fn readKey(self: *const SessionStore, peer: types.Endpoint) ?[16]u8 {
    const stored = self.sessions.get(peer) orelse return null;
    return stored.value.read_key;
}

pub fn alternateReadKey(self: *const SessionStore, peer: types.Endpoint) ?[16]u8 {
    const stored = self.sessions.get(peer) orelse return null;
    return stored.alternate_read_key;
}

pub fn touch(self: *SessionStore, peer: types.Endpoint, now_ms: u64) bool {
    const stored = self.sessions.getPtr(peer) orelse return false;
    stored.last_used_ms = now_ms;
    return true;
}

/// Consumes the next nonce for `peer`. When the counter is exhausted the session is removed
/// rather than wrapped, because AES-GCM must never see a nonce twice under one key.
pub fn outbound(
    self: *SessionStore,
    peer: types.Endpoint,
    random_tail: *const [8]u8,
    now_ms: u64,
) Error!?Outbound {
    const stored = self.sessions.getPtr(peer) orelse return null;
    const counter = std.math.add(u32, stored.value.nonce_counter, 1) catch {
        clearSession(stored);
        const removed = self.sessions.remove(peer);
        std.debug.assert(removed);
        return Error.NonceExhausted;
    };
    const nonce = makeNonce(counter, random_tail);
    stored.value.nonce_counter = counter;
    stored.last_used_ms = now_ms;
    return .{ .write_key = stored.value.write_key, .nonce = nonce };
}

/// Retains the preceding read key until replacement or session expiry. Crossed handshakes may
/// select different write generations at each endpoint, so receiving never promotes old keys.
pub fn install(
    self: *SessionStore,
    peer: types.Endpoint,
    active: *const Session,
    now_ms: u64,
) void {
    if (self.sessions.getPtr(peer)) |stored| {
        const counter = if (std.mem.eql(u8, &stored.value.write_key, &active.write_key))
            @max(stored.value.nonce_counter, active.nonce_counter)
        else
            active.nonce_counter;
        if (!std.mem.eql(u8, &stored.value.read_key, &active.read_key)) {
            if (stored.alternate_read_key) |*key| std.crypto.secureZero(u8, key);
            stored.alternate_read_key = stored.value.read_key;
        }
        std.crypto.secureZero(u8, std.mem.asBytes(&stored.value));
        stored.value = active.*;
        stored.value.nonce_counter = counter;
        stored.last_used_ms = now_ms;
    } else {
        if (self.sessions.count() == self.session_capacity) self.evictOldestSession();
        self.sessions.putAssumeCapacityNoClobber(peer, .{
            .value = active.*,
            .last_used_ms = now_ms,
        });
    }
}

/// Stores a challenge for `peer` unless one is already pending. When the cache is full, the
/// oldest challenge is evicted.
pub fn putChallenge(
    self: *SessionStore,
    peer: types.Endpoint,
    data: *const [constants.whoareyou_packet_size]u8,
    known: ?KnownIdentity,
    now_ms: u64,
) bool {
    if (self.findChallenge(peer) != null) return false;
    const index = self.challengeIndexForInsert();
    self.challenges[index] = .{
        .peer = peer,
        .value = .{ .data = data.*, .sent_at_ms = now_ms, .known = known },
    };
    return true;
}

pub fn getChallenge(self: *const SessionStore, peer: types.Endpoint) ?Challenge {
    const index = self.findChallenge(peer) orelse return null;
    return self.challenges[index].?.value;
}

pub fn expireChallenges(self: *SessionStore, now_ms: u64, timeout_ms: u64) usize {
    var expired: usize = 0;
    for (self.challenges) |*slot| {
        const stored = slot.* orelse continue;
        if (!expiredAt(stored.value.sent_at_ms, now_ms, timeout_ms)) continue;
        slot.* = null;
        expired += 1;
    }
    return expired;
}

pub fn expireSessions(self: *SessionStore, now_ms: u64, timeout_ms: u64) usize {
    var expired: usize = 0;
    var iterator = self.sessions.iterator();
    while (iterator.next()) |entry| {
        if (!expiredAt(entry.value_ptr.last_used_ms, now_ms, timeout_ms)) continue;
        clearSession(entry.value_ptr);
        self.sessions.removeByPtr(entry.key_ptr);
        expired += 1;
    }
    return expired;
}

pub fn nextDeadlineMs(
    self: *const SessionStore,
    challenge_timeout_ms: u64,
    session_idle_timeout_ms: u64,
) ?u64 {
    var next: ?u64 = null;
    for (self.challenges) |slot| {
        const stored = slot orelse continue;
        const deadline = stored.value.sent_at_ms +| challenge_timeout_ms;
        next = @min(next orelse deadline, deadline);
    }
    var iterator = self.sessions.valueIterator();
    while (iterator.next()) |entry| {
        const deadline = entry.last_used_ms +| session_idle_timeout_ms;
        next = @min(next orelse deadline, deadline);
    }
    return next;
}

pub fn sessionCount(self: *const SessionStore) usize {
    return self.sessions.count();
}

pub fn challengeCount(self: *const SessionStore) usize {
    var count: usize = 0;
    for (self.challenges) |entry| if (entry != null) {
        count += 1;
    };
    return count;
}

fn findChallenge(self: *const SessionStore, peer: types.Endpoint) ?usize {
    for (self.challenges, 0..) |entry, index| {
        if (entry) |stored| if (std.meta.eql(stored.peer, peer)) return index;
    }
    return null;
}

fn challengeIndexForInsert(self: *const SessionStore) usize {
    var oldest: usize = 0;
    for (self.challenges, 0..) |entry, index| {
        const stored = entry orelse return index;
        if (stored.value.sent_at_ms < self.challenges[oldest].?.value.sent_at_ms)
            oldest = index;
    }
    return oldest;
}

pub fn removeChallenge(self: *SessionStore, peer: types.Endpoint) void {
    const index = self.findChallenge(peer) orelse return;
    self.challenges[index] = null;
}

fn evictOldestSession(self: *SessionStore) void {
    var iterator = self.sessions.iterator();
    var oldest = iterator.next().?;
    while (iterator.next()) |entry| {
        if (entry.value_ptr.last_used_ms < oldest.value_ptr.last_used_ms) oldest = entry;
    }
    const key = oldest.key_ptr.*;
    clearSession(oldest.value_ptr);
    const removed = self.sessions.remove(key);
    std.debug.assert(removed);
}

pub fn makeNonce(counter: u32, random_tail: *const [8]u8) [constants.nonce_size]u8 {
    std.debug.assert(counter >= first_nonce_counter);
    var nonce: [constants.nonce_size]u8 = undefined;
    std.mem.writeInt(u32, nonce[0..4], counter, .big);
    @memcpy(nonce[4..], random_tail);
    return nonce;
}

fn expiredAt(start_ms: u64, now_ms: u64, timeout_ms: u64) bool {
    return now_ms >= start_ms +| timeout_ms;
}

fn clearSession(entry: *SessionEntry) void {
    std.crypto.secureZero(u8, std.mem.asBytes(&entry.value));
    if (entry.alternate_read_key) |*key| std.crypto.secureZero(u8, key);
    entry.alternate_read_key = null;
}

comptime {
    std.debug.assert(@sizeOf(SessionEntry) <= 128);
    std.debug.assert(@sizeOf(ChallengeEntry) <= 208);
    std.debug.assert(@sizeOf(SessionStore) <= 48);
}
