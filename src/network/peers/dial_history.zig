//! Bounded dial failure memory keyed by (peer, endpoint) or by peer. It outlives catalog rows, so
//! a replaced discovery intent cannot come back as an untried candidate. Keys are seeded hashes;
//! a collision only suppresses or escalates one candidate.
const std = @import("std");
const t = @import("types.zig");

pub const strikes_to_block: u8 = 2;
pub const endpoint_memory_ms: u64 = 30 * 60_000;
pub const mismatch_memory_ms: u64 = 6 * 60 * 60_000;
pub const remote_full_memory_ms: u64 = 2 * 60 * 60_000;
pub const remote_full_cooldowns_ms = [_]u64{ 5 * 60_000, 15 * 60_000, 60 * 60_000 };
pub const probe_max: usize = 8;

pub const Entry = struct {
    key: u64 = 0,
    until_ms: u64 = 0,
    block_until_ms: u64 = 0,
    sequence: u64 = 0,
    strikes: u8 = 0,
    /// The strikes from health closes, at most `strikes`. They outlive the connection-failure
    /// evidence an application exchange clears, and a newer ENR sequence neither lifts nor hides them.
    health: u8 = 0,
    /// Latest failure of an endpoint entry; null for a redial mark alone or an identity's "too many
    /// peers" entry.
    failure: ?t.DialFailure = null,
    /// The endpoint's latest failed dial, which its next dial redials; cleared once counted.
    retry: ?t.DialFailure = null,
};

pub const History = struct {
    entries: []Entry,
    seed: u64,

    pub fn capacityFor(intent_capacity: u16) usize {
        return std.math.ceilPowerOfTwoAssert(usize, std.math.clamp(@as(usize, intent_capacity) * 4, 64, 4096));
    }

    pub fn endpointKey(self: *const History, peer: *const t.PeerId, address: t.Address) u64 {
        var hasher = std.hash.Wyhash.init(self.seed);
        hasher.update(&peer.bytes);
        var port: [2]u8 = undefined;
        switch (address) {
            .ip4 => |value| {
                hasher.update(&[_]u8{4});
                hasher.update(&value.octets);
                std.mem.writeInt(u16, &port, value.port, .little);
            },
            .ip6 => |value| {
                hasher.update(&[_]u8{6});
                hasher.update(&value.octets);
                std.mem.writeInt(u16, &port, value.port, .little);
            },
        }
        hasher.update(&port);
        return hasher.final() | 1;
    }

    pub fn identityKey(self: *const History, peer: *const t.PeerId) u64 {
        var hasher = std.hash.Wyhash.init(self.seed);
        hasher.update(&peer.bytes);
        hasher.update(&[_]u8{0});
        return hasher.final() | 1;
    }

    /// Records a failed dial of a discovery intent's endpoint, or a health close of a connection to it.
    pub fn recordEndpoint(self: *History, key: u64, failure: t.DialFailure, sequence: u64, now_ms: u64) void {
        const entry = self.claim(key, now_ms);
        entry.strikes +|= 1;
        if (failure == .health) entry.health +|= 1;
        std.debug.assert(entry.health <= entry.strikes);
        entry.sequence = @max(entry.sequence, sequence);
        if (failure == .peer_id_mismatch) {
            entry.failure = .peer_id_mismatch;
            entry.strikes = @max(entry.strikes, strikes_to_block);
            entry.until_ms = @max(entry.until_ms, now_ms +| mismatch_memory_ms);
        } else {
            if (entry.failure != .peer_id_mismatch) entry.failure = failure;
            entry.until_ms = @max(entry.until_ms, now_ms +| endpoint_memory_ms);
        }
        if (entry.strikes >= strikes_to_block) entry.block_until_ms = entry.until_ms;
    }

    /// A strictly newer ENR sequence lifts a block, except after a peer-id mismatch or a health close:
    /// the peer authenticated on that endpoint, so a new record does not make it answer.
    pub fn blocked(self: *const History, key: u64, sequence: u64, now_ms: u64) bool {
        const entry = self.find(key, now_ms) orelse return false;
        if (now_ms >= entry.block_until_ms) return false;
        return entry.failure == .peer_id_mismatch or entry.health != 0 or sequence <= entry.sequence;
    }

    pub fn strikesFor(self: *const History, key: u64, sequence: u64, now_ms: u64) u8 {
        const entry = self.find(key, now_ms) orelse return 0;
        return if (sequence <= entry.sequence) entry.strikes else entry.health;
    }

    /// Marks the endpoint's next dial, by any intent, as a redial of `failure`. A live entry keeps
    /// its evidence and memory window; a new one lives for `endpoint_memory_ms`.
    pub fn markRetry(self: *History, key: u64, failure: t.DialFailure, now_ms: u64) void {
        const entry = self.claim(key, now_ms);
        if (now_ms >= entry.until_ms) entry.until_ms = now_ms +| endpoint_memory_ms;
        entry.retry = failure;
    }

    /// Returns the endpoint's marked failure once, whatever the ENR sequence.
    pub fn takeRetry(self: *History, key: u64, now_ms: u64) ?t.DialFailure {
        const mask: u64 = self.entries.len - 1;
        for (0..probe_max) |offset| {
            const entry = &self.entries[@intCast((key +% @as(u64, offset)) & mask)];
            if (entry.key != key) continue;
            if (now_ms >= entry.until_ms) return null;
            defer entry.retry = null;
            return entry.retry;
        }
        return null;
    }

    /// Forgets the endpoint's connection-failure evidence, including a peer-id mismatch, and keeps
    /// its health evidence.
    pub fn clearFailures(self: *History, key: u64) void {
        const entry = self.lookup(key) orelse return;
        if (entry.health == 0) {
            entry.* = .{};
            return;
        }
        entry.strikes = entry.health;
        entry.failure = .health;
        if (entry.strikes < strikes_to_block) entry.block_until_ms = 0;
    }

    /// Forgets the endpoint's health evidence and keeps any connection-failure evidence.
    pub fn clearHealth(self: *History, key: u64) void {
        const entry = self.lookup(key) orelse return;
        if (entry.health == 0) return;
        entry.strikes -= entry.health;
        entry.health = 0;
        if (entry.strikes == 0) {
            entry.* = .{};
            return;
        }
        if (entry.failure == .peer_id_mismatch) {
            entry.strikes = @max(entry.strikes, strikes_to_block);
        } else if (entry.strikes < strikes_to_block) {
            entry.block_until_ms = 0;
        }
    }

    /// Returns the cooldown for another "too many peers" Goodbye from this identity.
    pub fn remoteFull(self: *History, key: u64, now_ms: u64) u64 {
        const entry = self.claim(key, now_ms);
        entry.strikes = if (entry.failure == null) entry.strikes +| 1 else 1;
        entry.failure = null;
        const cooldown = remote_full_cooldowns_ms[@min(entry.strikes, remote_full_cooldowns_ms.len) - 1];
        entry.until_ms = now_ms +| remote_full_memory_ms;
        entry.block_until_ms = now_ms +| cooldown;
        return cooldown;
    }

    /// The key's entry, live or expired.
    fn lookup(self: *History, key: u64) ?*Entry {
        const mask: u64 = self.entries.len - 1;
        for (0..probe_max) |offset| {
            const entry = &self.entries[@intCast((key +% @as(u64, offset)) & mask)];
            if (entry.key == key) return entry;
        }
        return null;
    }

    fn find(self: *const History, key: u64, now_ms: u64) ?*const Entry {
        const mask: u64 = self.entries.len - 1;
        for (0..probe_max) |offset| {
            const entry = &self.entries[@intCast((key +% @as(u64, offset)) & mask)];
            if (entry.key == key) return if (now_ms < entry.until_ms) entry else null;
        }
        return null;
    }

    fn claim(self: *History, key: u64, now_ms: u64) *Entry {
        std.debug.assert(key != 0);
        std.debug.assert(std.math.isPowerOfTwo(self.entries.len));
        const mask: u64 = self.entries.len - 1;
        var victim: usize = @intCast(key & mask);
        for (0..probe_max) |offset| {
            const index: usize = @intCast((key +% @as(u64, offset)) & mask);
            const entry = &self.entries[index];
            if (entry.key == key) {
                if (now_ms >= entry.until_ms) entry.* = .{ .key = key };
                return entry;
            }
            const current = &self.entries[victim];
            if (current.key != 0 and (entry.key == 0 or entry.until_ms < current.until_ms)) victim = index;
        }
        self.entries[victim] = .{ .key = key };
        return &self.entries[victim];
    }
};

test {
    _ = @import("dial_history_test.zig");
}
