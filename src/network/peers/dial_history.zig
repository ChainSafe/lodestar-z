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
    /// Latest failure of an endpoint entry; null for an identity's "too many peers" entry.
    failure: ?t.DialFailure = null,
    /// The next dial of the endpoint retries `failure` and has not been counted yet.
    retry_pending: bool = false,
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

    /// Records a failed dial of a discovery intent's endpoint. Only a `retry` record marks the
    /// endpoint's next dial as a retry of `failure`.
    pub fn recordEndpoint(self: *History, key: u64, failure: t.DialFailure, sequence: u64, now_ms: u64, retry: bool) void {
        const entry = self.claim(key, now_ms);
        entry.strikes +|= 1;
        entry.sequence = @max(entry.sequence, sequence);
        entry.retry_pending = entry.retry_pending or retry;
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

    /// A strictly newer ENR sequence lifts a block, except after a peer-id mismatch.
    pub fn blocked(self: *const History, key: u64, sequence: u64, now_ms: u64) bool {
        const entry = self.find(key, now_ms) orelse return false;
        if (now_ms >= entry.block_until_ms) return false;
        return entry.failure == .peer_id_mismatch or sequence <= entry.sequence;
    }

    pub fn strikesFor(self: *const History, key: u64, sequence: u64, now_ms: u64) u8 {
        const entry = self.find(key, now_ms) orelse return 0;
        return if (sequence <= entry.sequence) entry.strikes else 0;
    }

    /// Returns the endpoint's latest failure once per recorded failure, whatever the ENR sequence.
    pub fn takeRetry(self: *History, key: u64, now_ms: u64) ?t.DialFailure {
        const mask: u64 = self.entries.len - 1;
        for (0..probe_max) |offset| {
            const entry = &self.entries[@intCast((key +% @as(u64, offset)) & mask)];
            if (entry.key != key) continue;
            if (now_ms >= entry.until_ms or !entry.retry_pending) return null;
            entry.retry_pending = false;
            return entry.failure;
        }
        return null;
    }

    pub fn clear(self: *History, key: u64) void {
        const mask: u64 = self.entries.len - 1;
        for (0..probe_max) |offset| {
            const entry = &self.entries[@intCast((key +% @as(u64, offset)) & mask)];
            if (entry.key == key) entry.* = .{};
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
