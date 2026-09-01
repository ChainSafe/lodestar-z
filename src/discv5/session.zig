const std = @import("std");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

pub const session_capacity_max: usize = 2_048;
pub const challenge_capacity_max: usize = 256;
pub const first_nonce_counter: u32 = 1;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCapacity,
    NonceExhausted,
};

pub const Session = struct {
    read_key: [16]u8,
    write_key: [16]u8,
    nonce_counter: u32 = 0,
};

pub const Outbound = struct {
    write_key: [16]u8,
    nonce: [constants.nonce_size]u8,
};

pub const Challenge = struct {
    data: [constants.whoareyou_packet_size]u8,
    sent_at_ms: u64,
};

const SessionEntry = struct {
    value: Session,
    last_used_ms: u64,
};

const SessionMap = std.AutoHashMapUnmanaged(types.Endpoint, SessionEntry);

const ChallengeEntry = struct {
    peer: types.Endpoint,
    value: Challenge,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    sessions: SessionMap,
    session_capacity: u32,
    challenges: []?ChallengeEntry,

    pub fn init(
        self: *Store,
        allocator: std.mem.Allocator,
        session_capacity: usize,
        challenge_capacity: usize,
    ) Error!void {
        if (session_capacity == 0 or session_capacity > session_capacity_max)
            return Error.InvalidCapacity;
        if (challenge_capacity == 0 or challenge_capacity > challenge_capacity_max)
            return Error.InvalidCapacity;

        var sessions: SessionMap = .empty;
        try sessions.ensureTotalCapacity(allocator, @intCast(session_capacity));
        errdefer sessions.deinit(allocator);
        const challenges = try allocator.alloc(?ChallengeEntry, challenge_capacity);

        @memset(challenges, null);
        self.* = .{
            .allocator = allocator,
            .sessions = sessions,
            .session_capacity = @intCast(session_capacity),
            .challenges = challenges,
        };
    }

    pub fn deinit(self: *Store) void {
        var iterator = self.sessions.valueIterator();
        while (iterator.next()) |entry| clearSession(entry);
        self.sessions.deinit(self.allocator);
        self.allocator.free(self.challenges);
    }

    pub fn hasSession(self: *const Store, peer: types.Endpoint) bool {
        return self.sessions.contains(peer);
    }

    pub fn readKey(self: *const Store, peer: types.Endpoint) ?[16]u8 {
        const stored = self.sessions.get(peer) orelse return null;
        return stored.value.read_key;
    }

    pub fn touch(self: *Store, peer: types.Endpoint, now_ms: u64) bool {
        const stored = self.sessions.getPtr(peer) orelse return false;
        stored.last_used_ms = now_ms;
        return true;
    }

    pub fn outbound(
        self: *Store,
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

    pub fn install(
        self: *Store,
        peer: types.Endpoint,
        active: *const Session,
        now_ms: u64,
    ) void {
        if (self.sessions.getPtr(peer)) |stored| {
            clearSession(stored);
            stored.* = .{ .value = active.*, .last_used_ms = now_ms };
        } else {
            if (self.sessions.count() == self.session_capacity) self.evictOldestSession();
            self.sessions.putAssumeCapacityNoClobber(peer, .{
                .value = active.*,
                .last_used_ms = now_ms,
            });
        }
        self.removeChallenge(peer);
    }

    pub fn putChallenge(
        self: *Store,
        peer: types.Endpoint,
        data: *const [constants.whoareyou_packet_size]u8,
        now_ms: u64,
    ) bool {
        if (self.findChallenge(peer) != null) return false;
        const index = self.challengeIndexForInsert();
        self.challenges[index] = .{
            .peer = peer,
            .value = .{ .data = data.*, .sent_at_ms = now_ms },
        };
        return true;
    }

    pub fn getChallenge(self: *const Store, peer: types.Endpoint) ?Challenge {
        const index = self.findChallenge(peer) orelse return null;
        return self.challenges[index].?.value;
    }

    pub fn expireChallenges(self: *Store, now_ms: u64, timeout_ms: u64) usize {
        var expired: usize = 0;
        for (self.challenges) |*slot| {
            const stored = slot.* orelse continue;
            if (!expiredAt(stored.value.sent_at_ms, now_ms, timeout_ms)) continue;
            slot.* = null;
            expired += 1;
        }
        return expired;
    }

    pub fn expireSessions(self: *Store, now_ms: u64, timeout_ms: u64) usize {
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

    pub fn sessionCount(self: *const Store) usize {
        return self.sessions.count();
    }

    pub fn challengeCount(self: *const Store) usize {
        var count: usize = 0;
        for (self.challenges) |entry| if (entry != null) {
            count += 1;
        };
        return count;
    }

    fn findChallenge(self: *const Store, peer: types.Endpoint) ?usize {
        for (self.challenges, 0..) |entry, index| {
            if (entry) |stored| if (std.meta.eql(stored.peer, peer)) return index;
        }
        return null;
    }

    fn challengeIndexForInsert(self: *const Store) usize {
        var oldest: usize = 0;
        for (self.challenges, 0..) |entry, index| {
            const stored = entry orelse return index;
            if (stored.value.sent_at_ms < self.challenges[oldest].?.value.sent_at_ms)
                oldest = index;
        }
        return oldest;
    }

    fn removeChallenge(self: *Store, peer: types.Endpoint) void {
        const index = self.findChallenge(peer) orelse return;
        self.challenges[index] = null;
    }

    fn evictOldestSession(self: *Store) void {
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
};

pub fn makeNonce(counter: u32, random_tail: *const [8]u8) [constants.nonce_size]u8 {
    std.debug.assert(counter >= first_nonce_counter);
    var nonce: [constants.nonce_size]u8 = undefined;
    std.mem.writeInt(u32, nonce[0..4], counter, .big);
    @memcpy(nonce[4..], random_tail);
    return nonce;
}

fn expiredAt(start_ms: u64, now_ms: u64, timeout_ms: u64) bool {
    if (now_ms < start_ms) return false;
    return now_ms - start_ms >= timeout_ms;
}

fn clearSession(entry: *SessionEntry) void {
    std.crypto.secureZero(u8, std.mem.asBytes(&entry.value));
}

comptime {
    std.debug.assert(@sizeOf(SessionEntry) <= 128);
    std.debug.assert(@sizeOf(ChallengeEntry) <= 160);
    std.debug.assert(@sizeOf(Store) <= 64);
}
