const std = @import("std");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

pub const capacity_max: u16 = 256;
pub const first_nonce_counter: u32 = 1;

pub const Error = error{
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

const Entry = struct {
    peer: types.Endpoint,
    session: ?Session = null,
    challenge: ?Challenge = null,
    last_used_ms: u64,
};

pub const Table = struct {
    entries: [capacity_max]?Entry = [_]?Entry{null} ** capacity_max,
    capacity: u16,

    pub fn init(self: *Table, capacity: u16) Error!void {
        if (capacity == 0 or capacity > capacity_max) return Error.InvalidCapacity;
        self.* = .{ .capacity = capacity };
    }

    pub fn deinit(self: *Table) void {
        for (self.activeEntries()) |*entry| clearEntry(entry);
    }

    pub fn readKey(
        self: *Table,
        peer: types.Endpoint,
        now_ms: u64,
    ) ?[16]u8 {
        const index = self.findIndex(peer) orelse return null;
        const stored = &self.entries[index].?;
        const active = stored.session orelse return null;
        stored.last_used_ms = now_ms;
        return active.read_key;
    }

    pub fn outbound(
        self: *Table,
        peer: types.Endpoint,
        random_tail: *const [8]u8,
        now_ms: u64,
    ) Error!?Outbound {
        const index = self.findIndex(peer) orelse return null;
        const stored = &self.entries[index].?;
        const active = if (stored.session) |*value| value else return null;
        const counter = std.math.add(u32, active.nonce_counter, 1) catch {
            clearSession(&stored.session);
            return Error.NonceExhausted;
        };
        const nonce = makeNonce(counter, random_tail);
        active.nonce_counter = counter;
        stored.last_used_ms = now_ms;
        return .{ .write_key = active.write_key, .nonce = nonce };
    }

    pub fn install(
        self: *Table,
        peer: types.Endpoint,
        active: *const Session,
        now_ms: u64,
    ) void {
        const stored = self.getOrCreate(peer, now_ms);
        clearSession(&stored.session);
        stored.session = active.*;
        stored.challenge = null;
        stored.last_used_ms = now_ms;
    }

    pub fn putChallenge(
        self: *Table,
        peer: types.Endpoint,
        data: *const [constants.whoareyou_packet_size]u8,
        now_ms: u64,
    ) bool {
        const stored = self.getOrCreate(peer, now_ms);
        if (stored.challenge != null) return false;
        stored.challenge = .{ .data = data.*, .sent_at_ms = now_ms };
        stored.last_used_ms = now_ms;
        return true;
    }

    pub fn getChallenge(
        self: *Table,
        peer: types.Endpoint,
        now_ms: u64,
    ) ?Challenge {
        const index = self.findIndex(peer) orelse return null;
        const stored = &self.entries[index].?;
        const challenge = stored.challenge orelse return null;
        stored.last_used_ms = now_ms;
        return challenge;
    }

    pub fn expireChallenges(self: *Table, now_ms: u64, timeout_ms: u64) usize {
        var expired: usize = 0;
        for (self.activeEntries()) |*slot| {
            const stored = if (slot.*) |*entry| entry else continue;
            const challenge = stored.challenge orelse continue;
            if (now_ms < challenge.sent_at_ms) continue;
            if (now_ms - challenge.sent_at_ms < timeout_ms) continue;
            stored.challenge = null;
            expired += 1;
            if (stored.session == null) clearEntry(slot);
        }
        return expired;
    }

    pub fn sessionCount(self: *const Table) usize {
        var count: usize = 0;
        for (self.activeEntriesConst()) |entry| if (entry != null and entry.?.session != null) {
            count += 1;
        };
        return count;
    }

    pub fn challengeCount(self: *const Table) usize {
        var count: usize = 0;
        for (self.activeEntriesConst()) |entry| if (entry != null and entry.?.challenge != null) {
            count += 1;
        };
        return count;
    }

    fn findIndex(self: *const Table, peer: types.Endpoint) ?usize {
        for (self.activeEntriesConst(), 0..) |entry, index| {
            if (entry) |stored| if (types.Endpoint.eql(stored.peer, peer)) return index;
        }
        return null;
    }

    fn getOrCreate(self: *Table, peer: types.Endpoint, now_ms: u64) *Entry {
        if (self.findIndex(peer)) |index| return &self.entries[index].?;
        const index = self.replacementIndex();
        clearEntry(&self.entries[index]);
        self.entries[index] = .{ .peer = peer, .last_used_ms = now_ms };
        return &self.entries[index].?;
    }

    fn replacementIndex(self: *const Table) usize {
        var oldest_any: usize = 0;
        var oldest_challenge_only: ?usize = null;
        for (self.activeEntriesConst(), 0..) |entry, index| {
            const stored = entry orelse return index;
            if (stored.last_used_ms < self.entries[oldest_any].?.last_used_ms)
                oldest_any = index;
            if (stored.session == null) {
                if (oldest_challenge_only == null or stored.last_used_ms <
                    self.entries[oldest_challenge_only.?].?.last_used_ms)
                {
                    oldest_challenge_only = index;
                }
            }
        }
        return oldest_challenge_only orelse oldest_any;
    }

    fn activeEntries(self: *Table) []?Entry {
        return self.entries[0..self.capacity];
    }

    fn activeEntriesConst(self: *const Table) []const ?Entry {
        return self.entries[0..self.capacity];
    }
};

pub fn makeNonce(counter: u32, random_tail: *const [8]u8) [constants.nonce_size]u8 {
    std.debug.assert(counter >= first_nonce_counter);
    var nonce: [constants.nonce_size]u8 = undefined;
    std.mem.writeInt(u32, nonce[0..4], counter, .big);
    @memcpy(nonce[4..], random_tail);
    return nonce;
}

fn clearSession(active: *?Session) void {
    if (active.*) |*session| std.crypto.secureZero(u8, std.mem.asBytes(session));
    active.* = null;
}

fn clearEntry(entry: *?Entry) void {
    if (entry.*) |*stored| clearSession(&stored.session);
    entry.* = null;
}

comptime {
    std.debug.assert(@sizeOf(Entry) <= 224);
    std.debug.assert(@sizeOf(Table) <= 56 * 1_024);
}
