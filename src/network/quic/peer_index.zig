const std = @import("std");
const limits = @import("limits.zig");
const peer_id = @import("../wire/peer_id.zig");

const assert = std.debug.assert;
const key_mixer: u64 = 0x9E37_79B9_7F4A_7C15;

pub const Entry = struct {
    key: u64 = 0,
    index: u16 = 0,
    generation: u32 = 0,
    used: bool = false,
};

pub fn keyOf(seed: u64, id: *const peer_id.PeerId) u64 {
    return std.hash.Wyhash.hash(seed, &id.bytes);
}

pub const Candidates = struct {
    index: *const PeerIndex,
    key: u64,
    cursor: usize,
    probes: usize = 0,

    pub fn next(self: *Candidates) ?Entry {
        const entries = self.index.entries;
        assert(self.probes <= entries.len);
        const mask = entries.len - 1;
        while (self.probes < entries.len) {
            const entry = entries[self.cursor];
            self.cursor = (self.cursor + 1) & mask;
            self.probes += 1;
            if (!entry.used) return null;
            if (entry.key == self.key) return entry;
        }
        return null;
    }
};

pub const PeerIndex = struct {
    entries: []Entry,

    pub fn init(allocator: std.mem.Allocator, slots: u16) std.mem.Allocator.Error!PeerIndex {
        assert(slots > 0);
        assert(slots <= limits.connections_max_ceiling);
        const wanted = 2 * @as(usize, slots);
        const entries = try allocator.alloc(Entry, std.math.ceilPowerOfTwoAssert(usize, wanted));
        @memset(entries, .{});
        assert(entries.len >= wanted);
        return .{ .entries = entries };
    }

    pub fn deinit(self: *PeerIndex, allocator: std.mem.Allocator) void {
        assert(std.math.isPowerOfTwo(self.entries.len));
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn candidates(self: *const PeerIndex, key: u64) Candidates {
        assert(std.math.isPowerOfTwo(self.entries.len));
        return .{ .index = self, .key = key, .cursor = self.bucket(key) };
    }

    pub fn insert(self: *PeerIndex, entry: Entry) void {
        assert(entry.used);
        assert(entry.index < self.entries.len / 2);
        const mask = self.entries.len - 1;
        var cursor = self.bucket(entry.key);
        var probes: usize = 0;
        while (probes < self.entries.len) : (probes += 1) {
            if (!self.entries[cursor].used) {
                self.entries[cursor] = entry;
                return;
            }
            cursor = (cursor + 1) & mask;
        }
        unreachable;
    }

    pub fn remove(self: *PeerIndex, key: u64, index: u16) void {
        assert(index < self.entries.len / 2);
        const mask = self.entries.len - 1;
        var cursor = self.bucket(key);
        var probes: usize = 0;
        while (probes < self.entries.len) : (probes += 1) {
            const entry = self.entries[cursor];
            if (!entry.used) return;
            if (entry.key == key and entry.index == index) {
                self.evict(cursor);
                return;
            }
            cursor = (cursor + 1) & mask;
        }
    }

    fn evict(self: *PeerIndex, at: usize) void {
        assert(self.entries[at].used);
        const mask = self.entries.len - 1;
        self.entries[at] = .{};
        var cursor = (at + 1) & mask;
        var probes: usize = 0;
        while (probes < self.entries.len) : (probes += 1) {
            const entry = self.entries[cursor];
            if (!entry.used) return;
            self.entries[cursor] = .{};
            self.insert(entry);
            cursor = (cursor + 1) & mask;
        }
    }

    fn bucket(self: *const PeerIndex, key: u64) usize {
        const mask = self.entries.len - 1;
        const mixed = key *% key_mixer;
        return @as(usize, @truncate(mixed >> 32)) & mask;
    }
};

comptime {
    assert(peer_id.length >= @sizeOf(u64));
}
