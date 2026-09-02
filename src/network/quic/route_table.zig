const std = @import("std");
const binding = @import("binding.zig");
const limits = @import("limits.zig");

const assert = std.debug.assert;
const Cid = binding.Cid;

pub const probe_max: usize = 64;
pub const routes_per_slot: usize = 2;

pub const Error = error{Full};

const Entry = struct {
    cid: Cid = .{},
    index: u16 = 0,
    used: bool = false,
};

pub const RouteTable = struct {
    entries: []Entry,
    seed: u64,
    count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        slots: u16,
        seed: u64,
    ) std.mem.Allocator.Error!RouteTable {
        assert(slots > 0);
        assert(slots <= limits.connections_max_ceiling);
        const wanted = 2 * routes_per_slot * @as(usize, slots);
        const entry_count = std.math.ceilPowerOfTwoAssert(usize, wanted);
        const entries = try allocator.alloc(Entry, entry_count);
        @memset(entries, .{});
        assert(std.math.isPowerOfTwo(entries.len));
        return .{ .entries = entries, .seed = seed };
    }

    pub fn deinit(self: *RouteTable, allocator: std.mem.Allocator) void {
        assert(self.count <= self.entries.len);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn capacity(self: *const RouteTable) usize {
        assert(std.math.isPowerOfTwo(self.entries.len));
        assert(self.count <= self.entries.len);
        return self.entries.len;
    }

    pub fn insert(self: *RouteTable, cid: *const Cid, index: u16) Error!void {
        assert(cid.len > 0);
        assert(cid.len <= limits.cid_length_max);
        if (self.count >= self.entries.len / 2) return error.Full;
        const mask = self.entries.len - 1;
        var cursor = self.bucket(cid);
        var probes: usize = 0;
        while (probes < probe_max) : (probes += 1) {
            const entry = &self.entries[cursor];
            if (!entry.used) {
                entry.* = .{ .cid = cid.*, .index = index, .used = true };
                self.count += 1;
                assert(self.count <= self.entries.len / 2);
                return;
            }
            cursor = (cursor + 1) & mask;
        }
        return error.Full;
    }

    pub fn find(self: *const RouteTable, cid: *const Cid) ?u16 {
        assert(cid.len <= limits.cid_length_max);
        assert(self.count <= self.entries.len);
        if (cid.len == 0) return null;
        const mask = self.entries.len - 1;
        var cursor = self.bucket(cid);
        var probes: usize = 0;
        while (probes < probe_max) : (probes += 1) {
            const entry = &self.entries[cursor];
            if (!entry.used) return null;
            if (entry.cid.eql(cid)) return entry.index;
            cursor = (cursor + 1) & mask;
        }
        return null;
    }

    pub fn remove(self: *RouteTable, cid: *const Cid, index: u16) void {
        assert(cid.len > 0);
        assert(self.count <= self.entries.len);
        const mask = self.entries.len - 1;
        var cursor = self.bucket(cid);
        var probes: usize = 0;
        while (probes < probe_max) : (probes += 1) {
            const entry = &self.entries[cursor];
            if (!entry.used) return;
            if (entry.index == index and entry.cid.eql(cid)) {
                self.evict(cursor);
                return;
            }
            cursor = (cursor + 1) & mask;
        }
    }

    pub fn removeAll(self: *RouteTable, index: u16) void {
        assert(self.count <= self.entries.len);
        var position: usize = 0;
        while (position < self.entries.len) {
            const entry = &self.entries[position];
            if (entry.used and entry.index == index) {
                self.evict(position);
                continue;
            }
            position += 1;
        }
        assert(self.count <= self.entries.len);
    }

    fn evict(self: *RouteTable, at: usize) void {
        assert(self.entries[at].used);
        assert(self.count > 0);
        const mask = self.entries.len - 1;
        self.entries[at] = .{};
        self.count -= 1;
        var cursor = (at + 1) & mask;
        var moved: usize = 0;
        while (moved < probe_max) : (moved += 1) {
            const entry = self.entries[cursor];
            if (!entry.used) return;
            self.entries[cursor] = .{};
            self.count -= 1;
            self.reinsert(&entry);
            cursor = (cursor + 1) & mask;
        }
    }

    fn reinsert(self: *RouteTable, entry: *const Entry) void {
        assert(entry.used);
        const mask = self.entries.len - 1;
        var cursor = self.bucket(&entry.cid);
        var probes: usize = 0;
        while (probes < probe_max) : (probes += 1) {
            if (!self.entries[cursor].used) {
                self.entries[cursor] = entry.*;
                self.count += 1;
                return;
            }
            cursor = (cursor + 1) & mask;
        }
        unreachable;
    }

    fn bucket(self: *const RouteTable, cid: *const Cid) usize {
        assert(std.math.isPowerOfTwo(self.entries.len));
        const mask = self.entries.len - 1;
        const hashed = std.hash.Wyhash.hash(self.seed, cid.slice());
        return @as(usize, @truncate(hashed)) & mask;
    }
};

comptime {
    assert(std.math.isPowerOfTwo(probe_max));
    assert(routes_per_slot == 2);
}
