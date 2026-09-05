const std = @import("std");
const storage = @import("message_store.zig");
const topic_mod = @import("topic.zig");
const assert = std.debug.assert;

pub const Handle = struct { index: u32, generation: u64 };
pub const PeerRef = struct { index: u16, generation: u32 };
pub const Verdict = enum { accept, reject, ignore };
pub const Outcome = union(enum) { applied: Verdict, already_resolved, expired, stale_handle };
pub const duplicates_max = 16;
pub const Duplicate = struct { peer: PeerRef, eligible: bool };
pub const Entry = struct {
    generation: u64 = 0,
    state: enum { free, pending, resolved, expired } = .free,
    deadline: u64 = 0,
    tombstone_until: u64 = 0,
    verdict: Verdict = .ignore,
    superseded: bool = false,
    message: storage.Handle = undefined,
    id: topic_mod.MessageId = undefined,
    source: PeerRef = undefined,
    topic: u16 = 0,
    duplicates: [duplicates_max]Duplicate = undefined,
    duplicate_len: u8 = 0,
};

pub const Validation = struct {
    entries: []Entry,
    cursor: usize = 0,
    timeout_ms: u64,
    tombstone_ms: u64,

    pub fn init(a: std.mem.Allocator, capacity: usize, timeout_ms: u64, tombstone_ms: u64) !Validation {
        if (capacity == 0 or capacity > 8192 or timeout_ms == 0 or tombstone_ms == 0) return error.InvalidLimits;
        const entries = try a.alloc(Entry, capacity);
        @memset(entries, .{});
        return .{ .entries = entries, .timeout_ms = timeout_ms, .tombstone_ms = tombstone_ms };
    }
    pub fn deinit(self: *Validation, a: std.mem.Allocator) void {
        a.free(self.entries);
        self.* = undefined;
    }
    pub fn available(self: *const Validation) bool {
        for (self.entries) |e| if (e.state != .pending and e.generation != std.math.maxInt(u64)) return true;
        return false;
    }
    pub fn admit(self: *Validation, store: *storage.Store, message: storage.Handle, source: PeerRef, topic: u16, now: u64) Handle {
        assert(self.available());
        const id = store.get(message).?.id;
        for (self.entries, 0..) |*e, index| {
            if (e.state == .free or e.superseded or !std.mem.eql(u8, &e.id, &id)) continue;
            assert(e.state != .pending);
            if (e.generation == std.math.maxInt(u64)) {
                // Preserve the old handle outcome without letting it own the replacement's ID lookup.
                e.superseded = true;
                continue;
            }
            self.cursor = index;
            break;
        }
        for (0..self.entries.len) |_| {
            const index = self.cursor;
            self.cursor = (index + 1) % self.entries.len;
            const e = &self.entries[index];
            if (e.state == .pending or e.generation == std.math.maxInt(u64)) continue;
            e.* = .{
                .generation = e.generation + 1,
                .state = .pending,
                .deadline = now +| self.timeout_ms,
                .message = message,
                .id = id,
                .source = source,
                .topic = topic,
            };
            store.retainValidation(message);
            return .{ .index = @intCast(index), .generation = e.generation };
        }
        unreachable;
    }
    pub fn find(self: *Validation, id: topic_mod.MessageId, now: u64) ?*Entry {
        for (self.entries) |*e| {
            if (e.state == .free or e.superseded) continue;
            if (e.state != .pending and now >= e.tombstone_until) continue;
            if (std.mem.eql(u8, &e.id, &id)) return e;
        }
        return null;
    }
    pub fn duplicate(e: *Entry, peer: PeerRef, eligible: bool) bool {
        if (std.meta.eql(e.source, peer)) return false;
        for (e.duplicates[0..e.duplicate_len]) |d| if (std.meta.eql(d.peer, peer)) return false;
        if (e.duplicate_len == duplicates_max) return false;
        e.duplicates[e.duplicate_len] = .{ .peer = peer, .eligible = eligible };
        e.duplicate_len += 1;
        return true;
    }
    pub fn inspect(self: *Validation, store: *storage.Store, h: Handle, now: u64) ?Outcome {
        if (h.index >= self.entries.len) return .stale_handle;
        const e = &self.entries[h.index];
        if (e.generation != h.generation or e.state == .free) return .stale_handle;
        self.expireEntry(store, e, now);
        return switch (e.state) {
            .pending => null,
            .resolved => if (now < e.tombstone_until) .already_resolved else .stale_handle,
            .expired => if (now < e.tombstone_until) .expired else .stale_handle,
            .free => .stale_handle,
        };
    }
    pub fn finish(self: *Validation, store: *storage.Store, h: Handle, verdict: Verdict, now: u64) void {
        const e = &self.entries[h.index];
        assert(e.state == .pending and e.generation == h.generation and now < e.deadline);
        e.state = .resolved;
        e.verdict = verdict;
        e.tombstone_until = now +| self.tombstone_ms;
        store.releaseValidation(e.message);
    }
    pub fn expire(self: *Validation, store: *storage.Store, now: u64) void {
        for (self.entries) |*e| self.expireEntry(store, e, now);
    }
    fn expireEntry(self: *Validation, store: *storage.Store, e: *Entry, now: u64) void {
        if (e.state != .pending or now < e.deadline) return;
        e.state = .expired;
        e.tombstone_until = e.deadline +| self.tombstone_ms;
        store.releaseValidation(e.message);
    }
    pub fn nextDeadline(self: *const Validation) ?u64 {
        var next: ?u64 = null;
        for (self.entries) |e| if (e.state == .pending) {
            next = @min(next orelse e.deadline, e.deadline);
        };
        return next;
    }
};

test "gossip validation expires without pump and resolves exactly once" {
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var v = try Validation.init(std.testing.allocator, 1, 10, 20);
    defer v.deinit(std.testing.allocator);
    const m = store.put([_]u8{1} ** 20, "t", "body").?;
    const h = v.admit(&store, m, .{ .index = 0, .generation = 1 }, 0, 100);
    store.seal(m);
    try std.testing.expect(v.inspect(&store, h, 109) == null);
    try std.testing.expectEqual(Outcome.expired, v.inspect(&store, h, 110).?);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(Outcome.stale_handle, v.inspect(&store, h, 130).?);
    const m2 = store.put([_]u8{2} ** 20, "t", "body").?;
    const h2 = v.admit(&store, m2, .{ .index = 0, .generation = 2 }, 0, 130);
    store.seal(m2);
    try std.testing.expectEqual(Outcome.stale_handle, v.inspect(&store, h, 130).?);
    v.finish(&store, h2, .ignore, 131);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, h2, 132).?);
}

test "gossip validation readmission skips exhausted generation without hiding pending ID" {
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var v = try Validation.init(std.testing.allocator, 2, 10, 20);
    defer v.deinit(std.testing.allocator);
    v.entries[0].generation = std.math.maxInt(u64) - 1;
    const id = [_]u8{1} ** 20;
    const source: PeerRef = .{ .index = 0, .generation = 1 };
    const first = store.put(id, "t", "body").?;
    const old = v.admit(&store, first, source, 0, 100);
    store.seal(first);
    v.finish(&store, old, .ignore, 101);
    const second = store.put(id, "t", "body").?;
    const current = v.admit(&store, second, source, 0, 102);
    store.seal(second);
    try std.testing.expectEqual(std.math.maxInt(u64), old.generation);
    try std.testing.expectEqual(@as(u64, 1), current.generation);
    try std.testing.expect(old.index != current.index);
    try std.testing.expectEqual(&v.entries[current.index], v.find(id, 103).?);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, old, 103).?);
    try std.testing.expectEqual(@as(usize, 1), store.used_entries);
    v.finish(&store, current, .reject, 104);
    try std.testing.expectEqual(Verdict.reject, v.find(id, 105).?.verdict);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, old, 105).?);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(store.next.len, store.free_pages);
}
