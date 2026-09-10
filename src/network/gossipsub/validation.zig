const std = @import("std");
const storage = @import("message_store.zig");
const topic_mod = @import("topic.zig");
const assert = std.debug.assert;

pub const Handle = struct { index: u32, generation: u64 };
const Peers = @import("peer_book.zig").PeerBook;
pub const PeerRef = @import("peer_book.zig").Ref;
pub const Verdict = enum { accept, reject, ignore };
pub const Outcome = union(enum) { applied: Verdict, already_resolved, expired, stale_handle };
pub const duplicates_max = 16;
pub const Duplicate = struct { peer: PeerRef, eligible: bool };
pub const Entry = struct {
    generation: u64 = 0,
    state: union(enum) {
        free,
        pending: struct { message: storage.Handle, delivery: u32, deadline: u64 },
        resolved: u64,
        expired: u64,
    } = .free,
};

pub const Delivery = struct {
    handle: Handle = undefined,
    state: enum { free, pending, resolved } = .free,
    until: u64 = 0,
    verdict: Verdict = .ignore,
    id: topic_mod.MessageId = undefined,
    source: PeerRef = undefined,
    topic: topic_mod.Ref = undefined,
    admitted_ms: u64 = 0,
    source_eligible: bool = false,
    pinned: bool = false,
    duplicates: [duplicates_max]Duplicate = undefined,
    duplicate_len: u8 = 0,
};

pub const MessageEvent = struct {
    handle: Handle,
    id: topic_mod.MessageId,
    peer: @import("../quic/engine.zig").Handle,
    topic: []const u8,
    bytes: []const u8,
    identity: @import("../wire/peer_id.zig").PeerId,
    admitted_ms: u64,
    deadline: u64,
};
pub const Workspace = struct {
    arena: []u8,
    scratch: []u8,
    used: *usize,
    peer_work: *usize,
    work: *usize,
    large_used: *bool,
    event_available: bool,
};
pub const InvalidReason = enum { signed, compressed_size, ssz_size, snappy };
pub const Received = union(enum) { ignored, invalid: InvalidReason, duplicate: topic_mod.MessageId, admitted: MessageEvent, blocked: enum { events, storage, work } };
pub const Applied = struct {
    verdict: Verdict,
    id: topic_mod.MessageId,
    source: @import("../wire/peer_id.zig").PeerId,
    admitted_ms: u64,
    topic_bytes: [topic_mod.topic_max_len]u8,
    topic_len: u8,
    forward: ?struct { message: storage.Handle, source: PeerRef, topic: topic_mod.Ref } = null,

    pub fn topicString(self: *const Applied) []const u8 {
        return self.topic_bytes[0..self.topic_len];
    }
};

pub const Report = union(enum) {
    applied: Applied,
    already_resolved,
    expired,
    stale_handle,

    pub fn outcome(self: *const Report) Outcome {
        return switch (self.*) {
            .applied => |applied| .{ .applied = applied.verdict },
            .already_resolved => .already_resolved,
            .expired => .expired,
            .stale_handle => .stale_handle,
        };
    }
};

pub const Validation = struct {
    entries: []Entry,
    recent: []Delivery,
    recent_cursor: usize = 0,
    delivery_evictions: u64 = 0,
    cursor: usize = 0,
    timeout_ms: u64,
    tombstone_ms: u64,

    pub fn init(a: std.mem.Allocator, capacity: usize, timeout_ms: u64, tombstone_ms: u64) !Validation {
        if (capacity == 0 or capacity > 8192 or timeout_ms == 0 or tombstone_ms == 0) return error.InvalidLimits;
        const entries = try a.alloc(Entry, capacity);
        errdefer a.free(entries);
        @memset(entries, .{});
        const recent = try a.alloc(Delivery, capacity * 4);
        errdefer a.free(recent);
        @memset(recent, .{});
        return .{ .entries = entries, .recent = recent, .timeout_ms = timeout_ms, .tombstone_ms = tombstone_ms };
    }

    pub fn deinit(self: *Validation, a: std.mem.Allocator) void {
        a.free(self.recent);
        a.free(self.entries);
        self.* = undefined;
    }

    pub fn clear(self: *Validation, store: *storage.Store, peers: *Peers) void {
        for (self.entries) |*entry| {
            if (entry.state == .pending) store.releaseValidation(entry.state.pending.message);
            entry.state = .free;
        }
        for (self.recent) |*record| {
            releaseAttribution(record, peers);
            record.state = .free;
        }
    }

    pub fn memoryBytes(self: *const Validation) usize {
        return self.entries.len * @sizeOf(Entry) + self.recent.len * @sizeOf(Delivery);
    }

    pub fn available(self: *const Validation) bool {
        for (self.entries) |*e| if (e.state != .pending and e.generation != std.math.maxInt(u64)) return true;
        return false;
    }

    pub fn admit(self: *Validation, store: *storage.Store, peers: *Peers, message: storage.Handle, source: PeerRef, topic: topic_mod.Ref, now: u64) Handle {
        assert(self.available() and topic.generation > 0);
        const id = store.get(message).?.id;
        for (self.recent) |*record| {
            if (record.state == .free or !std.mem.eql(u8, &record.id, &id)) continue;
            assert(record.state != .pending);
            const previous = &self.entries[record.handle.index];
            if (previous.generation == record.handle.generation and previous.generation < std.math.maxInt(u64)) self.cursor = record.handle.index;
            releaseAttribution(record, peers);
            record.state = .free;
        }
        for (0..self.entries.len) |_| {
            const index = self.cursor;
            self.cursor = (index + 1) % self.entries.len;
            const e = &self.entries[index];
            if (e.state == .pending or e.generation == std.math.maxInt(u64)) continue;
            const record = self.reserveDelivery(peers, now);
            peers.retain(source);
            self.recent[record] = .{ .handle = .{ .index = @intCast(index), .generation = e.generation + 1 }, .state = .pending, .id = id, .source = source, .topic = topic, .admitted_ms = now, .pinned = true };
            e.* = .{ .generation = e.generation + 1, .state = .{ .pending = .{ .message = message, .delivery = record, .deadline = now +| self.timeout_ms } } };
            store.retainValidation(message);
            return .{ .index = @intCast(index), .generation = e.generation };
        }
        unreachable;
    }

    fn reserveDelivery(self: *Validation, peers: *Peers, now: u64) u32 {
        for (0..self.recent.len) |_| {
            const index = self.recent_cursor;
            self.recent_cursor = (index + 1) % self.recent.len;
            const record = &self.recent[index];
            if (record.state == .pending) continue;
            if (record.pinned and now < record.until) self.delivery_evictions +|= 1;
            releaseAttribution(record, peers);
            return @intCast(index);
        }
        unreachable;
    }

    pub fn delivery(self: *Validation, h: Handle) *Delivery {
        const e = &self.entries[h.index];
        assert(e.generation == h.generation and e.state == .pending);
        const record = &self.recent[e.state.pending.delivery];
        assert(record.state == .pending);
        return record;
    }

    pub fn find(self: *Validation, id: topic_mod.MessageId, now: u64) ?*Delivery {
        for (self.recent) |*e| {
            if (e.state == .free or (e.state == .resolved and now >= e.until)) continue;
            if (std.mem.eql(u8, &e.id, &id)) return e;
        }
        return null;
    }

    pub fn duplicate(e: *Delivery, peers: *Peers, peer: PeerRef, eligible: bool) bool {
        if (!e.pinned or std.meta.eql(e.source, peer)) return false;
        for (e.duplicates[0..e.duplicate_len]) |d| if (std.meta.eql(d.peer, peer)) return false;
        if (e.duplicate_len == duplicates_max) return false;
        peers.retain(peer);
        e.duplicates[e.duplicate_len] = .{ .peer = peer, .eligible = eligible };
        e.duplicate_len += 1;
        return true;
    }

    pub fn inspect(self: *Validation, store: *storage.Store, peers: *Peers, h: Handle, now: u64) ?Outcome {
        if (h.index >= self.entries.len) return .stale_handle;
        const e = &self.entries[h.index];
        if (e.generation != h.generation) return .stale_handle;
        self.expireEntry(store, peers, e, now);
        return switch (e.state) {
            .pending => null,
            .resolved => |until| if (now < until) .already_resolved else .stale_handle,
            .expired => |until| if (now < until) .expired else .stale_handle,
            .free => .stale_handle,
        };
    }

    pub fn finish(self: *Validation, store: *storage.Store, peers: *Peers, h: Handle, verdict: Verdict, now: u64) void {
        _ = peers;
        const e = &self.entries[h.index];
        assert(e.state == .pending and e.generation == h.generation and now < e.state.pending.deadline);
        const pending = e.state.pending;
        const record = &self.recent[pending.delivery];
        record.state = .resolved;
        record.verdict = verdict;
        record.until = now +| self.tombstone_ms;
        e.state = .{ .resolved = record.until };
        store.releaseValidation(pending.message);
    }

    pub fn expire(self: *Validation, store: *storage.Store, peers: *Peers, now: u64) void {
        for (self.entries) |*e| self.expireEntry(store, peers, e, now);
        for (self.recent) |*record| {
            if (record.state != .resolved or now < record.until) continue;
            releaseAttribution(record, peers);
            record.state = .free;
        }
    }

    fn expireEntry(self: *Validation, store: *storage.Store, peers: *Peers, e: *Entry, now: u64) void {
        if (e.state != .pending or now < e.state.pending.deadline) return;
        const pending = e.state.pending;
        const record = &self.recent[pending.delivery];
        std.log.scoped(.network_gossip).debug("validation_expired message_id={x} topic_index={d} generation={d} elapsed_ms={d}", .{ record.id, record.topic.index, e.generation, now -| record.admitted_ms });
        releaseAttribution(record, peers);
        record.state = .free;
        e.state = .{ .expired = pending.deadline +| self.tombstone_ms };
        store.releaseValidation(pending.message);
    }

    pub fn nextDeadline(self: *const Validation) ?u64 {
        var next: ?u64 = null;
        for (self.entries) |*e| if (e.state == .pending) {
            const deadline = e.state.pending.deadline;
            next = @min(next orelse deadline, deadline);
        };
        return next;
    }
};

fn releaseAttribution(e: *Delivery, peers: *Peers) void {
    if (!e.pinned) return;
    peers.release(e.source);
    for (e.duplicates[0..e.duplicate_len]) |d| peers.release(d.peer);
    e.pinned = false;
}

test "gossip validation expires without pump and resolves exactly once" {
    var peers = try Peers.init(std.testing.allocator, 100);
    defer peers.deinit(std.testing.allocator);
    peers.rows[0] = .{ .occupied = true, .generation = 1 };
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var v = try Validation.init(std.testing.allocator, 1, 10, 20);
    defer v.deinit(std.testing.allocator);
    const m = store.put([_]u8{1} ** 20, "t", "body").?;
    const h = v.admit(&store, &peers, m, .{ .index = 0, .generation = 1 }, .{ .index = 0, .generation = 1 }, 100);
    store.seal(m);
    try std.testing.expect(v.inspect(&store, &peers, h, 109) == null);
    try std.testing.expectEqual(Outcome.expired, v.inspect(&store, &peers, h, 110).?);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(Outcome.stale_handle, v.inspect(&store, &peers, h, 130).?);
    const m2 = store.put([_]u8{2} ** 20, "t", "body").?;
    peers.rows[0].generation = 2;
    const h2 = v.admit(&store, &peers, m2, .{ .index = 0, .generation = 2 }, .{ .index = 0, .generation = 1 }, 130);
    store.seal(m2);
    try std.testing.expectEqual(Outcome.stale_handle, v.inspect(&store, &peers, h, 130).?);
    v.finish(&store, &peers, h2, .ignore, 131);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, h2, 132).?);
}

test "gossip validation readmission skips exhausted generation without hiding pending ID" {
    var peers = try Peers.init(std.testing.allocator, 100);
    defer peers.deinit(std.testing.allocator);
    peers.rows[0] = .{ .occupied = true, .generation = 1 };
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var v = try Validation.init(std.testing.allocator, 2, 10, 20);
    defer v.deinit(std.testing.allocator);
    v.entries[0].generation = std.math.maxInt(u64) - 1;
    const id = [_]u8{1} ** 20;
    const source: PeerRef = .{ .index = 0, .generation = 1 };
    const first = store.put(id, "t", "body").?;
    const old = v.admit(&store, &peers, first, source, .{ .index = 0, .generation = 1 }, 100);
    store.seal(first);
    v.finish(&store, &peers, old, .ignore, 101);
    const second = store.put(id, "t", "body").?;
    const current = v.admit(&store, &peers, second, source, .{ .index = 0, .generation = 1 }, 102);
    store.seal(second);
    try std.testing.expectEqual(std.math.maxInt(u64), old.generation);
    try std.testing.expectEqual(@as(u64, 1), current.generation);
    try std.testing.expect(old.index != current.index);
    try std.testing.expectEqual(v.delivery(current), v.find(id, 103).?);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, old, 103).?);
    try std.testing.expectEqual(@as(usize, 1), store.used_entries);
    v.finish(&store, &peers, current, .reject, 104);
    try std.testing.expectEqual(Verdict.reject, v.find(id, 105).?.verdict);
    try std.testing.expectEqual(Outcome.already_resolved, v.inspect(&store, &peers, old, 105).?);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(store.next.len, store.free_pages);
}
