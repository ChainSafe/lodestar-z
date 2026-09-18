const std = @import("std");
const mcache = @import("mcache.zig");
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
    reserved: bool = false,
    state: union(enum) {
        free,
        pending: struct { message: storage.Handle, delivery: u32, deadline: u64 },
        resolved: u64,
        expired: u64,
    } = .free,
};

pub const Attribution = struct {
    reserved: bool = false,
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

pub const Validation = struct {
    entries: []Entry,
    recent: []Attribution,
    index: mcache.IdIndex(Attribution),
    recent_cursor: usize = 0,
    delivery_evictions: u64 = 0,
    cursor: usize = 0,
    timeout_ms: u64,
    tombstone_ms: u64,
    pending_per_peer_kind: [@import("peer_book.zig").capacity][@import("../gossip_processor/limits.zig").kind_count]u16 = @splat(@splat(0)),
    pending_per_kind: [@import("../gossip_processor/limits.zig").kind_count]usize = @splat(0),
    pending_per_peer: [@import("peer_book.zig").capacity]u16 = @splat(0),

    pub fn init(a: std.mem.Allocator, capacity: usize, timeout_ms: u64, tombstone_ms: u64) !Validation {
        if (capacity == 0 or capacity > 65535 or timeout_ms == 0 or tombstone_ms == 0) return error.InvalidLimits;
        const entries = try a.alloc(Entry, capacity);
        errdefer a.free(entries);
        @memset(entries, .{});
        const recent = try a.alloc(Attribution, attributionCapacity(capacity));
        errdefer a.free(recent);
        @memset(recent, .{});
        const index = try mcache.IdIndex(Attribution).init(a, recent);
        return .{ .entries = entries, .recent = recent, .index = index, .timeout_ms = timeout_ms, .tombstone_ms = tombstone_ms };
    }

    pub fn deinit(self: *Validation, a: std.mem.Allocator, store: *storage.Store, peers: *Peers) void {
        self.clear(store, peers);
        self.index.deinit(a);
        a.free(self.recent);
        a.free(self.entries);
        self.* = undefined;
    }

    pub fn clear(self: *Validation, store: *storage.Store, peers: *Peers) void {
        @memset(&self.pending_per_peer, 0);
        @memset(&self.pending_per_peer_kind, @splat(0));
        @memset(&self.pending_per_kind, 0);
        for (self.entries) |*entry| {
            assert(!entry.reserved);
            if (entry.state == .pending) store.releaseValidation(entry.state.pending.message);
            entry.state = .free;
        }
        for (self.recent) |*record| {
            assert(!record.reserved);
            releaseAttribution(record, peers);
            record.state = .free;
        }
        self.index.clear();
    }

    pub fn backingBytes(capacity: usize) usize {
        return capacity * @sizeOf(Entry) + attributionCapacity(capacity) * @sizeOf(Attribution) +
            mcache.indexCapacity(attributionCapacity(capacity)) * @sizeOf(u32);
    }

    pub fn attributionCapacity(capacity: usize) usize {
        return capacity * 4;
    }

    pub fn available(self: *const Validation) bool {
        for (self.entries) |*e| if (!e.reserved and e.state != .pending and e.generation != std.math.maxInt(u64)) return true;
        return false;
    }

    pub const Reservation = struct {
        owner: ?*Validation,
        index: u32,
        record: u32,
        previous: ?u32,

        pub fn cancel(self: *Reservation) void {
            const owner = self.owner orelse return;
            assert(owner.entries[self.index].reserved and owner.recent[self.record].reserved);
            owner.entries[self.index].reserved = false;
            owner.recent[self.record].reserved = false;
            self.owner = null;
        }

        pub fn commit(self: *Reservation, store: *storage.Store, peers: *Peers, message: storage.Handle, source: PeerRef, topic: topic_mod.Ref, now: u64) Handle {
            const owner = self.owner.?;
            const entry = &owner.entries[self.index];
            const record = &owner.recent[self.record];
            assert(entry.reserved and record.reserved and topic.generation > 0);
            const id = store.get(message).?.id;
            if (self.previous) |index| if (index != self.record) {
                const prior = &owner.recent[index];
                assert(!prior.reserved and prior.state == .resolved and std.mem.eql(u8, &prior.id, &id));
                owner.index.remove(prior.id);
                releaseAttribution(prior, peers);
                prior.state = .free;
            };
            if (record.pinned and now < record.until and !std.mem.eql(u8, &record.id, &id)) owner.delivery_evictions +|= 1;
            if (record.state != .free) owner.index.remove(record.id);
            releaseAttribution(record, peers);
            const handle: Handle = .{ .index = self.index, .generation = entry.generation + 1 };
            peers.retain(source);
            owner.pending_per_peer[source.index] += 1;
            owner.pending_per_kind[@intFromEnum(store.get(message).?.kind)] += 1;
            owner.pending_per_peer_kind[source.index][@intFromEnum(store.get(message).?.kind)] += 1;
            record.* = .{ .handle = handle, .state = .pending, .id = id, .source = source, .topic = topic, .admitted_ms = now, .pinned = true };
            owner.index.insert(id, self.record);
            entry.* = .{ .generation = handle.generation, .state = .{ .pending = .{ .message = message, .delivery = self.record, .deadline = now +| owner.timeout_ms } } };
            store.retainValidation(message);
            self.owner = null;
            return handle;
        }
    };

    /// Acquires both operation and attribution slots without discarding previous
    /// outcomes. Cancellation leaves them intact if payload admission fails.
    /// Commit or cancel in the same owner call, before another validation mutation.
    pub fn reserve(self: *Validation, id: topic_mod.MessageId) ?Reservation {
        const previous_record = self.index.find(id);
        if (previous_record) |index| {
            const record = &self.recent[index];
            assert(record.state != .free);
            if (record.reserved or record.state == .pending) return null;
            const previous = &self.entries[record.handle.index];
            if (previous.generation == record.handle.generation and previous.generation < std.math.maxInt(u64)) self.cursor = record.handle.index;
        }
        for (0..self.entries.len) |_| {
            const index = self.cursor;
            self.cursor = (index + 1) % self.entries.len;
            const e = &self.entries[index];
            if (e.reserved or e.state == .pending or e.generation == std.math.maxInt(u64)) continue;
            const record = self.reserveAttribution();
            e.reserved = true;
            return .{ .owner = self, .index = @intCast(index), .record = record, .previous = previous_record };
        }
        return null;
    }

    fn reserveAttribution(self: *Validation) u32 {
        for (0..self.recent.len) |_| {
            const index = self.recent_cursor;
            self.recent_cursor = (index + 1) % self.recent.len;
            const record = &self.recent[index];
            if (record.reserved or record.state == .pending) continue;
            record.reserved = true;
            return @intCast(index);
        }
        unreachable;
    }

    pub fn attribution(self: *Validation, h: Handle) *Attribution {
        const e = &self.entries[h.index];
        assert(e.generation == h.generation and e.state == .pending);
        const record = &self.recent[e.state.pending.delivery];
        assert(record.state == .pending);
        return record;
    }

    pub fn find(self: *Validation, id: topic_mod.MessageId, now: u64) ?*Attribution {
        const slot = self.index.find(id) orelse return null;
        const record = &self.recent[slot];
        assert(record.state != .free);
        if (record.state == .resolved and now >= record.until) return null;
        return record;
    }

    pub fn duplicate(e: *Attribution, peers: *Peers, peer: PeerRef, eligible: bool) bool {
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

    pub fn finish(self: *Validation, store: *storage.Store, h: Handle, verdict: Verdict, now: u64) void {
        const e = &self.entries[h.index];
        assert(e.state == .pending and e.generation == h.generation and now < e.state.pending.deadline);
        const pending = e.state.pending;
        const record = &self.recent[pending.delivery];
        assert(self.pending_per_peer[record.source.index] > 0);
        self.pending_per_peer[record.source.index] -= 1;
        self.pending_per_kind[@intFromEnum(store.get(pending.message).?.kind)] -= 1;
        self.pending_per_peer_kind[record.source.index][@intFromEnum(store.get(pending.message).?.kind)] -= 1;
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
            self.index.remove(record.id);
            releaseAttribution(record, peers);
            record.state = .free;
        }
    }

    fn expireEntry(self: *Validation, store: *storage.Store, peers: *Peers, e: *Entry, now: u64) void {
        if (e.state != .pending or now < e.state.pending.deadline) return;
        const pending = e.state.pending;
        const record = &self.recent[pending.delivery];
        assert(self.pending_per_peer[record.source.index] > 0);
        self.pending_per_peer[record.source.index] -= 1;
        self.pending_per_kind[@intFromEnum(store.get(pending.message).?.kind)] -= 1;
        self.pending_per_peer_kind[record.source.index][@intFromEnum(store.get(pending.message).?.kind)] -= 1;
        std.log.scoped(.network_gossip).debug("validation_expired message_id={x} topic_index={d} generation={d} elapsed_ms={d}", .{ record.id, record.topic.index, e.generation, now -| record.admitted_ms });
        self.index.remove(record.id);
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

fn releaseAttribution(e: *Attribution, peers: *Peers) void {
    if (!e.pinned) return;
    peers.release(e.source);
    for (e.duplicates[0..e.duplicate_len]) |d| peers.release(d.peer);
    e.pinned = false;
}

test {
    _ = @import("validation_test.zig");
}
