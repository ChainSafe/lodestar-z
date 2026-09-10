const std = @import("std");
const mcache = @import("mcache.zig");
const storage = @import("message_store.zig");
const validation = @import("validation.zig");
const Options = @import("options.zig").Options;
const topic_mod = @import("topic.zig");
const MessageId = topic_mod.MessageId;
const protobuf = @import("protobuf.zig");
const admission = @import("admission.zig");
const assert = std.debug.assert;
const PeerRef = validation.PeerRef;
const Workspace = @import("turn.zig").Workspace;
const Handle = validation.Handle;
const Verdict = validation.Verdict;
const Outcome = validation.Outcome;
const Attribution = validation.Attribution;
const Validation = validation.Validation;
const Peers = @import("peer_book.zig").PeerBook;

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

pub const Context = struct {
    overlay: *const @import("overlay.zig").Overlay,
    peers: *Peers,
    options: *const Options,
    epoch: u64,
};

pub const Source = struct {
    peer: PeerRef,
    session: @import("sessions.zig").SessionRef,
    connection: @import("../quic/engine.zig").Handle,
};

const FastEntry = struct {
    fingerprint: [32]u8 = @splat(0),
    result: union(enum) { empty, valid: topic_mod.MessageId, invalid: topic_mod.MessageId } = .empty,
};

pub const Messages = struct {
    store: storage.Store,
    history: mcache.History,
    seen: mcache.SeenCache,
    validation: validation.Validation,
    gossip_ids: []MessageId,
    decoded_messages: u64 = 0,
    fast_hits: u64 = 0,
    fast: []FastEntry,

    pub fn init(a: std.mem.Allocator, options: *const Options) !Messages {
        const layout = @import("layout.zig").Layout.init(options);
        return initLayout(a, options, &layout);
    }

    pub fn initLayout(a: std.mem.Allocator, options: *const Options, layout: *const @import("layout.zig").Layout) !Messages {
        var store = try storage.Store.init(a, layout.payload_entries, layout.payload_bytes);
        errdefer store.deinit(a);
        var history = try mcache.History.initCapacity(a, layout.history, layout.retained);
        errdefer history.deinit(a);
        var seen = try mcache.SeenCache.init(a, layout.seen, options.seen_ttl_ms);
        errdefer seen.deinit(a);
        var pending = try validation.Validation.init(a, layout.validations, options.validation_timeout_ms, options.validation_tombstone_ms);
        errdefer pending.deinit(a);
        const gossip_ids = try a.alloc(MessageId, layout.history);
        errdefer a.free(gossip_ids);
        const fast = try a.alloc(FastEntry, Validation.attributionCapacity(layout.validations));
        @memset(fast, .{});
        return .{ .store = store, .history = history, .seen = seen, .validation = pending, .gossip_ids = gossip_ids, .fast = fast };
    }

    pub fn deinit(self: *Messages, a: std.mem.Allocator, peers: *Peers) void {
        self.validation.clear(&self.store, peers);
        self.validation.deinit(a);
        self.history.deinit(a);
        self.seen.deinit(a);
        self.store.deinit(a);
        a.free(self.gossip_ids);
        a.free(self.fast);
        self.* = undefined;
    }

    pub fn metadataBytes(layout: *const @import("layout.zig").Layout) usize {
        return layout.payload_entries * @sizeOf(storage.Entry) + layout.payload_bytes / storage.page_bytes * @sizeOf(u32) +
            Validation.memoryBytes(layout.validations) + Validation.attributionCapacity(layout.validations) * @sizeOf(FastEntry) +
            layout.history * (@sizeOf(mcache.HistoryEntry) + layout.retained + 2 * @sizeOf(MessageId)) +
            layout.retained * @sizeOf(u64) + mcache.indexCapacity(layout.history) * @sizeOf(u32) +
            layout.seen * (@sizeOf(MessageId) + @sizeOf(u64)) + mcache.indexCapacity(layout.seen) * @sizeOf(u32);
    }

    pub const Stats = struct {
        seen: usize,
        history: usize,
        recent: usize = 0,
        pending: usize = 0,
        fast_hits: u64,
        decoded: u64,
        delivery_evictions: u64,
    };

    pub fn stats(self: *const Messages) Stats {
        var result: Stats = .{ .seen = self.seen.count, .history = self.history.count, .fast_hits = self.fast_hits, .decoded = self.decoded_messages, .delivery_evictions = self.validation.delivery_evictions };
        for (self.validation.recent) |*entry| result.recent += @intFromBool(entry.state != .free);
        for (self.validation.entries) |*entry| result.pending += @intFromBool(entry.state == .pending);
        return result;
    }

    pub fn validationCapacity(self: *const Messages) usize {
        return self.validation.entries.len;
    }

    pub fn nextDeadline(self: *const Messages) ?u64 {
        return self.validation.nextDeadline();
    }

    pub fn wasSeen(self: *Messages, id: MessageId, now: u64) bool {
        return self.seen.contains(id, now);
    }

    pub fn wants(self: *Messages, id: MessageId, now: u64) bool {
        return !self.seen.contains(id, now) and self.validation.find(id, now) == null;
    }

    pub fn hasPayload(self: *Messages, id: MessageId) bool {
        return self.history.get(&self.store, id) != null;
    }

    pub fn gossipIds(self: *Messages, topic: []const u8, epoch: u64) []MessageId {
        const count = self.history.gossip(&self.store, topic, self.gossip_ids, epoch);
        return self.gossip_ids[0..count];
    }

    pub const ServeOutcome = union(enum) {
        unknown,
        known: struct { topic: []const u8, result: enum { queued, limited, pressured } },
    };

    pub fn serve(self: *Messages, outbox: *@import("outbox.zig").Outbox, peer: PeerRef, id: MessageId, byte_limit: usize, now: u64) ServeOutcome {
        const entry = self.history.get(&self.store, id) orelse return .unknown;
        const topic = self.store.get(entry.message).?.topicString();
        self.history.bindPeer(peer);
        if (!self.history.iwantAllowed(entry, peer, @import("constants.zig").gossip_retransmission)) return .{ .known = .{ .topic = topic, .result = .limited } };
        const queued = outbox.queueData(&self.store, entry.message, byte_limit, now) == .queued;
        if (queued) self.history.sent(entry, peer);
        return .{ .known = .{ .topic = topic, .result = if (queued) .queued else .pressured } };
    }

    pub fn publish(self: *Messages, id: MessageId, name: []const u8, compressed: []const u8, now: u64, epoch: u64) ?storage.Handle {
        const handle = self.history.admitPayload(&self.store, id, name, compressed) orelse return null;
        self.history.put(&self.store, handle, epoch);
        self.store.seal(handle);
        std.debug.assert(self.seen.add(id, now));
        return handle;
    }

    pub fn receive(self: *Messages, context: *const Context, workspace: *const Workspace, source: *const Source, msg: protobuf.Message, now: u64) Received {
        const rule = if (context.overlay.namespace) |*ns| (ns.lookup(msg.topic) orelse return .ignored).rule else null;
        const topic = context.overlay.findTopic(msg.topic) orelse return .ignored;
        if (!context.overlay.subscribed(topic)) return .ignored;
        if (msg.signed) return invalid(context, source, topic, .signed);
        const header = admission.inspect(&msg);
        if (header == .rejected) return invalid(context, source, topic, if (msg.data.len > @import("constants.zig").maxCompressedLen(@import("constants.zig").MAX_PAYLOAD_SIZE)) .compressed_size else .ssz_size);
        if (header == .invalid) {
            if (!workspace.charge(context.options, msg.data.len, 0)) return .{ .blocked = .work };
            _ = self.seen.add(topic_mod.invalidMessageId(msg.topic, msg.data, context.options.message_id_policy), now);
            return invalid(context, source, topic, .snappy);
        }
        const size = header.payload;
        if (rule) |bounds| if (size < bounds.ssz_min or size > bounds.ssz_max) return invalid(context, source, topic, .ssz_size);
        if (!workspace.charge(context.options, msg.data.len, size)) return .{ .blocked = .work };
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&.{@intCast(msg.topic.len)});
        hash.update(msg.topic);
        hash.update(msg.data);
        const fingerprint = hash.finalResult();
        const cached = &self.fast[std.mem.readInt(u64, fingerprint[0..8], .little) % self.fast.len];
        if (std.mem.eql(u8, &cached.fingerprint, &fingerprint)) switch (cached.result) {
            .valid => |id| if (self.duplicateId(context, source, topic, id, now)) {
                self.fast_hits +|= 1;
                return .{ .duplicate = id };
            },
            .invalid => |id| {
                _ = self.seen.add(id, now);
                self.fast_hits +|= 1;
                return invalid(context, source, topic, .snappy);
            },
            .empty => {},
        };
        const room = workspace.arena[workspace.used.*..];
        const output = if (room.len >= size) room[0..size] else workspace.scratch[0..size];
        const decoded = admission.decode(&msg, output, context.options.message_id_policy);
        self.decoded_messages +|= 1;
        cached.* = .{ .fingerprint = fingerprint, .result = if (decoded == .invalid) .{ .invalid = decoded.invalid } else .{ .valid = decoded.valid.id } };
        if (decoded == .invalid) {
            _ = self.seen.add(decoded.invalid, now);
            return invalid(context, source, topic, .snappy);
        }
        const id = decoded.valid.id;
        if (self.duplicateId(context, source, topic, id, now)) return .{ .duplicate = id };
        if (!workspace.event_available or size + msg.topic.len > room.len) return .{ .blocked = .events };
        return self.admitReceived(context, workspace, source, topic, msg, id, size, now);
    }

    fn duplicateId(self: *Messages, context: *const Context, source: *const Source, topic: u16, id: topic_mod.MessageId, now: u64) bool {
        const pending = self.validation.find(id, now);
        if ((pending != null and pending.?.state == .pending) or self.seen.contains(id, now)) {
            if (pending) |entry| recordDuplicate(context, entry, source, topic, now);
            return true;
        }
        return false;
    }

    fn invalid(context: *const Context, source: *const Source, topic: u16, reason: InvalidReason) Received {
        const ref = source.peer;
        context.peers.invalid(ref, topic);
        return .{ .invalid = reason };
    }

    fn admitReceived(self: *Messages, context: *const Context, workspace: *const Workspace, source: *const Source, topic: u16, msg: protobuf.Message, id: topic_mod.MessageId, written: usize, now: u64) Received {
        var reservation = self.validation.reserve(id) orelse return .{ .blocked = .storage };
        defer reservation.cancel();
        const message = self.history.admitPayload(&self.store, id, msg.topic, msg.data) orelse return .{ .blocked = .storage };
        const handle = reservation.commit(&self.store, context.peers, message, source.peer, context.overlay.ref(topic), now);
        self.validation.attribution(handle).source_eligible = context.overlay.inMesh(topic, source.session.index);
        self.store.seal(message);
        const room = workspace.arena[workspace.used.*..];
        @memcpy(room[written..][0..msg.topic.len], msg.topic);
        workspace.used.* += written + msg.topic.len;
        _ = self.seen.add(id, now);
        const entry = self.validation.attribution(handle);
        assert(context.peers.matches(entry.source));
        return .{ .admitted = .{ .identity = context.peers.rows[entry.source.index].identity, .admitted_ms = entry.admitted_ms, .deadline = self.validation.entries[handle.index].state.pending.deadline, .handle = handle, .id = id, .peer = source.connection, .topic = room[written..][0..msg.topic.len], .bytes = room[0..written] } };
    }

    pub fn report(self: *Messages, context: *const Context, handle: Handle, verdict: Verdict, now: u64) Report {
        if (self.validation.inspect(&self.store, context.peers, handle, now)) |outcome| return switch (outcome) {
            .already_resolved => .already_resolved,
            .expired => .expired,
            .stale_handle => .stale_handle,
            .applied => unreachable,
        };
        const entry = self.validation.attribution(handle);
        assert(context.overlay.matches(entry.topic));
        const message = self.validation.entries[handle.index].state.pending.message;
        const name = context.overlay.topicString(entry.topic.index);
        var result: Applied = .{ .verdict = verdict, .id = entry.id, .source = context.peers.rows[entry.source.index].identity, .admitted_ms = entry.admitted_ms, .topic_bytes = undefined, .topic_len = @intCast(name.len) };
        @memcpy(result.topic_bytes[0..name.len], name);
        if (verdict == .accept) {
            self.history.put(&self.store, message, context.epoch);
            if (context.overlay.subscribed(entry.topic.index)) result.forward = .{ .message = message, .source = entry.source, .topic = entry.topic };
        }
        if (verdict != .ignore) {
            assert(context.peers.matches(entry.source));
            if (verdict == .accept) context.peers.scores.deliverEligible(entry.source.index, entry.topic.index, entry.source_eligible) else context.peers.invalid(entry.source, entry.topic.index);
            for (entry.duplicates[0..entry.duplicate_len]) |d| {
                assert(context.peers.matches(d.peer));
                if (verdict == .reject) context.peers.invalid(d.peer, entry.topic.index) else if (d.eligible) context.peers.scores.creditMesh(d.peer.index, entry.topic.index);
            }
        }
        self.validation.finish(&self.store, handle, verdict, now);
        return .{ .applied = result };
    }

    pub fn topicPins(self: *const Messages) @import("local_intent.zig").TopicSet {
        var pins: @import("local_intent.zig").TopicSet = .initEmpty();
        for (self.validation.recent) |*entry| if (entry.pinned) {
            pins.set(entry.topic.index);
        };
        return pins;
    }

    pub fn expire(self: *Messages, peers: *Peers, now: u64) void {
        self.validation.expire(&self.store, peers, now);
    }

    pub fn takeReleased(self: *Messages) bool {
        const released = self.store.released or self.validation.released;
        self.store.released = false;
        self.validation.released = false;
        return released;
    }
};

fn recordDuplicate(context: *const Context, entry: *Attribution, source: *const Source, topic: u16, now: u64) void {
    const ref = source.peer;
    const eligible = context.overlay.inMesh(topic, source.session.index) and now -| entry.admitted_ms <= context.peers.scores.topic_params[topic].mesh_delivery_window_ms;
    if (!Validation.duplicate(entry, context.peers, ref, eligible) or entry.state != .resolved) return;
    if (entry.verdict == .reject) {
        context.peers.invalid(ref, topic);
    } else if (entry.verdict == .accept and eligible) context.peers.scores.creditMesh(ref.index, topic);
}
