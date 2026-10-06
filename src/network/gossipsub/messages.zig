const std = @import("std");
const mcache = @import("mcache.zig");
const storage = @import("message_store.zig");
const validation = @import("validation.zig");
const Options = @import("options.zig").Options;
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const MessageId = topic_mod.MessageId;
const protobuf = @import("protobuf.zig");
const admission = @import("admission.zig");
const sha256 = @import("sha256.zig");
const assert = std.debug.assert;
const PeerRef = validation.PeerRef;
const Workspace = @import("turn.zig").Workspace;
const Handle = validation.Handle;
const Verdict = validation.Verdict;
const Outcome = validation.Outcome;
const Attribution = validation.Attribution;
const Validation = validation.Validation;
const Peers = @import("peer_book.zig").PeerBook;
const Engine = @import("../quic/Engine.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const overlay_mod = @import("overlay.zig");
const SessionRef = @import("sessions.zig").SessionRef;
const gossip_limits = @import("../gossip_limits.zig");
const layout_mod = @import("layout.zig");
const outbox_mod = @import("outbox.zig");
const delivery = @import("delivery.zig");

/// Topic and payload slices are borrowed for the synchronous admission callback only.
pub const MessageEvent = struct {
    source: ?PeerRef = null,
    handle: Handle,
    id: topic_mod.MessageId,
    peer: Engine.Handle,
    topic: []const u8,
    bytes: []const u8,
    identity: PeerId,
    admitted_ms: u64,
    deadline: u64,
};

pub const Admission = @import("message_admission.zig").Admission;

/// Admission runs synchronously on the network owner. The consumer serializes
/// preflight, replacement and commit, and copies the payload before returning.
pub const MessageSink = struct {
    context: *anyopaque,
    has_capacity: *const fn (*anyopaque, topic_mod.Kind, usize) bool,
    admit: *const fn (*anyopaque, *Admission) bool,
};
pub const InvalidReason = enum { signed, compressed_size, ssz_size, snappy };
/// Identified receipt proves the valid-domain ID, not successful gossip validation.
pub const Refusal = union(enum) { identified: MessageId, unidentified };
pub const Received = union(enum) { ignored, invalid: InvalidReason, duplicate: MessageId, admitted: struct { id: MessageId, topic_index: u16 }, refused: Refusal, deferred };
pub const StorageRefusal = enum { kind_validations, kind_payload, peer_validations, validation_capacity, payload_capacity, processor_capacity };
pub const StorageRefusals = [std.meta.fields(StorageRefusal).len]u64;
pub const Applied = struct {
    verdict: Verdict,
    id: topic_mod.MessageId,
    source: PeerId,
    admitted_ms: u64,
    topic_bytes: [topic_mod.topic_max_len]u8,
    topic_len: u8,
    forward: ?struct { message: storage.Handle, source: PeerRef, topic: u16 } = null,

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
    overlay: *const overlay_mod.Overlay,
    peers: *Peers,
    options: *const Options,
    epoch: u64,
};

pub const Source = struct {
    peer: PeerRef,
    session: SessionRef,
    connection: Engine.Handle,
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
    storage_refusals: StorageRefusals = @splat(0),
    /// Accepted or published messages whose kind's retention allowance stayed full: they are
    /// neither cached nor forwarded.
    retention_refusals: [gossip_limits.kind_count]u64 = @splat(0),
    fast: []FastEntry,

    pub fn init(a: std.mem.Allocator, options: *const Options, layout: *const layout_mod.Layout) !Messages {
        var store = try storage.Store.init(a, layout.payload_entries, layout.payload_bytes);
        errdefer store.deinit(a);
        store.limits = options.payload_limits;
        var history = try mcache.History.init(a, layout.history, layout.retained);
        errdefer history.deinit(a);
        var seen = try mcache.SeenCache.init(a, layout.seen, options.seen_ttl_ms);
        errdefer seen.deinit(a);
        const gossip_ids = try a.alloc(MessageId, layout.history);
        errdefer a.free(gossip_ids);
        const fast = try a.alloc(FastEntry, layout.fingerprints);
        errdefer a.free(fast);
        @memset(fast, .{});
        var pending = try validation.Validation.initForTopics(a, layout.validations, options.validation_timeout_ms, options.validation_tombstone_ms, layout.topics);
        seen.index.seed = options.random_seed.?;
        history.index.seed = options.random_seed.? ^ 1;
        history.topic_index.seed = options.random_seed.? ^ 2;
        pending.index.seed = options.random_seed.? ^ 2;
        return .{ .store = store, .history = history, .seen = seen, .validation = pending, .gossip_ids = gossip_ids, .fast = fast };
    }

    pub fn deinit(self: *Messages, a: std.mem.Allocator, peers: *Peers) void {
        self.validation.deinit(a, &self.store, peers);
        self.history.deinit(a);
        self.seen.deinit(a);
        self.store.deinit(a);
        a.free(self.gossip_ids);
        a.free(self.fast);
        self.* = undefined;
    }

    pub fn metadataBytes(layout: *const layout_mod.Layout) usize {
        return storage.Store.metadataBytes(layout.payload_entries, layout.payload_bytes) +
            Validation.backingBytesForTopics(layout.validations, layout.topics) + layout.fingerprints * @sizeOf(FastEntry) +
            mcache.History.backingBytes(layout.history, layout.retained) + layout.history * @sizeOf(MessageId) +
            mcache.SeenCache.backingBytes(layout.seen);
    }

    pub fn pendingValidations(self: *const Messages) usize {
        var result: usize = 0;
        for (self.validation.entries) |*entry| result += @intFromBool(entry.state == .pending);
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
        const count = self.history.gossip(topic, self.gossip_ids, epoch);
        return self.gossip_ids[0..count];
    }

    pub const ServeOutcome = union(enum) {
        unknown,
        known: enum { queued, limited, pressured },
    };

    pub fn serve(self: *Messages, outbox: *outbox_mod.Outbox, peer: PeerRef, id: MessageId, limits: delivery.Limits, now: u64) ServeOutcome {
        const slot = self.history.get(&self.store, id) orelse return .unknown;
        self.history.bindPeer(peer);
        if (!self.history.iwantAllowed(slot, peer, constants.gossip_retransmission)) return .{ .known = .limited };
        const queued = outbox.queueData(&self.store, self.history.message(slot), .iwant, limits, now) == .queued;
        if (queued) self.history.sent(slot, peer);
        return .{ .known = if (queued) .queued else .pressured };
    }

    pub fn publish(self: *Messages, id: MessageId, name: []const u8, compressed: []const u8, now: u64, epoch: u64) ?storage.Handle {
        const handle = self.history.admitPayload(&self.store, id, name, compressed) orelse return null;
        if (!self.retain(handle)) {
            self.store.seal(handle);
            return null;
        }
        self.history.put(&self.store, handle, epoch);
        self.store.seal(handle);
        std.debug.assert(self.seen.add(id, now));
        return handle;
    }

    pub fn receive(self: *Messages, context: *const Context, workspace: *const Workspace, source: *const Source, msg: protobuf.Message, now: u64) Received {
        const canonical = topic_mod.parseCanonical(msg.topic) orelse return .ignored;
        const match = context.overlay.namespace.lookupCanonical(canonical) orelse return .ignored;
        const rule = match.rule;
        const topic = match.ordinal;
        if (!context.overlay.subscribed(topic)) return .ignored;
        if (msg.signed) return invalid(context, source, topic, .signed);
        const header = admission.inspect(&msg);
        if (header == .rejected) return invalid(context, source, topic, if (msg.data.len > constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE)) .compressed_size else .ssz_size);
        if (header == .invalid) {
            if (!workspace.charge(context.options, msg.data.len, 0)) return .deferred;
            _ = self.seen.add(topic_mod.invalidMessageId(msg.topic, msg.data, context.options.message_id_policy), now);
            return invalid(context, source, topic, .snappy);
        }
        const size = header.payload;
        if (size < rule.ssz_min or size > rule.ssz_max) return invalid(context, source, topic, .ssz_size);
        const kind = canonical.name.kind;
        const refusal: ?StorageRefusal = if (workspace.sink) |sink| (if (!sink.has_capacity(sink.context, kind, size)) .processor_capacity else null) else .processor_capacity;
        const cost = if (refusal != null) msg.data.len else msg.data.len * 2 + size * 2;
        if (!workspace.chargeWork(context.options, cost)) return .deferred;
        const fingerprint = sha256.digest(&.{@intCast(msg.topic.len)}, msg.topic, msg.data);
        const cached = &self.fast[std.mem.readInt(u64, fingerprint[0..8], .little) % self.fast.len];
        var identified: ?MessageId = null;
        if (std.mem.eql(u8, &cached.fingerprint, &fingerprint)) switch (cached.result) {
            .valid => |id| {
                if (self.duplicateId(context, source, topic, id, now)) return .{ .duplicate = id };
                identified = id;
            },
            .invalid => |id| {
                _ = self.seen.add(id, now);
                return invalid(context, source, topic, .snappy);
            },
            .empty => {},
        };
        // Known duplicates retain attribution even when new work has no capacity.
        if (refusal) |reason| return self.refuseStorage(reason, identified);
        const output = workspace.scratch[0..size];
        const decoded = admission.decode(&msg, output, context.options.message_id_policy);
        cached.* = .{ .fingerprint = fingerprint, .result = if (decoded == .invalid) .{ .invalid = decoded.invalid } else .{ .valid = decoded.valid.id } };
        if (decoded == .invalid) {
            _ = self.seen.add(decoded.invalid, now);
            return invalid(context, source, topic, .snappy);
        }
        const id = decoded.valid.id;
        if (self.duplicateId(context, source, topic, id, now)) return .{ .duplicate = id };
        assert(context.peers.matches(source.peer));
        const maximum = constants.maxCompressedLen(rule.ssz_max);
        var candidate: Admission = .{
            .messages = self,
            .workspace = workspace,
            .context = context,
            .source = source,
            .topic_index = topic,
            .canonical = canonical,
            .maximum_compressed = maximum,
            .compressed = msg.data,
            .event = .{ .source = source.peer, .identity = context.peers.rows[source.peer.index].identity, .admitted_ms = now, .deadline = now +| self.validation.timeout_ms, .handle = undefined, .id = id, .peer = source.connection, .topic = msg.topic, .bytes = workspace.scratch[0..size] },
        };
        const sink = workspace.sink.?;
        if (!sink.admit(sink.context, &candidate)) {
            assert(!candidate.committed);
            return self.refuseStorage(candidate.refusal, id);
        }
        assert(candidate.committed);
        return .{ .admitted = .{ .id = id, .topic_index = topic } };
    }

    fn duplicateId(self: *Messages, context: *const Context, source: *const Source, topic: u16, id: topic_mod.MessageId, now: u64) bool {
        const pending = self.validation.find(id, now);
        if (pending != null or self.seen.contains(id, now)) {
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

    fn retain(self: *Messages, message: storage.Handle) bool {
        if (self.history.makeRoom(&self.store, message)) return true;
        self.retention_refusals[@intFromEnum(self.store.get(message).?.kind)] +|= 1;
        return false;
    }

    fn refuseStorage(self: *Messages, reason: StorageRefusal, id: ?MessageId) Received {
        self.storage_refusals[@intFromEnum(reason)] +|= 1;
        return .{ .refused = if (id) |known| .{ .identified = known } else .unidentified };
    }

    pub fn report(self: *Messages, context: *const Context, handle: Handle, verdict: Verdict, now: u64) Report {
        if (self.validation.inspect(&self.store, context.peers, handle, now)) |outcome| return switch (outcome) {
            .already_resolved => .already_resolved,
            .expired => .expired,
            .stale_handle => .stale_handle,
            .applied => unreachable,
        };
        const entry = self.validation.attribution(handle);
        assert(context.overlay.rows[entry.topic].active);
        const message = self.validation.entries[handle.index].state.pending.message;
        const name = context.overlay.topicString(entry.topic);
        var result: Applied = .{ .verdict = verdict, .id = entry.id, .source = context.peers.rows[entry.source.index].identity, .admitted_ms = entry.admitted_ms, .topic_bytes = undefined, .topic_len = @intCast(name.len) };
        @memcpy(result.topic_bytes[0..name.len], name);
        if (verdict == .accept and self.retain(message)) {
            self.history.put(&self.store, message, context.epoch);
            if (context.overlay.subscribed(entry.topic)) result.forward = .{ .message = message, .source = entry.source, .topic = entry.topic };
        }
        if (verdict != .ignore) {
            assert(context.peers.matches(entry.source));
            if (verdict == .accept) context.peers.scores.deliverEligible(entry.source.index, entry.topic, entry.source_eligible) else context.peers.invalid(entry.source, entry.topic);
            for (entry.duplicates[0..entry.duplicate_len]) |d| {
                assert(context.peers.matches(d.peer));
                if (verdict == .reject) context.peers.invalid(d.peer, entry.topic) else if (d.eligible) context.peers.scores.creditMesh(d.peer.index, entry.topic);
            }
        }
        self.validation.finish(&self.store, handle, verdict, now);
        return .{ .applied = result };
    }

    pub fn expire(self: *Messages, peers: *Peers, now: u64) void {
        self.validation.expire(&self.store, peers, now);
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

test {
    _ = @import("messages_test.zig");
}
