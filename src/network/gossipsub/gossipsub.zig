const std = @import("std");
const snappy = @import("snappy");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const topic_policy = @import("topic_policy.zig");
const local_intent = @import("local_intent.zig");
const topic_mod = @import("topic.zig");
const mcache_mod = @import("mcache.zig");
const storage = @import("message_store.zig");
const validation_mod = @import("validation.zig");
const Recovery = @import("recovery.zig").Recovery;
const peer_io_mod = @import("peer_io.zig");
const score_mod = @import("score.zig");
const overlay_mod = @import("overlay.zig");
const peers_mod = @import("peer_book.zig");
const sessions_mod = @import("sessions.zig");
const engine_mod = @import("../quic/engine.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const Now = types.Now;
const Sessions = sessions_mod.Sessions;
const Version = sessions_mod.Version;

pub const Options = @import("options.zig").Options;

pub const InitError = Allocator.Error || error{InvalidLimits} || topic_policy.Error;

/// Advertised protocol ids, newest first; the negotiator settles the version.
pub const meshsub_ids = @import("../router.zig").meshsub_ids;

pub const MessageId = topic_mod.MessageId;

pub const Verdict = validation_mod.Verdict;
pub const ValidationHandle = validation_mod.Handle;
pub const ReportOutcome = validation_mod.Outcome;

pub const Event = union(enum) {
    /// A new message the host must validate and then close out with
    /// `report(handle, verdict, now)`. `bytes` is the decompressed payload, valid
    /// until the next pump; the host copies what it needs.
    message: validation_mod.MessageEvent,
    subscription_change: struct { peer: Handle, topic: []const u8, subscribed: bool },
};

const sub_frame_max = 16 + topic_mod.topic_max_len;
const control_frame_max = 32 + topic_mod.topic_max_len;
const PeerIo = peer_io_mod.PeerIo;
const Budget = struct {
    input: usize = 0,
    output: usize = 0,
    items: usize = 0,
    calls: usize = 0,
    work: usize = 0,
    large_used: bool = false,
    fields: usize = 0,
};
pub const MemoryPlan = struct {
    retained_bytes: usize,
    page_count: usize,
    message_entries: usize,
    validation_capacity: usize,
    duplicate_attributions_per_validation: usize,
    data_descriptors_per_peer: usize,
    data_descriptors_total: usize,
    legal_atomic_work_bytes: usize,
    page_bytes: usize,
    rounding_per_message_max: usize,
    frame_bytes: usize,
    event_bytes: usize,
    compression_bytes: usize,
    peer_buffer_bytes: usize,
    metadata_bytes: usize,
    total_bytes: usize,
};

/// Live occupancy for bounded host supervision and deterministic test baselines.
/// This scans fixed startup capacities: peers, topics, validation entries and store entries.
/// High waters are the largest physical-row peak since init, including previous connections.
/// Age uses last_now_ms and original queue admission until complete send or reset.
pub const ResourceSnapshot = struct {
    connected_capacity: usize = 0,
    retained_capacity: usize = 0,
    validation_capacity: usize = 0,
    control_frames: usize = 0,
    control_bytes: usize = 0,
    critical_frames: usize = 0,
    critical_bytes: usize = 0,
    data_bytes_per_row_high_water: usize = 0,
    data_descriptors_per_row_high_water: usize = 0,
    control_bytes_per_row_high_water: usize = 0,
    control_frames_per_row_high_water: usize = 0,
    critical_bytes_per_row_high_water: usize = 0,
    critical_frames_per_row_high_water: usize = 0,
    oldest_tx_age_ms: ?u64 = null,
    inbound_streams: usize = 0,
    outbound_streams: usize = 0,
    subscription_pending_peers: usize = 0,

    admitted_peers: usize,
    remote_subscriptions: usize,
    mesh_members: usize,
    queued_descriptors: usize,
    queued_bytes: usize,
    held_frames: usize,
    held_tx_retains: usize,
    store_entries: usize,
    store_pages: usize,
    pending_validations: usize,
    promises: usize,
};

pub const Gossipsub = struct {
    allocator: Allocator,
    options: Options,
    sessions: *Sessions,
    peers: peers_mod.PeerBook,
    messages: @import("messages.zig").Messages,
    cycle: @import("heartbeat_cycle.zig").Cycle = .{},
    budget: Budget = .{},
    overlay: *overlay_mod.Overlay,
    heartbeat_at: u64 = 0,
    opportunistic_at: u64 = 0,
    last_now_ms: u64 = 0,
    msg_scratch: []u8,
    decompressed: []u8,
    decompressed_used: usize = 0,
    recovery: Recovery,
    counters: Counters = .{},
    topic_metrics: @import("metrics.zig").Topics = .{},
    rpc_metrics: @import("metrics.zig").Rpc = .{},
    validation_time: @import("metrics.zig").ValidationTime = .{},

    pub const Counters = struct {
        retained_penalty_evictions: u64 = 0,
        messages_received: u64 = 0,
        messages_published: u64 = 0,
        messages_forwarded: u64 = 0,
        duplicates: u64 = 0,
        rpcs_received: u64 = 0,
        send_dropped: u64 = 0,
        malformed_rpcs: u64 = 0,
        arena_full: u64 = 0,
        decompress_throttled: u64 = 0,
        oversized_dropped: u64 = 0,
        large_stalled: u64 = 0,
        iwant_sent: u64 = 0,
        broken_promises: u64 = 0,
        promises_cancelled_pressure: u64 = 0,
        local_pressure_resets: u64 = 0,
        tx_stalled: u64 = 0,
        subscription_timeouts: u64 = 0,
        receive_pressure_timeouts: u64 = 0,
        receive_frame_timeouts: u64 = 0,
        send_queue_timeouts: u64 = 0,
        send_progress_timeouts: u64 = 0,
        negotiation_started: u64 = 0,
        negotiation_ready: u64 = 0,
        negotiation_rejected: u64 = 0,
        negotiation_failed: u64 = 0,
        negotiation_deferred: u64 = 0,
    };

    pub fn init(allocator: Allocator, options: Options) InitError!Gossipsub {
        try @import("options.zig").validate(&options);
        const namespace: ?topic_policy.Namespace = if (options.topic_policy) |boundaries| try topic_policy.Namespace.init(allocator, boundaries, options.connected_capacity) else null;
        errdefer if (namespace) |owned| {
            var ns = owned;
            ns.deinit(allocator);
        };

        const sessions = try allocator.create(Sessions);
        errdefer allocator.destroy(sessions);
        sessions.* = try Sessions.initOptions(allocator, &options);
        errdefer sessions.deinit(allocator);

        const overlay = try allocator.create(overlay_mod.Overlay);
        errdefer allocator.destroy(overlay);
        overlay.* = overlay_mod.Overlay.init(options.random_seed.?);

        var peers = try peers_mod.PeerBook.initOptions(allocator, &options);
        errdefer peers.deinit(allocator);

        var messages = try @import("messages.zig").Messages.init(allocator, &options);
        errdefer messages.deinit(allocator, &peers);
        const msg_scratch = try allocator.alloc(u8, constants.GOSSIP_MAX_SIZE);
        errdefer allocator.free(msg_scratch);
        const decompressed = try allocator.alloc(u8, options.decompressed_arena_bytes);
        errdefer allocator.free(decompressed);
        var recovery = try Recovery.init(allocator);
        errdefer recovery.deinit(allocator, &peers);

        var result: Gossipsub = .{
            .allocator = allocator,
            .options = options,
            .sessions = sessions,
            .peers = peers,
            .messages = messages,
            .msg_scratch = msg_scratch,
            .decompressed = decompressed,
            .recovery = recovery,
            .overlay = overlay,
        };
        result.overlay.namespace = namespace;
        result.options.ip_allowlist = &.{};
        result.options.topic_policy = null;
        return result;
    }

    pub fn deinit(self: *Gossipsub) void {
        for (self.sessions.rows) |*peer| if (peer.active) self.connectionClosed(peer.conn);
        self.recovery.deinit(self.allocator, &self.peers);
        self.allocator.free(self.decompressed);
        self.allocator.free(self.msg_scratch);
        self.messages.deinit(self.allocator, &self.peers);
        self.peers.deinit(self.allocator);
        self.overlay.deinit(self.allocator);
        self.allocator.destroy(self.overlay);
        self.sessions.deinit(self.allocator);
        self.allocator.destroy(self.sessions);
        self.* = undefined;
    }

    // Subscriptions ----------------------------------------------------------

    pub fn subscribe(self: *Gossipsub, name: []const u8) bool {
        const topic = self.internTopic(name) orelse return false;
        const context = self.overlayContext(self.last_now_ms);
        self.overlay.setLocal(&context, topic, true);
        return true;
    }

    pub fn unsubscribe(self: *Gossipsub, name: []const u8) bool {
        const topic = self.overlay.findTopic(name) orelse return false;
        const context = self.overlayContext(self.last_now_ms);
        self.overlay.setLocal(&context, topic, false);
        return true;
    }

    fn internTopic(self: *Gossipsub, name: []const u8) ?u16 {
        const context = self.overlayContext(self.last_now_ms);
        const pins = self.messages.topicPins();
        return self.overlay.internTopic(&context, &pins, name);
    }

    fn validTopic(self: *const Gossipsub, name: []const u8) bool {
        return self.overlay.validTopic(name);
    }

    fn reclaimTopic(self: *Gossipsub, topic: u16) void {
        const context = self.overlayContext(self.last_now_ms);
        const pins = self.messages.topicPins();
        self.overlay.reclaimTopic(&context, &pins, topic);
    }

    pub fn prepareSubscriptions(self: *Gossipsub, subscriptions: []const local_intent.Subscription, workspace: *local_intent.Workspace, now: Now) local_intent.Error!bool {
        const context = self.overlayContext(self.last_now_ms);
        const pins = self.messages.topicPins();
        return self.overlay.prepareSubscriptions(&context, &pins, subscriptions, workspace, now.mono_ms);
    }

    pub fn commitSubscriptions(self: *Gossipsub, workspace: *local_intent.Workspace) void {
        self.last_now_ms = workspace.now_ms;
        const context = self.overlayContext(self.last_now_ms);
        self.overlay.commitSubscriptions(&context, workspace);
    }

    pub const ConfigureTopicError = error{ InvalidLimits, InvalidTopic, TopicCapacity };

    pub fn configureTopic(self: *Gossipsub, name: []const u8, params: *const score_mod.TopicParams) ConfigureTopicError!void {
        const copied = params.*;
        try score_mod.validateTopic(copied);
        if (!self.validTopic(name)) return error.InvalidTopic;
        const topic = self.internTopic(name) orelse return error.TopicCapacity;
        self.peers.scores.applyValidatedTopic(topic, copied);
    }

    // Peer lifecycle ---------------------------------------------------------

    pub const PeerAdmission = union(enum) { admitted: sessions_mod.SessionRef, duplicate, capacity };

    /// Metadata must come from an authenticated transport connection. Refusal leaves transport usable.
    pub fn addPeer(self: *Gossipsub, conn: Handle, version: Version, metadata: *const peers_mod.Metadata, now: Now) PeerAdmission {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        if (self.sessions.findPeer(conn)) |index| return .{ .admitted = .{ .index = index, .generation = self.sessions.peerGeneration(index) } };
        if (self.peers.find(&metadata.identity)) |ref| {
            if (self.peers.rows[ref.index].connection != null) return .duplicate;
        }
        const handle = self.sessions.addPeer(conn, version) orelse return .capacity;
        if (self.overlay.namespace) |*ns| ns.clearPeer(handle.index);
        const admitted = self.peers.admit(conn, metadata, now.mono_ms);
        if (admitted != .admitted) {
            self.sessions.removePeer(handle.index);
            return if (admitted == .duplicate) .duplicate else .capacity;
        }
        if (admitted.admitted.penalty_evicted) self.counters.retained_penalty_evictions += 1;
        const ref = admitted.admitted.peer;
        self.sessions.rows[handle.index].logical = ref;
        self.sessions.rows[handle.index].io.resetTx(&self.messages.store);
        self.sessions.rows[handle.index].io.resetRx();
        self.sessions.rows[handle.index].io.resetHeartbeat();
        self.sendSubscriptions(handle.index);
        return .{ .admitted = handle };
    }

    fn logical(self: *const Gossipsub, index: u16) peers_mod.Ref {
        assert(self.sessions.rows[index].active);
        return self.sessions.rows[index].logical;
    }

    pub fn connectionClosed(self: *Gossipsub, conn: Handle) void {
        const index = self.sessions.findPeer(conn) orelse return;
        _ = self.sessions.resetRx(index);
        self.sessions.rows[index].io.resetTx(&self.messages.store);
        self.cancelPromises(index, false);
        self.wakeStorage();
        const context = self.overlayContext(self.last_now_ms);
        self.overlay.peerDisconnected(&context, index);
        self.sessions.rows[index].io.write_first = false;
        self.sessions.rows[index].io.subscription_since = null;
        const ref = self.logical(index);
        self.peers.disconnect(ref, self.last_now_ms);
        self.sessions.removePeer(index);
    }

    pub fn sendSubscriptions(self: *Gossipsub, index: u16) void {
        const io = &self.sessions.rows[index].io;
        io.subscription_dirty = .initEmpty();
        for (&self.overlay.rows, 0..) |*topic, t| {
            if (topic.active and topic.subscribed) io.subscription_dirty.set(t);
        }
        io.tx_ready = true;
        io.subscription_since = if (io.subscription_dirty.count() > 0) io.subscription_since orelse self.last_now_ms else null;
    }

    pub fn queueSubscriptions(self: *Gossipsub, io: *PeerIo) void {
        var buf: [sub_frame_max]u8 = undefined;
        for (0..constants.topics_cap) |_| {
            const topic = io.subscription_cursor;
            if (io.subscription_dirty.isSet(topic)) {
                const t = &self.overlay.rows[topic];
                var w = protobuf.Writer.init(&buf);
                w.varint(protobuf.subscriptionSize(t.string[0..t.string_len]));
                protobuf.writeSubscription(&w, t.subscribed, t.string[0..t.string_len]);
                if (io.appendControl(w.written(), true, .subscription, self.last_now_ms) == null) return;
                io.subscription_dirty.unset(topic);
            }
            io.subscription_cursor = (topic + 1) % constants.topics_cap;
        }
        io.subscription_since = null;
    }

    pub const PublishOptions = struct { allow_zero_peers: bool = true, ignore_duplicate: bool = false, flood: bool = false };
    pub const PublishError = error{ PayloadTooSmall, PayloadTooLarge, UnknownTopic, CompressFailed, ResourceExhausted, Duplicate, NoPeersSubscribedToTopic };
    pub const PublishOutcome = struct { queued: u16 = 0, pressured: u16 = 0, selected: u16 = 0, unavailable: u16 = 0, duplicate: bool = false };

    pub fn publish(self: *Gossipsub, topic_str: []const u8, ssz: []const u8, now: Now) PublishError!PublishOutcome {
        return self.publishWithOptions(topic_str, ssz, .{}, now);
    }

    /// Admits one shared history payload; queued counts live stream queue admissions.
    pub fn publishWithOptions(self: *Gossipsub, topic_str: []const u8, ssz: []const u8, options: PublishOptions, now: Now) PublishError!PublishOutcome {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        const now_ms = self.last_now_ms;
        if (ssz.len > constants.MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;
        if (self.overlay.namespace) |*ns| {
            const rule = (ns.lookup(topic_str) orelse return error.UnknownTopic).rule;
            if (ssz.len < rule.ssz_min) return error.PayloadTooSmall;
            if (ssz.len > rule.ssz_max) return error.PayloadTooLarge;
        } else if (topic_mod.parse(topic_str) == null) return error.UnknownTopic;
        const id = topic_mod.validMessageId(topic_str, ssz, self.options.message_id_policy);
        if (self.messages.wasSeen(id, now_ms)) {
            if (options.ignore_duplicate) return .{ .duplicate = true };
            return error.Duplicate;
        }
        const topic = self.internTopic(topic_str) orelse return error.ResourceExhausted;
        const context = self.overlayContext(now_ms);
        const recipients = self.overlay.publicationRecipients(&context, topic, options.flood);
        if (recipients.count() == 0 and !options.allow_zero_peers) return error.NoPeersSubscribedToTopic;
        const clen = snappy.raw.compress(ssz, self.msg_scratch) catch return error.CompressFailed;
        const h = self.messages.publish(id, topic_str, self.msg_scratch[0..clen], now_ms) orelse return error.ResourceExhausted;
        self.resolvePromises(id, null);
        const result = self.deliver(&recipients, h, null, now_ms);
        self.counters.messages_published += 1;
        const counts = self.topic_metrics.get(topic_str);
        counts.published +|= 1;
        counts.published_peers +|= result.queued;
        counts.published_bytes +|= @as(u64, @intCast(clen)) * result.queued;
        return result;
    }

    fn messageContext(self: *Gossipsub) @import("messages.zig").Context {
        return .{ .overlay = self.overlay, .peers = &self.peers, .options = &self.options };
    }

    /// Event slices remain valid until the next pump, including after report or publish.
    pub fn report(self: *Gossipsub, handle: ValidationHandle, verdict: Verdict, now: Now) ReportOutcome {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        const context = self.messageContext();
        const result = self.messages.report(&context, handle, verdict, now.mono_ms);
        if (result == .applied) {
            const applied = &result.applied;
            const counts = self.topic_metrics.get(applied.topicString());
            switch (applied.verdict) {
                .accept => counts.accepted +|= 1,
                .reject => counts.rejected +|= 1,
                .ignore => counts.ignored +|= 1,
            }
            self.validation_time.observe(now.mono_ms -| applied.admitted_ms);
            if (verdict != .accept) std.log.scoped(.network_gossip).debug("validation_verdict validation={d}:{d} message_id={x} verdict={s} topic={s} peer={f} elapsed_ms={d}", .{ handle.index, handle.generation, applied.id, @tagName(verdict), applied.topicString(), @import("../logging.zig").peer(&applied.source), now.mono_ms -| applied.admitted_ms });
            if (applied.forward) |forward| {
                const delivered = self.deliver(self.overlay.mesh(forward.topic.index), forward.message, forward.source, now.mono_ms);
                if (delivered.queued > 0) {
                    self.counters.messages_forwarded += 1;
                    counts.forwarded +|= 1;
                    counts.forwarded_peers +|= delivered.queued;
                }
            }
        } else {
            std.log.scoped(.network_gossip).debug("validation_report_refused validation={d}:{d} verdict={s} reason={s}", .{ handle.index, handle.generation, @tagName(verdict), @tagName(result) });
        }
        self.wakeStorage();
        return result.outcome();
    }

    fn deliver(self: *Gossipsub, peers: *const sessions_mod.PeerSet, h: storage.Handle, source: ?validation_mod.PeerRef, now_ms: u64) PublishOutcome {
        const id = self.messages.store.get(h).?.id;
        var result: PublishOutcome = .{};
        var recipients = peers.*;
        const topic = self.overlay.findTopic(self.messages.store.get(h).?.topicString()).?;
        if (source != null) for (self.sessions.rows, 0..) |*row, peer| {
            if (row.active and self.peers.rows[row.logical.index].direct and self.overlay.subscribers(topic).isSet(peer)) recipients.set(peer);
        };
        var it = recipients.iterator(.{});
        while (it.next()) |peer| {
            const index: u16 = @intCast(peer);
            if (!self.sessions.rows[index].active or self.overlay.retire.isSet(index)) continue;
            if (source) |p| {
                if (std.meta.eql(p, self.logical(index)) or self.sessions.suppresses(index, id, now_ms)) continue;
            }
            if (!self.peers.rows[self.logical(index).index].direct and self.peerScore(index, now_ms) < self.options.score_params.publish_threshold) continue;
            result.selected += 1;
            if (self.sessions.rows[index].outStream() == null) {
                result.unavailable += 1;
                continue;
            }
            if (self.sessions.rows[index].io.queueData(&self.messages.store, h, self.options.tx_peer_bytes, now_ms) == .queued) {
                result.queued += 1;
            } else {
                result.pressured += 1;
                self.counters.send_dropped += 1;
            }
        }
        assert(result.selected == result.queued + result.pressured + result.unavailable);
        return result;
    }

    pub fn overlayContext(self: *Gossipsub, now_ms: u64) overlay_mod.Context {
        return .{ .sessions = self.sessions, .peers = &self.peers, .now = now_ms, .options = &self.options };
    }

    // Pump -------------------------------------------------------------------

    /// Begins a serialized owner turn and ends the preceding event borrows.
    pub fn beginPump(self: *Gossipsub, now: Now) void {
        self.decompressed_used = 0;
        self.last_now_ms = now.mono_ms;
        self.budget = .{
            .input = self.options.input_per_pump,
            .output = self.options.output_per_pump,
            .items = self.options.items_per_pump,
            .calls = self.options.calls_per_pump,
            .work = self.options.work_per_pump,
            .fields = self.options.fields_per_pump,
        };
        const free_before = self.messages.store.free_pages;
        self.messages.expire(&self.peers, now.mono_ms);
        if (self.messages.store.free_pages != free_before) self.wakeStorage();
    }

    pub fn tick(self: *Gossipsub, now: Now) void {
        if (self.heartbeat_at == 0) {
            self.heartbeat_at = now.mono_ms +| self.options.heartbeat_interval_ms;
        } else if (now.mono_ms >= self.heartbeat_at) {
            self.heartbeat(now);
            self.heartbeat_at = now.mono_ms +| self.options.heartbeat_interval_ms;
            self.wakeStorage();
        }
    }

    pub fn finishPump(self: *Gossipsub, now: Now) void {
        self.maintainTopics(now);
        self.expirePromises(now.mono_ms);
    }

    pub fn nextWakeup(self: *const Gossipsub, now: Now) u64 {
        if (self.cycle.remaining > 0) return now.mono_ms;
        var deadline = if (self.heartbeat_at == 0) now.mono_ms else self.heartbeat_at;
        if (self.messages.nextDeadline()) |d| deadline = @min(deadline, d);
        for (self.overlay.pending_since) |since| if (since) |started| {
            deadline = @min(deadline, started +| self.options.pressure_timeout_ms);
        };
        if (self.recovery.nextExpiry()) |expiry| deadline = @min(deadline, expiry);
        return @max(now.mono_ms, deadline);
    }

    pub fn receiveItem(self: *Gossipsub, session: sessions_mod.SessionRef, item: protobuf.Item, now: Now, events: []Event, count: *usize) bool {
        if (!self.sessions.matches(session)) return true;
        const index = session.index;
        const io = &self.sessions.rows[index].io;
        switch (item) {
            .subscription => |sub| {
                if (io.subscriptions < constants.max_subscriptions_per_rpc) {
                    if (self.validTopic(sub.topic) and self.overlay.findTopic(sub.topic) != null and (count.* == events.len or self.decompressed.len - self.decompressed_used < sub.topic.len)) {
                        self.pressure(index, .events, now.mono_ms);
                        return false;
                    }
                    count.* = self.onSubscription(index, sub, events, count.*);
                    io.subscriptions += 1;
                }
            },
            .message => |msg| {
                if (io.messages < constants.max_publish_per_rpc) {
                    const result = self.onMessage(index, msg, now, events, count.*);
                    if (result == null) return false;
                    count.* = result.?;
                    io.messages += 1;
                }
            },
            else => {
                if (io.controls < constants.max_control_per_rpc) {
                    io.controls += 1;
                    switch (item) {
                        .ihave => |ihave| self.onIhave(index, ihave, now),
                        .iwant => |iwant| self.onIwant(index, iwant),
                        .graft => |name| self.onGraft(index, name, now),
                        .prune => |prune| self.onPrune(index, prune, now),
                        .idontwant => |ids| self.onIdontwant(index, ids),
                        else => unreachable,
                    }
                }
            },
        }
        return true;
    }

    pub fn ignoreRpc(self: *Gossipsub, index: u16, now: Now) bool {
        if (self.peers.rows[self.logical(index).index].direct or self.peerScore(index, now.mono_ms) >= self.options.score_params.graylist_threshold) return false;
        self.rpc_metrics.graylist_dropped +|= 1;
        return true;
    }

    pub fn memoryPlan(self: *const Gossipsub) MemoryPlan {
        const metadata = @sizeOf(Gossipsub) + @sizeOf(Sessions) + @sizeOf(overlay_mod.Overlay) + self.sessions.rows.len * @sizeOf(@TypeOf(self.sessions.rows[0])) + self.peers.rows.len * @sizeOf(peers_mod.Row) + self.peers.backoffs.len * @sizeOf(peers_mod.Backoff) +
            self.messages.metadataBytes() + self.recovery.memoryBytes() + self.sessions.receive_pool.metadataBytes() + (if (self.overlay.namespace) |*ns| ns.allocatedBytes() else @as(usize, 0)) +
            self.peers.scores.topics.len * @sizeOf(@TypeOf(self.peers.scores.topics[0])) + self.peers.scores.app_score.len * @sizeOf(f64) + self.peers.scores.behaviour.len * @sizeOf(f64);
        return .{
            .retained_bytes = self.messages.store.bytes.len,
            .page_count = self.messages.store.next.len,
            .message_entries = self.messages.store.entries.len,
            .validation_capacity = self.messages.validationCapacity(),
            .duplicate_attributions_per_validation = validation_mod.duplicates_max,
            .data_descriptors_per_peer = peer_io_mod.data_capacity,
            .data_descriptors_total = self.sessions.rows.len * peer_io_mod.data_capacity,
            .legal_atomic_work_bytes = 2 * constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 2 * constants.MAX_PAYLOAD_SIZE,
            .page_bytes = storage.page_bytes,
            .rounding_per_message_max = storage.page_bytes - 1,
            .frame_bytes = self.sessions.receive_pool.bytes.len,
            .event_bytes = self.decompressed.len,
            .compression_bytes = self.msg_scratch.len,
            .peer_buffer_bytes = self.sessions.io_arena.len,
            .metadata_bytes = metadata,
            .total_bytes = self.messages.store.bytes.len + self.sessions.receive_pool.bytes.len + self.decompressed.len + self.msg_scratch.len + self.sessions.io_arena.len + metadata,
        };
    }

    pub fn resourceSnapshot(self: *const Gossipsub) ResourceSnapshot {
        var result: ResourceSnapshot = .{
            .connected_capacity = self.sessions.rows.len,
            .retained_capacity = self.peers.rows.len,
            .validation_capacity = self.messages.validationCapacity(),
            .admitted_peers = 0,
            .remote_subscriptions = 0,
            .mesh_members = 0,
            .queued_descriptors = 0,
            .queued_bytes = 0,
            .held_frames = 0,
            .held_tx_retains = 0,
            .store_entries = self.messages.store.used_entries,
            .store_pages = self.messages.store.next.len - self.messages.store.free_pages,
            .pending_validations = 0,
            .promises = self.recovery.len,
        };
        for (self.sessions.rows) |*peer| {
            const io = &peer.io;
            if (peer.active) result.admitted_peers += 1;
            result.inbound_streams += @intFromBool(peer.in_stream != null);
            result.outbound_streams += @intFromBool(peer.outStream() != null);
            result.subscription_pending_peers += @intFromBool(io.subscription_since != null);
            result.queued_descriptors += io.data_count;
            result.queued_bytes += io.data_bytes;
            result.control_frames += io.control.count;
            result.control_bytes += io.control.used;
            result.critical_frames += io.critical.count;
            result.critical_bytes += io.critical.used;
            result.data_bytes_per_row_high_water = @max(result.data_bytes_per_row_high_water, io.data_bytes_high_water);
            result.data_descriptors_per_row_high_water = @max(result.data_descriptors_per_row_high_water, io.data_descriptors_high_water);
            result.control_bytes_per_row_high_water = @max(result.control_bytes_per_row_high_water, io.control.bytes_high_water);
            result.control_frames_per_row_high_water = @max(result.control_frames_per_row_high_water, io.control.frames_high_water);
            result.critical_bytes_per_row_high_water = @max(result.critical_bytes_per_row_high_water, io.critical.bytes_high_water);
            result.critical_frames_per_row_high_water = @max(result.critical_frames_per_row_high_water, io.critical.frames_high_water);
            if (io.oldestTx()) |since| result.oldest_tx_age_ms = @max(result.oldest_tx_age_ms orelse 0, self.last_now_ms -| since);
            if (io.reader.declaredLen() != null or io.rpc != null) result.held_frames += 1;
        }
        for (self.overlay.rows) |topic| {
            if (!topic.active) continue;
            for (0..self.sessions.rows.len) |peer| {
                if (topic.subscribers.isSet(peer)) result.remote_subscriptions += 1;
                if (topic.mesh.isSet(peer)) result.mesh_members += 1;
            }
        }
        for (self.messages.store.entries) |entry| result.held_tx_retains += entry.tx;
        result.pending_validations = self.messages.stats().pending;
        return result;
    }

    pub fn wakeStorage(self: *Gossipsub) void {
        for (self.sessions.rows) |*peer| if (peer.io.blocked == .storage) {
            const io = &peer.io;
            io.rx_ready = true;
        };
    }

    fn heartbeat(self: *Gossipsub, now: Now) void {
        for (self.sessions.rows) |*peer| peer.io.resetHeartbeat();
        self.peers.refresh(now.mono_ms);
        if (self.cycle.remaining > 0) return;
        const opportunistic = self.opportunistic_at != 0 and now.mono_ms >= self.opportunistic_at;
        if (self.opportunistic_at == 0 or opportunistic) self.opportunistic_at = now.mono_ms +| self.options.opportunistic_graft_interval_ms;
        self.cycle.begin(self.sessions, &self.peers.scores, now.mono_ms, opportunistic);
        self.messages.beginCycle();
    }

    fn maintainTopics(self: *Gossipsub, now: Now) void {
        var serviced: usize = 0;
        for (0..constants.topics_cap) |_| {
            const index = self.cycle.next() orelse break;
            const topic = &self.overlay.rows[index];
            if (!topic.active) continue;
            var context = self.overlayContext(now.mono_ms);
            context.snapshot = &self.cycle.scores;
            if (topic.fanout.count() > 0) _ = self.overlay.maintainFanout(&context, index, false);
            self.overlay.maintain(&context, index);
            if (self.cycle.opportunistic) self.overlay.opportunistic(&context, index);
            self.emitGossip(index, &context);
            self.reclaimTopic(index);
            serviced += 1;
            if (serviced == self.options.topics_per_pump) break;
        }
        if (self.cycle.remaining == 0) self.messages.finishCycle();
    }

    fn emitGossip(self: *Gossipsub, topic: u16, context: *const overlay_mod.Context) void {
        const topic_str = self.overlay.topicString(topic);
        const ids = self.messages.gossipIds(topic_str);
        const count = ids.len;
        if (count == 0) return;
        const n = @min(count, constants.gossip_ids_max);
        const recipients = self.overlay.gossipRecipients(context, topic, self.options.gossip_factor);
        var it = recipients.iterator(.{});
        while (it.next()) |peer| {
            for (0..n) |i| {
                const j = self.overlay.rng.random().uintLessThan(usize, count - i) + i;
                std.mem.swap(MessageId, &ids[i], &ids[j]);
            }
            var writer = protobuf.Writer.init(self.msg_scratch);
            writer.varint(protobuf.ihaveRpcSize(topic_str, n, constants.message_id_length));
            protobuf.beginIhaveRpc(&writer, topic_str, n, constants.message_id_length);
            for (ids[0..n]) |id| protobuf.writeIhaveId(&writer, &id);
            if (self.sessions.rows[peer].io.appendControl(writer.written(), false, .ihave, self.last_now_ms) == null) self.counters.send_dropped += 1;
        }
    }

    fn addPromise(self: *Gossipsub, id: MessageId, index: u16, token: u64) void {
        self.recovery.add(&self.peers, id, self.logical(index), self.sessions.rows[index].conn, token);
    }

    fn resolvePromises(self: *Gossipsub, id: MessageId, receipt: ?Recovery.Receipt) void {
        self.recovery.resolve(&self.peers, id, receipt);
    }

    pub fn cancelPromises(self: *Gossipsub, peer: u16, local_pressure: bool) void {
        const removed = self.recovery.cancel(&self.peers, self.sessions.rows[peer].conn, local_pressure);
        if (local_pressure) self.counters.promises_cancelled_pressure += removed;
    }

    pub fn writeCompleted(self: *Gossipsub, session: sessions_mod.SessionRef, completion: peer_io_mod.Completion, now_ms: u64) void {
        if (!self.sessions.matches(session)) return;
        const peer = session.index;
        self.rpc_metrics.observeSent(completion.itemKind());
        switch (completion) {
            .control => |receipt| self.controlSent(peer, receipt.token, now_ms),
            .data => {},
        }
    }

    fn controlSent(self: *Gossipsub, peer: u16, token: u64, now_ms: u64) void {
        self.recovery.controlSent(self.sessions.rows[peer].conn, token, self.options.iwant_followup_ms, now_ms);
    }

    fn expirePromises(self: *Gossipsub, now_ms: u64) void {
        self.counters.broken_promises += self.recovery.expire(&self.peers, now_ms);
    }

    fn peerScore(self: *Gossipsub, index: u16, now_ms: u64) f64 {
        const ref = self.logical(index);
        return self.peers.score(ref, now_ms);
    }

    fn belowGossip(self: *Gossipsub, index: u16, now_ms: u64) bool {
        return self.peerScore(index, now_ms) < self.options.score_params.gossip_threshold;
    }

    /// The host's application-specific P5 term for a peer, from its own signals.
    pub fn setPeerScore(self: *Gossipsub, conn: Handle, value: f64) bool {
        const index = self.sessions.findPeer(conn) orelse return false;
        return self.peers.scores.setAppScore(self.logical(index).index, value);
    }

    pub fn scoreSnapshot(self: *Gossipsub, conn: Handle, now: Now) ?f64 {
        const index = self.sessions.findPeer(conn) orelse return null;
        return self.peerScore(index, now.mono_ms);
    }

    pub fn unmarkDirect(self: *Gossipsub, identity: *const @import("../wire/peer_id.zig").PeerId) void {
        const peer = self.peers.find(identity) orelse return;
        self.peers.rows[peer.index].direct = false;
    }

    /// Direct peers receive subscribed publications outside mesh and fanout score gates.
    pub fn markDirect(self: *Gossipsub, conn: Handle) void {
        const index = self.sessions.findPeer(conn) orelse return;
        self.peers.rows[self.logical(index).index].direct = true;
        const context = self.overlayContext(self.last_now_ms);
        for (&self.overlay.rows, 0..) |*topic, t| {
            if (topic.mesh.isSet(index)) self.overlay.prune(&context, @intCast(t), index, constants.prune_backoff_ms);
            topic.fanout.unset(index);
        }
    }

    pub fn pressure(self: *Gossipsub, index: u16, reason: @TypeOf(@as(PeerIo, undefined).blocked), now_ms: u64) void {
        const io = &self.sessions.rows[index].io;
        if (io.pressure_since == null) {
            const conn = self.sessions.rows[index].conn;
            std.log.scoped(.network_gossip).debug("gossip_pressure_started connection={d}:{d} reason={s}", .{ conn.index, conn.generation, @tagName(reason) });
            io.pressure_since = now_ms;
        }
        io.blocked = reason;
        io.rx_ready = false;
        self.cancelPromises(index, true);
    }

    fn onMessage(self: *Gossipsub, index: u16, msg: protobuf.Message, now: Now, events: []Event, start: usize) ?usize {
        const context = self.messageContext();
        const workspace: validation_mod.Workspace = .{ .arena = self.decompressed, .scratch = self.msg_scratch, .used = &self.decompressed_used, .peer_work = &self.sessions.rows[index].io.decompressed_pump, .work = &self.budget.work, .large_used = &self.budget.large_used, .event_available = start < events.len };
        const source: @import("messages.zig").Source = .{ .peer = self.logical(index), .session = self.sessions.ref(index), .connection = self.sessions.rows[index].conn };
        switch (self.messages.receive(&context, &workspace, &source, msg, now.mono_ms)) {
            .ignored => return start,
            .invalid => |reason| {
                self.rpc_metrics.invalid_messages[@intFromEnum(reason)] +|= 1;
                const conn = self.sessions.rows[index].conn;
                std.log.scoped(.network_gossip).debug("invalid_message connection={d}:{d} topic={s} reason={s} compressed_bytes={d}", .{ conn.index, conn.generation, msg.topic, @tagName(reason), msg.data.len });
                return start;
            },
            .duplicate => |id| {
                self.counters.duplicates += 1;
                self.topic_metrics.get(msg.topic).duplicates +|= 1;
                self.resolvePromises(id, .{ .now_ms = now.mono_ms, .duplicate = true });
                return start;
            },
            .blocked => |reason| {
                switch (reason) {
                    .events => self.pressure(index, .events, now.mono_ms),
                    .storage => self.pressure(index, .storage, now.mono_ms),
                    .work => self.counters.decompress_throttled += 1,
                }
                return null;
            },
            .admitted => |event| {
                events[start] = .{ .message = event };
                self.resolvePromises(event.id, .{ .now_ms = now.mono_ms });
                self.counters.messages_received += 1;
                self.topic_metrics.get(event.topic).admitted +|= 1;
                if (msg.data.len >= self.options.idontwant_min_data_size) self.broadcastIdontwant(self.overlay.findTopic(event.topic).?, event.id, index);
                return start + 1;
            },
        }
    }

    fn onIhave(self: *Gossipsub, index: u16, ihave: protobuf.IHave, now: Now) void {
        if (self.belowGossip(index, now.mono_ms)) {
            self.rpc_metrics.ignoreIhave(.low_score);
            return;
        }
        const io = &self.sessions.rows[index].io;
        if (io.ihave_recv >= constants.max_ihave_per_heartbeat) {
            self.rpc_metrics.ignoreIhave(.limit);
            return;
        }
        io.ihave_recv += 1;
        const topic = self.overlay.findTopic(ihave.topic);
        if (topic == null or !self.overlay.subscribed(topic.?)) {
            self.rpc_metrics.ignoreIhave(.unsubscribed);
            return;
        }
        const id_budget = constants.max_ihave_ids_per_heartbeat -| @as(usize, io.iwant_ids_sent);
        if (id_budget == 0 or self.recovery.available() == 0) {
            self.rpc_metrics.ignoreIhave(if (id_budget == 0) .limit else .capacity);
            return;
        }
        const metrics = self.topic_metrics.get(ihave.topic);
        var wanted: [constants.gossip_ids_max]MessageId = undefined;
        var count: usize = 0;
        var examined: usize = 0;
        var it = ihave.ids();
        while (it.next() catch return) |id_bytes| {
            if (examined == constants.max_ihave_ids_per_heartbeat) break;
            examined += 1;
            if (count == wanted.len or count >= id_budget) break;
            if (id_bytes.len != constants.message_id_length) continue;
            const id: MessageId = id_bytes[0..constants.message_id_length].*;
            metrics.ihave_ids +|= 1;
            if (!self.messages.wants(id, now.mono_ms)) continue;
            metrics.ihave_unseen +|= 1;
            wanted[count] = id;
            count += 1;
        }
        if (count == 0) return;
        count = self.recovery.select(self.logical(index), wanted[0..count]) catch {
            self.rpc_metrics.ignoreIhave(.peer_capacity);
            return;
        };
        if (count == 0) {
            self.rpc_metrics.ignoreIhave(.no_new_ids);
            return;
        }
        var writer = protobuf.Writer.init(self.msg_scratch);
        writer.varint(protobuf.iwantRpcSize(count, constants.message_id_length));
        protobuf.beginIwantRpc(&writer, count, constants.message_id_length);
        for (wanted[0..count]) |id| protobuf.writeIwantId(&writer, &id);
        if (io.appendControl(writer.written(), false, .iwant, now.mono_ms)) |token| {
            self.recovery.addBatch(&self.peers, wanted[0..count], self.logical(index), self.sessions.rows[index].conn, token, self.overlay.rng.random().uintLessThan(usize, count));
            io.iwant_ids_sent += @intCast(count);
            self.counters.iwant_sent += 1;
        } else self.counters.send_dropped += 1;
    }

    fn onIwant(self: *Gossipsub, index: u16, iwant: protobuf.IdList) void {
        if (self.belowGossip(index, self.last_now_ms)) return;
        var examined: usize = 0;
        var it = iwant.ids();
        while (it.next() catch return) |id_bytes| {
            if (examined >= constants.max_iwant_ids_per_rpc) break;
            examined += 1;
            if (id_bytes.len != constants.message_id_length) continue;
            const id: MessageId = id_bytes[0..constants.message_id_length].*;
            if (self.sessions.suppresses(index, id, self.last_now_ms)) continue;
            switch (self.messages.serve(&self.sessions.rows[index].io, self.logical(index), id, self.options.tx_peer_bytes, self.last_now_ms)) {
                .unknown => self.rpc_metrics.iwant_unknown +|= 1,
                .known => |known| {
                    self.topic_metrics.get(known.topic).iwant_ids +|= 1;
                    if (known.result == .pressured) self.counters.send_dropped += 1;
                },
            }
        }
    }

    /// v1.2: on the first copy of a large message, tell mesh peers not to send
    /// their duplicate. Sent before validation, only to peers on 1.2.0.
    fn broadcastIdontwant(self: *Gossipsub, topic: u16, id: MessageId, source: u16) void {
        var buf: [control_frame_max]u8 = undefined;
        var writer = protobuf.Writer.init(&buf);
        writer.varint(protobuf.idontwantRpcSize(1, constants.message_id_length));
        protobuf.beginIdontwantRpc(&writer, 1, constants.message_id_length);
        protobuf.writeIdontwantId(&writer, &id);
        const rpc = writer.written();
        var it = self.overlay.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            const peer_index: u16 = @intCast(peer);
            if (peer_index == source) continue;
            if (self.sessions.peerVersion(peer_index) != .v1_2) continue;
            if (self.sessions.rows[peer_index].io.appendControl(rpc, false, .idontwant, self.last_now_ms) == null) self.counters.send_dropped += 1;
        }
    }

    fn onIdontwant(self: *Gossipsub, index: u16, idontwant: protobuf.IdList) void {
        const io = &self.sessions.rows[index].io;
        if (io.idontwant_recv >= constants.max_idontwant_per_heartbeat) return;
        io.idontwant_recv += 1;
        var examined: usize = 0;
        var it = idontwant.ids();
        while (it.next() catch return) |id_bytes| {
            if (examined >= constants.dont_send_cap) break;
            examined += 1;
            if (id_bytes.len != constants.message_id_length) continue;
            self.rpc_metrics.idontwant_ids +|= 1;
            if (!self.messages.hasPayload(id_bytes[0..constants.message_id_length].*)) self.rpc_metrics.idontwant_unknown +|= 1;
            self.sessions.suppress(index, id_bytes[0..constants.message_id_length].*, self.last_now_ms, constants.mcache_len * self.options.heartbeat_interval_ms);
        }
    }

    fn onGraft(self: *Gossipsub, index: u16, topic_str: []const u8, now: Now) void {
        const topic = self.overlay.findTopic(topic_str) orelse return;
        _ = self.peerScore(index, now.mono_ms);
        const context = self.overlayContext(now.mono_ms);
        self.overlay.onGraft(&context, topic, index);
    }

    fn onPrune(self: *Gossipsub, index: u16, prune: protobuf.Prune, now: Now) void {
        const topic = self.overlay.findTopic(prune.topic) orelse return;
        const context = self.overlayContext(now.mono_ms);
        self.overlay.onPrune(&context, topic, index, if (prune.backoff == 0) constants.prune_backoff_ms else prune.backoff *| 1000);
    }

    fn onSubscription(
        self: *Gossipsub,
        index: u16,
        sub: protobuf.SubOpts,
        events: []Event,
        start: usize,
    ) usize {
        const context = self.overlayContext(self.last_now_ms);
        _ = self.overlay.peerSubscription(&context, index, sub.topic, sub.subscribe) orelse return start;
        assert(start < events.len);
        const name = self.decompressed[self.decompressed_used..][0..sub.topic.len];
        @memcpy(name, sub.topic);
        self.decompressed_used += name.len;
        events[start] = .{ .subscription_change = .{
            .peer = self.sessions.rows[index].conn,
            .topic = name,
            .subscribed = sub.subscribe,
        } };
        return start + 1;
    }
};

test "gossipsub preserves admission after zero event capacity" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var compressed: [128]u8 = undefined;
    const n = try snappy.raw.compress("payload", &compressed);
    const msg = protobuf.Message{ .data = compressed[0..n], .topic = topic };
    g.budget = .{ .work = g.options.work_per_pump };
    var empty: [0]Event = .{};
    var events: [1]Event = undefined;
    _ = g.onMessage(peer.index, msg, .{ .mono_ms = 1, .unix_s = 1 }, &empty, 0);
    const delivered = g.onMessage(peer.index, msg, .{ .mono_ms = 2, .unix_s = 1 }, &events, 0);
    try std.testing.expectEqual(@as(?usize, 1), delivered);
}

test "gossipsub metrics count a deferred RPC item only once" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    var compressed: [128]u8 = undefined;
    const n = try snappy.raw.compress("payload", &compressed);
    var bytes: [256]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.writeMessage(&writer, compressed[0..n], name);
    g.sessions.rows[peer.index].io.rpc = protobuf.RpcReader.init(writer.written());
    g.budget = .{ .items = 128, .fields = 131072, .work = 1024 * 1024 };
    var count: usize = 0;
    var items: usize = 128;
    for (0..2) |_| try std.testing.expect(!try @import("test_support.zig").driver(&g).processRpc(peer.index, .{ .mono_ms = 1, .unix_s = 1 }, &.{}, &count, &items));
    try std.testing.expectEqual(@as(u64, 1), g.rpc_metrics.items[@intFromEnum(std.meta.Tag(protobuf.Item).message)]);
    try std.testing.expectEqual(@as(u64, 1), g.topic_metrics.get(name).prevalidation);
    try std.testing.expectEqual(@as(u64, 0), g.counters.messages_received);
    var events: [1]Event = undefined;
    try std.testing.expect(try @import("test_support.zig").driver(&g).processRpc(peer.index, .{ .mono_ms = 2, .unix_s = 1 }, &events, &count, &items));
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u64, 1), g.topic_metrics.get(name).prevalidation);
    try std.testing.expectEqual(@as(u64, 1), g.counters.messages_received);
}

test "gossipsub metrics distinguish partial writes from complete publication RPCs" {
    var setup: @import("gossipsub_test.zig").GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.subscribe(name));
    try std.testing.expect(setup.server.subscribe(name));
    for (0..20) |_| try setup.pumpOnce();
    setup.pair.advance(1000);
    for (0..128) |_| try setup.pumpOnce();
    const before = setup.client.rpc_metrics;
    const ItemKind = std.meta.Tag(protobuf.Item);
    try std.testing.expect(before.sent_items[@intFromEnum(ItemKind.subscription)] > 0);
    try std.testing.expect(before.sent_items[@intFromEnum(ItemKind.graft)] + setup.server.rpc_metrics.sent_items[@intFromEnum(ItemKind.graft)] > 0);
    setup.client.options.output_per_peer = 1;
    const result = try setup.client.publish(name, "payload", setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), result.queued);
    try setup.pumpOnce();
    try std.testing.expectEqual(before.sent_bytes + 1, setup.client.rpc_metrics.sent_bytes);
    try std.testing.expectEqual(before.sent_frames, setup.client.rpc_metrics.sent_frames);
    try std.testing.expectEqual(@as(u64, 0), setup.client.rpc_metrics.sent_items[@intFromEnum(std.meta.Tag(protobuf.Item).message)]);
    var received = false;
    for (0..1000) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            try std.testing.expectEqualStrings("payload", event.message.bytes);
            received = true;
        };
        if (received) break;
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.client.rpc_metrics.sent_items[@intFromEnum(std.meta.Tag(protobuf.Item).message)]);
    try std.testing.expectEqual(@as(u64, 1), setup.server.topic_metrics.get(name).prevalidation);
    try std.testing.expect(setup.client.rpc_metrics.sent_bytes > before.sent_bytes + 1);
    try std.testing.expectEqual(setup.client.rpc_metrics.sent_bytes, setup.server.rpc_metrics.received_bytes);
    try std.testing.expect(setup.client.unsubscribe(name));
    for (0..1000) |_| {
        try setup.pumpOnce();
        if (setup.server.rpc_metrics.items[@intFromEnum(ItemKind.prune)] > 0 and
            setup.server.rpc_metrics.items[@intFromEnum(ItemKind.subscription)] > 1) break;
    }
    try std.testing.expectEqual(@as(u64, 1), setup.client.rpc_metrics.sent_items[@intFromEnum(ItemKind.prune)]);
    try std.testing.expectEqual(@as(u64, 2), setup.client.rpc_metrics.sent_items[@intFromEnum(ItemKind.subscription)]);
    try std.testing.expectEqual(@as(u64, 1), setup.server.rpc_metrics.items[@intFromEnum(ItemKind.prune)]);
}

fn testMessage(g: *Gossipsub, peer: u16, text: []const u8, now_ms: u64, events: []Event) !?usize {
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    var compressed: [256]u8 = undefined;
    const n = try snappy.raw.compress(text, &compressed);
    g.budget = .{ .work = g.options.work_per_pump };
    g.sessions.rows[peer].io.decompressed_pump = 0;
    return g.onMessage(peer, .{ .data = compressed[0..n], .topic = topic }, .{ .mono_ms = now_ms, .unix_s = 1 }, events, 0);
}

test "gossipsub pending validation survives history churn and report publish event reuse" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1, .validation_capacity = 2, .seen_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "pending", 1, &events));
    const event = events[0].message;
    for (0..20) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .little);
        _ = try g.publish(topic, &bytes, .{ .mono_ms = 2, .unix_s = 1 });
        g.messages.history.shift(&g.messages.store);
    }
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "pending", 3, &events));
    try std.testing.expectEqual(ReportOutcome{ .applied = .ignore }, g.report(event.handle, .ignore, .{ .mono_ms = 4, .unix_s = 1 }));
    _ = try g.publish("/eth2/01020304/other/ssz_snappy", "reuse", .{ .mono_ms = 5, .unix_s = 1 });
    try std.testing.expectEqualStrings("pending", event.bytes);
    try std.testing.expectEqualStrings(topic, event.topic);
    try std.testing.expectEqual(ReportOutcome.already_resolved, g.report(event.handle, .accept, .{ .mono_ms = 6, .unix_s = 1 }));
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "expires", 7, &events));
    const expires = events[0].message.handle;
    try std.testing.expectEqual(ReportOutcome.expired, g.report(expires, .accept, .{ .mono_ms = 30_007, .unix_s = 1 }));
    try std.testing.expectEqual(ReportOutcome.stale_handle, g.report(expires, .accept, .{ .mono_ms = 60_007, .unix_s = 1 }));
}

test "gossipsub duplicate invalid bytes do not evict useful history" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    _ = try g.publish(topic, "useful", .{ .mono_ms = 1, .unix_s = 1 });
    const useful = topic_mod.validMessageId(topic, "useful", .{});
    const retained = g.messages.history.get(&g.messages.store, useful).?.message;
    var events: [1]Event = undefined;
    for (0..20) |_| {
        try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "useful", 2, &events));
        _ = g.onMessage(peer.index, .{ .topic = topic, .data = &.{ 5, 0 } }, .{ .mono_ms = 2, .unix_s = 1 }, &events, 0);
        try std.testing.expectEqual(retained, g.messages.history.get(&g.messages.store, useful).?.message);
    }
}

test "gossipsub IWANT promises commit on queue and start at completed control transmission" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .control_bytes = 64 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var body: [32]u8 = undefined;
    var w = protobuf.Writer.init(&body);
    const id = [_]u8{7} ** 20;
    w.bytesField(2, &id);
    try std.testing.expect(g.sessions.rows[peer.index].io.append(&([_]u8{0} ** 64), 1));
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    g.sessions.rows[peer.index].io.resetTx(&g.messages.store);
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 2, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    g.expirePromises(10_000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    const io = &g.sessions.rows[peer.index].io;
    const first = io.segment(&g.messages.store);
    _ = io.advance(&g.messages.store, 1);
    try std.testing.expect(g.recovery.batches[0].expiry == null);
    const token = io.advance(&g.messages.store, first.len - 1).?.control.token;
    g.controlSent(peer.index, token, 10_000);
    try std.testing.expectEqual(@as(?u64, 13_000), g.recovery.batches[0].expiry);
    var empty: [0]Event = .{};
    try std.testing.expectEqual(@as(?usize, null), try testMessage(&g, peer.index, "held behind host pressure", 11_000, &empty));
    g.expirePromises(14_000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u64, 1), g.counters.promises_cancelled_pressure);
    g.sessions.rows[peer.index].io.resetHeartbeat();
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 14_000, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    _ = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 2 }, .v1_2).?;
    g.expirePromises(20_000);
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
}

test "gossipsub IHAVE security ignores unknown and unsubscribed topics through RPC decoding" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const subscribed = "/eth2/01020304/beacon_block/ssz_snappy";
    const retired = "/eth2/01020304/beacon_aggregate_and_proof/ssz_snappy";
    try std.testing.expect(g.subscribe(subscribed));
    try std.testing.expect(g.subscribe(retired));
    try std.testing.expect(g.unsubscribe(retired));
    for ([_][]const u8{ "/eth2/01020304/unknown/ssz_snappy", retired, subscribed }) |name| {
        var bytes: [256]u8 = undefined;
        var writer = protobuf.Writer.init(&bytes);
        protobuf.beginIhaveRpc(&writer, name, 1, constants.message_id_length);
        protobuf.writeIhaveId(&writer, &([_]u8{7} ** 20));
        const io = &g.sessions.rows[peer.index].io;
        io.rpc = protobuf.RpcReader.init(writer.written());
        io.rpc_had_control = false;
        io.fields_pump = 0;
        g.budget = .{ .items = 128, .fields = 131072 };
        var items: usize = 128;
        var count: usize = 0;
        try std.testing.expect(try @import("test_support.zig").driver(&g).processRpc(peer.index, .{ .mono_ms = 1, .unix_s = 1 }, &.{}, &count, &items));
        try std.testing.expectEqual(@as(usize, @intFromBool(std.mem.eql(u8, name, subscribed))), g.recovery.len);
    }
}

test "gossipsub IHAVE security bounds one identity and deduplicates queued requests" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .iwant_followup_ms = 12000 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    var bytes: [4096]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    const duplicate = [_]u8{7} ** 20;
    for (0..128) |_| writer.bytesField(2, &duplicate);
    const io = &g.sessions.rows[peer.index].io;
    for (0..2) |_| g.onIhave(peer.index, .{ .topic = name, .body = writer.written() }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    for (0..7) |heartbeat| {
        io.resetHeartbeat();
        for (0..constants.max_ihave_per_heartbeat) |batch| {
            writer.len = 0;
            for (0..constants.gossip_ids_max) |item| {
                var id: MessageId = @splat(0);
                std.mem.writeInt(u32, id[0..4], @intCast((heartbeat * constants.max_ihave_per_heartbeat + batch) * constants.gossip_ids_max + item), .little);
                writer.bytesField(2, &id);
            }
            g.onIhave(peer.index, .{ .topic = name, .body = writer.written() }, .{ .mono_ms = heartbeat * 1000, .unix_s = 1 });
            for (0..4) |_| {
                const segment = io.segment(&g.messages.store);
                if (segment.len == 0) break;
                if (io.advance(&g.messages.store, segment.len)) |completion| g.writeCompleted(g.sessions.ref(peer.index), completion, heartbeat * 1000);
            }
        }
    }
    try std.testing.expectEqual(@as(usize, constants.gossip_ids_max * constants.max_ihave_per_heartbeat), g.recovery.len);
    const other = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const occupied = g.recovery.len;
    g.onIhave(other.index, .{ .topic = name, .body = writer.written() }, .{ .mono_ms = 7000, .unix_s = 1 });
    try std.testing.expectEqual(occupied + constants.gossip_ids_max, g.recovery.len);
    try std.testing.expectEqual(occupied, g.recovery.cancel(&g.peers, g.sessions.rows[peer.index].conn, true));
    io.resetHeartbeat();
    g.onIhave(peer.index, .{ .topic = name, .body = writer.written() }, .{ .mono_ms = 7000, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 2 * constants.gossip_ids_max), g.recovery.len);
}

test "gossipsub rejects incompatible memory plans and cleans partial startup allocations" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .random_seed = 1, .large_message_bytes = 65536 }));
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .random_seed = 1, .decompressed_arena_bytes = 4096 }));
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .random_seed = 1, .large_pool_count = 256 }));
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .random_seed = 1, .fields_per_pump = 1 }));
    try std.testing.checkAllAllocationFailures(a, testStartup, .{});
}
fn testStartup(a: Allocator) !void {
    var g = try Gossipsub.init(a, .{ .random_seed = 1, .seen_capacity = 1, .mcache_capacity = 1, .validation_capacity = 1, .body_buffer_bytes = 1, .control_bytes = 1, .critical_bytes = control_frame_max, .large_pool_count = 1 });
    defer g.deinit();
    const plan = g.memoryPlan();
    try std.testing.expectEqual(@as(usize, 4096), plan.page_bytes);
    try std.testing.expectEqual(g.messages.store.bytes.len, plan.retained_bytes);
    try std.testing.expectEqual(plan.total_bytes, plan.retained_bytes + plan.frame_bytes + plan.event_bytes + plan.compression_bytes + plan.peer_buffer_bytes + plan.metadata_bytes);
}

test "gossipsub legal maximum host acceptance forwards retained pages through actual IO" {
    var setup: @import("gossipsub_test.zig").GossipPair = .{};
    const small = try @import("../configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    try setup.initOpts(small.core.service.gossipsub, small.core.service.gossipsub);
    defer setup.deinit();
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.subscribe(topic));
    try std.testing.expect(setup.server.subscribe(topic));
    for (0..20) |_| try setup.pumpOnce();
    const destination = setup.server.sessions.findPeer(setup.handles.server).?;
    const source = @import("test_support.zig").addPeer(&setup.server, .{ .index = 77, .generation = 1 }, .v1_2).?;
    setup.server.overlay.rows[setup.server.overlay.findTopic(topic).?].mesh.set(destination);
    const payload = try std.testing.allocator.alloc(u8, constants.MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(91);
    rng.random().bytes(payload);
    _ = @import("test_support.zig").pump(&setup.server, &setup.pair.server, setup.pair.now, &.{});
    const len = try snappy.raw.compress(payload, setup.server.msg_scratch);
    setup.server.budget = .{ .work = setup.server.options.work_per_pump };
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), setup.server.onMessage(source.index, .{ .topic = topic, .data = setup.server.msg_scratch[0..len] }, setup.pair.now, &events, 0));
    const handle = events[0].message.handle;
    const message = setup.server.messages.validation.entries[handle.index].state.pending.message;
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, setup.server.report(handle, .accept, setup.pair.now));
    try std.testing.expectEqual(@as(u32, 1), setup.server.messages.store.get(message).?.tx);
    for (0..constants.mcache_len) |_| setup.server.messages.history.shift(&setup.server.messages.store);
    try std.testing.expect(!setup.server.messages.store.get(message).?.history);
    var received = false;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| if (event == .message) {
            try std.testing.expectEqualSlices(u8, payload, event.message.bytes);
            received = true;
        };
        if (received) break;
    }
    try std.testing.expect(received);
    try std.testing.expect(setup.server.messages.store.get(message) == null);
}

test "gossipsub rotates the legal atomic allowance past a duplicate flood" {
    var pair: @import("../test_support.zig").Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .decompress_per_peer_bytes = 1 });
    defer g.deinit();
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var first_rpc: [128]u8 = undefined;
    var second_rpc: [128]u8 = undefined;
    var compressed: [64]u8 = undefined;
    var w1 = protobuf.Writer.init(&first_rpc);
    var w2 = protobuf.Writer.init(&second_rpc);
    const n1 = try snappy.raw.compress("one", &compressed);
    protobuf.writeMessage(&w1, compressed[0..n1], topic);
    const n2 = try snappy.raw.compress("two", &compressed);
    protobuf.writeMessage(&w2, compressed[0..n2], topic);
    const first = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const second = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const stream1: StreamHandle = .{ .conn = .{ .index = 0, .generation = 1 }, .slot = 0, .id = 0 };
    const stream2: StreamHandle = .{ .conn = .{ .index = 1, .generation = 1 }, .slot = 0, .id = 0 };
    g.sessions.setStreams(first.index, null, stream1);
    g.sessions.setStreams(second.index, null, stream2);
    g.sessions.rows[first.index].io.rpc = protobuf.RpcReader.init(w1.written());
    g.sessions.rows[second.index].io.rpc = protobuf.RpcReader.init(w2.written());
    var events: [2]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), @import("test_support.zig").pump(&g, &pair.server, pair.now, &events));
    try std.testing.expectEqualStrings("one", events[0].message.bytes);
    g.sessions.setStreams(first.index, null, stream1);
    g.sessions.rows[first.index].io.rx_ready = true;
    g.sessions.rows[first.index].io.rpc = protobuf.RpcReader.init(w1.written());
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), @import("test_support.zig").driver(&g).nextIoWakeup(pair.now, 2));
    try std.testing.expectEqual(@as(usize, 1), @import("test_support.zig").pump(&g, &pair.server, pair.now, &events));
    try std.testing.expectEqualStrings("two", events[0].message.bytes);
}

test "gossipsub validation attribution cannot penalize reused source or duplicate slots" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const source_conn: Handle = .{ .index = 0, .generation = 1 };
    const duplicate_conn: Handle = .{ .index = 1, .generation = 1 };
    const source = @import("test_support.zig").addPeer(&g, source_conn, .v1_2).?;
    const duplicate = @import("test_support.zig").addPeer(&g, duplicate_conn, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "invalid", 1, &events));
    const handle = events[0].message.handle;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "invalid", 2, &events));
    g.connectionClosed(source_conn);
    g.connectionClosed(duplicate_conn);
    const replacement1 = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 2 }, .v1_2).?;
    const replacement2 = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 2 }, .v1_2).?;
    try std.testing.expectEqual(ReportOutcome{ .applied = .reject }, g.report(handle, .reject, .{ .mono_ms = 3, .unix_s = 1 }));
    try std.testing.expectEqual(@as(f64, 0), g.peers.scores.score(g.logical(replacement1.index).index, 3));
    try std.testing.expectEqual(@as(f64, 0), g.peers.scores.score(g.logical(replacement2.index).index, 3));
}

test "gossip policy reconnect retains authenticated penalty" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const first = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2, &metadata, now).admitted;
    const original = g.logical(first.index);
    g.peers.scores.penalize(original.index, 20);
    const topic_name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic_name));
    const topic = g.overlay.findTopic(topic_name).?;
    const topic_generation = g.overlay.rows[topic].generation;
    g.peers.addBackoff(original, topic, topic_generation, 1, 60_000);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    const second = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2, &metadata, now).admitted;
    try std.testing.expectEqual(original, g.logical(second.index));
    try std.testing.expect(g.peers.backedOff(original, topic, topic_generation, 60_000));
    try std.testing.expect(!g.peers.backedOff(original, topic, topic_generation, 60_001));
    try std.testing.expect(g.peers.scores.score(g.logical(second.index).index, 1) < 0);
}

test "gossip policy GRAFT rejects negative peers and excludes direct peers" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const topic_str = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic_str));
    const topic = g.overlay.findTopic(topic_str).?;
    try std.testing.expect(g.setPeerScore(conn, -1));
    g.onGraft(peer.index, topic_str, .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(topic).count());
    try std.testing.expect(g.setPeerScore(conn, 0));
    g.markDirect(conn);
    g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), topic, peer.index, true);
    var context = g.overlayContext(100_000);
    context.snapshot = &g.cycle.scores;
    g.overlay.maintain(&context, topic);
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(topic).count());
}

test "gossip policy combined transport calls respect one shared peer allowance" {
    var setup: @import("gossipsub_test.zig").GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const peer = setup.client.sessions.findPeer(setup.handles.client).?;
    setup.client.options.calls_per_peer = 1;
    var events: [1]Event = undefined;
    for ([_]usize{ 8, 1 }) |global| {
        setup.client.options.calls_per_pump = global;
        var read_turns: usize = 0;
        var write_turns: usize = 0;
        for (0..8) |_| {
            try std.testing.expect(setup.client.sessions.rows[peer].io.append(&.{0}, setup.pair.now.mono_ms));
            setup.client.sessions.connectionActivity(setup.handles.client);
            _ = @import("test_support.zig").pump(&setup.client, &setup.pair.client, setup.pair.now, &events);
            const calls = global - setup.client.budget.calls;
            try std.testing.expect(calls <= 1);
            if (calls > 0) {
                if (setup.client.budget.output < setup.client.options.output_per_pump) write_turns += 1 else read_turns += 1;
            }
        }
        try std.testing.expect(read_turns > 0 and write_turns > 0);
        for (0..32) |_| {
            if (@import("test_support.zig").driver(&setup.client).nextIoWakeup(setup.pair.now, events.len).? > setup.pair.now.mono_ms) break;
            _ = @import("test_support.zig").pump(&setup.client, &setup.pair.client, setup.pair.now, &events);
            try std.testing.expect(global - setup.client.budget.calls <= 1);
        }
        try std.testing.expect(!setup.client.sessions.rows[peer].io.pending());
        try std.testing.expect(@import("test_support.zig").driver(&setup.client).nextIoWakeup(setup.pair.now, events.len).? > setup.pair.now.mono_ms);
    }
}

test "gossip policy sent promise survives reconnect without token rearming" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = g.addPeer(conn, .v1_2, &metadata, now).admitted;
    const ref = g.logical(first.index);
    g.addPromise([_]u8{1} ** 20, first.index, 9);
    g.controlSent(first.index, 9, 10);
    g.connectionClosed(conn);
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    const next = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2, &metadata, now).admitted;
    g.controlSent(next.index, 9, 2000);
    try std.testing.expectEqual(@as(?u64, 3010), g.recovery.batches[0].expiry);
    g.expirePromises(3010);
    try std.testing.expectEqual(@as(u64, 1), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[ref.index].pins);
}

test "gossip policy duplicate connections preserve one logical owner and direct deliveries" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .outbound };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = g.addPeer(conn, .v1_2, &metadata, now).admitted;
    const second: Handle = .{ .index = 1, .generation = 1 };
    try std.testing.expectEqual(Gossipsub.PeerAdmission.duplicate, g.addPeer(second, .v1_2, &metadata, now));
    g.connectionClosed(second);
    try std.testing.expectEqual(@as(?u16, first.index), g.sessions.findPeer(conn));
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), g.overlay.findTopic(topic).?, first.index, true);
    g.markDirect(conn);
    try std.testing.expect(g.setPeerScore(conn, -100_000));
    g.sessions.rows[first.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
    const result = try g.publish(topic, "direct data", now);
    try std.testing.expectEqual(@as(u16, 1), result.queued);
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(g.overlay.findTopic(topic).?).count());
    g.connectionClosed(conn);
    const next = g.addPeer(second, .v1_2, &metadata, now).admitted;
    try std.testing.expect(g.peers.rows[g.logical(next.index).index].direct);
}

test "gossip policy topic reuse waits for attribution and preserves copied event window" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const topic = g.overlay.findTopic(name).?;
    const generation = g.overlay.rows[topic].generation;
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "retained", 1, &events));
    const event = events[0].message;
    const copied = g.resourceSnapshot();
    try g.configureTopic(name, &.{ .weight = 2 });
    try std.testing.expectEqualStrings("retained", event.bytes);
    try std.testing.expectEqualStrings(name, event.topic);
    try std.testing.expectEqual(@as(usize, 1), copied.pending_validations);
    try std.testing.expectEqualDeep(copied, g.resourceSnapshot());
    try std.testing.expect(g.unsubscribe(name));
    g.connectionClosed(conn);
    g.reclaimTopic(topic);
    try std.testing.expect(g.overlay.rows[topic].active);
    _ = g.report(event.handle, .ignore, .{ .mono_ms = 2, .unix_s = 0 });
    g.messages.validation.expire(&g.messages.store, &g.peers, 30_002);
    g.last_now_ms = 30_002;
    g.reclaimTopic(topic);
    try std.testing.expect(!g.overlay.rows[topic].active);
    const next_name = "/eth2/02030405/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(next_name));
    try std.testing.expectEqual(@as(?u16, topic), g.overlay.findTopic(next_name));
    try std.testing.expect(g.overlay.rows[topic].generation > generation);
    try std.testing.expectEqualStrings(name, event.topic);
    try std.testing.expectEqualStrings("retained", event.bytes);
}

test "gossip policy topic retirement bounds arbitrarily slow active score decay" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .retained_score_ms = 10, .score_params = .{ .decay_interval_ms = 1, .topic = .{ .first_delivery_decay = 0.999999999999 } } });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const topic = g.overlay.findTopic(name).?;
    g.peers.scores.deliver(g.logical(peer.index).index, topic);
    try std.testing.expect(g.unsubscribe(name));
    g.queueSubscriptions(&g.sessions.rows[peer.index].io);
    g.last_now_ms = 11;
    g.peers.scores.refresh(11);
    g.reclaimTopic(topic);
    try std.testing.expect(!g.overlay.rows[topic].active);
    try std.testing.expectEqual(@as(f64, 0), g.peers.scores.score(g.logical(peer.index).index, 11));
}

test "gossip policy unsent subscriptions cannot pin retired topics indefinitely" {
    var pair: @import("../test_support.zig").Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .pressure_timeout_ms = 10 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    _ = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    try std.testing.expect(g.unsubscribe(name));
    var events: [0]Event = .{};
    _ = @import("test_support.zig").pump(&g, &pair.server, .{ .mono_ms = 11, .unix_s = 0 }, &events);
    try std.testing.expect(g.sessions.findPeer(conn) == null);
    try std.testing.expectEqual(@as(u64, 1), g.counters.subscription_timeouts);
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_resets);
    const topic = g.overlay.findTopic(name).?;
    g.reclaimTopic(topic);
    try std.testing.expect(!g.overlay.rows[topic].active);
}

test "gossip policy subscription retry preserves its first pressure deadline" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try std.testing.expect(g.subscribe("/eth2/01020304/beacon_block/ssz_snappy"));
    g.last_now_ms = 1;
    g.sendSubscriptions(peer.index);
    try std.testing.expectEqual(@as(?u64, 0), g.sessions.rows[peer.index].io.subscription_since);
}

test "gossip policy review I4 heartbeat fanout and advertisements share one snapshot" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 17, .topics_per_pump = 1 });
    defer g.deinit();
    const first_name = "/eth2/01020304/beacon_block/ssz_snappy";
    const second_name = "/eth2/01020304/beacon_aggregate_and_proof/ssz_snappy";
    const first = g.internTopic(first_name).?;
    const second = g.internTopic(second_name).?;
    for (0..9) |i| {
        const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), first, peer.index, true);
        g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), second, peer.index, true);
        g.sessions.rows[peer.index].outbound = .{ .live = .{ .conn = g.sessions.rows[peer.index].conn, .id = 2, .slot = 0 } };
    }
    const start: Now = .{ .mono_ms = 1, .unix_s = 0 };
    _ = try g.publish(first_name, "first", start);
    _ = try g.publish(second_name, "second", start);
    g.heartbeat(start);
    g.maintainTopics(start);
    try std.testing.expectEqual(@as(usize, 1), g.cycle.cursor);
    const retained = g.overlay.fanoutMembers(second).findFirstSet().?;
    var advertised: u16 = 0;
    for (0..9) |i| if (!g.overlay.fanoutMembers(second).isSet(i)) {
        advertised = @intCast(i);
    };
    try std.testing.expect(g.peers.scores.setAppScore(g.logical(@intCast(retained)).index, -10_000));
    try std.testing.expect(g.peers.scores.setAppScore(g.logical(advertised).index, -10_000));
    for (g.sessions.rows) |*peer| peer.io.resetTx(&g.messages.store);
    g.last_now_ms = 2;
    g.opportunistic_at = 2;
    g.heartbeat(.{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expect(!g.cycle.opportunistic);
    g.maintainTopics(.{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expect(g.overlay.fanoutMembers(second).isSet(retained));
    try std.testing.expectEqual(@as(usize, 8), g.overlay.fanoutMembers(second).count());
    try std.testing.expectEqual(@as(usize, 1), g.sessions.rows[advertised].io.control.count);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[retained].io.control.count);
    g.maintainTopics(.{ .mono_ms = 3, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.cycle.remaining);
    for (g.sessions.rows) |*peer| peer.io.resetTx(&g.messages.store);
    g.last_now_ms = 701;
    g.heartbeat(.{ .mono_ms = 701, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 701, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 702, .unix_s = 0 });
    try std.testing.expect(!g.overlay.fanoutMembers(second).isSet(retained));
    try std.testing.expectEqual(@as(usize, 7), g.overlay.fanoutMembers(second).count());
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[advertised].io.control.count);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[retained].io.control.count);
    const live = g.overlay.fanoutMembers(second).findFirstSet().?;
    try std.testing.expect(g.peers.scores.setAppScore(g.logical(@intCast(live)).index, -10_000));
    _ = try g.publish(second_name, "live publish", .{ .mono_ms = 703, .unix_s = 0 });
    try std.testing.expect(!g.overlay.fanoutMembers(second).isSet(live));
}

test "gossipsub resource snapshot starts empty" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const snapshot = g.resourceSnapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.admitted_peers);
    try std.testing.expectEqual(@as(usize, 0), snapshot.queued_descriptors);
    try std.testing.expectEqual(@as(usize, 0), snapshot.store_entries);
    try std.testing.expectEqual(@as(usize, 0), snapshot.pending_validations);
}

test "gossip independent RPC enumerates every receive split through admission" {
    // RPC 17.1.1, it-length-prefixed 11.0.1 and Snappy 7.3.3 encoded this two-message fixture.
    const wire = @embedFile("testdata/independent-two.rpc");
    const name = "/eth2/01000000/beacon_block/ssz_snappy";
    try std.testing.expect(wire[0] & 0x80 != 0);
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
        .mcache_capacity = 2,
        .validation_capacity = 2,
        .seen_capacity = 2,
        .seen_ttl_ms = 1,
        .validation_tombstone_ms = 1,
        .body_buffer_bytes = 512,
        .large_pool_count = 1,
    });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try std.testing.expect(g.subscribe(name));
    var expected: [2][64]u8 = undefined;
    for (0..64) |i| {
        expected[0][i] = @intCast(i);
        expected[1][i] = @intCast(255 - i);
    }
    for (0..wire.len + 1) |split| {
        const now: Now = .{ .mono_ms = 1 + split * 10, .unix_s = 1 };
        g.last_now_ms = now.mono_ms;
        g.messages.validation.expire(&g.messages.store, &g.peers, now.mono_ms);
        g.decompressed_used = 0;
        g.budget = .{ .items = 128, .fields = 131072, .work = 1024 * 1024 };
        const io = &g.sessions.rows[peer.index].io;
        io.resetRx();
        io.fields_pump = 0;
        io.decompressed_pump = 0;
        var events: [2]Event = undefined;
        var count: usize = 0;
        var consumed: usize = 0;
        var items: usize = 128;
        for ([_][]const u8{ wire[0..split], wire[split..] }) |fragment| {
            try std.testing.expect(g.sessions.receiveHandoff(peer.index, fragment, false));
            for (0..wire.len + 1) |_| {
                if (io.unread_start == io.unread_end) break;
                const result = try io.feedUnread(io.body, io.unread_end - io.unread_start, now.mono_ms);
                try std.testing.expect(result.consumed > 0);
                consumed += result.consumed;
                if (result.complete) {
                    try std.testing.expect(try @import("test_support.zig").driver(&g).processRpc(peer.index, now, &events, &count, &items));
                    try std.testing.expect(try @import("test_support.zig").driver(&g).processRpc(peer.index, now, &events, &count, &items));
                    io.rpc = null;
                    io.frame_since = null;
                }
            }
        }
        try std.testing.expectEqual(wire.len, consumed);
        try std.testing.expectEqual(@as(usize, 2), count);
        for (events, 0..) |event, i| {
            try std.testing.expectEqualSlices(u8, &expected[i], event.message.bytes);
            try std.testing.expect(g.report(event.message.handle, .ignore, now) == .applied);
        }
        try std.testing.expect(io.rpc == null and io.item == null and io.reader.declaredLen() == null);
        try std.testing.expectEqual(io.unread_end, io.unread_start);
        const snapshot = g.resourceSnapshot();
        try std.testing.expectEqual(@as(usize, 0), snapshot.pending_validations);
        try std.testing.expectEqual(@as(usize, 0), snapshot.store_entries);
        try std.testing.expectEqual(@as(usize, 0), snapshot.store_pages);
        try std.testing.expectEqual(@as(u64, 0), g.counters.duplicates);
    }
}

test "gossipsub history queue refusal and authenticated reconnect preserve retransmission counts" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 2 });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const first = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2, &metadata, now).admitted;
    const logical_peer = g.logical(first.index);
    const id: MessageId = @splat(9);
    const message = g.messages.store.put(id, "t", "payload").?;
    g.messages.history.put(&g.messages.store, message);
    g.messages.store.seal(message);
    var bytes: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.beginIwantRpc(&writer, 1, id.len);
    protobuf.writeIwantId(&writer, &id);
    var reader = protobuf.RpcReader.init(writer.written());
    const iwant = (try reader.next()).?.iwant;
    for (0..peer_io_mod.data_capacity) |_| {
        try std.testing.expectEqual(peer_io_mod.QueueResult.queued, g.sessions.rows[first.index].io.queueData(&g.messages.store, message, g.options.tx_peer_bytes, 1));
    }
    g.onIwant(first.index, iwant);
    try std.testing.expectEqual(@as(u8, 0), g.messages.history.get(&g.messages.store, id).?.counts[logical_peer.index]);
    try std.testing.expectEqual(@as(u64, 1), g.counters.send_dropped);
    g.sessions.rows[first.index].io.resetTx(&g.messages.store);
    for (0..4) |_| g.onIwant(first.index, iwant);
    try std.testing.expectEqual(@as(usize, 3), g.sessions.rows[first.index].io.data_count);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    const second = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2, &metadata, now).admitted;
    try std.testing.expectEqual(logical_peer, g.logical(second.index));
    g.onIwant(second.index, iwant);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[second.index].io.data_count);
    g.connectionClosed(.{ .index = 0, .generation = 2 });
    const expired: Now = .{ .mono_ms = g.peers.retention_ms + 2, .unix_s = 0 };
    const third = g.addPeer(.{ .index = 0, .generation = 3 }, .v1_2, &metadata, expired).admitted;
    try std.testing.expectEqual(logical_peer.index, g.logical(third.index).index);
    try std.testing.expect(g.logical(third.index).generation > logical_peer.generation);
    for (0..4) |_| g.onIwant(third.index, iwant);
    try std.testing.expectEqual(@as(usize, 3), g.sessions.rows[third.index].io.data_count);
}

test "gossip resolved capacities allocate owner rows and reject stale ceiling handles" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    try std.testing.expectEqual(@as(usize, 2), g.sessions.rows.len);
    try std.testing.expectEqual(@as(usize, 2), g.sessions.rows.len);
    try std.testing.expectEqual(@as(usize, 4), g.peers.rows.len);
    try std.testing.expectEqual(@as(usize, 4), g.peers.scores.app_score.len);
    try std.testing.expect(!g.sessions.matches(.{ .index = 2, .generation = 0 }));
    try std.testing.expect(!g.peers.matches(.{ .index = 4, .generation = 0 }));
    try std.testing.expectEqual(ledger.bytes, g.memoryPlan().total_bytes - @sizeOf(Gossipsub));
    g.deinit();
    try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
}

test "recovery owner clear releases sent and unsent attribution pins" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const ref = g.logical(peer.index);
    g.addPromise([_]u8{1} ** 20, peer.index, 1);
    g.addPromise([_]u8{2} ** 20, peer.index, 2);
    g.controlSent(peer.index, 1, 10);
    try std.testing.expectEqual(@as(u32, 2), g.peers.rows[ref.index].pins);
    g.recovery.clear(&g.peers);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[ref.index].pins);
    g.controlSent(peer.index, 2, 20);
    g.expirePromises(4000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
}

test "gossip default owner memory reconciles requested allocations" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    {
        var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1 });
        defer g.deinit();
        const plan = g.memoryPlan();
        try std.testing.expectEqual(ledger.bytes, plan.total_bytes - @sizeOf(Gossipsub));
    }
    try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
}

test "gossip topic rejection preserves expired scores and retained obligations" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
    });
    defer g.deinit();
    var name: [topic_mod.topic_max_len]u8 = undefined;
    for (0..constants.topics_cap) |index| {
        const text = try std.fmt.bufPrint(&name, "/eth2/{x:0>8}/custom/ssz_snappy", .{index});
        try std.testing.expect(g.subscribe(text));
    }
    const first = g.overlay.topicString(0);
    try std.testing.expect(g.unsubscribe(first));
    g.peers.scores.invalid(0, 0);
    g.last_now_ms = g.overlay.rows[0].retire_after_ms.?;
    g.peers.backoffs[0] = .{ .topic_generation = g.overlay.rows[0].generation, .until = g.last_now_ms + 100 };
    const revision = g.peers.scores.revision;
    const generation = g.overlay.rows[0].generation;
    const score = g.peers.scores.topics[0];
    const old_scores = try std.testing.allocator.dupe(@TypeOf(score), g.peers.scores.topics);
    defer std.testing.allocator.free(old_scores);
    const old_topics = try std.testing.allocator.dupe(@TypeOf(g.overlay.rows[0]), &g.overlay.rows);
    defer std.testing.allocator.free(old_topics);
    const old_backoffs = try std.testing.allocator.dupe(@TypeOf(g.peers.backoffs[0]), g.peers.backoffs);
    defer std.testing.allocator.free(old_backoffs);
    const old_params = g.peers.scores.topic_params;
    const old_dirty = g.peers.scores.dirty;
    try std.testing.expectError(error.TopicCapacity, g.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{}));
    try std.testing.expectEqualDeep(old_scores, g.peers.scores.topics);
    try std.testing.expectEqualDeep(old_backoffs, g.peers.backoffs);
    try std.testing.expectEqualDeep(old_params, g.peers.scores.topic_params);
    try std.testing.expectEqualDeep(old_dirty, g.peers.scores.dirty);
    for (old_topics, &g.overlay.rows) |*before, *after| {
        try std.testing.expectEqual(before.active, after.active);
        try std.testing.expectEqual(before.generation, after.generation);
        try std.testing.expectEqual(before.subscribed, after.subscribed);
        try std.testing.expectEqual(before.retire_after_ms, after.retire_after_ms);
        try std.testing.expectEqualDeep(before.subscribers, after.subscribers);
        try std.testing.expectEqualDeep(before.mesh, after.mesh);
        try std.testing.expectEqualDeep(before.fanout, after.fanout);
        try std.testing.expectEqualStrings(before.string[0..before.string_len], after.string[0..after.string_len]);
    }
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expect(g.overlay.rows[0].active);
    try std.testing.expectError(error.InvalidTopic, g.configureTopic("invalid", &.{}));
    try std.testing.expectEqualDeep(score, g.peers.scores.topics[0]);
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    g.last_now_ms += 100;
    g.overlay.rows[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.TopicCapacity, g.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{}));
    try std.testing.expectEqualDeep(score, g.peers.scores.topics[0]);
    g.overlay.rows[0].generation = generation;
    try g.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{ .weight = 2 });
    try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
    try std.testing.expect(!g.peers.scores.retainsTopic(0));
    try std.testing.expectEqual(@as(f64, 2), g.peers.scores.topic_params[0].weight);
}

test "gossip diagnostics tracks queued age and preserves peaks after owner release" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const calls = ledger.allocation_calls;
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const io = &g.sessions.rows[peer.index].io;
    io.resetTx(&g.messages.store);
    const message = g.messages.store.put([_]u8{1} ** 20, "t", "abc").?;
    g.messages.store.retainHistory(message);
    g.messages.store.seal(message);
    try std.testing.expectEqual(peer_io_mod.QueueResult.queued, io.queueData(&g.messages.store, message, 10, 7));
    try std.testing.expect(io.appendControl("ctrl", true, null, 9) != null);
    g.last_now_ms = 20;
    const snapshot = g.resourceSnapshot();
    try std.testing.expectEqual(@as(?u64, 13), snapshot.oldest_tx_age_ms);
    try std.testing.expectEqual(@as(usize, 3), snapshot.queued_bytes);
    try std.testing.expectEqual(@as(usize, 3), snapshot.data_bytes_per_row_high_water);
    try std.testing.expectEqual(@as(usize, 4), snapshot.critical_bytes);
    try std.testing.expectEqual(@as(usize, 1), snapshot.held_tx_retains);
    try std.testing.expectEqualDeep(snapshot, g.resourceSnapshot());
    g.connectionClosed(conn);
    g.messages.store.releaseHistory(message);
    const released = g.resourceSnapshot();
    try std.testing.expectEqual(@as(?u64, null), released.oldest_tx_age_ms);
    try std.testing.expectEqual(@as(usize, 0), released.queued_bytes);
    try std.testing.expectEqual(@as(usize, 0), released.held_tx_retains);
    try std.testing.expectEqual(@as(usize, 3), released.data_bytes_per_row_high_water);
    try std.testing.expectEqual(@as(usize, 3), snapshot.queued_bytes);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
}

test "gossip topic retirement clears expired scores while backoff remains" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
    });
    defer g.deinit();
    const name = "/eth2/00000000/custom/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    g.peers.scores.invalid(0, 0);
    try std.testing.expect(g.unsubscribe(name));
    g.last_now_ms = g.overlay.rows[0].retire_after_ms.?;
    const generation = g.overlay.rows[0].generation;
    g.peers.backoffs[0] = .{ .topic_generation = generation, .until = g.last_now_ms + 100 };
    g.reclaimTopic(0);
    try std.testing.expect(!g.peers.scores.retainsTopic(0));
    try std.testing.expect(g.overlay.rows[0].active);
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expectEqual(g.last_now_ms + 100, g.peers.backoffs[0].until);
}

test "gossip topic configuration snapshots aliased policy before reclamation" {
    for (0..2) |source| {
        var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var g = try Gossipsub.init(ledger.allocator(), .{
            .random_seed = 1,
            .connected_capacity = 2,
            .retained_capacity = 4,
            .retained_outbound_reserve = 1,
        });
        defer g.deinit();
        const calls = ledger.allocation_calls;
        var name: [topic_mod.topic_max_len]u8 = undefined;
        for (0..constants.topics_cap) |index| {
            const text = try std.fmt.bufPrint(&name, "/eth2/{x:0>8}/custom/ssz_snappy", .{index});
            try std.testing.expect(g.subscribe(text));
        }
        try g.configureTopic(g.overlay.topicString(@intCast(source)), &.{ .weight = 2 });
        const expected = g.peers.scores.topic_params[source];
        try std.testing.expect(g.unsubscribe(g.overlay.topicString(0)));
        try std.testing.expect(g.unsubscribe(g.overlay.topicString(1)));
        const generation = g.overlay.rows[0].generation;
        const replacement = "/eth2/ffffffff/custom/ssz_snappy";
        try g.configureTopic(replacement, &g.peers.scores.topic_params[source]);
        try std.testing.expectEqual(@as(?u16, 0), g.overlay.findTopic(replacement));
        try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
        try std.testing.expectEqualDeep(expected, g.peers.scores.topic_params[0]);
        try std.testing.expectEqual(calls, ledger.allocation_calls);
    }
}

test "gossip topic configuration snapshots aliased text under full capacity" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const calls = ledger.allocation_calls;
    const original = "/eth2/00000000/a/ssz_snappy/b/ssz_snappy";
    const shorter = "/eth2/00000000/a/ssz_snappy";
    try std.testing.expect(g.subscribe(original));
    var name: [topic_mod.topic_max_len]u8 = undefined;
    for (1..constants.topics_cap) |index| {
        const text = try std.fmt.bufPrint(&name, "/eth2/{x:0>8}/custom/ssz_snappy", .{index});
        try std.testing.expect(g.subscribe(text));
    }
    const input = g.overlay.topicString(0)[0..shorter.len];
    try std.testing.expect(g.unsubscribe(g.overlay.topicString(0)));
    const generation = g.overlay.rows[0].generation;
    try g.configureTopic(input, &.{ .weight = 2 });
    try std.testing.expectEqualStrings(shorter, g.overlay.topicString(0));
    try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
    try std.testing.expectEqual(@as(f64, 2), g.peers.scores.topic_params[0].weight);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
}

test "gossipsub configured IWANT receipt starts twelve second deadline once" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .iwant_followup_ms = 12_000 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const p = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const io = &g.sessions.rows[p.index].io;
    const token = io.appendControl("control", false, null, 1).?;
    g.recovery.add(&g.peers, [_]u8{1} ** 20, g.logical(p.index), conn, token);
    g.recovery.controlSent(.{ .index = 0, .generation = 2 }, token, 12_000, 5);
    g.controlSent(p.index, token + 1, 5);
    try std.testing.expect(g.recovery.nextExpiry() == null);
    _ = io.segment(&g.messages.store);
    try std.testing.expect(io.advance(&g.messages.store, 1) == null);
    try std.testing.expect(g.recovery.nextExpiry() == null);
    try std.testing.expectEqual(@as(u64, 0), g.recovery.metrics.sent);
    g.writeCompleted(g.sessions.ref(p.index), io.advance(&g.messages.store, 6).?, 100);
    g.controlSent(p.index, token, 200);
    try std.testing.expectEqual(@as(?u64, 12_100), g.recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 1), g.recovery.metrics.sent);
    try std.testing.expectEqual(@as(u64, 0), g.recovery.metrics.resolved);
    g.expirePromises(12_099);
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    g.expirePromises(12_100);
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    try std.testing.expectEqual(@as(u64, 1), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[g.logical(p.index).index].pins);
}

test "gossipsub configured IDONTWANT uses admitted compressed wire bytes" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .idontwant_min_data_size = 128 });
    defer g.deinit();
    const source = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const destination = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    g.overlay.rows[g.overlay.findTopic(name).?].mesh.set(destination.index);
    var payload: [126]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);
    var compressed: [constants.maxCompressedLen(256)]u8 = undefined;
    var events: [1]Event = undefined;
    for ([_]usize{ 124, 125, 126 }, [_]usize{ 127, 128, 129 }) |size, wire_size| {
        g.sessions.rows[destination.index].io.resetTx(&g.messages.store);
        const len = try snappy.raw.compress(payload[0..size], &compressed);
        try std.testing.expectEqual(wire_size, len);
        g.budget = .{ .work = g.options.work_per_pump };
        try std.testing.expectEqual(@as(?usize, 1), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
        try std.testing.expectEqual(wire_size >= 128, g.sessions.rows[destination.index].io.control.used > 0);
        g.sessions.rows[destination.index].io.resetTx(&g.messages.store);
        try std.testing.expectEqual(@as(?usize, 0), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
        try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.control.used);
    }
    const len = try snappy.raw.compress(&([_]u8{0} ** 256), &compressed);
    try std.testing.expect(len < 128);
    try std.testing.expectEqual(@as(?usize, 1), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.control.used);
    _ = g.onMessage(source.index, .{ .topic = name, .data = &.{ 5, 0 } }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.control.used);
    const fresh_len = try snappy.raw.compress("nonadmitted", &compressed);
    g.options.idontwant_min_data_size = 0;
    try std.testing.expectEqual(@as(?usize, null), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..fresh_len] }, .{ .mono_ms = 1, .unix_s = 0 }, &.{}, 0));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.control.used);
    try std.testing.expectEqual(@as(?usize, 1), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..fresh_len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
    try std.testing.expect(g.sessions.rows[destination.index].io.control.used > 0);
}

test "gossipsub remote forwarding honors IDONTWANT and preserves borrowed event through local publication" {
    var pair: @import("gossipsub_test.zig").GossipPair = .{};
    try pair.init();
    defer pair.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(pair.client.subscribe(name));
    try std.testing.expect(pair.server.subscribe(name));
    for (0..20) |_| try pair.pumpOnce();
    const destination = pair.server.sessions.findPeer(pair.handles.server).?;
    const source = @import("test_support.zig").addPeer(&pair.server, .{ .index = 77, .generation = 1 }, .v1_2).?;
    pair.server.overlay.rows[pair.server.overlay.findTopic(name).?].mesh.set(destination);
    const suppressed_id = topic_mod.validMessageId(name, "remote suppressed", .{});
    pair.server.sessions.suppress(destination, suppressed_id, pair.pair.now.mono_ms, 60_000);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&pair.server, source.index, "remote suppressed", pair.pair.now.mono_ms, &events));
    const borrowed = events[0].message;
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, pair.server.report(borrowed.handle, .accept, pair.pair.now));
    try std.testing.expectEqual(@as(usize, 0), pair.server.sessions.rows[destination].io.data_count);
    const local = try pair.server.publish(name, "local while borrowed", pair.pair.now);
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, local);
    try std.testing.expectError(error.Duplicate, pair.server.publish(name, "local while borrowed", pair.pair.now));
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .duplicate = true }, try pair.server.publishWithOptions(name, "local while borrowed", .{ .ignore_duplicate = true }, pair.pair.now));
    try std.testing.expectEqualStrings(name, borrowed.topic);
    try std.testing.expectEqualStrings("remote suppressed", borrowed.bytes);
    var received: usize = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.clientEvents()) |event| if (event == .message) {
            try std.testing.expectEqualStrings("local while borrowed", event.message.bytes);
            received += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try std.testing.expectEqual(@as(u64, 0), pair.server.counters.messages_forwarded);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&pair.server, source.index, "remote forwarded", pair.pair.now.mono_ms, &events));
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, pair.server.report(events[0].message.handle, .accept, pair.pair.now));
    try std.testing.expectEqual(@as(usize, 1), pair.server.sessions.rows[destination].io.data_count);
    received = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.clientEvents()) |event| if (event == .message) {
            try std.testing.expectEqualStrings("remote forwarded", event.message.bytes);
            received += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.messages_forwarded);
}

test "publication subscribed fanout expires through owner maintenance" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const p = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const t = g.overlay.findTopic(name).?;
    g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), t, p.index, true);
    g.sessions.rows[p.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
    _ = try g.publish(name, "fanout expiry", .{ .mono_ms = 0, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.overlay.fanoutMembers(t).count());
    g.heartbeat(.{ .mono_ms = 59_999, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 59_999, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.overlay.fanoutMembers(t).count());
    g.heartbeat(.{ .mono_ms = 60_000, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 60_000, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.overlay.fanoutMembers(t).count());
    g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), t, p.index, false);
    g.sessions.rows[p.index].io.resetTx(&g.messages.store);
    const next_conn: Handle = .{ .index = 1, .generation = 1 };
    const next = @import("test_support.zig").addPeer(&g, next_conn, .v1_2).?;
    g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), t, next.index, true);
    g.sessions.rows[next.index].outbound = .{ .live = .{ .conn = next_conn, .id = 2, .slot = 0 } };
    const result = try g.publish(name, "fresh fanout", .{ .mono_ms = 60_001, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, result);
    try std.testing.expectEqual(@as(usize, 1), g.overlay.fanoutMembers(t).count());
    try std.testing.expect(g.overlay.fanoutMembers(t).isSet(next.index));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[p.index].io.data_count);
    const queued = g.sessions.rows[next.index].io.data[g.sessions.rows[next.index].io.data_head].message;
    try std.testing.expectEqual(topic_mod.validMessageId(name, "fresh fanout", .{}), g.messages.store.get(queued).?.id);
}

test "local intent reclaimed history answers actual IWANT with original wire topic and bytes" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
        .topic_policy = &.{@import("topic_policy_test.zig").full(.{ 1, 2, 3, 4 })},
    });
    defer g.deinit();
    const workspace = try std.testing.allocator.create(local_intent.Workspace);
    defer std.testing.allocator.destroy(workspace);
    workspace.* = .{};
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const replacement = "/eth2/01020304/voluntary_exit/ssz_snappy";
    for (g.overlay.rows[1..]) |*row| row.generation = std.math.maxInt(u64);
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    _ = try g.publish(name, "original payload", now);
    const id = topic_mod.validMessageId(name, "original payload", .{});
    const message = g.messages.history.get(&g.messages.store, id).?.message;
    try std.testing.expect(try g.prepareSubscriptions(&.{.{ .name = replacement, .params = .{} }}, workspace, now));
    g.commitSubscriptions(workspace);
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    var request: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&request);
    protobuf.beginIwantRpc(&writer, 1, id.len);
    protobuf.writeIwantId(&writer, &id);
    var reader = protobuf.RpcReader.init(writer.written());
    g.onIwant(peer.index, (try reader.next()).?.iwant);
    const io = &g.sessions.rows[peer.index].io;
    try std.testing.expectEqual(@as(usize, 1), io.data_count);
    try std.testing.expectEqual(message, io.data[io.data_head].message);
    try std.testing.expectEqual(@as(u8, 1), g.messages.history.get(&g.messages.store, id).?.counts[g.logical(peer.index).index]);
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    for (0..8) |_| {
        const segment = io.segment(&g.messages.store);
        if (segment.len == 0) break;
        try std.testing.expect(used + segment.len <= wire.len);
        @memcpy(wire[used..][0..segment.len], segment);
        used += segment.len;
        _ = io.advance(&g.messages.store, segment.len);
    }
    try std.testing.expectEqual(@as(usize, 0), io.data_count);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..used], name) != null);
    var decompressed: [64]u8 = undefined;
    const size = try snappy.raw.uncompress(g.messages.store.segment(message, g.messages.store.cursor(message)), &decompressed);
    try std.testing.expectEqualStrings("original payload", decompressed[0..size]);
    try std.testing.expectEqualStrings(replacement, g.overlay.topicString(0));
}

test "gossip duplicate fast path ignores host capacity and malformed bodies receive penalties" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .validation_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "pending", 1, &events));
    const handle = events[0].message.handle;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "pending", 2, &.{}));
    try std.testing.expectEqual(@as(u64, 1), g.messages.decoded_messages);
    try std.testing.expectEqual(@as(u64, 1), g.messages.fast_hits);
    _ = g.report(handle, .ignore, .{ .mono_ms = 3, .unix_s = 1 });
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "pending", 4, &events));
    for (0..20) |_| {
        g.budget = .{ .work = g.options.work_per_pump };
        _ = g.onMessage(peer.index, .{ .topic = name, .data = &.{5} }, .{ .mono_ms = 5, .unix_s = 1 }, &events, 0);
    }
    try std.testing.expectEqual(@as(u64, 20), g.peers.scores.penalties.invalid_message);
    try std.testing.expectEqual(@as(u64, 2), g.messages.decoded_messages);
}

test "gossip advertisements sample the whole burst independently for each recipient" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 17 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const t = g.internTopic(name).?;
    for (0..2) |i| {
        const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), t, peer.index, true);
        g.sessions.rows[peer.index].outbound = .{ .live = .{ .conn = g.sessions.rows[peer.index].conn, .id = 2, .slot = 0 } };
    }
    for (0..512) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .little);
        _ = try g.publish(name, &bytes, .{ .mono_ms = 1, .unix_s = 0 });
    }
    for (g.sessions.rows) |*peer| peer.io.resetTx(&g.messages.store);
    g.overlay.rows[t].fanout = .initEmpty();
    const context = g.overlayContext(1);
    g.cycle.takeSnapshot(context.sessions, &context.peers.scores, context.now);
    var snapshot_context = context;
    snapshot_context.snapshot = &g.cycle.scores;
    g.emitGossip(t, &snapshot_context);
    const first = g.sessions.rows[0].io.segment(&g.messages.store);
    const second = g.sessions.rows[1].io.segment(&g.messages.store);
    try std.testing.expect(first.len > 0 and second.len > 0);
    try std.testing.expect(!std.mem.eql(u8, first, second));
    var beyond_prefix: usize = 0;
    for (g.messages.gossip_ids[0..constants.gossip_ids_max]) |id| {
        const entry = g.messages.history.get(&g.messages.store, id).?;
        if (entry.message.index >= constants.gossip_ids_max) beyond_prefix += 1;
    }
    try std.testing.expect(beyond_prefix > constants.gossip_ids_max / 2);
}

test "gossip recent attribution survives validation slot reuse and duplicate pressure" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .validation_capacity = 1 });
    defer g.deinit();
    const source = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const duplicate = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "rejected", 1, &events));
    const old = events[0].message.handle;
    _ = g.report(old, .reject, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "pending", 3, &events));
    const current = events[0].message;
    try std.testing.expectEqual(old.index, current.handle.index);
    try std.testing.expect(old.generation != current.handle.generation);
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "rejected", 4, &.{}));
    try std.testing.expectEqual(@as(u64, 2), g.peers.scores.penalties.invalid_message);
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "rejected", 5, &.{}));
    try std.testing.expectEqual(@as(u64, 2), g.peers.scores.penalties.invalid_message);
    try std.testing.expectEqual(ReportOutcome.stale_handle, g.report(old, .accept, .{ .mono_ms = 6, .unix_s = 0 }));
    @memset(g.messages.fast, .{});
    g.decompressed_used = g.decompressed.len;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, source.index, "pending", 7, &.{}));
    try std.testing.expectEqualStrings("pending", current.bytes);
    try std.testing.expectEqualStrings(name, current.topic);
    try std.testing.expectEqual(ReportOutcome{ .applied = .ignore }, g.report(current.handle, .ignore, .{ .mono_ms = 8, .unix_s = 0 }));
    g.messages.expire(&g.peers, 30_008);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[g.logical(source.index).index].pins);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[g.logical(duplicate.index).index].pins);
}

test "gossip lifecycle sequence preserves ownership under pressure reconnect and late verdicts" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 91, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1, .validation_capacity = 2, .mcache_capacity = 4, .seen_capacity = 8, .mcache_arena_bytes = constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + storage.page_bytes, .validation_timeout_ms = 100, .validation_tombstone_ms = 200 });
    defer g.deinit();
    var rng = std.Random.DefaultPrng.init(17);
    var conn: Handle = .{ .index = 0, .generation = 1 };
    var source = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const metadata: peers_mod.Metadata = .{ .identity = g.peers.rows[g.logical(source.index).index].identity, .address = .unspecified, .direction = .inbound };
    g.markDirect(conn);
    g.sessions.rows[source.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
    if (g.overlay.findTopic(name)) |topic| g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), topic, source.index, true);
    var handles: [8]?ValidationHandle = @splat(null);
    for (0..512) |step| {
        const now: Now = .{ .mono_ms = step * 17 + 1, .unix_s = 0 };
        g.last_now_ms = now.mono_ms;
        const value = rng.random().uintLessThan(u8, 8);
        const payload = [_]u8{'a' + value};
        switch (rng.random().uintLessThan(u8, 9)) {
            0, 1 => {
                g.decompressed_used = 0;
                var events: [1]Event = undefined;
                if (try testMessage(&g, source.index, &payload, now.mono_ms, &events)) |count| {
                    if (count == 1) handles[value] = events[0].message.handle;
                }
            },
            2 => if (handles[value]) |handle| {
                _ = g.report(handle, @enumFromInt(rng.random().uintLessThan(u8, 3)), now);
            },
            3 => {
                _ = g.publish(name, &payload, now) catch |err| switch (err) {
                    error.Duplicate, error.ResourceExhausted => Gossipsub.PublishOutcome{},
                    else => return err,
                };
            },
            4 => g.messages.expire(&g.peers, now.mono_ms),
            5 => {
                g.connectionClosed(conn);
                conn.generation += 1;
                source = g.addPeer(conn, .v1_2, &metadata, now).admitted;
                g.markDirect(conn);
                g.sessions.rows[source.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
                if (g.overlay.findTopic(name)) |topic| g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), topic, source.index, true);
            },
            6 => {
                const subscribed = if (g.overlay.findTopic(name)) |topic| g.overlay.subscribed(topic) else false;
                if (subscribed) {
                    try std.testing.expect(g.unsubscribe(name));
                } else try std.testing.expect(g.subscribe(name));
            },
            7 => {
                g.heartbeat(now);
                g.maintainTopics(now);
            },
            8 => for (g.sessions.rows) |*peer| peer.io.resetTx(&g.messages.store),
            else => unreachable,
        }
        var pending: usize = 0;
        var occupied_pages: usize = 0;
        for (g.messages.store.entries, 0..) |*entry, index| {
            if (!entry.active) continue;
            try std.testing.expect(!entry.provisional);
            occupied_pages += storage.Store.pagesFor(entry.len);
            var validations: usize = 0;
            for (g.messages.validation.entries) |*slot| if (slot.state == .pending and slot.state.pending.message.index == index) {
                try std.testing.expectEqual(entry.generation, slot.state.pending.message.generation);
                validations += 1;
            };
            try std.testing.expectEqual(@as(usize, @intFromBool(entry.validation)), validations);
            pending += validations;
            const history = g.messages.history.get(&g.messages.store, entry.id);
            try std.testing.expectEqual(entry.history, if (history) |record| record.message.index == index and record.message.generation == entry.generation else false);
            var retained: u32 = 0;
            for (g.sessions.rows) |*peer| for (0..peer.io.data_count) |queued| {
                const handle = peer.io.data[(peer.io.data_head + queued) % peer_io_mod.data_capacity].message;
                if (handle.index == index and handle.generation == entry.generation) retained += 1;
            };
            try std.testing.expectEqual(entry.tx, retained);
        }
        try std.testing.expectEqual(g.messages.store.next.len, occupied_pages + g.messages.store.free_pages);
        var records_pending: usize = 0;
        var pins: [4]u32 = @splat(0);
        for (g.messages.validation.recent) |*record| {
            records_pending += @intFromBool(record.state == .pending);
            if (!record.pinned) continue;
            try std.testing.expect(g.peers.matches(record.source));
            pins[record.source.index] += 1;
            for (record.duplicates[0..record.duplicate_len]) |*duplicate| {
                try std.testing.expect(g.peers.matches(duplicate.peer));
                pins[duplicate.peer.index] += 1;
            }
        }
        try std.testing.expectEqual(pending, records_pending);
        for (g.peers.rows, pins) |*peer, expected| try std.testing.expectEqual(expected, peer.pins);
    }
}
