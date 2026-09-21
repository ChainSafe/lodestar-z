const session_io = @import("session_io.zig");
const std = @import("std");
const snappy = @import("snappy");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const topic_policy = @import("topic_policy.zig");
const local_intent = @import("local_intent.zig");
const topic_mod = @import("topic.zig");
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
const Now = types.Now;
const timing = @import("../metrics/timing.zig");
const Sessions = sessions_mod.Sessions;

pub const Options = @import("options.zig").Options;

pub const InitError = Allocator.Error || error{InvalidLimits} || topic_policy.Error;

/// Advertised protocol ids, newest first; the negotiator settles the version.
pub const MessageId = topic_mod.MessageId;

pub const Verdict = validation_mod.Verdict;
pub const ValidationHandle = validation_mod.Handle;
pub const ReportOutcome = validation_mod.Outcome;
pub const MessageSink = @import("messages.zig").MessageSink;

pub const Event = union(enum) {
    /// A new message the host must validate and then close out with
    /// `report(handle, verdict, now)`. `bytes` is the decompressed payload, valid
    /// until the next pump; the host copies what it needs.
    message: @import("messages.zig").MessageEvent,
    subscription_change: struct { peer: Handle, topic: []const u8, subscribed: bool },
};

const PeerIo = peer_io_mod.PeerIo;
const Turn = @import("turn.zig").Turn;
const Credits = @import("turn.zig").Credits;
const Progress = @import("turn.zig").Progress;
const Layout = @import("layout.zig").Layout;
pub const MemoryPlan = @import("layout.zig").Plan;

/// Live occupancy for bounded host supervision and deterministic test baselines.
/// This scans fixed startup capacities: peers, topics, validation entries and store entries.
/// High waters are the largest physical-row peak since init, including previous connections.
/// Age uses last_now_ms and original queue admission until complete send or reset.
pub const ResourceSnapshot = struct {
    receive_pages: usize = 0,
    receive_page_capacity: usize = 0,
    receive_pages_high_water: usize = 0,
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
    delivery_descriptors_capacity: usize = 0,
    delivery_descriptors_available: usize = 0,
    delivery_descriptors_reserved: usize = 0,

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
    open_cursor: usize = 0,
    allocator: Allocator,
    options: Options,
    memory: MemoryPlan,
    sessions: *Sessions,
    peers: peers_mod.PeerBook,
    messages: @import("messages.zig").Messages,
    /// The sink and its context must outlive every pump that uses them.
    message_sink: ?*const MessageSink = null,
    cycle: @import("heartbeat_cycle.zig").Cycle = .{},
    metrics_io: std.Io = std.Io.Threaded.global_single_threaded.io(),
    maintenance: timing.Gossip = .{},
    retired_queue_drops: [@import("outbox.zig").drop_reason_count]u64 = @splat(0),
    overlay: *overlay_mod.Overlay,
    heartbeat_at: u64 = 0,
    opportunistic_at: u64 = 0,
    last_now_ms: u64 = 0,
    msg_scratch: []u8,
    decompressed: []u8,
    recovery: Recovery,
    counters: Counters = .{},
    topic_metrics: @import("metrics.zig").Topics = .{},
    rpc_metrics: @import("metrics.zig").Rpc = .{},
    validation_time: @import("metrics.zig").ValidationTime = .{},

    pub const Admission = session_io.Admission;
    pub const Delivery = session_io.Delivery;
    pub const shutdown = session_io.shutdown;
    pub const admitted = session_io.admitted;
    pub const deliveryStatus = session_io.deliveryStatus;
    pub const deliveryAvailable = session_io.deliveryAvailable;
    pub const peerConnected = session_io.peerConnected;
    pub const transportEvents = session_io.transportEvents;
    pub const retireConnection = session_io.retireConnection;
    pub const negotiationResult = session_io.negotiationResult;
    pub const connectionActivity = session_io.connectionActivity;
    pub const nextWakeup = session_io.nextWakeup;
    pub const pump = session_io.pump;

    pub fn deliveryRevision(self: *const Gossipsub) u64 {
        return self.sessions.delivery_revision;
    }

    pub fn coverageRevision(self: *const Gossipsub) [4]u64 {
        return .{ self.overlay.subscription_revision, if (self.overlay.namespace) |*ns| ns.revision else 0, self.peers.scores.revision, self.cycle.epoch };
    }

    pub fn coverageSubscriptions(self: *Gossipsub, conn: Handle, digest: [4]u8, local: *const @import("topic_policy.zig").Subnets, now: Now) @import("topic_policy.zig").Subnets {
        const index = self.sessions.findPeer(conn) orelse return .{};
        if (self.sessions.rows[index].outStream() == null) return .{};
        var result = self.overlay.subnetSubscriptions(index, digest);
        if (self.peers.rows[self.logical(index).index].direct) return result;
        const value = self.peerScore(index, now.mono_ms);
        if (value < self.options.score_params.publish_threshold) return .{};
        if (value < 0) {
            result.attnets &= ~local.attnets;
            result.syncnets &= ~local.syncnets;
            result.columns = result.columns.differenceWith(local.columns);
        }
        return result;
    }

    pub const Counters = struct {
        heartbeats_skipped: u64 = 0,
        retained_penalty_evictions: u64 = 0,
        messages_received: u64 = 0,
        messages_published: u64 = 0,
        messages_forwarded: u64 = 0,
        duplicates: u64 = 0,
        rpcs_received: u64 = 0,
        send_dropped: u64 = 0,
        malformed_rpcs: u64 = 0,
        decompress_throttled: u64 = 0,
        large_stalled: u64 = 0,
        iwant_sent: u64 = 0,
        broken_promises: u64 = 0,
        promises_cancelled_pressure: u64 = 0,
        local_pressure_resets: u64 = 0,
        tx_stalled: u64 = 0,
        subscription_timeouts: u64 = 0,
        receive_capacity_refusals: u64 = 0,
        message_capacity_refusals: u64 = 0,
        receive_copy_bytes: u64 = 0,
        receive_pressure_timeouts: u64 = 0,
        receive_frame_timeouts: u64 = 0,
        send_queue_timeouts: u64 = 0,
        send_progress_timeouts: u64 = 0,
        negotiation_started: u64 = 0,
        negotiation_ready: u64 = 0,
        negotiation_rejected: u64 = 0,
        negotiation_failed: u64 = 0,
        negotiation_refused: u64 = 0,
    };

    pub fn init(allocator: Allocator, options: Options) InitError!Gossipsub {
        try @import("options.zig").validate(&options);
        const layout = Layout.init(&options);
        const memory = layout.plan();
        const namespace: ?topic_policy.Namespace = if (options.topic_policy) |boundaries| try topic_policy.Namespace.init(allocator, boundaries, options.connected_capacity) else null;
        errdefer if (namespace) |owned| {
            var ns = owned;
            ns.deinit(allocator);
        };

        const sessions = try allocator.create(Sessions);
        errdefer allocator.destroy(sessions);
        sessions.* = try Sessions.init(allocator, &options, &layout);
        errdefer sessions.deinit(allocator);

        const overlay = try allocator.create(overlay_mod.Overlay);
        errdefer allocator.destroy(overlay);
        overlay.* = overlay_mod.Overlay.init(options.random_seed.?);
        overlay.slot = options.initial_slot;

        var peers = try peers_mod.PeerBook.init(allocator, &options);
        errdefer peers.deinit(allocator);

        var messages = try @import("messages.zig").Messages.init(allocator, &options, &layout);
        errdefer messages.deinit(allocator, &peers);
        const msg_scratch = try allocator.alloc(u8, constants.GOSSIP_MAX_SIZE);
        errdefer allocator.free(msg_scratch);
        const decompressed = try allocator.alloc(u8, layout.output_bytes);
        errdefer allocator.free(decompressed);
        var recovery = try Recovery.init(allocator);
        errdefer recovery.deinit(allocator, &peers);

        var result: Gossipsub = .{
            .allocator = allocator,
            .options = options,
            .memory = memory,
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

    pub fn prepareSubscriptions(self: *Gossipsub, subscriptions: []const local_intent.Boundary, workspace: *local_intent.Workspace, now: Now, slot: u64) local_intent.Error!bool {
        const context = self.overlayContext(self.last_now_ms);
        const pins = self.messages.topicPins();
        return self.overlay.prepareSubscriptions(&context, &pins, subscriptions, workspace, now.mono_ms, slot);
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
    pub fn addPeer(self: *Gossipsub, conn: Handle, metadata: *const peers_mod.Metadata, now: Now) PeerAdmission {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        if (self.sessions.findPeer(conn)) |index| return .{ .admitted = .{ .index = index, .generation = self.sessions.peerGeneration(index) } };
        if (self.peers.find(&metadata.identity)) |ref| {
            if (self.peers.rows[ref.index].connection != null) return .duplicate;
        }
        const handle = self.sessions.addPeer(conn) orelse return .capacity;
        if (self.overlay.namespace) |*ns| ns.clearPeer(handle.index);
        const admission_result = self.peers.admit(conn, metadata, now.mono_ms);
        if (admission_result != .admitted) {
            self.sessions.removePeer(handle.index);
            return if (admission_result == .duplicate) .duplicate else .capacity;
        }
        if (admission_result.admitted.penalty_evicted) self.counters.retained_penalty_evictions += 1;
        const ref = admission_result.admitted.peer;
        self.sessions.rows[handle.index].logical = ref;
        return .{ .admitted = handle };
    }

    fn logical(self: *const Gossipsub, index: u16) peers_mod.Ref {
        assert(self.sessions.rows[index].active);
        return self.sessions.rows[index].logical;
    }

    pub fn connectionClosed(self: *Gossipsub, conn: Handle) void {
        const index = self.sessions.findPeer(conn) orelse return;
        _ = self.sessions.resetRx(index);
        self.cancelWrites(self.sessions.ref(index));
        const context = self.overlayContext(self.last_now_ms);
        self.overlay.peerDisconnected(&context, index);
        const ref = self.logical(index);
        self.peers.disconnect(ref, self.last_now_ms);
        for (&self.retired_queue_drops, self.sessions.rows[index].io.tx.drops) |*total, value| total.* +|= value;
        self.sessions.rows[index].io.tx.drops = @splat(0);
        self.sessions.removePeer(index);
    }

    pub fn cancelWrites(self: *Gossipsub, session: sessions_mod.SessionRef) void {
        if (!self.sessions.matches(session)) return;
        self.sessions.rows[session.index].io.tx.cancelStream(&self.messages.store);
        self.cancelPromises(session.index, false);
    }

    pub fn sendSubscriptions(self: *Gossipsub, index: u16) void {
        self.overlay.synchronize(&self.sessions.rows[index].io.tx, self.last_now_ms);
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
        const h = self.messages.publish(id, topic_str, self.msg_scratch[0..clen], now_ms, self.cycle.epoch) orelse return error.ResourceExhausted;
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
        return .{ .overlay = self.overlay, .peers = &self.peers, .options = &self.options, .epoch = self.cycle.epoch };
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
            if (!self.sessions.rows[index].active or self.sessions.rows[index].outbound == .closing) continue;
            if (source) |p| {
                if (std.meta.eql(p, self.logical(index)) or self.sessions.suppresses(index, id, now_ms)) continue;
            }
            result.selected += 1;
            if (self.sessions.rows[index].outStream() == null) {
                result.unavailable += 1;
                continue;
            }
            if (self.sessions.rows[index].io.tx.queueData(&self.messages.store, h, self.options.tx_peer_bytes, now_ms) == .queued) {
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

    pub fn tick(self: *Gossipsub, now: Now) void {
        if (self.heartbeat_at == 0) {
            self.heartbeat_at = now.mono_ms +| self.options.heartbeat_interval_ms;
        } else if (now.mono_ms >= self.heartbeat_at) {
            const start = timing.now(self.metrics_io);
            self.maintenance.lateness.observe((now.mono_ms - self.heartbeat_at) *| 1_000_000);
            if (!self.cycle.isActive()) self.maintenance.started_ns = start;
            self.heartbeat(now);
            self.maintenance.setup.observe(timing.now(self.metrics_io) -| start);
            self.heartbeat_at = now.mono_ms +| self.options.heartbeat_interval_ms;
        }
    }

    pub fn receiveItem(self: *Gossipsub, session: sessions_mod.SessionRef, item: protobuf.Item, turn: *Turn, peer: *Credits) Progress {
        if (!self.sessions.matches(session)) return .done;
        const now = turn.now;
        const index = session.index;
        if (self.sessions.rows[index].outbound == .closing) return .done;
        switch (item) {
            .subscription => |sub| {
                if (self.options.observe_subscriptions and self.validTopic(sub.topic) and self.overlay.findTopic(sub.topic) != null and (turn.count == turn.events.len or turn.arena.len - turn.used < sub.topic.len)) {
                    return .events;
                }
                self.onSubscription(index, sub, turn);
            },
            .message => |msg| {
                const result = self.onMessage(index, msg, turn, peer);
                if (result != .done) return result;
            },
            else => {
                if (self.sessions.rows[index].outStream() != null) {
                    switch (item) {
                        .ihave => |ihave| {
                            const workspace = turn.workspace(peer);
                            if (!workspace.chargeWork(&self.options, self.ihaveWork(ihave.body.len))) return .credits;
                            self.onIhave(index, ihave, now);
                        },
                        .iwant => |iwant| self.onIwant(index, iwant),
                        .graft => |name| self.onGraft(index, name, now),
                        .prune => |prune| self.onPrune(index, prune, now),
                        .idontwant => |ids| self.onIdontwant(index, ids),
                        else => unreachable,
                    }
                }
            },
        }
        return .done;
    }

    pub fn acceptsRpc(self: *Gossipsub, index: u16, now: Now) bool {
        return self.peers.rows[self.logical(index).index].direct or
            self.peerScore(index, now.mono_ms) >= self.options.score_params.graylist_threshold;
    }

    pub fn ignoreRpc(self: *Gossipsub, index: u16, now: Now) bool {
        if (self.acceptsRpc(index, now)) return false;
        self.rpc_metrics.graylist_dropped +|= 1;
        return true;
    }

    pub fn memoryPlan(self: *const Gossipsub) MemoryPlan {
        return self.memory;
    }

    pub fn resourceSnapshot(self: *const Gossipsub) ResourceSnapshot {
        var result: ResourceSnapshot = .{
            .connected_capacity = self.sessions.rows.len,
            .retained_capacity = self.peers.rows.len,
            .validation_capacity = self.messages.validationCapacity(),
            .delivery_descriptors_capacity = self.sessions.deliveries.slots.len,
            .delivery_descriptors_available = self.sessions.deliveries.available,
            .delivery_descriptors_reserved = self.sessions.deliveries.protected,
            .admitted_peers = 0,
            .remote_subscriptions = 0,
            .mesh_members = 0,
            .queued_descriptors = 0,
            .queued_bytes = 0,
            .held_frames = 0,
            .receive_pages = self.sessions.receive_pool.next.len - self.sessions.receive_pool.free_pages,
            .receive_page_capacity = self.sessions.receive_pool.next.len,
            .receive_pages_high_water = self.sessions.receive_pool.high_water,
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
            result.subscription_pending_peers += @intFromBool(io.tx.subscription_since != null);
            result.queued_descriptors += io.tx.data.count;
            result.queued_bytes += io.tx.data.bytes;
            result.control_frames += io.tx.control.count;
            result.control_bytes += io.tx.control.used;
            result.critical_frames += io.tx.critical.count;
            result.critical_bytes += io.tx.critical.used;
            result.data_bytes_per_row_high_water = @max(result.data_bytes_per_row_high_water, io.tx.data.bytes_high_water);
            result.data_descriptors_per_row_high_water = @max(result.data_descriptors_per_row_high_water, io.tx.data.descriptors_high_water);
            result.control_bytes_per_row_high_water = @max(result.control_bytes_per_row_high_water, io.tx.control.bytes_high_water);
            result.control_frames_per_row_high_water = @max(result.control_frames_per_row_high_water, io.tx.control.frames_high_water);
            result.critical_bytes_per_row_high_water = @max(result.critical_bytes_per_row_high_water, io.tx.critical.bytes_high_water);
            result.critical_frames_per_row_high_water = @max(result.critical_frames_per_row_high_water, io.tx.critical.frames_high_water);
            if (io.tx.oldest()) |since| result.oldest_tx_age_ms = @max(result.oldest_tx_age_ms orelse 0, self.last_now_ms -| since);
            if (io.reader.declaredLen() != null or io.rpc != null) result.held_frames += 1;
        }
        for (self.overlay.rows) |topic| {
            if (!topic.active) continue;
            for (0..self.sessions.rows.len) |peer| {
                if (self.overlay.namespace == null and topic.subscribers.isSet(peer)) result.remote_subscriptions += 1;
                if (topic.mesh.isSet(peer)) result.mesh_members += 1;
            }
        }
        if (self.overlay.namespace) |*ns| result.remote_subscriptions = ns.subscription_count;
        for (self.messages.store.entries) |entry| result.held_tx_retains += entry.tx;
        result.pending_validations = self.messages.stats().pending;
        return result;
    }

    fn heartbeat(self: *Gossipsub, now: Now) void {
        for (self.sessions.rows) |*peer| peer.io.resetHeartbeat();
        self.peers.refresh(now.mono_ms);
        if (self.cycle.isActive()) {
            self.counters.heartbeats_skipped +|= 1;
            return;
        }
        const opportunistic = self.opportunistic_at != 0 and now.mono_ms >= self.opportunistic_at;
        if (self.opportunistic_at == 0 or opportunistic) self.opportunistic_at = now.mono_ms +| self.options.opportunistic_graft_interval_ms;
        self.cycle.begin(self.sessions, &self.peers, now.mono_ms, opportunistic);
    }

    pub fn maintainTopics(self: *Gossipsub, now: Now) void {
        if (!self.cycle.isActive()) return;
        const start = timing.now(self.metrics_io);
        defer self.maintenance.topics.observe(timing.now(self.metrics_io) -| start);
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
        if (self.cycle.complete()) |epoch| {
            self.messages.history.age(&self.messages.store, epoch);
            self.maintenance.completed(timing.now(self.metrics_io), std.Io.Timestamp.now(self.metrics_io, .real).toSeconds());
        }
    }

    fn emitGossip(self: *Gossipsub, topic: u16, context: *const overlay_mod.Context) void {
        const topic_str = self.overlay.topicString(topic);
        const ids = self.messages.gossipIds(topic_str, self.cycle.epoch);
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
            if (self.sessions.rows[peer].io.tx.submit(&.{ .ihave = .{ .topic = topic_str, .ids = ids[0..n] } }, self.last_now_ms) == null) self.counters.send_dropped += 1;
        }
    }

    fn resolvePromises(self: *Gossipsub, id: MessageId, receipt: ?Recovery.Receipt) void {
        self.recovery.resolve(&self.peers, id, receipt);
    }

    pub fn cancelPromises(self: *Gossipsub, peer: u16, local_pressure: bool) void {
        const removed = self.recovery.cancel(&self.peers, self.sessions.rows[peer].conn, local_pressure);
        if (local_pressure) self.counters.promises_cancelled_pressure += removed;
    }

    pub fn writeSegment(self: *Gossipsub, session: sessions_mod.SessionRef) []const u8 {
        assert(self.sessions.matches(session));
        const outbox = &self.sessions.rows[session.index].io.tx;
        self.overlay.flushSubscriptions(outbox, self.last_now_ms);
        return outbox.segment(&self.messages.store);
    }

    pub fn advanceWrite(self: *Gossipsub, session: sessions_mod.SessionRef, written: usize, now_ms: u64) void {
        assert(self.sessions.matches(session));
        self.rpc_metrics.sent_bytes +|= written;
        if (self.sessions.rows[session.index].io.tx.advance(&self.messages.store, written)) |completion| self.writeCompleted(session, completion, now_ms);
    }

    pub fn writeCompleted(self: *Gossipsub, session: sessions_mod.SessionRef, completion: @import("outbox.zig").Completion, now_ms: u64) void {
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

    pub fn expirePromises(self: *Gossipsub, now_ms: u64) void {
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
            if (topic.mesh.isSet(index)) self.overlay.prune(&context, @intCast(t), index, constants.prune_backoff_ms, .direct);
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

    fn onMessage(self: *Gossipsub, index: u16, msg: protobuf.Message, turn: *Turn, peer: *Credits) Progress {
        const now = turn.now;
        const context = self.messageContext();
        const workspace = turn.workspace(peer);
        const source: @import("messages.zig").Source = .{ .peer = self.logical(index), .session = self.sessions.ref(index), .connection = self.sessions.rows[index].conn };
        const result = self.messages.receive(&context, &workspace, &source, msg, now.mono_ms);
        if (result == .duplicate or result == .admitted) {
            const work = self.recovery.resolveWork();
            turn.budget.work -|= work;
            peer.work -|= work;
        }
        switch (result) {
            .ignored => return .done,
            .invalid => |reason| {
                self.rpc_metrics.invalid_messages[@intFromEnum(reason)] +|= 1;
                const conn = self.sessions.rows[index].conn;
                std.log.scoped(.network_gossip).debug("invalid_message connection={d}:{d} topic={s} reason={s} compressed_bytes={d}", .{ conn.index, conn.generation, msg.topic, @tagName(reason), msg.data.len });
                return .done;
            },
            .duplicate => |id| {
                self.counters.duplicates += 1;
                self.topic_metrics.get(msg.topic).duplicates +|= 1;
                self.resolvePromises(id, .{ .now_ms = now.mono_ms, .duplicate = true });
                return .done;
            },
            .blocked => |reason| {
                if (reason == .work) self.counters.decompress_throttled += 1;
                return switch (reason) {
                    .events => .events,
                    .storage => blk: {
                        self.counters.message_capacity_refusals += 1;
                        self.cancelPromises(index, true);
                        break :blk .done;
                    },
                    .work => .credits,
                };
            },
            .admitted => |event| {
                self.resolvePromises(event.id, .{ .now_ms = now.mono_ms });
                self.counters.messages_received += 1;
                self.topic_metrics.get(event.topic).admitted +|= 1;
                if (msg.data.len >= self.options.idontwant_min_data_size) self.broadcastIdontwant(self.overlay.findTopic(event.topic).?, event.id, index);
                if (turn.sink) |sink| {
                    sink.deliver(sink.context, &event);
                } else {
                    turn.events[turn.count] = .{ .message = event };
                    turn.count += 1;
                }
                return .done;
            },
        }
    }

    pub fn ihaveWork(self: *const Gossipsub, body_len: usize) usize {
        return ihaveWorkBound(body_len, self.messages.seen.index.probe_limit + self.messages.validation.index.probe_limit, self.recovery.batch_len, self.recovery.len);
    }

    pub fn ihaveWorkBound(body_len: usize, probes: usize, batches: usize, requests: usize) usize {
        const ids: usize = @min(constants.max_ihave_ids_per_heartbeat, body_len / (constants.message_id_length + 2));
        const selected: usize = @min(ids, constants.gossip_ids_max);
        const fields: usize = @min(body_len / 2 + 1, 8193);
        const header_work = constants.topics_cap * (topic_mod.topic_max_len + @sizeOf(score_mod.TopicParams) + @sizeOf(score_mod.TopicCounters) + @sizeOf(score_mod.TopicWeights)) +
            @as(usize, peers_mod.capacity) * @sizeOf(peers_mod.Row) + @sizeOf(peers_mod.PeerBook);
        // Each protobuf field consumes at least two bytes and at most two
        // ten-byte varints. Include a score refresh, IP population and topic
        // lookup; ID lookups include a slot read and key comparison. Selected
        // IDs include one bounded sampling swap, promise admission and encoding.
        return header_work + 20 * fields +
            Recovery.selectionWork(ids, batches, requests) + ids * probes * (@sizeOf(MessageId) + @sizeOf(u32)) +
            selected * 384;
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
        comptime assert(constants.max_ihave_ids_per_heartbeat * @sizeOf(MessageId) <= constants.GOSSIP_MAX_SIZE);
        const candidates = std.mem.bytesAsSlice(MessageId, self.msg_scratch[0 .. constants.max_ihave_ids_per_heartbeat * @sizeOf(MessageId)]);
        var count: usize = 0;
        var it = ihave.ids();
        for (0..constants.max_ihave_ids_per_heartbeat) |_| {
            const id_bytes = (it.next() catch return) orelse break;
            if (id_bytes.len != constants.message_id_length) continue;
            metrics.ihave_ids +|= 1;
            candidates[count] = id_bytes[0..constants.message_id_length].*;
            count += 1;
        }
        const selected = self.recovery.filterPending(self.logical(index), candidates[0..count]) catch {
            self.rpc_metrics.ignoreIhave(.peer_capacity);
            return;
        };
        const limit = @min(constants.gossip_ids_max, id_budget, selected.capacity);
        count = 0;
        for (candidates[0..selected.count]) |id| {
            if (!self.messages.wants(id, now.mono_ms)) continue;
            candidates[count] = id;
            count += 1;
        }
        if (count == 0) {
            self.rpc_metrics.ignoreIhave(.no_new_ids);
            return;
        }
        const requested = @min(count, limit);
        for (0..requested) |i| {
            const chosen = i + @as(usize, @intCast(self.overlay.rng.random().uintLessThanBiased(u64, @intCast(count - i))));
            std.mem.swap(MessageId, &candidates[i], &candidates[chosen]);
        }
        metrics.ihave_unseen +|= requested;
        self.recovery.requestBatch(&self.peers, &io.tx, candidates[0..requested], self.logical(index), self.sessions.rows[index].conn, self.overlay.rng.random(), self.options.iwant_followup_ms, now.mono_ms) catch {
            self.counters.send_dropped += 1;
            return;
        };
        io.iwant_ids_sent += @intCast(requested);
        self.counters.iwant_sent += 1;
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
            if (!self.messages.hasPayload(id)) {
                self.rpc_metrics.iwant_unknown +|= 1;
                continue;
            }
            if (self.sessions.suppresses(index, id, self.last_now_ms)) continue;
            switch (self.messages.serve(&self.sessions.rows[index].io.tx, self.logical(index), id, self.options.tx_peer_bytes, self.last_now_ms)) {
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
        var it = self.overlay.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            const peer_index: u16 = @intCast(peer);
            if (peer_index == source) continue;
            const outbound = self.sessions.rows[peer_index].outbound;
            if (outbound != .live or outbound.live.version != .v1_2) continue;
            if (self.sessions.rows[peer_index].io.tx.submit(&.{ .idontwant = &.{id} }, self.last_now_ms) == null) self.counters.send_dropped += 1;
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
        turn: *Turn,
    ) void {
        const context = self.overlayContext(self.last_now_ms);
        _ = self.overlay.peerSubscription(&context, index, sub.topic, sub.subscribe) orelse return;
        if (!self.options.observe_subscriptions) return;
        assert(turn.count < turn.events.len);
        const name = turn.arena[turn.used..][0..sub.topic.len];
        @memcpy(name, sub.topic);
        turn.used += name.len;
        turn.events[turn.count] = .{ .subscription_change = .{
            .peer = self.sessions.rows[index].conn,
            .topic = name,
            .subscribed = sub.subscribe,
        } };
        turn.count += 1;
    }
};

test {
    _ = @import("gossipsub_ingress_test.zig");
    _ = @import("gossipsub_owner_messages_test.zig");
    _ = @import("gossipsub_owner_policy_test.zig");
    _ = @import("gossipsub_owner_resources_test.zig");
    _ = @import("gossipsub_publication_test.zig");
    _ = @import("gossipsub_resource_test.zig");
    _ = @import("gossipsub_scheduled_test.zig");
    _ = @import("gossipsub_service_test.zig");
    _ = @import("gossipsub_simulation_test.zig");
    _ = @import("gossipsub_test.zig");
}
