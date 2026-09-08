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
const ReceivePool = @import("receive_pool.zig").ReceivePool;
const Recovery = @import("recovery.zig").Recovery;
const peer_io_mod = @import("peer_io.zig");
const score_mod = @import("score.zig");
const mesh_mod = @import("mesh.zig");
const peers_mod = @import("peers.zig");
const state_mod = @import("state.zig");
const engine_mod = @import("../quic/engine.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const Now = types.Now;
const State = state_mod.State;
const Version = state_mod.Version;

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
    namespace: ?topic_policy.Namespace,
    state: *State,
    scores: score_mod.PeerScore,
    peers: peers_mod.Peers,
    ip_allowlist: [32]peers_mod.Ip = undefined,
    ip_allowlist_len: u8 = 0,
    seen: mcache_mod.SeenCache,
    mcache: mcache_mod.History,
    store: storage.Store,
    validation: validation_mod.Validation,
    peer_cursor: usize = 0,
    topic_cursor: usize = 0,
    topics_remaining: usize = 0,
    opportunistic_pending: bool = false,
    budget: Budget = .{},
    io: peer_io_mod.Pool,
    receive_pool: ReceivePool,
    mesh_policy: mesh_mod.Mesh,
    heartbeat_at: u64 = 0,
    opportunistic_at: u64 = 0,
    last_now_ms: u64 = 0,
    msg_scratch: []u8,
    decompressed: []u8,
    decompressed_used: usize = 0,
    recovery: Recovery,
    counters: Counters = .{},

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
    };

    pub fn init(allocator: Allocator, options: Options) InitError!Gossipsub {
        try @import("options.zig").validate(&options);
        var namespace: ?topic_policy.Namespace = if (options.topic_policy) |boundaries| try topic_policy.Namespace.init(allocator, boundaries, options.connected_capacity) else null;
        errdefer if (namespace) |*ns| ns.deinit(allocator);

        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.* = try State.init(allocator, options.connected_capacity);
        errdefer state.deinit(allocator);

        var peers = try peers_mod.Peers.initCapacity(allocator, options.retained_score_ms, options.retained_capacity, options.retained_outbound_reserve);
        errdefer peers.deinit(allocator);

        var scores = try score_mod.PeerScore.initCapacity(allocator, options.score_params, options.retained_capacity);
        errdefer scores.deinit(allocator);
        @memset(&scores.connected, false);

        var seen = try mcache_mod.SeenCache.init(
            allocator,
            options.seen_capacity,
            options.seen_ttl_ms,
        );
        errdefer seen.deinit(allocator);
        var mcache = try mcache_mod.History.initCapacity(allocator, options.mcache_capacity, options.retained_capacity);
        errdefer mcache.deinit(allocator);
        var store = try storage.Store.init(allocator, options.mcache_capacity + options.validation_capacity, options.mcache_arena_bytes);
        errdefer store.deinit(allocator);
        var validation = try validation_mod.Validation.init(allocator, options.validation_capacity, options.validation_timeout_ms, options.validation_tombstone_ms);
        errdefer validation.deinit(allocator);
        var io = try peer_io_mod.Pool.init(allocator, &options);
        errdefer io.deinit(allocator);
        const msg_scratch = try allocator.alloc(u8, constants.GOSSIP_MAX_SIZE);
        errdefer allocator.free(msg_scratch);
        const decompressed = try allocator.alloc(u8, options.decompressed_arena_bytes);
        errdefer allocator.free(decompressed);
        var recovery = try Recovery.init(allocator);
        errdefer recovery.deinit(allocator, &peers);
        var receive_pool = try ReceivePool.init(allocator, options.large_pool_count, options.large_message_bytes);
        errdefer receive_pool.deinit(allocator);

        var result: Gossipsub = .{
            .allocator = allocator,
            .options = options,
            .namespace = namespace,
            .state = state,
            .scores = scores,
            .peers = peers,
            .seen = seen,
            .mcache = mcache,
            .store = store,
            .validation = validation,
            .io = io,
            .receive_pool = receive_pool,
            .msg_scratch = msg_scratch,
            .decompressed = decompressed,
            .recovery = recovery,
            .mesh_policy = mesh_mod.Mesh.init(options.random_seed.?),
        };
        @memcpy(result.ip_allowlist[0..options.ip_allowlist.len], options.ip_allowlist);
        result.ip_allowlist_len = @intCast(options.ip_allowlist.len);
        result.options.ip_allowlist = &.{};
        result.options.topic_policy = null;
        return result;
    }

    pub fn deinit(self: *Gossipsub) void {
        self.receive_pool.deinit(self.allocator);
        self.recovery.deinit(self.allocator, &self.peers);
        self.allocator.free(self.decompressed);
        self.allocator.free(self.msg_scratch);
        self.io.deinit(self.allocator);
        self.mcache.deinit(self.allocator);
        self.validation.deinit(self.allocator);
        self.store.deinit(self.allocator);
        self.seen.deinit(self.allocator);
        self.scores.deinit(self.allocator);
        self.peers.deinit(self.allocator);
        self.state.deinit(self.allocator);
        self.allocator.destroy(self.state);
        if (self.namespace) |*ns| ns.deinit(self.allocator);
        self.* = undefined;
    }

    // Subscriptions ----------------------------------------------------------

    pub fn subscribe(self: *Gossipsub, topic_str: []const u8) bool {
        const topic = self.internTopic(topic_str) orelse return false;
        if (self.state.subscribed(topic)) return true;
        self.state.topics[topic].retire_after_ms = null;
        self.state.setSubscribed(topic, true);
        self.state.fanout(topic).* = .initEmpty();
        self.announce(topic_str, true);
        return true;
    }

    fn internTopic(self: *Gossipsub, name: []const u8) ?u16 {
        if (!self.validTopic(name)) return null;
        if (self.state.findTopic(name)) |topic| return topic;
        if (self.state.internTopic(name)) |topic| return self.initializeTopic(topic);
        const pins = self.retirementPins();
        for (0..constants.topics_cap) |index| {
            const topic: u16 = @intCast(index);
            if (self.state.topics[topic].generation == std.math.maxInt(u64) or
                !self.retirement(topic, &pins, self.last_now_ms).reusable) continue;
            for (0..constants.topics_cap) |reclaim| self.reclaimObserved(@intCast(reclaim), self.retirement(@intCast(reclaim), &pins, self.last_now_ms));
            return self.initializeTopic(self.state.internTopic(name) orelse unreachable);
        }
        return null;
    }

    fn validTopic(self: *const Gossipsub, name: []const u8) bool {
        if (self.namespace) |*ns| return ns.lookup(name) != null;
        return name.len <= topic_mod.topic_max_len and topic_mod.parse(name) != null;
    }

    fn initializeTopic(self: *Gossipsub, topic: u16) u16 {
        if (self.namespace) |*ns| {
            const match = ns.lookup(self.state.topicString(topic)).?;
            ns.initializeSubscribers(match.ordinal, &self.state.topics[topic].subscribers);
        }
        return topic;
    }

    fn retirementPins(self: *const Gossipsub) local_intent.Pins {
        var pins: local_intent.Pins = .{};
        for (self.validation.entries) |*entry| if (entry.pinned) {
            pins.validation.set(entry.topic);
        };
        for (self.io.peers, 0..) |*io, peer| {
            if (self.state.peers[peer].active) pins.announcements.setUnion(io.subscription_dirty);
        }
        return pins;
    }

    const Retirement = struct { blocked: bool, expired: bool, reusable: bool };

    fn retirement(self: *const Gossipsub, topic: u16, pins: *const local_intent.Pins, now_ms: u64) Retirement {
        const row = &self.state.topics[topic];
        if (!row.active or row.subscribed or row.mesh.count() > 0 or row.fanout.count() > 0 or
            self.mesh_policy.pending_prunes[topic].count() > 0 or pins.validation.isSet(topic) or
            pins.announcements.isSet(topic)) return .{ .blocked = true, .expired = false, .reusable = false };
        const expired = if (row.retire_after_ms) |deadline| now_ms >= deadline else false;
        var backoff = false;
        for (0..self.peers.rows.len) |peer| {
            const value = self.peers.backoffs[peer * constants.topics_cap + topic];
            if (value.topic_generation == row.generation and now_ms < value.until) {
                backoff = true;
                break;
            }
        }
        return .{ .blocked = false, .expired = expired, .reusable = (expired or !self.scores.retainsTopic(topic)) and !backoff };
    }

    fn reclaimObserved(self: *Gossipsub, topic: u16, observed: Retirement) void {
        if (observed.blocked) return;
        if (observed.expired) self.scores.resetTopic(topic);
        if (!observed.reusable) return;
        self.state.topics[topic].active = false;
        self.state.topics[topic].subscribers = .initEmpty();
        self.scores.configureTopic(topic, self.options.score_params.topic) catch unreachable;
    }

    fn reclaimTopic(self: *Gossipsub, topic: u16) void {
        const pins = self.retirementPins();
        self.reclaimObserved(topic, self.retirement(topic, &pins, self.last_now_ms));
    }

    /// Does not mutate protocol state or end event borrows. Commit must immediately follow acceptance.
    pub fn prepareSubscriptions(self: *Gossipsub, subscriptions: []const local_intent.Subscription, workspace: *local_intent.Workspace, now: Now) local_intent.Error!bool {
        workspace.prepared = false;
        if (subscriptions.len > constants.topics_cap) return error.TopicCapacity;
        if (subscriptions.len > 0 and self.namespace == null) return error.TopicPolicyRequired;
        workspace.len = @intCast(subscriptions.len);
        workspace.reserved = .initEmpty();
        workspace.now_ms = @max(self.last_now_ms, now.mono_ms);
        var changed = false;
        for (subscriptions, 0..) |*subscription, i| {
            if (!self.validTopic(subscription.name)) return error.InvalidTopic;
            try score_mod.validateTopic(subscription.params);
            const entry = &workspace.entries[i];
            entry.len = @intCast(subscription.name.len);
            @memcpy(entry.bytes[0..entry.len], subscription.name);
            entry.params = subscription.params;
            for (workspace.entries[0..i]) |*earlier| {
                if (std.mem.eql(u8, entry.name(), earlier.name())) return error.DuplicateTopic;
            }
            entry.row = self.state.findTopic(entry.name());
            entry.existing = entry.row != null;
            if (entry.row) |row| {
                workspace.reserved.set(row);
                entry.generation = self.state.topics[row].generation;
                changed = changed or !self.state.subscribed(row) or !std.meta.eql(entry.params, self.scores.topic_params[row]);
            } else changed = true;
        }
        workspace.pins = self.retirementPins();
        var cursor: usize = 0;
        for (workspace.entries[0..workspace.len]) |*entry| {
            if (entry.existing) continue;
            while (cursor < constants.topics_cap) : (cursor += 1) {
                const row = &self.state.topics[cursor];
                if (workspace.reserved.isSet(cursor) or row.generation == std.math.maxInt(u64)) continue;
                if (row.active and !self.retirement(@intCast(cursor), &workspace.pins, workspace.now_ms).reusable) continue;
                entry.row = @intCast(cursor);
                entry.generation = row.generation;
                workspace.reserved.set(cursor);
                cursor += 1;
                break;
            }
            if (entry.row == null) return error.TopicCapacity;
        }
        for (&self.state.topics, 0..) |*row, index| {
            if (row.active and row.subscribed and !workspace.reserved.isSet(index)) changed = true;
        }
        workspace.prepared = true;
        return changed;
    }

    pub fn commitSubscriptions(self: *Gossipsub, workspace: *local_intent.Workspace) void {
        assert(workspace.prepared);
        workspace.prepared = false;
        self.last_now_ms = workspace.now_ms;
        for (workspace.entries[0..workspace.len]) |*entry| {
            const index = entry.row.?;
            const row = &self.state.topics[index];
            assert(row.generation == entry.generation);
            if (!entry.existing) {
                self.scores.resetTopic(index);
                row.active = false;
                self.state.assignTopic(index, entry.name(), entry.generation);
                _ = self.initializeTopic(index);
            }
            self.scores.configureTopic(index, entry.params) catch unreachable;
        }
        for (workspace.entries[0..workspace.len]) |*entry| {
            const subscribed = self.subscribe(entry.name());
            assert(subscribed);
        }
        for (&self.state.topics, 0..) |*row, index| {
            if (row.active and row.subscribed and !workspace.reserved.isSet(index)) {
                const unsubscribed = self.unsubscribe(self.state.topicString(@intCast(index)));
                assert(unsubscribed);
            }
        }
    }

    pub const ConfigureTopicError = error{ InvalidLimits, InvalidTopic, TopicCapacity };

    /// Copies scalar parameters and topic bytes without ending the current event borrow window.
    pub fn configureTopic(self: *Gossipsub, name: []const u8, params: *const score_mod.TopicParams) ConfigureTopicError!void {
        const copied = params.*;
        try score_mod.validateTopic(copied);
        if (!self.validTopic(name)) return error.InvalidTopic;
        const topic = self.internTopic(name) orelse return error.TopicCapacity;
        self.scores.configureTopic(topic, copied) catch unreachable;
    }

    pub fn unsubscribe(self: *Gossipsub, topic_str: []const u8) bool {
        const topic = self.state.findTopic(topic_str) orelse return false;
        if (!self.state.subscribed(topic)) return true;
        self.leaveMesh(topic, topic_str);
        self.state.setSubscribed(topic, false);
        self.state.topics[topic].retire_after_ms = self.last_now_ms +| self.options.retained_score_ms;
        self.announce(topic_str, false);
        return true;
    }

    /// Leaving a topic: PRUNE every mesh peer with the shorter unsubscribe
    /// backoff, then clear the mesh so a later re-subscribe starts fresh.
    fn leaveMesh(self: *Gossipsub, topic: u16, topic_str: []const u8) void {
        _ = topic_str;
        const context = self.meshContext(self.last_now_ms);
        var it = self.state.mesh(topic).iterator(.{});
        while (it.next()) |peer| self.mesh_policy.prune(&context, topic, @intCast(peer), constants.unsubscribe_backoff_ms);
    }

    fn announce(self: *Gossipsub, topic_str: []const u8, subscribe_flag: bool) void {
        _ = subscribe_flag;
        const topic = self.state.findTopic(topic_str).?;
        for (self.io.peers, 0..) |*io, index| {
            if (!self.state.peers[index].active) continue;
            io.subscription_dirty.set(topic);
            if (io.subscription_since == null) io.subscription_since = self.last_now_ms;
            io.tx_ready = true;
        }
    }

    // Peer lifecycle ---------------------------------------------------------

    pub const PeerAdmission = union(enum) { admitted: state_mod.PeerHandle, duplicate, capacity };

    /// Metadata must come from an authenticated transport connection. Refusal leaves transport usable.
    pub fn addPeer(self: *Gossipsub, conn: Handle, version: Version, metadata: *const peers_mod.Metadata, now: Now) PeerAdmission {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        if (self.state.findPeer(conn)) |index| return .{ .admitted = .{ .index = index, .generation = self.state.peerGeneration(index) } };
        if (self.peers.find(&metadata.identity)) |ref| {
            if (self.peers.rows[ref.index].connection != null) return .duplicate;
        }
        const handle = self.state.addPeer(conn, version) orelse return .capacity;
        if (self.namespace) |*ns| ns.clearPeer(handle.index);
        const admitted = self.peers.admit(conn, metadata, now.mono_ms);
        if (admitted != .admitted) {
            self.state.removePeer(handle.index);
            return if (admitted == .duplicate) .duplicate else .capacity;
        }
        if (admitted.admitted.penalty_evicted) self.counters.retained_penalty_evictions += 1;
        const ref = admitted.admitted.peer;
        self.mcache.bindPeer(ref);
        self.state.peers[handle.index].logical = ref;
        if (admitted.admitted.fresh) self.scores.resetPeer(ref.index);
        self.scores.setConnected(ref.index, true, now.mono_ms);
        self.io.peers[handle.index].resetTx(&self.store);
        self.io.peers[handle.index].resetRx();
        self.io.peers[handle.index].resetHeartbeat();
        self.sendSubscriptions(handle.index);
        return .{ .admitted = handle };
    }

    fn logical(self: *const Gossipsub, index: u16) peers_mod.Ref {
        assert(self.state.peers[index].active);
        return self.state.peers[index].logical;
    }

    pub fn setStreams(self: *Gossipsub, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        self.state.setStreams(index, out, in);
        self.io.peers[index].rx_ready = in != null;
        self.io.peers[index].tx_ready = out != null;
    }

    pub fn resetInbound(self: *Gossipsub, engine: *Engine, index: u16) void {
        if (self.state.peers[index].in_stream) |stream| engine.closeStream(stream, 0);
        self.state.peers[index].in_stream = null;
        const io = &self.io.peers[index];
        self.releaseLarge(io);
        io.resetRx();
    }

    pub fn resetOutbound(self: *Gossipsub, engine: *Engine, index: u16) void {
        if (self.state.peers[index].out_stream) |stream| engine.closeStream(stream, 0);
        self.state.peers[index].out_stream = null;
        self.io.peers[index].resetTx(&self.store);
        self.cancelPromises(index, false);
        self.wakeStorage();
    }

    pub fn replaceInbound(
        self: *Gossipsub,
        engine: *Engine,
        index: u16,
        stream: StreamHandle,
        version: Version,
    ) void {
        if (self.state.peers[index].in_stream) |prior| {
            if (std.meta.eql(prior, stream)) return;
        }
        self.resetInbound(engine, index);
        self.state.peers[index].inbound_version = version;
        self.state.peers[index].in_stream = stream;
        self.io.peers[index].rx_ready = true;
    }

    pub fn replaceOutbound(
        self: *Gossipsub,
        engine: *Engine,
        index: u16,
        stream: StreamHandle,
        version: Version,
    ) void {
        if (self.state.peers[index].out_stream) |prior| {
            if (std.meta.eql(prior, stream)) return;
        }
        self.resetOutbound(engine, index);
        self.state.setVersion(index, version);
        self.state.peers[index].out_stream = stream;
        self.sendSubscriptions(index);
    }

    pub fn receiveHandoff(self: *Gossipsub, index: u16, bytes: []const u8, fin: bool) bool {
        const io = &self.io.peers[index];
        if (bytes.len > io.unread.len - io.unread_end) return false;
        @memcpy(io.unread[io.unread_end..][0..bytes.len], bytes);
        io.unread_end += bytes.len;
        io.fin_seen = fin;
        io.rx_ready = true;
        return true;
    }

    pub fn connectionClosed(self: *Gossipsub, conn: Handle) void {
        const index = self.state.findPeer(conn) orelse return;
        self.releaseLarge(&self.io.peers[index]);
        self.io.peers[index].resetTx(&self.store);
        self.io.peers[index].resetRx();
        self.cancelPromises(index, false);
        self.wakeStorage();
        self.mesh_policy.forget(index);
        self.io.peers[index].write_first = false;
        self.io.peers[index].subscription_since = null;
        const ref = self.logical(index);
        for (&self.state.topics, 0..) |*topic, t| {
            if (topic.mesh.isSet(index)) self.scores.prune(ref.index, @intCast(t), self.last_now_ms);
        }
        self.scores.setConnected(ref.index, false, self.last_now_ms);
        self.peers.disconnect(ref, self.last_now_ms, self.scores.score(ref.index, self.last_now_ms) < 0);
        self.state.removePeer(index);
        if (self.namespace) |*ns| ns.clearPeer(index);
    }

    fn sendSubscriptions(self: *Gossipsub, index: u16) void {
        const io = &self.io.peers[index];
        io.subscription_dirty = .initEmpty();
        for (&self.state.topics, 0..) |*topic, t| {
            if (topic.active and topic.subscribed) io.subscription_dirty.set(t);
        }
        io.tx_ready = true;
        io.subscription_since = if (io.subscription_dirty.count() > 0) io.subscription_since orelse self.last_now_ms else null;
    }

    fn queueSubscriptions(self: *Gossipsub, io: *PeerIo) void {
        var buf: [sub_frame_max]u8 = undefined;
        for (0..constants.topics_cap) |_| {
            const topic = io.subscription_cursor;
            if (io.subscription_dirty.isSet(topic)) {
                const t = &self.state.topics[topic];
                var w = protobuf.Writer.init(&buf);
                w.varint(protobuf.subscriptionSize(t.string[0..t.string_len]));
                protobuf.writeSubscription(&w, t.subscribed, t.string[0..t.string_len]);
                if (io.appendControl(w.written(), true, self.last_now_ms) == null) return;
                io.subscription_dirty.unset(topic);
            }
            io.subscription_cursor = (topic + 1) % constants.topics_cap;
        }
        io.subscription_since = null;
    }

    pub const PublishOptions = struct { allow_zero_peers: bool = true, ignore_duplicate: bool = false, flood: bool = false };
    pub const PublishError = error{ PayloadTooLarge, UnknownTopic, CompressFailed, ResourceExhausted, Duplicate, NoPeersSubscribedToTopic };
    pub const PublishOutcome = struct { queued: u16 = 0, pressured: u16 = 0, selected: u16 = 0, unavailable: u16 = 0, duplicate: bool = false };

    pub fn publish(self: *Gossipsub, topic_str: []const u8, ssz: []const u8, now: Now) PublishError!PublishOutcome {
        return self.publishWithOptions(topic_str, ssz, .{}, now);
    }

    /// Admits one shared history payload; queued counts live stream queue admissions.
    pub fn publishWithOptions(self: *Gossipsub, topic_str: []const u8, ssz: []const u8, options: PublishOptions, now: Now) PublishError!PublishOutcome {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        const now_ms = self.last_now_ms;
        if (ssz.len > constants.MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;
        if (!self.validTopic(topic_str)) return error.UnknownTopic;
        if (self.namespace) |*ns| {
            if (ssz.len > ns.lookup(topic_str).?.rule.ssz_max) return error.PayloadTooLarge;
        }
        const id = topic_mod.validMessageId(topic_str, ssz, self.options.message_id_policy);
        if (self.seen.contains(id, now_ms)) {
            if (options.ignore_duplicate) return .{ .duplicate = true };
            return error.Duplicate;
        }
        const topic = self.internTopic(topic_str) orelse return error.UnknownTopic;
        const context = self.meshContext(now_ms);
        const recipients = self.mesh_policy.publicationRecipients(&context, topic, options.flood);
        if (recipients.count() == 0 and !options.allow_zero_peers) return error.NoPeersSubscribedToTopic;
        const clen = snappy.raw.compress(ssz, self.msg_scratch) catch return error.CompressFailed;
        const h = self.mcache.admitPayload(&self.store, id, topic_str, self.msg_scratch[0..clen]) orelse return error.ResourceExhausted;
        self.mcache.put(&self.store, h);
        self.store.seal(h);
        const fresh = self.seen.add(id, now_ms);
        assert(fresh);
        self.resolvePromises(id);
        const result = self.deliver(&recipients, h, null, now_ms);
        self.counters.messages_published += 1;
        return result;
    }

    fn validationContext(self: *Gossipsub) validation_mod.Context {
        return .{ .state = self.state, .peers = &self.peers, .scores = &self.scores, .store = &self.store, .history = &self.mcache, .seen = &self.seen, .options = &self.options, .namespace = if (self.namespace) |*ns| ns else null };
    }

    /// Event slices remain valid until the next pump, including after report or publish.
    pub fn report(self: *Gossipsub, handle: ValidationHandle, verdict: Verdict, now: Now) ReportOutcome {
        self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
        const context = self.validationContext();
        const result = self.validation.report(&context, handle, verdict, now.mono_ms);
        if (result.forward) |forward| {
            const delivered = self.deliver(self.state.mesh(forward.topic), forward.message, forward.source, now.mono_ms);
            if (delivered.queued > 0) self.counters.messages_forwarded += 1;
        }
        self.wakeStorage();
        return result.outcome;
    }

    fn deliver(self: *Gossipsub, peers: *const state_mod.PeerSet, h: storage.Handle, source: ?validation_mod.PeerRef, now_ms: u64) PublishOutcome {
        const id = self.store.get(h).?.id;
        var result: PublishOutcome = .{};
        var recipients = peers.*;
        const topic = self.state.findTopic(self.store.get(h).?.topicString()).?;
        if (source != null) for (self.state.peers, 0..) |*row, peer| {
            if (row.active and self.peers.rows[row.logical.index].direct and self.state.subscribers(topic).isSet(peer)) recipients.set(peer);
        };
        var it = recipients.iterator(.{});
        while (it.next()) |peer| {
            const index: u16 = @intCast(peer);
            if (!self.state.peers[index].active or self.mesh_policy.retire.isSet(index)) continue;
            if (source) |p| {
                if (std.meta.eql(p, self.logical(index)) or self.state.suppresses(index, id, now_ms)) continue;
            }
            if (!self.peers.rows[self.logical(index).index].direct and self.peerScore(index, now_ms) < self.options.score_params.publish_threshold) continue;
            result.selected += 1;
            if (self.state.peers[index].out_stream == null) {
                result.unavailable += 1;
                continue;
            }
            if (self.io.peers[index].queueData(&self.store, h, self.options.tx_peer_bytes, now_ms) == .queued) {
                result.queued += 1;
            } else {
                result.pressured += 1;
                self.counters.send_dropped += 1;
            }
        }
        assert(result.selected == result.queued + result.pressured + result.unavailable);
        return result;
    }

    fn meshContext(self: *Gossipsub, now_ms: u64) mesh_mod.Context {
        return .{ .state = self.state, .peers = &self.peers, .scores = &self.scores, .io = self.io.peers, .now = now_ms, .heartbeat_ms = self.options.heartbeat_interval_ms, .pressure_ms = self.options.pressure_timeout_ms };
    }

    // Pump -------------------------------------------------------------------

    pub fn memoryPlan(self: *const Gossipsub) MemoryPlan {
        const metadata = @sizeOf(Gossipsub) + @sizeOf(State) + self.state.peers.len * @sizeOf(@TypeOf(self.state.peers[0])) + self.peers.rows.len * @sizeOf(peers_mod.Row) + self.peers.backoffs.len * @sizeOf(peers_mod.Backoff) + self.io.peers.len * @sizeOf(PeerIo) +
            self.store.entries.len * @sizeOf(storage.Entry) + self.store.next.len * @sizeOf(u32) +
            self.validation.entries.len * @sizeOf(validation_mod.Entry) + self.mcache.entries.len * @sizeOf(mcache_mod.HistoryEntry) +
            self.mcache.counts.len + self.mcache.generations.len * @sizeOf(u64) + self.mcache.ids.len * @sizeOf(MessageId) + self.mcache.index.slots.len * @sizeOf(u32) +
            self.recovery.memoryBytes() + self.receive_pool.metadataBytes() + (if (self.namespace) |*ns| ns.allocatedBytes() else @as(usize, 0)) +
            self.seen.ids.len * (@sizeOf(MessageId) + @sizeOf(u64)) + self.seen.index.slots.len * @sizeOf(u32) +
            self.scores.topics.len * @sizeOf(@TypeOf(self.scores.topics[0])) + self.scores.app_score.len * @sizeOf(f64) + self.scores.behaviour.len * @sizeOf(f64);
        return .{
            .retained_bytes = self.store.bytes.len,
            .page_count = self.store.next.len,
            .message_entries = self.store.entries.len,
            .validation_capacity = self.validation.entries.len,
            .duplicate_attributions_per_validation = validation_mod.duplicates_max,
            .data_descriptors_per_peer = peer_io_mod.data_capacity,
            .data_descriptors_total = self.io.peers.len * peer_io_mod.data_capacity,
            .legal_atomic_work_bytes = 2 * constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 2 * constants.MAX_PAYLOAD_SIZE,
            .page_bytes = storage.page_bytes,
            .rounding_per_message_max = storage.page_bytes - 1,
            .frame_bytes = self.receive_pool.bytes.len,
            .event_bytes = self.decompressed.len,
            .compression_bytes = self.msg_scratch.len,
            .peer_buffer_bytes = self.io.arena.len,
            .metadata_bytes = metadata,
            .total_bytes = self.store.bytes.len + self.receive_pool.bytes.len + self.decompressed.len + self.msg_scratch.len + self.io.arena.len + metadata,
        };
    }

    pub fn resourceSnapshot(self: *const Gossipsub) ResourceSnapshot {
        var result: ResourceSnapshot = .{
            .connected_capacity = self.state.peers.len,
            .retained_capacity = self.peers.rows.len,
            .validation_capacity = self.validation.entries.len,
            .admitted_peers = 0,
            .remote_subscriptions = 0,
            .mesh_members = 0,
            .queued_descriptors = 0,
            .queued_bytes = 0,
            .held_frames = 0,
            .held_tx_retains = 0,
            .store_entries = self.store.used_entries,
            .store_pages = self.store.next.len - self.store.free_pages,
            .pending_validations = 0,
            .promises = self.recovery.len,
        };
        for (self.state.peers, self.io.peers) |*peer, *io| {
            if (peer.active) result.admitted_peers += 1;
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
        for (self.state.topics) |topic| {
            if (!topic.active) continue;
            for (0..self.state.peers.len) |peer| {
                if (topic.subscribers.isSet(peer)) result.remote_subscriptions += 1;
                if (topic.mesh.isSet(peer)) result.mesh_members += 1;
            }
        }
        for (self.store.entries) |entry| result.held_tx_retains += entry.tx;
        for (self.validation.entries) |entry| {
            if (entry.state == .pending) result.pending_validations += 1;
        }
        return result;
    }

    pub fn connectionActivity(self: *Gossipsub, conn: Handle) void {
        const index = self.state.findPeer(conn) orelse return;
        self.io.peers[index].rx_ready = true;
        self.io.peers[index].tx_ready = true;
    }

    fn wakeStorage(self: *Gossipsub) void {
        for (self.io.peers) |*io| if (io.blocked == .storage) {
            io.rx_ready = true;
        };
    }

    pub fn nextWakeup(self: *const Gossipsub, now: Now, event_capacity: usize) ?u64 {
        if (self.topics_remaining > 0) return now.mono_ms;
        var deadline = if (self.heartbeat_at == 0) now.mono_ms else self.heartbeat_at;
        if (self.validation.nextDeadline()) |d| deadline = @min(deadline, d);
        for (self.io.peers, 0..) |*io, i| {
            if (!self.state.peers[i].active) continue;
            if (self.state.peers[i].in_stream != null and
                ((io.rx_ready and io.blocked != .events) or (io.blocked == .events and event_capacity > 0))) return now.mono_ms;
            if (self.state.peers[i].out_stream != null and io.tx_ready and
                (io.pending() or io.subscription_dirty.count() > 0)) return now.mono_ms;
            if (io.subscription_since) |since| deadline = @min(deadline, since +| self.options.pressure_timeout_ms);
            if (io.pressure_since) |since| deadline = @min(deadline, since +| self.options.pressure_timeout_ms);
            if (io.frame_since) |since| {
                deadline = @min(deadline, since +| self.options.pressure_timeout_ms);
                if (io.pressure_since == null) deadline = @min(deadline, io.progress_ms +| self.options.large_frame_timeout_ms);
            }
            if (io.oldestTx()) |since| {
                deadline = @min(deadline, since +| self.options.tx_timeout_ms);
            }
            if (io.tx_progress_ms) |progress| deadline = @min(deadline, progress +| self.options.large_frame_timeout_ms);
        }
        for (self.mesh_policy.pending_since) |since| if (since) |started| {
            deadline = @min(deadline, started +| self.options.pressure_timeout_ms);
        };
        if (self.recovery.nextExpiry()) |expiry| deadline = @min(deadline, expiry);
        return @max(now.mono_ms, deadline);
    }

    pub fn pump(self: *Gossipsub, engine: *Engine, now: Now, events: []Event) usize {
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
        const free_before = self.store.free_pages;
        self.validation.expire(&self.store, &self.peers, now.mono_ms);
        if (self.store.free_pages != free_before) self.wakeStorage();
        self.expireIo(engine, now.mono_ms);
        self.mesh_policy.expireActions(now.mono_ms, self.options.pressure_timeout_ms);
        var retired = self.mesh_policy.retire.iterator(.{});
        while (retired.next()) |index| {
            const peer: u16 = @intCast(index);
            self.resetInbound(engine, peer);
            self.resetOutbound(engine, peer);
            self.connectionClosed(self.state.peers[peer].conn);
        }
        if (self.heartbeat_at == 0) {
            self.heartbeat_at = now.mono_ms +| self.options.heartbeat_interval_ms;
        } else if (now.mono_ms >= self.heartbeat_at) {
            self.heartbeat(now);
            self.heartbeat_at = now.mono_ms +| self.options.heartbeat_interval_ms;
            self.wakeStorage();
        }
        var count: usize = 0;
        var serviced: usize = 0;
        var first_serviced: ?usize = null;
        for (0..self.io.peers.len) |_| {
            const index = self.peer_cursor;
            self.peer_cursor = (index + 1) % self.io.peers.len;
            if (!self.state.peers[index].active) continue;
            if (first_serviced == null) first_serviced = index;
            const io = &self.io.peers[index];
            io.decompressed_pump = 0;
            io.fields_pump = 0;
            io.calls_pump = self.options.calls_per_peer;
            const write_first = io.write_first;
            if (write_first and io.tx_ready) self.flush(engine, @intCast(index), io, now);
            if (io.rx_ready or (io.blocked == .events and count < events.len)) {
                count = self.readPeer(engine, @intCast(index), io, now, events, count);
            }
            if (!write_first and io.tx_ready) self.flush(engine, @intCast(index), io, now);
            serviced += 1;
            if (serviced == self.options.peers_per_pump) break;
        }
        if (serviced < self.options.peers_per_pump) {
            if (first_serviced) |first| self.peer_cursor = (first + 1) % self.io.peers.len;
        }
        self.maintainTopics(now);
        self.expirePromises(now.mono_ms);
        return count;
    }

    fn expireIo(self: *Gossipsub, engine: *Engine, now_ms: u64) void {
        for (self.io.peers, 0..) |*io, index| {
            if (!self.state.peers[index].active) continue;
            if (io.subscription_since) |since| {
                if (now_ms -| since >= self.options.pressure_timeout_ms) {
                    self.counters.local_pressure_resets += 1;
                    self.resetInbound(engine, @intCast(index));
                    self.resetOutbound(engine, @intCast(index));
                    self.connectionClosed(self.state.peers[index].conn);
                    continue;
                }
            }
            if (io.pressure_since) |since| {
                if (now_ms -| since >= self.options.pressure_timeout_ms) {
                    self.counters.local_pressure_resets += 1;
                    self.resetInbound(engine, @intCast(index));
                }
            }
            if (io.frame_since) |since| {
                if (now_ms -| since >= self.options.pressure_timeout_ms or
                    (io.pressure_since == null and now_ms -| io.progress_ms >= self.options.large_frame_timeout_ms))
                {
                    if (io.pressure_since != null) self.counters.local_pressure_resets += 1 else self.counters.large_stalled += 1;
                    self.resetInbound(engine, @intCast(index));
                }
            }
            if (io.oldestTx()) |since| {
                if (now_ms -| since >= self.options.tx_timeout_ms or
                    (io.tx_progress_ms != null and now_ms -| io.tx_progress_ms.? >= self.options.large_frame_timeout_ms))
                {
                    self.counters.tx_stalled += 1;
                    self.resetOutbound(engine, @intCast(index));
                }
            }
        }
    }

    fn heartbeat(self: *Gossipsub, now: Now) void {
        for (self.io.peers) |*peer_io| peer_io.resetHeartbeat();
        for (self.peers.rows, 0..) |row, i| {
            if (!row.occupied) continue;
            const ref: peers_mod.Ref = .{ .index = @intCast(i), .generation = row.generation };
            self.scores.ip_count[i] = self.peers.ipCount(ref, self.ip_allowlist[0..self.ip_allowlist_len]);
            if (row.connection == null) {
                var useful = self.scores.score(@intCast(i), now.mono_ms) < 0;
                for (self.peers.backoffs[i * constants.topics_cap ..][0..constants.topics_cap]) |entry| {
                    if (now.mono_ms < entry.until) useful = true;
                }
                self.peers.rows[i].negative = useful;
            }
            if (row.connection == null and row.pins == 0 and now.mono_ms >= row.retain_until) {
                self.scores.resetPeer(@intCast(i));
                self.peers.rows[i].occupied = false;
                @memset(self.peers.backoffs[i * constants.topics_cap ..][0..constants.topics_cap], .{});
            }
        }
        self.scores.refresh(now.mono_ms);
        if (self.topics_remaining == 0) {
            const context = self.meshContext(now.mono_ms);
            self.mesh_policy.takeSnapshot(&context);
            self.topics_remaining = constants.topics_cap;
        }
        if (self.opportunistic_at == 0) {
            self.opportunistic_at = now.mono_ms +| self.options.opportunistic_graft_interval_ms;
        } else if (now.mono_ms >= self.opportunistic_at) {
            self.opportunistic_at = now.mono_ms +| self.options.opportunistic_graft_interval_ms;
            self.opportunistic_pending = true;
        }
        self.mcache.shift(&self.store);
    }

    fn maintainTopics(self: *Gossipsub, now: Now) void {
        var serviced: usize = 0;
        for (0..constants.topics_cap) |_| {
            if (self.topics_remaining == 0) {
                self.opportunistic_pending = false;
                return;
            }
            const index: u16 = @intCast(self.topic_cursor);
            self.topic_cursor = (self.topic_cursor + 1) % constants.topics_cap;
            self.topics_remaining -= 1;
            const topic = &self.state.topics[index];
            if (!topic.active) continue;
            var context = self.meshContext(now.mono_ms);
            context.use_snapshot = true;
            if (topic.fanout.count() > 0) _ = self.mesh_policy.fanout(&context, index, false);
            self.maintainTopic(index, now);
            if (self.opportunistic_pending) self.opportunisticGraft(index, now);
            self.emitGossip(index);
            self.reclaimTopic(index);
            serviced += 1;
            if (serviced == self.options.topics_per_pump) return;
        }
    }

    fn opportunisticGraft(self: *Gossipsub, topic: u16, now: Now) void {
        var context = self.meshContext(now.mono_ms);
        context.use_snapshot = true;
        self.mesh_policy.opportunistic(&context, topic);
    }

    fn emitGossip(self: *Gossipsub, topic: u16) void {
        const topic_str = self.state.topicString(topic);
        var ids: [constants.gossip_ids_max]MessageId = undefined;
        const n = self.mcache.gossip(&self.store, topic_str, &ids);
        if (n == 0) return;
        var writer = protobuf.Writer.init(self.msg_scratch);
        writer.varint(protobuf.ihaveRpcSize(topic_str, n, constants.message_id_length));
        protobuf.beginIhaveRpc(&writer, topic_str, n, constants.message_id_length);
        for (ids[0..n]) |id| protobuf.writeIhaveId(&writer, &id);
        const rpc = writer.written();
        var context = self.meshContext(self.last_now_ms);
        context.use_snapshot = true;
        const recipients = self.mesh_policy.gossipRecipients(&context, topic, self.options.gossip_factor);
        var it = recipients.iterator(.{});
        while (it.next()) |peer| {
            if (!self.io.peers[peer].append(rpc, self.last_now_ms)) self.counters.send_dropped += 1;
        }
    }

    fn addPromise(self: *Gossipsub, id: MessageId, index: u16, token: u64) void {
        self.recovery.add(&self.peers, id, self.logical(index), self.state.peers[index].conn, token);
    }

    fn resolvePromises(self: *Gossipsub, id: MessageId) void {
        self.recovery.resolve(&self.peers, id);
    }

    fn cancelPromises(self: *Gossipsub, peer: u16, local_pressure: bool) void {
        const removed = self.recovery.cancel(&self.peers, self.state.peers[peer].conn, local_pressure);
        if (local_pressure) self.counters.promises_cancelled_pressure += removed;
    }

    fn controlSent(self: *Gossipsub, peer: u16, token: u64, now_ms: u64) void {
        self.recovery.controlSent(self.state.peers[peer].conn, token, self.options.iwant_followup_ms, now_ms);
    }

    fn expirePromises(self: *Gossipsub, now_ms: u64) void {
        self.counters.broken_promises += self.recovery.expire(&self.peers, &self.scores, now_ms);
    }

    fn maintainTopic(self: *Gossipsub, topic: u16, now: Now) void {
        var context = self.meshContext(now.mono_ms);
        context.use_snapshot = true;
        self.mesh_policy.maintain(&context, topic);
    }

    fn peerScore(self: *Gossipsub, index: u16, now_ms: u64) f64 {
        const ref = self.logical(index);
        self.scores.ip_count[ref.index] = self.peers.ipCount(ref, self.ip_allowlist[0..self.ip_allowlist_len]);
        return self.scores.score(ref.index, now_ms);
    }

    fn belowGossip(self: *Gossipsub, index: u16, now_ms: u64) bool {
        return self.peerScore(index, now_ms) < self.options.score_params.gossip_threshold;
    }

    /// The host's application-specific P5 term for a peer, from its own signals.
    pub fn setPeerScore(self: *Gossipsub, conn: Handle, value: f64) bool {
        const index = self.state.findPeer(conn) orelse return false;
        return self.scores.setAppScore(self.logical(index).index, value);
    }

    pub fn scoreSnapshot(self: *Gossipsub, conn: Handle, now: Now) ?f64 {
        const index = self.state.findPeer(conn) orelse return null;
        return self.peerScore(index, now.mono_ms);
    }

    pub fn unmarkDirect(self: *Gossipsub, identity: *const @import("../wire/peer_id.zig").PeerId) void {
        const peer = self.peers.find(identity) orelse return;
        self.peers.rows[peer.index].direct = false;
    }

    /// Direct peers receive subscribed publications outside mesh and fanout score gates.
    pub fn markDirect(self: *Gossipsub, conn: Handle) void {
        const index = self.state.findPeer(conn) orelse return;
        self.peers.rows[self.logical(index).index].direct = true;
        const context = self.meshContext(self.last_now_ms);
        for (&self.state.topics, 0..) |*topic, t| {
            if (topic.mesh.isSet(index)) self.mesh_policy.prune(&context, @intCast(t), index, constants.prune_backoff_ms);
            topic.fanout.unset(index);
        }
    }

    fn pressure(self: *Gossipsub, index: u16, reason: @TypeOf(@as(PeerIo, undefined).blocked), now_ms: u64) void {
        const io = &self.io.peers[index];
        if (io.pressure_since == null) io.pressure_since = now_ms;
        io.blocked = reason;
        io.rx_ready = false;
        self.cancelPromises(index, true);
    }

    fn readPeer(self: *Gossipsub, engine: *Engine, index: u16, io: *PeerIo, now: Now, events: []Event, start: usize) usize {
        var count = start;
        const stream = self.state.peers[index].in_stream orelse return count;
        var input: usize = self.options.input_per_peer;
        var items: usize = self.options.items_per_peer;
        io.rx_ready = true;
        io.blocked = .none;
        // A turn consumes at least one item, byte, or transport-call credit per iteration.
        for (0..self.options.items_per_peer + self.options.calls_per_peer + self.options.input_per_peer + 1) |_| {
            if (io.rpc != null) {
                const done = self.processRpc(index, now, events, &count, &items) catch {
                    self.counters.malformed_rpcs += 1;
                    self.resetInbound(engine, index);
                    return count;
                };
                if (!done) return count;
                io.rpc = null;
                io.frame_since = null;
                io.pressure_since = null;
                self.releaseLarge(io);
            }
            if (io.unread_start < io.unread_end) {
                if (input == 0 or self.budget.input == 0) return count;
                const body = self.frameBody(io, now.mono_ms) orelse {
                    self.pressure(index, .storage, now.mono_ms);
                    return count;
                };
                const take = @min(io.unread_end - io.unread_start, input, self.budget.input);
                const result = io.feedUnread(body, take, now.mono_ms) catch {
                    self.counters.malformed_rpcs += 1;
                    self.resetInbound(engine, index);
                    return count;
                };
                input -= result.consumed;
                self.budget.input -= result.consumed;
                if (result.complete) self.counters.rpcs_received += 1;
                continue;
            }
            io.unread_start = 0;
            io.unread_end = 0;
            if (io.fin_seen) {
                self.resetInbound(engine, index);
                return count;
            }
            if (io.calls_pump == 0 or self.budget.calls == 0 or input == 0 or self.budget.input == 0) return count;
            io.calls_pump -= 1;
            io.write_first = true;
            self.budget.calls -= 1;
            const read = engine.read(stream, io.unread[0..@min(io.unread.len, input, self.budget.input)]) catch |err| {
                io.rx_ready = false;
                if (err != error.WouldBlock) self.resetInbound(engine, index);
                return count;
            };
            io.unread_end = read.len;
            io.fin_seen = read.fin;
            if (read.len == 0 and !read.fin) {
                io.rx_ready = false;
                return count;
            }
        }
        return count;
    }

    fn frameBody(self: *Gossipsub, io: *PeerIo, now_ms: u64) ?[]u8 {
        _ = now_ms;
        if (io.large_slot) |lease| return self.receive_pool.buffer(lease).?;
        const declared = io.reader.declaredLen() orelse return io.body;
        if (declared <= io.body.len) return io.body;
        const lease = self.receive_pool.claim() orelse return null;
        io.large_slot = lease;
        return self.receive_pool.buffer(lease).?;
    }

    fn releaseLarge(self: *Gossipsub, peer_io: *PeerIo) void {
        if (peer_io.large_slot) |lease| {
            const released = self.receive_pool.release(lease);
            assert(released);
            peer_io.large_slot = null;
            self.wakeStorage();
        }
    }

    fn processRpc(self: *Gossipsub, index: u16, now: Now, events: []Event, count: *usize, items: *usize) protobuf.Error!bool {
        const io = &self.io.peers[index];
        if (!self.peers.rows[self.logical(index).index].direct and self.peerScore(index, now.mono_ms) < self.options.score_params.graylist_threshold) return true;
        for (0..self.options.items_per_peer) |_| {
            if (items.* == 0 or self.budget.items == 0) return false;
            items.* -= 1;
            self.budget.items -= 1;
            if (io.item == null) {
                const available = @min(self.budget.fields, self.options.fields_per_peer - io.fields_pump);
                var fields = available;
                const step = try io.rpc.?.step(&fields);
                self.budget.fields -= available - fields;
                io.fields_pump += available - fields;
                switch (step) {
                    .item => |item| io.item = item,
                    .end => return true,
                    .deferred => return false,
                    .skipped => continue,
                }
            }
            const item = io.item.?;
            switch (item) {
                .subscription => |sub| {
                    if (io.subscriptions < constants.max_subscriptions_per_rpc) {
                        if (self.validTopic(sub.topic) and self.state.findTopic(sub.topic) != null and (count.* == events.len or self.decompressed.len - self.decompressed_used < sub.topic.len)) {
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
            io.item = null;
            io.pressure_since = null;
        }
        return false;
    }

    fn onMessage(self: *Gossipsub, index: u16, msg: protobuf.Message, now: Now, events: []Event, start: usize) ?usize {
        const context = self.validationContext();
        const workspace: validation_mod.Workspace = .{ .arena = self.decompressed, .used = &self.decompressed_used, .peer_work = &self.io.peers[index].decompressed_pump, .work = &self.budget.work, .large_used = &self.budget.large_used, .event_available = start < events.len };
        switch (self.validation.receive(&context, &workspace, index, msg, now.mono_ms)) {
            .ignored => return start,
            .duplicate => |id| {
                self.counters.duplicates += 1;
                self.resolvePromises(id);
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
                self.resolvePromises(event.id);
                self.counters.messages_received += 1;
                if (msg.data.len >= self.options.idontwant_min_data_size) self.broadcastIdontwant(self.state.findTopic(event.topic).?, event.id, index);
                return start + 1;
            },
        }
    }

    fn onIhave(self: *Gossipsub, index: u16, ihave: protobuf.IHave, now: Now) void {
        if (self.belowGossip(index, now.mono_ms)) return;
        const io = &self.io.peers[index];
        if (io.ihave_recv >= constants.max_ihave_per_heartbeat) return;
        io.ihave_recv += 1;
        const id_budget = constants.max_ihave_ids_per_heartbeat -| @as(usize, io.iwant_ids_sent);
        if (id_budget == 0 or self.recovery.available() == 0) return;
        var wanted: [constants.gossip_ids_max]MessageId = undefined;
        var count: usize = 0;
        var examined: usize = 0;
        var it = ihave.ids();
        while (it.next() catch return) |id_bytes| {
            if (examined == constants.max_ihave_ids_per_heartbeat) break;
            examined += 1;
            if (count == wanted.len or count >= id_budget or count == self.recovery.available()) break;
            if (id_bytes.len != constants.message_id_length) continue;
            const id: MessageId = id_bytes[0..constants.message_id_length].*;
            if (self.seen.contains(id, now.mono_ms) or self.validation.find(id, now.mono_ms) != null) continue;
            wanted[count] = id;
            count += 1;
        }
        if (count == 0) return;
        var writer = protobuf.Writer.init(self.msg_scratch);
        writer.varint(protobuf.iwantRpcSize(count, constants.message_id_length));
        protobuf.beginIwantRpc(&writer, count, constants.message_id_length);
        for (wanted[0..count]) |id| protobuf.writeIwantId(&writer, &id);
        if (io.appendControl(writer.written(), false, now.mono_ms)) |token| {
            for (wanted[0..count]) |id| self.addPromise(id, index, token);
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
            if (self.state.suppresses(index, id, self.last_now_ms)) continue;
            const cached = self.mcache.get(&self.store, id) orelse continue;
            const peer = self.logical(index);
            if (!self.mcache.iwantAllowed(cached, peer, constants.gossip_retransmission)) continue;
            if (self.io.peers[index].queueData(&self.store, cached.message, self.options.tx_peer_bytes, self.last_now_ms) == .queued) {
                self.mcache.sent(cached, peer);
            } else self.counters.send_dropped += 1;
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
        var it = self.state.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            const peer_index: u16 = @intCast(peer);
            if (peer_index == source) continue;
            if (self.state.peerVersion(peer_index) != .v1_2) continue;
            if (!self.io.peers[peer_index].append(rpc, self.last_now_ms)) self.counters.send_dropped += 1;
        }
    }

    fn onIdontwant(self: *Gossipsub, index: u16, idontwant: protobuf.IdList) void {
        const io = &self.io.peers[index];
        if (io.idontwant_recv >= constants.max_idontwant_per_heartbeat) return;
        io.idontwant_recv += 1;
        var examined: usize = 0;
        var it = idontwant.ids();
        while (it.next() catch return) |id_bytes| {
            if (examined >= constants.dont_send_cap) break;
            examined += 1;
            if (id_bytes.len != constants.message_id_length) continue;
            self.state.suppress(index, id_bytes[0..constants.message_id_length].*, self.last_now_ms, constants.mcache_len * self.options.heartbeat_interval_ms);
        }
    }

    fn onGraft(self: *Gossipsub, index: u16, topic_str: []const u8, now: Now) void {
        const topic = self.state.findTopic(topic_str) orelse return;
        _ = self.peerScore(index, now.mono_ms);
        const context = self.meshContext(now.mono_ms);
        self.mesh_policy.onGraft(&context, topic, index);
    }

    fn onPrune(self: *Gossipsub, index: u16, prune: protobuf.Prune, now: Now) void {
        const topic = self.state.findTopic(prune.topic) orelse return;
        const context = self.meshContext(now.mono_ms);
        self.mesh_policy.onPrune(&context, topic, index, if (prune.backoff == 0) constants.prune_backoff_ms else prune.backoff *| 1000);
    }

    fn onSubscription(
        self: *Gossipsub,
        index: u16,
        sub: protobuf.SubOpts,
        events: []Event,
        start: usize,
    ) usize {
        if (self.namespace) |*ns| {
            const match = ns.lookup(sub.topic) orelse return start;
            ns.setSubscription(index, match.ordinal, sub.subscribe);
        }
        const topic = self.state.findTopic(sub.topic) orelse return start;
        assert(start < events.len);
        if (!sub.subscribe and self.state.mesh(topic).isSet(index)) self.scores.prune(self.logical(index).index, topic, self.last_now_ms);
        self.state.setSubscription(topic, index, sub.subscribe);
        const name = self.decompressed[self.decompressed_used..][0..sub.topic.len];
        @memcpy(name, sub.topic);
        self.decompressed_used += name.len;
        events[start] = .{ .subscription_change = .{
            .peer = self.state.peers[index].conn,
            .topic = name,
            .subscribed = sub.subscribe,
        } };
        return start + 1;
    }

    fn flush(self: *Gossipsub, engine: *Engine, index: u16, io: *PeerIo, now: Now) void {
        const stream = self.state.peers[index].out_stream orelse return;
        var bytes = self.options.output_per_peer;
        for (0..self.options.calls_per_peer) |_| {
            self.queueSubscriptions(io);
            const segment = io.segment(&self.store);
            if (segment.len == 0) {
                io.tx_ready = false;
                io.tx_progress_ms = null;
                return;
            }
            if (bytes == 0 or self.budget.output == 0 or io.calls_pump == 0 or self.budget.calls == 0) return;
            const take = @min(bytes, self.budget.output, segment.len);
            io.calls_pump -= 1;
            io.write_first = false;
            self.budget.calls -= 1;
            if (io.tx_progress_ms == null) io.tx_progress_ms = now.mono_ms;
            const written = engine.write(stream, segment[0..take], false) catch |err| {
                io.tx_ready = false;
                if (err != error.WouldBlock) self.resetOutbound(engine, index);
                return;
            };
            if (written == 0) {
                io.tx_ready = false;
                return;
            }
            bytes -= written;
            self.budget.output -= written;
            io.tx_progress_ms = now.mono_ms;
            const free = self.store.free_pages;
            if (io.advance(&self.store, written)) |token| self.controlSent(index, token, now.mono_ms);
            if (self.store.free_pages != free) self.wakeStorage();
        }
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

fn testMessage(g: *Gossipsub, peer: u16, text: []const u8, now_ms: u64, events: []Event) !?usize {
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    var compressed: [256]u8 = undefined;
    const n = try snappy.raw.compress(text, &compressed);
    g.budget = .{ .work = g.options.work_per_pump };
    g.io.peers[peer].decompressed_pump = 0;
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
        g.mcache.shift(&g.store);
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
    const retained = g.mcache.get(&g.store, useful).?.message;
    var events: [1]Event = undefined;
    for (0..20) |_| {
        try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "useful", 2, &events));
        _ = g.onMessage(peer.index, .{ .topic = topic, .data = &.{ 5, 0 } }, .{ .mono_ms = 2, .unix_s = 1 }, &events, 0);
        try std.testing.expectEqual(retained, g.mcache.get(&g.store, useful).?.message);
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
    try std.testing.expect(g.io.peers[peer.index].append(&([_]u8{0} ** 64), 1));
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    g.io.peers[peer.index].resetTx(&g.store);
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 2, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    g.expirePromises(10_000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    const io = &g.io.peers[peer.index];
    const first = io.segment(&g.store);
    _ = io.advance(&g.store, 1);
    try std.testing.expect(g.recovery.promises[0].expiry == null);
    const token = io.advance(&g.store, first.len - 1).?;
    g.controlSent(peer.index, token, 10_000);
    try std.testing.expectEqual(@as(?u64, 13_000), g.recovery.promises[0].expiry);
    var empty: [0]Event = .{};
    try std.testing.expectEqual(@as(?usize, null), try testMessage(&g, peer.index, "held behind host pressure", 11_000, &empty));
    g.expirePromises(14_000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u64, 1), g.counters.promises_cancelled_pressure);
    g.io.peers[peer.index].resetHeartbeat();
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 14_000, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    _ = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 2 }, .v1_2).?;
    g.expirePromises(20_000);
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
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
    try std.testing.expectEqual(g.store.bytes.len, plan.retained_bytes);
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
    const destination = setup.server.state.findPeer(setup.handles.server).?;
    const source = @import("test_support.zig").addPeer(&setup.server, .{ .index = 77, .generation = 1 }, .v1_2).?;
    setup.server.state.mesh(setup.server.state.findTopic(topic).?).set(destination);
    const payload = try std.testing.allocator.alloc(u8, constants.MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(91);
    rng.random().bytes(payload);
    _ = setup.server.pump(&setup.pair.server, setup.pair.now, &.{});
    const len = try snappy.raw.compress(payload, setup.server.msg_scratch);
    setup.server.budget = .{ .work = setup.server.options.work_per_pump };
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), setup.server.onMessage(source.index, .{ .topic = topic, .data = setup.server.msg_scratch[0..len] }, setup.pair.now, &events, 0));
    const handle = events[0].message.handle;
    const message = setup.server.validation.entries[handle.index].message;
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, setup.server.report(handle, .accept, setup.pair.now));
    try std.testing.expectEqual(@as(u32, 1), setup.server.store.get(message).?.tx);
    for (0..constants.mcache_len) |_| setup.server.mcache.shift(&setup.server.store);
    try std.testing.expect(!setup.server.store.get(message).?.history);
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
    try std.testing.expect(setup.server.store.get(message) == null);
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
    g.setStreams(first.index, null, stream1);
    g.setStreams(second.index, null, stream2);
    g.io.peers[first.index].rpc = protobuf.RpcReader.init(w1.written());
    g.io.peers[second.index].rpc = protobuf.RpcReader.init(w2.written());
    var events: [2]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), g.pump(&pair.server, pair.now, &events));
    try std.testing.expectEqualStrings("one", events[0].message.bytes);
    g.setStreams(first.index, null, stream1);
    g.io.peers[first.index].rx_ready = true;
    g.io.peers[first.index].rpc = protobuf.RpcReader.init(w1.written());
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), g.nextWakeup(pair.now, 2));
    try std.testing.expectEqual(@as(usize, 1), g.pump(&pair.server, pair.now, &events));
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
    try std.testing.expectEqual(@as(f64, 0), g.scores.score(g.logical(replacement1.index).index, 3));
    try std.testing.expectEqual(@as(f64, 0), g.scores.score(g.logical(replacement2.index).index, 3));
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
    g.scores.penalize(original.index, 20);
    const topic_name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic_name));
    const topic = g.state.findTopic(topic_name).?;
    const topic_generation = g.state.topics[topic].generation;
    g.peers.addBackoff(original, topic, topic_generation, 1, 60_000);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    const second = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2, &metadata, now).admitted;
    try std.testing.expectEqual(original, g.logical(second.index));
    try std.testing.expect(g.peers.backedOff(original, topic, topic_generation, 60_000));
    try std.testing.expect(!g.peers.backedOff(original, topic, topic_generation, 60_001));
    try std.testing.expect(g.scores.score(g.logical(second.index).index, 1) < 0);
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
    const topic = g.state.findTopic(topic_str).?;
    try std.testing.expect(g.setPeerScore(conn, -1));
    g.onGraft(peer.index, topic_str, .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.state.mesh(topic).count());
    try std.testing.expect(g.setPeerScore(conn, 0));
    g.markDirect(conn);
    g.state.setSubscription(topic, peer.index, true);
    g.maintainTopic(topic, .{ .mono_ms = 100_000, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.state.mesh(topic).count());
}

test "gossip policy combined transport calls respect one shared peer allowance" {
    var setup: @import("gossipsub_test.zig").GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const peer = setup.client.state.findPeer(setup.handles.client).?;
    setup.client.options.calls_per_peer = 1;
    var events: [1]Event = undefined;
    for ([_]usize{ 8, 1 }) |global| {
        setup.client.options.calls_per_pump = global;
        var read_turns: usize = 0;
        var write_turns: usize = 0;
        for (0..8) |_| {
            try std.testing.expect(setup.client.io.peers[peer].append(&.{0}, setup.pair.now.mono_ms));
            setup.client.connectionActivity(setup.handles.client);
            _ = setup.client.pump(&setup.pair.client, setup.pair.now, &events);
            const calls = global - setup.client.budget.calls;
            try std.testing.expect(calls <= 1);
            if (calls > 0) {
                if (setup.client.budget.output < setup.client.options.output_per_pump) write_turns += 1 else read_turns += 1;
            }
        }
        try std.testing.expect(read_turns > 0 and write_turns > 0);
        for (0..32) |_| {
            if (setup.client.nextWakeup(setup.pair.now, events.len).? > setup.pair.now.mono_ms) break;
            _ = setup.client.pump(&setup.pair.client, setup.pair.now, &events);
            try std.testing.expect(global - setup.client.budget.calls <= 1);
        }
        try std.testing.expect(!setup.client.io.peers[peer].pending());
        try std.testing.expect(setup.client.nextWakeup(setup.pair.now, events.len).? > setup.pair.now.mono_ms);
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
    try std.testing.expectEqual(@as(?u64, 3010), g.recovery.promises[0].expiry);
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
    try std.testing.expectEqual(@as(?u16, first.index), g.state.findPeer(conn));
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    g.state.setSubscription(g.state.findTopic(topic).?, first.index, true);
    g.markDirect(conn);
    try std.testing.expect(g.setPeerScore(conn, -100_000));
    g.state.peers[first.index].out_stream = .{ .conn = conn, .id = 2, .slot = 0 };
    const result = try g.publish(topic, "direct data", now);
    try std.testing.expectEqual(@as(u16, 1), result.queued);
    try std.testing.expectEqual(@as(usize, 0), g.state.mesh(g.state.findTopic(topic).?).count());
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
    const topic = g.state.findTopic(name).?;
    const generation = g.state.topics[topic].generation;
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
    try std.testing.expect(g.state.topics[topic].active);
    _ = g.report(event.handle, .ignore, .{ .mono_ms = 2, .unix_s = 0 });
    g.validation.expire(&g.store, &g.peers, 30_002);
    g.last_now_ms = 30_002;
    g.reclaimTopic(topic);
    try std.testing.expect(!g.state.topics[topic].active);
    const next_name = "/eth2/02030405/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(next_name));
    try std.testing.expectEqual(@as(?u16, topic), g.state.findTopic(next_name));
    try std.testing.expect(g.state.topics[topic].generation > generation);
    try std.testing.expectEqualStrings(name, event.topic);
    try std.testing.expectEqualStrings("retained", event.bytes);
}

test "gossip policy topic retirement bounds arbitrarily slow active score decay" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .retained_score_ms = 10, .score_params = .{ .decay_interval_ms = 1, .topic = .{ .first_delivery_decay = 0.999999999999 } } });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const topic = g.state.findTopic(name).?;
    g.scores.deliver(g.logical(peer.index).index, topic);
    try std.testing.expect(g.unsubscribe(name));
    g.queueSubscriptions(&g.io.peers[peer.index]);
    g.last_now_ms = 11;
    g.scores.refresh(11);
    g.reclaimTopic(topic);
    try std.testing.expect(!g.state.topics[topic].active);
    try std.testing.expectEqual(@as(f64, 0), g.scores.score(g.logical(peer.index).index, 11));
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
    _ = g.pump(&pair.server, .{ .mono_ms = 11, .unix_s = 0 }, &events);
    try std.testing.expect(g.state.findPeer(conn) == null);
    const topic = g.state.findTopic(name).?;
    g.reclaimTopic(topic);
    try std.testing.expect(!g.state.topics[topic].active);
}

test "gossip policy subscription retry preserves its first pressure deadline" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try std.testing.expect(g.subscribe("/eth2/01020304/beacon_block/ssz_snappy"));
    g.last_now_ms = 1;
    g.sendSubscriptions(peer.index);
    try std.testing.expectEqual(@as(?u64, 0), g.io.peers[peer.index].subscription_since);
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
        g.state.setSubscription(first, peer.index, true);
        g.state.setSubscription(second, peer.index, true);
        g.state.peers[peer.index].out_stream = .{ .conn = g.state.peers[peer.index].conn, .id = 2, .slot = 0 };
    }
    const start: Now = .{ .mono_ms = 1, .unix_s = 0 };
    _ = try g.publish(first_name, "first", start);
    _ = try g.publish(second_name, "second", start);
    g.heartbeat(start);
    g.maintainTopics(start);
    try std.testing.expectEqual(@as(usize, 1), g.topic_cursor);
    const retained = g.state.fanout(second).findFirstSet().?;
    var advertised: u16 = 0;
    for (0..9) |i| if (!g.state.fanout(second).isSet(i)) {
        advertised = @intCast(i);
    };
    try std.testing.expect(g.scores.setAppScore(g.logical(@intCast(retained)).index, -10_000));
    try std.testing.expect(g.scores.setAppScore(g.logical(advertised).index, -10_000));
    for (g.io.peers) |*io| io.resetTx(&g.store);
    g.last_now_ms = 2;
    g.maintainTopics(.{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expect(g.state.fanout(second).isSet(retained));
    try std.testing.expectEqual(@as(usize, 8), g.state.fanout(second).count());
    try std.testing.expectEqual(@as(usize, 1), g.io.peers[advertised].control.count);
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[retained].control.count);
    g.maintainTopics(.{ .mono_ms = 3, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.topics_remaining);
    for (g.io.peers) |*io| io.resetTx(&g.store);
    g.last_now_ms = 701;
    g.heartbeat(.{ .mono_ms = 701, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 701, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 702, .unix_s = 0 });
    try std.testing.expect(!g.state.fanout(second).isSet(retained));
    try std.testing.expectEqual(@as(usize, 7), g.state.fanout(second).count());
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[advertised].control.count);
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[retained].control.count);
    const live = g.state.fanout(second).findFirstSet().?;
    try std.testing.expect(g.scores.setAppScore(g.logical(@intCast(live)).index, -10_000));
    _ = try g.publish(second_name, "live publish", .{ .mono_ms = 703, .unix_s = 0 });
    try std.testing.expect(!g.state.fanout(second).isSet(live));
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
        g.validation.expire(&g.store, &g.peers, now.mono_ms);
        g.decompressed_used = 0;
        g.budget = .{ .items = 128, .fields = 131072, .work = 1024 * 1024 };
        const io = &g.io.peers[peer.index];
        io.resetRx();
        io.fields_pump = 0;
        io.decompressed_pump = 0;
        var events: [2]Event = undefined;
        var count: usize = 0;
        var consumed: usize = 0;
        var items: usize = 128;
        for ([_][]const u8{ wire[0..split], wire[split..] }) |fragment| {
            try std.testing.expect(g.receiveHandoff(peer.index, fragment, false));
            for (0..wire.len + 1) |_| {
                if (io.unread_start == io.unread_end) break;
                const result = try io.feedUnread(io.body, io.unread_end - io.unread_start, now.mono_ms);
                try std.testing.expect(result.consumed > 0);
                consumed += result.consumed;
                if (result.complete) {
                    try std.testing.expect(try g.processRpc(peer.index, now, &events, &count, &items));
                    try std.testing.expect(try g.processRpc(peer.index, now, &events, &count, &items));
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
    const message = g.store.put(id, "t", "payload").?;
    g.mcache.put(&g.store, message);
    g.store.seal(message);
    var bytes: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.beginIwantRpc(&writer, 1, id.len);
    protobuf.writeIwantId(&writer, &id);
    var reader = protobuf.RpcReader.init(writer.written());
    const iwant = (try reader.next()).?.iwant;
    for (0..peer_io_mod.data_capacity) |_| {
        try std.testing.expectEqual(peer_io_mod.QueueResult.queued, g.io.peers[first.index].queueData(&g.store, message, g.options.tx_peer_bytes, 1));
    }
    g.onIwant(first.index, iwant);
    try std.testing.expectEqual(@as(u8, 0), g.mcache.get(&g.store, id).?.counts[logical_peer.index]);
    try std.testing.expectEqual(@as(u64, 1), g.counters.send_dropped);
    g.io.peers[first.index].resetTx(&g.store);
    for (0..4) |_| g.onIwant(first.index, iwant);
    try std.testing.expectEqual(@as(usize, 3), g.io.peers[first.index].data_count);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    const second = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2, &metadata, now).admitted;
    try std.testing.expectEqual(logical_peer, g.logical(second.index));
    g.onIwant(second.index, iwant);
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[second.index].data_count);
    g.connectionClosed(.{ .index = 0, .generation = 2 });
    const expired: Now = .{ .mono_ms = g.peers.retention_ms + 2, .unix_s = 0 };
    const third = g.addPeer(.{ .index = 0, .generation = 3 }, .v1_2, &metadata, expired).admitted;
    try std.testing.expectEqual(logical_peer.index, g.logical(third.index).index);
    try std.testing.expect(g.logical(third.index).generation > logical_peer.generation);
    for (0..4) |_| g.onIwant(third.index, iwant);
    try std.testing.expectEqual(@as(usize, 3), g.io.peers[third.index].data_count);
}

test "gossip resolved capacities allocate owner rows and reject stale ceiling handles" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    try std.testing.expectEqual(@as(usize, 2), g.state.peers.len);
    try std.testing.expectEqual(@as(usize, 2), g.io.peers.len);
    try std.testing.expectEqual(@as(usize, 4), g.peers.rows.len);
    try std.testing.expectEqual(@as(usize, 4), g.scores.app_score.len);
    try std.testing.expect(!g.state.peerMatches(2, 0));
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
    const first = g.state.topicString(0);
    try std.testing.expect(g.unsubscribe(first));
    g.scores.invalid(0, 0);
    g.last_now_ms = g.state.topics[0].retire_after_ms.?;
    g.peers.backoffs[0] = .{ .topic_generation = g.state.topics[0].generation, .until = g.last_now_ms + 100 };
    const revision = g.scores.revision;
    const generation = g.state.topics[0].generation;
    const score = g.scores.topics[0];
    const old_scores = try std.testing.allocator.dupe(@TypeOf(score), g.scores.topics);
    defer std.testing.allocator.free(old_scores);
    const old_topics = try std.testing.allocator.dupe(@TypeOf(g.state.topics[0]), &g.state.topics);
    defer std.testing.allocator.free(old_topics);
    const old_backoffs = try std.testing.allocator.dupe(@TypeOf(g.peers.backoffs[0]), g.peers.backoffs);
    defer std.testing.allocator.free(old_backoffs);
    const old_params = g.scores.topic_params;
    const old_dirty = g.scores.dirty;
    try std.testing.expectError(error.TopicCapacity, g.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{}));
    try std.testing.expectEqualDeep(old_scores, g.scores.topics);
    try std.testing.expectEqualDeep(old_backoffs, g.peers.backoffs);
    try std.testing.expectEqualDeep(old_params, g.scores.topic_params);
    try std.testing.expectEqualDeep(old_dirty, g.scores.dirty);
    for (old_topics, &g.state.topics) |*before, *after| {
        try std.testing.expectEqual(before.active, after.active);
        try std.testing.expectEqual(before.generation, after.generation);
        try std.testing.expectEqual(before.subscribed, after.subscribed);
        try std.testing.expectEqual(before.retire_after_ms, after.retire_after_ms);
        try std.testing.expectEqualDeep(before.subscribers, after.subscribers);
        try std.testing.expectEqualDeep(before.mesh, after.mesh);
        try std.testing.expectEqualDeep(before.fanout, after.fanout);
        try std.testing.expectEqualStrings(before.string[0..before.string_len], after.string[0..after.string_len]);
    }
    try std.testing.expectEqual(revision, g.scores.revision);
    try std.testing.expectEqual(generation, g.state.topics[0].generation);
    try std.testing.expect(g.state.topics[0].active);
    try std.testing.expectError(error.InvalidTopic, g.configureTopic("invalid", &.{}));
    try std.testing.expectEqualDeep(score, g.scores.topics[0]);
    try std.testing.expectEqual(revision, g.scores.revision);
    g.last_now_ms += 100;
    g.state.topics[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.TopicCapacity, g.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{}));
    try std.testing.expectEqualDeep(score, g.scores.topics[0]);
    g.state.topics[0].generation = generation;
    try g.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{ .weight = 2 });
    try std.testing.expectEqual(generation + 1, g.state.topics[0].generation);
    try std.testing.expect(!g.scores.retainsTopic(0));
    try std.testing.expectEqual(@as(f64, 2), g.scores.topic_params[0].weight);
}

test "gossip diagnostics tracks queued age and preserves peaks after owner release" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const calls = ledger.allocation_calls;
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const io = &g.io.peers[peer.index];
    io.resetTx(&g.store);
    const message = g.store.put([_]u8{1} ** 20, "t", "abc").?;
    g.store.retainHistory(message);
    g.store.seal(message);
    try std.testing.expectEqual(peer_io_mod.QueueResult.queued, io.queueData(&g.store, message, 10, 7));
    try std.testing.expect(io.appendControl("ctrl", true, 9) != null);
    g.last_now_ms = 20;
    const snapshot = g.resourceSnapshot();
    try std.testing.expectEqual(@as(?u64, 13), snapshot.oldest_tx_age_ms);
    try std.testing.expectEqual(@as(usize, 3), snapshot.queued_bytes);
    try std.testing.expectEqual(@as(usize, 3), snapshot.data_bytes_per_row_high_water);
    try std.testing.expectEqual(@as(usize, 4), snapshot.critical_bytes);
    try std.testing.expectEqual(@as(usize, 1), snapshot.held_tx_retains);
    try std.testing.expectEqualDeep(snapshot, g.resourceSnapshot());
    g.connectionClosed(conn);
    g.store.releaseHistory(message);
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
    g.scores.invalid(0, 0);
    try std.testing.expect(g.unsubscribe(name));
    g.last_now_ms = g.state.topics[0].retire_after_ms.?;
    const generation = g.state.topics[0].generation;
    g.peers.backoffs[0] = .{ .topic_generation = generation, .until = g.last_now_ms + 100 };
    g.reclaimTopic(0);
    try std.testing.expect(!g.scores.retainsTopic(0));
    try std.testing.expect(g.state.topics[0].active);
    try std.testing.expectEqual(generation, g.state.topics[0].generation);
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
        try g.configureTopic(g.state.topicString(@intCast(source)), &.{ .weight = 2 });
        const expected = g.scores.topic_params[source];
        try std.testing.expect(g.unsubscribe(g.state.topicString(0)));
        try std.testing.expect(g.unsubscribe(g.state.topicString(1)));
        const generation = g.state.topics[0].generation;
        const replacement = "/eth2/ffffffff/custom/ssz_snappy";
        try g.configureTopic(replacement, &g.scores.topic_params[source]);
        try std.testing.expectEqual(@as(?u16, 0), g.state.findTopic(replacement));
        try std.testing.expectEqual(generation + 1, g.state.topics[0].generation);
        try std.testing.expectEqualDeep(expected, g.scores.topic_params[0]);
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
    const input = g.state.topicString(0)[0..shorter.len];
    try std.testing.expect(g.unsubscribe(g.state.topicString(0)));
    const generation = g.state.topics[0].generation;
    try g.configureTopic(input, &.{ .weight = 2 });
    try std.testing.expectEqualStrings(shorter, g.state.topicString(0));
    try std.testing.expectEqual(generation + 1, g.state.topics[0].generation);
    try std.testing.expectEqual(@as(f64, 2), g.scores.topic_params[0].weight);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
}

test "gossipsub configured IWANT receipt starts twelve second deadline once" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .iwant_followup_ms = 12_000 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const p = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const io = &g.io.peers[p.index];
    const token = io.appendControl("control", false, 1).?;
    g.recovery.add(&g.peers, [_]u8{1} ** 20, g.logical(p.index), conn, token);
    g.recovery.controlSent(.{ .index = 0, .generation = 2 }, token, 12_000, 5);
    g.controlSent(p.index, token + 1, 5);
    try std.testing.expect(g.recovery.nextExpiry() == null);
    _ = io.segment(&g.store);
    try std.testing.expect(io.advance(&g.store, 1) == null);
    try std.testing.expect(g.recovery.nextExpiry() == null);
    g.controlSent(p.index, io.advance(&g.store, 6).?, 100);
    g.controlSent(p.index, token, 200);
    try std.testing.expectEqual(@as(?u64, 12_100), g.recovery.nextExpiry());
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
    g.state.mesh(g.state.findTopic(name).?).set(destination.index);
    var payload: [126]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);
    var compressed: [constants.maxCompressedLen(256)]u8 = undefined;
    var events: [1]Event = undefined;
    for ([_]usize{ 124, 125, 126 }, [_]usize{ 127, 128, 129 }) |size, wire_size| {
        g.io.peers[destination.index].resetTx(&g.store);
        const len = try snappy.raw.compress(payload[0..size], &compressed);
        try std.testing.expectEqual(wire_size, len);
        g.budget = .{ .work = g.options.work_per_pump };
        try std.testing.expectEqual(@as(?usize, 1), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
        try std.testing.expectEqual(wire_size >= 128, g.io.peers[destination.index].control.used > 0);
        g.io.peers[destination.index].resetTx(&g.store);
        try std.testing.expectEqual(@as(?usize, 0), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
        try std.testing.expectEqual(@as(usize, 0), g.io.peers[destination.index].control.used);
    }
    const len = try snappy.raw.compress(&([_]u8{0} ** 256), &compressed);
    try std.testing.expect(len < 128);
    try std.testing.expectEqual(@as(?usize, 1), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[destination.index].control.used);
    _ = g.onMessage(source.index, .{ .topic = name, .data = &.{ 5, 0 } }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0);
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[destination.index].control.used);
    const fresh_len = try snappy.raw.compress("nonadmitted", &compressed);
    g.options.idontwant_min_data_size = 0;
    try std.testing.expectEqual(@as(?usize, null), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..fresh_len] }, .{ .mono_ms = 1, .unix_s = 0 }, &.{}, 0));
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[destination.index].control.used);
    try std.testing.expectEqual(@as(?usize, 1), g.onMessage(source.index, .{ .topic = name, .data = compressed[0..fresh_len] }, .{ .mono_ms = 1, .unix_s = 0 }, &events, 0));
    try std.testing.expect(g.io.peers[destination.index].control.used > 0);
}

test "gossipsub remote forwarding honors IDONTWANT and preserves borrowed event through local publication" {
    var pair: @import("gossipsub_test.zig").GossipPair = .{};
    try pair.init();
    defer pair.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(pair.client.subscribe(name));
    try std.testing.expect(pair.server.subscribe(name));
    for (0..20) |_| try pair.pumpOnce();
    const destination = pair.server.state.findPeer(pair.handles.server).?;
    const source = @import("test_support.zig").addPeer(&pair.server, .{ .index = 77, .generation = 1 }, .v1_2).?;
    pair.server.state.mesh(pair.server.state.findTopic(name).?).set(destination);
    const suppressed_id = topic_mod.validMessageId(name, "remote suppressed", .{});
    pair.server.state.suppress(destination, suppressed_id, pair.pair.now.mono_ms, 60_000);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&pair.server, source.index, "remote suppressed", pair.pair.now.mono_ms, &events));
    const borrowed = events[0].message;
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, pair.server.report(borrowed.handle, .accept, pair.pair.now));
    try std.testing.expectEqual(@as(usize, 0), pair.server.io.peers[destination].data_count);
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
    try std.testing.expectEqual(@as(usize, 1), pair.server.io.peers[destination].data_count);
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
    const t = g.state.findTopic(name).?;
    g.state.setSubscription(t, p.index, true);
    g.state.peers[p.index].out_stream = .{ .conn = conn, .id = 2, .slot = 0 };
    _ = try g.publish(name, "fanout expiry", .{ .mono_ms = 0, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.state.fanout(t).count());
    g.heartbeat(.{ .mono_ms = 59_999, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 59_999, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.state.fanout(t).count());
    g.heartbeat(.{ .mono_ms = 60_000, .unix_s = 0 });
    g.maintainTopics(.{ .mono_ms = 60_000, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.state.fanout(t).count());
    g.state.setSubscription(t, p.index, false);
    g.io.peers[p.index].resetTx(&g.store);
    const next_conn: Handle = .{ .index = 1, .generation = 1 };
    const next = @import("test_support.zig").addPeer(&g, next_conn, .v1_2).?;
    g.state.setSubscription(t, next.index, true);
    g.state.peers[next.index].out_stream = .{ .conn = next_conn, .id = 2, .slot = 0 };
    const result = try g.publish(name, "fresh fanout", .{ .mono_ms = 60_001, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, result);
    try std.testing.expectEqual(@as(usize, 1), g.state.fanout(t).count());
    try std.testing.expect(g.state.fanout(t).isSet(next.index));
    try std.testing.expectEqual(@as(usize, 0), g.io.peers[p.index].data_count);
    const queued = g.io.peers[next.index].data[g.io.peers[next.index].data_head].message;
    try std.testing.expectEqual(topic_mod.validMessageId(name, "fresh fanout", .{}), g.store.get(queued).?.id);
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
    for (g.state.topics[1..]) |*row| row.generation = std.math.maxInt(u64);
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    _ = try g.publish(name, "original payload", now);
    const id = topic_mod.validMessageId(name, "original payload", .{});
    const message = g.mcache.get(&g.store, id).?.message;
    try std.testing.expect(try g.prepareSubscriptions(&.{.{ .name = replacement, .params = .{} }}, workspace, now));
    g.commitSubscriptions(workspace);
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    var request: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&request);
    protobuf.beginIwantRpc(&writer, 1, id.len);
    protobuf.writeIwantId(&writer, &id);
    var reader = protobuf.RpcReader.init(writer.written());
    g.onIwant(peer.index, (try reader.next()).?.iwant);
    const io = &g.io.peers[peer.index];
    try std.testing.expectEqual(@as(usize, 1), io.data_count);
    try std.testing.expectEqual(message, io.data[io.data_head].message);
    try std.testing.expectEqual(@as(u8, 1), g.mcache.get(&g.store, id).?.counts[g.logical(peer.index).index]);
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    for (0..8) |_| {
        const segment = io.segment(&g.store);
        if (segment.len == 0) break;
        try std.testing.expect(used + segment.len <= wire.len);
        @memcpy(wire[used..][0..segment.len], segment);
        used += segment.len;
        _ = io.advance(&g.store, segment.len);
    }
    try std.testing.expectEqual(@as(usize, 0), io.data_count);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..used], name) != null);
    var decompressed: [64]u8 = undefined;
    const size = try snappy.raw.uncompress(g.store.segment(message, g.store.cursor(message)), &decompressed);
    try std.testing.expectEqualStrings("original payload", decompressed[0..size]);
    try std.testing.expectEqualStrings(replacement, g.state.topicString(0));
}
