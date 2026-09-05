const std = @import("std");
const snappy = @import("snappy");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const topic_mod = @import("topic.zig");
const mcache_mod = @import("mcache.zig");
const storage = @import("message_store.zig");
const validation_mod = @import("validation.zig");
const peer_io_mod = @import("peer_io.zig");
const score_mod = @import("score.zig");
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

pub const InitError = Allocator.Error || error{InvalidLimits};

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
    message: struct { handle: ValidationHandle, id: MessageId, peer: Handle, topic: []const u8, bytes: []const u8 },
    subscription_change: struct { peer: Handle, topic: []const u8, subscribed: bool },
};

const sub_frame_max = 16 + topic_mod.topic_max_len;
const control_frame_max = 32 + topic_mod.topic_max_len;
const PeerIo = peer_io_mod.PeerIo;
const Promise = struct {
    id: MessageId,
    peer: validation_mod.PeerRef,
    token: u64,
    expiry: ?u64 = null,
};
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

pub const Gossipsub = struct {
    allocator: Allocator,
    options: Options,
    state: *State,
    scores: score_mod.PeerScore,
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
    large_pool: []u8,
    large_used: []bool,
    direct: state_mod.PeerSet = state_mod.PeerSet.initEmpty(),
    heartbeat_at: u64 = 0,
    opportunistic_at: u64 = 0,
    last_now_ms: u64 = 0,
    msg_scratch: []u8,
    decompressed: []u8,
    decompressed_used: usize = 0,
    promises: []Promise,
    promise_len: usize = 0,
    rng: std.Random.DefaultPrng,
    counters: Counters = .{},

    pub const Counters = struct {
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
        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.* = .{};

        var scores = try score_mod.PeerScore.init(allocator, options.score_params);
        errdefer scores.deinit(allocator);

        var seen = try mcache_mod.SeenCache.init(
            allocator,
            options.seen_capacity,
            options.seen_ttl_ms,
        );
        errdefer seen.deinit(allocator);
        var mcache = try mcache_mod.History.init(allocator, options.mcache_capacity);
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
        const promises = try allocator.alloc(Promise, constants.promises_cap);
        errdefer allocator.free(promises);
        const pool_bytes = options.large_pool_count * options.large_message_bytes;
        const large_pool = try allocator.alloc(u8, pool_bytes);
        errdefer allocator.free(large_pool);
        const large_used = try allocator.alloc(bool, options.large_pool_count);
        errdefer allocator.free(large_used);
        @memset(large_used, false);

        return .{
            .allocator = allocator,
            .options = options,
            .state = state,
            .scores = scores,
            .seen = seen,
            .mcache = mcache,
            .store = store,
            .validation = validation,
            .io = io,
            .large_pool = large_pool,
            .large_used = large_used,
            .msg_scratch = msg_scratch,
            .decompressed = decompressed,
            .promises = promises,
            .rng = std.Random.DefaultPrng.init(options.random_seed),
        };
    }

    pub fn deinit(self: *Gossipsub) void {
        self.allocator.free(self.large_used);
        self.allocator.free(self.large_pool);
        self.allocator.free(self.promises);
        self.allocator.free(self.decompressed);
        self.allocator.free(self.msg_scratch);
        self.io.deinit(self.allocator);
        self.mcache.deinit(self.allocator);
        self.validation.deinit(self.allocator);
        self.store.deinit(self.allocator);
        self.seen.deinit(self.allocator);
        self.scores.deinit(self.allocator);
        self.allocator.destroy(self.state);
        self.* = undefined;
    }

    // Subscriptions ----------------------------------------------------------

    pub fn subscribe(self: *Gossipsub, topic_str: []const u8) bool {
        const topic = self.state.internTopic(topic_str) orelse return false;
        if (self.state.subscribed(topic)) return true;
        self.state.setSubscribed(topic, true);
        self.announce(topic_str, true);
        return true;
    }

    pub fn unsubscribe(self: *Gossipsub, topic_str: []const u8) bool {
        const topic = self.state.findTopic(topic_str) orelse return false;
        if (!self.state.subscribed(topic)) return true;
        self.leaveMesh(topic, topic_str);
        self.state.setSubscribed(topic, false);
        self.announce(topic_str, false);
        return true;
    }

    /// Leaving a topic: PRUNE every mesh peer with the shorter unsubscribe
    /// backoff, then clear the mesh so a later re-subscribe starts fresh.
    fn leaveMesh(self: *Gossipsub, topic: u16, topic_str: []const u8) void {
        const now_ms = self.last_now_ms;
        const backoff_s = constants.unsubscribe_backoff_ms / 1000;
        var it = self.state.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            const index: u16 = @intCast(peer);
            self.scores.prune(index, topic, now_ms);
            self.state.addBackoff(index, topic, now_ms +| constants.unsubscribe_backoff_ms);
            _ = self.queuePrune(index, topic_str, backoff_s);
        }
        self.state.mesh(topic).* = state_mod.PeerSet.initEmpty();
    }

    fn announce(self: *Gossipsub, topic_str: []const u8, subscribe_flag: bool) void {
        _ = subscribe_flag;
        const topic = self.state.findTopic(topic_str).?;
        for (self.io.peers, 0..) |*io, index| {
            if (!self.state.peers[index].active) continue;
            io.subscription_dirty.set(topic);
            io.tx_ready = true;
        }
    }

    // Peer lifecycle ---------------------------------------------------------

    pub fn addPeer(self: *Gossipsub, conn: Handle, version: Version) ?state_mod.PeerHandle {
        const handle = self.state.addPeer(conn, version) orelse return null;
        self.scores.resetPeer(handle.index);
        self.io.peers[handle.index].resetTx(&self.store);
        self.io.peers[handle.index].resetRx();
        self.io.peers[handle.index].resetHeartbeat();
        self.sendSubscriptions(handle.index);
        return handle;
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
        self.direct.unset(index);
        self.state.removePeer(index);
    }

    fn sendSubscriptions(self: *Gossipsub, index: u16) void {
        const io = &self.io.peers[index];
        io.subscription_dirty = .initEmpty();
        for (&self.state.topics, 0..) |*topic, t| {
            if (topic.active and topic.subscribed) io.subscription_dirty.set(t);
        }
        io.tx_ready = true;
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
    }

    pub const PublishError = error{ PayloadTooLarge, UnknownTopic, CompressFailed, ResourceExhausted };
    pub const PublishOutcome = struct { queued: u16 = 0, pressured: u16 = 0 };

    /// Admits local history and reports queued and pressured recipient counts. Zero recipients is a local publish.
    pub fn publish(self: *Gossipsub, topic_str: []const u8, ssz: []const u8, now: Now) PublishError!PublishOutcome {
        if (ssz.len > constants.MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;
        const topic = self.state.internTopic(topic_str) orelse return error.UnknownTopic;
        const clen = snappy.raw.compress(ssz, self.msg_scratch) catch return error.CompressFailed;
        const id = topic_mod.validMessageId(topic_str, ssz, self.options.message_id_policy);
        const h = self.storeMessage(id, topic_str, self.msg_scratch[0..clen]) orelse return error.ResourceExhausted;
        self.mcache.put(&self.store, h);
        self.store.seal(h);
        _ = self.seen.add(id, now.mono_ms);
        const peers = if (self.state.subscribed(topic)) self.state.mesh(topic) else self.fillFanout(topic, now);
        const result = self.deliver(peers, h, null, now.mono_ms);
        self.counters.messages_published += 1;
        return result;
    }

    fn storeMessage(self: *Gossipsub, id: MessageId, name: []const u8, bytes: []const u8) ?storage.Handle {
        for (0..self.mcache.entries.len) |_| {
            if (self.store.canReserve(bytes.len)) break;
            if (!self.mcache.evictOldest(&self.store)) return null;
        }
        return self.store.put(id, name, bytes);
    }

    /// Event topic and payload slices remain valid until the next pump, even after report or publish.
    /// Outcomes retain already-resolved/expired distinction until tombstone expiry or slot reuse.
    pub fn report(self: *Gossipsub, handle: ValidationHandle, verdict: Verdict, now: Now) ReportOutcome {
        const free_before = self.store.free_pages;
        if (self.validation.inspect(&self.store, handle, now.mono_ms)) |outcome| {
            if (self.store.free_pages != free_before) self.wakeStorage();
            return outcome;
        }
        const e = &self.validation.entries[handle.index];
        if (verdict == .accept) {
            self.mcache.put(&self.store, e.message);
            if (self.state.subscribed(e.topic)) {
                const delivered = self.deliver(self.state.mesh(e.topic), e.message, e.source, now.mono_ms);
                if (delivered.queued > 0) self.counters.messages_forwarded += 1;
            }
        }
        if (verdict != .ignore) {
            if (self.state.peerMatches(e.source.index, e.source.generation)) {
                if (verdict == .accept) self.scores.deliver(e.source.index, e.topic) else self.scores.invalid(e.source.index, e.topic);
            }
            for (e.duplicates[0..e.duplicate_len]) |d| {
                if (!self.state.peerMatches(d.peer.index, d.peer.generation)) continue;
                if (verdict == .reject) self.scores.invalid(d.peer.index, e.topic) else if (d.eligible) self.scores.duplicate(d.peer.index, e.topic);
            }
        }
        self.validation.finish(&self.store, handle, verdict, now.mono_ms);
        self.wakeStorage();
        return .{ .applied = verdict };
    }

    fn deliver(self: *Gossipsub, peers: *state_mod.PeerSet, h: storage.Handle, source: ?validation_mod.PeerRef, now_ms: u64) PublishOutcome {
        const id = self.store.get(h).?.id;
        var result: PublishOutcome = .{};
        var it = peers.iterator(.{});
        while (it.next()) |peer| {
            const index: u16 = @intCast(peer);
            if (!self.state.peers[index].active) continue;
            if (source) |p| if (p.index == index and self.state.peerMatches(index, p.generation)) continue;
            if (self.state.suppresses(index, id)) continue;
            if (!self.direct.isSet(index) and self.scores.score(index, now_ms) < self.options.score_params.publish_threshold) continue;
            if (self.io.peers[index].queueData(&self.store, h, self.options.tx_peer_bytes, now_ms) == .queued) {
                result.queued += 1;
            } else {
                result.pressured += 1;
                self.counters.send_dropped += 1;
            }
        }
        return result;
    }

    fn fillFanout(self: *Gossipsub, topic: u16, now: Now) *state_mod.PeerSet {
        const fanout = self.state.fanout(topic);
        self.state.topics[topic].fanout_last_ms = now.mono_ms;
        if (fanout.count() < constants.mesh_d) {
            var need = constants.mesh_d - fanout.count();
            var it = self.state.subscribers(topic).iterator(.{});
            while (it.next()) |peer| {
                if (need == 0) break;
                if (fanout.isSet(peer)) continue;
                fanout.set(peer);
                need -= 1;
            }
        }
        return fanout;
    }

    // Pump -------------------------------------------------------------------

    pub fn memoryPlan(self: *const Gossipsub) MemoryPlan {
        const metadata = @sizeOf(Gossipsub) + @sizeOf(State) + self.io.peers.len * @sizeOf(PeerIo) +
            self.store.entries.len * @sizeOf(storage.Entry) + self.store.next.len * @sizeOf(u32) +
            self.validation.entries.len * @sizeOf(validation_mod.Entry) + self.mcache.entries.len * @sizeOf(mcache_mod.HistoryEntry) +
            self.mcache.ids.len * @sizeOf(MessageId) + self.mcache.index.slots.len * @sizeOf(u32) +
            self.promises.len * @sizeOf(Promise) + self.large_used.len * @sizeOf(bool) +
            self.seen.ids.len * (@sizeOf(MessageId) + @sizeOf(u64)) + self.seen.index.slots.len * @sizeOf(u32) +
            self.scores.topics.len * @sizeOf(@TypeOf(self.scores.topics[0])) + self.scores.app_score.len * @sizeOf(f64) + self.scores.behaviour.len * @sizeOf(f64);
        return .{
            .retained_bytes = self.store.bytes.len,
            .page_count = self.store.next.len,
            .message_entries = self.store.entries.len,
            .validation_capacity = self.validation.entries.len,
            .duplicate_attributions_per_validation = validation_mod.duplicates_max,
            .data_descriptors_per_peer = peer_io_mod.data_capacity,
            .data_descriptors_total = constants.peers_cap * peer_io_mod.data_capacity,
            .legal_atomic_work_bytes = 2 * constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 2 * constants.MAX_PAYLOAD_SIZE,
            .page_bytes = storage.page_bytes,
            .rounding_per_message_max = storage.page_bytes - 1,
            .frame_bytes = self.large_pool.len,
            .event_bytes = self.decompressed.len,
            .compression_bytes = self.msg_scratch.len,
            .peer_buffer_bytes = self.io.arena.len,
            .metadata_bytes = metadata,
            .total_bytes = self.store.bytes.len + self.large_pool.len + self.decompressed.len + self.msg_scratch.len + self.io.arena.len + metadata,
        };
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
        for (self.promises[0..self.promise_len]) |promise| if (promise.expiry) |expiry| {
            deadline = @min(deadline, expiry);
        };
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
        self.validation.expire(&self.store, now.mono_ms);
        if (self.store.free_pages != free_before) self.wakeStorage();
        self.expireIo(engine, now.mono_ms);
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
            if (io.rx_ready or (io.blocked == .events and count < events.len)) {
                count = self.readPeer(engine, @intCast(index), io, now, events, count);
            }
            if (io.tx_ready) self.flush(engine, @intCast(index), io, now);
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
        self.scores.refresh(now.mono_ms);
        self.state.pruneBackoffs(now.mono_ms, self.backoffSlackMs());
        self.expireFanout(now.mono_ms);
        if (self.topics_remaining == 0) self.topics_remaining = constants.topics_cap;
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
            if (!topic.active or !topic.subscribed) continue;
            self.maintainTopic(index, now);
            if (self.opportunistic_pending) self.opportunisticGraft(index, now);
            self.emitGossip(index);
            serviced += 1;
            if (serviced == self.options.topics_per_pump) return;
        }
    }

    /// When the mesh median score falls below the threshold, graft a couple of
    /// above-median peers to recover from an underperforming or captured mesh.
    fn opportunisticGraft(self: *Gossipsub, topic: u16, now: Now) void {
        const mesh = self.state.mesh(topic);
        if (mesh.count() < constants.mesh_d) return;
        var members: [constants.peers_cap]Member = undefined;
        const count = self.meshMembers(topic, now, &members);
        std.sort.pdq(Member, members[0..count], {}, memberLess);
        const median = members[count / 2].sc;
        if (median >= self.options.score_params.opportunistic_graft_threshold) return;
        const topic_str = self.state.topicString(topic);
        var added: u8 = 0;
        var it = self.state.subscribers(topic).iterator(.{});
        while (it.next()) |peer| {
            if (added == constants.opportunistic_graft_peers) break;
            const index: u16 = @intCast(peer);
            if (mesh.isSet(peer)) continue;
            if (self.graftBackedOff(index, topic, now.mono_ms)) continue;
            if (self.scores.score(index, now.mono_ms) <= median) continue;
            mesh.set(peer);
            self.scores.graft(index, topic, now.mono_ms);
            _ = self.queueGraft(index, topic_str);
            added += 1;
        }
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
        const mesh = self.state.mesh(topic);
        const gossip_threshold = self.options.score_params.gossip_threshold;
        var need: usize = constants.mesh_d_lazy;
        var it = self.state.subscribers(topic).iterator(.{});
        while (it.next()) |peer| {
            if (need == 0) break;
            if (mesh.isSet(peer)) continue;
            if (self.scores.score(@intCast(peer), self.last_now_ms) < gossip_threshold) continue;
            if (self.io.peers[peer].append(rpc, self.last_now_ms)) need -= 1 else self.counters.send_dropped += 1;
        }
    }

    fn addPromise(self: *Gossipsub, id: MessageId, index: u16, token: u64) void {
        assert(self.promise_len < self.promises.len);
        self.promises[self.promise_len] = .{ .id = id, .peer = .{ .index = index, .generation = self.state.peerGeneration(index) }, .token = token };
        self.promise_len += 1;
    }

    fn resolvePromises(self: *Gossipsub, id: MessageId) void {
        var index: usize = 0;
        for (0..self.promises.len) |_| {
            if (index == self.promise_len) break;
            if (std.mem.eql(u8, &self.promises[index].id, &id)) {
                self.promises[index] = self.promises[self.promise_len - 1];
                self.promise_len -= 1;
            } else index += 1;
        }
    }

    fn cancelPromises(self: *Gossipsub, peer: u16, local_pressure: bool) void {
        var index: usize = 0;
        for (0..self.promises.len) |_| {
            if (index == self.promise_len) break;
            const p = self.promises[index];
            if (p.peer.index == peer and self.state.peerMatches(peer, p.peer.generation)) {
                self.promises[index] = self.promises[self.promise_len - 1];
                self.promise_len -= 1;
                if (local_pressure) self.counters.promises_cancelled_pressure += 1;
            } else index += 1;
        }
    }

    fn controlSent(self: *Gossipsub, peer: u16, token: u64, now_ms: u64) void {
        for (self.promises[0..self.promise_len]) |*p| {
            if (p.peer.index == peer and p.token == token and self.state.peerMatches(peer, p.peer.generation)) {
                p.expiry = now_ms +| constants.iwant_followup_ms;
            }
        }
    }

    fn expirePromises(self: *Gossipsub, now_ms: u64) void {
        var index: usize = 0;
        for (0..self.promises.len) |_| {
            if (index == self.promise_len) break;
            const p = self.promises[index];
            const current = self.state.peerMatches(p.peer.index, p.peer.generation);
            if (!current or (p.expiry != null and now_ms >= p.expiry.?)) {
                if (current and p.expiry != null) {
                    self.counters.broken_promises += 1;
                    self.scores.penalize(p.peer.index, 1);
                }
                self.promises[index] = self.promises[self.promise_len - 1];
                self.promise_len -= 1;
            } else index += 1;
        }
    }

    const Member = struct { peer: u16, sc: f64 };

    fn maintainTopic(self: *Gossipsub, topic: u16, now: Now) void {
        const topic_str = self.state.topicString(topic);
        const mesh = self.state.mesh(topic);

        var direct_it = self.direct.iterator(.{});
        while (direct_it.next()) |peer| {
            if (self.state.subscribers(topic).isSet(peer) and !mesh.isSet(peer)) {
                mesh.set(peer);
                self.scores.graft(@intCast(peer), topic, now.mono_ms);
                _ = self.queueGraft(@intCast(peer), topic_str);
            }
        }

        var members: [constants.peers_cap]Member = undefined;
        var count = self.meshMembers(topic, now, &members);
        for (members[0..count]) |member| {
            if (member.sc < 0) self.pruneMember(topic, topic_str, member.peer, now);
        }

        const size = mesh.count();
        if (size < constants.mesh_d_low) {
            var need = constants.mesh_d - size;
            var it = self.state.subscribers(topic).iterator(.{});
            while (it.next()) |peer| {
                if (need == 0) break;
                const index: u16 = @intCast(peer);
                if (mesh.isSet(peer)) continue;
                if (self.graftBackedOff(index, topic, now.mono_ms)) continue;
                if (self.scores.score(index, now.mono_ms) < 0) continue;
                mesh.set(peer);
                self.scores.graft(index, topic, now.mono_ms);
                _ = self.queueGraft(index, topic_str);
                need -= 1;
            }
        } else if (size > constants.mesh_d_high) {
            count = self.meshMembers(topic, now, &members);
            std.sort.pdq(Member, members[0..count], {}, memberGreater);
            if (count > constants.mesh_d_score) {
                self.rng.random().shuffle(Member, members[constants.mesh_d_score..count]);
            }
            for (members[constants.mesh_d..count]) |member| {
                self.pruneMember(topic, topic_str, member.peer, now);
            }
        }
    }

    fn meshMembers(self: *Gossipsub, topic: u16, now: Now, out: []Member) usize {
        var count: usize = 0;
        var it = self.state.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            const index: u16 = @intCast(peer);
            out[count] = .{ .peer = index, .sc = self.scores.score(index, now.mono_ms) };
            count += 1;
        }
        return count;
    }

    fn pruneMember(self: *Gossipsub, topic: u16, topic_str: []const u8, peer: u16, now: Now) void {
        if (self.direct.isSet(peer)) return;
        self.state.mesh(topic).unset(peer);
        self.scores.prune(peer, topic, now.mono_ms);
        self.state.addBackoff(peer, topic, now.mono_ms +| constants.prune_backoff_ms);
        _ = self.queuePrune(peer, topic_str, constants.prune_backoff_ms / 1000);
    }

    fn memberLess(_: void, a: Member, b: Member) bool {
        return a.sc < b.sc;
    }

    fn memberGreater(_: void, a: Member, b: Member) bool {
        return a.sc > b.sc;
    }

    fn belowGossip(self: *Gossipsub, index: u16, now_ms: u64) bool {
        return self.scores.score(index, now_ms) < self.options.score_params.gossip_threshold;
    }

    fn backoffSlackMs(self: *const Gossipsub) u64 {
        return constants.backoff_slack_heartbeats * self.options.heartbeat_interval_ms;
    }

    /// Whether we should refrain from grafting a peer: backed off, plus a slack
    /// window so we never re-graft at the exact instant the peer's backoff ends.
    fn graftBackedOff(self: *Gossipsub, index: u16, topic: u16, now_ms: u64) bool {
        return self.state.backedOff(index, topic, now_ms -| self.backoffSlackMs());
    }

    /// The host's application-specific P5 term for a peer, from its own signals.
    pub fn setPeerScore(self: *Gossipsub, conn: Handle, value: f64) void {
        if (self.state.findPeer(conn)) |index| self.scores.setAppScore(index, value);
    }

    /// Marks a peer as direct (a configured trusted peer): kept in every shared
    /// mesh, never pruned or graylisted, exempt from the score gates.
    pub fn markDirect(self: *Gossipsub, conn: Handle) void {
        if (self.state.findPeer(conn)) |index| self.direct.set(index);
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
        var calls: usize = self.options.calls_per_peer;
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
            if (calls == 0 or self.budget.calls == 0 or input == 0 or self.budget.input == 0) return count;
            calls -= 1;
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
        if (io.large_slot) |slot| return self.largeBuffer(slot);
        const declared = io.reader.declaredLen() orelse return io.body;
        if (declared <= io.body.len) return io.body;
        const slot = self.claimLarge() orelse return null;
        io.large_slot = slot;
        return self.largeBuffer(slot);
    }

    /// Drops fanout peer sets for topics not published to within the fanout TTL,
    /// so stale fanout targets do not persist for the process lifetime.
    fn expireFanout(self: *Gossipsub, now_ms: u64) void {
        for (&self.state.topics) |*topic| {
            if (!topic.active or topic.fanout.count() == 0) continue;
            if (now_ms -| topic.fanout_last_ms > constants.fanout_ttl_ms) {
                topic.fanout = state_mod.PeerSet.initEmpty();
            }
        }
    }

    fn largeBuffer(self: *Gossipsub, slot: u8) []u8 {
        const base = @as(usize, slot) * self.options.large_message_bytes;
        return self.large_pool[base..][0..self.options.large_message_bytes];
    }

    fn claimLarge(self: *Gossipsub) ?u8 {
        for (self.large_used, 0..) |used, slot| {
            if (!used) {
                self.large_used[slot] = true;
                return @intCast(slot);
            }
        }
        return null;
    }

    fn releaseLarge(self: *Gossipsub, peer_io: *PeerIo) void {
        if (peer_io.large_slot) |slot| {
            self.large_used[slot] = false;
            peer_io.large_slot = null;
            self.wakeStorage();
        }
    }

    fn processRpc(self: *Gossipsub, index: u16, now: Now, events: []Event, count: *usize, items: *usize) protobuf.Error!bool {
        const io = &self.io.peers[index];
        if (!self.direct.isSet(index) and self.scores.score(index, now.mono_ms) < self.options.score_params.graylist_threshold) return true;
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
                        if (self.state.findTopic(sub.topic) != null and (count.* == events.len or self.decompressed.len - self.decompressed_used < sub.topic.len)) {
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

    fn chargeMessage(self: *Gossipsub, io: *PeerIo, compressed: usize, decoded: usize) bool {
        const cost = compressed * 2 + decoded * 2;
        if (cost <= self.budget.work and cost <= self.options.decompress_per_peer_bytes -| io.decompressed_pump) {
            self.budget.work -= cost;
            io.decompressed_pump += cost;
            return true;
        }
        if (!self.budget.large_used and cost > @min(self.options.work_per_pump, self.options.decompress_per_peer_bytes)) {
            self.budget.large_used = true;
            return true;
        }
        self.counters.decompress_throttled += 1;
        return false;
    }

    fn onMessage(self: *Gossipsub, index: u16, msg: protobuf.Message, now: Now, events: []Event, start: usize) ?usize {
        if (msg.signed or msg.data.len > constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE)) return start;
        const topic = self.state.findTopic(msg.topic) orelse return start;
        if (!self.state.subscribed(topic)) return start;
        const io = &self.io.peers[index];
        const size = snappy.raw.uncompressedLength(msg.data) catch {
            if (!self.chargeMessage(io, msg.data.len, 0)) return null;
            _ = self.seen.add(topic_mod.invalidMessageId(msg.topic, msg.data, self.options.message_id_policy), now.mono_ms);
            return start;
        };
        if (size > constants.MAX_PAYLOAD_SIZE) return start;
        if (start == events.len or size + msg.topic.len > self.decompressed.len - self.decompressed_used) {
            self.pressure(index, .events, now.mono_ms);
            return null;
        }
        if (!self.validation.available()) {
            self.pressure(index, .storage, now.mono_ms);
            return null;
        }
        if (!self.chargeMessage(io, msg.data.len, size)) return null;
        const room = self.decompressed[self.decompressed_used..];
        const written = snappy.raw.uncompress(msg.data, room[0..size]) catch {
            _ = self.seen.add(topic_mod.invalidMessageId(msg.topic, msg.data, self.options.message_id_policy), now.mono_ms);
            return start;
        };
        const payload = room[0..written];
        const id = topic_mod.validMessageId(msg.topic, payload, self.options.message_id_policy);
        const pending = self.validation.find(id, now.mono_ms);
        if ((pending != null and pending.?.state == .pending) or self.seen.contains(id, now.mono_ms)) {
            self.counters.duplicates += 1;
            if (pending) |e| {
                const peer: validation_mod.PeerRef = .{ .index = index, .generation = self.state.peerGeneration(index) };
                const eligible = self.state.mesh(topic).isSet(index);
                if (validation_mod.Validation.duplicate(e, peer, eligible) and e.state == .resolved) {
                    if (e.verdict == .reject) self.scores.invalid(index, topic) else if (e.verdict == .accept and eligible) self.scores.duplicate(index, topic);
                }
            }
            self.resolvePromises(id);
            return start;
        }
        const h = self.storeMessage(id, msg.topic, msg.data) orelse {
            self.pressure(index, .storage, now.mono_ms);
            return null;
        };
        const handle = self.validation.admit(&self.store, h, .{ .index = index, .generation = self.state.peerGeneration(index) }, topic, now.mono_ms);
        self.store.seal(h);
        @memcpy(room[written..][0..msg.topic.len], msg.topic);
        self.decompressed_used += written + msg.topic.len;
        events[start] = .{ .message = .{
            .handle = handle,
            .id = id,
            .peer = self.state.peers[index].conn,
            .topic = room[written..][0..msg.topic.len],
            .bytes = payload,
        } };
        _ = self.seen.add(id, now.mono_ms);
        self.resolvePromises(id);
        self.counters.messages_received += 1;
        if (written >= constants.idontwant_size_threshold) self.broadcastIdontwant(topic, id, index);
        return start + 1;
    }

    fn onIhave(self: *Gossipsub, index: u16, ihave: protobuf.IHave, now: Now) void {
        if (self.belowGossip(index, now.mono_ms)) return;
        const io = &self.io.peers[index];
        if (io.ihave_recv >= constants.max_ihave_per_heartbeat) return;
        io.ihave_recv += 1;
        const id_budget = constants.max_ihave_ids_per_heartbeat -| @as(usize, io.iwant_ids_sent);
        if (id_budget == 0 or self.promise_len == self.promises.len) return;
        var wanted: [constants.gossip_ids_max]MessageId = undefined;
        var count: usize = 0;
        var examined: usize = 0;
        var it = ihave.ids();
        while (it.next() catch return) |id_bytes| {
            if (examined == constants.max_ihave_ids_per_heartbeat) break;
            examined += 1;
            if (count == wanted.len or count >= id_budget or count == self.promises.len - self.promise_len) break;
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
            if (self.state.suppresses(index, id)) continue;
            const cached = self.mcache.get(&self.store, id) orelse continue;
            const peer: validation_mod.PeerRef = .{ .index = index, .generation = self.state.peerGeneration(index) };
            if (!mcache_mod.History.iwantAllowed(cached, peer, constants.gossip_retransmission)) continue;
            if (self.io.peers[index].queueData(&self.store, cached.message, self.options.tx_peer_bytes, self.last_now_ms) == .queued) {
                mcache_mod.History.sent(cached, peer);
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
            self.state.suppress(index, id_bytes[0..constants.message_id_length].*);
        }
    }

    fn onGraft(self: *Gossipsub, index: u16, topic_str: []const u8, now: Now) void {
        const topic = self.state.findTopic(topic_str) orelse return;
        if (!self.state.subscribed(topic)) return;
        if (self.state.backedOff(index, topic, now.mono_ms)) {
            self.scores.penalize(index, 1);
            if (self.state.backoffUntil(index, topic)) |until| {
                const remaining = until -| now.mono_ms;
                const flood_window =
                    constants.prune_backoff_ms -| constants.graft_flood_threshold_ms;
                if (remaining > flood_window) self.scores.penalize(index, 1);
            }
            _ = self.queuePrune(index, topic_str, constants.prune_backoff_ms / 1000);
            return;
        }
        self.state.setSubscription(topic, index, true);
        self.state.mesh(topic).set(index);
        self.scores.graft(index, topic, now.mono_ms);
    }

    fn onPrune(self: *Gossipsub, index: u16, prune: protobuf.Prune, now: Now) void {
        const topic = self.state.findTopic(prune.topic) orelse return;
        self.state.mesh(topic).unset(index);
        self.scores.prune(index, topic, now.mono_ms);
        const backoff_ms = if (prune.backoff > 0)
            prune.backoff *| 1000
        else
            constants.prune_backoff_ms;
        self.state.addBackoff(index, topic, now.mono_ms +| backoff_ms);
    }

    fn onSubscription(
        self: *Gossipsub,
        index: u16,
        sub: protobuf.SubOpts,
        events: []Event,
        start: usize,
    ) usize {
        const topic = self.state.findTopic(sub.topic) orelse return start;
        assert(start < events.len);
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

    fn queueGraft(self: *Gossipsub, index: u16, topic_str: []const u8) peer_io_mod.QueueResult {
        var buf: [control_frame_max]u8 = undefined;
        var writer = protobuf.Writer.init(&buf);
        writer.varint(protobuf.graftRpcSize(topic_str));
        protobuf.writeGraftRpc(&writer, topic_str);
        if (self.io.peers[index].appendControl(writer.written(), true, self.last_now_ms) != null) return .queued;
        self.counters.send_dropped += 1;
        return .full;
    }

    fn queuePrune(self: *Gossipsub, index: u16, topic_str: []const u8, backoff_s: u64) peer_io_mod.QueueResult {
        var buf: [control_frame_max]u8 = undefined;
        var writer = protobuf.Writer.init(&buf);
        writer.varint(protobuf.pruneRpcSize(topic_str, backoff_s));
        protobuf.writePruneRpc(&writer, topic_str, backoff_s);
        if (self.io.peers[index].appendControl(writer.written(), true, self.last_now_ms) != null) return .queued;
        self.counters.send_dropped += 1;
        return .full;
    }

    fn flush(self: *Gossipsub, engine: *Engine, index: u16, io: *PeerIo, now: Now) void {
        const stream = self.state.peers[index].out_stream orelse return;
        var bytes = self.options.output_per_peer;
        var calls = self.options.calls_per_peer;
        for (0..self.options.calls_per_peer) |_| {
            self.queueSubscriptions(io);
            const segment = io.segment(&self.store);
            if (segment.len == 0) {
                io.tx_ready = false;
                io.tx_progress_ms = null;
                return;
            }
            if (bytes == 0 or self.budget.output == 0 or calls == 0 or self.budget.calls == 0) return;
            const take = @min(bytes, self.budget.output, segment.len);
            calls -= 1;
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
    var g = try Gossipsub.init(std.testing.allocator, .{});
    defer g.deinit();
    const peer = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2).?;
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
    var g = try Gossipsub.init(std.testing.allocator, .{ .mcache_capacity = 1, .validation_capacity = 2, .seen_capacity = 1 });
    defer g.deinit();
    const peer = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2).?;
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
    var g = try Gossipsub.init(std.testing.allocator, .{ .mcache_capacity = 1 });
    defer g.deinit();
    const peer = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2).?;
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
    var g = try Gossipsub.init(std.testing.allocator, .{ .control_bytes = 64 });
    defer g.deinit();
    const peer = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var body: [32]u8 = undefined;
    var w = protobuf.Writer.init(&body);
    const id = [_]u8{7} ** 20;
    w.bytesField(2, &id);
    try std.testing.expect(g.io.peers[peer.index].append(&([_]u8{0} ** 64), 1));
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 0), g.promise_len);
    g.io.peers[peer.index].resetTx(&g.store);
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 2, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.promise_len);
    g.expirePromises(10_000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    const io = &g.io.peers[peer.index];
    const first = io.segment(&g.store);
    _ = io.advance(&g.store, 1);
    try std.testing.expect(g.promises[0].expiry == null);
    const token = io.advance(&g.store, first.len - 1).?;
    g.controlSent(peer.index, token, 10_000);
    try std.testing.expectEqual(@as(?u64, 13_000), g.promises[0].expiry);
    var empty: [0]Event = .{};
    try std.testing.expectEqual(@as(?usize, null), try testMessage(&g, peer.index, "held behind host pressure", 11_000, &empty));
    g.expirePromises(14_000);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u64, 1), g.counters.promises_cancelled_pressure);
    g.io.peers[peer.index].resetHeartbeat();
    g.onIhave(peer.index, .{ .topic = topic, .body = w.written() }, .{ .mono_ms = 14_000, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.promise_len);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    _ = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2).?;
    g.expirePromises(20_000);
    try std.testing.expectEqual(@as(usize, 0), g.promise_len);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
}

test "gossipsub rejects incompatible memory plans and cleans partial startup allocations" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .large_message_bytes = 65536 }));
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .decompressed_arena_bytes = 4096 }));
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .large_pool_count = 256 }));
    try std.testing.expectError(error.InvalidLimits, Gossipsub.init(a, .{ .fields_per_pump = 1 }));
    try std.testing.checkAllAllocationFailures(a, testStartup, .{});
}
fn testStartup(a: Allocator) !void {
    var g = try Gossipsub.init(a, .{ .seen_capacity = 1, .mcache_capacity = 1, .validation_capacity = 1, .body_buffer_bytes = 1, .control_bytes = 1, .critical_bytes = control_frame_max, .large_pool_count = 1 });
    defer g.deinit();
    const plan = g.memoryPlan();
    try std.testing.expectEqual(@as(usize, 4096), plan.page_bytes);
    try std.testing.expectEqual(g.store.bytes.len, plan.retained_bytes);
    try std.testing.expectEqual(plan.total_bytes, plan.retained_bytes + plan.frame_bytes + plan.event_bytes + plan.compression_bytes + plan.peer_buffer_bytes + plan.metadata_bytes);
}

test "gossipsub legal maximum host acceptance forwards retained pages through actual IO" {
    var setup: @import("gossipsub_test.zig").GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.subscribe(topic));
    try std.testing.expect(setup.server.subscribe(topic));
    for (0..20) |_| try setup.pumpOnce();
    const destination = setup.server.state.findPeer(setup.handles.server).?;
    const source = setup.server.addPeer(.{ .index = 77, .generation = 1 }, .v1_2).?;
    setup.server.state.mesh(setup.server.state.findTopic(topic).?).set(destination);
    const payload = try std.testing.allocator.alloc(u8, constants.MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(91);
    rng.random().bytes(payload);
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
    var g = try Gossipsub.init(std.testing.allocator, .{ .decompress_per_peer_bytes = 1 });
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
    const first = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2).?;
    const second = g.addPeer(.{ .index = 1, .generation = 1 }, .v1_2).?;
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
    var g = try Gossipsub.init(std.testing.allocator, .{});
    defer g.deinit();
    const source_conn: Handle = .{ .index = 0, .generation = 1 };
    const duplicate_conn: Handle = .{ .index = 1, .generation = 1 };
    const source = g.addPeer(source_conn, .v1_2).?;
    const duplicate = g.addPeer(duplicate_conn, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "invalid", 1, &events));
    const handle = events[0].message.handle;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "invalid", 2, &events));
    g.connectionClosed(source_conn);
    g.connectionClosed(duplicate_conn);
    const replacement1 = g.addPeer(.{ .index = 0, .generation = 2 }, .v1_2).?;
    const replacement2 = g.addPeer(.{ .index = 1, .generation = 2 }, .v1_2).?;
    try std.testing.expectEqual(ReportOutcome{ .applied = .reject }, g.report(handle, .reject, .{ .mono_ms = 3, .unix_s = 1 }));
    try std.testing.expectEqual(@as(f64, 0), g.scores.score(replacement1.index, 3));
    try std.testing.expectEqual(@as(f64, 0), g.scores.score(replacement2.index, 3));
}
