const std = @import("std");
const snappy = @import("snappy");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const topic_mod = @import("topic.zig");
const frame_mod = @import("frame.zig");
const mcache_mod = @import("mcache.zig");
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

pub const Options = struct {
    heartbeat_interval_ms: u64 = constants.heartbeat_interval_ms,
    seen_capacity: usize = 65_536,
    mcache_capacity: usize = 8_192,
    mcache_arena_bytes: usize = 8 * 1024 * 1024,
    /// Decompressed bytes surfaced in one pump; the host consumes them before
    /// the next pump. Full means new messages wait, applying backpressure.
    decompressed_arena_bytes: usize = 4 * 1024 * 1024,
    body_buffer_bytes: usize = constants.body_buffer_len,
    /// A pool of large body buffers claimed while receiving a frame that does
    /// not fit the per-peer buffer (blocks and data columns).
    large_message_bytes: usize = 2 * 1024 * 1024,
    large_pool_count: usize = 8,
    seen_ttl_ms: u64 = constants.seenTtlMs(32, 12),
    score_params: score_mod.Params = .{},
    opportunistic_graft_interval_ms: u64 = constants.opportunistic_graft_ms,
};

pub const InitError = Allocator.Error;

/// Advertised protocol ids, newest first; the negotiator settles the version.
pub const meshsub_ids = [_][]const u8{ "/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0" };

pub fn versionFor(protocol_index: u8) Version {
    return switch (protocol_index) {
        0 => .v1_2,
        1 => .v1_1,
        else => .v1_0,
    };
}

pub const MessageId = topic_mod.MessageId;

pub const Verdict = enum { accept, reject, ignore };

pub const Event = union(enum) {
    /// A new message the host must validate and then close out with
    /// `report(handle, verdict)`. `bytes` is the decompressed payload, valid
    /// until the next pump; the host copies what it needs.
    message: struct { handle: MessageId, peer: Handle, topic: []const u8, bytes: []const u8 },
    subscription_change: struct { peer: Handle, topic: []const u8, subscribed: bool },
};

/// Per-peer stream I/O: a linear send buffer that batches outgoing RPCs and the
/// resumable framing state for the inbound stream.
const sub_frame_max = 16 + topic_mod.topic_max_len;
const control_frame_max = 32 + topic_mod.topic_max_len;

/// An outstanding IWANT: we requested `id` from `peer` after its IHAVE and
/// expect delivery before `expiry`, else the peer takes a behavioural penalty.
const Promise = struct { id: MessageId, peer: u16, expiry: u64 };

const PeerIo = struct {
    send: []u8,
    send_head: usize = 0,
    send_tail: usize = 0,
    reader: frame_mod.Reader = .{},
    body: []u8,
    large_slot: ?u8 = null,

    fn reset(self: *PeerIo) void {
        self.send_head = 0;
        self.send_tail = 0;
        self.reader = .{};
    }

    fn pending(self: *const PeerIo) []const u8 {
        return self.send[self.send_tail..self.send_head];
    }

    fn append(self: *PeerIo, bytes: []const u8) bool {
        if (self.send_head == self.send_tail) {
            self.send_head = 0;
            self.send_tail = 0;
        }
        if (self.send_head + bytes.len > self.send.len) return false;
        @memcpy(self.send[self.send_head..][0..bytes.len], bytes);
        self.send_head += bytes.len;
        return true;
    }

    /// Frames a publish RPC directly into the free tail of the send buffer,
    /// avoiding an intermediate copy of the message data. Fails when the frame
    /// does not fit (a large message the send path streams instead).
    fn appendMessage(self: *PeerIo, topic_str: []const u8, data: []const u8) bool {
        if (self.send_head == self.send_tail) {
            self.send_head = 0;
            self.send_tail = 0;
        }
        const body_size = protobuf.messageSize(data, topic_str);
        const total = protobuf.varintLen(body_size) + body_size;
        if (self.send_head + total > self.send.len) return false;
        var writer = protobuf.Writer.init(self.send[self.send_head..]);
        writer.varint(body_size);
        protobuf.writeMessage(&writer, data, topic_str);
        self.send_head += writer.len;
        return true;
    }
};

pub const Gossipsub = struct {
    allocator: Allocator,
    options: Options,
    state: *State,
    scores: score_mod.PeerScore,
    seen: mcache_mod.SeenCache,
    mcache: mcache_mod.MessageCache,
    io: []PeerIo,
    io_arena: []u8,
    large_pool: []u8,
    large_used: []bool,
    direct: state_mod.PeerSet = state_mod.PeerSet.initEmpty(),
    heartbeat_at: u64 = 0,
    opportunistic_at: u64 = 0,
    last_now_ms: u64 = 0,
    scratch: []u8,
    msg_scratch: []u8,
    decompressed: []u8,
    decompressed_used: usize = 0,
    promises: []Promise,
    promise_len: usize = 0,
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
        oversized_dropped: u64 = 0,
        iwant_sent: u64 = 0,
        broken_promises: u64 = 0,
    };

    pub fn init(allocator: Allocator, options: Options) InitError!Gossipsub {
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
        var mcache = try mcache_mod.MessageCache.init(
            allocator,
            options.mcache_capacity,
            options.mcache_arena_bytes,
        );
        errdefer mcache.deinit(allocator);

        const per_peer = constants.send_buffer_len + options.body_buffer_bytes;
        const io_arena = try allocator.alloc(u8, constants.peers_cap * per_peer);
        errdefer allocator.free(io_arena);
        const io = try allocator.alloc(PeerIo, constants.peers_cap);
        errdefer allocator.free(io);
        for (io, 0..) |*slot, index| {
            const base = index * per_peer;
            slot.* = .{
                .send = io_arena[base..][0..constants.send_buffer_len],
                .body = io_arena[base + constants.send_buffer_len ..][0..options.body_buffer_bytes],
            };
        }
        const scratch = try allocator.alloc(u8, constants.read_scratch_len);
        errdefer allocator.free(scratch);
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
            .io = io,
            .io_arena = io_arena,
            .large_pool = large_pool,
            .large_used = large_used,
            .scratch = scratch,
            .msg_scratch = msg_scratch,
            .decompressed = decompressed,
            .promises = promises,
        };
    }

    pub fn deinit(self: *Gossipsub) void {
        self.allocator.free(self.large_used);
        self.allocator.free(self.large_pool);
        self.allocator.free(self.promises);
        self.allocator.free(self.decompressed);
        self.allocator.free(self.msg_scratch);
        self.allocator.free(self.scratch);
        self.allocator.free(self.io);
        self.allocator.free(self.io_arena);
        self.mcache.deinit(self.allocator);
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
        self.state.setSubscribed(topic, false);
        self.announce(topic_str, false);
        return true;
    }

    fn announce(self: *Gossipsub, topic_str: []const u8, subscribe_flag: bool) void {
        var buf: [sub_frame_max]u8 = undefined;
        var writer = protobuf.Writer.init(&buf);
        writer.varint(protobuf.subscriptionSize(topic_str));
        protobuf.writeSubscription(&writer, subscribe_flag, topic_str);
        for (self.io, 0..) |*peer_io, index| {
            if (!self.state.peers[index].active) continue;
            if (!peer_io.append(writer.written())) self.counters.send_dropped += 1;
        }
    }

    // Peer lifecycle ---------------------------------------------------------

    pub fn addPeer(self: *Gossipsub, conn: Handle, version: Version) ?state_mod.PeerHandle {
        const handle = self.state.addPeer(conn, version) orelse return null;
        self.scores.resetPeer(handle.index);
        self.io[handle.index].reset();
        self.sendSubscriptions(handle.index);
        return handle;
    }

    pub fn setStreams(self: *Gossipsub, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        self.state.setStreams(index, out, in);
    }

    pub fn connectionClosed(self: *Gossipsub, conn: Handle) void {
        const index = self.state.findPeer(conn) orelse return;
        self.releaseLarge(&self.io[index]);
        self.direct.unset(index);
        self.state.removePeer(index);
    }

    fn sendSubscriptions(self: *Gossipsub, index: u16) void {
        var buf: [sub_frame_max]u8 = undefined;
        for (&self.state.topics) |*topic| {
            if (!topic.active or !topic.subscribed) continue;
            const topic_str = topic.string[0..topic.string_len];
            var writer = protobuf.Writer.init(&buf);
            writer.varint(protobuf.subscriptionSize(topic_str));
            protobuf.writeSubscription(&writer, true, topic_str);
            if (!self.io[index].append(writer.written())) self.counters.send_dropped += 1;
        }
    }

    // Publish and forward ----------------------------------------------------

    /// Originates a message on `topic_str`. Compresses the SSZ, caches it, and
    /// sends it to the topic mesh (or fanout when unsubscribed).
    pub fn publish(self: *Gossipsub, topic_str: []const u8, ssz: []const u8, now: Now) bool {
        if (ssz.len > constants.MAX_PAYLOAD_SIZE) return false;
        const topic = self.state.internTopic(topic_str) orelse return false;
        const clen = snappy.raw.compress(ssz, self.msg_scratch) catch return false;
        const data = self.msg_scratch[0..clen];
        const id = topic_mod.validMessageId(ssz);
        _ = self.seen.add(id, now.mono_ms);
        _ = self.mcache.put(id, topic_str, data, std.math.maxInt(u16));
        self.mcache.validate(id);
        const peers = if (self.state.subscribed(topic))
            self.state.mesh(topic)
        else
            self.fillFanout(topic, now);
        self.deliver(peers, topic_str, id, data, null);
        self.counters.messages_published += 1;
        return true;
    }

    /// Closes out a message the host validated. Accept forwards it to the mesh
    /// (minus the source and any peer that sent IDONTWANT); reject and ignore
    /// drop it, leaving it unvalidated so it is never gossiped.
    pub fn report(self: *Gossipsub, handle: MessageId, verdict: Verdict) void {
        if (verdict == .reject) {
            const source = self.mcache.sourceOf(handle) orelse return;
            const topic_str = self.mcache.topicOf(handle) orelse return;
            const topic = self.state.findTopic(topic_str) orelse return;
            self.scores.invalid(source, topic);
            return;
        }
        if (verdict == .ignore) return;
        self.mcache.validate(handle);
        const source = self.mcache.sourceOf(handle);
        const cached = self.mcache.get(handle, self.msg_scratch) orelse return;
        const topic = self.state.findTopic(cached.topic) orelse return;
        if (!self.state.subscribed(topic)) return;
        self.deliver(self.state.mesh(topic), cached.topic, handle, cached.data, source);
        self.counters.messages_forwarded += 1;
    }

    fn deliver(
        self: *Gossipsub,
        peers: *state_mod.PeerSet,
        topic_str: []const u8,
        id: MessageId,
        data: []const u8,
        source: ?u16,
    ) void {
        const publish_threshold = self.options.score_params.publish_threshold;
        var it = peers.iterator(.{});
        while (it.next()) |peer| {
            const index: u16 = @intCast(peer);
            if (source != null and index == source.?) continue;
            if (self.state.suppresses(index, id)) continue;
            if (!self.direct.isSet(index) and
                self.scores.score(index, self.last_now_ms) < publish_threshold) continue;
            if (!self.io[index].appendMessage(topic_str, data)) self.counters.send_dropped += 1;
        }
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

    pub fn pump(self: *Gossipsub, engine: *Engine, now: Now, events: []Event) usize {
        self.decompressed_used = 0;
        self.last_now_ms = now.mono_ms;
        var count: usize = 0;
        for (self.io, 0..) |*peer_io, index| {
            if (!self.state.peers[index].active) continue;
            count = self.readPeer(engine, @intCast(index), peer_io, now, events, count);
        }
        if (self.heartbeat_at == 0) {
            self.heartbeat_at = now.mono_ms + self.options.heartbeat_interval_ms;
        } else if (now.mono_ms >= self.heartbeat_at) {
            self.heartbeat(now);
            self.heartbeat_at = now.mono_ms + self.options.heartbeat_interval_ms;
        }
        for (self.io, 0..) |*peer_io, index| {
            if (self.state.peers[index].active) self.flush(engine, index, peer_io);
        }
        return count;
    }

    fn heartbeat(self: *Gossipsub, now: Now) void {
        self.scores.refresh(now.mono_ms);
        self.state.pruneBackoffs(now.mono_ms);
        for (&self.state.topics, 0..) |*topic, index| {
            if (topic.active and topic.subscribed) self.maintainTopic(@intCast(index), now);
        }
        if (self.opportunistic_at == 0) {
            self.opportunistic_at = now.mono_ms + self.options.opportunistic_graft_interval_ms;
        } else if (now.mono_ms >= self.opportunistic_at) {
            self.opportunistic_at = now.mono_ms + self.options.opportunistic_graft_interval_ms;
            for (&self.state.topics, 0..) |*topic, index| {
                if (topic.active and topic.subscribed) {
                    self.opportunisticGraft(@intCast(index), now);
                }
            }
        }
        for (&self.state.topics, 0..) |*topic, index| {
            if (topic.active and topic.subscribed) self.emitGossip(@intCast(index));
        }
        self.mcache.shift();
        self.expirePromises(now.mono_ms);
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
            if (self.state.backedOff(index, topic, now.mono_ms)) continue;
            if (self.scores.score(index, now.mono_ms) <= median) continue;
            mesh.set(peer);
            self.scores.graft(index, topic, now.mono_ms);
            self.queueGraft(index, topic_str);
            added += 1;
        }
    }

    fn emitGossip(self: *Gossipsub, topic: u16) void {
        const topic_str = self.state.topicString(topic);
        var ids: [constants.gossip_ids_max]MessageId = undefined;
        const n = self.mcache.gossip(topic_str, &ids);
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
            if (self.io[peer].append(rpc)) need -= 1 else self.counters.send_dropped += 1;
        }
    }

    fn addPromise(self: *Gossipsub, id: MessageId, peer: u16, expiry: u64) void {
        if (self.promise_len == self.promises.len) return;
        self.promises[self.promise_len] = .{ .id = id, .peer = peer, .expiry = expiry };
        self.promise_len += 1;
    }

    fn resolvePromises(self: *Gossipsub, id: MessageId) void {
        var index: usize = 0;
        while (index < self.promise_len) {
            if (std.mem.eql(u8, &self.promises[index].id, &id)) {
                self.promises[index] = self.promises[self.promise_len - 1];
                self.promise_len -= 1;
            } else index += 1;
        }
    }

    fn expirePromises(self: *Gossipsub, now_ms: u64) void {
        var index: usize = 0;
        while (index < self.promise_len) {
            if (now_ms >= self.promises[index].expiry) {
                self.counters.broken_promises += 1;
                self.scores.penalize(self.promises[index].peer, 1); // P7 behavioural
                self.promises[index] = self.promises[self.promise_len - 1];
                self.promise_len -= 1;
            } else index += 1;
        }
    }

    const Member = struct { peer: u16, sc: f64 };

    fn maintainTopic(self: *Gossipsub, topic: u16, now: Now) void {
        const topic_str = self.state.topicString(topic);
        const mesh = self.state.mesh(topic);

        // Direct peers are always in a shared mesh.
        var direct_it = self.direct.iterator(.{});
        while (direct_it.next()) |peer| {
            if (self.state.subscribers(topic).isSet(peer) and !mesh.isSet(peer)) {
                mesh.set(peer);
                self.scores.graft(@intCast(peer), topic, now.mono_ms);
                self.queueGraft(@intCast(peer), topic_str);
            }
        }

        // Prune mesh peers whose score went negative.
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
                if (self.state.backedOff(index, topic, now.mono_ms)) continue;
                if (self.scores.score(index, now.mono_ms) < 0) continue;
                mesh.set(peer);
                self.scores.graft(index, topic, now.mono_ms);
                self.queueGraft(index, topic_str);
                need -= 1;
            }
        } else if (size > constants.mesh_d_high) {
            count = self.meshMembers(topic, now, &members);
            std.sort.pdq(Member, members[0..count], {}, memberLess);
            const keep = constants.mesh_d;
            for (members[0 .. count - keep]) |member| {
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
        self.state.addBackoff(peer, topic, now.mono_ms + constants.prune_backoff_ms);
        self.queuePrune(peer, topic_str);
    }

    fn memberLess(_: void, a: Member, b: Member) bool {
        return a.sc < b.sc;
    }

    fn belowGossip(self: *Gossipsub, index: u16, now_ms: u64) bool {
        return self.scores.score(index, now_ms) < self.options.score_params.gossip_threshold;
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

    fn readPeer(
        self: *Gossipsub,
        engine: *Engine,
        index: u16,
        peer_io: *PeerIo,
        now: Now,
        events: []Event,
        start: usize,
    ) usize {
        var count = start;
        const stream = self.state.peers[index].in_stream orelse return count;
        var reads: u32 = 0;
        while (reads < constants.reads_per_pump_max) : (reads += 1) {
            const read = engine.read(stream, self.scratch) catch return count;
            if (read.len == 0 and !read.fin) return count;
            var chunk = self.scratch[0..read.len];
            while (chunk.len > 0) {
                const body = self.frameBody(peer_io);
                const result = peer_io.reader.feed(chunk, body) catch {
                    self.counters.malformed_rpcs += 1;
                    self.releaseLarge(peer_io);
                    peer_io.reader = .{};
                    return count;
                };
                chunk = chunk[result.consumed..];
                if (result.frame) |rpc| {
                    count = self.processRpc(index, rpc, now, events, count);
                    self.releaseLarge(peer_io);
                }
                if (result.consumed == 0) break;
            }
            if (read.fin) return count;
        }
        return count;
    }

    /// Picks the buffer to accumulate the current inbound frame into: the small
    /// per-peer buffer normally, a claimed pool buffer for a larger frame, and
    /// switches the reader to discard mode for a frame too large to hold.
    fn frameBody(self: *Gossipsub, peer_io: *PeerIo) []u8 {
        if (peer_io.reader.isDiscarding()) return peer_io.body;
        if (peer_io.large_slot) |slot| return self.largeBuffer(slot);
        const declared = peer_io.reader.declaredLen() orelse return peer_io.body;
        if (declared <= peer_io.body.len) return peer_io.body;
        if (declared > self.options.large_message_bytes) {
            peer_io.reader.discard();
            self.counters.oversized_dropped += 1;
            return peer_io.body;
        }
        if (self.claimLarge()) |slot| {
            peer_io.large_slot = slot;
            return self.largeBuffer(slot);
        }
        peer_io.reader.discard();
        self.counters.oversized_dropped += 1;
        return peer_io.body;
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
        }
    }

    fn processRpc(
        self: *Gossipsub,
        index: u16,
        rpc: []const u8,
        now: Now,
        events: []Event,
        start: usize,
    ) usize {
        var count = start;
        self.counters.rpcs_received += 1;
        // graylist: drop RPCs from a peer whose score is too low to trust
        const graylisted = !self.direct.isSet(index) and
            self.scores.score(index, now.mono_ms) < self.options.score_params.graylist_threshold;
        if (graylisted) return count;
        var subs: usize = 0;
        var msgs: usize = 0;
        var control: usize = 0;
        var reader = protobuf.RpcReader.init(rpc);
        while (reader.next() catch {
            self.counters.malformed_rpcs += 1;
            return count;
        }) |item| {
            switch (item) {
                .subscription => |sub| {
                    if (subs >= constants.max_subscriptions_per_rpc) continue;
                    subs += 1;
                    count = self.onSubscription(index, sub, events, count);
                },
                .message => |msg| {
                    if (msgs >= constants.max_publish_per_rpc) continue;
                    msgs += 1;
                    count = self.onMessage(index, msg, now, events, count);
                },
                else => {
                    if (control >= constants.max_control_per_rpc) continue;
                    control += 1;
                    switch (item) {
                        .ihave => |ihave| self.onIhave(index, ihave, now),
                        .iwant => |iwant| self.onIwant(index, iwant),
                        .graft => |topic_str| self.onGraft(index, topic_str, now),
                        .prune => |prune| self.onPrune(index, prune, now),
                        .idontwant => |idontwant| self.onIdontwant(index, idontwant),
                        else => unreachable,
                    }
                },
            }
        }
        return count;
    }

    fn onMessage(
        self: *Gossipsub,
        index: u16,
        msg: protobuf.Message,
        now: Now,
        events: []Event,
        start: usize,
    ) usize {
        if (msg.signed) return start; // StrictNoSign violation
        if (msg.data.len > constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE)) return start;
        const topic = self.state.findTopic(msg.topic) orelse return start;
        if (!self.state.subscribed(topic)) return start;
        const size = snappy.raw.uncompressedLength(msg.data) catch {
            _ = self.seen.add(topic_mod.invalidMessageId(msg.data), now.mono_ms);
            return start;
        };
        if (size > constants.MAX_PAYLOAD_SIZE) return start;
        const room = self.decompressed[self.decompressed_used..];
        if (size > room.len) {
            self.counters.arena_full += 1;
            return start;
        }
        const written = snappy.raw.uncompress(msg.data, room[0..size]) catch {
            _ = self.seen.add(topic_mod.invalidMessageId(msg.data), now.mono_ms);
            return start;
        };
        const payload = room[0..written];
        const id = topic_mod.validMessageId(payload);
        if (!self.seen.add(id, now.mono_ms)) {
            self.counters.duplicates += 1;
            self.scores.duplicate(index, topic);
            return start;
        }
        self.decompressed_used += written;
        self.counters.messages_received += 1;
        self.scores.deliver(index, topic);
        self.resolvePromises(id);
        _ = self.mcache.put(id, self.state.topicString(topic), msg.data, index);
        if (written >= constants.idontwant_size_threshold) {
            self.broadcastIdontwant(topic, id, index);
        }
        if (start >= events.len) return start;
        events[start] = .{ .message = .{
            .handle = id,
            .peer = self.state.peers[index].conn,
            .topic = self.state.topicString(topic),
            .bytes = payload,
        } };
        return start + 1;
    }

    fn onIhave(self: *Gossipsub, index: u16, ihave: protobuf.IHave, now: Now) void {
        if (self.belowGossip(index, now.mono_ms)) return;
        var wanted: [constants.gossip_ids_max]MessageId = undefined;
        var count: usize = 0;
        var it = ihave.ids();
        while (it.next() catch return) |id_bytes| {
            if (count == wanted.len) break;
            if (id_bytes.len != constants.message_id_length) continue;
            const id: MessageId = id_bytes[0..constants.message_id_length].*;
            if (self.seen.contains(id)) continue;
            wanted[count] = id;
            count += 1;
            self.addPromise(id, index, now.mono_ms + constants.iwant_followup_ms);
        }
        if (count == 0) return;
        var writer = protobuf.Writer.init(self.msg_scratch);
        writer.varint(protobuf.iwantRpcSize(count, constants.message_id_length));
        protobuf.beginIwantRpc(&writer, count, constants.message_id_length);
        for (wanted[0..count]) |id| protobuf.writeIwantId(&writer, &id);
        if (self.io[index].append(writer.written())) {
            self.counters.iwant_sent += 1;
        } else self.counters.send_dropped += 1;
    }

    fn onIwant(self: *Gossipsub, index: u16, iwant: protobuf.IdList) void {
        if (self.belowGossip(index, self.last_now_ms)) return;
        var served: u8 = 0;
        var it = iwant.ids();
        while (it.next() catch return) |id_bytes| {
            if (served >= constants.gossip_retransmission) break;
            if (id_bytes.len != constants.message_id_length) continue;
            const id: MessageId = id_bytes[0..constants.message_id_length].*;
            if (!self.mcache.isValidated(id)) continue;
            const cached = self.mcache.get(id, self.msg_scratch) orelse continue;
            if (self.io[index].appendMessage(cached.topic, cached.data)) {
                served += 1;
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
            if (!self.io[peer_index].append(rpc)) self.counters.send_dropped += 1;
        }
    }

    fn onIdontwant(self: *Gossipsub, index: u16, idontwant: protobuf.IdList) void {
        var it = idontwant.ids();
        while (it.next() catch return) |id_bytes| {
            if (id_bytes.len != constants.message_id_length) continue;
            self.state.suppress(index, id_bytes[0..constants.message_id_length].*);
        }
    }

    fn onGraft(self: *Gossipsub, index: u16, topic_str: []const u8, now: Now) void {
        const topic = self.state.findTopic(topic_str) orelse return;
        if (!self.state.subscribed(topic)) return; // unknown/unsubscribed topic: ignore
        if (self.state.backedOff(index, topic, now.mono_ms)) {
            self.scores.penalize(index, 1); // GRAFT before the backoff expired
            self.queuePrune(index, self.state.topicString(topic));
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
        self.state.setSubscription(topic, index, sub.subscribe);
        if (start >= events.len) return start;
        events[start] = .{ .subscription_change = .{
            .peer = self.state.peers[index].conn,
            .topic = self.state.topicString(topic),
            .subscribed = sub.subscribe,
        } };
        return start + 1;
    }

    fn queueGraft(self: *Gossipsub, index: u16, topic_str: []const u8) void {
        var buf: [control_frame_max]u8 = undefined;
        var writer = protobuf.Writer.init(&buf);
        writer.varint(protobuf.graftRpcSize(topic_str));
        protobuf.writeGraftRpc(&writer, topic_str);
        if (!self.io[index].append(writer.written())) self.counters.send_dropped += 1;
    }

    fn queuePrune(self: *Gossipsub, index: u16, topic_str: []const u8) void {
        const backoff_s = constants.prune_backoff_ms / 1000;
        var buf: [control_frame_max]u8 = undefined;
        var writer = protobuf.Writer.init(&buf);
        writer.varint(protobuf.pruneRpcSize(topic_str, backoff_s));
        protobuf.writePruneRpc(&writer, topic_str, backoff_s);
        if (!self.io[index].append(writer.written())) self.counters.send_dropped += 1;
    }

    fn flush(self: *Gossipsub, engine: *Engine, index: usize, peer_io: *PeerIo) void {
        const stream = self.state.peers[index].out_stream orelse return;
        while (peer_io.send_tail < peer_io.send_head) {
            const written = engine.write(stream, peer_io.pending(), false) catch return;
            if (written == 0) return;
            peer_io.send_tail += written;
        }
        peer_io.send_tail = 0;
        peer_io.send_head = 0;
    }
};
