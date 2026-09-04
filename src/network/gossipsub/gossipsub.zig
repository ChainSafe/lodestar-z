const std = @import("std");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const topic_mod = @import("topic.zig");
const frame_mod = @import("frame.zig");
const mcache_mod = @import("mcache.zig");
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
    seen_ttl_ms: u64 = constants.seenTtlMs(32, 12),
};

pub const InitError = Allocator.Error;

pub const Event = union(enum) {
    /// A new message the host must validate and then close out with `report`.
    message: struct { peer: Handle, topic: []const u8, bytes: []const u8 },
    subscription_change: struct { peer: Handle, topic: []const u8, subscribed: bool },
};

/// Per-peer stream I/O: a linear send buffer that batches outgoing RPCs and the
/// resumable framing state for the inbound stream.
const sub_frame_max = 16 + topic_mod.topic_max_len;
const control_frame_max = 32 + topic_mod.topic_max_len;

const PeerIo = struct {
    send: []u8,
    send_head: usize = 0,
    send_tail: usize = 0,
    reader: frame_mod.Reader = .{},
    body: []u8,

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
};

pub const Gossipsub = struct {
    allocator: Allocator,
    options: Options,
    state: *State,
    seen: mcache_mod.SeenCache,
    mcache: mcache_mod.MessageCache,
    io: []PeerIo,
    io_arena: []u8,
    heartbeat_at: u64 = 0,
    scratch: []u8,
    counters: Counters = .{},

    pub const Counters = struct {
        messages_received: u64 = 0,
        messages_published: u64 = 0,
        rpcs_received: u64 = 0,
        send_dropped: u64 = 0,
        malformed_rpcs: u64 = 0,
    };

    pub fn init(allocator: Allocator, options: Options) InitError!Gossipsub {
        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.* = .{};

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

        const per_peer = constants.send_buffer_len + constants.body_buffer_len;
        const io_arena = try allocator.alloc(u8, constants.peers_cap * per_peer);
        errdefer allocator.free(io_arena);
        const io = try allocator.alloc(PeerIo, constants.peers_cap);
        errdefer allocator.free(io);
        for (io, 0..) |*slot, index| {
            const base = index * per_peer;
            slot.* = .{
                .send = io_arena[base..][0..constants.send_buffer_len],
                .body = io_arena[base + constants.send_buffer_len ..][0..constants.body_buffer_len],
            };
        }
        const scratch = try allocator.alloc(u8, constants.read_scratch_len);
        errdefer allocator.free(scratch);

        return .{
            .allocator = allocator,
            .options = options,
            .state = state,
            .seen = seen,
            .mcache = mcache,
            .io = io,
            .io_arena = io_arena,
            .scratch = scratch,
        };
    }

    pub fn deinit(self: *Gossipsub) void {
        self.allocator.free(self.scratch);
        self.allocator.free(self.io);
        self.allocator.free(self.io_arena);
        self.mcache.deinit(self.allocator);
        self.seen.deinit(self.allocator);
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
        self.io[handle.index].reset();
        self.sendSubscriptions(handle.index);
        return handle;
    }

    pub fn setStreams(self: *Gossipsub, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        self.state.setStreams(index, out, in);
    }

    pub fn connectionClosed(self: *Gossipsub, conn: Handle) void {
        const index = self.state.findPeer(conn) orelse return;
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

    // Pump -------------------------------------------------------------------

    pub fn pump(self: *Gossipsub, engine: *Engine, now: Now, events: []Event) usize {
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
        self.state.pruneBackoffs(now.mono_ms);
        for (&self.state.topics, 0..) |*topic, index| {
            if (topic.active and topic.subscribed) self.maintainTopic(@intCast(index), now);
        }
        self.mcache.shift();
    }

    fn maintainTopic(self: *Gossipsub, topic: u16, now: Now) void {
        const topic_str = self.state.topicString(topic);
        const mesh = self.state.mesh(topic);
        const count = mesh.count();
        if (count < constants.mesh_d_low) {
            var need = constants.mesh_d - count;
            var it = self.state.subscribers(topic).iterator(.{});
            while (it.next()) |peer| {
                if (need == 0) break;
                if (mesh.isSet(peer)) continue;
                if (self.state.backedOff(@intCast(peer), topic, now.mono_ms)) continue;
                mesh.set(peer);
                self.queueGraft(@intCast(peer), topic_str);
                need -= 1;
            }
        } else if (count > constants.mesh_d_high) {
            const excess = count - constants.mesh_d;
            var victims: [constants.peers_cap]u16 = undefined;
            var found: usize = 0;
            var it = mesh.iterator(.{});
            while (it.next()) |peer| {
                if (found == excess) break;
                victims[found] = @intCast(peer);
                found += 1;
            }
            for (victims[0..found]) |peer| {
                mesh.unset(peer);
                self.state.addBackoff(peer, topic, now.mono_ms + constants.prune_backoff_ms);
                self.queuePrune(peer, topic_str);
            }
        }
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
                const result = peer_io.reader.feed(chunk, peer_io.body) catch {
                    self.counters.malformed_rpcs += 1;
                    peer_io.reader = .{};
                    return count;
                };
                chunk = chunk[result.consumed..];
                if (result.frame) |rpc| count = self.processRpc(index, rpc, now, events, count);
                if (result.consumed == 0) break;
            }
            if (read.fin) return count;
        }
        return count;
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
        var reader = protobuf.RpcReader.init(rpc);
        while (reader.next() catch {
            self.counters.malformed_rpcs += 1;
            return count;
        }) |item| {
            switch (item) {
                .subscription => |sub| count = self.onSubscription(index, sub, events, count),
                .graft => |topic_str| self.onGraft(index, topic_str, now),
                .prune => |prune| self.onPrune(index, prune, now),
                else => {}, // messages and gossip land in later slices
            }
        }
        return count;
    }

    fn onGraft(self: *Gossipsub, index: u16, topic_str: []const u8, now: Now) void {
        const topic = self.state.findTopic(topic_str) orelse return;
        if (!self.state.subscribed(topic)) return; // unknown/unsubscribed topic: ignore
        if (self.state.backedOff(index, topic, now.mono_ms)) {
            self.queuePrune(index, self.state.topicString(topic));
            return;
        }
        self.state.mesh(topic).set(index);
    }

    fn onPrune(self: *Gossipsub, index: u16, prune: protobuf.Prune, now: Now) void {
        const topic = self.state.findTopic(prune.topic) orelse return;
        self.state.mesh(topic).unset(index);
        const backoff_ms = if (prune.backoff > 0)
            prune.backoff * 1000
        else
            constants.prune_backoff_ms;
        self.state.addBackoff(index, topic, now.mono_ms + backoff_ms);
    }

    fn onSubscription(
        self: *Gossipsub,
        index: u16,
        sub: protobuf.SubOpts,
        events: []Event,
        start: usize,
    ) usize {
        const topic = self.state.internTopic(sub.topic) orelse return start;
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
