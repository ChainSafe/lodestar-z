const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");

const assert = std.debug.assert;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const MessageId = [constants.message_id_length]u8;
pub const PeerSet = std.StaticBitSet(constants.peers_cap);

pub const Version = enum(u8) { v1_0, v1_1, v1_2 };

pub const PeerHandle = struct { index: u16, generation: u32 };

/// One gossip peer, keyed by its transport connection. Its subscriptions and
/// mesh membership live in the topic table as per-topic peer sets; the peer row
/// holds the connection, protocol version, the two directional streams, and the
/// bounded set of message ids the peer has asked us not to send.
const Peer = struct {
    active: bool = false,
    generation: u32 = 0,
    conn: Handle = undefined,
    version: Version = .v1_0,
    out_stream: ?StreamHandle = null,
    in_stream: ?StreamHandle = null,
    dont_send: [constants.dont_send_cap]MessageId = undefined,
    dont_send_head: u8 = 0,
    dont_send_len: u8 = 0,

    fn suppresses(self: *const Peer, id: MessageId) bool {
        for (0..self.dont_send_len) |offset| {
            const at = (@as(usize, self.dont_send_head) + constants.dont_send_cap - 1 - offset) %
                constants.dont_send_cap;
            if (std.mem.eql(u8, &self.dont_send[at], &id)) return true;
        }
        return false;
    }

    fn suppress(self: *Peer, id: MessageId) void {
        if (self.suppresses(id)) return;
        self.dont_send[self.dont_send_head] = id;
        self.dont_send_head = @intCast((self.dont_send_head + 1) % constants.dont_send_cap);
        if (self.dont_send_len < constants.dont_send_cap) self.dont_send_len += 1;
    }
};

const Topic = struct {
    active: bool = false,
    subscribed: bool = false,
    name: [topic_mod.name_max_len]u8 = undefined,
    name_len: u8 = 0,
    string: [topic_mod.topic_max_len]u8 = undefined,
    string_len: u8 = 0,
    subscribers: PeerSet = PeerSet.initEmpty(),
    mesh: PeerSet = PeerSet.initEmpty(),
    fanout: PeerSet = PeerSet.initEmpty(),
    fanout_last_ms: u64 = 0,

    fn topicString(self: *const Topic) []const u8 {
        return self.string[0..self.string_len];
    }
};

const Backoff = struct {
    peer: u16,
    topic: u16,
    until_ms: u64,
};

pub const State = struct {
    peers: [constants.peers_cap]Peer = [_]Peer{.{}} ** constants.peers_cap,
    topics: [constants.topics_cap]Topic = [_]Topic{.{}} ** constants.topics_cap,
    backoffs: [constants.backoffs_cap]Backoff = undefined,
    backoff_len: usize = 0,

    // Peers ------------------------------------------------------------------

    pub fn addPeer(self: *State, conn: Handle, version: Version) ?PeerHandle {
        const index = self.freePeer() orelse return null;
        const peer = &self.peers[index];
        peer.* = .{
            .active = true,
            .generation = peer.generation +% 1,
            .conn = conn,
            .version = version,
        };
        return .{ .index = @intCast(index), .generation = peer.generation };
    }

    pub fn removePeer(self: *State, index: u16) void {
        assert(index < constants.peers_cap);
        if (!self.peers[index].active) return;
        for (&self.topics) |*topic| {
            if (!topic.active) continue;
            topic.subscribers.unset(index);
            topic.mesh.unset(index);
            topic.fanout.unset(index);
        }
        self.dropBackoffs(index);
        self.peers[index].active = false;
    }

    pub fn findPeer(self: *State, conn: Handle) ?u16 {
        for (&self.peers, 0..) |*peer, index| {
            if (peer.active and std.meta.eql(peer.conn, conn)) return @intCast(index);
        }
        return null;
    }

    pub fn peerVersion(self: *const State, index: u16) Version {
        assert(self.peers[index].active);
        return self.peers[index].version;
    }

    pub fn setVersion(self: *State, index: u16, version: Version) void {
        assert(self.peers[index].active);
        self.peers[index].version = version;
    }

    pub fn peerGeneration(self: *const State, index: u16) u32 {
        return self.peers[index].generation;
    }

    /// Whether `index` still holds the same peer as when `generation` was taken.
    pub fn peerMatches(self: *const State, index: u16, generation: u32) bool {
        return self.peers[index].active and self.peers[index].generation == generation;
    }

    pub fn setStreams(self: *State, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        assert(self.peers[index].active);
        if (out) |stream| self.peers[index].out_stream = stream;
        if (in) |stream| self.peers[index].in_stream = stream;
    }

    pub fn outStream(self: *const State, index: u16) ?StreamHandle {
        return self.peers[index].out_stream;
    }

    pub fn suppress(self: *State, index: u16, id: MessageId) void {
        assert(self.peers[index].active);
        self.peers[index].suppress(id);
    }

    pub fn suppresses(self: *const State, index: u16, id: MessageId) bool {
        return self.peers[index].active and self.peers[index].suppresses(id);
    }

    fn freePeer(self: *State) ?usize {
        for (&self.peers, 0..) |*peer, index| {
            if (!peer.active) return index;
        }
        return null;
    }

    // Topics -----------------------------------------------------------------

    pub fn internTopic(self: *State, topic_str: []const u8) ?u16 {
        if (topic_str.len > topic_mod.topic_max_len) return null;
        const parsed = topic_mod.parse(topic_str) orelse return null;
        if (self.findTopic(topic_str)) |index| return index;
        const index = self.freeTopic() orelse return null;
        const topic = &self.topics[index];
        topic.* = .{ .active = true };
        @memcpy(topic.name[0..parsed.name.len], parsed.name);
        topic.name_len = @intCast(parsed.name.len);
        @memcpy(topic.string[0..topic_str.len], topic_str);
        topic.string_len = @intCast(topic_str.len);
        return @intCast(index);
    }

    pub fn findTopic(self: *State, topic_str: []const u8) ?u16 {
        for (&self.topics, 0..) |*topic, index| {
            if (!topic.active) continue;
            if (std.mem.eql(u8, topic.topicString(), topic_str)) return @intCast(index);
        }
        return null;
    }

    pub fn topicString(self: *const State, index: u16) []const u8 {
        return self.topics[index].topicString();
    }

    pub fn setSubscribed(self: *State, index: u16, on: bool) void {
        assert(self.topics[index].active);
        self.topics[index].subscribed = on;
    }

    pub fn subscribed(self: *const State, index: u16) bool {
        return self.topics[index].active and self.topics[index].subscribed;
    }

    pub fn setSubscription(self: *State, topic: u16, peer: u16, on: bool) void {
        assert(self.topics[topic].active);
        if (on) self.topics[topic].subscribers.set(peer) else {
            self.topics[topic].subscribers.unset(peer);
            self.topics[topic].mesh.unset(peer);
            self.topics[topic].fanout.unset(peer);
        }
    }

    pub fn subscribers(self: *const State, topic: u16) *const PeerSet {
        return &self.topics[topic].subscribers;
    }

    pub fn mesh(self: *State, topic: u16) *PeerSet {
        return &self.topics[topic].mesh;
    }

    pub fn fanout(self: *State, topic: u16) *PeerSet {
        return &self.topics[topic].fanout;
    }

    fn freeTopic(self: *State) ?usize {
        for (&self.topics, 0..) |*topic, index| {
            if (!topic.active) return index;
        }
        return null;
    }

    // Backoff ----------------------------------------------------------------

    pub fn addBackoff(self: *State, peer: u16, topic: u16, until_ms: u64) void {
        for (self.backoffs[0..self.backoff_len]) |*entry| {
            if (entry.peer == peer and entry.topic == topic) {
                entry.until_ms = @max(entry.until_ms, until_ms);
                return;
            }
        }
        const fresh: Backoff = .{ .peer = peer, .topic = topic, .until_ms = until_ms };
        if (self.backoff_len < self.backoffs.len) {
            self.backoffs[self.backoff_len] = fresh;
            self.backoff_len += 1;
            return;
        }
        // Full: replace the soonest-to-expire entry so the newest backoff is kept
        // and no single peer can deny backoff tracking to the others.
        var min: usize = 0;
        for (self.backoffs[0..self.backoff_len], 0..) |entry, i| {
            if (entry.until_ms < self.backoffs[min].until_ms) min = i;
        }
        if (until_ms > self.backoffs[min].until_ms) self.backoffs[min] = fresh;
    }

    pub fn backedOff(self: *const State, peer: u16, topic: u16, now_ms: u64) bool {
        for (self.backoffs[0..self.backoff_len]) |entry| {
            if (entry.peer == peer and entry.topic == topic) return now_ms < entry.until_ms;
        }
        return false;
    }

    pub fn pruneBackoffs(self: *State, now_ms: u64) void {
        var index: usize = 0;
        while (index < self.backoff_len) {
            if (now_ms >= self.backoffs[index].until_ms) {
                self.backoffs[index] = self.backoffs[self.backoff_len - 1];
                self.backoff_len -= 1;
            } else index += 1;
        }
    }

    fn dropBackoffs(self: *State, peer: u16) void {
        var index: usize = 0;
        while (index < self.backoff_len) {
            if (self.backoffs[index].peer == peer) {
                self.backoffs[index] = self.backoffs[self.backoff_len - 1];
                self.backoff_len -= 1;
            } else index += 1;
        }
    }
};

test "state tracks peers, topics, subscriptions, and mesh membership" {
    var state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);
    state.* = .{};
    const conn = Handle{ .index = 3, .generation = 1 };
    const peer = state.addPeer(conn, .v1_2).?;
    try std.testing.expectEqual(@as(?u16, peer.index), state.findPeer(conn));
    try std.testing.expectEqual(Version.v1_2, state.peerVersion(peer.index));

    const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const topic_str = topic_mod.build(digest, "beacon_block", &buf);
    const topic = state.internTopic(topic_str).?;
    try std.testing.expectEqual(@as(?u16, topic), state.internTopic(topic_str)); // interns once
    state.setSubscribed(topic, true);
    try std.testing.expect(state.subscribed(topic));

    state.setSubscription(topic, peer.index, true);
    try std.testing.expect(state.subscribers(topic).isSet(peer.index));
    state.mesh(topic).set(peer.index);
    try std.testing.expect(state.mesh(topic).isSet(peer.index));

    state.removePeer(peer.index);
    try std.testing.expect(!state.subscribers(topic).isSet(peer.index));
    try std.testing.expect(!state.mesh(topic).isSet(peer.index));
    try std.testing.expectEqual(@as(?u16, null), state.findPeer(conn));
}

test "state suppresses ids per peer and tracks backoff" {
    var state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);
    state.* = .{};
    const peer = state.addPeer(.{ .index = 1, .generation = 1 }, .v1_2).?;
    const id = [_]u8{7} ** 20;
    try std.testing.expect(!state.suppresses(peer.index, id));
    state.suppress(peer.index, id);
    try std.testing.expect(state.suppresses(peer.index, id));

    state.addBackoff(peer.index, 0, 1_000);
    try std.testing.expect(state.backedOff(peer.index, 0, 500));
    try std.testing.expect(!state.backedOff(peer.index, 0, 1_000));
    state.pruneBackoffs(1_000);
    try std.testing.expect(!state.backedOff(peer.index, 0, 500));
}
