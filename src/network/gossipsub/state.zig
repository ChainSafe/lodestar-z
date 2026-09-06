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

pub const PeerHandle = struct { index: u16, generation: u64 };

/// One gossip peer, keyed by its transport connection. Its subscriptions and
/// mesh membership live in the topic table as per-topic peer sets; the peer row
/// holds the connection, protocol version, the two directional streams, and the
/// bounded set of message ids the peer has asked us not to send.
const Peer = struct {
    logical: @import("peers.zig").Ref = undefined,
    active: bool = false,
    generation: u64 = 0,
    conn: Handle = undefined,
    version: Version = .v1_0,
    inbound_version: Version = .v1_0,
    out_stream: ?StreamHandle = null,
    in_stream: ?StreamHandle = null,
    dont_send: [constants.dont_send_cap]MessageId = undefined,
    dont_send_until: [constants.dont_send_cap]u64 = undefined,
    dont_send_head: u8 = 0,
    dont_send_len: u8 = 0,

    fn suppresses(self: *const Peer, id: MessageId, now: u64) bool {
        for (0..self.dont_send_len) |offset| {
            const at = (@as(usize, self.dont_send_head) + constants.dont_send_cap - 1 - offset) %
                constants.dont_send_cap;
            if (now < self.dont_send_until[at] and std.mem.eql(u8, &self.dont_send[at], &id)) return true;
        }
        return false;
    }

    fn suppress(self: *Peer, id: MessageId, now: u64, ttl: u64) void {
        if (self.suppresses(id, now)) return;
        self.dont_send[self.dont_send_head] = id;
        self.dont_send_until[self.dont_send_head] = now +| ttl;
        self.dont_send_head = @intCast((self.dont_send_head + 1) % constants.dont_send_cap);
        if (self.dont_send_len < constants.dont_send_cap) self.dont_send_len += 1;
    }
};

const Topic = struct {
    retire_after_ms: ?u64 = null,
    generation: u64 = 0,
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

pub const State = struct {
    peers: []Peer,
    topics: [constants.topics_cap]Topic = [_]Topic{.{}} ** constants.topics_cap,

    pub fn init(a: std.mem.Allocator, capacity: u16) !State {
        if (capacity == 0 or capacity > constants.peers_cap) return error.InvalidLimits;
        const rows = try a.alloc(Peer, capacity);
        @memset(rows, .{});
        return .{ .peers = rows };
    }

    pub fn deinit(self: *State, a: std.mem.Allocator) void {
        a.free(self.peers);
    }

    // Peers ------------------------------------------------------------------

    pub fn addPeer(self: *State, conn: Handle, version: Version) ?PeerHandle {
        const index = self.freePeer() orelse return null;
        const peer = &self.peers[index];
        peer.* = .{
            .active = true,
            .generation = peer.generation + 1,
            .conn = conn,
            .version = version,
        };
        return .{ .index = @intCast(index), .generation = peer.generation };
    }

    pub fn removePeer(self: *State, index: u16) void {
        assert(index < self.peers.len);
        if (!self.peers[index].active) return;
        for (&self.topics) |*topic| {
            if (!topic.active) continue;
            topic.subscribers.unset(index);
            topic.mesh.unset(index);
            topic.fanout.unset(index);
        }
        self.peers[index].active = false;
    }

    pub fn findPeer(self: *State, conn: Handle) ?u16 {
        for (self.peers, 0..) |*peer, index| {
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

    pub fn peerGeneration(self: *const State, index: u16) u64 {
        return self.peers[index].generation;
    }

    /// Whether `index` still holds the same peer as when `generation` was taken.
    pub fn peerMatches(self: *const State, index: u16, generation: u64) bool {
        return index < self.peers.len and self.peers[index].active and self.peers[index].generation == generation;
    }

    pub fn setStreams(self: *State, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        assert(self.peers[index].active);
        if (out) |stream| self.peers[index].out_stream = stream;
        if (in) |stream| self.peers[index].in_stream = stream;
    }

    pub fn outStream(self: *const State, index: u16) ?StreamHandle {
        return self.peers[index].out_stream;
    }

    pub fn suppress(self: *State, index: u16, id: MessageId, now: u64, ttl: u64) void {
        assert(self.peers[index].active);
        self.peers[index].suppress(id, now, ttl);
    }

    pub fn suppresses(self: *const State, index: u16, id: MessageId, now: u64) bool {
        return self.peers[index].active and self.peers[index].suppresses(id, now);
    }

    fn freePeer(self: *State) ?usize {
        for (self.peers, 0..) |*peer, index| {
            if (!peer.active and peer.generation != std.math.maxInt(u64)) return index;
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
        topic.* = .{ .active = true, .generation = topic.generation + 1 };
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
            if (!topic.active and topic.generation != std.math.maxInt(u64)) return index;
        }
        return null;
    }
};

test "state tracks peers, topics, subscriptions, and mesh membership" {
    var state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);
    state.* = try State.init(std.testing.allocator, constants.peers_cap);
    defer state.deinit(std.testing.allocator);
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

test "state suppresses ids per peer until monotonic expiry" {
    var state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);
    state.* = try State.init(std.testing.allocator, constants.peers_cap);
    defer state.deinit(std.testing.allocator);
    const peer = state.addPeer(.{ .index = 1, .generation = 1 }, .v1_2).?;
    const id = [_]u8{7} ** 20;
    try std.testing.expect(!state.suppresses(peer.index, id, 0));
    state.suppress(peer.index, id, 0, 10);
    try std.testing.expect(!state.suppresses(peer.index, id, 10));
    try std.testing.expect(state.suppresses(peer.index, id, 0));
}

test "gossip policy topic capacity supports two full fork subnet sets" {
    const names = @import("topics.zig");
    var gossip = try @import("gossipsub.zig").Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer gossip.deinit();
    const state = gossip.state;
    var name: [topic_mod.name_max_len]u8 = undefined;
    var buffer: [topic_mod.topic_max_len]u8 = undefined;
    for (0..3) |fork| {
        if (fork == 2) {
            for (&state.topics, 0..) |*topic, index| {
                if (topic.active and std.mem.startsWith(u8, state.topicString(@intCast(index)), "/eth2/00000000/")) {
                    try std.testing.expect(gossip.unsubscribe(state.topicString(@intCast(index))));
                }
            }
        }
        const digest: topic_mod.ForkDigest = .{ @intCast(fork), 0, 0, 0 };
        for (0..names.attestation_subnet_count) |subnet| {
            try std.testing.expect(gossip.subscribe(topic_mod.build(digest, names.attestationSubnet(subnet, &name), &buffer)));
        }
        for (0..128) |subnet| {
            try std.testing.expect(gossip.subscribe(topic_mod.build(digest, names.dataColumnSubnet(subnet, &name), &buffer)));
        }
        for (0..names.sync_committee_subnet_count) |subnet| {
            try std.testing.expect(gossip.subscribe(topic_mod.build(digest, names.syncCommitteeSubnet(subnet, &name), &buffer)));
        }
        for ([_][]const u8{ names.beacon_block, names.beacon_aggregate_and_proof, names.voluntary_exit, names.proposer_slashing, names.attester_slashing, names.bls_to_execution_change, names.sync_committee_contribution_and_proof, names.light_client_finality_update, names.light_client_optimistic_update }) |n| {
            try std.testing.expect(gossip.subscribe(topic_mod.build(digest, n, &buffer)));
        }
    }
    try std.testing.expect(state.findTopic("/eth2/00000000/beacon_block/ssz_snappy") == null);
    try std.testing.expect(state.findTopic("/eth2/01000000/beacon_block/ssz_snappy") != null);
    try std.testing.expect(state.findTopic("/eth2/02000000/beacon_block/ssz_snappy") != null);
}
