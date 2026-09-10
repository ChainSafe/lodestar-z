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

const Session = @import("peer_session.zig").Session;

pub const State = struct {
    peers: []Session,
    io_arena: []u8,

    pub fn init(a: std.mem.Allocator, capacity: u16) !State {
        return initOptions(a, &.{ .connected_capacity = capacity });
    }

    pub fn initOptions(a: std.mem.Allocator, options: *const @import("options.zig").Options) !State {
        if (options.connected_capacity == 0 or options.connected_capacity > constants.peers_cap) return error.InvalidLimits;
        const PeerIo = @import("peer_io.zig").PeerIo;
        const rows = try a.alloc(Session, options.connected_capacity);
        errdefer a.free(rows);
        const per_peer = PeerIo.bufferBytes(options);
        const arena = try a.alloc(u8, rows.len * per_peer);
        for (rows, 0..) |*row, i| row.* = .{ .io = PeerIo.init(arena[i * per_peer ..][0..per_peer], options) };
        return .{ .peers = rows, .io_arena = arena };
    }

    pub fn deinit(self: *State, a: std.mem.Allocator) void {
        a.free(self.peers);
        a.free(self.io_arena);
    }

    // Peers ------------------------------------------------------------------

    pub fn addPeer(self: *State, conn: Handle, version: Version) ?PeerHandle {
        const index = self.freePeer() orelse return null;
        const peer = &self.peers[index];
        assert(peer.io.data_count == 0 and peer.io.large_slot == null);
        peer.active = true;
        peer.generation += 1;
        peer.conn = conn;
        peer.version = version;
        peer.inbound_version = .v1_0;
        peer.in_stream = null;
        peer.outbound = .{ .waiting = 0 };
        peer.failures = 0;
        peer.needs_service = false;
        peer.dont_send_head = 0;
        peer.dont_send_len = 0;
        return .{ .index = @intCast(index), .generation = peer.generation };
    }

    pub fn removePeer(self: *State, index: u16) void {
        assert(index < self.peers.len);
        if (!self.peers[index].active) return;
        self.peers[index].active = false;
        self.peers[index].outbound = .{ .waiting = 0 };
        self.peers[index].in_stream = null;
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
        if (out) |stream| self.peers[index].outbound = .{ .live = stream };
        if (in) |stream| self.peers[index].in_stream = stream;
    }

    pub fn outStream(self: *const State, index: u16) ?StreamHandle {
        return self.peers[index].outStream();
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
};

test "session slots track connection generations" {
    var state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);
    state.* = try State.init(std.testing.allocator, constants.peers_cap);
    defer state.deinit(std.testing.allocator);
    const conn = Handle{ .index = 3, .generation = 1 };
    const peer = state.addPeer(conn, .v1_2).?;
    try std.testing.expectEqual(@as(?u16, peer.index), state.findPeer(conn));
    try std.testing.expectEqual(Version.v1_2, state.peerVersion(peer.index));

    state.removePeer(peer.index);
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
    const overlay = gossip.overlay;
    var name: [topic_mod.name_max_len]u8 = undefined;
    var buffer: [topic_mod.topic_max_len]u8 = undefined;
    for (0..3) |fork| {
        if (fork == 2) {
            for (&overlay.rows, 0..) |*topic, index| {
                if (topic.active and std.mem.startsWith(u8, overlay.topicString(@intCast(index)), "/eth2/00000000/")) {
                    try std.testing.expect(gossip.unsubscribe(overlay.topicString(@intCast(index))));
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
    try std.testing.expect(overlay.findTopic("/eth2/00000000/beacon_block/ssz_snappy") == null);
    try std.testing.expect(overlay.findTopic("/eth2/01000000/beacon_block/ssz_snappy") != null);
    try std.testing.expect(overlay.findTopic("/eth2/02000000/beacon_block/ssz_snappy") != null);
}

test "gossip state intern snapshots an aliased retiring topic string" {
    var overlay = @import("overlay.zig").Overlay.init(1);
    defer overlay.deinit(std.testing.allocator);
    const oversized = [_]u8{'x'} ** (topic_mod.topic_max_len + 1);
    try std.testing.expectEqual(@as(?u16, null), overlay.internVacant(&oversized));
    try std.testing.expectEqual(@as(?u16, null), overlay.internVacant("invalid"));
    const original = "/eth2/00000000/a/ssz_snappy/b/ssz_snappy";
    const shorter = "/eth2/00000000/a/ssz_snappy";
    try std.testing.expectEqual(@as(?u16, 0), overlay.internVacant(original));
    const input = overlay.topicString(0)[0..shorter.len];
    overlay.rows[0].active = false;
    try std.testing.expectEqual(@as(?u16, 0), overlay.internVacant(input));
    try std.testing.expectEqualStrings(shorter, overlay.topicString(0));
    try std.testing.expectEqual(@as(u64, 2), overlay.rows[0].generation);
    const maximum = "/eth2/00000000/sync_committee_contribution_and_proof/ssz_snappy";
    try std.testing.expectEqual(topic_mod.topic_max_len, maximum.len);
    try std.testing.expectEqual(@as(?u16, 1), overlay.internVacant(maximum));
    try std.testing.expectEqualStrings(maximum, overlay.topicString(1));
}
