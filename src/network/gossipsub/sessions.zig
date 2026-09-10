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

pub const SessionRef = struct { index: u16, generation: u64 };

const Session = @import("peer_session.zig").Session;

pub const Sessions = struct {
    rows: []Session,
    io_arena: []u8,

    pub fn init(a: std.mem.Allocator, capacity: u16) !Sessions {
        return initOptions(a, &.{ .connected_capacity = capacity });
    }

    pub fn initOptions(a: std.mem.Allocator, options: *const @import("options.zig").Options) !Sessions {
        if (options.connected_capacity == 0 or options.connected_capacity > constants.peers_cap) return error.InvalidLimits;
        const PeerIo = @import("peer_io.zig").PeerIo;
        const rows = try a.alloc(Session, options.connected_capacity);
        errdefer a.free(rows);
        const per_peer = PeerIo.bufferBytes(options);
        const arena = try a.alloc(u8, rows.len * per_peer);
        for (rows, 0..) |*row, i| row.* = .{ .io = PeerIo.init(arena[i * per_peer ..][0..per_peer], options) };
        return .{ .rows = rows, .io_arena = arena };
    }

    pub fn deinit(self: *Sessions, a: std.mem.Allocator) void {
        a.free(self.rows);
        a.free(self.io_arena);
    }

    // Peers ------------------------------------------------------------------

    pub fn addPeer(self: *Sessions, conn: Handle, version: Version) ?SessionRef {
        const index = self.freePeer() orelse return null;
        const peer = &self.rows[index];
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

    pub fn removePeer(self: *Sessions, index: u16) void {
        assert(index < self.rows.len);
        if (!self.rows[index].active) return;
        self.rows[index].active = false;
        self.rows[index].outbound = .{ .waiting = 0 };
        self.rows[index].in_stream = null;
    }

    pub fn findPeer(self: *Sessions, conn: Handle) ?u16 {
        for (self.rows, 0..) |*peer, index| {
            if (peer.active and std.meta.eql(peer.conn, conn)) return @intCast(index);
        }
        return null;
    }

    pub fn peerVersion(self: *const Sessions, index: u16) Version {
        assert(self.rows[index].active);
        return self.rows[index].version;
    }

    pub fn setVersion(self: *Sessions, index: u16, version: Version) void {
        assert(self.rows[index].active);
        self.rows[index].version = version;
    }

    pub fn peerGeneration(self: *const Sessions, index: u16) u64 {
        return self.rows[index].generation;
    }

    /// Whether `index` still holds the same peer as when `generation` was taken.
    pub fn peerMatches(self: *const Sessions, index: u16, generation: u64) bool {
        return index < self.rows.len and self.rows[index].active and self.rows[index].generation == generation;
    }

    pub fn setStreams(self: *Sessions, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        assert(self.rows[index].active);
        if (out) |stream| self.rows[index].outbound = .{ .live = stream };
        if (in) |stream| self.rows[index].in_stream = stream;
    }

    pub fn outStream(self: *const Sessions, index: u16) ?StreamHandle {
        return self.rows[index].outStream();
    }

    pub fn suppress(self: *Sessions, index: u16, id: MessageId, now: u64, ttl: u64) void {
        assert(self.rows[index].active);
        self.rows[index].suppress(id, now, ttl);
    }

    pub fn suppresses(self: *const Sessions, index: u16, id: MessageId, now: u64) bool {
        return self.rows[index].active and self.rows[index].suppresses(id, now);
    }

    fn freePeer(self: *Sessions) ?usize {
        for (self.rows, 0..) |*peer, index| {
            if (!peer.active and peer.generation != std.math.maxInt(u64)) return index;
        }
        return null;
    }
};

test "session slots track connection generations" {
    var sessions = try std.testing.allocator.create(Sessions);
    defer std.testing.allocator.destroy(sessions);
    sessions.* = try Sessions.init(std.testing.allocator, constants.peers_cap);
    defer sessions.deinit(std.testing.allocator);
    const conn = Handle{ .index = 3, .generation = 1 };
    const peer = sessions.addPeer(conn, .v1_2).?;
    try std.testing.expectEqual(@as(?u16, peer.index), sessions.findPeer(conn));
    try std.testing.expectEqual(Version.v1_2, sessions.peerVersion(peer.index));

    sessions.removePeer(peer.index);
    try std.testing.expectEqual(@as(?u16, null), sessions.findPeer(conn));
}

test "sessions suppresses ids per peer until monotonic expiry" {
    var sessions = try std.testing.allocator.create(Sessions);
    defer std.testing.allocator.destroy(sessions);
    sessions.* = try Sessions.init(std.testing.allocator, constants.peers_cap);
    defer sessions.deinit(std.testing.allocator);
    const peer = sessions.addPeer(.{ .index = 1, .generation = 1 }, .v1_2).?;
    const id = [_]u8{7} ** 20;
    try std.testing.expect(!sessions.suppresses(peer.index, id, 0));
    sessions.suppress(peer.index, id, 0, 10);
    try std.testing.expect(!sessions.suppresses(peer.index, id, 10));
    try std.testing.expect(sessions.suppresses(peer.index, id, 0));
}
