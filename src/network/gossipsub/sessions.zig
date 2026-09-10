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

const ReceivePool = @import("receive_pool.zig").ReceivePool;
const DeliveryPool = @import("delivery.zig").Pool;
const PeerIo = @import("peer_io.zig").PeerIo;

const Session = @import("peer_session.zig").Session;

pub const Sessions = struct {
    rows: []Session,
    cursor: usize = 0,
    io_arena: []u8,
    receive_pool: ReceivePool,
    deliveries: *DeliveryPool,

    pub fn init(a: std.mem.Allocator, capacity: u16) !Sessions {
        return initOptions(a, &.{ .connected_capacity = capacity });
    }

    pub fn initOptions(a: std.mem.Allocator, options: *const @import("options.zig").Options) !Sessions {
        if (options.connected_capacity == 0 or options.connected_capacity > constants.peers_cap) return error.InvalidLimits;
        const layout = @import("layout.zig").Layout.init(options);
        return initLayout(a, options, &layout);
    }

    pub fn initLayout(a: std.mem.Allocator, options: *const @import("options.zig").Options, layout: *const @import("layout.zig").Layout) !Sessions {
        assert(std.meta.eql(layout.*, @import("layout.zig").Layout.init(options)));
        const rows = try a.alloc(Session, layout.sessions);
        errdefer a.free(rows);
        const per_peer = layout.session_buffer_bytes;
        const arena = try a.alloc(u8, rows.len * per_peer);
        errdefer a.free(arena);
        const receive_pool = try ReceivePool.init(a, layout.receive_frames, layout.receive_frame_bytes);
        errdefer {
            var pool = receive_pool;
            pool.deinit(a);
        }
        const deliveries = try a.create(DeliveryPool);
        errdefer a.destroy(deliveries);
        deliveries.* = try DeliveryPool.initCapacity(a, rows.len, layout.deliveries);
        for (rows, 0..) |*row, i| row.* = .{ .io = PeerIo.init(arena[i * per_peer ..][0..per_peer], options, deliveries) };
        return .{ .rows = rows, .io_arena = arena, .receive_pool = receive_pool, .deliveries = deliveries };
    }

    pub fn metadataBytes(layout: *const @import("layout.zig").Layout) usize {
        return @as(usize, layout.sessions) * @sizeOf(Session) + @sizeOf(DeliveryPool) +
            DeliveryPool.backingBytes(layout.deliveries) + ReceivePool.metadataBytes(layout.receive_frames);
    }

    pub fn deinit(self: *Sessions, a: std.mem.Allocator) void {
        self.deliveries.deinit(a);
        a.destroy(self.deliveries);
        self.receive_pool.deinit(a);
        a.free(self.rows);
        a.free(self.io_arena);
    }

    // Peers ------------------------------------------------------------------

    pub fn addPeer(self: *Sessions, conn: Handle, version: Version) ?SessionRef {
        const index = self.freePeer() orelse return null;
        const peer = &self.rows[index];
        peer.start(conn, version);
        return .{ .index = @intCast(index), .generation = peer.generation };
    }

    pub fn removePeer(self: *Sessions, index: u16) void {
        assert(index < self.rows.len);
        if (!self.rows[index].active) return;
        assert(self.rows[index].io.large_slot == null and !self.rows[index].io.tx.pending());
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

    pub fn ref(self: *const Sessions, index: u16) SessionRef {
        assert(self.rows[index].active);
        return .{ .index = index, .generation = self.rows[index].generation };
    }

    pub fn matches(self: *const Sessions, session: SessionRef) bool {
        return session.index < self.rows.len and self.rows[session.index].active and self.rows[session.index].generation == session.generation;
    }

    pub fn setStreams(self: *Sessions, index: u16, out: ?StreamHandle, in: ?StreamHandle) void {
        assert(self.rows[index].active);
        if (out) |stream| self.rows[index].outbound = .{ .live = stream };
        if (in) |stream| self.rows[index].in_stream = stream;
        self.rows[index].io.rx_ready = in != null;
        self.rows[index].io.tx.ready = out != null;
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

    pub fn receiveHandoff(self: *Sessions, index: u16, bytes: []const u8, fin: bool) bool {
        const io = &self.rows[index].io;
        if (bytes.len > io.unread.len - io.unread_end) return false;
        @memcpy(io.unread[io.unread_end..][0..bytes.len], bytes);
        io.unread_end += bytes.len;
        io.fin_seen = fin;
        io.rx_ready = true;
        return true;
    }

    pub fn frameBody(self: *Sessions, io: *PeerIo) ?[]u8 {
        if (io.large_slot) |lease| return self.receive_pool.buffer(lease).?;
        const declared = io.reader.declaredLen() orelse return io.body;
        if (declared <= io.body.len) return io.body;
        const lease = self.receive_pool.claim() orelse return null;
        io.large_slot = lease;
        return self.receive_pool.buffer(lease).?;
    }

    pub fn releaseFrame(self: *Sessions, peer_io: *PeerIo) bool {
        if (peer_io.large_slot) |lease| {
            const released = self.receive_pool.release(lease);
            assert(released);
            peer_io.large_slot = null;
            return true;
        }
        return false;
    }

    pub fn connectionActivity(self: *Sessions, conn: Handle) void {
        const index = self.findPeer(conn) orelse return;
        self.rows[index].needs_service = true;
        self.rows[index].io.rx_ready = true;
        self.rows[index].io.tx.ready = true;
    }

    pub fn resetRx(self: *Sessions, index: u16) bool {
        const io = &self.rows[index].io;
        const released = self.releaseFrame(io);
        io.resetRx();
        return released;
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

test "gossip session reuse clears protocol state while stream cancellation retains intent and token history" {
    const a = std.testing.allocator;
    var sessions = try Sessions.init(a, 1);
    defer sessions.deinit(a);
    var store = try @import("message_store.zig").Store.init(a, 1, 4096);
    defer store.deinit(a);
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = sessions.addPeer(conn, .v1_2).?;
    const peer = &sessions.rows[first.index];
    const id: MessageId = @splat(1);
    peer.suppress(id, 1, 100);
    peer.failures = 5;
    peer.io.ihave_recv = 10;
    peer.io.write_first = true;
    peer.io.tx.control_burst = 4;
    peer.io.tx.subscriptionChanged(0, 1);
    peer.io.tx.deferPrune(1, 1);
    const token = peer.io.tx.injectFrame("frame", false, .iwant, 1).?;
    const high_water = peer.io.tx.control.bytes_high_water;
    peer.io.tx.drops[0] = 3;
    peer.io.tx.cancelStream(&store);
    try std.testing.expect(peer.io.tx.subscription_dirty.isSet(0));
    try std.testing.expect(peer.io.tx.pending_prunes.isSet(1));
    try std.testing.expectEqual(@as(u8, 4), peer.io.tx.control_burst);
    try std.testing.expect(peer.suppresses(id, 2));
    sessions.removePeer(first.index);
    const next = sessions.addPeer(conn, .v1_1).?;
    try std.testing.expectEqual(first.index, next.index);
    try std.testing.expect(next.generation > first.generation);
    try std.testing.expect(!sessions.matches(first));
    try std.testing.expect(!peer.suppresses(id, 2));
    try std.testing.expectEqual(@as(u8, 0), peer.failures);
    try std.testing.expectEqual(@as(u16, 0), peer.io.ihave_recv);
    try std.testing.expect(!peer.io.write_first);
    try std.testing.expectEqual(@as(u8, 0), peer.io.tx.control_burst);
    try std.testing.expectEqual(@as(usize, 0), peer.io.tx.subscription_dirty.count());
    try std.testing.expectEqual(@as(usize, 0), peer.io.tx.pending_prunes.count());
    try std.testing.expectEqual(high_water, peer.io.tx.control.bytes_high_water);
    try std.testing.expectEqual(@as(u64, 3), peer.io.tx.drops[0]);
    try std.testing.expect(peer.io.tx.injectFrame("next", false, .iwant, 2).? > token);
    peer.io.tx.cancelStream(&store);
}
