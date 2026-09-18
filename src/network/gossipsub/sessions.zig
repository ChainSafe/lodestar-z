const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");

const assert = std.debug.assert;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const MessageId = [constants.message_id_length]u8;
pub const PeerSet = std.StaticBitSet(constants.peers_cap);

pub const Version = @import("protocol.zig").Version;

pub const SessionRef = struct { index: u16, generation: u64 };

const ReceivePool = @import("receive_pool.zig").ReceivePool;
const DeliveryPool = @import("delivery.zig").Pool;
const PeerIo = @import("peer_io.zig").PeerIo;

const Session = @import("peer_session.zig").Session;

pub const Sessions = struct {
    rows: []Session,
    cursor: usize = 0,
    delivery_revision: u64 = 0,
    io_arena: []u8,
    receive_pool: ReceivePool,
    decode_scratch: []u8,
    deliveries: *DeliveryPool,

    pub fn setOutbound(self: *Sessions, index: u16, outbound: @import("peer_session.zig").Outbound) void {
        assert(self.rows[index].active);
        self.rows[index].outbound = outbound;
        self.delivery_revision +|= 1;
    }

    pub fn init(a: std.mem.Allocator, options: *const @import("options.zig").Options) !Sessions {
        const layout = @import("layout.zig").Layout.init(options);
        const rows = try a.alloc(Session, layout.sessions);
        errdefer a.free(rows);
        const per_peer = layout.session_buffer_bytes;
        const arena = try a.alloc(u8, rows.len * per_peer);
        errdefer a.free(arena);
        const receive_pool = try ReceivePool.init(a, layout.receive_arena_bytes);
        errdefer {
            var pool = receive_pool;
            pool.deinit(a);
        }
        const decode_scratch = try a.alloc(u8, constants.GOSSIP_MAX_SIZE);
        errdefer a.free(decode_scratch);
        const deliveries = try a.create(DeliveryPool);
        errdefer a.destroy(deliveries);
        deliveries.* = try DeliveryPool.init(a, rows.len, layout.deliveries);
        for (rows, 0..) |*row, i| row.* = .{ .io = PeerIo.init(arena[i * per_peer ..][0..per_peer], options, deliveries) };
        return .{ .rows = rows, .io_arena = arena, .receive_pool = receive_pool, .decode_scratch = decode_scratch, .deliveries = deliveries };
    }

    pub fn metadataBytes(layout: *const @import("layout.zig").Layout) usize {
        return @as(usize, layout.sessions) * @sizeOf(Session) + @sizeOf(DeliveryPool) +
            DeliveryPool.backingBytes(layout.deliveries) + layout.receive_arena_bytes / @import("receive_pool.zig").page_bytes * @sizeOf(u32);
    }

    pub fn deinit(self: *Sessions, a: std.mem.Allocator) void {
        self.deliveries.deinit(a);
        a.destroy(self.deliveries);
        self.receive_pool.deinit(a);
        a.free(self.decode_scratch);
        a.free(self.rows);
        a.free(self.io_arena);
    }

    // Peers ------------------------------------------------------------------

    pub fn addPeer(self: *Sessions, conn: Handle) ?SessionRef {
        const index = self.freePeer() orelse return null;
        const peer = &self.rows[index];
        peer.start(conn);
        self.delivery_revision +|= 1;
        return .{ .index = @intCast(index), .generation = peer.generation };
    }

    pub fn removePeer(self: *Sessions, index: u16) void {
        assert(index < self.rows.len);
        if (!self.rows[index].active) return;
        assert(self.rows[index].io.overflow.pages == 0 and self.rows[index].io.rpc == null and !self.rows[index].io.tx.pending());
        self.setOutbound(index, .none);
        self.rows[index].active = false;
        self.rows[index].in_stream = null;
    }

    pub fn findPeer(self: *Sessions, conn: Handle) ?u16 {
        for (self.rows, 0..) |*peer, index| {
            if (peer.active and std.meta.eql(peer.conn, conn)) return @intCast(index);
        }
        return null;
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

    pub fn finishFrame(self: *Sessions, peer_io: *PeerIo) bool {
        const released = peer_io.overflow.pages != 0;
        peer_io.rpc = null;
        self.receive_pool.release(&peer_io.overflow);
        peer_io.finishFrame();
        return released;
    }

    pub fn connectionActivity(self: *Sessions, conn: Handle) void {
        const index = self.findPeer(conn) orelse return;
        self.rows[index].needs_service = true;
        self.rows[index].io.rx_ready = true;
        self.rows[index].io.tx.ready = true;
    }

    pub fn resetRx(self: *Sessions, index: u16) bool {
        const io = &self.rows[index].io;
        const released = self.finishFrame(io);
        io.unread_start = 0;
        io.unread_end = 0;
        io.fin_seen = false;
        io.rx_ready = false;
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
    sessions.* = try @import("test_support.zig").sessions(std.testing.allocator, constants.peers_cap);
    defer sessions.deinit(std.testing.allocator);
    const conn = Handle{ .index = 3, .generation = 1 };
    const peer = sessions.addPeer(conn).?;
    try std.testing.expectEqual(@as(?u16, peer.index), sessions.findPeer(conn));

    sessions.removePeer(peer.index);
    try std.testing.expectEqual(@as(?u16, null), sessions.findPeer(conn));
}

test "sessions suppresses ids per peer until monotonic expiry" {
    var sessions = try std.testing.allocator.create(Sessions);
    defer std.testing.allocator.destroy(sessions);
    sessions.* = try @import("test_support.zig").sessions(std.testing.allocator, constants.peers_cap);
    defer sessions.deinit(std.testing.allocator);
    const peer = sessions.addPeer(.{ .index = 1, .generation = 1 }).?;
    const id = [_]u8{7} ** 20;
    try std.testing.expect(!sessions.suppresses(peer.index, id, 0));
    sessions.suppress(peer.index, id, 0, 10);
    try std.testing.expect(!sessions.suppresses(peer.index, id, 10));
    try std.testing.expect(sessions.suppresses(peer.index, id, 0));
}

test "gossip stream cancellation discards unsent work and session reuse preserves receipt identity" {
    const a = std.testing.allocator;
    var sessions = try @import("test_support.zig").sessions(a, 1);
    defer sessions.deinit(a);
    var store = try @import("message_store.zig").Store.init(a, 1, 4096);
    defer store.deinit(a);
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = sessions.addPeer(conn).?;
    const peer = &sessions.rows[first.index];
    const id: MessageId = @splat(1);
    peer.suppress(id, 1, 100);
    peer.io.ihave_recv = 10;
    peer.io.write_first = true;
    peer.io.tx.control_burst = 4;
    peer.io.tx.subscriptionChanged(0, 1);
    const token = peer.io.tx.injectFrame("frame", false, .iwant, 1).?;
    const high_water = peer.io.tx.control.bytes_high_water;
    peer.io.tx.drops[0] = 3;
    peer.io.tx.cancelStream(&store);
    try std.testing.expectEqual(@as(usize, 0), peer.io.tx.subscription_dirty.count());
    try std.testing.expectEqual(@as(u8, 0), peer.io.tx.control_burst);
    try std.testing.expect(peer.suppresses(id, 2));
    sessions.removePeer(first.index);
    const next = sessions.addPeer(conn).?;
    try std.testing.expectEqual(first.index, next.index);
    try std.testing.expect(next.generation > first.generation);
    try std.testing.expect(!sessions.matches(first));
    try std.testing.expect(!peer.suppresses(id, 2));
    try std.testing.expectEqual(@as(u16, 0), peer.io.ihave_recv);
    try std.testing.expect(!peer.io.write_first);
    try std.testing.expectEqual(@as(u8, 0), peer.io.tx.control_burst);
    try std.testing.expectEqual(@as(usize, 0), peer.io.tx.subscription_dirty.count());
    try std.testing.expectEqual(high_water, peer.io.tx.control.bytes_high_water);
    try std.testing.expectEqual(@as(u64, 3), peer.io.tx.drops[0]);
    try std.testing.expect(peer.io.tx.injectFrame("next", false, .iwant, 2).? > token);
    peer.io.tx.cancelStream(&store);
}
