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

    pub fn init(a: std.mem.Allocator, options: *const @import("options.zig").Options, layout: *const @import("layout.zig").Layout) !Sessions {
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

    pub fn discardFrame(self: *Sessions, io: *PeerIo) void {
        if (io.rpc != null) {
            _ = self.finishFrame(io);
        } else {
            std.debug.assert(io.reader.declaredLen() != null);
            self.receive_pool.release(&io.overflow);
            io.discarding = true;
            io.pressure_since = null;
            io.blocked = .none;
        }
        io.rx_ready = true;
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

test {
    _ = @import("sessions_test.zig");
}
