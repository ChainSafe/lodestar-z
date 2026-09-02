const std = @import("std");
const binding = @import("binding.zig");
const constants = @import("../constants.zig");
const peer_id = @import("../identity/peer_id.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const c = binding.c;

pub const Error = binding.Error || tls.Error || error{
    StreamTableFull,
    StreamLimit,
    UnknownStream,
    NotEstablished,
};

pub const State = enum { free, handshaking, established, closed };
pub const Direction = enum { inbound, outbound };
pub const ShutdownDirection = enum { read, write };

pub const CloseReason = union(enum) {
    host,
    idle_timeout,
    handshake_timeout,
    peer_id_mismatch,
    tls_failed,
    peer_closed: struct { app: bool, code: u64 },
    transport_error: u64,
};

pub const PendingClose = struct { reason: CloseReason, code: u64 };

pub const app_error_normal: u64 = 0;
pub const app_error_peer_id_mismatch: u64 = 1;
pub const app_error_handshake_timeout: u64 = 2;
pub const app_error_stream_table_full: u64 = 3;

pub const Now = struct {
    mono_ms: u64,
    unix_s: i64,
};

pub const Read = struct {
    len: usize,
    fin: bool,
};

pub const Stream = struct {
    id: u64 = 0,
    active: bool = false,
    opened_pending: bool = false,
    fin_sent: bool = false,
    fin_received: bool = false,
};

pub const OpenParams = struct {
    direction: Direction,
    local: types.Address,
    peer: types.Address,
    scid: [constants.local_cid_length]u8,
    odcid: ?binding.Cid,
    expected_peer_id: ?peer_id.PeerId,
    now: Now,
};

const local_stream_slots = constants.streams_per_connection / 2;

pub const Slot = struct {
    state: State = .free,
    generation: u32 = 0,
    direction: Direction = .inbound,
    conn: ?*c.quiche_conn = null,
    handshake: tls.HandshakeState = .{},
    peer: types.Address = undefined,
    peer_sockaddr: binding.SockAddr = undefined,
    local_sockaddr: binding.SockAddr = undefined,
    expected_peer_id: ?peer_id.PeerId = null,
    peer_id: ?peer_id.PeerId = null,
    scid: binding.Cid = .{},
    odcid: ?binding.Cid = null,
    created_ms: u64 = 0,
    last_send_ms: u64 = 0,
    close_reason: ?CloseReason = null,
    pending_close: ?PendingClose = null,
    pending_close_armed: bool = false,
    connected_pending: bool = false,
    closed_pending: bool = false,
    streams_pending: u16 = 0,
    next_local_stream_id: u64 = 0,
    streams: [constants.streams_per_connection]Stream = [_]Stream{.{}} ** constants.streams_per_connection,

    pub fn open(
        self: *Slot,
        ctx: *const tls.Context,
        config: *const binding.Config,
        params: OpenParams,
    ) Error!void {
        std.debug.assert(self.state == .free and self.conn == null);
        self.handshake = .{ .now_unix = params.now.unix_s };
        self.direction = params.direction;
        self.peer = params.peer;
        self.peer_sockaddr = binding.SockAddr.fromAddress(params.peer);
        self.local_sockaddr = binding.SockAddr.fromAddress(params.local);
        self.expected_peer_id = params.expected_peer_id;
        self.peer_id = null;
        self.scid = binding.Cid.fromSlice(&params.scid);
        self.odcid = params.odcid;
        self.created_ms = params.now.mono_ms;
        self.last_send_ms = params.now.mono_ms;
        self.close_reason = null;
        self.pending_close = null;
        self.pending_close_armed = false;
        self.connected_pending = false;
        self.closed_pending = false;
        self.streams_pending = 0;
        self.next_local_stream_id = if (params.direction == .outbound) 0 else 1;
        self.streams = [_]Stream{.{}} ** constants.streams_per_connection;

        const ssl = try ctx.newSsl(&self.handshake);
        // quiche owns the SSL handle from this call onward and frees it even when construction fails, so the slot must never free it.
        self.conn = c.quiche_conn_new_with_tls(
            self.scid.slice().ptr,
            self.scid.len,
            null,
            0,
            @ptrCast(self.local_sockaddr.any()),
            self.local_sockaddr.len,
            @ptrCast(self.peer_sockaddr.any()),
            self.peer_sockaddr.len,
            config.ptr,
            ssl,
            params.direction == .inbound,
        ) orelse return error.Unknown;
        self.state = .handshaking;
    }

    pub fn release(self: *Slot) void {
        if (self.conn) |conn| c.quiche_conn_free(conn);
        self.conn = null;
        self.state = .free;
        self.generation +%= 1;
    }

    pub fn recv(self: *Slot, datagram: []u8) Error!void {
        var info = c.quiche_recv_info{
            .from = @ptrCast(@constCast(self.peer_sockaddr.any())),
            .from_len = self.peer_sockaddr.len,
            .to = @ptrCast(@constCast(self.local_sockaddr.any())),
            .to_len = self.local_sockaddr.len,
        };
        const rc = c.quiche_conn_recv(self.conn.?, datagram.ptr, datagram.len, &info);
        if (rc == c.QUICHE_ERR_DONE) return;
        _ = try binding.check(rc);
    }

    pub fn send(self: *Slot, now_ms: u64, out: []u8) Error!?[]u8 {
        var info: c.quiche_send_info = undefined;
        const rc = c.quiche_conn_send(self.conn.?, out.ptr, out.len, &info);
        if (rc == c.QUICHE_ERR_DONE) return null;
        const length = try binding.check(rc);
        self.last_send_ms = now_ms;
        return out[0..length];
    }

    pub fn onTimeout(self: *Slot) void {
        c.quiche_conn_on_timeout(self.conn.?);
    }

    pub fn timeoutMs(self: *const Slot) ?u64 {
        const value = c.quiche_conn_timeout_as_millis(self.conn.?);
        return if (value == std.math.maxInt(u64)) null else value;
    }

    pub fn keepAlive(self: *Slot) bool {
        return c.quiche_conn_send_ack_eliciting(self.conn.?) == 0;
    }

    pub fn close(self: *Slot, reason: CloseReason, code: u64) void {
        if (self.close_reason == null) self.close_reason = reason;
        _ = c.quiche_conn_close(self.conn.?, true, code, "", 0);
    }

    pub fn deferClose(self: *Slot, reason: CloseReason, code: u64) void {
        if (self.close_reason == null) self.close_reason = reason;
        self.pending_close = .{ .reason = reason, .code = code };
    }

    pub fn isEstablished(self: *const Slot) bool {
        return c.quiche_conn_is_established(self.conn.?);
    }

    pub fn isFinished(self: *const Slot) bool {
        return c.quiche_conn_is_closed(self.conn.?) or c.quiche_conn_is_draining(self.conn.?);
    }

    pub fn closeReason(self: *const Slot) CloseReason {
        if (self.close_reason) |reason| return reason;
        if (self.handshake.failure != null) return .tls_failed;
        if (c.quiche_conn_is_timed_out(self.conn.?)) return .idle_timeout;
        var is_app = false;
        var code: u64 = 0;
        var reason_ptr: [*c]const u8 = null;
        var reason_len: usize = 0;
        if (c.quiche_conn_peer_error(self.conn.?, &is_app, &code, &reason_ptr, &reason_len)) {
            return .{ .peer_closed = .{ .app = is_app, .code = code } };
        }
        if (c.quiche_conn_local_error(self.conn.?, &is_app, &code, &reason_ptr, &reason_len)) {
            return .{ .transport_error = code };
        }
        return .{ .transport_error = 0 };
    }

    pub fn isPeerInitiated(self: *const Slot, id: u64) bool {
        const peer_bit: u64 = if (self.direction == .outbound) 1 else 0;
        return (id & 0x3) == peer_bit;
    }

    pub fn streamIndex(self: *const Slot, id: u64) ?usize {
        for (&self.streams, 0..) |*stream, index| {
            if (stream.active and stream.id == id) return index;
        }
        return null;
    }

    fn clearStream(self: *Slot, index: usize) void {
        if (self.streams[index].opened_pending) self.streams_pending -= 1;
        self.streams[index] = .{};
    }

    fn freeStream(self: *Slot, peer_initiated: bool) ?usize {
        const start: usize = if (peer_initiated) local_stream_slots else 0;
        for (self.streams[start .. start + local_stream_slots], start..) |*stream, index| {
            if (!stream.active) return index;
        }
        return null;
    }

    pub fn openStream(self: *Slot) Error!u64 {
        if (self.state != .established or self.close_reason != null) return error.NotEstablished;
        if (c.quiche_conn_peer_streams_left_bidi(self.conn.?) == 0) return error.StreamLimit;
        const index = self.freeStream(false) orelse return error.StreamTableFull;
        const id = self.next_local_stream_id;
        var code: u64 = 0;
        const rc = c.quiche_conn_stream_send(self.conn.?, id, "", 0, false, &code);
        if (rc != c.QUICHE_ERR_DONE) _ = try binding.check(rc);
        self.next_local_stream_id += 4;
        self.streams[index] = .{ .id = id, .active = true };
        return id;
    }

    pub fn discoverPeerStreams(self: *Slot) void {
        const iter = c.quiche_conn_readable(self.conn.?) orelse return;
        defer c.quiche_stream_iter_free(iter);
        var id: u64 = 0;
        var seen: u16 = 0;
        while (seen < constants.streams_per_connection and c.quiche_stream_iter_next(iter, &id)) : (seen += 1) {
            if (!self.isPeerInitiated(id) or self.streamIndex(id) != null) continue;
            if (self.freeStream(true)) |index| {
                self.streams[index] = .{ .id = id, .active = true, .opened_pending = true };
                self.streams_pending += 1;
            } else {
                self.shutdown(id, .read, app_error_stream_table_full);
                self.shutdown(id, .write, app_error_stream_table_full);
            }
        }
    }

    pub fn read(self: *Slot, id: u64, buf: []u8) Error!Read {
        const index = self.streamIndex(id) orelse return error.UnknownStream;
        var fin = false;
        var code: u64 = 0;
        const rc = c.quiche_conn_stream_recv(self.conn.?, id, buf.ptr, buf.len, &fin, &code);
        if (rc == c.QUICHE_ERR_DONE) return .{ .len = 0, .fin = false };
        const length = try binding.check(rc);
        if (fin) {
            self.streams[index].fin_received = true;
            if (self.streams[index].fin_sent) self.clearStream(index);
        }
        return .{ .len = length, .fin = fin };
    }

    pub fn write(self: *Slot, id: u64, bytes: []const u8, fin: bool) Error!usize {
        const index = self.streamIndex(id) orelse return error.UnknownStream;
        var code: u64 = 0;
        const rc = c.quiche_conn_stream_send(self.conn.?, id, bytes.ptr, bytes.len, fin, &code);
        if (rc == c.QUICHE_ERR_DONE) return 0;
        const length = try binding.check(rc);
        if (fin and length == bytes.len) {
            self.streams[index].fin_sent = true;
            if (self.streams[index].fin_received) self.clearStream(index);
        }
        return length;
    }

    pub fn shutdown(self: *Slot, id: u64, direction: ShutdownDirection, code: u64) void {
        const which: c_int = if (direction == .read) c.QUICHE_SHUTDOWN_READ else c.QUICHE_SHUTDOWN_WRITE;
        _ = c.quiche_conn_stream_shutdown(self.conn.?, id, @intCast(which), code);
    }

    pub fn closeStream(self: *Slot, id: u64, code: u64) void {
        const index = self.streamIndex(id) orelse return;
        if (!self.streams[index].fin_received) self.shutdown(id, .read, code);
        if (!self.streams[index].fin_sent) self.shutdown(id, .write, code);
        self.clearStream(index);
    }
};
