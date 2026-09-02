const std = @import("std");
const binding = @import("binding.zig");
const limits = @import("limits.zig");
const peer_id = @import("../wire/peer_id.zig");
const stream_table = @import("stream_table.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const c = binding.c;
const StreamTable = stream_table.StreamTable;

pub const Error = binding.Error || tls.Error || error{
    StreamTableFull,
    StreamLimit,
    UnknownStream,
    NotEstablished,
    WouldBlock,
};

pub const State = enum { free, handshaking, established, closed };

pub const OpenedStream = struct {
    id: u64,
    index: u8,
};

pub const OpenParams = struct {
    direction: types.Direction,
    local: types.Address,
    peer: types.Address,
    scid: [limits.local_cid_length]u8,
    expected_peer_id: ?peer_id.PeerId,
    now: types.Now,
};

pub const Slot = struct {
    state: State = .free,
    generation: u32 = 0,
    direction: types.Direction = .inbound,
    conn: ?*c.quiche_conn = null,
    handshake: tls.HandshakeState = .{},
    peer: types.Address = .unspecified,
    peer_sockaddr: binding.SockAddr = .unspecified,
    local_sockaddr: binding.SockAddr = .unspecified,
    expected_peer_id: ?peer_id.PeerId = null,
    peer_id: ?peer_id.PeerId = null,
    scid: binding.Cid = .{},
    created_ms: u64 = 0,
    last_send_ms: u64 = 0,
    close_reason: ?types.CloseReason = null,
    pending_close: ?types.PendingClose = null,
    pending_close_armed: bool = false,
    connected_pending: bool = false,
    closed_pending: bool = false,
    closed_reported: bool = false,
    table: StreamTable = .{},

    pub fn open(
        self: *Slot,
        ctx: *const tls.Context,
        config: *const binding.Config,
        params: OpenParams,
    ) Error!void {
        assert(self.state == .free);
        assert(self.conn == null);
        self.handshake = .{ .now_unix = params.now.unix_s };
        self.direction = params.direction;
        self.peer = params.peer;
        self.peer_sockaddr = binding.SockAddr.fromAddress(params.peer);
        self.local_sockaddr = binding.SockAddr.fromAddress(params.local);
        self.expected_peer_id = params.expected_peer_id;
        self.peer_id = null;
        self.scid = binding.Cid.fromSlice(&params.scid);
        self.created_ms = params.now.mono_ms;
        self.last_send_ms = params.now.mono_ms;
        self.close_reason = null;
        self.pending_close = null;
        self.pending_close_armed = false;
        self.connected_pending = false;
        self.closed_pending = false;
        self.closed_reported = false;
        self.table = StreamTable.init(params.direction);

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
        _ = try binding.check(c.quiche_conn_recv(self.conn.?, datagram.ptr, datagram.len, &info));
    }

    pub fn send(self: *Slot, now_ms: u64, out: []u8) Error!?[]u8 {
        var info: c.quiche_send_info = undefined;
        const rc = c.quiche_conn_send(self.conn.?, out.ptr, out.len, &info);
        const length = try binding.check(rc) orelse return null;
        assert(length <= out.len);
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

    pub fn close(self: *Slot, reason: types.CloseReason, code: u64) void {
        if (self.close_reason == null) self.close_reason = reason;
        _ = c.quiche_conn_close(self.conn.?, true, code, "", 0);
    }

    pub fn deferClose(self: *Slot, reason: types.CloseReason, code: u64) void {
        if (self.close_reason == null) self.close_reason = reason;
        self.pending_close = .{ .reason = reason, .code = code };
    }

    pub fn isEstablished(self: *const Slot) bool {
        return c.quiche_conn_is_established(self.conn.?);
    }

    pub fn isFinished(self: *const Slot) bool {
        return c.quiche_conn_is_closed(self.conn.?) or c.quiche_conn_is_draining(self.conn.?);
    }

    pub fn closeReason(self: *const Slot) types.CloseReason {
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
            return types.reasonFromLocalError(is_app, code);
        }
        return .{ .transport_error = 0 };
    }

    pub fn streamIndex(self: *const Slot, id: u64) ?u8 {
        return self.table.find(id);
    }

    pub fn openStream(self: *Slot) Error!OpenedStream {
        if (self.state != .established or self.close_reason != null) return error.NotEstablished;
        if (c.quiche_conn_peer_streams_left_bidi(self.conn.?) == 0) return error.StreamLimit;
        const index = self.table.freeLocal() orelse return error.StreamTableFull;
        const id = self.table.next_local_id;
        var code: u64 = 0;
        _ = try binding.check(c.quiche_conn_stream_send(self.conn.?, id, "", 0, false, &code));
        self.table.claimLocal(index, id);
        assert(self.table.matches(index, id));
        return .{ .id = id, .index = index };
    }

    pub fn discoverPeerStreams(self: *Slot) void {
        const iter = c.quiche_conn_readable(self.conn.?) orelse return;
        defer c.quiche_stream_iter_free(iter);
        var id: u64 = 0;
        var seen: u16 = 0;
        while (seen < limits.streams_per_connection and c.quiche_stream_iter_next(iter, &id)) : (seen += 1) {
            if (!StreamTable.isPeerInitiated(self.direction, id)) continue;
            if (self.table.find(id) != null) continue;
            if (self.table.claimPeer(id) == null) {
                self.shutdownRaw(id, .read, types.app_error_stream_table_full);
                self.shutdownRaw(id, .write, types.app_error_stream_table_full);
            }
        }
    }

    pub fn read(self: *Slot, index: u8, id: u64, buf: []u8) Error!types.Read {
        assert(self.conn != null);
        assert(self.table.matches(index, id));
        var fin = false;
        var code: u64 = 0;
        const rc = c.quiche_conn_stream_recv(self.conn.?, id, buf.ptr, buf.len, &fin, &code);
        if (rc == c.QUICHE_ERR_STREAM_RESET) {
            self.table.markFinReceived(index);
            if (c.quiche_conn_stream_capacity(self.conn.?, id) < 0) self.table.markFinSent(index);
            if (self.table.entries[index].fin_sent) self.finishStream(index, code);
            return .{ .len = 0, .fin = true, .reset_code = code };
        }
        const length = try binding.check(rc) orelse return .{ .len = 0, .fin = false };
        assert(length <= buf.len);
        if (fin) {
            self.table.markFinReceived(index);
            if (self.table.entries[index].fin_sent) self.finishStream(index, null);
        }
        return .{ .len = length, .fin = fin };
    }

    pub fn write(self: *Slot, index: u8, id: u64, bytes: []const u8, fin: bool) Error!usize {
        assert(self.conn != null);
        assert(self.table.matches(index, id));
        var code: u64 = 0;
        const rc = c.quiche_conn_stream_send(self.conn.?, id, bytes.ptr, bytes.len, fin, &code);
        if (rc == c.QUICHE_ERR_STREAM_STOPPED) {
            self.table.markFinSent(index);
            if (self.table.entries[index].fin_received) self.finishStream(index, code);
            return error.StreamStopped;
        }
        const length = try binding.check(rc) orelse {
            const available = c.quiche_conn_stream_capacity(self.conn.?, id);
            if (available < 0 and available != c.QUICHE_ERR_DONE) {
                self.finishStream(index, null);
                return error.UnknownStream;
            }
            return error.WouldBlock;
        };
        assert(length <= bytes.len);
        if (fin and length == bytes.len) {
            self.table.markFinSent(index);
            if (self.table.entries[index].fin_received) self.finishStream(index, null);
        }
        return length;
    }

    pub fn capacity(self: *Slot, index: u8, id: u64) Error!usize {
        assert(self.conn != null);
        assert(self.table.matches(index, id));
        const rc = c.quiche_conn_stream_capacity(self.conn.?, id);
        const available = binding.check(rc) catch |err| switch (err) {
            error.InvalidStreamState => {
                self.finishStream(index, null);
                return error.UnknownStream;
            },
            else => return err,
        };
        return available orelse error.WouldBlock;
    }

    pub fn shutdown(
        self: *Slot,
        index: u8,
        id: u64,
        direction: types.ShutdownDirection,
        code: u64,
    ) void {
        assert(self.conn != null);
        assert(self.table.matches(index, id));
        self.shutdownRaw(id, direction, code);
        if (direction == .read) self.table.markFinReceived(index) else self.table.markFinSent(index);
        const entry = self.table.entries[index];
        if (entry.fin_received and entry.fin_sent) self.finishStream(index, null);
    }

    pub fn closeStream(self: *Slot, index: u8, id: u64, code: u64) void {
        assert(self.conn != null);
        assert(self.table.matches(index, id));
        const entry = self.table.entries[index];
        if (!entry.fin_received) self.shutdownRaw(id, .read, code);
        if (!entry.fin_sent) self.shutdownRaw(id, .write, code);
        self.finishStream(index, null);
        assert(!self.table.matches(index, id));
    }

    fn finishStream(self: *Slot, index: u8, reset_code: ?u64) void {
        assert(index < limits.streams_per_connection);
        assert(self.table.entries[index].claimed);
        if (self.state == .closed) {
            self.table.discard(index);
        } else {
            self.table.clear(index, reset_code);
        }
    }

    fn shutdownRaw(self: *Slot, id: u64, direction: types.ShutdownDirection, code: u64) void {
        const which: c_int = if (direction == .read)
            c.QUICHE_SHUTDOWN_READ
        else
            c.QUICHE_SHUTDOWN_WRITE;
        _ = c.quiche_conn_stream_shutdown(self.conn.?, id, @intCast(which), code);
    }
};

comptime {
    assert(@sizeOf(Slot) <= 4 * 1_024);
}
