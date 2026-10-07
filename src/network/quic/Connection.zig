const std = @import("std");
const binding = @import("binding.zig");
const index_list = @import("../index_list.zig");
const limits = @import("limits.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const StreamTable = @import("StreamTable.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const c = binding.c;

pub const Error = binding.Error || tls.Error || error{
    StreamTableFull,
    StreamLimit,
    UnknownStream,
    NotEstablished,
    WouldBlock,
};

pub const Event = union(enum) {
    connected: struct { conn: types.Handle, peer_id: PeerId, direction: types.Direction },
    closed: struct {
        conn: types.Handle,
        peer_id: ?PeerId,
        direction: types.Direction,
        reason: types.CloseReason,
    },
    /// A newly claimed peer stream. It implies readiness for read and write.
    stream_opened: types.StreamHandle,
    /// Edge-triggered: a readable stream is reported again only after a read returned Done, and
    /// a writable one only after a blocked write armed it and send capacity reached the armed
    /// watermark, or the peer stopped the stream.
    stream_ready: struct { stream: types.StreamHandle, ready: types.Readiness },
    /// `route` is the stream's owner, captured before its table entry cleared. The owner of a
    /// routed stream caused its close in one of its own stream calls, so that close is reported
    /// by the next poll and does not make events pending.
    stream_closed: struct { stream: types.StreamHandle, reset_code: ?u64, route: types.Route = .{} },
    path_changed: struct { conn: types.Handle, peer: types.Address },
};

const State = enum { free, handshaking, established, closed };

/// Scheduling work produced by a stream operation, including one that returns an error.
pub const Effects = struct {
    dirty: bool = false,
    collect: bool = false,
};

/// Independent of connection phase, final-flight drain and close-event delivery.
const Closing = union(enum) {
    none,
    after_flight: types.PendingClose,
    started: types.CloseReason,
};

const OpenedStream = struct {
    id: u64,
    index: u8,
};

const Sent = types.Sent;

pub const OpenParams = struct {
    direction: types.Direction,
    local: types.Address,
    peer: types.Address,
    scid: [limits.local_cid_length]u8,
    original_dcid: ?binding.Cid = null,
    expected_peer_id: ?PeerId,
    now: types.Now,
};

const Connection = @This();

state: State = .free,
generation: u32 = 0,
direction: types.Direction = .inbound,
conn: ?*c.quiche_conn = null,
handshake: tls.HandshakeState = .{},
peer: types.Address = .unspecified,
peer_sockaddr: binding.SockAddr = .unspecified,
local_sockaddr: binding.SockAddr = .unspecified,
expected_peer_id: ?PeerId = null,
peer_id: ?PeerId = null,
scid: binding.Cid = .{},
created_ms: u64 = 0,
last_send_ms: u64 = 0,
closing: Closing = .none,
/// An outbound connection is established and quiche has not reported its output drained
/// since, so its final handshake flight may be unsent. The server cannot read a client's close
/// without that flight, while a client reads a server's close without the server's.
flight_pending: bool = false,
connected_pending: bool = false,
answered: bool = false,
close_event: enum { none, pending, reported } = .none,
path_changed_pending: ?types.Address = null,
/// Largest watermark this peer's flow-control windows let a blocked stream reach.
write_lowat_ceiling: u32 = limits.write_lowat_max,
/// Needs advancement after received datagrams, timer expiry or stream operations.
pending_link: index_list.Link = .{},
/// May have output for quiche_conn_send.
dirty_link: index_list.Link = .{},
/// Has undelivered lifecycle or stream events.
event_link: index_list.Link = .{},
/// Close event delivered; the slot is retired on the next turn.
release_link: index_list.Link = .{},
/// Has deferred stream close events, made deliverable by the next poll.
deferred_link: index_list.Link = .{},
table: StreamTable = .{},

pub fn open(
    self: *Connection,
    ctx: *const tls.Context,
    config: *const binding.Config,
    params: OpenParams,
) Error!void {
    assert(self.state == .free);
    assert(self.conn == null);
    assert(!self.pending_link.linked and !self.dirty_link.linked and !self.event_link.linked and !self.release_link.linked);
    assert(!self.deferred_link.linked);
    self.handshake = .{ .now_unix = params.now.unixSeconds() };
    self.direction = params.direction;
    self.peer = params.peer;
    self.peer_sockaddr = binding.SockAddr.fromAddress(params.peer);
    self.local_sockaddr = binding.SockAddr.fromAddress(params.local);
    self.expected_peer_id = params.expected_peer_id;
    self.peer_id = null;
    self.scid = binding.Cid.fromSlice(&params.scid);
    self.created_ms = params.now.millis();
    self.last_send_ms = params.now.millis();
    self.closing = .none;
    self.flight_pending = false;
    self.connected_pending = false;
    self.answered = false;
    self.close_event = .none;
    self.path_changed_pending = null;
    self.write_lowat_ceiling = limits.write_lowat_max;
    self.table = StreamTable.init(params.direction);

    const ssl = try ctx.newSsl(&self.handshake);
    // quiche owns the SSL handle from this call onward and frees it even when construction
    // fails, so the slot must never free it.
    self.conn = c.quiche_conn_new_with_tls(
        self.scid.slice().ptr,
        self.scid.len,
        if (params.original_dcid) |*original| original.slice().ptr else null,
        if (params.original_dcid) |original| original.len else 0,
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

pub fn release(self: *Connection) void {
    assert(self.state != .free);
    if (self.conn) |conn| c.quiche_conn_free(conn);
    self.conn = null;
    self.state = .free;
    self.generation +|= 1;
    assert(self.conn == null);
}

pub fn recv(self: *Connection, datagram: []u8, from: *const binding.SockAddr, to: *const binding.SockAddr) Error!void {
    assert(self.conn != null);
    assert(from.len > 0);
    var info = c.quiche_recv_info{
        .from = @ptrCast(@constCast(from.any())),
        .from_len = from.len,
        .to = @ptrCast(@constCast(to.any())),
        .to_len = to.len,
    };
    _ = try binding.check(c.quiche_conn_recv(self.conn.?, datagram.ptr, datagram.len, &info));
}

pub fn send(self: *Connection, now_ms: u64, out: []u8) Error!?Sent {
    assert(self.conn != null);
    var info: binding.SendInfo = undefined;
    const rc = binding.connSend(self.conn.?, out, &info);
    const length = try binding.check(rc) orelse return null;
    assert(length <= out.len);
    self.last_send_ms = now_ms;
    const destination = binding.SockAddr.fromStorage(&info.to, info.to_len);
    const to = if (destination) |addr| addr.toAddress() orelse self.peer else self.peer;
    return .{ .bytes = out[0..length], .to = to, .transmit_at_ns = info.transmitDeadline() };
}

pub fn drainPathEvents(self: *Connection) ?types.Address {
    assert(self.conn != null);
    var migrated: ?types.Address = null;
    var drained: u8 = 0;
    while (drained < limits.path_events_per_call_max) : (drained += 1) {
        const event = c.quiche_conn_path_event_next(self.conn.?) orelse break;
        defer c.quiche_path_event_free(event);
        if (c.quiche_path_event_type(event) != c.QUICHE_PATH_EVENT_PEER_MIGRATED) continue;
        var local: c.struct_sockaddr_storage = undefined;
        var local_len: c.socklen_t = 0;
        var peer: c.struct_sockaddr_storage = undefined;
        var peer_len: c.socklen_t = 0;
        c.quiche_path_event_peer_migrated(event, &local, &local_len, &peer, &peer_len);
        const sockaddr = binding.SockAddr.fromStorage(&peer, peer_len) orelse continue;
        migrated = sockaddr.toAddress() orelse continue;
    }
    assert(drained <= limits.path_events_per_call_max);
    return migrated;
}

pub fn onTimeout(self: *Connection) void {
    assert(self.conn != null);
    assert(self.state != .free);
    c.quiche_conn_on_timeout(self.conn.?);
}

/// Time until quiche's next timer, or null when no timer is armed.
pub fn timeoutNs(self: *const Connection) ?u64 {
    assert(self.conn != null);
    assert(self.state != .free);
    const value = c.quiche_conn_timeout_as_nanos(self.conn.?);
    return if (value == std.math.maxInt(u64)) null else value;
}

/// QUIC packets quiche has processed on this connection.
pub fn receivedPackets(self: *const Connection) usize {
    assert(self.conn != null);
    var stats: c.quiche_stats = undefined;
    c.quiche_conn_stats(self.conn.?, &stats);
    return stats.recv;
}

/// quiche grants a blocked stream at least half of the peer's window once the peer reads, so a
/// watermark above that could never be reached.
pub fn learnPeerWindows(self: *Connection) void {
    assert(self.conn != null);
    var params: c.quiche_transport_params = undefined;
    if (!c.quiche_conn_peer_transport_params(self.conn.?, &params)) return;
    const window = @min(params.peer_initial_max_data, params.peer_initial_max_stream_data_bidi_local, params.peer_initial_max_stream_data_bidi_remote);
    self.write_lowat_ceiling = @intCast(@max(1, @min(limits.write_lowat_max, window / 2)));
}

pub fn collectStreams(self: *Connection) void {
    if (self.state != .established or self.closing == .after_flight) return;
    self.gatherReadable();
    self.gatherWritable();
}

fn gatherReadable(self: *Connection) void {
    const conn = self.conn.?;
    for (0..limits.streams_per_connection) |_| {
        const next = c.quiche_conn_stream_readable_next(conn);
        if (next < 0) break;
        const id: u64 = @intCast(next);
        if (self.table.find(id)) |entry_index| {
            self.table.markReady(entry_index, .{ .readable = true });
            continue;
        }
        if (!StreamTable.isPeerInitiated(self.direction, id)) continue;
        if (self.table.claimPeer(id) == null) {
            self.shutdownRaw(id, .read, types.app_error_stream_table_full);
            self.shutdownRaw(id, .write, types.app_error_stream_table_full);
        }
    }
}

// STOP must be captured before quiche reclaims a reset acknowledged by the peer. Native
// writable iteration omits exact-watermark credit, so also check the bounded armed set.
fn gatherWritable(self: *Connection) void {
    const conn = self.conn.?;
    for (0..limits.streams_per_connection) |_| {
        const next = c.quiche_conn_stream_writable_next(conn);
        if (next < 0) break;
        const id: u64 = @intCast(next);
        const entry_index = self.table.find(id) orelse continue;
        if (!self.table.matches(entry_index, id)) continue;
        const entry = &self.table.entries[entry_index];
        if (!entry.stopped and !entry.fin_sent) if (self.stopCode(id)) |code| {
            self.table.stop(entry_index, code);
            continue;
        };
        if (entry.write_lowat > 0) self.table.markReady(entry_index, .{ .writable = true });
    }
    var armed = self.table.armed;
    for (0..limits.streams_per_connection) |_| {
        if (armed == 0) break;
        const entry_index: u8 = @intCast(@ctz(armed));
        armed &= armed - 1;
        const entry = &self.table.entries[entry_index];
        const available = c.quiche_conn_stream_capacity(conn, entry.id);
        if (available < 0 or available >= entry.write_lowat) self.table.markReady(entry_index, .{ .writable = true });
    }
}

pub fn checkStreamInvariants(self: *const Connection) void {
    const table = &self.table;
    // E4: an armed writer is below its watermark or has an undelivered writable edge.
    var armed = table.armed;
    for (0..limits.streams_per_connection) |_| {
        if (armed == 0) break;
        const entry_index: u8 = @intCast(@ctz(armed));
        armed &= armed - 1;
        const entry = &table.entries[entry_index];
        assert(entry.write_lowat > 0);
        const available = c.quiche_conn_stream_capacity(self.conn.?, entry.id);
        assert(entry.ready.writable or (available >= 0 and available < entry.write_lowat));
    }
    // E5: every readable stream has an undelivered readable edge or an open delivered one.
    const iter = c.quiche_conn_readable(self.conn.?) orelse return;
    defer c.quiche_stream_iter_free(iter);
    var id: u64 = 0;
    for (0..2 * limits.streams_per_connection) |_| {
        if (!c.quiche_stream_iter_next(iter, &id)) break;
        const entry_index = table.find(id) orelse {
            assert(!StreamTable.isPeerInitiated(self.direction, id));
            continue;
        };
        const entry = &table.entries[entry_index];
        assert(entry.ready.readable or table.readOpen(entry_index) or entry.opened_pending or entry.closed_pending);
    }
}

pub fn drainEvents(self: *Connection, conn: types.Handle, events: []Event) usize {
    assert(conn.generation == self.generation and self.state != .free);
    var count: usize = 0;
    if (self.connected_pending) {
        if (count == events.len) return count;
        events[count] = .{ .connected = .{
            .conn = conn,
            .peer_id = self.peer_id.?,
            .direction = self.direction,
        } };
        count += 1;
        self.connected_pending = false;
    }
    if (self.path_changed_pending) |peer| {
        if (count == events.len) return count;
        events[count] = .{ .path_changed = .{ .conn = conn, .peer = peer } };
        count += 1;
        self.path_changed_pending = null;
    }
    const table = &self.table;
    for (0..limits.streams_per_connection) |_| {
        const entry_index = table.nextPending() orelse break;
        const entry = &table.entries[entry_index];
        const stream: types.StreamHandle = .{ .conn = conn, .id = entry.id, .slot = entry_index };
        if (entry.opened_pending) {
            if (count == events.len) return count;
            events[count] = .{ .stream_opened = stream };
            count += 1;
            table.takeOpened(entry_index);
        }
        const ready: u2 = @bitCast(entry.ready);
        if (ready != 0) {
            assert(!entry.closed_pending);
            if (count == events.len) return count;
            events[count] = .{ .stream_ready = .{ .stream = stream, .ready = table.takeReady(entry_index) } };
            count += 1;
        }
        if (entry.closed_pending) {
            if (count == events.len) return count;
            const closed = table.takeClosed(entry_index).?;
            events[count] = .{ .stream_closed = .{
                .stream = .{ .conn = conn, .id = closed.id, .slot = entry_index },
                .reset_code = closed.reset_code,
                .route = closed.route,
            } };
            count += 1;
        }
        assert(table.pending & StreamTable.bit(entry_index) == 0);
        table.advanceCursor(entry_index);
    }
    if (table.hasPending()) return count;
    if (self.close_event == .pending) {
        if (count == events.len) return count;
        events[count] = .{ .closed = .{
            .conn = conn,
            .peer_id = self.peer_id,
            .direction = self.direction,
            .reason = self.closing.started,
        } };
        count += 1;
        self.close_event = .reported;
    }
    return count;
}

pub fn hasEvents(self: *const Connection) bool {
    return self.connected_pending or self.path_changed_pending != null or self.table.hasPending() or
        self.close_event == .pending;
}

pub fn keepAlive(self: *Connection) bool {
    assert(self.conn != null);
    assert(self.state == .established);
    return c.quiche_conn_send_ack_eliciting(self.conn.?) == 0;
}

pub fn close(self: *Connection, reason: types.CloseReason, code: u64) void {
    assert(self.conn != null and self.state != .free);
    // The first local reason remains authoritative if another close cause arrives.
    const latched = if (self.closing == .none) reason else self.closeReason();
    self.closing = .{ .started = latched };
    _ = c.quiche_conn_close(self.conn.?, true, code, "", 0);
}

/// Closes once a flush has sent the final handshake flight, which quiche_close would discard.
pub fn deferClose(self: *Connection, reason: types.CloseReason, code: u64) void {
    assert(self.state == .established and self.flight_pending);
    assert(self.closing != .after_flight);
    const latched = if (self.closing == .none) reason else self.closeReason();
    self.closing = .{ .after_flight = .{ .reason = latched, .code = code } };
}

pub fn closeAfterFlight(self: *Connection) void {
    if (self.closing != .after_flight or self.flight_pending) return;
    const pending = self.closing.after_flight;
    self.close(pending.reason, pending.code);
}

pub fn markClosed(self: *Connection, reason: types.CloseReason) void {
    assert(self.state == .handshaking or self.state == .established);
    // Preserve the existing claims policy: immediate closes drain native readable streams;
    // closes waiting for the final flight do not. Claimed buffered reads survive either.
    if (self.state == .established and self.closing != .after_flight) self.gatherReadable();
    self.state = .closed;
    self.closing = .{ .started = reason };
    self.close_event = .pending;
    self.table.promoteDeferred();
}

pub fn isEstablished(self: *const Connection) bool {
    return c.quiche_conn_is_established(self.conn.?);
}

pub fn isFinished(self: *const Connection) bool {
    return c.quiche_conn_is_closed(self.conn.?) or c.quiche_conn_is_draining(self.conn.?);
}

pub fn closeReason(self: *const Connection) types.CloseReason {
    switch (self.closing) {
        .none => {},
        .after_flight => |pending| return pending.reason,
        .started => |reason| return reason,
    }
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

pub fn openStream(self: *Connection) Error!OpenedStream {
    if (self.state != .established or self.closing != .none) return error.NotEstablished;
    if (c.quiche_conn_peer_streams_left_bidi(self.conn.?) == 0) return error.StreamLimit;
    const index = self.table.freeLocal() orelse return error.StreamTableFull;
    const id = self.table.next_local_id;
    var code: u64 = 0;
    _ = try binding.check(c.quiche_conn_stream_send(self.conn.?, id, "", 0, false, &code));
    self.table.claimLocal(index, id);
    assert(self.table.matches(index, id));
    return .{ .id = id, .index = index };
}

pub fn read(self: *Connection, index: u8, id: u64, buf: []u8, effects: *Effects) Error!types.Read {
    const result = try self.readNative(index, id, buf);
    effects.dirty = result.len > 0 or result.fin or result.reset_code != null;
    if ((result.len == 0 or result.fin) and self.table.matches(index, id)) self.table.readDone(index);
    return result;
}

fn readNative(self: *Connection, index: u8, id: u64, buf: []u8) Error!types.Read {
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
    const length = try self.streamResult(index, rc) orelse return .{ .len = 0, .fin = false };
    assert(length <= buf.len);
    if (fin) {
        self.table.markFinReceived(index);
        if (self.table.entries[index].fin_sent) self.finishStream(index, null);
    }
    return .{ .len = length, .fin = fin };
}

pub fn write(self: *Connection, index: u8, id: u64, bytes: []const u8, fin: bool, effects: *Effects) Error!usize {
    const written = self.writeNative(index, id, bytes, fin) catch |err| {
        if (err == error.WouldBlock) {
            effects.dirty = self.armWrite(index, id, bytes.len);
        } else if (self.table.matches(index, id)) self.table.disarm(index);
        return err;
    };
    effects.dirty = written > 0 or (fin and written == bytes.len);
    if (self.table.matches(index, id)) {
        if (written < bytes.len) {
            effects.dirty = self.armWrite(index, id, bytes.len - written) or effects.dirty;
        } else self.table.disarm(index);
    }
    return written;
}

fn writeNative(self: *Connection, index: u8, id: u64, bytes: []const u8, fin: bool) Error!usize {
    assert(self.conn != null);
    assert(self.table.matches(index, id));
    const entry = &self.table.entries[index];
    if (entry.stopped) {
        // quiche may already have freed the stream; report the stop it delivered.
        self.table.markFinSent(index);
        if (entry.fin_received) self.finishStream(index, entry.reset_code);
        return error.StreamStopped;
    }
    var code: u64 = 0;
    const rc = c.quiche_conn_stream_send(self.conn.?, id, bytes.ptr, bytes.len, fin, &code);
    if (rc == c.QUICHE_ERR_STREAM_STOPPED) {
        self.table.markFinSent(index);
        if (self.table.entries[index].fin_received) self.finishStream(index, code);
        return error.StreamStopped;
    }
    const length = try self.streamResult(index, rc) orelse {
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

pub fn capacity(self: *Connection, index: u8, id: u64) Error!usize {
    assert(self.conn != null and self.table.matches(index, id));
    if (self.table.entries[index].stopped) return error.StreamStopped;
    return (try self.streamResult(index, c.quiche_conn_stream_capacity(self.conn.?, id))) orelse error.WouldBlock;
}

fn streamResult(self: *Connection, index: u8, rc: isize) Error!?usize {
    return binding.check(rc) catch |err| switch (err) {
        error.InvalidStreamState => {
            self.finishStream(index, null);
            return error.UnknownStream;
        },
        else => return err,
    };
}

fn armWrite(self: *Connection, index: u8, id: u64, wanted: usize) bool {
    assert(self.table.matches(index, id));
    const lowat: u32 = @intCast(@min(wanted, self.write_lowat_ceiling));
    if (lowat == 0 or self.table.entries[index].write_lowat == lowat) return false;
    self.table.arm(index, lowat);
    const rc = c.quiche_conn_stream_writable(self.conn.?, id, lowat);
    // Already writable, stopped or finished: the owner learns which on its next write.
    if (rc != 0) self.table.markReady(index, .{ .writable = true });
    return true;
}

pub fn streamReadable(self: *const Connection, index: u8, id: u64) bool {
    assert(self.table.matches(index, id));
    return c.quiche_conn_stream_readable(self.conn.?, id);
}

/// The peer's STOP_SENDING code when it stopped the stream. quiche frees a stopped stream
/// once its reset is acknowledged, so the code is read while the stream still exists.
fn stopCode(self: *Connection, id: u64) ?u64 {
    assert(self.conn != null);
    var code: u64 = 0;
    const rc = c.quiche_conn_stream_send(self.conn.?, id, "", 0, false, &code);
    return if (rc == c.QUICHE_ERR_STREAM_STOPPED) code else null;
}

pub fn shutdown(
    self: *Connection,
    index: u8,
    id: u64,
    direction: types.ShutdownDirection,
    code: u64,
) Effects {
    assert(self.conn != null);
    assert(self.table.matches(index, id));
    self.shutdownRaw(id, direction, code);
    if (direction == .read) {
        self.table.shutdownRead(index);
    } else {
        self.table.shutdownWrite(index);
    }
    const entry = self.table.entries[index];
    if (entry.fin_received and entry.fin_sent) self.finishStream(index, null);
    return .{ .dirty = true, .collect = self.table.armed != 0 };
}

pub fn closeStream(self: *Connection, index: u8, id: u64, code: u64) Effects {
    assert(self.conn != null);
    assert(self.table.matches(index, id));
    const entry = self.table.entries[index];
    if (!entry.fin_received) self.shutdownRaw(id, .read, code);
    if (!entry.fin_sent) self.shutdownRaw(id, .write, code);
    self.finishStream(index, null);
    assert(!self.table.matches(index, id));
    // A local reset can release connection credit to other blocked writers.
    return .{ .dirty = true, .collect = self.table.armed != 0 };
}

fn finishStream(self: *Connection, index: u8, reset_code: ?u64) void {
    assert(index < limits.streams_per_connection);
    assert(self.table.entries[index].claimed);
    if (self.state == .closed) {
        self.table.discard(index);
    } else {
        self.table.clear(index, reset_code);
    }
}

fn shutdownRaw(self: *Connection, id: u64, direction: types.ShutdownDirection, code: u64) void {
    const which: c_int = if (direction == .read)
        c.QUICHE_SHUTDOWN_READ
    else
        c.QUICHE_SHUTDOWN_WRITE;
    _ = c.quiche_conn_stream_shutdown(self.conn.?, id, @intCast(which), code);
}

comptime {
    assert(@sizeOf(Connection) <= 5 * 1_024);
}

test {
    _ = StreamTable;
}
