const std = @import("std");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const constants = @import("../constants.zig");
const index_list = @import("../index_list.zig");
const limits = @import("limits.zig");
const retry = @import("retry.zig");
const peer_id = @import("../wire/peer_id.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");
const StreamTable = @import("stream_table.zig").StreamTable;

const assert = std.debug.assert;
const c = binding.c;

pub const Now = types.Now;
pub const Direction = types.Direction;
pub const ShutdownDirection = types.ShutdownDirection;
pub const CloseReason = types.CloseReason;
pub const Read = types.Read;
pub const Address = types.Address;
pub const Sent = types.Sent;
pub const Readiness = types.Readiness;
pub const Route = types.Route;

pub const Error = std.mem.Allocator.Error || error{InvalidLimits};

pub const StreamError = error{
    StaleHandle,
    UnknownStream,
    WouldBlock,
    StreamStopped,
    StreamLimit,
    StreamTableFull,
    NotEstablished,
    Transport,
};

pub const DialError = error{
    AddressFamilyUnsupported,
    TableFull,
    DialLimit,
    OpenFailed,
};

pub const Handle = types.Handle;
pub const StreamHandle = types.StreamHandle;

/// How long a turn may run after its clock read before a timer key checked against quiche's own
/// clock is treated as late.
const invariant_clock_slack_ns: u64 = 250 * std.time.ns_per_ms;

pub const Event = union(enum) {
    connected: struct { conn: Handle, peer_id: peer_id.PeerId, direction: Direction },
    closed: struct {
        conn: Handle,
        peer_id: ?peer_id.PeerId,
        direction: Direction,
        reason: CloseReason,
    },
    /// A newly claimed peer stream. It implies readiness for read and write.
    stream_opened: StreamHandle,
    /// Edge-triggered: a readable stream is reported again only after a read returned Done, and
    /// a writable one only after a blocked write armed it and send capacity reached the armed
    /// watermark, or the peer stopped the stream.
    stream_ready: struct { stream: StreamHandle, ready: Readiness },
    /// `route` is the stream's owner, captured before its table entry cleared. The owner of a
    /// routed stream caused its close in one of its own stream calls, so that close is reported
    /// by the next poll and does not make events pending.
    stream_closed: struct { stream: StreamHandle, reset_code: ?u64, route: Route = .{} },
    path_changed: struct { conn: Handle, peer: Address },
};

pub const Limits = struct {
    connections_max: u16 = limits.connections_max_default,
    handshaking_max: u16 = limits.handshaking_max,
    handshaking_per_source_max: u16 = limits.handshaking_per_source_max,
    dialing_max: u16 = limits.dialing_max,
    outbound_max: ?u16 = null,
    outbound_reserved: u16 = 0,
    receive_budget_bytes: u64 = limits.receive_budget_bytes,
    idle_timeout_ms: u64 = limits.idle_timeout_ms,
    handshake_timeout_ms: u64 = limits.handshake_timeout_ms,
    unanswered_dial_timeout_ms: u64 = limits.unanswered_dial_timeout_ms,
    keep_alive_ms: u64 = limits.keep_alive_ms,
    keylog: bool = false,
};

/// Per-connection visits by phase. An idle connection is visited in none of them. Readiness tests
/// and the idle benchmarks read them.
pub const Visits = struct {
    /// Timer keys popped by expire.
    timer: u64 = 0,
    /// quiche_conn_on_timeout calls, made only when a popped key found quiche's timer expired.
    timeouts: u64 = 0,
    /// Connections whose stream readiness collect gathered.
    collect: u64 = 0,
    /// Dirty connections a flush pass drained.
    flush: u64 = 0,
};

pub const ReceiveOutcome = union(enum) {
    accepted: Handle,
    version_negotiation: []u8,
    retry: []u8,
    dropped,
};

/// Configured flow-control windows, excluding native QUIC/TLS overhead.
pub const MemoryPlan = struct {
    requested_receive_window_bytes: u64,
    receive_window_bytes: u64,
    connection_window_bytes: u64,
    stream_window_bytes: u64,
    native_pacing_supported: bool,
};

pub const ConnectionCounters = struct {
    established: [@typeInfo(Direction).@"enum".fields.len]u64 = @splat(0),
    closed: [@typeInfo(Direction).@"enum".fields.len][@typeInfo(CloseReason).@"union".fields.len]u64 = @splat(@splat(0)),
};

const Stream = struct {
    slot: *connection.Slot,
    index: u8,
    id: u64,
};

pub const Options = struct {
    tls: tls.Context,
    limits: Limits = .{},
    local: [2]?Address,
    /// Uniform startup secret from a cryptographic random source; borrowed only during init.
    seed: *const [std.Random.DefaultCsprng.secret_seed_length]u8,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    tls: tls.Context,
    config: binding.Config,
    limits: Limits,
    local: [2]?Address,
    registry: @import("registry.zig").Registry,
    connection_window: u64,
    stream_window: u64,
    outbound_max: u16,
    csprng: std.Random.DefaultCsprng,
    retry_key: [32]u8,
    visits: Visits = .{},
    connection_metrics: ConnectionCounters = .{},
    /// The received packet's token, borrowed by its header until the next receive. A field
    /// rather than a local so ReleaseSafe does not fill it for every datagram.
    header_token: [binding.token_length_max]u8 = undefined,

    /// Live connections, and those still handshaking.
    pub const Resources = struct { active: usize, handshaking: usize };

    pub fn resourceSnapshot(self: *const Engine) Resources {
        return .{ .active = self.registry.active_len, .handshaking = self.registry.handshaking };
    }

    pub fn validateLimits(wanted: Limits) Error!u16 {
        if (wanted.connections_max == 0) return error.InvalidLimits;
        if (wanted.connections_max > limits.connections_max_ceiling) return error.InvalidLimits;
        if (wanted.handshaking_max == 0 or wanted.handshaking_max > wanted.connections_max) {
            return error.InvalidLimits;
        }
        if (wanted.handshaking_per_source_max == 0) return error.InvalidLimits;
        const minimum_receive_budget = @as(u64, wanted.connections_max) * limits.connection_window_min;
        if (wanted.receive_budget_bytes < minimum_receive_budget) return error.InvalidLimits;
        if (wanted.idle_timeout_ms > limits.timeout_ms_max or wanted.handshake_timeout_ms > limits.timeout_ms_max or
            wanted.unanswered_dial_timeout_ms > limits.timeout_ms_max or wanted.keep_alive_ms > limits.timeout_ms_max) return error.InvalidLimits;
        if (wanted.idle_timeout_ms == 0) return error.InvalidLimits;
        if (wanted.handshake_timeout_ms == 0 or wanted.unanswered_dial_timeout_ms == 0) return error.InvalidLimits;
        if (wanted.keep_alive_ms == 0) return error.InvalidLimits;
        if (wanted.dialing_max == 0 or wanted.outbound_reserved > wanted.dialing_max or
            wanted.outbound_reserved > wanted.connections_max) return error.InvalidLimits;
        const outbound_max = wanted.outbound_max orelse
            @max(1, wanted.connections_max - wanted.connections_max / 4);
        if (outbound_max == 0 or outbound_max > wanted.connections_max) return error.InvalidLimits;

        return outbound_max;
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!Engine {
        std.debug.assert(options.local[0] != null or options.local[1] != null);
        if (options.local[0]) |address| std.debug.assert(address == .ip4);
        if (options.local[1]) |address| std.debug.assert(address == .ip6);
        const wanted = options.limits;
        const outbound_max = try validateLimits(wanted);

        const connection_window = @min(
            wanted.receive_budget_bytes / wanted.connections_max,
            limits.connection_window_max,
        );
        const stream_window = connection_window / 2;

        var config = binding.Config.init(
            wanted.idle_timeout_ms,
            connection_window,
            stream_window,
        ) catch return error.OutOfMemory;
        errdefer config.deinit();

        var csprng = std.Random.DefaultCsprng.init(options.seed.*);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&csprng));
        var retry_key: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &retry_key);
        csprng.fill(&retry_key);
        var route_seed = csprng.random().int(u64);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&route_seed));

        var registry = try @import("registry.zig").Registry.init(allocator, wanted.connections_max, wanted.keylog, route_seed);
        errdefer registry.deinit(allocator);

        return .{
            .allocator = allocator,
            .tls = options.tls,
            .config = config,
            .limits = wanted,
            .local = options.local,
            .registry = registry,
            .connection_window = connection_window,
            .stream_window = stream_window,
            .outbound_max = outbound_max,
            .csprng = csprng,
            .retry_key = retry_key,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.registry.deinit(self.allocator);
        self.tls.deinit();
        self.config.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.csprng));
        std.crypto.secureZero(u8, &self.retry_key);
        self.* = undefined;
    }

    pub fn sendOwner(self: *const Engine, index: u16) ?Handle {
        if (index >= self.registry.slots.len) return null;
        const slot = &self.registry.slots[index];
        if (slot.state == .free or slot.state == .closed) return null;
        return .{ .index = index, .generation = slot.generation };
    }

    pub fn takeKeylog(self: *Engine, index: u16, out: []u8) usize {
        assert(index < self.registry.slots.len);
        assert(out.len >= tls.keylog_capacity);
        const slot = &self.registry.slots[index];
        if (slot.state == .free) return 0;
        return slot.takeKeylog(out);
    }

    fn retire(self: *Engine, index: u16) void {
        self.registry.retire(index);
    }

    pub fn failSend(self: *Engine, index: u16) void {
        assert(index < self.registry.slots.len);
        const slot = &self.registry.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        self.markClosed(index, .send_failed);
    }

    /// Transport-only slot indices. Track their generations with sendOwner across turns.
    pub fn activeIndices(self: *const Engine) []const u16 {
        assert(self.registry.active.len == self.registry.slots.len);
        assert(self.registry.active_len <= self.registry.active.len);
        return self.registry.active[0..self.registry.active_len];
    }

    pub fn memoryPlan(self: *const Engine) MemoryPlan {
        const count = self.limits.connections_max;
        return .{
            .requested_receive_window_bytes = self.limits.receive_budget_bytes,
            .receive_window_bytes = self.connection_window * count,
            .connection_window_bytes = self.connection_window,
            .stream_window_bytes = self.stream_window,
            .native_pacing_supported = binding.native_pacing_supported,
        };
    }

    pub fn dial(
        self: *Engine,
        peer: *const Address,
        expected: peer_id.PeerId,
        now: Now,
    ) DialError!Handle {
        assert(self.registry.active_len <= self.registry.active.len);
        assert(self.registry.dialing <= self.registry.outbound);
        if (self.registry.dialing >= self.limits.dialing_max) return error.DialLimit;
        if (self.registry.outbound >= self.outbound_max) return error.DialLimit;
        const local = self.localFor(peer.*) orelse return error.AddressFamilyUnsupported;
        const index = self.registry.claim() orelse return error.TableFull;
        assert(index < self.registry.slots.len);
        const slot = &self.registry.slots[index];
        slot.open(&self.tls, &self.config, .{
            .direction = .outbound,
            .local = local,
            .peer = peer.*,
            .scid = self.connectionId(),
            .expected_peer_id = expected,
            .now = now,
            .keylog = self.registry.keylogFor(index),
        }) catch {
            self.registry.unclaim(index);
            return error.OpenFailed;
        };
        self.registry.addRoute(&slot.scid, index) catch {
            self.retire(index);
            return error.TableFull;
        };
        self.registry.dialing += 1;
        self.registry.outbound += 1;
        assert(self.registry.dialing <= self.limits.dialing_max);
        assert(self.registry.outbound <= self.outbound_max);
        self.markDirty(index);
        self.rekey(index, now);
        return .{ .index = index, .generation = slot.generation };
    }

    fn connectionId(self: *Engine) [limits.local_cid_length]u8 {
        var bytes: [limits.local_cid_length]u8 = undefined;
        self.csprng.fill(&bytes);
        return bytes;
    }

    /// An outbound connection whose final handshake flight may be unsent closes on the turn after
    /// a flush drains its output.
    pub fn close(self: *Engine, conn: Handle, code: u64) bool {
        const slot = self.liveSlot(conn) catch return false;
        assert(slot.conn != null);
        assert(slot.close_reason == null);
        if (slot.flight_pending) slot.deferClose(.host, code) else slot.close(.host, code);
        self.markDirty(conn.index);
        return true;
    }

    pub fn abandon(self: *Engine, conn: Handle) bool {
        const slot = self.readableSlot(conn) catch return false;
        switch (slot.state) {
            .handshaking => {
                self.leaveHandshaking(slot);
                if (slot.direction == .outbound) {
                    assert(self.registry.outbound > 0);
                    self.registry.outbound -= 1;
                }
            },
            .closed => {},
            else => return false,
        }
        assert(conn.index < self.registry.slots.len);
        assert(self.registry.active_len > 0);
        self.retire(conn.index);
        return true;
    }

    pub fn peerId(self: *const Engine, conn: Handle) ?peer_id.PeerId {
        const slot = self.liveView(conn) orelse return null;
        assert(slot.state != .free);
        assert(slot.generation == conn.generation);
        return slot.peer_id;
    }

    /// True once an outbound handshake processed any packet from the server, including a Retry.
    pub fn dialAnswered(self: *const Engine, conn: Handle) bool {
        const slot = self.liveView(conn) orelse return false;
        return slot.direction == .outbound and slot.answered;
    }

    fn handshakeLimitMs(self: *const Engine, slot: *const connection.Slot) u64 {
        if (slot.direction == .outbound and !slot.answered)
            return @min(self.limits.unanswered_dial_timeout_ms, self.limits.handshake_timeout_ms);
        return self.limits.handshake_timeout_ms;
    }

    pub fn peerAddress(self: *const Engine, conn: Handle) ?Address {
        const slot = self.liveView(conn) orelse return null;
        assert(slot.state != .free);
        assert(slot.generation == conn.generation);
        return slot.peer;
    }

    pub fn direction(self: *const Engine, conn: Handle) ?Direction {
        const slot = self.liveView(conn) orelse return null;
        assert(slot.state != .free);
        assert(slot.generation == conn.generation);
        return slot.direction;
    }

    /// Opening a stream queues no frame, so it marks nothing.
    pub fn openStream(self: *Engine, conn: Handle) StreamError!StreamHandle {
        const slot = try self.liveSlot(conn);
        const opened = slot.openStream() catch |err| {
            if (err != error.StreamLimit and err != error.StreamTableFull and err != error.NotEstablished) self.markDirty(conn.index);
            return streamError(err);
        };
        assert(opened.index < limits.streams_per_connection);
        assert(slot.table.matches(opened.index, opened.id));
        return .{ .conn = conn, .id = opened.id, .slot = opened.index };
    }

    /// Marks the connection dirty only when bytes were consumed or a FIN or reset was read.
    /// A read that reaches Done ends the delivered readable edge.
    pub fn read(self: *Engine, stream: StreamHandle, buf: []u8) StreamError!Read {
        const target = try self.readableStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        defer self.noteEvents(stream.conn.index);
        const result = target.slot.read(target.index, target.id, buf) catch |err|
            return streamError(err);
        assert(result.len <= buf.len);
        if (result.len > 0) assert(result.reset_code == null);
        if (result.len > 0 or result.fin or result.reset_code != null) self.markLiveDirty(stream.conn.index);
        if ((result.len == 0 or result.fin) and target.slot.table.matches(target.index, target.id)) {
            target.slot.table.readDone(target.index);
        }
        return result;
    }

    /// Names the owner that now holds the stream. The engine never interprets the route; it
    /// returns it from `route` and in the stream's close event.
    pub fn bindStream(self: *Engine, stream: StreamHandle, owner: Route) StreamError!void {
        const target = try self.readableStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        target.slot.table.entries[target.index].route = owner;
    }

    /// The owner bound to a live stream, or null when the handle is stale. O(1).
    pub fn route(self: *const Engine, stream: StreamHandle) ?Route {
        if (stream.conn.index >= self.registry.slots.len) return null;
        const slot = &self.registry.slots[stream.conn.index];
        if (slot.generation != stream.conn.generation or slot.state == .free) return null;
        if (!slot.table.matches(stream.slot, stream.id)) return null;
        return slot.table.entries[stream.slot].route;
    }

    pub const StreamWaits = struct {
        /// A readable edge was delivered and the stream has not been read to Done since.
        read_open: bool,
        /// A blocked write waits on armed write interest, an undelivered writable edge or a stop.
        write_waiting: bool,
    };

    /// What an owner of a live stream on an established connection is waiting for, or null
    /// otherwise. Owners check their ready lists against it.
    pub fn streamWaits(self: *const Engine, stream: StreamHandle) ?StreamWaits {
        if (self.route(stream) == null) return null;
        const slot = &self.registry.slots[stream.conn.index];
        if (slot.state != .established or slot.pending_close != null or slot.close_reason != null) return null;
        const entry = &slot.table.entries[stream.slot];
        return .{
            .read_open = slot.table.readOpen(stream.slot),
            .write_waiting = entry.write_lowat > 0 or entry.ready.writable or entry.stopped,
        };
    }

    pub fn streamReadable(self: *Engine, stream: StreamHandle) StreamError!bool {
        const target = try self.readableStream(stream);
        return binding.c.quiche_conn_stream_readable(target.slot.conn.?, target.id);
    }

    /// Marks the connection dirty only when bytes were accepted or a FIN was queued. A WouldBlock
    /// or short write arms write interest at min(unwritten bytes, the connection's watermark
    /// ceiling); a writable event follows once the stream's send capacity reaches it. Arming may
    /// queue a blocked frame, so it marks the connection dirty; a repeated WouldBlock at the same
    /// watermark marks nothing.
    pub fn write(
        self: *Engine,
        stream: StreamHandle,
        bytes: []const u8,
        fin: bool,
    ) StreamError!usize {
        const target = try self.liveStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        const index = stream.conn.index;
        defer self.noteEvents(index);
        const written = target.slot.write(target.index, target.id, bytes, fin) catch |err| {
            if (err == error.WouldBlock) {
                self.armWrite(index, target, bytes.len);
            } else if (target.slot.table.matches(target.index, target.id)) {
                target.slot.table.disarm(target.index);
            }
            return streamError(err);
        };
        assert(written <= bytes.len);
        if (written > 0 or (fin and written == bytes.len)) self.markDirty(index);
        if (!target.slot.table.matches(target.index, target.id)) return written;
        if (written < bytes.len) {
            self.armWrite(index, target, bytes.len - written);
        } else target.slot.table.disarm(target.index);
        return written;
    }

    fn armWrite(self: *Engine, index: u16, target: Stream, wanted: usize) void {
        assert(target.slot.table.matches(target.index, target.id));
        const lowat: u32 = @intCast(@min(wanted, target.slot.write_lowat_ceiling));
        if (lowat == 0) return;
        const entry = &target.slot.table.entries[target.index];
        if (entry.write_lowat == lowat) return;
        target.slot.table.arm(target.index, lowat);
        self.markDirty(index);
        const rc = c.quiche_conn_stream_writable(target.slot.conn.?, target.id, lowat);
        // Already writable, stopped or finished: the owner learns which on its next write.
        if (rc != 0) target.slot.table.markReady(target.index, .{ .writable = true });
    }

    pub fn streamCapacity(self: *Engine, stream: StreamHandle) StreamError!usize {
        const target = try self.readableStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        defer self.noteEvents(stream.conn.index);
        const available = target.slot.capacity(target.index, target.id) catch |err|
            return streamError(err);
        assert(target.index < limits.streams_per_connection);
        return available;
    }

    pub fn shutdown(self: *Engine, stream: StreamHandle, dir: ShutdownDirection, code: u64) void {
        const target = self.liveStream(stream) catch return;
        assert(target.index < limits.streams_per_connection);
        assert(target.slot.conn != null);
        if (dir == .write) target.slot.table.disarm(target.index);
        target.slot.shutdown(target.index, target.id, dir, code);
        self.markDirty(stream.conn.index);
        self.recheckWriters(stream.conn.index);
        self.noteEvents(stream.conn.index);
    }

    pub fn closeStream(self: *Engine, stream: StreamHandle, code: u64) void {
        const target = self.liveStream(stream) catch return;
        assert(target.index < limits.streams_per_connection);
        assert(target.slot.conn != null);
        target.slot.closeStream(target.index, target.id, code);
        self.markDirty(stream.conn.index);
        self.recheckWriters(stream.conn.index);
        self.noteEvents(stream.conn.index);
    }

    /// A local reset recomputes quiche's connection send capacity, so blocked writers on the
    /// connection are checked again at the next collect.
    fn recheckWriters(self: *Engine, index: u16) void {
        if (self.registry.slots[index].table.armed != 0) self.markCollect(index);
    }

    /// Drains connections with undelivered events in FIFO order. A connection whose events do
    /// not fit stays at the head. Per connection: connected, path_changed, stream events, closed.
    pub fn pollEvents(self: *Engine, events: []Event) usize {
        const slots = self.registry.slots;
        var promoted: usize = 0;
        while (self.registry.deferred.pop(slots, "deferred_link")) |row| : (promoted += 1) {
            assert(promoted < slots.len);
            slots[row].table.promoteDeferred();
            self.noteEvents(@intCast(row));
        }
        var count: usize = 0;
        var visited: usize = 0;
        while (count < events.len) : (visited += 1) {
            assert(visited <= slots.len);
            const head = self.registry.events.head;
            if (head == index_list.none) break;
            const index: u16 = @intCast(head);
            const slot = &slots[index];
            assert(slot.state != .free);
            count = self.drainEvents(index, events, count);
            if (slot.hasEvents()) break;
            self.registry.events.remove(slots, "event_link", index);
            if (slot.close_event == .reported) _ = self.registry.released.insert(slots, "release_link", index);
        }
        assert(count <= events.len);
        return count;
    }

    fn drainEvents(self: *Engine, index: u16, events: []Event, start: usize) usize {
        const slot = &self.registry.slots[index];
        const conn = self.toHandle(index);
        var count = start;
        if (slot.connected_pending) {
            if (count == events.len) return count;
            events[count] = .{ .connected = .{
                .conn = conn,
                .peer_id = slot.peer_id.?,
                .direction = slot.direction,
            } };
            count += 1;
            slot.connected_pending = false;
        }
        if (slot.path_changed_pending) |peer| {
            if (count == events.len) return count;
            events[count] = .{ .path_changed = .{ .conn = conn, .peer = peer } };
            count += 1;
            slot.path_changed_pending = null;
        }
        const table = &slot.table;
        for (0..limits.streams_per_connection) |_| {
            const entry_index = table.nextPending() orelse break;
            const entry = &table.entries[entry_index];
            const stream: StreamHandle = .{ .conn = conn, .id = entry.id, .slot = entry_index };
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
            assert(table.pending & @import("stream_table.zig").bit(entry_index) == 0);
            table.advanceCursor(entry_index);
        }
        if (table.hasPending()) return count;
        if (slot.close_event == .pending) {
            if (count == events.len) return count;
            events[count] = .{ .closed = .{
                .conn = conn,
                .peer_id = slot.peer_id,
                .direction = slot.direction,
                .reason = slot.close_reason.?,
            } };
            count += 1;
            slot.close_event = .reported;
        }
        return count;
    }

    /// O(1).
    pub fn eventsPending(self: *const Engine) bool {
        return self.registry.events.len > 0;
    }

    /// First connection that may have output. O(1).
    pub fn nextDirty(self: *const Engine) ?u16 {
        const head = self.registry.dirty.head;
        return if (head == index_list.none) null else @intCast(head);
    }

    pub fn dirtyCount(self: *const Engine) usize {
        return self.registry.dirty.len;
    }

    /// A flush left connections with output. O(1).
    pub fn backlog(self: *const Engine) bool {
        return self.registry.dirty.len > 0;
    }

    /// Earliest timer key in monotonic nanoseconds. O(1).
    pub fn nextDeadlineNs(self: *const Engine) ?u64 {
        const top = self.registry.timers.peek() orelse return null;
        return top.deadline;
    }

    pub fn receive(
        self: *Engine,
        datagram: []u8,
        from: *const Address,
        now: Now,
        out: []u8,
    ) ReceiveOutcome {
        assert(datagram.len <= out.len);
        assert(self.registry.slots.len > 0);
        const local = self.localFor(from.*) orelse return .dropped;
        const header = binding.headerInfo(datagram, &self.header_token) catch
            return .dropped;
        if (self.registry.findRoute(&header.dcid)) |index| {
            _ = self.feed(index, datagram, from, now, false);
            return .{ .accepted = self.toHandle(index) };
        }
        if (header.packet_type == .short) {
            // A peer that changed its connection ID after a rebinding is found by address. Junk
            // from a live peer's address marks nothing.
            const index = self.slotForPeer(from) orelse
                return .dropped;
            if (!self.feed(index, datagram, from, now, true)) return .dropped;
            return .{ .accepted = self.toHandle(index) };
        }
        if (datagram.len < limits.client_initial_min) {
            return .dropped;
        }
        if (header.packet_type == .version_negotiation or header.version == 0) {
            return .dropped;
        }
        if (!binding.versionSupported(header.version)) {
            return negotiateVersion(&header, out);
        }
        if (header.packet_type != .initial) return .dropped;
        // RFC 9000 section 7.2 requires at least eight bytes for a new connection's DCID.
        if (header.dcid.len < limits.initial_dcid_length_min) return .dropped;
        if (self.registry.handshaking >= self.limits.handshaking_max) {
            return .dropped;
        }
        if (self.handshakingFromSource(from) >= self.limits.handshaking_per_source_max) {
            return .dropped;
        }
        if (!retry.isLocal(header.token)) {
            return self.sendRetry(&header, from, now, out);
        }
        const original = retry.validate(&self.retry_key, from, &header.dcid, header.token, now.mono_ms, self.limits.handshake_timeout_ms) orelse return .dropped;
        const scid = header.dcid.bytes[0..limits.local_cid_length].*;
        const reserved = self.limits.outbound_reserved -| self.registry.dialing;
        if (self.limits.connections_max - self.registry.active_len <= reserved)
            return .dropped;
        const index = self.registry.claim() orelse return .dropped;

        const slot = &self.registry.slots[index];
        slot.open(&self.tls, &self.config, .{
            .direction = .inbound,
            .original_dcid = original,
            .local = local,
            .peer = from.*,
            .scid = scid,
            .expected_peer_id = null,
            .now = now,
            .keylog = self.registry.keylogFor(index),
        }) catch {
            self.registry.unclaim(index);
            return .dropped;
        };
        self.registry.addRoute(&slot.scid, index) catch {
            self.retire(index);
            return .dropped;
        };
        assert(slot.scid.eql(&header.dcid));
        self.registry.handshaking += 1;
        assert(self.registry.handshaking <= self.limits.handshaking_max);
        _ = self.feed(index, datagram, from, now, false);
        return .{ .accepted = self.toHandle(index) };
    }

    fn sendRetry(self: *Engine, header: *const binding.HeaderInfo, from: *const Address, now: Now, out: []u8) ReceiveOutcome {
        const bytes = self.connectionId();
        const scid = binding.Cid.fromSlice(&bytes);
        var buffer: [retry.token_max]u8 = undefined;
        const token = retry.mint(&self.retry_key, from, &header.dcid, &scid, now.mono_ms, &buffer);
        const length = (binding.check(c.quiche_retry(header.scid.slice().ptr, header.scid.len, header.dcid.slice().ptr, header.dcid.len, scid.slice().ptr, scid.len, token.ptr, token.len, header.version, out.ptr, out.len)) catch return .dropped) orelse return .dropped;
        return .{ .retry = out[0..length] };
    }

    fn negotiateVersion(
        header: *const binding.HeaderInfo,
        out: []u8,
    ) ReceiveOutcome {
        const written = binding.check(c.quiche_negotiate_version(
            header.scid.slice().ptr,
            header.scid.len,
            header.dcid.slice().ptr,
            header.dcid.len,
            out.ptr,
            out.len,
        )) catch return .dropped;
        const length = written orelse return .dropped;
        assert(length <= out.len);
        return .{ .version_negotiation = out[0..length] };
    }

    /// Pops due timer keys. Applies the handshake limit, keep-alive and a deferred close whose
    /// flight left, and calls on_timeout only when quiche's own timer has expired. Each popped
    /// connection joins collect and dirty. A connection re-keyed during this call is not popped
    /// again in it.
    pub fn expire(self: *Engine, now: Now) void {
        const registry = &self.registry;
        const now_ns = now.nanos();
        var count: usize = 0;
        while (count < registry.expired.len) : (count += 1) {
            const row = registry.timers.popDue(now_ns) orelse break;
            registry.expired[count] = @intCast(row);
        }
        self.visits.timer +|= count;
        for (registry.expired[0..count]) |index| self.fire(index, now);
    }

    fn fire(self: *Engine, index: u16, now: Now) void {
        const slot = &self.registry.slots[index];
        assert(slot.state == .handshaking or slot.state == .established);
        if (slot.timeoutNs()) |remaining| if (remaining == 0) {
            slot.onTimeout();
            self.visits.timeouts +|= 1;
        };
        if (slot.state == .handshaking and slot.close_reason == null and
            now.mono_ms -| slot.created_ms >= self.handshakeLimitMs(slot))
        {
            const unanswered = slot.direction == .outbound and !slot.answered;
            slot.close(if (unanswered) .dial_unanswered else .handshake_timeout, types.app_error_handshake_timeout);
        }
        if (slot.state == .established and slot.close_reason == null and
            now.mono_ms -| slot.last_send_ms >= self.limits.keep_alive_ms and
            slot.keepAlive())
        {
            slot.last_send_ms = now.mono_ms;
        }
        if (slot.pending_close) |pending| if (!slot.flight_pending) {
            slot.pending_close = null;
            slot.close(pending.reason, pending.code);
        };
        self.refresh(index);
        self.observePath(index);
        self.touched(index, now);
    }

    /// Gathers stream readiness for the connections that received datagrams or had a timer fire,
    /// claiming new peer streams, and refreshes their timer keys.
    pub fn collect(self: *Engine, now: Now) void {
        const slots = self.registry.slots;
        var visited: usize = 0;
        while (self.registry.collect.pop(slots, "collect_link")) |row| : (visited += 1) {
            assert(visited < slots.len);
            const index: u16 = @intCast(row);
            self.visits.collect +|= 1;
            const slot = &slots[index];
            if (slot.state != .handshaking and slot.state != .established) continue;
            self.refresh(index);
            if (slot.state == .established and slot.pending_close == null) {
                self.gatherReadable(index);
                self.gatherWritable(index);
            }
            self.observePath(index);
            self.rekey(index, now);
            self.noteEvents(index);
        }
    }

    /// Drains quiche's readable edges and claims new peer streams.
    fn gatherReadable(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        const conn = slot.conn.?;
        for (0..limits.streams_per_connection) |_| {
            const next = c.quiche_conn_stream_readable_next(conn);
            if (next < 0) break;
            const id: u64 = @intCast(next);
            if (slot.table.find(id)) |entry_index| {
                slot.table.markReady(entry_index, .{ .readable = true });
                continue;
            }
            if (!StreamTable.isPeerInitiated(slot.direction, id)) continue;
            if (slot.table.claimPeer(id) == null) {
                slot.shutdownRaw(id, .read, types.app_error_stream_table_full);
                slot.shutdownRaw(id, .write, types.app_error_stream_table_full);
            }
        }
    }

    /// Drains quiche's writable edges. A stream with write interest is reported, and so is one
    /// the peer stopped: quiche frees a stopped stream once it leaves the writable set and its
    /// reset is acknowledged, so the stop code is taken here for the owner's next write. Other
    /// edges (a new stream, credit for a stream that was not blocked) concern no owner. quiche
    /// does not re-arm a stream whose credit exactly equals its watermark, so armed streams are
    /// also checked against it.
    fn gatherWritable(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        const conn = slot.conn.?;
        for (0..limits.streams_per_connection) |_| {
            const next = c.quiche_conn_stream_writable_next(conn);
            if (next < 0) break;
            const id: u64 = @intCast(next);
            const entry_index = slot.table.find(id) orelse continue;
            if (!slot.table.matches(entry_index, id)) continue;
            const entry = &slot.table.entries[entry_index];
            if (!entry.stopped and !entry.fin_sent) if (slot.stopCode(id)) |code| {
                entry.stopped = true;
                entry.reset_code = code;
                slot.table.markReady(entry_index, .{ .writable = true });
                continue;
            };
            if (entry.write_lowat > 0) slot.table.markReady(entry_index, .{ .writable = true });
        }
        var armed = slot.table.armed;
        for (0..limits.streams_per_connection) |_| {
            if (armed == 0) break;
            const entry_index: u8 = @intCast(@ctz(armed));
            armed &= armed - 1;
            const entry = &slot.table.entries[entry_index];
            const available = c.quiche_conn_stream_capacity(conn, entry.id);
            if (available < 0 or available >= entry.write_lowat) slot.table.markReady(entry_index, .{ .writable = true });
        }
    }

    /// Sends one datagram from the connection, or returns null when quiche has nothing to send.
    pub fn sendOne(self: *Engine, index: u16, now: Now, out: []u8) ?Sent {
        if (index >= self.registry.slots.len) return null;
        const slot = &self.registry.slots[index];
        if (slot.state == .free or slot.state == .closed) return null;
        const datagram = slot.send(now.mono_ms, out) catch {
            self.refresh(index);
            return null;
        };
        if (datagram == null) {
            // The establishing pass acknowledges the server's Handshake flight, and quiche sends that
            // ACK regardless of congestion and then discards the Initial space's bytes in flight.
            // Cubic keeps two datagrams of window and the final flight fits one, so Done means it left.
            slot.flight_pending = false;
            self.refresh(index);
        }
        return datagram;
    }

    /// Ends one burst of sendOne calls: refreshes the timer key, then removes a drained
    /// connection from dirty or moves an undrained one to its tail. The key adds quiche's
    /// remaining time to `now`, so a live clock is read after the burst.
    pub fn sent(self: *Engine, index: u16, now: Now, drained: bool) void {
        assert(index < self.registry.slots.len);
        self.visits.flush +|= 1;
        const slots = self.registry.slots;
        const slot = &slots[index];
        if (slot.dirty_link.linked) {
            self.registry.dirty.remove(slots, "dirty_link", index);
            const live = slot.state == .handshaking or slot.state == .established;
            if (!drained and live) self.registry.dirty.append(slots, "dirty_link", index);
        }
        self.rekey(index, now);
        self.noteEvents(index);
    }

    /// Ends a turn's flush pass. Test builds check the engine invariants here.
    pub fn finishFlush(self: *Engine, now: Now) void {
        if (@import("builtin").is_test) self.checkInvariants(now);
    }

    /// E1 to E5. Runs after the turn's last send, before any time passes.
    fn checkInvariants(self: *Engine, now: Now) void {
        const slots = self.registry.slots;
        var scratch: [constants.datagram_size_max]u8 = undefined;
        for (slots, 0..) |*slot, position| {
            const index: u16 = @intCast(position);
            // Deferred close events wait on the deferred list.
            assert(slot.deferred_link.linked == (slot.table.deferred != 0));
            if (slot.state == .free) {
                assert(!slot.collect_link.linked and !slot.dirty_link.linked and !slot.event_link.linked and !slot.release_link.linked);
                assert(self.registry.timers.get(index) == null);
                continue;
            }
            // E3: undelivered events if and only if the slot is on the events list.
            assert(slot.event_link.linked == slot.hasEvents());
            if (slot.state == .closed) {
                assert(!slot.collect_link.linked and !slot.dirty_link.linked);
                assert(self.registry.timers.get(index) == null);
                continue;
            }
            // E1: one key per live slot, no later than any of its sources.
            const key = self.registry.timers.get(index);
            assert((key == null) == (self.deadlineNs(index, now) == null));
            if (key) |deadline| {
                if (slot.close_reason == null) {
                    const due_ms = if (slot.state == .handshaking)
                        slot.created_ms +| self.handshakeLimitMs(slot)
                    else
                        slot.last_send_ms +| self.limits.keep_alive_ms;
                    assert(deadline <= due_ms *| std.time.ns_per_ms);
                }
                if (slot.pending_close != null and !slot.flight_pending) assert(deadline <= now.nanos());
                // quiche reads its own clock, so its timer is comparable only with a real clock,
                // and only up to the time this turn has run since its clock read.
                if (now.mono_ns != null) if (slot.timeoutNs()) |remaining| {
                    assert(deadline <= now.nanos() +| remaining +| invariant_clock_slack_ns);
                };
            }
            // E2: a slot off the dirty list has no output.
            if (!slot.dirty_link.linked) {
                var info: c.quiche_send_info = undefined;
                const rc = c.quiche_conn_send(slot.conn.?, &scratch, scratch.len, &info);
                assert(rc == c.QUICHE_ERR_DONE);
            }
            if (slot.collect_link.linked or slot.state != .established or slot.pending_close != null) continue;
            const table = &slot.table;
            // E4: an armed writer is below its watermark or has an undelivered writable edge.
            var armed = table.armed;
            for (0..limits.streams_per_connection) |_| {
                if (armed == 0) break;
                const entry_index: u8 = @intCast(@ctz(armed));
                armed &= armed - 1;
                const entry = &table.entries[entry_index];
                assert(entry.write_lowat > 0);
                const available = c.quiche_conn_stream_capacity(slot.conn.?, entry.id);
                assert(entry.ready.writable or (available >= 0 and available < entry.write_lowat));
            }
            // E5: every readable stream has an undelivered readable edge or an open delivered one.
            const iter = c.quiche_conn_readable(slot.conn.?) orelse continue;
            defer c.quiche_stream_iter_free(iter);
            var id: u64 = 0;
            for (0..2 * limits.streams_per_connection) |_| {
                if (!c.quiche_stream_iter_next(iter, &id)) break;
                const entry_index = table.find(id) orelse {
                    assert(!StreamTable.isPeerInitiated(slot.direction, id));
                    continue;
                };
                const entry = &table.entries[entry_index];
                assert(entry.ready.readable or table.readOpen(entry_index) or entry.opened_pending or entry.closed_pending);
            }
        }
    }

    /// Retires the connections whose close event was delivered by an earlier pollEvents call.
    pub fn releaseReported(self: *Engine) void {
        const slots = self.registry.slots;
        var released: usize = 0;
        while (self.registry.released.pop(slots, "release_link")) |row| : (released += 1) {
            assert(released < slots.len);
            const index: u16 = @intCast(row);
            const slot = &slots[index];
            assert(slot.state == .closed and slot.close_event == .reported);
            assert(!slot.hasEvents());
            self.retire(index);
        }
    }

    /// The earliest deadline among quiche's timers, the handshake limit, keep-alive and a deferred
    /// close whose flight left, or null when none is armed.
    fn deadlineNs(self: *const Engine, index: u16, now: Now) ?u64 {
        const slot = &self.registry.slots[index];
        if (slot.state != .handshaking and slot.state != .established) return null;
        var deadline: ?u64 = null;
        if (slot.timeoutNs()) |remaining| deadline = now.nanos() +| remaining;
        if (slot.close_reason == null) {
            const due_ms = if (slot.state == .handshaking)
                slot.created_ms +| self.handshakeLimitMs(slot)
            else
                slot.last_send_ms +| self.limits.keep_alive_ms;
            const due = due_ms *| std.time.ns_per_ms;
            deadline = @min(deadline orelse due, due);
        }
        if (slot.pending_close != null and !slot.flight_pending) deadline = @min(deadline orelse now.nanos(), now.nanos());
        return deadline;
    }

    fn rekey(self: *Engine, index: u16, now: Now) void {
        if (self.deadlineNs(index, now)) |deadline| {
            self.registry.timers.set(index, deadline);
        } else self.registry.timers.clear(index);
    }

    /// A datagram was processed or a timer fired: gather readiness and flush this turn.
    fn touched(self: *Engine, index: u16, now: Now) void {
        const slot = &self.registry.slots[index];
        if (slot.state == .handshaking or slot.state == .established) {
            self.markCollect(index);
            self.markDirty(index);
        }
        self.rekey(index, now);
        self.noteEvents(index);
    }

    fn markCollect(self: *Engine, index: u16) void {
        _ = self.registry.collect.insert(self.registry.slots, "collect_link", index);
    }

    fn markDirty(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        assert(slot.state == .handshaking or slot.state == .established);
        _ = self.registry.dirty.insert(self.registry.slots, "dirty_link", index);
    }

    fn markLiveDirty(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        if (slot.state == .handshaking or slot.state == .established) self.markDirty(index);
    }

    fn noteEvents(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        if (slot.state == .free) return;
        if (slot.table.deferred != 0) _ = self.registry.deferred.insert(self.registry.slots, "deferred_link", index);
        if (slot.hasEvents()) {
            _ = self.registry.events.insert(self.registry.slots, "event_link", index);
        } else if (slot.event_link.linked) {
            // A deferred close replaced the entry's only undelivered event.
            self.registry.events.remove(self.registry.slots, "event_link", index);
        }
    }

    fn streamError(err: connection.Error) StreamError {
        return switch (err) {
            error.UnknownStream => error.UnknownStream,
            error.WouldBlock => error.WouldBlock,
            error.StreamStopped => error.StreamStopped,
            error.StreamLimit => error.StreamLimit,
            error.StreamTableFull => error.StreamTableFull,
            error.NotEstablished => error.NotEstablished,
            else => return error.Transport,
        };
    }

    fn liveStream(self: *Engine, stream: StreamHandle) StreamError!Stream {
        const slot = try self.liveSlot(stream.conn);
        if (!slot.table.matches(stream.slot, stream.id)) return error.UnknownStream;
        assert(stream.slot < limits.streams_per_connection);
        assert(slot.conn != null);
        return .{ .slot = slot, .index = stream.slot, .id = stream.id };
    }

    fn readableStream(self: *Engine, stream: StreamHandle) StreamError!Stream {
        const slot = try self.readableSlot(stream.conn);
        if (!slot.table.matches(stream.slot, stream.id)) return error.UnknownStream;
        assert(stream.slot < limits.streams_per_connection);
        assert(slot.conn != null);
        return .{ .slot = slot, .index = stream.slot, .id = stream.id };
    }

    fn readableSlot(self: *Engine, conn: Handle) StreamError!*connection.Slot {
        if (conn.index >= self.registry.slots.len) return error.StaleHandle;
        const slot = &self.registry.slots[conn.index];
        if (slot.generation != conn.generation or slot.conn == null) return error.StaleHandle;
        return slot;
    }

    fn liveSlot(self: *Engine, conn: Handle) StreamError!*connection.Slot {
        if (conn.index >= self.registry.slots.len) return error.StaleHandle;
        const slot = &self.registry.slots[conn.index];
        if (slot.generation != conn.generation or slot.state == .free or slot.state == .closed or
            slot.pending_close != null or slot.close_reason != null)
        {
            return error.StaleHandle;
        }
        return slot;
    }

    fn liveView(self: *const Engine, conn: Handle) ?*const connection.Slot {
        if (conn.index >= self.registry.slots.len) return null;
        const slot = &self.registry.slots[conn.index];
        if (slot.generation != conn.generation or slot.state == .free) return null;
        return slot;
    }

    fn toHandle(self: *const Engine, index: u16) Handle {
        return .{ .index = index, .generation = self.registry.slots[index].generation };
    }

    fn localFor(self: *const Engine, peer: Address) ?Address {
        return self.local[
            switch (peer) {
                .ip4 => @as(usize, 0),
                .ip6 => 1,
            }
        ];
    }

    /// Returns false only when progress was required and quiche neither processed a packet nor
    /// started closing.
    fn feed(self: *Engine, index: u16, datagram: []u8, from: *const Address, now: Now, require_progress: bool) bool {
        assert(index < self.registry.slots.len);
        assert(datagram.len > 0);
        const slot = &self.registry.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return !require_progress;
        const received_before = if (require_progress) slot.receivedPackets() else 0;
        const source = binding.SockAddr.fromAddress(from.*);
        const destination = binding.SockAddr.fromAddress(self.localFor(from.*).?);
        const received = if (slot.recv(datagram, &source, &destination)) |_| true else |_| false;
        if (require_progress and slot.receivedPackets() == received_before and !slot.isFinished()) return false;
        if (received) slot.answered = true;
        self.refresh(index);
        self.observePath(index);
        self.touched(index, now);
        return true;
    }

    fn observePath(self: *Engine, index: u16) void {
        assert(index < self.registry.slots.len);
        const slot = &self.registry.slots[index];
        if (slot.state == .closed or slot.conn == null) return;
        const peer = slot.drainPathEvents() orelse return;
        assert(slot.state != .free);
        if (peer.eql(slot.peer)) return;
        slot.peer = peer;
        slot.peer_sockaddr = binding.SockAddr.fromAddress(peer);
        slot.path_changed_pending = peer;
        self.noteEvents(index);
    }

    fn leaveHandshaking(self: *Engine, slot: *const connection.Slot) void {
        assert(slot.state == .handshaking);
        if (slot.direction == .inbound) {
            assert(self.registry.handshaking > 0);
            self.registry.handshaking -= 1;
        } else {
            assert(self.registry.dialing > 0);
            self.registry.dialing -= 1;
        }
    }

    fn refresh(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        if (slot.state == .handshaking and slot.isEstablished()) {
            self.leaveHandshaking(slot);
            slot.state = .established;
            slot.flight_pending = slot.direction == .outbound;
            slot.learnPeerWindows();
            if (slot.handshake.peer_id) |id| {
                assert(slot.peer_id == null);
                slot.peer_id = id;
                if (slot.expected_peer_id != null and !slot.expected_peer_id.?.eql(&id)) {
                    slot.deferClose(.peer_id_mismatch, types.app_error_peer_id_mismatch);
                } else {
                    slot.connected_pending = true;
                    self.connection_metrics.established[@intFromEnum(slot.direction)] +|= 1;
                    std.log.scoped(.network_quic).debug("connection_established connection={d}:{d} direction={s} peer={f}", .{ index, slot.generation, @tagName(slot.direction), @import("../logging.zig").peer(&id) });
                }
            } else {
                slot.close(.tls_failed, types.app_error_normal);
            }
            if (slot.state == .established and slot.pending_close == null) self.markCollect(index);
        }
        if (slot.state != .closed and slot.isFinished()) {
            self.markClosed(index, slot.closeReason());
        }
        self.noteEvents(index);
    }

    fn markClosed(self: *Engine, index: u16, reason: CloseReason) void {
        const slot = &self.registry.slots[index];
        assert(slot.state == .handshaking or slot.state == .established);
        self.connection_metrics.closed[@intFromEnum(slot.direction)][@intFromEnum(reason)] +|= 1;
        const code: u64 = switch (reason) {
            .peer_closed => |closed| closed.code,
            .transport_error => |value| value,
            else => 0,
        };
        std.log.scoped(.network_quic).debug("connection_closed connection={d}:{d} direction={s} state={s} reason={s} code={d}", .{ index, slot.generation, @tagName(slot.direction), @tagName(slot.state), @tagName(reason), code });
        if (slot.state == .established and slot.pending_close == null) self.gatherReadable(index);
        if (slot.state == .handshaking) {
            self.leaveHandshaking(slot);
        }
        if (slot.direction == .outbound) {
            assert(self.registry.outbound > 0);
            self.registry.outbound -= 1;
        }
        slot.state = .closed;
        slot.close_reason = reason;
        slot.close_event = .pending;
        self.registry.removeRoutesFor(index);
        const slots = self.registry.slots;
        // Stream events precede the connection's close event.
        slot.table.promoteDeferred();
        if (slot.deferred_link.linked) self.registry.deferred.remove(slots, "deferred_link", index);
        if (slot.collect_link.linked) self.registry.collect.remove(slots, "collect_link", index);
        if (slot.dirty_link.linked) self.registry.dirty.remove(slots, "dirty_link", index);
        self.registry.timers.clear(index);
        self.noteEvents(index);
        assert(self.registry.dialing <= self.registry.outbound);
    }

    fn slotForPeer(self: *const Engine, from: *const Address) ?u16 {
        assert(self.registry.active_len <= self.registry.active.len);
        var found: ?u16 = null;
        for (self.registry.active[0..self.registry.active_len]) |index| {
            const slot = &self.registry.slots[index];
            assert(slot.state != .free);
            if (slot.state == .closed or !slot.peer.eql(from.*)) continue;
            if (found != null) return null;
            found = index;
        }
        return found;
    }

    fn handshakingFromSource(self: *const Engine, from: *const Address) u16 {
        assert(self.registry.active_len <= self.registry.active.len);
        var count: u16 = 0;
        for (self.registry.active[0..self.registry.active_len]) |index| {
            const slot = &self.registry.slots[index];
            if (slot.state != .handshaking or slot.direction != .inbound) continue;
            if (slot.peer.sameSourceGroup(from.*)) count += 1;
        }
        assert(count <= self.registry.handshaking);
        return count;
    }
};

comptime {
    assert(limits.streams_per_connection <= std.math.maxInt(u8) + 1);
}

test {
    _ = @import("engine_admission_test.zig");
    _ = @import("engine_close_test.zig");
    _ = @import("engine_handshake_test.zig");
    _ = @import("engine_notifications_test.zig");
    _ = @import("engine_path_test.zig");
    _ = @import("engine_readiness_test.zig");
    _ = @import("engine_stream_test.zig");
}
