const std = @import("std");
const api = @import("api.zig");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const constants = @import("../constants.zig");
const limits = @import("limits.zig");
const peer_index = @import("peer_index.zig");
const route_table = @import("route_table.zig");
const stream_iter = @import("stream_iter.zig");
const peer_id = @import("../wire/peer_id.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const c = binding.c;

pub const Now = api.Now;
pub const Direction = api.Direction;
pub const ShutdownDirection = api.ShutdownDirection;
pub const CloseReason = api.CloseReason;
pub const Read = api.Read;
pub const Address = api.Address;
pub const Stats = api.Stats;
pub const Sent = api.Sent;
pub const Error = api.Error;
pub const StreamError = api.StreamError;
pub const DialError = api.DialError;
pub const Handle = api.Handle;
pub const StreamHandle = api.StreamHandle;
pub const Event = api.Event;
pub const Limits = api.Limits;
pub const Counters = api.Counters;
pub const SendBatch = api.SendBatch;
pub const ReceiveOutcome = api.ReceiveOutcome;
pub const EntropyPool = api.EntropyPool;

const Stream = struct {
    slot: *connection.Slot,
    index: u8,
    id: u64,
};

pub const DriverView = struct {
    engine: *Engine,

    pub fn receive(
        self: DriverView,
        datagram: []u8,
        from: *const Address,
        now: Now,
        entropy: *EntropyPool,
        out: []u8,
    ) ReceiveOutcome {
        assert(datagram.len <= out.len);
        assert(self.engine.slots.len > 0);
        return self.engine.receive(datagram, from, now, entropy, out);
    }

    pub fn tick(self: DriverView, now: Now) void {
        self.engine.tick(now);
    }

    pub fn slotCount(self: DriverView) u16 {
        const engine = self.engine;
        assert(engine.slots.len > 0);
        assert(engine.slots.len <= limits.connections_max_ceiling);
        return @intCast(engine.slots.len);
    }

    pub fn nextTimeoutMs(self: DriverView) ?u64 {
        return self.engine.nextTimeoutMs();
    }

    pub fn sendBatch(self: DriverView, index: u16, now: Now, batch: *SendBatch) u8 {
        assert(index < self.engine.slots.len);
        var count: u8 = 0;
        while (count < constants.send_batch_max) : (count += 1) {
            const sent = self.engine.send(index, now, &batch.buffers[count]) orelse break;
            batch.sent[count] = sent;
        }
        assert(count <= constants.send_batch_max);
        return count;
    }

    pub fn takeKeylog(self: DriverView, index: u16, out: []u8) usize {
        assert(index < self.engine.slots.len);
        assert(out.len >= tls.keylog_capacity);
        const slot = &self.engine.slots[index];
        if (slot.state == .free) return 0;
        return slot.takeKeylog(out);
    }

    pub fn failSend(self: DriverView, index: u16) void {
        assert(index < self.engine.slots.len);
        const slot = &self.engine.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        self.engine.markClosed(index, .send_failed);
    }

    pub fn activeIndices(self: DriverView) []const u16 {
        const engine = self.engine;
        assert(engine.active.len == engine.slots.len);
        assert(engine.active_len <= engine.active.len);
        return engine.active[0..engine.active_len];
    }

    pub fn releaseReported(self: DriverView) void {
        const engine = self.engine;
        assert(engine.active_len <= engine.active.len);
        assert(engine.active.len == engine.slots.len);
        engine.releaseReported();
    }

    pub fn takeActivity(self: DriverView, out: []Handle) usize {
        const engine = self.engine;
        assert(engine.activity.len == engine.slots.len);
        assert(engine.active_len <= engine.active.len);
        var count: usize = 0;
        for (engine.active[0..engine.active_len]) |index| {
            if (!engine.activity[index]) continue;
            if (count == out.len) break;
            out[count] = .{ .index = index, .generation = engine.slots[index].generation };
            engine.activity[index] = false;
            count += 1;
        }
        assert(count <= out.len);
        return count;
    }

    pub fn activityPending(self: DriverView) bool {
        const engine = self.engine;
        assert(engine.activity.len == engine.slots.len);
        assert(engine.active_len <= engine.active.len);
        for (engine.active[0..engine.active_len]) |index| {
            if (engine.activity[index]) return true;
        }
        return false;
    }
};

pub const Options = struct {
    tls: tls.Context,
    limits: Limits = .{},
    local: Address,
    seed: u64,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    tls: tls.Context,
    config: binding.Config,
    limits: Limits,
    local: Address,
    slots: []connection.Slot,
    routes: route_table.RouteTable,
    active: []u16,
    activity: []bool,
    keylog_arena: []u8,
    peers: peer_index.PeerIndex,
    active_len: u16 = 0,
    connection_window: u64,
    stream_window: u64,
    outbound_max: u16,
    handshaking: u16 = 0,
    dialing: u16 = 0,
    outbound: u16 = 0,
    counters: Counters = .{},

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!Engine {
        const wanted = options.limits;
        if (wanted.connections_max == 0) return error.InvalidLimits;
        if (wanted.connections_max > limits.connections_max_ceiling) return error.InvalidLimits;
        if (wanted.handshaking_max == 0 or wanted.handshaking_max > wanted.connections_max) {
            return error.InvalidLimits;
        }
        if (wanted.handshaking_per_source_max == 0) return error.InvalidLimits;
        if (wanted.idle_timeout_ms == 0) return error.InvalidLimits;
        if (wanted.handshake_timeout_ms == 0) return error.InvalidLimits;
        if (wanted.keep_alive_ms == 0) return error.InvalidLimits;
        if (wanted.dialing_max == 0) return error.InvalidLimits;
        const outbound_max = wanted.outbound_max orelse
            @max(1, wanted.connections_max - wanted.connections_max / 4);
        if (outbound_max == 0 or outbound_max > wanted.connections_max) return error.InvalidLimits;

        const connection_window = std.math.clamp(
            wanted.receive_budget_bytes / wanted.connections_max,
            limits.connection_window_min,
            limits.connection_window_max,
        );
        const stream_window = connection_window / 2;

        var config = binding.Config.init(
            wanted.idle_timeout_ms,
            connection_window,
            stream_window,
        ) catch return error.OutOfMemory;
        errdefer config.deinit();

        const slots = try allocator.alloc(connection.Slot, wanted.connections_max);
        errdefer allocator.free(slots);
        @memset(slots, .{});

        var routes = try route_table.RouteTable.init(
            allocator,
            wanted.connections_max,
            options.seed,
        );
        errdefer routes.deinit(allocator);

        const active = try allocator.alloc(u16, wanted.connections_max);
        errdefer allocator.free(active);
        for (active, 0..) |*entry, index| entry.* = @intCast(index);

        const activity = try allocator.alloc(bool, wanted.connections_max);
        errdefer allocator.free(activity);
        @memset(activity, false);

        const keylog_len: usize = if (wanted.keylog)
            tls.keylog_capacity * @as(usize, wanted.connections_max)
        else
            0;
        const keylog_arena = try allocator.alloc(u8, keylog_len);
        errdefer allocator.free(keylog_arena);

        var peers = try peer_index.PeerIndex.init(allocator, wanted.connections_max);
        errdefer peers.deinit(allocator);

        return .{
            .allocator = allocator,
            .tls = options.tls,
            .config = config,
            .limits = wanted,
            .local = options.local,
            .slots = slots,
            .routes = routes,
            .active = active,
            .activity = activity,
            .keylog_arena = keylog_arena,
            .peers = peers,
            .connection_window = connection_window,
            .stream_window = stream_window,
            .outbound_max = outbound_max,
        };
    }

    pub fn deinit(self: *Engine) void {
        for (self.slots) |*slot| {
            if (slot.state != .free) slot.release();
        }
        self.tls.deinit();
        self.peers.deinit(self.allocator);
        self.allocator.free(self.keylog_arena);
        self.allocator.free(self.activity);
        self.allocator.free(self.active);
        self.routes.deinit(self.allocator);
        self.allocator.free(self.slots);
        self.config.deinit();
        self.* = undefined;
    }

    pub fn driverView(self: *Engine) DriverView {
        assert(self.slots.len > 0);
        assert(self.active_len <= self.slots.len);
        return .{ .engine = self };
    }

    pub fn connectionWindow(self: *const Engine) u64 {
        assert(self.connection_window >= limits.connection_window_min);
        assert(self.connection_window <= limits.connection_window_max);
        return self.connection_window;
    }

    pub fn streamWindow(self: *const Engine) u64 {
        assert(self.stream_window > 0);
        assert(self.stream_window <= self.connection_window);
        return self.stream_window;
    }

    pub fn dial(
        self: *Engine,
        peer: *const Address,
        expected: peer_id.PeerId,
        now: Now,
        entropy: [limits.local_cid_length]u8,
    ) DialError!Handle {
        assert(self.active_len <= self.active.len);
        assert(self.dialing <= self.outbound);
        if (self.dialing >= self.limits.dialing_max) return error.DialLimit;
        if (self.outbound >= self.outbound_max) return error.DialLimit;
        const index = self.claimSlot() orelse return error.TableFull;
        assert(index < self.slots.len);
        const slot = &self.slots[index];
        slot.open(&self.tls, &self.config, .{
            .direction = .outbound,
            .local = self.local,
            .peer = peer.*,
            .scid = entropy,
            .expected_peer_id = expected,
            .now = now,
            .keylog = self.keylogFor(index),
        }) catch {
            self.unclaimSlot(index);
            return error.OpenFailed;
        };
        self.addRoute(&slot.scid, index) catch {
            slot.release();
            self.unclaimSlot(index);
            return error.TableFull;
        };
        self.dialing += 1;
        self.outbound += 1;
        assert(self.dialing <= self.limits.dialing_max);
        assert(self.outbound <= self.outbound_max);
        return .{ .index = index, .generation = slot.generation };
    }

    pub fn close(self: *Engine, conn: Handle, code: u64) bool {
        const slot = self.liveSlot(conn) catch return false;
        assert(slot.conn != null);
        assert(slot.close_reason == null);
        slot.close(.host, code);
        return true;
    }

    pub fn abandon(self: *Engine, conn: Handle) bool {
        const slot = self.readableSlot(conn) catch return false;
        switch (slot.state) {
            .handshaking => {
                if (slot.closed_pending) return false;
                if (slot.direction == .inbound) {
                    self.handshaking -= 1;
                } else {
                    assert(self.dialing > 0);
                    assert(self.outbound > 0);
                    self.dialing -= 1;
                    self.outbound -= 1;
                }
            },
            .closed => if (!slot.closed_pending and !slot.closed_reported) return false,
            else => return false,
        }
        assert(conn.index < self.slots.len);
        assert(self.active_len > 0);
        self.removeRoutesFor(conn.index);
        self.releaseSlot(conn.index);
        return true;
    }

    pub fn peerId(self: *const Engine, conn: Handle) ?peer_id.PeerId {
        const slot = self.liveView(conn) orelse return null;
        assert(slot.state != .free);
        assert(slot.generation == conn.generation);
        return slot.peer_id;
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

    pub fn connectionStats(self: *const Engine, conn: Handle) ?Stats {
        const slot = self.liveView(conn) orelse return null;
        assert(slot.state != .free);
        if (slot.conn == null) return null;
        return slot.stats();
    }

    pub fn connectionAgeMs(self: *const Engine, conn: Handle, now: Now) ?u64 {
        const slot = self.liveView(conn) orelse return null;
        assert(slot.state != .free);
        assert(slot.conn != null);
        return now.mono_ms -| slot.created_ms;
    }

    pub fn findByPeerId(self: *const Engine, id: *const peer_id.PeerId) ?Handle {
        assert(self.peers.entries.len >= 2 * self.slots.len);
        assert(self.active_len <= self.active.len);
        var candidates = self.peers.candidates(peer_index.keyOf(id));
        while (candidates.next()) |entry| {
            if (self.peerEntryMatches(entry, id)) {
                return .{ .index = entry.index, .generation = entry.generation };
            }
        }
        return null;
    }

    pub fn openStream(self: *Engine, conn: Handle) StreamError!StreamHandle {
        const slot = try self.liveSlot(conn);
        const opened = slot.openStream() catch |err| return self.streamError(err);
        assert(opened.index < limits.streams_per_connection);
        assert(slot.table.matches(opened.index, opened.id));
        return .{ .conn = conn, .id = opened.id, .slot = opened.index };
    }

    pub fn read(self: *Engine, stream: StreamHandle, buf: []u8) StreamError!Read {
        const target = try self.readableStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        const result = target.slot.read(target.index, target.id, buf) catch |err|
            return self.streamError(err);
        assert(result.len <= buf.len);
        if (result.len > 0) assert(result.reset_code == null);
        return result;
    }

    pub fn write(
        self: *Engine,
        stream: StreamHandle,
        bytes: []const u8,
        fin: bool,
    ) StreamError!usize {
        const target = try self.liveStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        const written = target.slot.write(target.index, target.id, bytes, fin) catch |err|
            return self.streamError(err);
        assert(written <= bytes.len);
        return written;
    }

    pub fn streamCapacity(self: *Engine, stream: StreamHandle) StreamError!usize {
        const target = try self.readableStream(stream);
        assert(target.slot.table.matches(target.index, target.id));
        const available = target.slot.capacity(target.index, target.id) catch |err|
            return self.streamError(err);
        assert(target.index < limits.streams_per_connection);
        return available;
    }

    pub fn shutdown(self: *Engine, stream: StreamHandle, dir: ShutdownDirection, code: u64) void {
        const target = self.liveStream(stream) catch return;
        assert(target.index < limits.streams_per_connection);
        assert(target.slot.conn != null);
        target.slot.shutdown(target.index, target.id, dir, code);
    }

    pub fn closeStream(self: *Engine, stream: StreamHandle, code: u64) void {
        const target = self.liveStream(stream) catch return;
        assert(target.index < limits.streams_per_connection);
        assert(target.slot.conn != null);
        target.slot.closeStream(target.index, target.id, code);
    }

    pub const ReadableIterator = stream_iter.StreamIterator(.readable);
    pub const WritableIterator = stream_iter.StreamIterator(.writable);

    pub fn readable(self: *Engine, conn: Handle) ReadableIterator {
        const slot = self.readableSlot(conn) catch return ReadableIterator.empty(conn);
        assert(slot.conn != null);
        assert(slot.generation == conn.generation);
        return ReadableIterator.open(slot, conn);
    }

    pub fn writable(self: *Engine, conn: Handle) WritableIterator {
        const slot = self.readableSlot(conn) catch return WritableIterator.empty(conn);
        assert(slot.conn != null);
        assert(slot.generation == conn.generation);
        return WritableIterator.open(slot, conn);
    }

    pub fn pollEvents(self: *Engine, events: []Event) usize {
        assert(self.active_len <= self.active.len);
        var count: usize = 0;
        for (self.active[0..self.active_len]) |index| {
            assert(index < self.slots.len);
            const slot = &self.slots[index];
            const conn = Handle{ .index = index, .generation = slot.generation };
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
            if (slot.table.pending > 0) {
                count = pollStreamEvents(slot, conn, events, count);
                if (count == events.len) return count;
            }
            if (slot.closed_pending) {
                if (count == events.len) return count;
                events[count] = .{ .closed = .{
                    .conn = conn,
                    .peer_id = slot.peer_id,
                    .direction = slot.direction,
                    .reason = slot.close_reason.?,
                } };
                count += 1;
                slot.closed_pending = false;
                slot.closed_reported = true;
            }
        }
        assert(count <= events.len);
        return count;
    }

    pub fn eventsPending(self: *const Engine) bool {
        assert(self.active_len <= self.active.len);
        for (self.active[0..self.active_len]) |index| {
            assert(index < self.slots.len);
            const slot = &self.slots[index];
            if (slot.connected_pending) return true;
            if (slot.path_changed_pending != null) return true;
            if (slot.table.pending > 0) return true;
            if (slot.closed_pending) return true;
        }
        return false;
    }

    fn receive(
        self: *Engine,
        datagram: []u8,
        from: *const Address,
        now: Now,
        entropy: *EntropyPool,
        out: []u8,
    ) ReceiveOutcome {
        const header = binding.headerInfo(datagram) catch
            return drop(&self.counters.dropped_unroutable);
        if (self.findRoute(&header.dcid)) |index| {
            self.feed(index, datagram, from);
            return .{ .accepted = self.toHandle(index) };
        }
        if (header.packet_type == .short) {
            const index = self.slotForPeer(from) orelse
                return drop(&self.counters.dropped_unroutable);
            self.feed(index, datagram, from);
            return .{ .accepted = self.toHandle(index) };
        }
        if (datagram.len < limits.client_initial_min) {
            return drop(&self.counters.dropped_short_initial);
        }
        if (header.packet_type == .version_negotiation or header.version == 0) {
            return drop(&self.counters.dropped_unroutable);
        }
        if (!binding.versionSupported(header.version)) {
            return self.negotiateVersion(&header, out);
        }
        if (header.packet_type != .initial) return drop(&self.counters.dropped_unroutable);
        if (self.handshaking >= self.limits.handshaking_max) {
            return drop(&self.counters.dropped_full);
        }
        if (self.handshakingFromSource(from) >= self.limits.handshaking_per_source_max) {
            return drop(&self.counters.dropped_source_limit);
        }
        if (self.limits.admit) |admit| {
            if (!admit(self.limits.admit_context, from)) {
                return drop(&self.counters.dropped_rejected);
            }
        }
        const scid = entropy.take() orelse return drop(&self.counters.dropped_no_entropy);
        const index = self.claimSlot() orelse return drop(&self.counters.dropped_full);

        const slot = &self.slots[index];
        slot.open(&self.tls, &self.config, .{
            .direction = .inbound,
            .local = self.local,
            .peer = from.*,
            .scid = scid,
            .expected_peer_id = null,
            .now = now,
            .keylog = self.keylogFor(index),
        }) catch {
            self.unclaimSlot(index);
            return drop(&self.counters.recv_errors);
        };
        self.addRoute(&slot.scid, index) catch {
            slot.release();
            self.unclaimSlot(index);
            return drop(&self.counters.dropped_full);
        };
        self.addRoute(&header.dcid, index) catch {
            self.removeRoutesFor(index);
            slot.release();
            self.unclaimSlot(index);
            return drop(&self.counters.dropped_full);
        };
        self.handshaking += 1;
        assert(self.handshaking <= self.limits.handshaking_max);
        self.feed(index, datagram, from);
        return .{ .accepted = self.toHandle(index) };
    }

    fn negotiateVersion(
        self: *Engine,
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
        )) catch return drop(&self.counters.dropped_unroutable);
        const length = written orelse return drop(&self.counters.dropped_unroutable);
        assert(length <= out.len);
        self.counters.version_negotiations += 1;
        return .{ .version_negotiation = out[0..length] };
    }

    fn tick(self: *Engine, now: Now) void {
        assert(self.active_len <= self.active.len);
        assert(self.handshaking <= self.limits.handshaking_max);
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            assert(slot.state != .free);
            if (slot.state == .closed) continue;
            const expired = if (slot.timeoutMs()) |remaining| remaining == 0 else false;
            slot.onTimeout();
            if (expired) self.activity[index] = true;
            if (slot.state == .handshaking and slot.close_reason == null and
                now.mono_ms -| slot.created_ms >= self.limits.handshake_timeout_ms)
            {
                slot.close(.handshake_timeout, types.app_error_handshake_timeout);
            }
            if (slot.state == .established and slot.close_reason == null and
                now.mono_ms -| slot.last_send_ms >= self.limits.keep_alive_ms and
                slot.keepAlive())
            {
                slot.last_send_ms = now.mono_ms;
                self.activity[index] = true;
            }
            if (slot.pending_close) |pending| {
                if (slot.pending_close_armed) {
                    slot.pending_close = null;
                    slot.pending_close_armed = false;
                    slot.close(pending.reason, pending.code);
                } else {
                    slot.pending_close_armed = true;
                }
            }
            self.refresh(index);
            self.observePath(index);
        }
    }

    fn nextTimeoutMs(self: *const Engine) ?u64 {
        assert(self.active_len <= self.active.len);
        var earliest: ?u64 = null;
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            assert(slot.state != .free);
            if (slot.state == .closed) continue;
            const timeout = slot.timeoutMs() orelse continue;
            if (earliest == null or timeout < earliest.?) earliest = timeout;
        }
        return earliest;
    }

    fn send(self: *Engine, index: u16, now: Now, out: []u8) ?Sent {
        if (index >= self.slots.len) return null;
        const slot = &self.slots[index];
        if (slot.state == .free or slot.state == .closed) return null;
        const sent = slot.send(now.mono_ms, out) catch {
            self.counters.send_errors += 1;
            self.refresh(index);
            return null;
        };
        if (sent == null) self.refresh(index);
        return sent;
    }

    fn releaseReported(self: *Engine) void {
        assert(self.active_len <= self.active.len);
        var cursor: u16 = 0;
        while (cursor < self.active_len) {
            const index = self.active[cursor];
            assert(index < self.slots.len);
            const slot = &self.slots[index];
            if (slot.state == .closed and slot.closed_reported) {
                assert(!slot.connected_pending);
                assert(slot.path_changed_pending == null);
                assert(!slot.closed_pending);
                assert(slot.table.pending == 0);
                self.releaseSlot(index);
                continue;
            }
            cursor += 1;
        }
    }

    fn streamError(self: *Engine, err: connection.Error) StreamError {
        return switch (err) {
            error.UnknownStream => error.UnknownStream,
            error.WouldBlock => error.WouldBlock,
            error.StreamStopped => error.StreamStopped,
            error.StreamLimit => error.StreamLimit,
            error.StreamTableFull => error.StreamTableFull,
            error.NotEstablished => error.NotEstablished,
            else => {
                self.counters.stream_errors += 1;
                return error.Transport;
            },
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
        if (conn.index >= self.slots.len) return error.StaleHandle;
        const slot = &self.slots[conn.index];
        if (slot.generation != conn.generation or slot.conn == null) return error.StaleHandle;
        return slot;
    }

    fn liveSlot(self: *Engine, conn: Handle) StreamError!*connection.Slot {
        if (conn.index >= self.slots.len) return error.StaleHandle;
        const slot = &self.slots[conn.index];
        if (slot.generation != conn.generation or slot.state == .free or slot.state == .closed or
            slot.pending_close != null or slot.close_reason != null)
        {
            return error.StaleHandle;
        }
        return slot;
    }

    fn liveView(self: *const Engine, conn: Handle) ?*const connection.Slot {
        if (conn.index >= self.slots.len) return null;
        const slot = &self.slots[conn.index];
        if (slot.generation != conn.generation or slot.state == .free) return null;
        return slot;
    }

    fn toHandle(self: *const Engine, index: u16) Handle {
        return .{ .index = index, .generation = self.slots[index].generation };
    }

    fn drop(counter: *u64) ReceiveOutcome {
        counter.* += 1;
        return .dropped;
    }

    fn feed(self: *Engine, index: u16, datagram: []u8, from: *const Address) void {
        assert(index < self.slots.len);
        assert(datagram.len > 0);
        const slot = &self.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        const was_established = slot.state == .established;
        const source = binding.SockAddr.fromAddress(from.*);
        var received = true;
        if (slot.recv(datagram, &source)) |_| {
            self.counters.accepted += 1;
            self.activity[index] = true;
        } else |_| {
            self.counters.recv_errors += 1;
            received = false;
        }
        self.refresh(index);
        const still_live = slot.state == .established and slot.pending_close == null;
        if (received and was_established and still_live) {
            slot.discoverPeerStreams();
        }
        self.observePath(index);
    }

    fn observePath(self: *Engine, index: u16) void {
        assert(index < self.slots.len);
        const slot = &self.slots[index];
        if (slot.state == .closed or slot.conn == null) return;
        const peer = slot.drainPathEvents() orelse return;
        assert(slot.state != .free);
        if (peer.eql(slot.peer)) return;
        slot.peer = peer;
        slot.peer_sockaddr = binding.SockAddr.fromAddress(peer);
        slot.path_changed_pending = peer;
        self.counters.path_changes += 1;
        self.activity[index] = true;
    }

    fn refresh(self: *Engine, index: u16) void {
        const slot = &self.slots[index];
        if (slot.state == .handshaking and slot.isEstablished()) {
            slot.state = .established;
            if (slot.direction == .inbound) {
                self.handshaking -= 1;
            } else {
                assert(self.dialing > 0);
                self.dialing -= 1;
            }
            if (slot.handshake.peer_id) |id| {
                slot.peer_id = id;
                self.peers.insert(.{
                    .key = peer_index.keyOf(&id),
                    .index = index,
                    .generation = slot.generation,
                    .used = true,
                });
                if (slot.expected_peer_id != null and !slot.expected_peer_id.?.eql(&id)) {
                    slot.deferClose(.peer_id_mismatch, types.app_error_peer_id_mismatch);
                } else {
                    slot.connected_pending = true;
                }
            } else {
                slot.close(.tls_failed, types.app_error_normal);
            }
            if (slot.state == .established and slot.pending_close == null) {
                slot.discoverPeerStreams();
            }
        }
        if (slot.state != .closed and slot.isFinished()) {
            self.markClosed(index, slot.closeReason());
        }
    }

    fn markClosed(self: *Engine, index: u16, reason: CloseReason) void {
        const slot = &self.slots[index];
        assert(slot.state == .handshaking or slot.state == .established);
        if (slot.state == .established and slot.pending_close == null) {
            slot.discoverPeerStreams();
        }
        if (slot.state == .handshaking) {
            if (slot.direction == .inbound) {
                self.handshaking -= 1;
            } else {
                assert(self.dialing > 0);
                self.dialing -= 1;
            }
        }
        if (slot.direction == .outbound) {
            assert(self.outbound > 0);
            self.outbound -= 1;
        }
        slot.state = .closed;
        slot.close_reason = reason;
        slot.closed_pending = true;
        self.removeRoutesFor(index);
        assert(self.dialing <= self.outbound);
    }

    fn slotForPeer(self: *const Engine, from: *const Address) ?u16 {
        assert(self.active_len <= self.active.len);
        var found: ?u16 = null;
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            assert(slot.state != .free);
            if (slot.state == .closed or !slot.peer.eql(from.*)) continue;
            if (found != null) return null;
            found = index;
        }
        return found;
    }

    fn handshakingFromSource(self: *const Engine, from: *const Address) u16 {
        assert(self.active_len <= self.active.len);
        var count: u16 = 0;
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            if (slot.state != .handshaking or slot.direction != .inbound) continue;
            if (slot.peer.sameHost(from.*)) count += 1;
        }
        assert(count <= self.handshaking);
        return count;
    }

    fn claimSlot(self: *Engine) ?u16 {
        assert(self.active.len == self.slots.len);
        assert(self.active_len <= self.active.len);
        if (self.active_len == self.active.len) return null;
        const index = self.active[self.active_len];
        assert(self.slots[index].state == .free);
        self.active_len += 1;
        self.activity[index] = false;
        return index;
    }

    fn unclaimSlot(self: *Engine, index: u16) void {
        assert(index < self.slots.len);
        assert(self.active_len > 0);
        var cursor: u16 = 0;
        while (cursor < self.active_len) : (cursor += 1) {
            if (self.active[cursor] != index) continue;
            self.active_len -= 1;
            self.active[cursor] = self.active[self.active_len];
            self.active[self.active_len] = index;
            return;
        }
        unreachable;
    }

    fn releaseSlot(self: *Engine, index: u16) void {
        assert(index < self.slots.len);
        const slot = &self.slots[index];
        assert(slot.state != .free);
        if (slot.peer_id) |id| self.peers.remove(peer_index.keyOf(&id), index);
        slot.release();
        self.unclaimSlot(index);
        assert(slot.state == .free);
    }

    fn keylogFor(self: *const Engine, index: u16) []u8 {
        assert(index < self.slots.len);
        if (self.keylog_arena.len == 0) return &.{};
        assert(self.keylog_arena.len == tls.keylog_capacity * self.slots.len);
        const start = tls.keylog_capacity * @as(usize, index);
        return self.keylog_arena[start..][0..tls.keylog_capacity];
    }

    fn peerEntryMatches(
        self: *const Engine,
        entry: peer_index.Entry,
        id: *const peer_id.PeerId,
    ) bool {
        assert(entry.used);
        if (entry.index >= self.slots.len) return false;
        const slot = &self.slots[entry.index];
        if (slot.generation != entry.generation or slot.state == .free) return false;
        const stored = slot.peer_id orelse return false;
        return stored.eql(id);
    }

    fn findRoute(self: *const Engine, cid: *const binding.Cid) ?u16 {
        const index = self.routes.find(cid) orelse return null;
        assert(index < self.slots.len);
        assert(self.slots[index].state != .free);
        return index;
    }

    fn addRoute(self: *Engine, cid: *const binding.Cid, index: u16) route_table.Error!void {
        assert(index < self.slots.len);
        assert(self.routes.count <= route_table.routes_per_slot * self.slots.len);
        try self.routes.insert(cid, index);
    }

    fn removeRoutesFor(self: *Engine, index: u16) void {
        assert(index < self.slots.len);
        self.routes.removeAll(index);
        assert(self.routes.count <= route_table.routes_per_slot * self.slots.len);
    }
};

fn pollStreamEvents(
    slot: *connection.Slot,
    conn: Handle,
    events: []Event,
    start: usize,
) usize {
    assert(slot.table.pending > 0);
    assert(start <= events.len);
    var count = start;
    for (0..limits.streams_per_connection) |position| {
        const index: u8 = @intCast(position);
        const entry = &slot.table.entries[index];
        if (entry.opened_pending) {
            if (count == events.len) return count;
            events[count] = .{ .stream_opened = .{ .conn = conn, .id = entry.id, .slot = index } };
            count += 1;
            slot.table.takeOpened(index);
        }
        if (entry.closed_pending) {
            if (count == events.len) return count;
            const closed = slot.table.takeClosed(index).?;
            events[count] = .{ .stream_closed = .{
                .stream = .{ .conn = conn, .id = closed.id, .slot = index },
                .reset_code = closed.reset_code,
            } };
            count += 1;
        }
    }
    assert(count <= events.len);
    return count;
}

comptime {
    assert(limits.streams_per_connection <= std.math.maxInt(u8) + 1);
}
