const std = @import("std");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const constants = @import("../constants.zig");
const peer_id = @import("../identity/peer_id.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const c = binding.c;

pub const Now = connection.Now;
pub const Direction = connection.Direction;
pub const ShutdownDirection = connection.ShutdownDirection;
pub const CloseReason = connection.CloseReason;
pub const Read = connection.Read;

pub const Error = connection.Error || std.mem.Allocator.Error || error{
    TableFull,
    StaleHandle,
    InvalidLimits,
};

pub const Handle = struct {
    index: u16,
    generation: u32,
};

pub const StreamHandle = struct {
    conn: Handle,
    id: u64,
};

pub const Event = union(enum) {
    connected: struct { conn: Handle, peer_id: peer_id.PeerId, direction: Direction },
    closed: struct { conn: Handle, reason: CloseReason },
    stream_opened: StreamHandle,
};

pub const Limits = struct {
    connections_max: u16 = constants.connections_max_default,
    handshaking_max: u16 = constants.handshaking_max,
    handshaking_per_source_max: u16 = constants.handshaking_per_source_max,
    receive_budget_bytes: u64 = constants.receive_budget_bytes,
    idle_timeout_ms: u64 = constants.idle_timeout_ms,
    handshake_timeout_ms: u64 = constants.handshake_timeout_ms,
    keep_alive_ms: u64 = constants.keep_alive_ms,
};

pub const Counters = struct {
    accepted: u64 = 0,
    dropped_unroutable: u64 = 0,
    dropped_short_initial: u64 = 0,
    dropped_full: u64 = 0,
    dropped_source_limit: u64 = 0,
    recv_errors: u64 = 0,
    version_negotiations: u64 = 0,
};

pub const ReceiveOutcome = union(enum) {
    accepted: Handle,
    version_negotiation: []u8,
    dropped,
};

pub const EntropyPool = struct {
    bytes: [constants.local_cid_length]u8 = undefined,
    fresh: bool = false,

    pub fn fill(self: *EntropyPool, bytes: [constants.local_cid_length]u8) void {
        self.bytes = bytes;
        self.fresh = true;
    }

    pub fn take(self: *EntropyPool) [constants.local_cid_length]u8 {
        std.debug.assert(self.fresh);
        self.fresh = false;
        return self.bytes;
    }
};

const Route = struct {
    cid: binding.Cid = .{},
    index: u16 = 0,
    active: bool = false,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    tls_ctx: *const tls.Context,
    config: binding.Config,
    limits: Limits,
    slots: []connection.Slot,
    routes: []Route,
    active: []u16,
    active_len: u16 = 0,
    connection_window: u64,
    stream_window: u64,
    handshaking: u16 = 0,
    counters: Counters = .{},

    pub fn init(allocator: std.mem.Allocator, tls_ctx: *const tls.Context, limits: Limits) Error!Engine {
        if (limits.connections_max == 0 or limits.connections_max > constants.connections_max_ceiling) return error.InvalidLimits;
        if (limits.handshaking_max == 0 or limits.handshaking_max > limits.connections_max) return error.InvalidLimits;
        if (limits.handshaking_per_source_max == 0) return error.InvalidLimits;
        if (limits.idle_timeout_ms == 0 or limits.handshake_timeout_ms == 0 or limits.keep_alive_ms == 0) return error.InvalidLimits;

        const connection_window = std.math.clamp(
            limits.receive_budget_bytes / limits.connections_max,
            constants.connection_window_min,
            constants.connection_window_max,
        );
        const stream_window = connection_window / 2;

        var config = try binding.Config.init(limits.idle_timeout_ms, connection_window, stream_window);
        errdefer config.deinit();

        const slots = try allocator.alloc(connection.Slot, limits.connections_max);
        errdefer allocator.free(slots);
        @memset(slots, .{});

        const routes = try allocator.alloc(Route, @as(usize, limits.connections_max) * 2);
        errdefer allocator.free(routes);
        @memset(routes, .{});

        const active = try allocator.alloc(u16, limits.connections_max);
        errdefer allocator.free(active);
        for (active, 0..) |*entry, index| entry.* = @intCast(index);

        return .{
            .allocator = allocator,
            .tls_ctx = tls_ctx,
            .config = config,
            .limits = limits,
            .slots = slots,
            .routes = routes,
            .active = active,
            .connection_window = connection_window,
            .stream_window = stream_window,
        };
    }

    pub fn deinit(self: *Engine) void {
        for (self.slots) |*slot| {
            if (slot.state != .free) slot.release();
        }
        self.allocator.free(self.active);
        self.allocator.free(self.routes);
        self.allocator.free(self.slots);
        self.config.deinit();
        self.* = undefined;
    }

    pub fn slotCount(self: *const Engine) u16 {
        return @intCast(self.slots.len);
    }

    pub fn dial(
        self: *Engine,
        local: types.Address,
        peer: types.Address,
        expected: peer_id.PeerId,
        now: Now,
        entropy: [constants.local_cid_length]u8,
    ) Error!Handle {
        const index = self.claimSlot() orelse return error.TableFull;
        const slot = &self.slots[index];
        slot.open(self.tls_ctx, &self.config, .{
            .direction = .outbound,
            .local = local,
            .peer = peer,
            .scid = entropy,
            .odcid = null,
            .expected_peer_id = expected,
            .now = now,
        }) catch |err| {
            self.unclaimSlot(index);
            return err;
        };
        self.addRoute(&slot.scid, index);
        return .{ .index = index, .generation = slot.generation };
    }

    pub fn receive(
        self: *Engine,
        datagram: []u8,
        from: types.Address,
        local: types.Address,
        now: Now,
        entropy: *EntropyPool,
        out: []u8,
    ) ReceiveOutcome {
        const header = binding.headerInfo(datagram) catch return self.drop(&self.counters.dropped_unroutable);
        if (self.findRoute(&header.dcid)) |index| {
            if (!self.slots[index].peer.eql(from)) return self.drop(&self.counters.dropped_unroutable);
            self.feed(index, datagram);
            return .{ .accepted = self.toHandle(index) };
        }
        if (header.packet_type == .short) {
            const index = self.slotForPeer(from) orelse return self.drop(&self.counters.dropped_unroutable);
            self.feed(index, datagram);
            return .{ .accepted = self.toHandle(index) };
        }
        if (datagram.len < constants.client_initial_min) return self.drop(&self.counters.dropped_short_initial);
        if (header.packet_type == .version_negotiation or header.version == 0) {
            return self.drop(&self.counters.dropped_unroutable);
        }
        if (!binding.versionSupported(header.version)) {
            const written = binding.check(c.quiche_negotiate_version(
                header.scid.slice().ptr,
                header.scid.len,
                header.dcid.slice().ptr,
                header.dcid.len,
                out.ptr,
                out.len,
            )) catch return self.drop(&self.counters.dropped_unroutable);
            self.counters.version_negotiations += 1;
            return .{ .version_negotiation = out[0..written] };
        }
        if (header.packet_type != .initial) return self.drop(&self.counters.dropped_unroutable);
        if (self.handshaking >= self.limits.handshaking_max) return self.drop(&self.counters.dropped_full);
        if (self.handshakingFromSource(from) >= self.limits.handshaking_per_source_max) {
            return self.drop(&self.counters.dropped_source_limit);
        }
        const index = self.claimSlot() orelse return self.drop(&self.counters.dropped_full);

        const slot = &self.slots[index];
        slot.open(self.tls_ctx, &self.config, .{
            .direction = .inbound,
            .local = local,
            .peer = from,
            .scid = entropy.take(),
            .odcid = header.dcid,
            .expected_peer_id = null,
            .now = now,
        }) catch {
            self.unclaimSlot(index);
            return self.drop(&self.counters.recv_errors);
        };
        self.addRoute(&slot.scid, index);
        self.addRoute(&header.dcid, index);
        self.handshaking += 1;
        self.feed(index, datagram);
        return .{ .accepted = self.toHandle(index) };
    }

    pub fn tick(self: *Engine, now: Now) void {
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            if (slot.state == .closed) continue;
            slot.onTimeout();
            if (slot.state == .handshaking and slot.close_reason == null and
                now.mono_ms -| slot.created_ms >= self.limits.handshake_timeout_ms)
            {
                slot.close(.handshake_timeout, connection.app_error_handshake_timeout);
            }
            if (slot.state == .established and slot.close_reason == null and
                now.mono_ms -| slot.last_send_ms >= self.limits.keep_alive_ms and
                slot.keepAlive())
            {
                slot.last_send_ms = now.mono_ms;
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
        }
    }

    pub fn nextTimeoutMs(self: *const Engine) ?u64 {
        var earliest: ?u64 = null;
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            if (slot.state == .closed) continue;
            const timeout = slot.timeoutMs() orelse continue;
            if (earliest == null or timeout < earliest.?) earliest = timeout;
        }
        return earliest;
    }

    pub fn send(self: *Engine, index: u16, now: Now, out: []u8) Error!?[]u8 {
        if (index >= self.slots.len) return null;
        const slot = &self.slots[index];
        if (slot.state == .free or slot.state == .closed) return null;
        const datagram = slot.send(now.mono_ms, out) catch |err| {
            self.refresh(index);
            return err;
        };
        if (datagram == null) self.refresh(index);
        return datagram;
    }

    pub fn peerAddress(self: *const Engine, index: u16) ?types.Address {
        if (index >= self.slots.len) return null;
        const slot = &self.slots[index];
        if (slot.state == .free) return null;
        return slot.peer;
    }

    pub fn pollEvents(self: *Engine, events: []Event) usize {
        var count: usize = 0;
        var cursor: u16 = 0;
        while (cursor < self.active_len) {
            const index = self.active[cursor];
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
            if (slot.streams_pending > 0) {
                for (&slot.streams) |*stream| {
                    if (!stream.opened_pending) continue;
                    if (count == events.len) return count;
                    events[count] = .{ .stream_opened = .{ .conn = conn, .id = stream.id } };
                    count += 1;
                    stream.opened_pending = false;
                    slot.streams_pending -= 1;
                }
            }
            if (slot.closed_pending) {
                if (count == events.len) return count;
                events[count] = .{ .closed = .{ .conn = conn, .reason = slot.close_reason.? } };
                count += 1;
                slot.closed_pending = false;
                self.releaseSlot(index);
                continue;
            }
            cursor += 1;
        }
        return count;
    }

    pub fn close(self: *Engine, conn: Handle, code: u64) bool {
        const slot = self.liveSlot(conn) catch return false;
        slot.close(.host, code);
        return true;
    }

    pub fn abandon(self: *Engine, conn: Handle) bool {
        const slot = self.readableSlot(conn) catch return false;
        if (slot.state != .handshaking or slot.closed_pending) return false;
        if (slot.direction == .inbound) self.handshaking -= 1;
        self.removeRoutesFor(conn.index);
        self.releaseSlot(conn.index);
        return true;
    }

    pub fn eventsPending(self: *const Engine) bool {
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            if (slot.connected_pending or slot.streams_pending > 0 or slot.closed_pending) return true;
        }
        return false;
    }

    pub fn peerId(self: *Engine, conn: Handle) ?peer_id.PeerId {
        const slot = self.readableSlot(conn) catch return null;
        return slot.peer_id;
    }

    pub fn openStream(self: *Engine, conn: Handle) Error!StreamHandle {
        const slot = try self.liveSlot(conn);
        const id = try slot.openStream();
        return .{ .conn = conn, .id = id };
    }

    pub fn read(self: *Engine, stream: StreamHandle, buf: []u8) Error!Read {
        const slot = try self.readableSlot(stream.conn);
        return slot.read(stream.id, buf);
    }

    pub fn write(self: *Engine, stream: StreamHandle, bytes: []const u8, fin: bool) Error!usize {
        const slot = try self.liveSlot(stream.conn);
        return slot.write(stream.id, bytes, fin);
    }

    pub fn streamCapacity(self: *Engine, stream: StreamHandle) Error!usize {
        const slot = try self.readableSlot(stream.conn);
        return slot.capacity(stream.id);
    }

    pub fn shutdown(self: *Engine, stream: StreamHandle, direction: ShutdownDirection, code: u64) void {
        const slot = self.liveSlot(stream.conn) catch return;
        if (slot.streamIndex(stream.id) == null) return;
        slot.shutdown(stream.id, direction, code);
    }

    pub fn closeStream(self: *Engine, stream: StreamHandle, code: u64) void {
        const slot = self.liveSlot(stream.conn) catch return;
        slot.closeStream(stream.id, code);
    }

    pub const StreamIterator = struct {
        iter: ?*c.quiche_stream_iter,
        slot: ?*connection.Slot,
        conn: Handle,

        pub fn next(self: *StreamIterator) ?StreamHandle {
            const iter = self.iter orelse return null;
            const slot = self.slot orelse return null;
            var id: u64 = 0;
            var seen: u16 = 0;
            while (seen < constants.streams_per_connection and c.quiche_stream_iter_next(iter, &id)) : (seen += 1) {
                if (slot.streamIndex(id) != null) return .{ .conn = self.conn, .id = id };
            }
            return null;
        }

        pub fn deinit(self: *StreamIterator) void {
            if (self.iter) |iter| c.quiche_stream_iter_free(iter);
            self.* = undefined;
        }
    };

    pub const ReadableIterator = StreamIterator;
    pub const WritableIterator = StreamIterator;

    pub fn readable(self: *Engine, conn: Handle) ReadableIterator {
        const slot = self.readableSlot(conn) catch return .{ .iter = null, .slot = null, .conn = conn };
        return .{ .iter = c.quiche_conn_readable(slot.conn.?), .slot = slot, .conn = conn };
    }

    pub fn writable(self: *Engine, conn: Handle) WritableIterator {
        const slot = self.readableSlot(conn) catch return .{ .iter = null, .slot = null, .conn = conn };
        return .{ .iter = c.quiche_conn_writable(slot.conn.?), .slot = slot, .conn = conn };
    }

    pub fn handle(self: *const Engine, index: u16) ?Handle {
        if (index >= self.slots.len) return null;
        const slot = &self.slots[index];
        if (slot.state == .free) return null;
        return .{ .index = index, .generation = slot.generation };
    }

    pub fn activeIndices(self: *const Engine, out: []u16) usize {
        const count = @min(out.len, self.active_len);
        @memcpy(out[0..count], self.active[0..count]);
        return count;
    }

    fn readableSlot(self: *Engine, conn: Handle) Error!*connection.Slot {
        if (conn.index >= self.slots.len) return error.StaleHandle;
        const slot = &self.slots[conn.index];
        if (slot.generation != conn.generation or slot.conn == null) return error.StaleHandle;
        return slot;
    }

    fn liveSlot(self: *Engine, conn: Handle) Error!*connection.Slot {
        if (conn.index >= self.slots.len) return error.StaleHandle;
        const slot = &self.slots[conn.index];
        if (slot.generation != conn.generation or slot.state == .free or slot.state == .closed or
            slot.pending_close != null or slot.close_reason != null)
        {
            return error.StaleHandle;
        }
        return slot;
    }

    fn toHandle(self: *const Engine, index: u16) Handle {
        return .{ .index = index, .generation = self.slots[index].generation };
    }

    fn drop(_: *Engine, counter: *u64) ReceiveOutcome {
        counter.* += 1;
        return .dropped;
    }

    fn feed(self: *Engine, index: u16, datagram: []u8) void {
        const slot = &self.slots[index];
        if (slot.state == .closed) return;
        if (slot.recv(datagram)) |_| {
            self.counters.accepted += 1;
        } else |_| {
            self.counters.recv_errors += 1;
        }
        self.refresh(index);
    }

    fn refresh(self: *Engine, index: u16) void {
        const slot = &self.slots[index];
        if (slot.state == .handshaking and slot.isEstablished()) {
            slot.state = .established;
            if (slot.direction == .inbound) self.handshaking -= 1;
            if (slot.handshake.peer_id) |id| {
                slot.peer_id = id;
                if (slot.expected_peer_id != null and !slot.expected_peer_id.?.eql(&id)) {
                    slot.deferClose(.peer_id_mismatch, connection.app_error_peer_id_mismatch);
                } else {
                    slot.connected_pending = true;
                }
            } else {
                slot.close(.tls_failed, connection.app_error_normal);
            }
        }
        if (slot.state == .established and slot.pending_close == null) slot.discoverPeerStreams();
        if (slot.state != .closed and slot.isFinished()) {
            if (slot.state == .handshaking and slot.direction == .inbound) self.handshaking -= 1;
            slot.state = .closed;
            slot.close_reason = slot.closeReason();
            slot.closed_pending = true;
            self.removeRoutesFor(index);
        }
    }

    fn slotForPeer(self: *const Engine, from: types.Address) ?u16 {
        var found: ?u16 = null;
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            if (slot.state == .closed or !slot.peer.eql(from)) continue;
            if (found != null) return null;
            found = index;
        }
        return found;
    }

    fn handshakingFromSource(self: *const Engine, from: types.Address) u16 {
        var count: u16 = 0;
        for (self.active[0..self.active_len]) |index| {
            const slot = &self.slots[index];
            if (slot.state != .handshaking or slot.direction != .inbound) continue;
            if (slot.peer.sameHost(from)) count += 1;
        }
        return count;
    }

    fn claimSlot(self: *Engine) ?u16 {
        if (self.active_len == self.active.len) return null;
        const index = self.active[self.active_len];
        self.active_len += 1;
        return index;
    }

    fn unclaimSlot(self: *Engine, index: u16) void {
        var cursor: u16 = 0;
        while (cursor < self.active_len) : (cursor += 1) {
            if (self.active[cursor] != index) continue;
            self.active_len -= 1;
            self.active[cursor] = self.active[self.active_len];
            self.active[self.active_len] = index;
            return;
        }
    }

    fn releaseSlot(self: *Engine, index: u16) void {
        self.slots[index].release();
        self.unclaimSlot(index);
    }

    fn findRoute(self: *const Engine, cid: *const binding.Cid) ?u16 {
        for (self.routes) |*route| {
            if (route.active and route.cid.eql(cid)) return route.index;
        }
        return null;
    }

    fn addRoute(self: *Engine, cid: *const binding.Cid, index: u16) void {
        for (self.routes) |*route| {
            if (route.active) continue;
            route.* = .{ .cid = cid.*, .index = index, .active = true };
            return;
        }
        unreachable;
    }

    fn removeRoutesFor(self: *Engine, index: u16) void {
        for (self.routes) |*route| {
            if (route.active and route.index == index) route.active = false;
        }
    }
};
