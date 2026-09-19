const std = @import("std");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const constants = @import("../constants.zig");
const limits = @import("limits.zig");
const retry = @import("retry.zig");
const peer_id = @import("../wire/peer_id.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const c = binding.c;

pub const Now = types.Now;
pub const Direction = types.Direction;
pub const ShutdownDirection = types.ShutdownDirection;
pub const CloseReason = types.CloseReason;
pub const Read = types.Read;
pub const Address = types.Address;
pub const Sent = types.Sent;

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

pub const Event = union(enum) {
    connected: struct { conn: Handle, peer_id: peer_id.PeerId, direction: Direction },
    closed: struct {
        conn: Handle,
        peer_id: ?peer_id.PeerId,
        direction: Direction,
        reason: CloseReason,
    },
    stream_opened: StreamHandle,
    stream_closed: struct { stream: StreamHandle, reset_code: ?u64 },
    path_changed: struct { conn: Handle, peer: Address },
};

pub const Limits = struct {
    connections_max: u16 = limits.connections_max_default,
    handshaking_max: u16 = limits.handshaking_max,
    handshaking_per_source_max: u16 = limits.handshaking_per_source_max,
    dialing_max: u16 = limits.dialing_max,
    outbound_max: ?u16 = null,
    receive_budget_bytes: u64 = limits.receive_budget_bytes,
    idle_timeout_ms: u64 = limits.idle_timeout_ms,
    handshake_timeout_ms: u64 = limits.handshake_timeout_ms,
    keep_alive_ms: u64 = limits.keep_alive_ms,
    keylog: bool = false,
};

pub const Counters = struct {
    accepted: u64 = 0,
    dropped_unroutable: u64 = 0,
    dropped_short_initial: u64 = 0,
    dropped_full: u64 = 0,
    dropped_source_limit: u64 = 0,
    recv_errors: u64 = 0,
    send_errors: u64 = 0,
    stream_errors: u64 = 0,
    version_negotiations: u64 = 0,
    retries: u64 = 0,
    path_changes: u64 = 0,
    keylog_dropped: u64 = 0,
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
    counters: Counters = .{},
    connection_metrics: ConnectionCounters = .{},
    host_work_pending: bool = false,
    // Physical slot positions preserve continuation through active-list swap removal.
    event_cursor: u16 = 0,
    activity_cursor: u16 = 0,

    pub const Resources = struct {
        capacity: usize,
        active: usize,
        handshaking: usize,
        dialing: usize,
        outbound: usize,
    };

    pub fn resourceSnapshot(self: *const Engine) Resources {
        return .{ .capacity = self.registry.slots.len, .active = self.registry.active_len, .handshaking = self.registry.handshaking, .dialing = self.registry.dialing, .outbound = self.registry.outbound };
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
        if (wanted.idle_timeout_ms > limits.timeout_ms_max or wanted.handshake_timeout_ms > limits.timeout_ms_max or wanted.keep_alive_ms > limits.timeout_ms_max) return error.InvalidLimits;
        if (wanted.idle_timeout_ms == 0) return error.InvalidLimits;
        if (wanted.handshake_timeout_ms == 0) return error.InvalidLimits;
        if (wanted.keep_alive_ms == 0) return error.InvalidLimits;
        if (wanted.dialing_max == 0) return error.InvalidLimits;
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

    pub fn hostWorkPending(self: *const Engine) bool {
        return self.host_work_pending;
    }

    pub fn takeHostWork(self: *Engine) bool {
        const pending = self.host_work_pending;
        self.host_work_pending = false;
        return pending;
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
        self.collectKeylogDrops(index);
        return slot.takeKeylog(out);
    }

    fn collectKeylogDrops(self: *Engine, index: u16) void {
        if (!self.limits.keylog) return;
        const state = &self.registry.slots[index].handshake;
        self.counters.keylog_dropped +|= state.keylog_dropped;
        state.keylog_dropped = 0;
    }

    fn retire(self: *Engine, index: u16) void {
        self.collectKeylogDrops(index);
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

    pub fn takeActivity(self: *Engine, out: []Handle) usize {
        assert(self.registry.activity.len == self.registry.slots.len);
        assert(self.registry.active_len <= self.registry.active.len);
        assert(self.activity_cursor < self.registry.slots.len);
        var count: usize = 0;
        for (0..self.registry.slots.len) |_| {
            if (count == out.len) break;
            const index = self.activity_cursor;
            self.activity_cursor = @intCast((@as(usize, index) + 1) % self.registry.slots.len);
            const slot = &self.registry.slots[index];
            if (slot.state == .free or !self.registry.activity[index]) continue;
            out[count] = .{ .index = index, .generation = slot.generation };
            self.registry.activity[index] = false;
            count += 1;
        }
        assert(count <= out.len);
        return count;
    }

    pub fn activityPending(self: *const Engine) bool {
        assert(self.registry.activity.len == self.registry.slots.len);
        assert(self.registry.active_len <= self.registry.active.len);
        for (self.registry.active[0..self.registry.active_len]) |index| {
            if (self.registry.activity[index]) return true;
        }
        return false;
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
        self.host_work_pending = true;
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
        return .{ .index = index, .generation = slot.generation };
    }

    fn connectionId(self: *Engine) [limits.local_cid_length]u8 {
        var bytes: [limits.local_cid_length]u8 = undefined;
        self.csprng.fill(&bytes);
        return bytes;
    }

    pub fn close(self: *Engine, conn: Handle, code: u64) bool {
        const slot = self.liveSlot(conn) catch return false;
        assert(slot.conn != null);
        assert(slot.close_reason == null);
        slot.close(.host, code);
        self.host_work_pending = true;
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
        self.host_work_pending = true;
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

    pub fn openStream(self: *Engine, conn: Handle) StreamError!StreamHandle {
        const slot = try self.liveSlot(conn);
        self.host_work_pending = true;
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
        if (result.len > 0 or result.fin or result.reset_code != null) self.host_work_pending = true;
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
        self.host_work_pending = true;
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
        self.host_work_pending = true;
    }

    pub fn closeStream(self: *Engine, stream: StreamHandle, code: u64) void {
        const target = self.liveStream(stream) catch return;
        assert(target.index < limits.streams_per_connection);
        assert(target.slot.conn != null);
        target.slot.closeStream(target.index, target.id, code);
        self.host_work_pending = true;
    }

    pub fn pollEvents(self: *Engine, events: []Event) usize {
        assert(self.registry.active_len <= self.registry.active.len);
        assert(self.event_cursor < self.registry.slots.len);
        var count: usize = 0;
        for (0..self.registry.slots.len) |_| {
            if (count == events.len) return count;
            const index = self.event_cursor;
            self.event_cursor = @intCast((@as(usize, index) + 1) % self.registry.slots.len);
            assert(index < self.registry.slots.len);
            const slot = &self.registry.slots[index];
            if (slot.state == .free) continue;
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
        }
        assert(count <= events.len);
        return count;
    }

    pub fn eventsPending(self: *const Engine) bool {
        assert(self.registry.active_len <= self.registry.active.len);
        for (self.registry.active[0..self.registry.active_len]) |index| {
            assert(index < self.registry.slots.len);
            const slot = &self.registry.slots[index];
            if (slot.connected_pending) return true;
            if (slot.path_changed_pending != null) return true;
            if (slot.table.pending > 0) return true;
            if (slot.close_event == .pending) return true;
        }
        return false;
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
        const local = self.localFor(from.*) orelse return drop(&self.counters.dropped_unroutable);
        const header = binding.headerInfo(datagram) catch
            return drop(&self.counters.dropped_unroutable);
        if (self.registry.findRoute(&header.dcid)) |index| {
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
        // RFC 9000 section 7.2 requires at least eight bytes for a new connection's DCID.
        if (header.dcid.len < limits.initial_dcid_length_min) return drop(&self.counters.dropped_unroutable);
        if (self.registry.handshaking >= self.limits.handshaking_max) {
            return drop(&self.counters.dropped_full);
        }
        if (self.handshakingFromSource(from) >= self.limits.handshaking_per_source_max) {
            return drop(&self.counters.dropped_source_limit);
        }
        if (header.token_len == 0) return self.sendRetry(&header, from, now, out);
        const original = retry.validate(&self.retry_key, from, &header.dcid, header.token[0..header.token_len], now.mono_ms, self.limits.handshake_timeout_ms) orelse return drop(&self.counters.dropped_unroutable);
        const scid = header.dcid.bytes[0..limits.local_cid_length].*;
        const index = self.registry.claim() orelse return drop(&self.counters.dropped_full);

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
            return drop(&self.counters.recv_errors);
        };
        self.registry.addRoute(&slot.scid, index) catch {
            self.retire(index);
            return drop(&self.counters.dropped_full);
        };
        assert(slot.scid.eql(&header.dcid));
        self.registry.handshaking += 1;
        assert(self.registry.handshaking <= self.limits.handshaking_max);
        self.feed(index, datagram, from);
        return .{ .accepted = self.toHandle(index) };
    }

    fn sendRetry(self: *Engine, header: *const binding.HeaderInfo, from: *const Address, now: Now, out: []u8) ReceiveOutcome {
        const bytes = self.connectionId();
        const scid = binding.Cid.fromSlice(&bytes);
        var buffer: [retry.token_max]u8 = undefined;
        const token = retry.mint(&self.retry_key, from, &header.dcid, &scid, now.mono_ms, &buffer);
        const length = (binding.check(c.quiche_retry(header.scid.slice().ptr, header.scid.len, header.dcid.slice().ptr, header.dcid.len, scid.slice().ptr, scid.len, token.ptr, token.len, header.version, out.ptr, out.len)) catch return drop(&self.counters.dropped_unroutable)) orelse return drop(&self.counters.dropped_unroutable);
        self.counters.retries +|= 1;
        return .{ .retry = out[0..length] };
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

    pub fn tick(self: *Engine, now: Now) void {
        for (self.registry.active[0..self.registry.active_len]) |index| self.tickOne(index, now);
    }

    pub fn tickOne(self: *Engine, index: u16, now: Now) void {
        const slot = &self.registry.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        const expired = if (slot.timeoutMs()) |remaining| remaining == 0 else false;
        slot.onTimeout();
        if (expired) self.registry.activity[index] = true;
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
            self.registry.activity[index] = true;
        }
        if (slot.pending_close) |pending| {
            if (pending.stage == .armed) {
                slot.pending_close = null;
                slot.close(pending.reason, pending.code);
            } else {
                slot.pending_close.?.stage = .armed;
            }
        }
        self.refresh(index);
        self.observePath(index);
    }

    pub fn nextTimeoutMs(self: *const Engine, now: Now) ?u64 {
        assert(self.registry.active_len <= self.registry.active.len);
        if (self.eventsPending()) return 0;
        var earliest: ?u64 = null;
        for (self.registry.active[0..self.registry.active_len]) |index| {
            const slot = &self.registry.slots[index];
            assert(slot.state != .free);
            if (slot.state == .closed or slot.pending_close != null) return 0;
            var timeout = slot.timeoutMs();
            if (slot.close_reason == null) {
                const deadline = if (slot.state == .handshaking)
                    slot.created_ms +| self.limits.handshake_timeout_ms
                else
                    slot.last_send_ms +| self.limits.keep_alive_ms;
                const host_timeout = deadline -| now.mono_ms;
                timeout = @min(timeout orelse host_timeout, host_timeout);
            }
            if (timeout) |remaining| earliest = @min(earliest orelse remaining, remaining);
        }
        return earliest;
    }

    pub fn sendOne(self: *Engine, index: u16, now: Now, out: []u8) ?Sent {
        if (index >= self.registry.slots.len) return null;
        const slot = &self.registry.slots[index];
        if (slot.state == .free or slot.state == .closed) return null;
        const sent = slot.send(now.mono_ms, out) catch {
            self.counters.send_errors += 1;
            self.refresh(index);
            return null;
        };
        if (sent == null) self.refresh(index);
        return sent;
    }

    pub fn releaseReported(self: *Engine) void {
        assert(self.registry.active_len <= self.registry.active.len);
        var cursor: u16 = 0;
        while (cursor < self.registry.active_len) {
            const index = self.registry.active[cursor];
            assert(index < self.registry.slots.len);
            const slot = &self.registry.slots[index];
            if (slot.state == .closed and slot.close_event == .reported) {
                assert(!slot.connected_pending);
                assert(slot.path_changed_pending == null);
                assert(slot.close_event != .pending);
                assert(slot.table.pending == 0);
                self.retire(index);
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

    fn drop(counter: *u64) ReceiveOutcome {
        counter.* += 1;
        return .dropped;
    }

    fn localFor(self: *const Engine, peer: Address) ?Address {
        return self.local[
            switch (peer) {
                .ip4 => @as(usize, 0),
                .ip6 => 1,
            }
        ];
    }

    fn feed(self: *Engine, index: u16, datagram: []u8, from: *const Address) void {
        assert(index < self.registry.slots.len);
        assert(datagram.len > 0);
        const slot = &self.registry.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        const was_established = slot.state == .established;
        const source = binding.SockAddr.fromAddress(from.*);
        var received = true;
        const destination = binding.SockAddr.fromAddress(self.localFor(from.*).?);
        if (slot.recv(datagram, &source, &destination)) |_| {
            self.counters.accepted += 1;
            self.registry.activity[index] = true;
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
        assert(index < self.registry.slots.len);
        const slot = &self.registry.slots[index];
        if (slot.state == .closed or slot.conn == null) return;
        const peer = slot.drainPathEvents() orelse return;
        assert(slot.state != .free);
        if (peer.eql(slot.peer)) return;
        slot.peer = peer;
        slot.peer_sockaddr = binding.SockAddr.fromAddress(peer);
        slot.path_changed_pending = peer;
        self.counters.path_changes += 1;
        self.registry.activity[index] = true;
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
            if (slot.state == .established and slot.pending_close == null) {
                slot.discoverPeerStreams();
            }
        }
        if (slot.state != .closed and slot.isFinished()) {
            self.markClosed(index, slot.closeReason());
        }
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
        if (slot.state == .established and slot.pending_close == null) {
            slot.discoverPeerStreams();
        }
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

fn pollStreamEvents(
    slot: *connection.Slot,
    conn: Handle,
    events: []Event,
    start: usize,
) usize {
    assert(slot.table.pending > 0);
    assert(start <= events.len);
    assert(slot.table.event_cursor < limits.streams_per_connection);
    var count = start;
    for (0..limits.streams_per_connection) |_| {
        if (count == events.len) return count;
        const index = slot.table.event_cursor;
        slot.table.event_cursor = @intCast((@as(u16, index) + 1) % limits.streams_per_connection);
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

test {
    _ = @import("engine_admission_test.zig");
    _ = @import("engine_close_test.zig");
    _ = @import("engine_handshake_test.zig");
    _ = @import("engine_notifications_test.zig");
    _ = @import("engine_path_test.zig");
    _ = @import("engine_stream_test.zig");
}
