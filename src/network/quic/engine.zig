const std = @import("std");
const api = @import("api.zig");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const constants = @import("../constants.zig");
const limits = @import("limits.zig");
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
        assert(self.engine.registry.slots.len > 0);
        return self.engine.receive(datagram, from, now, entropy, out);
    }

    pub fn tick(self: DriverView, now: Now) void {
        self.engine.tick(now);
    }

    pub fn hostWorkPending(self: DriverView) bool {
        return self.engine.host_work_pending;
    }

    pub fn takeHostWork(self: DriverView) bool {
        const pending = self.engine.host_work_pending;
        self.engine.host_work_pending = false;
        return pending;
    }

    pub fn slotCount(self: DriverView) u16 {
        const engine = self.engine;
        assert(engine.registry.slots.len > 0);
        assert(engine.registry.slots.len <= limits.connections_max_ceiling);
        return @intCast(engine.registry.slots.len);
    }

    pub fn nextTimeoutMs(self: DriverView, now: Now) ?u64 {
        return self.engine.nextTimeoutMs(now);
    }

    pub fn sendOne(self: DriverView, index: u16, now: Now, out: []u8) ?Sent {
        return self.engine.send(index, now, out);
    }

    pub fn sendOwner(self: DriverView, index: u16) ?Handle {
        if (index >= self.engine.registry.slots.len) return null;
        const slot = &self.engine.registry.slots[index];
        if (slot.state == .free or slot.state == .closed) return null;
        return .{ .index = index, .generation = slot.generation };
    }

    pub fn tickOne(self: DriverView, index: u16, now: Now) void {
        self.engine.tickOne(index, now);
    }

    pub fn sendBatch(self: DriverView, index: u16, now: Now, batch: *SendBatch) u8 {
        assert(index < self.engine.registry.slots.len);
        var count: u8 = 0;
        while (count < constants.send_batch_max) : (count += 1) {
            const sent = self.engine.send(index, now, &batch.buffers[count]) orelse break;
            batch.sent[count] = sent;
        }
        assert(count <= constants.send_batch_max);
        return count;
    }

    pub fn takeKeylog(self: DriverView, index: u16, out: []u8) usize {
        assert(index < self.engine.registry.slots.len);
        assert(out.len >= tls.keylog_capacity);
        const slot = &self.engine.registry.slots[index];
        if (slot.state == .free) return 0;
        return slot.takeKeylog(out);
    }

    pub fn failSend(self: DriverView, index: u16) void {
        assert(index < self.engine.registry.slots.len);
        const slot = &self.engine.registry.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        self.engine.markClosed(index, .send_failed);
    }

    pub fn activeIndices(self: DriverView) []const u16 {
        const engine = self.engine;
        assert(engine.registry.active.len == engine.registry.slots.len);
        assert(engine.registry.active_len <= engine.registry.active.len);
        return engine.registry.active[0..engine.registry.active_len];
    }

    pub fn releaseReported(self: DriverView) void {
        const engine = self.engine;
        assert(engine.registry.active_len <= engine.registry.active.len);
        assert(engine.registry.active.len == engine.registry.slots.len);
        engine.releaseReported();
    }

    pub fn takeActivity(self: DriverView, out: []Handle) usize {
        const engine = self.engine;
        assert(engine.registry.activity.len == engine.registry.slots.len);
        assert(engine.registry.active_len <= engine.registry.active.len);
        assert(engine.activity_cursor < engine.registry.slots.len);
        var count: usize = 0;
        for (0..engine.registry.slots.len) |_| {
            if (count == out.len) break;
            const index = engine.activity_cursor;
            engine.activity_cursor = @intCast((@as(usize, index) + 1) % engine.registry.slots.len);
            const slot = &engine.registry.slots[index];
            if (slot.state == .free or !engine.registry.activity[index]) continue;
            out[count] = .{ .index = index, .generation = slot.generation };
            engine.registry.activity[index] = false;
            count += 1;
        }
        assert(count <= out.len);
        return count;
    }

    pub fn activityPending(self: DriverView) bool {
        const engine = self.engine;
        assert(engine.registry.activity.len == engine.registry.slots.len);
        assert(engine.registry.active_len <= engine.registry.active.len);
        for (engine.registry.active[0..engine.registry.active_len]) |index| {
            if (engine.registry.activity[index]) return true;
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
    registry: @import("registry.zig").Registry,
    connection_window: u64,
    stream_window: u64,
    outbound_max: u16,
    counters: Counters = .{},
    host_work_pending: bool = false,
    // Physical slot positions preserve continuation through active-list swap removal.
    event_cursor: u16 = 0,
    activity_cursor: u16 = 0,

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!Engine {
        const wanted = options.limits;
        if (wanted.connections_max == 0) return error.InvalidLimits;
        if (wanted.connections_max > limits.connections_max_ceiling) return error.InvalidLimits;
        if (wanted.handshaking_max == 0 or wanted.handshaking_max > wanted.connections_max) {
            return error.InvalidLimits;
        }
        if (wanted.handshaking_per_source_max == 0) return error.InvalidLimits;
        if (wanted.receive_budget_bytes == 0) return error.InvalidLimits;
        if (wanted.send_per_step_max == 0 or wanted.send_per_step_max > limits.send_burst_max) return error.InvalidLimits;
        if (wanted.receive_per_step_max == 0 or wanted.receive_per_step_max > constants.receive_batch_max) return error.InvalidLimits;
        if (wanted.work_per_step_max < 2 or wanted.work_per_step_max > limits.work_per_step_max) return error.InvalidLimits;
        if (wanted.idle_timeout_ms > limits.timeout_ms_max or wanted.handshake_timeout_ms > limits.timeout_ms_max or wanted.keep_alive_ms > limits.timeout_ms_max) return error.InvalidLimits;
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

        var registry = try @import("registry.zig").Registry.init(allocator, wanted.connections_max, wanted.keylog, options.seed);
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
        };
    }

    pub fn deinit(self: *Engine) void {
        self.registry.deinit(self.allocator);
        self.tls.deinit();
        self.config.deinit();
        self.* = undefined;
    }

    pub fn driverView(self: *Engine) DriverView {
        assert(self.registry.slots.len > 0);
        assert(self.registry.active_len <= self.registry.slots.len);
        return .{ .engine = self };
    }

    pub fn memoryPlan(self: *const Engine) api.MemoryPlan {
        const count = self.limits.connections_max;
        return .{
            .requested_receive_window_bytes = self.limits.receive_budget_bytes,
            .receive_window_bytes = self.connection_window * count,
            .connection_window_bytes = self.connection_window,
            .stream_window_bytes = self.stream_window,
            .scheduled_datagrams = count,
            .scheduled_payload_bytes = @as(u64, count) * constants.datagram_size_max,
            .scheduled_storage_bytes = @as(u64, count) * @sizeOf(@import("schedule.zig").Entry),
            .native_pacing_supported = binding.native_pacing_supported,
        };
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
        assert(self.registry.active_len <= self.registry.active.len);
        assert(self.registry.dialing <= self.registry.outbound);
        if (self.registry.dialing >= self.limits.dialing_max) return error.DialLimit;
        if (self.registry.outbound >= self.outbound_max) return error.DialLimit;
        const index = self.registry.claim() orelse return error.TableFull;
        self.host_work_pending = true;
        assert(index < self.registry.slots.len);
        const slot = &self.registry.slots[index];
        slot.open(&self.tls, &self.config, .{
            .direction = .outbound,
            .local = self.local,
            .peer = peer.*,
            .scid = entropy,
            .expected_peer_id = expected,
            .now = now,
            .keylog = self.registry.keylogFor(index),
        }) catch {
            self.registry.unclaim(index);
            return error.OpenFailed;
        };
        self.registry.addRoute(&slot.scid, index) catch {
            self.registry.retire(index);
            return error.TableFull;
        };
        self.registry.dialing += 1;
        self.registry.outbound += 1;
        assert(self.registry.dialing <= self.limits.dialing_max);
        assert(self.registry.outbound <= self.outbound_max);
        return .{ .index = index, .generation = slot.generation };
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
                if (slot.close_event == .pending) return false;
                if (slot.direction == .inbound) {
                    self.registry.handshaking -= 1;
                } else {
                    assert(self.registry.dialing > 0);
                    assert(self.registry.outbound > 0);
                    self.registry.dialing -= 1;
                    self.registry.outbound -= 1;
                }
            },
            .closed => if (slot.close_event == .none) return false,
            else => return false,
        }
        assert(conn.index < self.registry.slots.len);
        assert(self.registry.active_len > 0);
        self.registry.removeRoutesFor(conn.index);
        self.registry.retire(conn.index);
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
        return self.registry.findPeer(id);
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
        if (self.registry.handshaking >= self.limits.handshaking_max) {
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
        const index = self.registry.claim() orelse return drop(&self.counters.dropped_full);

        const slot = &self.registry.slots[index];
        slot.open(&self.tls, &self.config, .{
            .direction = .inbound,
            .local = self.local,
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
            self.registry.retire(index);
            return drop(&self.counters.dropped_full);
        };
        self.registry.addRoute(&header.dcid, index) catch {
            self.registry.removeRoutesFor(index);
            self.registry.retire(index);
            return drop(&self.counters.dropped_full);
        };
        self.registry.handshaking += 1;
        assert(self.registry.handshaking <= self.limits.handshaking_max);
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
        for (self.registry.active[0..self.registry.active_len]) |index| self.tickOne(index, now);
    }

    fn tickOne(self: *Engine, index: u16, now: Now) void {
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

    fn nextTimeoutMs(self: *const Engine, now: Now) ?u64 {
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

    fn send(self: *Engine, index: u16, now: Now, out: []u8) ?Sent {
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

    fn releaseReported(self: *Engine) void {
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
                self.registry.retire(index);
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

    fn feed(self: *Engine, index: u16, datagram: []u8, from: *const Address) void {
        assert(index < self.registry.slots.len);
        assert(datagram.len > 0);
        const slot = &self.registry.slots[index];
        assert(slot.state != .free);
        if (slot.state == .closed) return;
        const was_established = slot.state == .established;
        const source = binding.SockAddr.fromAddress(from.*);
        var received = true;
        if (slot.recv(datagram, &source)) |_| {
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

    fn refresh(self: *Engine, index: u16) void {
        const slot = &self.registry.slots[index];
        if (slot.state == .handshaking and slot.isEstablished()) {
            slot.state = .established;
            if (slot.direction == .inbound) {
                self.registry.handshaking -= 1;
            } else {
                assert(self.registry.dialing > 0);
                self.registry.dialing -= 1;
            }
            if (slot.handshake.peer_id) |id| {
                self.registry.indexPeer(index, id);
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
        const slot = &self.registry.slots[index];
        assert(slot.state == .handshaking or slot.state == .established);
        if (slot.state == .established and slot.pending_close == null) {
            slot.discoverPeerStreams();
        }
        if (slot.state == .handshaking) {
            if (slot.direction == .inbound) {
                self.registry.handshaking -= 1;
            } else {
                assert(self.registry.dialing > 0);
                self.registry.dialing -= 1;
            }
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
            if (slot.peer.sameHost(from.*)) count += 1;
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
