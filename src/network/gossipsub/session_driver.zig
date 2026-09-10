const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const sessions_mod = @import("sessions.zig");
const types = @import("../types.zig");
const gossipsub_mod = @import("gossipsub.zig");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const peer_io_mod = @import("peer_io.zig");
const PeerIo = peer_io_mod.PeerIo;
const Version = sessions_mod.Version;
const assert = std.debug.assert;

const Allocator = std.mem.Allocator;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const TransportEvent = engine_mod.Event;
const Now = types.Now;
const Gossipsub = gossipsub_mod.Gossipsub;
const Event = gossipsub_mod.Event;
const ValidationHandle = gossipsub_mod.ValidationHandle;
const Verdict = gossipsub_mod.Verdict;

pub const outcomes_per_pump: usize = 16;

pub const InitError = gossipsub_mod.InitError;

pub const retry_min_ms = @import("peer_session.zig").retry_min_ms;
pub const retry_max_ms = @import("peer_session.zig").retry_max_ms;
pub const openings_per_pump: usize = 16;

pub const Driver = struct {
    inner: *Gossipsub,
    open_cursor: usize = 0,

    pub fn init(allocator: Allocator, options: gossipsub_mod.Options) InitError!Driver {
        const inner = try allocator.create(Gossipsub);
        errdefer allocator.destroy(inner);
        inner.* = try Gossipsub.init(allocator, options);
        return .{ .inner = inner };
    }

    pub fn deinit(self: *Driver) void {
        const allocator = self.inner.allocator;
        self.inner.deinit();
        allocator.destroy(self.inner);
        self.* = undefined;
    }

    pub fn shutdown(self: *Driver, router: *routing.Router, engine: *Engine) void {
        for (self.inner.sessions.rows, 0..) |*peer, index| {
            if (peer.active) self.retirePeer(router, engine, @intCast(index));
        }
    }

    pub fn subscribe(self: *Driver, topic: []const u8) bool {
        return self.inner.subscribe(topic);
    }

    pub fn configureTopic(self: *Driver, topic: []const u8, params: *const @import("score.zig").TopicParams) Gossipsub.ConfigureTopicError!void {
        return self.inner.configureTopic(topic, params);
    }

    pub fn unsubscribe(self: *Driver, topic: []const u8) bool {
        return self.inner.unsubscribe(topic);
    }

    pub fn publish(
        self: *Driver,
        topic: []const u8,
        ssz: []const u8,
        now: Now,
    ) Gossipsub.PublishError!Gossipsub.PublishOutcome {
        return self.publishWithOptions(topic, ssz, .{}, now);
    }

    pub fn publishWithOptions(self: *Driver, topic: []const u8, ssz: []const u8, options: Gossipsub.PublishOptions, now: Now) Gossipsub.PublishError!Gossipsub.PublishOutcome {
        return self.inner.publishWithOptions(topic, ssz, options, now);
    }

    pub fn report(self: *Driver, handle: ValidationHandle, verdict: Verdict, now: Now) gossipsub_mod.ReportOutcome {
        return self.inner.report(handle, verdict, now);
    }

    pub fn setPeerScore(self: *Driver, conn: Handle, value: f64) bool {
        return self.inner.setPeerScore(conn, value);
    }

    pub fn markDirect(self: *Driver, conn: Handle) void {
        self.inner.markDirect(conn);
    }

    pub fn counters(self: *const Driver) Gossipsub.Counters {
        return self.inner.counters;
    }

    pub fn resourceSnapshot(self: *const Driver) gossipsub_mod.ResourceSnapshot {
        return self.inner.resourceSnapshot();
    }

    /// Hosts inspect this after each connected event and service pump. Refused or locally retired
    /// gossip relationships retain reqresp access.
    /// Retry peerConnected with the same live handle after capacity returns or its duplicate closes.
    /// Hosts schedule retries at most once per second per connection, bounded by transport capacity.
    pub fn admitted(self: *Driver, conn: Handle) bool {
        return self.inner.sessions.findPeer(conn) != null;
    }

    pub fn deliveryAvailable(self: *const Driver, conn: Handle) bool {
        const index = self.inner.sessions.findPeer(conn) orelse return false;
        return self.inner.sessions.rows[index].outStream() != null;
    }

    pub fn peerConnected(self: *Driver, engine: *Engine, conn: Handle, now: Now) Admission {
        if (self.inner.sessions.findPeer(conn) != null) return .admitted;
        const identity = engine.peerId(conn) orelse return .unauthenticated;
        const address = engine.peerAddress(conn) orelse return .unauthenticated;
        const direction = engine.direction(conn) orelse return .unauthenticated;
        const result = self.inner.addPeer(conn, .v1_2, &.{ .identity = identity, .address = address, .direction = direction }, now);
        const peer = switch (result) {
            .admitted => |peer| peer,
            .duplicate => return .duplicate,
            .capacity => return .capacity,
        };
        self.inner.sessions.rows[peer.index].outbound = .{ .waiting = now.mono_ms };
        return .admitted;
    }

    pub fn transportEvents(
        self: *Driver,
        router: *routing.Router,
        engine: *Engine,
        events: []const TransportEvent,
        now: Now,
    ) void {
        self.inner.last_now_ms = @max(self.inner.last_now_ms, now.mono_ms);
        for (events) |event| switch (event) {
            .connected => |connected| {
                _ = self.peerConnected(engine, connected.conn, now);
            },
            .path_changed => |changed| self.inner.peers.migrate(changed.conn, changed.peer),
            .stream_closed => |closed| self.streamClosed(engine, closed.stream, now),
            .closed => |closed| {
                const index = self.inner.sessions.findPeer(closed.conn) orelse continue;
                self.retirePeer(router, engine, index);
            },
            else => {},
        };
    }

    pub fn negotiationResult(
        self: *Driver,
        engine: *Engine,
        outcome: routing.Outcome,
        now: Now,
    ) void {
        const index = self.inner.sessions.findPeer(outcome.stream.conn) orelse {
            engine.closeStream(outcome.stream, 0);
            return;
        };
        const session = &self.inner.sessions.rows[index];
        switch (outcome.result) {
            .ready => self.inner.counters.negotiation_ready += 1,
            .rejected => self.inner.counters.negotiation_rejected += 1,
            .failed => self.inner.counters.negotiation_failed += 1,
        }
        if (outcome.result != .ready) std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_failed connection={d}:{d} stream={d} direction={s} reason={s} attempts={d}", .{ outcome.stream.conn.index, outcome.stream.conn.generation, outcome.stream.id, @tagName(outcome.direction), if (outcome.result == .failed) @tagName(outcome.result.failed) else "rejected", session.failures });
        if (outcome.direction == .outbound) {
            const pending = switch (session.outbound) {
                .negotiating => |stream| stream,
                else => return,
            };
            if (!std.meta.eql(pending, outcome.stream)) return;
            switch (outcome.result) {
                .ready => |selection| {
                    if (selection.leftover.len != 0) {
                        std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_leftover connection={d}:{d} stream={d} bytes={d} fin={any}", .{ outcome.stream.conn.index, outcome.stream.conn.generation, outcome.stream.id, selection.leftover.len, selection.fin });
                        engine.closeStream(outcome.stream, 0);
                        self.retry(index, now);
                        return;
                    }
                    self.replaceOutbound(
                        engine,
                        index,
                        outcome.stream,
                        selection.protocol.meshsub,
                    );
                },
                else => self.retry(index, now),
            }
        } else switch (outcome.result) {
            .ready => |selection| {
                self.replaceInbound(
                    engine,
                    index,
                    outcome.stream,
                    selection.protocol.meshsub,
                );
                if (!self.inner.sessions.receiveHandoff(index, selection.leftover, selection.fin)) {
                    self.resetInbound(engine, index);
                }
            },
            else => {},
        }
    }

    pub fn connectionActivity(self: *Driver, conn: Handle) void {
        self.inner.sessions.connectionActivity(conn);
    }

    pub fn nextWakeup(self: *const Driver, now: Now, event_capacity: usize) ?u64 {
        var next = self.nextIoWakeup(now, event_capacity);
        for (self.inner.sessions.rows) |*session| {
            if (!session.active) continue;
            if (session.needs_service) return now.mono_ms;
            switch (session.outbound) {
                .waiting => |deadline| next = @min(next orelse deadline, @max(now.mono_ms, deadline)),
                .live => {},
                .negotiating => {},
            }
        }
        return next;
    }

    pub fn pump(
        self: *Driver,
        router: *routing.Router,
        engine: *Engine,
        now: Now,
        out: []Event,
    ) usize {
        self.inner.last_now_ms = @max(self.inner.last_now_ms, now.mono_ms);
        var openings: usize = 0;
        var examined: usize = 0;
        for (0..self.inner.sessions.rows.len) |_| {
            if (examined == 32) break;
            const index: u16 = @intCast(self.open_cursor);
            self.open_cursor = (self.open_cursor + 1) % self.inner.sessions.rows.len;
            const session = &self.inner.sessions.rows[index];
            if (!session.active) continue;
            session.needs_service = false;
            examined += 1;
            switch (session.outbound) {
                .live => |stream| {
                    // Observe idle STOP_SENDING without a write or a host-work hint.
                    _ = engine.streamCapacity(stream) catch {
                        self.resetOutbound(engine, index);
                        continue;
                    };
                },
                .waiting => |deadline| if (now.mono_ms >= deadline) {
                    self.openOutbound(router, engine, index, now);
                    openings += 1;
                    if (openings == openings_per_pump) break;
                },
                .negotiating => {},
            }
        }
        return self.pumpReady(router, engine, now, out);
    }

    fn openOutbound(
        self: *Driver,
        router: *routing.Router,
        engine: *Engine,
        index: u16,
        now: Now,
    ) void {
        const conn = self.inner.sessions.rows[index].conn;
        const stream = router.beginMeshsub(engine, conn, now) catch |err| {
            self.inner.counters.negotiation_deferred += 1;
            std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_deferred connection={d}:{d} reason={s} attempts={d}", .{ conn.index, conn.generation, @errorName(err), self.inner.sessions.rows[index].failures });
            self.retry(index, now);
            return;
        };
        self.inner.counters.negotiation_started += 1;
        self.inner.sessions.rows[index].outbound = .{ .negotiating = stream };
    }

    fn retry(self: *Driver, index: u16, now: Now) void {
        self.inner.sessions.rows[index].retry(now.mono_ms);
    }

    fn streamClosed(self: *Driver, engine: *Engine, stream: StreamHandle, now: Now) void {
        const index = self.inner.sessions.findPeer(stream.conn) orelse return;
        const session = &self.inner.sessions.rows[index];
        switch (session.outbound) {
            .live => |live| if (std.meta.eql(live, stream)) {
                self.resetOutbound(engine, index);
            },
            .negotiating => |pending| if (std.meta.eql(pending, stream)) self.retry(index, now),
            .waiting => {},
        }
        // Read-side FIN can be reported with buffered payload. The framing owner
        // drains it before resetting; a reset is observed by its next read.
    }

    pub fn resetInbound(self: *const Driver, engine: *Engine, index: u16) void {
        if (self.inner.sessions.rows[index].in_stream) |stream| {
            std.log.scoped(.network_gossip).debug("gossip_stream_reset direction=inbound connection={d}:{d} stream={d} blocked={s}", .{ stream.conn.index, stream.conn.generation, stream.id, @tagName(self.inner.sessions.rows[index].io.blocked) });
            engine.closeStream(stream, 0);
        }
        self.inner.sessions.rows[index].in_stream = null;
        if (self.inner.sessions.resetRx(index)) self.inner.wakeStorage();
    }

    pub fn resetOutbound(self: *const Driver, engine: *Engine, index: u16) void {
        if (self.inner.sessions.rows[index].outStream()) |stream| {
            std.log.scoped(.network_gossip).debug("gossip_stream_reset direction=outbound connection={d}:{d} stream={d}", .{ stream.conn.index, stream.conn.generation, stream.id });
            engine.closeStream(stream, 0);
            self.inner.sessions.rows[index].retry(self.inner.last_now_ms);
        }
        self.inner.sessions.rows[index].io.resetTx(&self.inner.messages.store);
        self.inner.cancelPromises(index, false);
        self.inner.wakeStorage();
    }

    pub fn replaceInbound(
        self: *const Driver,
        engine: *Engine,
        index: u16,
        stream: StreamHandle,
        version: Version,
    ) void {
        if (self.inner.sessions.rows[index].in_stream) |prior| {
            if (std.meta.eql(prior, stream)) return;
        }
        self.resetInbound(engine, index);
        self.inner.sessions.rows[index].inbound_version = version;
        self.inner.sessions.rows[index].in_stream = stream;
        self.inner.sessions.rows[index].io.rx_ready = true;
    }

    pub fn replaceOutbound(
        self: *const Driver,
        engine: *Engine,
        index: u16,
        stream: StreamHandle,
        version: Version,
    ) void {
        if (self.inner.sessions.rows[index].outStream()) |prior| {
            if (std.meta.eql(prior, stream)) return;
        }
        self.resetOutbound(engine, index);
        self.inner.sessions.setVersion(index, version);
        self.inner.sessions.rows[index].outbound = .{ .live = stream };
        self.inner.sessions.rows[index].failures = 0;
        self.inner.sendSubscriptions(index);
    }

    pub fn retirePeer(self: *const Driver, router: *routing.Router, engine: *Engine, index: u16) void {
        const peer = &self.inner.sessions.rows[index];
        if (peer.outbound == .negotiating) {
            const stream = peer.outbound.negotiating;
            std.log.scoped(.network_gossip).debug("gossip_negotiation_cancelled connection={d}:{d} stream={d} reason=peer_retired", .{ stream.conn.index, stream.conn.generation, stream.id });
            router.cancel(engine, stream);
            peer.outbound = .{ .waiting = 0 };
        }
        self.resetInbound(engine, index);
        self.resetOutbound(engine, index);
        self.inner.connectionClosed(peer.conn);
    }

    fn readPeer(self: *const Driver, engine: *Engine, index: u16, io: *PeerIo, now: Now, events: []Event, start: usize) usize {
        var count = start;
        const stream = self.inner.sessions.rows[index].in_stream orelse return count;
        var input: usize = self.inner.options.input_per_peer;
        var items: usize = self.inner.options.items_per_peer;
        io.rx_ready = true;
        io.blocked = .none;
        // A turn consumes at least one item, byte, or transport-call credit per iteration.
        for (0..self.inner.options.items_per_peer + self.inner.options.calls_per_peer + self.inner.options.input_per_peer + 1) |_| {
            if (io.rpc != null) {
                const done = self.processRpc(index, now, events, &count, &items) catch {
                    const conn = self.inner.sessions.rows[index].conn;
                    std.log.scoped(.network_gossip).debug("gossip_rpc_refused connection={d}:{d} reason=malformed", .{ conn.index, conn.generation });
                    self.inner.counters.malformed_rpcs += 1;
                    self.resetInbound(engine, index);
                    return count;
                };
                if (!done) return count;
                io.rpc = null;
                io.frame_since = null;
                io.pressure_since = null;
                if (self.inner.sessions.releaseFrame(io)) self.inner.wakeStorage();
            }
            if (io.unread_start < io.unread_end) {
                if (input == 0 or self.inner.budget.input == 0) return count;
                const body = self.inner.sessions.frameBody(io) orelse {
                    self.inner.pressure(index, .storage, now.mono_ms);
                    return count;
                };
                const take = @min(io.unread_end - io.unread_start, input, self.inner.budget.input);
                const result = io.feedUnread(body, take, now.mono_ms) catch {
                    self.inner.counters.malformed_rpcs += 1;
                    self.resetInbound(engine, index);
                    return count;
                };
                input -= result.consumed;
                self.inner.budget.input -= result.consumed;
                self.inner.rpc_metrics.received_bytes +|= result.consumed;
                if (result.complete) self.inner.counters.rpcs_received += 1;
                continue;
            }
            io.unread_start = 0;
            io.unread_end = 0;
            if (io.fin_seen) {
                self.resetInbound(engine, index);
                return count;
            }
            if (io.calls_pump == 0 or self.inner.budget.calls == 0 or input == 0 or self.inner.budget.input == 0) return count;
            io.calls_pump -= 1;
            io.write_first = true;
            self.inner.budget.calls -= 1;
            const read = engine.read(stream, io.unread[0..@min(io.unread.len, input, self.inner.budget.input)]) catch |err| {
                io.rx_ready = false;
                if (err != error.WouldBlock) self.resetInbound(engine, index);
                return count;
            };
            io.unread_end = read.len;
            io.fin_seen = read.fin;
            if (read.len == 0 and !read.fin) {
                io.rx_ready = false;
                return count;
            }
        }
        return count;
    }

    fn flush(self: *const Driver, engine: *Engine, index: u16, io: *PeerIo, now: Now) void {
        const stream = self.inner.sessions.rows[index].outStream() orelse return;
        var bytes = self.inner.options.output_per_peer;
        for (0..self.inner.options.calls_per_peer) |_| {
            self.inner.queueSubscriptions(io);
            const segment = io.segment(&self.inner.messages.store);
            if (segment.len == 0) {
                io.tx_ready = false;
                io.tx_progress_ms = null;
                return;
            }
            if (bytes == 0 or self.inner.budget.output == 0 or io.calls_pump == 0 or self.inner.budget.calls == 0) return;
            const take = @min(bytes, self.inner.budget.output, segment.len);
            io.calls_pump -= 1;
            io.write_first = false;
            self.inner.budget.calls -= 1;
            if (io.tx_progress_ms == null) io.tx_progress_ms = now.mono_ms;
            const written = engine.write(stream, segment[0..take], false) catch |err| {
                io.tx_ready = false;
                if (err != error.WouldBlock) {
                    std.log.scoped(.network_gossip_errors).debug("gossip_write_failed connection={d}:{d} stream={d} reason={s} queued={d} bytes={d}", .{ stream.conn.index, stream.conn.generation, stream.id, @errorName(err), io.data_count, io.data_bytes });
                    self.resetOutbound(engine, index);
                }
                return;
            };
            if (written == 0) {
                io.tx_ready = false;
                return;
            }
            bytes -= written;
            self.inner.budget.output -= written;
            io.tx_progress_ms = now.mono_ms;
            const free = self.inner.messages.store.free_pages;
            self.inner.rpc_metrics.sent_bytes +|= written;
            if (io.advance(&self.inner.messages.store, written)) |completion| self.inner.writeCompleted(self.inner.sessions.ref(index), completion, now.mono_ms);
            if (self.inner.messages.store.free_pages != free) self.inner.wakeStorage();
        }
    }

    fn logSendPressure(self: *const Driver, index: u16, now_ms: u64) void {
        const io = &self.inner.sessions.rows[index].io;
        if (!io.pressure_pending or now_ms < io.pressure_log_due_ms) return;
        io.pressure_pending = false;
        io.pressure_log_due_ms = now_ms +| 1_000;
        const row = &self.inner.sessions.rows[index];
        const identity = &self.inner.peers.rows[row.logical.index].identity;
        std.log.scoped(.network_gossip_errors).debug("gossip_send_pressure peer={f} connection={d}:{d} reason={s} total={d} data_queued={d}/{d} data_bytes={d}/{d} control_frames={d} control_bytes={d} oldest_ms={d}", .{ @import("../logging.zig").peer(identity), row.conn.index, row.conn.generation, @tagName(io.last_drop), io.drops[@intFromEnum(io.last_drop)], io.data_count, peer_io_mod.data_capacity, io.data_bytes, self.inner.options.tx_peer_bytes, io.control.count, io.control.used, if (io.oldestTx()) |oldest| now_ms -| oldest else 0 });
    }

    fn logIoTimeout(self: *const Driver, index: u16, reason: []const u8, now_ms: u64) void {
        const row = &self.inner.sessions.rows[index];
        const io = &self.inner.sessions.rows[index].io;
        const identity = &self.inner.peers.rows[row.logical.index].identity;
        std.log.scoped(.network_gossip_errors).debug("gossip_io_timeout peer={f} connection={d}:{d} reason={s} inbound={any} outbound={any} blocked={s} subscriptions={d} data_queued={d} data_bytes={d} control_bytes={d} critical_bytes={d} oldest_ms={d}", .{ @import("../logging.zig").peer(identity), row.conn.index, row.conn.generation, reason, row.in_stream != null, row.outStream() != null, @tagName(io.blocked), io.subscription_dirty.count(), io.data_count, io.data_bytes, io.control.used, io.critical.used, if (io.oldestTx()) |oldest| now_ms -| oldest else 0 });
    }

    pub fn pumpReady(self: *const Driver, router: *routing.Router, engine: *Engine, now: Now, events: []Event) usize {
        self.inner.beginPump(now);
        self.expireIo(router, engine, now.mono_ms);
        self.inner.overlay.expireActions(now.mono_ms, self.inner.options.pressure_timeout_ms);
        var retired = self.inner.overlay.retire.iterator(.{});
        while (retired.next()) |index| {
            const peer: u16 = @intCast(index);
            self.retirePeer(router, engine, peer);
        }
        self.inner.tick(now);
        var count: usize = 0;
        var serviced: usize = 0;
        var first_serviced: ?usize = null;
        for (0..self.inner.sessions.rows.len) |_| {
            const index = self.inner.sessions.cursor;
            self.inner.sessions.cursor = (index + 1) % self.inner.sessions.rows.len;
            if (!self.inner.sessions.rows[index].active) continue;
            if (first_serviced == null) first_serviced = index;
            const io = &self.inner.sessions.rows[index].io;
            io.decompressed_pump = 0;
            io.fields_pump = 0;
            io.calls_pump = self.inner.options.calls_per_peer;
            const write_first = io.write_first;
            if (write_first and io.tx_ready) self.flush(engine, @intCast(index), io, now);
            if (io.rx_ready or (io.blocked == .events and count < events.len)) {
                count = self.readPeer(engine, @intCast(index), io, now, events, count);
            }
            if (!write_first and io.tx_ready) self.flush(engine, @intCast(index), io, now);
            self.logSendPressure(@intCast(index), now.mono_ms);
            serviced += 1;
            if (serviced == self.inner.options.peers_per_pump) break;
        }
        if (serviced < self.inner.options.peers_per_pump) {
            if (first_serviced) |first| self.inner.sessions.cursor = (first + 1) % self.inner.sessions.rows.len;
        }
        self.inner.finishPump(now);
        return count;
    }

    pub fn processRpc(self: *const Driver, index: u16, now: Now, events: []Event, count: *usize, items: *usize) protobuf.Error!bool {
        const io = &self.inner.sessions.rows[index].io;
        if (self.inner.ignoreRpc(index, now)) return true;
        for (0..self.inner.options.items_per_peer) |_| {
            if (items.* == 0 or self.inner.budget.items == 0) return false;
            items.* -= 1;
            self.inner.budget.items -= 1;
            if (io.item == null) {
                const available = @min(self.inner.budget.fields, self.inner.options.fields_per_peer - io.fields_pump);
                var fields = available;
                const step = try io.rpc.?.step(&fields);
                self.inner.budget.fields -= available - fields;
                io.fields_pump += available - fields;
                switch (step) {
                    .item => |item| {
                        io.item = item;
                        self.inner.rpc_metrics.observeItem(item, &io.rpc_had_control);
                        if (item == .message) self.inner.topic_metrics.get(item.message.topic).prevalidation +|= 1;
                    },
                    .end => return true,
                    .deferred => return false,
                    .skipped => continue,
                }
            }
            if (!self.inner.receiveItem(self.inner.sessions.ref(index), io.item.?, now, events, count)) return false;
            io.item = null;
            io.pressure_since = null;
        }
        return false;
    }

    pub fn nextIoWakeup(self: *const Driver, now: Now, event_capacity: usize) ?u64 {
        var deadline = self.inner.nextWakeup(now);
        for (self.inner.sessions.rows, 0..) |*peer, i| {
            const io = &peer.io;
            if (!self.inner.sessions.rows[i].active) continue;
            if (self.inner.sessions.rows[i].in_stream != null and
                ((io.rx_ready and io.blocked != .events) or (io.blocked == .events and event_capacity > 0))) return now.mono_ms;
            if (self.inner.sessions.rows[i].outStream() != null and io.tx_ready and
                (io.pending() or io.subscription_dirty.count() > 0)) return now.mono_ms;
            if (io.deadlines(&self.inner.options).next()) |due| deadline = @min(deadline, due);
        }
        return @max(now.mono_ms, deadline);
    }

    fn expireIo(self: *const Driver, router: *routing.Router, engine: *Engine, now_ms: u64) void {
        const g = self.inner;
        for (g.sessions.rows, 0..) |*peer, index| {
            if (!peer.active) continue;
            const io = &peer.io;
            for (0..3) |_| {
                const reason = io.deadlines(&g.options).expired(now_ms) orelse break;
                self.logIoTimeout(@intCast(index), @tagName(reason), now_ms);
                switch (reason) {
                    .subscriptions => {
                        g.counters.local_pressure_resets += 1;
                        g.counters.subscription_timeouts += 1;
                        self.retirePeer(router, engine, @intCast(index));
                        break;
                    },
                    .receive_pressure => {
                        g.counters.local_pressure_resets += 1;
                        g.counters.receive_pressure_timeouts += 1;
                        self.resetInbound(engine, @intCast(index));
                    },
                    .receive_frame => {
                        if (io.pressure_since != null) g.counters.local_pressure_resets += 1 else g.counters.large_stalled += 1;
                        g.counters.receive_frame_timeouts += 1;
                        self.resetInbound(engine, @intCast(index));
                    },
                    .send_queue, .send_progress => {
                        g.counters.tx_stalled += 1;
                        if (reason == .send_queue) g.counters.send_queue_timeouts += 1 else g.counters.send_progress_timeouts += 1;
                        self.resetOutbound(engine, @intCast(index));
                    },
                }
            }
        }
    }

    pub const Admission = enum { admitted, duplicate, capacity, unauthenticated };
};
