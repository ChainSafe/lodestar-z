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

const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const TransportEvent = engine_mod.Event;
const Now = types.Now;
const Gossipsub = gossipsub_mod.Gossipsub;
const Event = gossipsub_mod.Event;
const Turn = @import("turn.zig").Turn;
const Credits = @import("turn.zig").Credits;
const Progress = @import("turn.zig").Progress;

pub const openings_per_pump: usize = 16;
pub const direct_retry_delay_ms: u64 = 30_000;

pub fn shutdown(self: *Gossipsub, router: *routing.Router, engine: *Engine) void {
    for (self.sessions.rows, 0..) |*peer, index| {
        if (peer.active) retirePeer(self, router, engine, @intCast(index));
    }
}

pub fn admitted(self: *Gossipsub, conn: Handle) bool {
    return self.sessions.findPeer(conn) != null;
}

pub const Delivery = enum { unavailable, pending, available };

pub fn deliveryStatus(self: *Gossipsub, conn: Handle) Delivery {
    const index = self.sessions.findPeer(conn) orelse return .unavailable;
    return switch (self.sessions.rows[index].outbound) {
        .none, .closing => .unavailable,
        .pending, .retry_at, .negotiating => .pending,
        .live => .available,
    };
}

pub fn deliveryAvailable(self: *Gossipsub, conn: Handle) bool {
    return deliveryStatus(self, conn) == .available;
}

pub fn peerConnected(self: *Gossipsub, engine: *Engine, conn: Handle, now: Now) Admission {
    if (self.sessions.findPeer(conn) != null) return .admitted;
    const identity = engine.peerId(conn) orelse return .unauthenticated;
    const address = engine.peerAddress(conn) orelse return .unauthenticated;
    const direction = engine.direction(conn) orelse return .unauthenticated;
    const result = self.addPeer(conn, &.{ .identity = identity, .address = address, .direction = direction }, now);
    switch (result) {
        .admitted => {},
        .duplicate => return .duplicate,
        .capacity => return .capacity,
    }
    return .admitted;
}

pub fn transportEvents(
    self: *Gossipsub,
    router: *routing.Router,
    engine: *Engine,
    events: []const TransportEvent,
    now: Now,
) void {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    for (events) |event| switch (event) {
        .connected => |connected| {
            _ = peerConnected(self, engine, connected.conn, now);
        },
        .path_changed => |changed| self.peers.migrate(changed.conn, changed.peer),
        .stream_closed => |closed| streamClosed(self, engine, closed.stream),
        .closed => |closed| retireConnection(self, router, engine, closed.conn, now),
        else => {},
    };
}

pub fn retireConnection(self: *Gossipsub, router: *routing.Router, engine: *Engine, conn: Handle, now: Now) void {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    const index = self.sessions.findPeer(conn) orelse return;
    retirePeer(self, router, engine, index);
}

pub fn negotiationResult(
    self: *Gossipsub,
    engine: *Engine,
    outcome: routing.Outcome,
    now: Now,
) void {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    const index = self.sessions.findPeer(outcome.stream.conn) orelse {
        engine.closeStream(outcome.stream, 0);
        return;
    };
    const session = &self.sessions.rows[index];
    if (session.outbound == .closing) {
        engine.closeStream(outcome.stream, 0);
        return;
    }
    if (outcome.direction == .outbound) {
        const pending = switch (session.outbound) {
            .negotiating => |stream| stream,
            else => return,
        };
        if (!std.meta.eql(pending, outcome.stream)) return;
    }
    switch (outcome.result) {
        .ready => self.counters.negotiation_ready += 1,
        .rejected => self.counters.negotiation_rejected += 1,
        .failed => self.counters.negotiation_failed += 1,
    }
    if (outcome.result != .ready) std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_failed connection={d}:{d} stream={d} direction={s} reason={s}", .{ outcome.stream.conn.index, outcome.stream.conn.generation, outcome.stream.id, @tagName(outcome.direction), if (outcome.result == .failed) @tagName(outcome.result.failed) else "rejected" });
    if (outcome.direction == .outbound) {
        switch (outcome.result) {
            .ready => |selection| {
                if (selection.leftover.len != 0) {
                    std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_leftover connection={d}:{d} stream={d} bytes={d} fin={any}", .{ outcome.stream.conn.index, outcome.stream.conn.generation, outcome.stream.id, selection.leftover.len, selection.fin });
                    engine.closeStream(outcome.stream, 0);
                    resetOutbound(self, engine, index);
                    return;
                }
                replaceOutbound(
                    self,
                    engine,
                    index,
                    outcome.stream,
                    selection.protocol.meshsub,
                );
            },
            else => resetOutbound(self, engine, index),
        }
    } else switch (outcome.result) {
        .ready => |selection| {
            replaceInbound(
                self,
                engine,
                index,
                outcome.stream,
            );
            if (!self.sessions.receiveHandoff(index, selection.leftover, selection.fin)) {
                resetInbound(self, engine, index);
            }
        },
        else => {},
    }
}

pub fn connectionActivity(self: *Gossipsub, conn: Handle) void {
    self.sessions.connectionActivity(conn);
}

pub fn nextWakeup(self: *Gossipsub, now: Now, event_capacity: usize) ?u64 {
    const next = nextIoWakeup(self, now, event_capacity);
    for (self.sessions.rows) |*session| {
        if (!session.active) continue;
        if (session.needs_service or session.outbound == .pending or session.outbound == .closing) return now.mono_ms;
    }
    return next;
}

pub fn pump(
    self: *Gossipsub,
    router: *routing.Router,
    engine: *Engine,
    now: Now,
    out: []Event,
) usize {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    var openings: usize = 0;
    var examined: usize = 0;
    for (0..self.sessions.rows.len) |_| {
        if (examined == 32) break;
        const index: u16 = @intCast(self.open_cursor);
        self.open_cursor = (self.open_cursor + 1) % self.sessions.rows.len;
        const session = &self.sessions.rows[index];
        if (!session.active) continue;
        session.needs_service = false;
        examined += 1;
        if (session.outbound == .retry_at and now.mono_ms >= session.outbound.retry_at) {
            self.sessions.setOutbound(index, if (self.peers.rows[session.logical.index].direct) .pending else .none);
        }
        switch (session.outbound) {
            .live => |live| {
                // Observe idle STOP_SENDING without a write or a host-work hint.
                _ = engine.streamCapacity(live.stream) catch {
                    resetOutbound(self, engine, index);
                    continue;
                };
            },
            .pending => {
                openOutbound(self, router, engine, index, now);
                openings += 1;
                if (openings == openings_per_pump) break;
            },
            .closing => retirePeer(self, router, engine, index),
            .none, .retry_at, .negotiating => {},
        }
    }
    return pumpReady(self, router, engine, now, out);
}

fn openOutbound(
    self: *Gossipsub,
    router: *routing.Router,
    engine: *Engine,
    index: u16,
    now: Now,
) void {
    const conn = self.sessions.rows[index].conn;
    const stream = router.beginMeshsub(engine, conn, now) catch |err| {
        self.counters.negotiation_refused += 1;
        std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_refused connection={d}:{d} reason={s}", .{ conn.index, conn.generation, @errorName(err) });
        resetOutbound(self, engine, index);
        return;
    };
    self.counters.negotiation_started += 1;
    self.sessions.setOutbound(index, .{ .negotiating = stream });
}

fn streamClosed(self: *Gossipsub, engine: *Engine, stream: StreamHandle) void {
    const index = self.sessions.findPeer(stream.conn) orelse return;
    const session = &self.sessions.rows[index];
    switch (session.outbound) {
        .live => |live| if (std.meta.eql(live.stream, stream)) {
            resetOutbound(self, engine, index);
        },
        .negotiating => |pending| if (std.meta.eql(pending, stream)) resetOutbound(self, engine, index),
        .none, .pending, .retry_at, .closing => {},
    }
    // Read-side FIN can be reported with buffered payload. The framing owner
    // drains it before resetting; a reset is observed by its next read.
}

pub fn resetInbound(self: *Gossipsub, engine: *Engine, index: u16) void {
    if (self.sessions.rows[index].in_stream) |stream| {
        std.log.scoped(.network_gossip).debug("gossip_stream_reset direction=inbound connection={d}:{d} stream={d} blocked={s}", .{ stream.conn.index, stream.conn.generation, stream.id, @tagName(self.sessions.rows[index].io.blocked) });
        engine.closeStream(stream, 0);
    }
    self.sessions.rows[index].in_stream = null;
    _ = self.sessions.resetRx(index);
}

pub fn resetOutbound(self: *Gossipsub, engine: *Engine, index: u16) void {
    if (self.sessions.rows[index].outStream()) |stream| {
        std.log.scoped(.network_gossip).debug("gossip_stream_reset direction=outbound connection={d}:{d} stream={d}", .{ stream.conn.index, stream.conn.generation, stream.id });
        engine.closeStream(stream, 0);
    }
    self.sessions.setOutbound(index, .none);
    self.cancelWrites(self.sessions.ref(index));
}

fn replaceInbound(
    self: *Gossipsub,
    engine: *Engine,
    index: u16,
    stream: StreamHandle,
) void {
    if (self.sessions.rows[index].in_stream) |prior| {
        if (std.meta.eql(prior, stream)) return;
    }
    resetInbound(self, engine, index);
    self.sessions.rows[index].in_stream = stream;
    self.sessions.rows[index].io.rx_ready = true;
    if (self.sessions.rows[index].outbound == .none) self.sessions.setOutbound(index, .pending);
}

fn replaceOutbound(
    self: *Gossipsub,
    engine: *Engine,
    index: u16,
    stream: StreamHandle,
    version: Version,
) void {
    if (self.sessions.rows[index].outStream()) |prior| {
        if (std.meta.eql(prior, stream)) return;
    }
    if (self.sessions.rows[index].outStream()) |prior| engine.closeStream(prior, 0);
    self.cancelWrites(self.sessions.ref(index));
    self.sessions.setOutbound(index, .{ .live = .{ .stream = stream, .version = version } });
    self.sendSubscriptions(index);
}

pub fn retirePeer(self: *Gossipsub, router: *routing.Router, engine: *Engine, index: u16) void {
    const peer = &self.sessions.rows[index];
    if (peer.outbound == .closing) std.log.scoped(.network_gossip_errors).debug("gossip_relationship_closed connection={d}:{d} reason={s} critical_frames={d} critical_bytes={d}", .{ peer.conn.index, peer.conn.generation, @tagName(peer.io.tx.last_drop), peer.io.tx.critical.count, peer.io.tx.critical.used });
    if (peer.outbound == .negotiating) {
        const stream = peer.outbound.negotiating;
        std.log.scoped(.network_gossip).debug("gossip_negotiation_cancelled connection={d}:{d} stream={d} reason=peer_retired", .{ stream.conn.index, stream.conn.generation, stream.id });
        router.cancel(engine, stream);
        self.sessions.setOutbound(index, .none);
    }
    if (peer.in_stream) |stream| engine.closeStream(stream, 0);
    switch (peer.outbound) {
        .live => |live| engine.closeStream(live.stream, 0),
        .closing => |stream| engine.closeStream(stream, 0),
        else => {},
    }
    self.connectionClosed(peer.conn);
}

fn readPeer(self: *Gossipsub, engine: *Engine, index: u16, io: *PeerIo, turn: *Turn, peer: *Credits) void {
    const now = turn.now;
    const stream = self.sessions.rows[index].in_stream orelse return;
    io.rx_ready = true;
    io.blocked = .none;
    // A turn consumes at least one item, byte, or transport-call credit per iteration.
    for (0..self.options.items_per_peer + self.options.calls_per_peer + self.options.input_per_peer + 1) |_| {
        if (io.rpc != null) {
            const done = processRpc(self, index, turn, peer) catch {
                const conn = self.sessions.rows[index].conn;
                std.log.scoped(.network_gossip).debug("gossip_rpc_refused connection={d}:{d} reason=malformed", .{ conn.index, conn.generation });
                self.counters.malformed_rpcs += 1;
                resetInbound(self, engine, index);
                return;
            };
            if (done != .done) return;
            _ = self.sessions.finishFrame(io);
        }
        if (io.unread_start < io.unread_end) {
            if (peer.input == 0 or turn.budget.input == 0) return;
            const logical = self.sessions.rows[index].logical;
            if ((io.reader.declaredLen() orelse 0) > io.body.len and
                now.mono_ms < self.peers.rows[logical.index].large_frame_denied_until)
            {
                resetInbound(self, engine, index);
                return;
            }
            const take = @min(io.unread_end - io.unread_start, peer.input, turn.budget.input);
            const result = io.feedUnread(&self.sessions.receive_pool, take, now.mono_ms) catch |err| {
                if (err == error.ReceiveCapacity) {
                    self.counters.receive_capacity_refusals += 1;
                    self.counters.local_pressure_resets += 1;
                    self.cancelPromises(index, true);
                } else self.counters.malformed_rpcs += 1;
                resetInbound(self, engine, index);
                return;
            };
            peer.input -= result.consumed;
            turn.budget.input -= result.consumed;
            self.rpc_metrics.received_bytes +|= result.consumed;
            if (result.complete) self.counters.rpcs_received += 1;
            continue;
        }
        io.unread_start = 0;
        io.unread_end = 0;
        if (io.fin_seen) {
            resetInbound(self, engine, index);
            return;
        }
        if (peer.calls == 0 or turn.budget.calls == 0 or peer.input == 0 or turn.budget.input == 0) return;
        peer.calls -= 1;
        io.write_first = true;
        turn.budget.calls -= 1;
        const read = engine.read(stream, io.unread[0..@min(io.unread.len, peer.input, turn.budget.input)]) catch |err| {
            io.rx_ready = false;
            if (err != error.WouldBlock) resetInbound(self, engine, index);
            return;
        };
        io.unread_end = read.len;
        io.fin_seen = read.fin;
        if (read.len == 0 and !read.fin) {
            io.rx_ready = false;
            return;
        }
    }
    return;
}

fn flush(self: *Gossipsub, engine: *Engine, index: u16, io: *PeerIo, turn: *Turn, peer: *Credits) void {
    const now = turn.now;
    const stream = self.sessions.rows[index].outStream() orelse return;
    for (0..self.options.calls_per_peer) |_| {
        const segment = self.writeSegment(self.sessions.ref(index));
        if (segment.len == 0) {
            io.tx.ready = false;
            io.tx.progress_ms = null;
            return;
        }
        if (peer.output == 0 or turn.budget.output == 0 or peer.calls == 0 or turn.budget.calls == 0) return;
        const take = @min(peer.output, turn.budget.output, segment.len);
        peer.calls -= 1;
        io.write_first = false;
        turn.budget.calls -= 1;
        if (io.tx.progress_ms == null) io.tx.progress_ms = now.mono_ms;
        const written = engine.write(stream, segment[0..take], false) catch |err| {
            io.tx.ready = false;
            if (err != error.WouldBlock) {
                std.log.scoped(.network_gossip_errors).debug("gossip_write_failed connection={d}:{d} stream={d} reason={s} queued={d} bytes={d}", .{ stream.conn.index, stream.conn.generation, stream.id, @errorName(err), io.tx.data.count, io.tx.data.bytes });
                resetOutbound(self, engine, index);
            }
            return;
        };
        if (written == 0) {
            io.tx.ready = false;
            return;
        }
        peer.output -= written;
        turn.budget.output -= written;
        io.tx.progress_ms = now.mono_ms;
        self.advanceWrite(self.sessions.ref(index), written, now.mono_ms);
    }
}

fn logSendPressure(self: *Gossipsub, index: u16, now_ms: u64) void {
    const io = &self.sessions.rows[index].io;
    if (!io.tx.pressure_pending or now_ms < io.tx.pressure_log_due_ms) return;
    io.tx.pressure_pending = false;
    io.tx.pressure_log_due_ms = now_ms +| 1_000;
    const row = &self.sessions.rows[index];
    const identity = &self.peers.rows[row.logical.index].identity;
    std.log.scoped(.network_gossip_errors).debug("gossip_send_pressure peer={f} connection={d}:{d} reason={s} total={d} data_queued={d}/{d} data_bytes={d}/{d} control_frames={d} control_bytes={d} oldest_ms={d}", .{ @import("../logging.zig").peer(identity), row.conn.index, row.conn.generation, @tagName(io.tx.last_drop), io.tx.drops[@intFromEnum(io.tx.last_drop)], io.tx.data.count, @import("outbox.zig").data_capacity, io.tx.data.bytes, self.options.tx_peer_bytes, io.tx.control.count, io.tx.control.used, if (io.tx.oldest()) |oldest| now_ms -| oldest else 0 });
}

fn logIoTimeout(self: *Gossipsub, index: u16, reason: []const u8, now_ms: u64) void {
    const row = &self.sessions.rows[index];
    const io = &self.sessions.rows[index].io;
    const identity = &self.peers.rows[row.logical.index].identity;
    std.log.scoped(.network_gossip_errors).debug("gossip_io_timeout peer={f} connection={d}:{d} reason={s} inbound={any} outbound={any} blocked={s} subscriptions={d} data_queued={d} data_bytes={d} control_bytes={d} critical_bytes={d} oldest_ms={d}", .{ @import("../logging.zig").peer(identity), row.conn.index, row.conn.generation, reason, row.in_stream != null, row.outStream() != null, @tagName(io.blocked), io.tx.subscription_dirty.count(), io.tx.data.count, io.tx.data.bytes, io.tx.control.used, io.tx.critical.used, if (io.tx.oldest()) |oldest| now_ms -| oldest else 0 });
}

fn pumpReady(self: *Gossipsub, router: *routing.Router, engine: *Engine, now: Now, events: []Event) usize {
    var turn = beginPump(self, now, events);
    runTurn(self, router, engine, &turn);
    return turn.count;
}

pub fn runTurn(self: *Gossipsub, router: *routing.Router, engine: *Engine, turn: *Turn) void {
    const now = turn.now;
    expireIo(self, router, engine, now.mono_ms);
    self.tick(now);
    var serviced: usize = 0;
    var first_serviced: ?usize = null;
    for (0..self.sessions.rows.len) |_| {
        const index = self.sessions.cursor;
        self.sessions.cursor = (index + 1) % self.sessions.rows.len;
        if (!self.sessions.rows[index].active) continue;
        if (self.sessions.rows[index].outbound == .closing) {
            logSendPressure(self, @intCast(index), now.mono_ms);
            retirePeer(self, router, engine, @intCast(index));
            continue;
        }
        if (first_serviced == null) first_serviced = index;
        const io = &self.sessions.rows[index].io;
        var peer = Credits.peer(&self.options);
        const write_first = io.write_first;
        if (write_first and io.tx.ready) flush(self, engine, @intCast(index), io, turn, &peer);
        if (io.rx_ready or (io.blocked == .events and turn.count < turn.events.len)) {
            readPeer(self, engine, @intCast(index), io, turn, &peer);
        }
        if (!write_first and io.tx.ready) flush(self, engine, @intCast(index), io, turn, &peer);
        logSendPressure(self, @intCast(index), now.mono_ms);
        if (self.sessions.rows[index].outbound == .closing) retirePeer(self, router, engine, @intCast(index));
        serviced += 1;
        if (serviced == self.options.peers_per_pump) break;
    }
    if (serviced < self.options.peers_per_pump) {
        if (first_serviced) |first| self.sessions.cursor = (first + 1) % self.sessions.rows.len;
    }
    finishPump(self, now);
}

pub fn processRpc(self: *Gossipsub, index: u16, turn: *Turn, peer: *Credits) protobuf.Error!Progress {
    const now = turn.now;
    const io = &self.sessions.rows[index].io;
    const rpc = &io.rpc.?;
    if (self.ignoreRpc(index, now)) return .done;
    for (0..self.options.items_per_peer) |_| {
        if (peer.items == 0 or turn.budget.items == 0) return .credits;
        peer.items -= 1;
        turn.budget.items -= 1;
        const pending = rpc.item != null;
        if (rpc.item == null) {
            const available = @min(turn.budget.fields, peer.fields);
            var fields = available;
            const step = try rpc.reader.step(&fields);
            turn.budget.fields -= available - fields;
            peer.fields -= available - fields;
            switch (step) {
                .item => |item| {
                    rpc.item = item;
                },
                .end => return .done,
                .deferred => return .credits,
                .skipped => continue,
            }
        }
        if (!rpc.permitsItem()) {
            rpc.consumeItem();
            continue;
        }
        if (pending) {
            const cost = rpc.item.?.fieldCost();
            if (cost > @min(turn.budget.fields, peer.fields)) return .credits;
            turn.budget.fields -= cost;
            peer.fields -= cost;
        }
        const copy_bytes = rpc.reader.view.copyBytes(rpc.item.?.bytes);
        if (!turn.chargeCopy(peer, &self.options, copy_bytes)) return .credits;
        const item = try rpc.reader.decode(rpc.item.?, self.sessions.decode_scratch);
        self.counters.receive_copy_bytes +|= copy_bytes;
        if (!rpc.item_observed) {
            self.rpc_metrics.observeItem(item, &rpc.had_control);
            if (item == .message) self.topic_metrics.get(item.message.topic).prevalidation +|= 1;
            rpc.item_observed = true;
        }
        const result = self.receiveItem(self.sessions.ref(index), item, turn, peer);
        switch (result) {
            .events => self.pressure(index, .events, now.mono_ms),
            .done, .credits => {},
        }
        if (result != .done) return result;
        rpc.consumeItem();
        io.pressure_since = null;
    }
    return .credits;
}

pub fn nextIoWakeup(self: *Gossipsub, now: Now, event_capacity: usize) ?u64 {
    var deadline = nextMaintenance(self, now);
    for (self.sessions.rows, 0..) |*peer, i| {
        const io = &peer.io;
        if (!self.sessions.rows[i].active) continue;
        if (peer.outbound == .closing) return now.mono_ms;
        if (peer.outbound == .retry_at) deadline = @min(deadline, peer.outbound.retry_at);
        if (self.sessions.rows[i].in_stream != null and
            ((io.rx_ready and io.blocked != .events) or (io.blocked == .events and event_capacity > 0))) return now.mono_ms;
        if (self.sessions.rows[i].outStream() != null and io.tx.ready and
            (io.tx.pending() or io.tx.subscription_dirty.count() > 0)) return now.mono_ms;
        if (io.deadlines(&self.options).next()) |due| deadline = @min(deadline, due);
    }
    return @max(now.mono_ms, deadline);
}

fn expireIo(self: *Gossipsub, router: *routing.Router, engine: *Engine, now_ms: u64) void {
    const g = self;
    for (g.sessions.rows, 0..) |*peer, index| {
        if (!peer.active) continue;
        const io = &peer.io;
        for (0..3) |_| {
            const reason = io.deadlines(&g.options).expired(now_ms) orelse break;
            logIoTimeout(self, @intCast(index), @tagName(reason), now_ms);
            switch (reason) {
                .subscriptions => {
                    g.counters.local_pressure_resets += 1;
                    g.counters.subscription_timeouts += 1;
                    retirePeer(self, router, engine, @intCast(index));
                    break;
                },
                .receive_pressure => {
                    g.counters.local_pressure_resets += 1;
                    g.counters.receive_pressure_timeouts += 1;
                    resetInbound(self, engine, @intCast(index));
                },
                .receive_frame => {
                    if ((io.reader.declaredLen() orelse 0) > io.body.len and io.rpc == null and io.pressure_since == null) {
                        g.peers.penalize(peer.logical, 1);
                        g.peers.rows[peer.logical.index].large_frame_denied_until = now_ms +| g.options.pressure_timeout_ms;
                    }
                    if (io.pressure_since != null or io.rpc != null) {
                        g.counters.local_pressure_resets += 1;
                        g.cancelPromises(@intCast(index), true);
                    } else g.counters.large_stalled += 1;
                    g.counters.receive_frame_timeouts += 1;
                    resetInbound(self, engine, @intCast(index));
                },
                .send_queue, .send_progress => {
                    g.counters.tx_stalled += 1;
                    if (reason == .send_queue) g.counters.send_queue_timeouts += 1 else g.counters.send_progress_timeouts += 1;
                    const retry_direct = peer.outbound == .live and g.peers.rows[peer.logical.index].direct;
                    resetOutbound(self, engine, @intCast(index));
                    if (retry_direct) g.sessions.setOutbound(@intCast(index), .{ .retry_at = now_ms +| direct_retry_delay_ms });
                },
            }
        }
    }
}

pub const Admission = enum { admitted, duplicate, capacity, unauthenticated };

pub fn beginPump(self: *Gossipsub, now: Now, events: []Event) Turn {
    self.last_now_ms = now.mono_ms;
    self.messages.expire(&self.peers, now.mono_ms);
    return Turn.init(&self.options, now, events, self.decompressed, self.msg_scratch);
}

pub fn finishPump(self: *Gossipsub, now: Now) void {
    self.maintainTopics(now);
    self.expirePromises(now.mono_ms);
}

fn nextMaintenance(self: *const Gossipsub, now: Now) u64 {
    if (self.cycle.isActive()) return now.mono_ms;
    var deadline = if (self.heartbeat_at == 0) now.mono_ms else self.heartbeat_at;
    if (self.messages.nextDeadline()) |d| deadline = @min(deadline, d);
    if (self.recovery.nextExpiry()) |expiry| deadline = @min(deadline, expiry);
    return @max(now.mono_ms, deadline);
}
