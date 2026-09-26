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
const index_list = @import("../index_list.zig");
const Gossipsub = gossipsub_mod.Gossipsub;
const Turn = @import("turn.zig").Turn;
const Credits = @import("turn.zig").Credits;
const Progress = @import("turn.zig").Progress;
const Budget = @import("turn.zig").Budget;
const Budgets = @import("turn.zig").Budgets;

pub const openings_per_pump: usize = 16;
pub const direct_retry_delay_ms: u64 = 30_000;

pub fn shutdown(self: *Gossipsub, router: *routing.Router, engine: *Engine) void {
    for (self.sessions.rows, 0..) |*peer, index| {
        if (peer.active) retirePeer(self, router, engine, @intCast(index));
    }
}

pub fn admitted(self: *Gossipsub, conn: Handle) bool {
    return self.sessions.find(conn) != null;
}

pub const Delivery = enum { unavailable, pending, available };

pub fn deliveryStatus(self: *Gossipsub, conn: Handle) Delivery {
    const index = self.sessions.find(conn) orelse return .unavailable;
    return switch (self.sessions.rows[index].outbound) {
        .none, .closing => .unavailable,
        .pending, .retry_at, .negotiating => .pending,
        .live => .available,
    };
}

pub fn deliveryAvailable(self: *Gossipsub, conn: Handle) bool {
    return deliveryStatus(self, conn) == .available;
}

pub fn peerConnected(self: *Gossipsub, engine: *Engine, conn: Handle, direct: bool, now: Now) Admission {
    if (self.sessions.find(conn) != null) return .admitted;
    const identity = engine.peerId(conn) orelse return .unauthenticated;
    const address = engine.peerAddress(conn) orelse return .unauthenticated;
    const direction = engine.direction(conn) orelse return .unauthenticated;
    const result = self.addPeer(conn, &.{ .identity = identity, .address = address, .direction = direction, .direct = direct }, now);
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
            _ = peerConnected(self, engine, connected.conn, false, now);
        },
        .path_changed => |changed| self.peers.migrate(changed.conn, changed.peer),
        .stream_closed => |closed| streamClosed(self, engine, closed.stream),
        .closed => |closed| retireConnection(self, router, engine, closed.conn, now),
        else => {},
    };
}

pub fn retireConnection(self: *Gossipsub, router: *routing.Router, engine: *Engine, conn: Handle, now: Now) void {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    const index = self.sessions.find(conn) orelse return;
    retirePeer(self, router, engine, index);
}

pub fn negotiationResult(
    self: *Gossipsub,
    engine: *Engine,
    outcome: routing.Outcome,
    now: Now,
) void {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    const index = self.sessions.find(outcome.stream.conn) orelse {
        engine.closeStream(outcome.stream, 0);
        return;
    };
    takeNegotiated(self, engine, index, outcome);
    self.settle(index);
}

fn takeNegotiated(self: *Gossipsub, engine: *Engine, index: u16, outcome: routing.Outcome) void {
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

/// A routed stream event. A readable edge on the inbound stream or a writable edge on the out
/// stream marks the session ready; an event for a stream the session no longer holds is dropped.
pub fn streamReady(self: *Gossipsub, engine: *Engine, route: types.Route, stream: StreamHandle, ready: types.Readiness) void {
    if (route.row >= self.sessions.rows.len) return;
    const index: u16 = @intCast(route.row);
    const session = &self.sessions.rows[index];
    if (!session.active) return;
    switch (route.owner) {
        .gossip_inbound => {
            const held = session.in_stream orelse return;
            if (!std.meta.eql(held, stream) or !ready.readable) return;
            session.io.rx_ready = true;
        },
        .gossip_outbound => {
            const held = session.outStream() orelse return;
            if (!std.meta.eql(held, stream) or !ready.writable) return;
            const tx = &session.io.tx;
            tx.writable();
            // With nothing queued, no write armed the edge: the peer stopped the stream.
            if (!tx.pending() and tx.subscription_dirty.count() == 0) {
                _ = engine.streamCapacity(stream) catch resetOutbound(self, engine, index);
            }
        },
        else => return,
    }
    self.settle(index);
}

/// Now when a session is ready; otherwise the earliest session deadline, heartbeat or
/// maintenance deadline. Reads the list length and heap top only.
pub fn nextWakeup(self: *const Gossipsub, now: Now) ?u64 {
    if (self.sessions.ready.len > 0) return now.mono_ms;
    var deadline = nextMaintenance(self, now);
    if (self.sessions.deadlines.peek()) |top| deadline = @min(deadline, top.deadline);
    return @max(now.mono_ms, deadline);
}

pub fn pump(
    self: *Gossipsub,
    router: *routing.Router,
    engine: *Engine,
    now: Now,
) void {
    self.last_now_ms = @max(self.last_now_ms, now.mono_ms);
    var turn = beginPump(self, now);
    runTurn(self, router, engine, &turn);
    if (@import("builtin").is_test) checkRoutes(self, engine);
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
    const index = self.sessions.find(stream.conn) orelse return;
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
        std.log.scoped(.network_gossip).debug("gossip_stream_reset direction=inbound connection={d}:{d} stream={d}", .{ stream.conn.index, stream.conn.generation, stream.id });
        engine.closeStream(stream, 0);
    }
    self.sessions.rows[index].in_stream = null;
    _ = self.sessions.resetRx(index);
    self.settle(index);
}

pub fn resetOutbound(self: *Gossipsub, engine: *Engine, index: u16) void {
    if (self.sessions.rows[index].outStream()) |stream| {
        std.log.scoped(.network_gossip).debug("gossip_stream_reset direction=outbound connection={d}:{d} stream={d}", .{ stream.conn.index, stream.conn.generation, stream.id });
        engine.closeStream(stream, 0);
    }
    self.sessions.setOutbound(index, .none);
    self.cancelWrites(self.sessions.ref(index));
    self.settle(index);
}

/// Takes a negotiated inbound stream. quiche does not announce again the bytes the negotiator
/// left unread, so the session reads it at once.
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
    engine.bindStream(stream, .{ .owner = .gossip_inbound, .row = index }) catch {};
    self.sessions.rows[index].in_stream = stream;
    self.sessions.rows[index].io.rx_ready = true;
    if (self.sessions.rows[index].outbound == .none) self.sessions.setOutbound(index, .pending);
}

/// Takes a negotiated out stream, which takes writes until one blocks.
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
    engine.bindStream(stream, .{ .owner = .gossip_outbound, .row = index }) catch {};
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
    // A turn consumes at least one item, byte, or transport-call credit per iteration.
    for (0..self.options.items_per_peer + self.options.calls_per_peer + self.options.input_per_peer + 1) |_| {
        if (io.rpc != null) {
            const done = processRpc(self, index, turn, peer) catch |err| {
                const conn = self.sessions.rows[index].conn;
                std.log.scoped(.network_gossip).debug("gossip_rpc_refused connection={d}:{d} reason={s}", .{ conn.index, conn.generation, @errorName(err) });
                self.counters.malformed_rpcs += 1;
                self.peers.penalize(self.sessions.rows[index].logical, 1);
                resetInbound(self, engine, index);
                return;
            };
            if (done != .done) return;
            _ = self.sessions.finishFrame(io);
            if (!self.acceptsRpc(index, now)) {
                resetInbound(self, engine, index);
                return;
            }
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
                    discardInboundFrame(self, index);
                    continue;
                } else {
                    self.counters.malformed_rpcs += 1;
                    self.peers.penalize(logical, 1);
                }
                resetInbound(self, engine, index);
                return;
            };
            peer.input -= result.consumed;
            turn.budget.input -= result.consumed;
            self.rpc_metrics.received_bytes +|= result.consumed;
            if (result.complete) {
                if (io.discarding) {
                    _ = self.sessions.finishFrame(io);
                } else self.counters.rpcs_received += 1;
            }
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
        self.io_metrics.read_calls +|= 1;
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

/// Writes queued frames until the queue drains, a budget runs out or a write blocks. A short
/// write blocks too: the engine armed write interest for the rest, and the session waits for
/// its writable event instead of retrying.
fn flush(self: *Gossipsub, engine: *Engine, index: u16, io: *PeerIo, turn: *Turn, peer: *Credits) void {
    const now = turn.now;
    const stream = self.sessions.rows[index].outStream() orelse return;
    for (0..self.options.calls_per_peer) |_| {
        const segment = self.writeSegment(self.sessions.ref(index));
        if (segment.len == 0) {
            io.tx.progress_ms = null;
            return;
        }
        if (peer.output == 0 or turn.budget.output == 0 or peer.calls == 0 or turn.budget.calls == 0) return;
        const take = @min(peer.output, turn.budget.output, segment.len);
        peer.calls -= 1;
        io.write_first = false;
        turn.budget.calls -= 1;
        self.io_metrics.write_calls +|= 1;
        if (io.tx.progress_ms == null) io.tx.progress_ms = now.mono_ms;
        const written = engine.write(stream, segment[0..take], false) catch |err| {
            if (err == error.WouldBlock) {
                self.io_metrics.write_would_block +|= 1;
                io.tx.blocked(now.mono_ms);
            } else {
                std.log.scoped(.network_gossip_errors).debug("gossip_write_failed connection={d}:{d} stream={d} reason={s} queued={d} bytes={d}", .{ stream.conn.index, stream.conn.generation, stream.id, @errorName(err), io.tx.data.count, io.tx.data.bytes });
                resetOutbound(self, engine, index);
            }
            return;
        };
        if (written == 0) {
            self.io_metrics.write_zero +|= 1;
            io.write_zero +|= 1;
            io.tx.blocked(now.mono_ms);
            return;
        }
        peer.output -= written;
        turn.budget.output -= written;
        io.tx.progress_ms = now.mono_ms;
        self.advanceWrite(self.sessions.ref(index), written, now.mono_ms);
        if (written < take) {
            self.io_metrics.write_would_block +|= 1;
            io.tx.blocked(now.mono_ms);
            return;
        }
        io.tx.last_write_blocked = false;
    }
}

fn logSendPressure(self: *Gossipsub, index: u16, now_ms: u64) void {
    const io = &self.sessions.rows[index].io;
    if (!io.tx.pressure_pending or now_ms < io.tx.pressure_log_due_ms) return;
    io.tx.pressure_pending = false;
    io.tx.pressure_log_due_ms = now_ms +| 1_000;
    const row = &self.sessions.rows[index];
    const identity = &self.peers.rows[row.logical.index].identity;
    std.log.scoped(.network_gossip_errors).debug("gossip_send_pressure peer={f} connection={d}:{d} reason={s} total={d} data_queued={d}/{d} data_bytes={d}/{d} control_frames={d} control_bytes={d} oldest_ms={d} write_blocked_ms={d} write_zero={d} budget_deferred={d}", .{ @import("../logging.zig").peer(identity), row.conn.index, row.conn.generation, @tagName(io.tx.last_drop), io.tx.drops[@intFromEnum(io.tx.last_drop)], io.tx.data.count, @import("outbox.zig").data_capacity, io.tx.data.bytes, self.options.tx_peer_bytes, io.tx.control.count, io.tx.control.used, if (io.tx.oldest()) |oldest| now_ms -| oldest else 0, if (io.tx.blocked_since) |since| now_ms -| since else 0, io.write_zero, io.write_budget_deferred });
}

fn logIoTimeout(self: *Gossipsub, index: u16, reason: []const u8, now_ms: u64) void {
    const row = &self.sessions.rows[index];
    const io = &self.sessions.rows[index].io;
    const identity = &self.peers.rows[row.logical.index].identity;
    std.log.scoped(.network_gossip_errors).debug("gossip_io_timeout peer={f} connection={d}:{d} reason={s} inbound={any} outbound={any} subscriptions={d} data_queued={d} data_bytes={d} control_bytes={d} critical_bytes={d} oldest_ms={d}", .{ @import("../logging.zig").peer(identity), row.conn.index, row.conn.generation, reason, row.in_stream != null, row.outStream() != null, io.tx.subscription_dirty.count(), io.tx.data.count, io.tx.data.bytes, io.tx.control.used, io.tx.critical.used, if (io.tx.oldest()) |oldest| now_ms -| oldest else 0 });
}

/// Expires the due session deadlines, runs the heartbeat, then services up to `peers_per_pump`
/// of the sessions that were ready when the turn began, in the order they became ready. A
/// session that still wants service after its turn goes back to the tail; sessions marked
/// during the turn wait for the next one.
pub fn runTurn(self: *Gossipsub, router: *routing.Router, engine: *Engine, turn: *Turn) void {
    const now = turn.now;
    expireDue(self, router, engine, now.mono_ms);
    self.tick(now);
    const marked = @min(self.sessions.ready.len, self.options.peers_per_pump);
    var openings: usize = 0;
    var visited: usize = 0;
    for (0..marked) |_| {
        const index: u16 = @intCast(self.sessions.ready.pop(self.sessions.rows, "ready_link") orelse break);
        visited += 1;
        self.sessions.visits +|= 1;
        serviceSession(self, router, engine, index, turn, &openings);
        self.sessions.serviced(index, &self.options);
        if (turn.exhausted().count() > 0) break;
    }
    const exhausted = turn.exhausted();
    if (exhausted.count() > 0 and visited < marked) stopped(self, stoppingBudget(exhausted), marked - visited);
    var budgets = exhausted.iterator();
    while (budgets.next()) |budget| {
        self.io_metrics.turns_exhausted[@intFromEnum(budget)] +|= 1;
        var next = self.sessions.ready.head;
        for (0..self.sessions.ready.len) |_| {
            if (next == index_list.none) break;
            const row = &self.sessions.rows[next];
            next = row.ready_link.next;
            const writing = row.outStream() != null and row.io.tx.ready and row.io.tx.pending();
            const reading = row.in_stream != null and row.io.rx_ready;
            const ready = switch (budget) {
                .calls => reading or writing,
                .output => writing,
                .input, .items, .fields, .work, .copy => reading,
            };
            if (ready) self.io_metrics.ready_deferred[@intFromEnum(budget)] +|= 1;
            if (writing and (budget == .calls or (budget == .output and !exhausted.contains(.calls)))) row.io.write_budget_deferred +|= 1;
        }
    }
    finishPump(self, now);
    if (@import("builtin").is_test) checkSessions(self);
}

/// The budget a stopped turn is attributed to: calls or output, which writes spend too, before
/// any receive budget, so a receive budget names only stops that left writes unspent.
fn stoppingBudget(exhausted: Budgets) Budget {
    if (exhausted.contains(.calls)) return .calls;
    if (exhausted.contains(.output)) return .output;
    var budgets = exhausted.iterator();
    return budgets.next().?;
}

/// Counts a turn that stopped on `budget` with `skipped` of the sessions it took unvisited, which
/// lead the ready list.
fn stopped(self: *Gossipsub, budget: Budget, skipped: usize) void {
    self.io_metrics.stops[@intFromEnum(budget)] +|= 1;
    var next = self.sessions.ready.head;
    for (0..skipped) |_| {
        if (next == index_list.none) break;
        const index: u16 = @intCast(next);
        next = self.sessions.rows[index].ready_link.next;
        self.io_metrics.skipped[@intFromEnum(budget)][@intFromBool(self.sessions.rows[index].writable())] +|= 1;
    }
}

fn serviceSession(self: *Gossipsub, router: *routing.Router, engine: *Engine, index: u16, turn: *Turn, openings: *usize) void {
    const now = turn.now;
    const session = &self.sessions.rows[index];
    assert(session.active);
    switch (session.outbound) {
        .closing => {
            logSendPressure(self, index, now.mono_ms);
            retirePeer(self, router, engine, index);
            return;
        },
        .pending => if (openings.* < openings_per_pump) {
            openOutbound(self, router, engine, index, now);
            openings.* += 1;
        },
        .none, .retry_at, .negotiating, .live => {},
    }
    if (session.in_stream != null and self.ignoreRpc(index, now)) resetInbound(self, engine, index);
    const io = &session.io;
    var peer = Credits.peer(&self.options);
    const write_first = io.write_first;
    if (write_first and io.tx.ready) flush(self, engine, index, io, turn, &peer);
    if (session.in_stream != null and io.rx_ready) readPeer(self, engine, index, io, turn, &peer);
    if (!write_first and io.tx.ready) flush(self, engine, index, io, turn, &peer);
    logSendPressure(self, index, now.mono_ms);
    if (session.active and session.outbound == .closing) retirePeer(self, router, engine, index);
}

pub fn processRpc(self: *Gossipsub, index: u16, turn: *Turn, peer: *Credits) protobuf.Error!Progress {
    const now = turn.now;
    const io = &self.sessions.rows[index].io;
    const rpc = &io.rpc.?;
    for (0..self.options.items_per_peer) |_| {
        if (self.ignoreRpc(index, now)) return .done;
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
                .deferred => {
                    if (turn.budget.fields <= peer.fields) turn.deferred.insert(.fields);
                    return .credits;
                },
                .skipped => continue,
            }
        }
        if (pending) {
            const cost = rpc.item.?.fieldCost();
            if (cost > @min(turn.budget.fields, peer.fields)) {
                if (cost > turn.budget.fields) turn.deferred.insert(.fields);
                return .credits;
            }
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
        if (result != .done) return result;
        rpc.consumeItem();
    }
    return .credits;
}

fn discardInboundFrame(self: *Gossipsub, index: u16) void {
    self.counters.local_pressure_discards += 1;
    self.cancelPromises(index, true);
    self.sessions.discardFrame(&self.sessions.rows[index].io);
}

/// Pops the sessions whose earliest deadline passed. Handling an expiry clears it or retires the
/// session, so a key set here lies in the future and each session is popped at most once.
fn expireDue(self: *Gossipsub, router: *routing.Router, engine: *Engine, now_ms: u64) void {
    for (0..self.sessions.deadlines.len) |_| {
        const index: u16 = @intCast(self.sessions.deadlines.popDue(now_ms) orelse break);
        self.sessions.visits +|= 1;
        expireSession(self, router, engine, index, now_ms);
        self.settle(index);
    }
}

fn expireSession(self: *Gossipsub, router: *routing.Router, engine: *Engine, index: u16, now_ms: u64) void {
    const g = self;
    const peer = &g.sessions.rows[index];
    assert(peer.active);
    if (peer.outbound == .retry_at and now_ms >= peer.outbound.retry_at) {
        g.sessions.setOutbound(index, if (g.peers.rows[peer.logical.index].direct) .pending else .none);
    }
    const io = &peer.io;
    for (0..3) |_| {
        const reason = io.deadlines(&g.options).expired(now_ms) orelse break;
        logIoTimeout(self, index, @tagName(reason), now_ms);
        switch (reason) {
            .subscriptions => {
                g.counters.local_pressure_resets += 1;
                g.counters.subscription_timeouts += 1;
                retirePeer(self, router, engine, index);
                break;
            },
            .receive_frame => {
                g.counters.receive_frame_timeouts += 1;
                if (io.rpc != null) {
                    discardInboundFrame(self, index);
                    continue;
                }
                if (io.discarding) {
                    g.counters.local_pressure_resets += 1;
                } else {
                    if ((io.reader.declaredLen() orelse 0) > io.body.len) {
                        g.peers.penalize(peer.logical, 1);
                        g.peers.rows[peer.logical.index].large_frame_denied_until = now_ms +| g.options.pressure_timeout_ms;
                    }
                    g.counters.large_stalled += 1;
                }
                resetInbound(self, engine, index);
            },
            .send_queue, .send_progress => {
                g.counters.tx_stalled += 1;
                if (reason == .send_queue) g.counters.send_queue_timeouts += 1 else g.counters.send_progress_timeouts += 1;
                const retry_direct = peer.outbound == .live and g.peers.rows[peer.logical.index].direct;
                resetOutbound(self, engine, index);
                if (retry_direct) g.sessions.setOutbound(index, .{ .retry_at = now_ms +| direct_retry_delay_ms });
            },
        }
    }
}

/// Test builds check after every turn that the ready list holds every session that wants
/// service, that each session off the list is keyed on its recomputed deadline, and that the
/// connection index finds each active session.
fn checkSessions(self: *const Gossipsub) void {
    const sessions = self.sessions;
    var linked: usize = 0;
    for (sessions.rows, 0..) |*row, position| {
        const index: u16 = @intCast(position);
        linked += @intFromBool(row.ready_link.linked);
        if (!row.active) {
            assert(!row.ready_link.linked and sessions.deadlines.get(index) == null);
            continue;
        }
        assert(sessions.find(row.conn).? == index);
        if (row.wants()) assert(row.ready_link.linked);
        if (!row.ready_link.linked) assert(sessions.deadlines.get(index) == row.deadline(&self.options));
    }
    assert(linked == sessions.ready.len);
}

/// Test builds check after every pump that each stream a session holds routes to it, that a
/// session off the ready list holds no inbound stream with an unread readable edge, and that a
/// blocked out stream with queued output waits on armed write interest.
fn checkRoutes(self: *const Gossipsub, engine: *const Engine) void {
    for (self.sessions.rows, 0..) |*row, position| {
        if (!row.active) continue;
        const index: u24 = @intCast(position);
        if (row.in_stream) |stream| if (engine.route(stream)) |bound| {
            assert(bound.owner == .gossip_inbound and bound.row == index);
            if (!row.ready_link.linked) if (engine.streamWaits(stream)) |waits| assert(!waits.read_open);
        };
        if (row.outStream()) |stream| if (engine.route(stream)) |bound| {
            assert(bound.owner == .gossip_outbound and bound.row == index);
            const tx = &row.io.tx;
            if (!tx.ready and (tx.pending() or tx.subscription_dirty.count() > 0)) if (engine.streamWaits(stream)) |waits| assert(waits.write_waiting);
        };
    }
}

pub const Admission = enum { admitted, duplicate, capacity, unauthenticated };

pub fn beginPump(self: *Gossipsub, now: Now) Turn {
    self.last_now_ms = now.mono_ms;
    self.apply_metrics.close();
    self.messages.expire(&self.peers, now.mono_ms);
    var turn = Turn.init(&self.options, now, self.msg_scratch);
    turn.sink = self.message_sink;
    return turn;
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
