const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const state_mod = @import("state.zig");
const types = @import("../types.zig");
const gossipsub_mod = @import("gossipsub.zig");
const constants = @import("constants.zig");

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

pub const Handler = struct {
    inner: Gossipsub,
    open_cursor: usize = 0,

    pub fn init(allocator: Allocator, options: gossipsub_mod.Options) InitError!Handler {
        return .{ .inner = try Gossipsub.init(allocator, options) };
    }

    pub fn deinit(self: *Handler) void {
        self.inner.deinit();
        self.* = undefined;
    }

    pub fn shutdown(self: *Handler, router: *routing.Router, engine: *Engine) void {
        for (self.inner.state.peers, 0..) |*peer, index| {
            if (peer.active) self.inner.retirePeer(router, engine, @intCast(index));
        }
    }

    pub fn subscribe(self: *Handler, topic: []const u8) bool {
        return self.inner.subscribe(topic);
    }

    pub fn configureTopic(self: *Handler, topic: []const u8, params: *const @import("score.zig").TopicParams) Gossipsub.ConfigureTopicError!void {
        return self.inner.configureTopic(topic, params);
    }

    pub fn unsubscribe(self: *Handler, topic: []const u8) bool {
        return self.inner.unsubscribe(topic);
    }

    pub fn publish(
        self: *Handler,
        topic: []const u8,
        ssz: []const u8,
        now: Now,
    ) Gossipsub.PublishError!Gossipsub.PublishOutcome {
        return self.publishWithOptions(topic, ssz, .{}, now);
    }

    pub fn publishWithOptions(self: *Handler, topic: []const u8, ssz: []const u8, options: Gossipsub.PublishOptions, now: Now) Gossipsub.PublishError!Gossipsub.PublishOutcome {
        return self.inner.publishWithOptions(topic, ssz, options, now);
    }

    pub fn report(self: *Handler, handle: ValidationHandle, verdict: Verdict, now: Now) gossipsub_mod.ReportOutcome {
        return self.inner.report(handle, verdict, now);
    }

    pub fn setPeerScore(self: *Handler, conn: Handle, value: f64) bool {
        return self.inner.setPeerScore(conn, value);
    }

    pub fn markDirect(self: *Handler, conn: Handle) void {
        self.inner.markDirect(conn);
    }

    pub fn counters(self: *const Handler) Gossipsub.Counters {
        return self.inner.counters;
    }

    pub fn resourceSnapshot(self: *const Handler) gossipsub_mod.ResourceSnapshot {
        return self.inner.resourceSnapshot();
    }

    /// Hosts inspect this after each connected event and service pump. Refused or locally retired
    /// gossip relationships retain reqresp access.
    /// Retry peerConnected with the same live handle after capacity returns or its duplicate closes.
    /// Hosts schedule retries at most once per second per connection, bounded by transport capacity.
    pub fn admitted(self: *Handler, conn: Handle) bool {
        return self.inner.state.findPeer(conn) != null;
    }

    pub fn deliveryAvailable(self: *const Handler, conn: Handle) bool {
        const index = self.inner.state.findPeer(conn) orelse return false;
        return self.inner.state.peers[index].outStream() != null;
    }

    pub fn peerConnected(self: *Handler, engine: *Engine, conn: Handle, now: Now) Admission {
        if (self.inner.state.findPeer(conn) != null) return .admitted;
        const identity = engine.peerId(conn) orelse return .unauthenticated;
        const address = engine.peerAddress(conn) orelse return .unauthenticated;
        const direction = engine.direction(conn) orelse return .unauthenticated;
        const result = self.inner.addPeer(conn, .v1_2, &.{ .identity = identity, .address = address, .direction = direction }, now);
        const peer = switch (result) {
            .admitted => |peer| peer,
            .duplicate => return .duplicate,
            .capacity => return .capacity,
        };
        self.inner.state.peers[peer.index].outbound = .{ .waiting = now.mono_ms };
        return .admitted;
    }

    pub fn transportEvents(
        self: *Handler,
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
                const index = self.inner.state.findPeer(closed.conn) orelse continue;
                self.inner.retirePeer(router, engine, index);
            },
            else => {},
        };
    }

    pub fn negotiationResult(
        self: *Handler,
        engine: *Engine,
        outcome: routing.Outcome,
        now: Now,
    ) void {
        const index = self.inner.state.findPeer(outcome.stream.conn) orelse {
            engine.closeStream(outcome.stream, 0);
            return;
        };
        const session = &self.inner.state.peers[index];
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
                    self.inner.replaceOutbound(
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
                self.inner.replaceInbound(
                    engine,
                    index,
                    outcome.stream,
                    selection.protocol.meshsub,
                );
                if (!self.inner.receiveHandoff(index, selection.leftover, selection.fin)) {
                    self.inner.resetInbound(engine, index);
                }
            },
            else => {},
        }
    }

    pub fn connectionActivity(self: *Handler, conn: Handle) void {
        self.inner.connectionActivity(conn);
        const index = self.inner.state.findPeer(conn) orelse return;
        self.inner.state.peers[index].needs_service = true;
    }

    pub fn nextWakeup(self: *const Handler, now: Now, event_capacity: usize) ?u64 {
        var next = self.inner.nextWakeup(now, event_capacity);
        for (self.inner.state.peers) |*session| {
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
        self: *Handler,
        router: *routing.Router,
        engine: *Engine,
        now: Now,
        out: []Event,
    ) usize {
        self.inner.last_now_ms = @max(self.inner.last_now_ms, now.mono_ms);
        var openings: usize = 0;
        var examined: usize = 0;
        for (0..self.inner.state.peers.len) |_| {
            if (examined == 32) break;
            const index: u16 = @intCast(self.open_cursor);
            self.open_cursor = (self.open_cursor + 1) % self.inner.state.peers.len;
            const session = &self.inner.state.peers[index];
            if (!session.active) continue;
            session.needs_service = false;
            examined += 1;
            switch (session.outbound) {
                .live => |stream| {
                    // Observe idle STOP_SENDING without a write or a host-work hint.
                    _ = engine.streamCapacity(stream) catch {
                        self.inner.resetOutbound(engine, index);
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
        return self.inner.pumpRouted(router, engine, now, out);
    }

    fn openOutbound(
        self: *Handler,
        router: *routing.Router,
        engine: *Engine,
        index: u16,
        now: Now,
    ) void {
        const conn = self.inner.state.peers[index].conn;
        const stream = router.beginMeshsub(engine, conn, now) catch |err| {
            self.inner.counters.negotiation_deferred += 1;
            std.log.scoped(.network_gossip_errors).debug("gossip_negotiation_deferred connection={d}:{d} reason={s} attempts={d}", .{ conn.index, conn.generation, @errorName(err), self.inner.state.peers[index].failures });
            self.retry(index, now);
            return;
        };
        self.inner.counters.negotiation_started += 1;
        self.inner.state.peers[index].outbound = .{ .negotiating = stream };
    }

    fn retry(self: *Handler, index: u16, now: Now) void {
        self.inner.state.peers[index].retry(now.mono_ms);
    }

    fn streamClosed(self: *Handler, engine: *Engine, stream: StreamHandle, now: Now) void {
        const index = self.inner.state.findPeer(stream.conn) orelse return;
        const session = &self.inner.state.peers[index];
        switch (session.outbound) {
            .live => |live| if (std.meta.eql(live, stream)) {
                self.inner.resetOutbound(engine, index);
            },
            .negotiating => |pending| if (std.meta.eql(pending, stream)) self.retry(index, now),
            .waiting => {},
        }
        // Read-side FIN can be reported with buffered payload. The framing owner
        // drains it before resetting; a reset is observed by its next read.
    }

    pub const Admission = enum { admitted, duplicate, capacity, unauthenticated };
};
