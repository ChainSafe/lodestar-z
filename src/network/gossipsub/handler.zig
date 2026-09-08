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

pub const retry_min_ms: u64 = 1_000;
pub const retry_max_ms: u64 = 30_000;
pub const openings_per_pump: usize = 16;

const Outbound = union(enum) {
    waiting: u64,
    negotiating: StreamHandle,
    live: StreamHandle,
};

const Supervisor = struct {
    peer: ?state_mod.PeerHandle = null,
    outbound: Outbound = .{ .waiting = 0 },
    failures: u8 = 0,
    needs_service: bool = false,
};

pub const Handler = struct {
    allocator: Allocator,
    inner: Gossipsub,
    streams: []Supervisor,
    open_cursor: usize = 0,

    pub fn init(allocator: Allocator, options: gossipsub_mod.Options) InitError!Handler {
        var inner = try Gossipsub.init(allocator, options);
        errdefer inner.deinit();
        const streams = try allocator.alloc(Supervisor, options.connected_capacity);
        errdefer allocator.free(streams);
        @memset(streams, .{});
        return .{
            .allocator = allocator,
            .inner = inner,
            .streams = streams,
        };
    }

    pub fn deinit(self: *Handler) void {
        self.allocator.free(self.streams);
        self.inner.deinit();
        self.* = undefined;
    }

    pub fn shutdown(self: *Handler, router: *routing.Router, engine: *Engine) void {
        for (self.streams, 0..) |*supervisor, index| {
            const peer = supervisor.peer orelse continue;
            if (!self.inner.state.peerMatches(peer.index, peer.generation)) continue;
            if (supervisor.outbound == .negotiating) router.cancel(engine, supervisor.outbound.negotiating);
            const conn = self.inner.state.peers[index].conn;
            self.inner.resetInbound(engine, @intCast(index));
            self.inner.resetOutbound(engine, @intCast(index));
            self.inner.connectionClosed(conn);
            supervisor.* = .{};
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
        return switch (self.streams[index].outbound) {
            .live => |stream| std.meta.eql(self.inner.state.outStream(index), stream),
            else => false,
        };
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
        self.streams[peer.index] = .{ .peer = peer, .outbound = .{ .waiting = now.mono_ms } };
        return .admitted;
    }

    pub fn transportEvents(
        self: *Handler,
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
                self.streams[index] = .{};
                self.inner.connectionClosed(closed.conn);
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
        const supervisor = &self.streams[index];
        const peer = supervisor.peer orelse return;
        if (!self.inner.state.peerMatches(peer.index, peer.generation)) return;
        if (outcome.direction == .outbound) {
            const pending = switch (supervisor.outbound) {
                .negotiating => |stream| stream,
                else => return,
            };
            if (!std.meta.eql(pending, outcome.stream)) return;
            switch (outcome.result) {
                .ready => |selection| {
                    if (selection.leftover.len != 0) {
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
                    supervisor.outbound = .{ .live = outcome.stream };
                    supervisor.failures = 0;
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
        self.streams[index].needs_service = true;
    }

    pub fn nextWakeup(self: *const Handler, now: Now, event_capacity: usize) ?u64 {
        var next = self.inner.nextWakeup(now, event_capacity);
        for (self.streams) |supervisor| {
            const peer = supervisor.peer orelse continue;
            if (!self.inner.state.peerMatches(peer.index, peer.generation)) continue;
            if (supervisor.needs_service) return now.mono_ms;
            switch (supervisor.outbound) {
                .waiting => |deadline| next = @min(next orelse deadline, @max(now.mono_ms, deadline)),
                .live => if (self.inner.state.outStream(peer.index) == null) {
                    next = now.mono_ms;
                },
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
        var openings: usize = 0;
        var examined: usize = 0;
        for (0..self.streams.len) |_| {
            if (examined == 32) break;
            const index: u16 = @intCast(self.open_cursor);
            self.open_cursor = (self.open_cursor + 1) % self.streams.len;
            const supervisor = &self.streams[index];
            const peer = supervisor.peer orelse continue;
            if (!self.inner.state.peerMatches(peer.index, peer.generation)) continue;
            supervisor.needs_service = false;
            examined += 1;
            switch (supervisor.outbound) {
                .live => |stream| {
                    if (self.inner.state.outStream(index) == null) {
                        self.retry(index, now);
                        continue;
                    }
                    // Observe idle STOP_SENDING without a write or a host-work hint.
                    _ = engine.streamCapacity(stream) catch {
                        self.inner.resetOutbound(engine, index);
                        self.retry(index, now);
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
        return self.inner.pump(engine, now, out);
    }

    fn openOutbound(
        self: *Handler,
        router: *routing.Router,
        engine: *Engine,
        index: u16,
        now: Now,
    ) void {
        const conn = self.inner.state.peers[index].conn;
        const stream = router.beginMeshsub(engine, conn, now) catch {
            self.retry(index, now);
            return;
        };
        self.streams[index].outbound = .{ .negotiating = stream };
    }

    fn retry(self: *Handler, index: u16, now: Now) void {
        const supervisor = &self.streams[index];
        const delay = @min(retry_max_ms, retry_min_ms << @as(u6, @intCast(supervisor.failures)));
        supervisor.failures = @min(supervisor.failures + 1, 5);
        supervisor.outbound = .{ .waiting = now.mono_ms +| delay };
    }

    fn streamClosed(self: *Handler, engine: *Engine, stream: StreamHandle, now: Now) void {
        const index = self.inner.state.findPeer(stream.conn) orelse return;
        const supervisor = &self.streams[index];
        switch (supervisor.outbound) {
            .live => |live| if (std.meta.eql(live, stream)) {
                self.inner.resetOutbound(engine, index);
                self.retry(index, now);
            },
            .negotiating => |pending| if (std.meta.eql(pending, stream)) self.retry(index, now),
            .waiting => {},
        }
        // Read-side FIN can be reported with buffered payload. The framing owner
        // drains it before resetting; a reset is observed by its next read.
    }

    pub const Admission = enum { admitted, duplicate, capacity, unauthenticated };
};
