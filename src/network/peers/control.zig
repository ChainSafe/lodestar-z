const std = @import("std");
const t = @import("types.zig");
const wire = @import("control_wire.zig");
const Catalog = @import("catalog.zig").Catalog;
const Service = @import("../service.zig").Service;
const Engine = @import("../quic/engine.zig").Engine;
const rr = @import("../reqresp/root.zig");
const Now = @import("../types.zig").Now;
const client = @import("client.zig");
const goodbye = @import("goodbye.zig");
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;
const assert = std.debug.assert;
/// An `operation_by_peer` entry with no request in flight.
const no_operation = std.math.maxInt(u16);
pub const Options = struct {
    starts_per_turn_max: u16 = 8,
    inbound_status_grace_ms: u64 = 15_000,
    status_interval_ms: u64 = 300_000,
    ping_inbound_ms: u64 = 15_000,
    ping_outbound_ms: u64 = 20_000,
    status_transition_grace_ms: u64 = 10_000,
    local_retry_ms: u64 = 1_000,
    /// Consecutive failures of one probe that disconnect the peer.
    health_failures_max: u8 = 3,
    failure_retry_ms: u64 = 5_000,
};
/// Control probes whose failures count toward a health disconnect.
pub const HealthProbe = enum { status, metadata, ping };
const health_probe_count = @typeInfo(HealthProbe).@"enum".fields.len;
const Operation = struct {
    request: ?rr.RequestHandle = null,
    peer: t.PeerRef = undefined,
    conn: t.Handle = undefined,
    protocol: rr.Protocol = .ping_v1,
    cancelled: bool = false,
    received: bool = false,
    /// Started after the connection's Status and Metadata exchange, so its success proves health.
    after_ready: bool = false,
    bytes: [wire.status_size_max]u8 = undefined,
    sink: [wire.status_size_max]u8 = undefined,
};
const Response = struct {
    request: ?rr.RequestHandle = null,
    peer: t.PeerRef = undefined,
    conn: t.Handle = undefined,
    bytes: [wire.status_size_max]u8 = undefined,
};
const Schedule = struct {
    direction: t.Direction = .inbound,
    identify_state: enum { pending, started, done } = .pending,
    identify_retry_ms: u64 = 0,
    previous_digest: [4]u8 = @splat(0),
    previous_protocol: rr.Protocol = .status_v1,
    transition_until_ms: u64 = 0,
    peer: ?t.PeerRef = null,
    conn: t.Handle = undefined,
    status_due_ms: u64 = 0,
    ping_due_ms: u64 = 0,
    retry_ms: u64 = 0,
    metadata_due_ms: ?u64 = null,
    health_failures: [health_probe_count]u8 = @splat(0),
    /// `ready` once the connection completed a Status and Metadata exchange, which clears the dialed
    /// endpoint's connection failures; `proven` once a probe started after that succeeded, which
    /// clears the endpoint's health strikes.
    evidence: enum { pending, ready, proven } = .pending,
    closing: ?struct { reason: t.DisconnectReason, deadline_ms: u64, sent: bool = false } = null,
    /// How the remote refused us on this connection, recorded against its identity at close: its
    /// Goodbye, or for our dial a close before the Status and Metadata exchange completed. Neither
    /// counts once a local close began.
    rejection: ?t.Rejection = null,
};
pub const Control = struct {
    operations: []Operation,
    responses: []Response,
    schedules: []Schedule,
    /// Connected schedules keyed on the earliest time `decide` acts on them, in ms.
    deadlines: DeadlineHeap,
    /// Per schedule row, the operation whose request is in flight for that catalog index, or
    /// `no_operation`. A replacement owner of the index waits for that request's terminal event.
    operation_by_peer: []u16,
    /// The rows one maintain turn takes from the heap.
    due: []u32,
    options: Options,
    cursor: usize = 0,
    /// Schedules taken from the deadline heap. An idle peer set visits none.
    visits: u64 = 0,
    counters: Counters = .{},

    pub const Counters = struct {
        started: u64 = 0,
        deferred: u64 = 0,
        closed: [@typeInfo(t.DisconnectReason).@"enum".fields.len]u64 = @splat(0),
        health_failures: [health_probe_count]u64 = @splat(0),
        events: @import("control_metrics.zig").Counters = .{},
    };

    /// Control operations holding a request, which retirement tests watch drain.
    pub fn operationsInFlight(self: *const Control) usize {
        var count: usize = 0;
        for (self.operations) |*op| count += @intFromBool(op.request != null);
        return count;
    }

    pub fn validateOptions(options: Options) error{InvalidOptions}!void {
        if (options.starts_per_turn_max == 0 or options.starts_per_turn_max > 256 or options.health_failures_max == 0)
            return error.InvalidOptions;
        const timers = [_]u64{
            options.inbound_status_grace_ms,
            options.status_interval_ms,
            options.ping_inbound_ms,
            options.ping_outbound_ms,
            options.status_transition_grace_ms,
            options.local_retry_ms,
            options.failure_retry_ms,
        };
        for (timers) |timer| if (timer == 0 or timer > 86_400_000) return error.InvalidOptions;
    }

    pub fn init(
        a: std.mem.Allocator,
        options: Options,
        peer_capacity: u16,
        connected_capacity: u16,
        inbound_capacity: u16,
    ) !Control {
        try validateOptions(options);
        if (connected_capacity == 0 or connected_capacity > peer_capacity or connected_capacity > 256)
            return error.InvalidOptions;
        const operations = try a.alloc(Operation, connected_capacity);
        errdefer a.free(operations);
        const responses = try a.alloc(Response, inbound_capacity);
        errdefer a.free(responses);
        const schedules = try a.alloc(Schedule, peer_capacity);
        errdefer a.free(schedules);
        var deadlines = try DeadlineHeap.init(a, peer_capacity);
        errdefer deadlines.deinit(a);
        const operation_by_peer = try a.alloc(u16, peer_capacity);
        errdefer a.free(operation_by_peer);
        const due = try a.alloc(u32, peer_capacity);
        @memset(operations, .{});
        @memset(responses, .{});
        @memset(schedules, .{});
        @memset(operation_by_peer, no_operation);
        return .{
            .operations = operations,
            .responses = responses,
            .schedules = schedules,
            .deadlines = deadlines,
            .operation_by_peer = operation_by_peer,
            .due = due,
            .options = options,
        };
    }
    pub fn deinit(self: *Control, a: std.mem.Allocator) void {
        a.free(self.due);
        a.free(self.operation_by_peer);
        self.deadlines.deinit(a);
        a.free(self.schedules);
        a.free(self.responses);
        a.free(self.operations);
        self.* = undefined;
    }
    fn schedule(self: *Control, peer: t.PeerRef, conn: t.Handle) ?*Schedule {
        if (peer.index >= self.schedules.len) return null;
        const row = &self.schedules[peer.index];
        return if (std.meta.eql(row.peer, peer) and std.meta.eql(row.conn, conn)) row else null;
    }
    pub fn connected(
        self: *Control,
        catalog: *const Catalog,
        peer: t.PeerRef,
        conn: t.Handle,
        direction: t.Direction,
        now: Now,
    ) void {
        std.debug.assert(peer.index < self.schedules.len);
        self.counters.events.connected[@intFromEnum(direction)] +|= 1;
        self.schedules[peer.index] = .{
            .direction = direction,
            .peer = peer,
            .conn = conn,
            .status_due_ms = now.mono_ms +| if (direction == .inbound)
                self.options.inbound_status_grace_ms
            else
                0,
            .ping_due_ms = now.mono_ms +| self.pingInterval(direction),
        };
        self.touch(catalog, peer.index);
    }
    /// Rekeys one schedule from its row, the peer's catalog row and its in-flight operation.
    /// Every change to any of them calls this before the next maintain or wakeup.
    fn touch(self: *Control, catalog: *const Catalog, index: usize) void {
        const row: u32 = @intCast(index);
        if (self.keyOf(catalog, index)) |key| self.deadlines.set(row, key) else self.deadlines.clear(row);
    }
    fn keyOf(self: *const Control, catalog: *const Catalog, index: usize) ?u64 {
        const row = &self.schedules[index];
        const peer = row.peer orelse return null;
        const current = connectedRow(catalog, peer, row.conn) orelse return null;
        return dueAt(row, current.status != null, self.operation_by_peer[index] != no_operation);
    }
    /// The catalog row a schedule acts for, when the catalog still holds it on that connection.
    fn connectedRow(catalog: *const Catalog, peer: t.PeerRef, conn: t.Handle) ?*const @import("catalog.zig").Row {
        const current = catalog.rowFor(peer) orelse return null;
        if (current.established_slot == null or !std.meta.eql(current.connection, conn)) return null;
        return current;
    }
    /// Rekeys a schedule after a test edited its row or the peer's catalog row directly.
    pub fn reschedule(self: *Control, catalog: *const Catalog, peer: t.PeerRef) void {
        comptime assert(@import("builtin").is_test);
        self.touch(catalog, peer.index);
    }
    fn pingInterval(self: *const Control, direction: t.Direction) u64 {
        return if (direction == .inbound)
            self.options.ping_inbound_ms
        else
            self.options.ping_outbound_ms;
    }
    pub fn cancelConnection(
        self: *Control,
        service: *Service,
        engine: *Engine,
        peer: t.PeerRef,
        conn: t.Handle,
    ) void {
        self.cancelOperation(service, peer, conn);
        for (self.responses) |*response| if (response.request) |request| {
            if (std.meta.eql(response.peer, peer) and std.meta.eql(response.conn, conn)) {
                _ = service.reqresp.cancel(request);
            }
        };
        service.reqresp.cleanupPending(engine, &service.router);
        if (self.schedule(peer, conn)) |row| {
            row.peer = null;
            self.deadlines.clear(peer.index);
        }
    }
    /// Cancels the peer's in-flight request on this connection. Its operation stays held until
    /// the request's terminal event.
    fn cancelOperation(self: *Control, service: *Service, peer: t.PeerRef, conn: t.Handle) void {
        if (peer.index >= self.operation_by_peer.len) return;
        const index = self.operation_by_peer[peer.index];
        if (index == no_operation) return;
        const op = &self.operations[index];
        if (!std.meta.eql(op.peer, peer) or !std.meta.eql(op.conn, conn)) return;
        op.cancelled = true;
        _ = service.reqresp.cancel(op.request.?);
    }
    pub fn disconnect(
        self: *Control,
        catalog: *Catalog,
        peer: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
        now: Now,
    ) bool {
        const row = self.schedule(peer, conn) orelse return false;
        if (!catalog.markUnavailable(peer, conn, reason)) return false;
        if (row.closing == null) {
            if (reason == .capacity or reason == .count_pruning) {
                _ = catalog.deferRedial(peer, conn, now.mono_ms, goodbye.cooldownMs(129));
            } else if (reason != .shutdown and reason != .remote_goodbye) {
                _ = catalog.cooldown(peer, conn, now.mono_ms, goodbye.cooldownMs(goodbyeReason(reason)));
            }
            const snapshot = catalog.get(peer).?;
            const agent = client.agent(&snapshot.identify);
            std.log.scoped(.network_peers).debug("peer_disconnect_scheduled peer={f} connection={d}:{d} reason={s} grace_ms=2000 agent={f}", .{ @import("../logging.zig").peer(&snapshot.identity), conn.index, conn.generation, @tagName(reason), std.json.fmt(agent, .{}) });
            row.closing = .{ .reason = reason, .deadline_ms = now.mono_ms +| 2_000 };
        }
        self.touch(catalog, peer.index);
        return true;
    }
    pub fn reStatusPeer(self: *Control, catalog: *const Catalog, peer: t.PeerRef, conn: t.Handle, now: Now) bool {
        const row = self.schedule(peer, conn) orelse return false;
        if (row.closing != null) return false;
        row.status_due_ms = @min(row.status_due_ms, now.mono_ms);
        self.touch(catalog, peer.index);
        return true;
    }
    pub fn reStatusPeers(self: *Control, catalog: *const Catalog, now: Now) void {
        for (self.schedules, 0..) |*row, index| if (row.peer != null) {
            row.status_due_ms = @min(row.status_due_ms, now.mono_ms);
            self.touch(catalog, index);
        };
    }
    pub fn forkUpdated(self: *Control, service: *Service, catalog: *Catalog, previous: t.ForkContext, now: Now) void {
        for (self.schedules, 0..) |*row, index| if (row.peer) |peer| {
            if (row.closing != null) continue;
            const relevant = (catalog.get(peer) orelse continue).relevant;
            if (!catalog.invalidateStatus(peer, row.conn)) continue;
            row.previous_digest = previous.digest;
            row.previous_protocol = wire.statusProtocol(previous);
            row.transition_until_ms = if (relevant) now.mono_ms +| self.options.status_transition_grace_ms else 0;
            row.status_due_ms = now.mono_ms;
            row.retry_ms = 0;
            row.metadata_due_ms = row.metadata_due_ms orelse now.mono_ms;
            self.cancelOperation(service, peer, row.conn);
            self.touch(catalog, index);
        };
    }
    pub fn revalidationDeadline(self: *const Control, peer: t.PeerRef, conn: t.Handle, now: Now) ?u64 {
        if (peer.index >= self.schedules.len) return null;
        const row = &self.schedules[peer.index];
        if (!std.meta.eql(row.peer, peer) or !std.meta.eql(row.conn, conn) or row.closing != null or now.mono_ms >= row.transition_until_ms) return null;
        return row.transition_until_ms;
    }
    fn goodbyeReason(reason: t.DisconnectReason) u64 {
        return switch (reason) {
            .host, .shutdown, .duplicate, .remote_goodbye, .gossip_unavailable => 1,
            .capacity, .count_pruning => 129,
            .reputation => 250,
            .banned => 251,
            .incompatible_fork, .future_head, .finalized_mismatch, .missing_availability => 2,
            .transport_closed,
            .invalid_status,
            .invalid_metadata,
            .health_timeout,
            .health_error,
            => 3,
        };
    }
    const Start = enum { started, retiring, deferred };

    fn start(
        self: *Control,
        service: *Service,
        engine: *Engine,
        row: *Schedule,
        protocol: rr.Protocol,
        local: *const t.LocalState,
        now: Now,
    ) Start {
        const peer = row.peer.?;
        assert(self.operation_by_peer[peer.index] == no_operation);
        for (self.operations, 0..) |*op, index| {
            if (op.request != null) continue;
            const len = switch (protocol) {
                .status_v1, .status_v2 => wire.encodeStatus(
                    protocol,
                    &local.status,
                    &op.bytes,
                ) catch return .deferred,
                .ping_v1, .goodbye_v1 => blk: {
                    std.mem.writeInt(
                        u64,
                        op.bytes[0..8],
                        if (protocol == .ping_v1)
                            local.metadata.seq_number
                        else
                            goodbyeReason(row.closing.?.reason),
                        .little,
                    );
                    break :blk 8;
                },
                .metadata_v1, .metadata_v2, .metadata_v3 => 0,
                else => unreachable,
            };
            const request = service.request(
                engine,
                row.conn,
                protocol,
                op.bytes[0..len],
                &op.sink,
                .{},
                now,
            ) catch |err| return switch (err) {
                error.SlotsExhausted, error.NegotiationTableFull => .retiring,
                else => .deferred,
            };
            op.peer = peer;
            op.conn = row.conn;
            op.protocol = protocol;
            op.cancelled = false;
            op.received = false;
            op.after_ready = row.evidence == .ready;
            op.request = request;
            self.operation_by_peer[peer.index] = @intCast(index);
            self.counters.started +|= 1;
            return .started;
        }
        return .retiring;
    }
    /// Acts on the schedules whose deadline passed, in the order a scan of every row from the
    /// cursor would reach them, and rekeys each one afterwards.
    pub fn maintain(
        self: *Control,
        service: *Service,
        catalog: *Catalog,
        engine: *Engine,
        local: *const t.LocalState,
        now: Now,
    ) void {
        var count: usize = 0;
        // Each row holds at most one key, so the heap empties within schedules.len pops.
        while (self.deadlines.popDue(now.mono_ms)) |index| {
            self.due[count] = index;
            count += 1;
        }
        self.visits +|= count;
        const due = self.due[0..count];
        std.sort.pdq(u32, due, Rotation{ .start = self.cursor, .len = self.schedules.len }, Rotation.lessThan);
        var starts_remaining = self.options.starts_per_turn_max;
        for (due) |index| {
            defer self.touch(catalog, index);
            const row = &self.schedules[index];
            const peer = row.peer orelse continue;
            const current = connectedRow(catalog, peer, row.conn) orelse continue;
            const relevant = current.status != null;
            const decision = decide(row, relevant, self.operation_by_peer[index] != no_operation, now.mono_ms);
            if (decision.close) {
                self.close(service, catalog, engine, peer, row.conn, row.closing.?.reason, now);
                continue;
            }
            if (starts_remaining > 0 and relevant and row.closing == null and row.identify_state == .pending and now.mono_ms >= row.identify_retry_ms) {
                starts_remaining -= 1;
                self.cursor = (index + 1) % self.schedules.len;
                startIdentify(service, engine, row, now);
            }
            const action = decision.request orelse continue;
            if (starts_remaining == 0) continue;
            starts_remaining -= 1;
            self.cursor = (index + 1) % self.schedules.len;
            const protocol: rr.Protocol = switch (action) {
                .status => wire.statusProtocol(local.fork),
                .metadata => wire.metadataProtocol(local.fork),
                .ping => .ping_v1,
                .goodbye => .goodbye_v1,
            };
            switch (self.start(service, engine, row, protocol, local, now)) {
                .started => {
                    row.retry_ms = 0;
                    if (action == .goodbye) row.closing.?.sent = true;
                },
                .retiring, .deferred => {
                    self.counters.deferred +|= 1;
                    row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
                },
            }
        }
        if (@import("builtin").is_test) self.checkSchedules(catalog, now.mono_ms);
    }
    /// Orders row indices by their distance from `start`, wrapping at `len`.
    const Rotation = struct {
        start: usize,
        len: usize,
        fn lessThan(self: Rotation, a: u32, b: u32) bool {
            return (a + self.len - self.start) % self.len < (b + self.len - self.start) % self.len;
        }
    };
    fn startIdentify(service: *Service, engine: *Engine, row: *Schedule, now: Now) void {
        service.identify.start(&service.router, engine, row.peer.?, row.conn, now) catch {
            row.identify_retry_ms = now.mono_ms +| 1_000;
            return;
        };
        row.identify_state = .started;
    }

    pub fn identifyResults(self: *Control, catalog: *Catalog, results: []const @import("../identify/root.zig").Result) void {
        std.debug.assert(results.len <= 64);
        for (results) |*completion| {
            const row = self.schedule(completion.peer, completion.conn) orelse continue;
            if (row.identify_state != .started) continue;
            row.identify_state = .done;
            defer self.touch(catalog, completion.peer.index);
            switch (completion.outcome) {
                .success => |*metadata| {
                    if (catalog.updateIdentify(completion.peer, completion.conn, metadata)) {
                        const snapshot = catalog.get(completion.peer).?;
                        std.log.scoped(.network_peers).debug("identify_completed peer={f} connection={d}:{d} agent={f}", .{ @import("../logging.zig").peer(&snapshot.identity), completion.conn.index, completion.conn.generation, std.json.fmt(client.agent(&snapshot.identify), .{}) });
                    }
                },
                .failed => |failure| {
                    const snapshot = catalog.get(completion.peer).?;
                    std.log.scoped(.network_peers).debug("identify_failed peer={f} connection={d}:{d} reason={s}", .{ @import("../logging.zig").peer(&snapshot.identity), completion.conn.index, completion.conn.generation, @tagName(failure) });
                },
            }
        }
    }

    pub fn receivedGoodbye(self: *Control, catalog: *Catalog, peer: t.PeerRef, conn: t.Handle, code: u64, during_close: bool) void {
        const reason = goodbye.reason(code);
        const snapshot = catalog.get(peer).?;
        self.counters.events.goodbyeReceived(code);
        std.log.scoped(.network_peers).debug("peer_goodbye_received peer={f} connection={d}:{d} code={d} reason={s} during_close={any} agent={f}", .{ @import("../logging.zig").peer(&snapshot.identity), conn.index, conn.generation, code, @tagName(reason), during_close, std.json.fmt(client.agent(&snapshot.identify), .{}) });
        const row = self.schedule(peer, conn) orelse return;
        if (row.closing == null and row.rejection == null) row.rejection = goodbye.rejection(code);
    }

    /// Notes a close the remote initiated. On our dial before the Status and Metadata exchange
    /// completed, it is an early close.
    pub fn remoteClosed(self: *Control, peer: t.PeerRef, conn: t.Handle) void {
        const row = self.schedule(peer, conn) orelse return;
        if (row.closing == null and row.rejection == null and row.direction == .outbound and row.evidence == .pending)
            row.rejection = .early_close;
    }

    pub fn close(
        self: *Control,
        service: *Service,
        catalog: *Catalog,
        engine: *Engine,
        peer: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
        now: Now,
    ) void {
        const row = self.schedule(peer, conn) orelse return;
        catalog.settleRejections(peer, conn, row.evidence != .pending, row.rejection, now.mono_ms);
        catalog.rememberClosed(peer, conn, row.evidence != .pending, reason, row.rejection, now);
        self.cancelConnection(service, engine, peer, conn);
        service.gossipsub.retireConnection(&service.router, engine, conn, now);
        _ = catalog.disconnect(peer, conn, reason, now.mono_ms);
        self.counters.closed[@intFromEnum(reason)] +|= 1;
        _ = engine.close(conn, 0);
    }
    fn acceptStatus(
        self: *Control,
        catalog: *Catalog,
        peer: t.PeerRef,
        conn: t.Handle,
        protocol: rr.Protocol,
        bytes: []const u8,
        local: *const t.LocalState,
        now: Now,
        slot: u64,
    ) void {
        const row = self.schedule(peer, conn) orelse return;
        if (row.closing != null) return;
        const status = wire.decodeStatus(protocol, bytes) catch |err| {
            if (err == error.InvalidLength or err == error.InvalidEncoding)
                _ = catalog.report(peer, .low_tolerance, now.mono_ms);
            _ = self.disconnect(catalog, peer, conn, .invalid_status, now);
            return;
        };
        if (now.mono_ms < row.transition_until_ms and protocol == row.previous_protocol and
            std.mem.eql(u8, &status.fork_digest, &row.previous_digest) and
            (protocol != wire.statusProtocol(local.fork) or !std.mem.eql(u8, &status.fork_digest, &local.fork.digest)))
        {
            if (!(catalog.get(peer) orelse return).relevant)
                row.retry_ms = @min(row.transition_until_ms, now.mono_ms +| self.options.local_retry_ms);
            return;
        }
        const relevance = wire.relevance(local, &status, slot);
        if (relevance) |reason| {
            _ = self.disconnect(catalog, peer, conn, reason, now);
            return;
        }
        if (!catalog.updateStatus(peer, conn, &status, now.mono_ms)) return;
        row.status_due_ms = now.mono_ms +| self.options.status_interval_ms;
        if (catalog.get(peer).?.metadata == null) row.metadata_due_ms = row.metadata_due_ms orelse now.mono_ms;
        applicationReady(catalog, row, peer, conn);
    }
    /// Marks the connection ready once it holds a valid relevant Status and a valid Metadata.
    fn applicationReady(catalog: *Catalog, row: *Schedule, peer: t.PeerRef, conn: t.Handle) void {
        if (row.evidence != .pending) return;
        const current = connectedRow(catalog, peer, conn) orelse return;
        if (current.status == null or current.metadata == null) return;
        row.evidence = .ready;
        catalog.clearDialFailures(peer, conn);
    }
    fn sequence(
        self: *Control,
        catalog: *Catalog,
        peer: t.PeerRef,
        conn: t.Handle,
        seq: u64,
        now: Now,
    ) void {
        const row = self.schedule(peer, conn) orelse return;
        const snapshot = catalog.get(peer) orelse return;
        if (!snapshot.relevant or row.closing != null) return;
        if (snapshot.metadata) |metadata| {
            if (seq < metadata.seq_number) return;
            if (seq == metadata.seq_number) {
                _ = catalog.updateMetadata(peer, conn, &metadata, now.mono_ms);
                return;
            }
        }
        row.metadata_due_ms = row.metadata_due_ms orelse now.mono_ms;
    }
    pub fn events(
        self: *Control,
        service: *Service,
        catalog: *Catalog,
        engine: *Engine,
        local: *const t.LocalState,
        now: Now,
        slot: u64,
        batch: []const rr.Event,
    ) void {
        for (batch) |event| switch (event) {
            .request => |request| self.respond(service, catalog, local, request, now, slot),
            else => self.result(service, catalog, engine, local, event, now, slot),
        };
    }
    fn respond(
        self: *Control,
        service: *Service,
        catalog: *Catalog,
        local: *const t.LocalState,
        event: @FieldType(rr.Event, "request"),
        now: Now,
        slot: u64,
    ) void {
        const peer = catalog.findConnection(event.peer) orelse {
            _ = service.reqresp.cancel(event.request);
            return;
        };
        defer self.touch(catalog, peer.index);
        const response = available: {
            for (self.responses) |*candidate| if (candidate.request == null) break :available candidate;
            unreachable;
        };
        response.peer = peer;
        response.conn = event.peer;
        const len: usize = switch (event.protocol) {
            .status_v1, .status_v2 => blk: {
                self.acceptStatus(
                    catalog,
                    peer,
                    event.peer,
                    event.protocol,
                    event.bytes,
                    local,
                    now,
                    slot,
                );
                break :blk wire.encodeStatus(event.protocol, &local.status, &response.bytes) catch {
                    _ = service.reqresp.cancel(event.request);
                    return;
                };
            },
            .ping_v1 => blk: {
                if (event.bytes.len != 8) {
                    _ = service.reqresp.cancel(event.request);
                    return;
                }
                self.sequence(
                    catalog,
                    peer,
                    event.peer,
                    std.mem.readInt(u64, event.bytes[0..8], .little),
                    now,
                );
                std.mem.writeInt(u64, response.bytes[0..8], local.metadata.seq_number, .little);
                break :blk 8;
            },
            .metadata_v1, .metadata_v2, .metadata_v3 => wire.encodeMetadata(
                event.protocol,
                &local.metadata,
                local.fork,
                &response.bytes,
            ) catch {
                _ = service.reqresp.cancel(event.request);
                return;
            },
            .goodbye_v1 => blk: {
                std.debug.assert(event.bytes.len == 8);
                const code = std.mem.readInt(u64, event.bytes[0..8], .little);
                self.receivedGoodbye(catalog, peer, event.peer, code, false);
                _ = self.disconnect(catalog, peer, event.peer, .remote_goodbye, now);
                self.schedules[peer.index].closing.?.sent = true;
                std.mem.writeInt(u64, response.bytes[0..8], 1, .little);
                break :blk 8;
            },
            else => unreachable,
        };
        service.reqresp.respond(event.request, response.bytes[0..len], null, now) catch {
            _ = service.reqresp.cancel(event.request);
            return;
        };
        response.request = event.request;
    }
    fn result(
        self: *Control,
        service: *Service,
        catalog: *Catalog,
        engine: *Engine,
        local: *const t.LocalState,
        event: rr.Event,
        now: Now,
        slot: u64,
    ) void {
        const request = switch (event) {
            .chunk => |e| e.request,
            .done => |e| e.request,
            .failed => |e| e.request,
            .chunk_sent => |e| e.request,
            .served => |e| e.request,
            else => unreachable,
        };
        if (request.direction == .inbound) {
            const response = matching: {
                for (self.responses) |*candidate| if (std.meta.eql(candidate.request, request)) break :matching candidate;
                return;
            };
            switch (event) {
                .chunk_sent => {
                    _ = service.reqresp.finish(request, now);
                },
                .served, .failed => response.request = null,
                else => {},
            }
            return;
        }
        for (self.operations, 0..) |*op, index| {
            if (!std.meta.eql(op.request, request)) continue;
            const row = self.schedule(op.peer, op.conn);
            const matched = row != null and !op.cancelled;
            defer self.touch(catalog, op.peer.index);
            switch (event) {
                .chunk => |chunk| {
                    if (matched) self.acceptChunk(catalog, op, chunk.bytes, local, now, slot);
                    _ = service.reqresp.consume(request, now);
                    op.received = true;
                },
                .done, .failed => {
                    if (matched) self.complete(catalog, op, event, now);
                    service.reqresp.cleanupPending(engine, &service.router);
                    op.request = null;
                    assert(self.operation_by_peer[op.peer.index] == index);
                    self.operation_by_peer[op.peer.index] = no_operation;
                },
                else => {},
            }
            return;
        }
    }
    fn acceptChunk(
        self: *Control,
        catalog: *Catalog,
        op: *Operation,
        bytes: []const u8,
        local: *const t.LocalState,
        now: Now,
        slot: u64,
    ) void {
        const row = self.schedule(op.peer, op.conn) orelse return;
        if (row.closing != null) return;
        switch (op.protocol) {
            .status_v1, .status_v2 => self.acceptStatus(
                catalog,
                op.peer,
                op.conn,
                op.protocol,
                bytes,
                local,
                now,
                slot,
            ),
            .ping_v1 => {
                if (bytes.len == 8) self.sequence(
                    catalog,
                    op.peer,
                    op.conn,
                    std.mem.readInt(u64, bytes[0..8], .little),
                    now,
                );
            },
            .metadata_v1, .metadata_v2, .metadata_v3 => {
                const metadata = wire.decodeMetadata(op.protocol, bytes, local.fork) catch |err| {
                    if (err == error.InvalidLength or err == error.InvalidEncoding or err == error.InvalidSyncnets)
                        _ = catalog.report(op.peer, .low_tolerance, now.mono_ms);
                    if (catalog.get(op.peer)) |snapshot| {
                        std.log.scoped(.network_peers).debug("metadata_rejected peer={f} connection={d}:{d} method={s} reason={s} bytes={d}", .{
                            @import("../logging.zig").peer(&snapshot.identity),
                            op.conn.index,
                            op.conn.generation,
                            @tagName(op.protocol),
                            @errorName(err),
                            bytes.len,
                        });
                    }
                    _ = self.disconnect(catalog, op.peer, op.conn, .invalid_metadata, now);
                    return;
                };
                _ = catalog.updateMetadata(op.peer, op.conn, &metadata, now.mono_ms);
                row.metadata_due_ms = null;
                applicationReady(catalog, row, op.peer, op.conn);
            },
            else => {},
        }
    }
    fn complete(self: *Control, catalog: *Catalog, op: *Operation, event: rr.Event, now: Now) void {
        const row = self.schedule(op.peer, op.conn) orelse return;
        if (row.closing != null) return;
        switch (event) {
            .failed => |failed| switch (failed.reason) {
                .cancelled, .host_timeout, .quota_timeout => {
                    row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
                },
                .negotiation_rejected => {
                    if ((op.protocol == .status_v1 or op.protocol == .status_v2) and now.mono_ms < row.transition_until_ms) {
                        row.retry_ms = @min(row.transition_until_ms, now.mono_ms +| self.options.local_retry_ms);
                    } else {
                        _ = self.disconnect(catalog, op.peer, op.conn, .health_error, now);
                    }
                },
                else => {
                    const probe = healthProbe(op.protocol) orelse return;
                    const timed_out = failed.reason == .timeout or
                        (failed.reason == .negotiation_failed and failed.reason.negotiation_failed == .timeout);
                    self.healthFailure(catalog, row, op, probe, if (timed_out) .health_timeout else .health_error, now);
                },
            },
            .done => {
                const probe = healthProbe(op.protocol) orelse return;
                if (!op.received) {
                    self.healthFailure(catalog, row, op, probe, .health_error, now);
                    return;
                }
                row.health_failures[@intFromEnum(probe)] = 0;
                if (op.after_ready and probe != .metadata) {
                    row.evidence = .proven;
                    catalog.clearHealthStrikes(op.peer, op.conn);
                }
                const snapshot = catalog.get(op.peer) orelse return;
                if (probe != .status) row.ping_due_ms = now.mono_ms +| self.pingInterval(snapshot.direction);
            },
            else => unreachable,
        }
    }

    fn healthFailure(self: *Control, catalog: *Catalog, row: *Schedule, op: *const Operation, probe: HealthProbe, reason: t.DisconnectReason, now: Now) void {
        const failures = &row.health_failures[@intFromEnum(probe)];
        failures.* +|= 1;
        self.counters.health_failures[@intFromEnum(probe)] +|= 1;
        std.log.scoped(.network_peers).debug("peer_health_failure connection={d}:{d} probe={s} failures={d} limit={d}", .{ op.conn.index, op.conn.generation, @tagName(probe), failures.*, self.options.health_failures_max });
        if (failures.* >= self.options.health_failures_max) {
            _ = self.disconnect(catalog, op.peer, op.conn, reason, now);
            return;
        }
        row.retry_ms = now.mono_ms +| self.options.failure_retry_ms;
    }
    /// The earliest schedule deadline, bounded below by now. O(1).
    pub fn nextWakeup(self: *const Control, catalog: *const Catalog, now: Now) ?u64 {
        if (@import("builtin").is_test) self.checkSchedules(catalog, now.mono_ms);
        const top = self.deadlines.peek() orelse return null;
        return @max(top.deadline, now.mono_ms);
    }

    /// Test builds check that each schedule's key is the deadline a scan of every row computes
    /// with `decide`, so no due schedule waits off the heap, and that the operation index matches
    /// the operation table.
    fn checkSchedules(self: *const Control, catalog: *const Catalog, now_ms: u64) void {
        var in_flight: usize = 0;
        for (self.operations, 0..) |*op, index| if (op.request != null) {
            in_flight += 1;
            assert(self.operation_by_peer[op.peer.index] == index);
        };
        var indexed: usize = 0;
        for (self.schedules, 0..) |*row, index| {
            // With the counts equal below, the index names exactly the in-flight operations.
            const active_request = self.operation_by_peer[index] != no_operation;
            indexed += @intFromBool(active_request);
            const key = self.deadlines.get(@intCast(index));
            const peer = row.peer orelse {
                assert(key == null);
                continue;
            };
            const snapshot = catalog.get(peer) orelse {
                assert(key == null);
                continue;
            };
            if (!std.meta.eql(snapshot.connection, row.conn)) {
                assert(key == null);
                continue;
            }
            const expected = dueAt(row, snapshot.relevant, active_request);
            assert(key == expected);
            const bounded: ?u64 = if (expected) |value| @max(value, now_ms) else null;
            assert(decide(row, snapshot.relevant, active_request, now_ms).deadline_ms == bounded);
        }
        assert(in_flight == indexed);
    }
};

const Decision = struct {
    request: ?enum { status, metadata, ping, goodbye } = null,
    close: bool = false,
    deadline_ms: ?u64 = null,

    fn wake(self: *Decision, deadline: u64, now: u64) void {
        const bounded = @max(deadline, now);
        self.deadline_ms = @min(self.deadline_ms orelse bounded, bounded);
    }
};

/// The earliest time `decide` acts on the row. It does not depend on the clock, so a row needs a
/// new key only when its state changes; `decide` bounds the value by now.
fn dueAt(row: *const Schedule, relevant: bool, active_request: bool) ?u64 {
    if (row.closing) |closing| {
        if (closing.sent or active_request) return closing.deadline_ms;
        return @min(closing.deadline_ms, row.retry_ms);
    }
    const identify: ?u64 = if (relevant and row.identify_state == .pending) row.identify_retry_ms else null;
    if (active_request) return identify;
    const metadata_due = if (relevant) row.metadata_due_ms else null;
    const refresh_due = metadata_due orelse row.ping_due_ms;
    const request_due = @max(@min(row.status_due_ms, refresh_due), row.retry_ms);
    return @min(identify orelse request_due, request_due);
}

fn decide(row: *const Schedule, relevant: bool, active_request: bool, now: u64) Decision {
    var decision: Decision = .{};
    if (row.closing) |closing| {
        decision.wake(closing.deadline_ms, now);
        if (now >= closing.deadline_ms) {
            decision.close = true;
        } else if (!closing.sent and !active_request) {
            decision.wake(row.retry_ms, now);
            if (now >= row.retry_ms) decision.request = .goodbye;
        }
        return decision;
    }
    if (relevant) {
        if (row.identify_state == .pending) decision.wake(row.identify_retry_ms, now);
    }
    if (active_request) return decision;
    const metadata_due = if (relevant) row.metadata_due_ms else null;
    const refresh_due = metadata_due orelse row.ping_due_ms;
    const request_due = @min(row.status_due_ms, refresh_due);
    decision.wake(@max(request_due, row.retry_ms), now);
    if (now < row.retry_ms or now < request_due) return decision;
    decision.request = if (row.status_due_ms < refresh_due)
        .status
    else if (metadata_due != null)
        .metadata
    else
        .ping;
    return decision;
}

fn healthProbe(protocol: rr.Protocol) ?HealthProbe {
    return switch (protocol) {
        .status_v1, .status_v2 => .status,
        .metadata_v1, .metadata_v2, .metadata_v3 => .metadata,
        .ping_v1 => .ping,
        else => null,
    };
}

test "control repeated Status intent preserves the first due time" {
    var control = try Control.init(std.testing.allocator, .{}, 2, 2, 1);
    defer control.deinit(std.testing.allocator);
    var catalog = try Catalog.init(std.testing.allocator, .{ .capacity = 2, .outbound_reserve = 0, .target_peers = 2, .max_peers = 2, .min_outbound = 0 }, 2, 0);
    defer catalog.deinit(std.testing.allocator);
    const first: t.PeerRef = .{ .index = 0, .generation = 1 };
    const second: t.PeerRef = .{ .index = 1, .generation = 1 };
    const first_conn: t.Handle = .{ .index = 0, .generation = 1 };
    const second_conn: t.Handle = .{ .index = 1, .generation = 1 };
    control.connected(&catalog, first, first_conn, .outbound, .{ .mono_ms = 10, .unix_s = 0 });
    control.connected(&catalog, second, second_conn, .inbound, .{ .mono_ms = 10, .unix_s = 0 });
    for ([_]u64{ 20, 30, 40 }) |now| {
        control.reStatusPeers(&catalog, .{ .mono_ms = now, .unix_s = 0 });
        try std.testing.expect(control.reStatusPeer(&catalog, second, second_conn, .{ .mono_ms = now, .unix_s = 0 }));
        try std.testing.expectEqual(@as(u64, 10), control.schedules[0].status_due_ms);
        try std.testing.expectEqual(@as(u64, 20), control.schedules[1].status_due_ms);
    }
}
