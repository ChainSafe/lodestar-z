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
pub const Options = struct {
    operations_max: u16 = 16,
    inbound_status_grace_ms: u64 = 15_000,
    status_interval_ms: u64 = 300_000,
    ping_inbound_ms: u64 = 15_000,
    ping_outbound_ms: u64 = 20_000,
    progress_timeout_ms: u64 = 10_000,
    local_retry_ms: u64 = 1_000,
};
const Operation = struct {
    request: ?rr.RequestHandle = null,
    peer: t.PeerRef = undefined,
    conn: t.Handle = undefined,
    protocol: rr.Protocol = .ping_v1,
    cancelled: bool = false,
    received: bool = false,
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
    identify_enabled: bool = false,
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
    gossip_retry_ms: u64 = 0,
    metadata_pending: bool = false,
    desired_sequence: u64 = 0,
    closing: ?struct { reason: t.DisconnectReason, deadline_ms: u64, sent: bool = false } = null,
};
pub const Control = struct {
    operations: []Operation,
    responses: []Response,
    schedules: []Schedule,
    options: Options,
    cursor: usize = 0,
    counters: Counters = .{},

    pub const Counters = struct {
        identify_started: u64 = 0,
        identify_deferred: u64 = 0,
        identify_failures: [@typeInfo(@import("../identify/root.zig").Failure).@"enum".fields.len]u64 = @splat(0),
        started: u64 = 0,
        deferred: u64 = 0,
        gossip_refused: u64 = 0,
        closed: [@typeInfo(t.DisconnectReason).@"enum".fields.len]u64 = @splat(0),
        closed_by_client: [client.count][@typeInfo(t.DisconnectReason).@"enum".fields.len]u64 = @splat(@splat(0)),
        goodbyes: [goodbye.count]u64 = @splat(0),
    };

    pub const Resources = struct {
        operation_capacity: usize = 0,
        response_capacity: usize = 0,
        operations: usize = 0,
        responses: usize = 0,
        cancelled_operations: usize = 0,
        closing: usize = 0,
    };

    pub fn resourceSnapshot(self: *const Control) Resources {
        var snapshot: Resources = .{ .operation_capacity = self.operations.len, .response_capacity = self.responses.len };
        for (self.operations) |*op| if (op.request != null) {
            snapshot.operations += 1;
            if (op.cancelled) snapshot.cancelled_operations += 1;
        };
        for (self.responses) |*op| if (op.request != null) {
            snapshot.responses += 1;
        };
        for (self.schedules) |*row| if (row.peer != null and row.closing != null) {
            snapshot.closing += 1;
        };
        return snapshot;
    }

    pub fn validateOptions(options: Options) error{InvalidOptions}!void {
        if (options.operations_max == 0 or options.operations_max > 1024)
            return error.InvalidOptions;
        const timers = [_]u64{
            options.inbound_status_grace_ms,
            options.status_interval_ms,
            options.ping_inbound_ms,
            options.ping_outbound_ms,
            options.progress_timeout_ms,
            options.local_retry_ms,
        };
        for (timers) |timer| if (timer == 0 or timer > 86_400_000) return error.InvalidOptions;
    }

    pub fn init(
        a: std.mem.Allocator,
        options: Options,
        peer_capacity: u16,
        inbound_capacity: u16,
    ) !Control {
        try validateOptions(options);
        const operations = try a.alloc(Operation, options.operations_max);
        errdefer a.free(operations);
        const responses = try a.alloc(Response, inbound_capacity);
        errdefer a.free(responses);
        const schedules = try a.alloc(Schedule, peer_capacity);
        @memset(operations, .{});
        @memset(responses, .{});
        @memset(schedules, .{});
        return .{
            .operations = operations,
            .responses = responses,
            .schedules = schedules,
            .options = options,
        };
    }
    pub fn deinit(self: *Control, a: std.mem.Allocator) void {
        a.free(self.schedules);
        a.free(self.responses);
        a.free(self.operations);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const Control) struct {
        inline_bytes: usize,
        allocated_bytes: usize,
        outbound_bytes: usize,
        inbound_bytes: usize,
        schedule_bytes: usize,
    } {
        const outbound = self.operations.len * @sizeOf(Operation);
        const inbound = self.responses.len * @sizeOf(Response);
        const schedules = self.schedules.len * @sizeOf(Schedule);
        return .{
            .inline_bytes = @sizeOf(Control),
            .allocated_bytes = outbound + inbound + schedules,
            .outbound_bytes = outbound,
            .inbound_bytes = inbound,
            .schedule_bytes = schedules,
        };
    }
    fn schedule(self: *Control, peer: t.PeerRef, conn: t.Handle) ?*Schedule {
        if (peer.index >= self.schedules.len) return null;
        const row = &self.schedules[peer.index];
        return if (std.meta.eql(row.peer, peer) and std.meta.eql(row.conn, conn)) row else null;
    }
    pub fn peerFor(self: *Control, conn: t.Handle) ?t.PeerRef {
        for (self.schedules) |row| if (row.peer) |peer| {
            if (std.meta.eql(row.conn, conn)) return peer;
        };
        return null;
    }
    pub fn connected(
        self: *Control,
        peer: t.PeerRef,
        conn: t.Handle,
        direction: t.Direction,
        now: Now,
    ) void {
        std.debug.assert(peer.index < self.schedules.len);
        self.schedules[peer.index] = .{
            .peer = peer,
            .conn = conn,
            .status_due_ms = now.mono_ms +| if (direction == .inbound)
                self.options.inbound_status_grace_ms
            else
                0,
            .ping_due_ms = now.mono_ms +| self.pingInterval(direction),
        };
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
        for (self.operations) |*op| if (op.request) |request| {
            if (std.meta.eql(op.peer, peer) and std.meta.eql(op.conn, conn)) {
                op.cancelled = true;
                _ = service.reqresp.cancel(request);
            }
        };
        for (self.responses) |*response| if (response.request) |request| {
            if (std.meta.eql(response.peer, peer) and std.meta.eql(response.conn, conn)) {
                _ = service.reqresp.cancel(request);
            }
        };
        service.reqresp.inner.cleanupPending(engine, &service.router);
        if (self.schedule(peer, conn)) |row| row.peer = null;
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
            const snapshot = catalog.get(peer).?;
            const agent = client.agent(&snapshot.identify);
            std.log.scoped(.network_peers).debug("peer_disconnect_scheduled peer={f} connection={d}:{d} reason={s} grace_ms=2000 agent={f}", .{ @import("../logging.zig").peer(&snapshot.identity), conn.index, conn.generation, @tagName(reason), std.json.fmt(agent, .{}) });
            row.closing = .{ .reason = reason, .deadline_ms = now.mono_ms +| 2_000 };
        }
        return true;
    }
    pub fn reStatusPeer(self: *Control, peer: t.PeerRef, conn: t.Handle, now: Now) bool {
        const row = self.schedule(peer, conn) orelse return false;
        if (row.closing != null) return false;
        row.status_due_ms = now.mono_ms;
        return true;
    }
    pub fn reStatusPeers(self: *Control, now: Now) void {
        for (self.schedules) |*row| if (row.peer != null) {
            row.status_due_ms = now.mono_ms;
        };
    }
    pub fn forkUpdated(self: *Control, service: *Service, catalog: *Catalog, previous: t.ForkContext, now: Now) void {
        for (self.schedules) |*row| if (row.peer) |peer| {
            if (row.closing != null or !catalog.invalidateStatus(peer, row.conn)) continue;
            row.previous_digest = previous.digest;
            row.previous_protocol = wire.statusProtocol(previous);
            row.transition_until_ms = now.mono_ms +| self.options.progress_timeout_ms;
            row.status_due_ms = now.mono_ms;
            row.retry_ms = 0;
            // Gossip admission resumes in maintain only after fresh Status restores relevance.
            row.gossip_retry_ms = 0;
            row.metadata_pending = true;
            for (self.operations) |*op| if (op.request) |request| {
                if (!std.meta.eql(op.peer, peer) or !std.meta.eql(op.conn, row.conn)) continue;
                op.cancelled = true;
                _ = service.reqresp.cancel(request);
            };
        };
    }
    fn active(self: *const Control, peer: t.PeerRef, conn: t.Handle) bool {
        for (self.operations) |op| if (op.request != null and !op.cancelled and
            std.meta.eql(op.peer, peer) and std.meta.eql(op.conn, conn)) return true;
        return false;
    }
    fn goodbyeReason(reason: t.DisconnectReason) u64 {
        return switch (reason) {
            .host, .shutdown, .duplicate, .capacity, .remote_goodbye, .count_pruning => 1,
            .incompatible_fork, .future_head, .finalized_mismatch, .missing_availability => 2,
            .transport_closed,
            .invalid_status,
            .invalid_metadata,
            .health_timeout,
            .health_error,
            .reputation,
            .banned,
            => 3,
        };
    }
    fn start(
        self: *Control,
        service: *Service,
        engine: *Engine,
        row: *Schedule,
        protocol: rr.Protocol,
        local: *const t.LocalState,
        now: Now,
    ) bool {
        for (self.operations) |*op| {
            if (op.request != null) continue;
            const len = switch (protocol) {
                .status_v1, .status_v2 => wire.encodeStatus(
                    protocol,
                    &local.status,
                    &op.bytes,
                ) catch return false,
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
                .{ .progress_timeout_ms = self.options.progress_timeout_ms },
                now,
            ) catch return false;
            op.peer = row.peer.?;
            op.conn = row.conn;
            op.protocol = protocol;
            op.cancelled = false;
            op.received = false;
            op.request = request;
            self.counters.started +|= 1;
            return true;
        }
        return false;
    }
    pub fn maintain(
        self: *Control,
        service: *Service,
        catalog: *Catalog,
        engine: *Engine,
        local: *const t.LocalState,
        now: Now,
    ) void {
        const start_index = self.cursor;
        self.cursor = (self.cursor + 1) % self.schedules.len;
        for (0..self.schedules.len) |offset| {
            const index = (start_index + offset) % self.schedules.len;
            const row = &self.schedules[index];
            const peer = row.peer orelse continue;
            const snapshot = catalog.get(peer) orelse continue;
            if (!std.meta.eql(snapshot.connection, row.conn)) continue;
            const decision = decide(row, snapshot.relevant, self.active(peer, row.conn), now.mono_ms);
            if (decision.close) {
                self.close(service, catalog, engine, peer, row.conn, row.closing.?.reason, now);
                continue;
            }
            if (decision.gossip) {
                const admission = service.gossipsub.peerConnected(engine, row.conn, now);
                if (admission != .admitted) self.counters.gossip_refused +|= 1;
                if (snapshot.direct) service.gossipsub.markDirect(row.conn);
                row.gossip_retry_ms = now.mono_ms +| 1_000;
            }
            row.identify_enabled = service.identify != null;
            if (snapshot.relevant and row.closing == null and row.identify_enabled and row.identify_state == .pending and now.mono_ms >= row.identify_retry_ms) {
                self.startIdentify(service, engine, row, now);
            }
            const action = decision.request orelse continue;
            const protocol: rr.Protocol = switch (action) {
                .status => wire.statusProtocol(local.fork),
                .metadata => wire.metadataProtocol(local.fork),
                .ping => .ping_v1,
                .goodbye => .goodbye_v1,
            };
            if (action == .goodbye) {
                row.closing.?.sent = self.start(service, engine, row, protocol, local, now);
                row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
                continue;
            }
            if (self.start(service, engine, row, protocol, local, now)) {
                row.retry_ms = 0;
            } else {
                self.counters.deferred +|= 1;
                row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
            }
        }
    }
    fn startIdentify(self: *Control, service: *Service, engine: *Engine, row: *Schedule, now: Now) void {
        service.identify.?.start(&service.router, engine, row.peer.?, row.conn, now) catch {
            row.identify_retry_ms = now.mono_ms +| 1_000;
            self.counters.identify_deferred +|= 1;
            return;
        };
        row.identify_state = .started;
        self.counters.identify_started +|= 1;
    }

    pub fn identifyResults(self: *Control, catalog: *Catalog, results: []const @import("../identify/root.zig").Result) void {
        std.debug.assert(results.len <= 64);
        for (results) |*completion| {
            const row = self.schedule(completion.peer, completion.conn) orelse continue;
            if (row.identify_state != .started) continue;
            row.identify_state = .done;
            switch (completion.outcome) {
                .success => |*metadata| {
                    if (catalog.updateIdentify(completion.peer, completion.conn, metadata)) {
                        const snapshot = catalog.get(completion.peer).?;
                        std.log.scoped(.network_peers).debug("identify_completed peer={f} connection={d}:{d} agent={f}", .{ @import("../logging.zig").peer(&snapshot.identity), completion.conn.index, completion.conn.generation, std.json.fmt(client.agent(&snapshot.identify), .{}) });
                    }
                },
                .failed => |failure| {
                    self.counters.identify_failures[@intFromEnum(failure)] +|= 1;
                    const snapshot = catalog.get(completion.peer).?;
                    std.log.scoped(.network_peers).debug("identify_failed peer={f} connection={d}:{d} reason={s}", .{ @import("../logging.zig").peer(&snapshot.identity), completion.conn.index, completion.conn.generation, @tagName(failure) });
                },
            }
        }
    }

    pub fn receivedGoodbye(self: *Control, catalog: *Catalog, peer: t.PeerRef, conn: t.Handle, code: u64, now: Now, during_close: bool) void {
        const reason = goodbye.reason(code);
        self.counters.goodbyes[@intFromEnum(reason)] +|= 1;
        const snapshot = catalog.get(peer).?;
        std.log.scoped(.network_peers).debug("peer_goodbye_received peer={f} connection={d}:{d} code={d} reason={s} cooldown_ms={d} during_close={any} agent={f}", .{ @import("../logging.zig").peer(&snapshot.identity), conn.index, conn.generation, code, @tagName(reason), goodbye.cooldownMs(code), during_close, std.json.fmt(client.agent(&snapshot.identify), .{}) });
        _ = catalog.remoteGoodbye(peer, conn, now.mono_ms, goodbye.cooldownMs(code));
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
        if (self.schedule(peer, conn) == null) return;
        const kind = client.fromIdentify(&catalog.get(peer).?.identify);
        self.cancelConnection(service, engine, peer, conn);
        service.gossipsub.transportEvents(
            engine,
            &.{.{ .closed = .{
                .conn = conn,
                .peer_id = null,
                .direction = .inbound,
                .reason = .host,
            } }},
            now,
        );
        _ = catalog.disconnect(peer, conn, reason, now.mono_ms);
        self.counters.closed[@intFromEnum(reason)] +|= 1;
        self.counters.closed_by_client[@intFromEnum(kind)][@intFromEnum(reason)] +|= 1;
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
        inbound: bool,
    ) void {
        const row = self.schedule(peer, conn) orelse return;
        if (row.closing != null) return;
        const status = wire.decodeStatus(protocol, bytes) catch {
            _ = self.disconnect(catalog, peer, conn, .invalid_status, now);
            return;
        };
        // A request already in flight when the host advanced forks cannot establish new
        // relevance. A bounded grace permits its old-context bytes without penalizing it.
        if (inbound and now.mono_ms < row.transition_until_ms and protocol == row.previous_protocol and
            std.mem.eql(u8, &status.fork_digest, &row.previous_digest)) return;
        if (wire.relevance(local, &status, slot)) |reason| {
            _ = self.disconnect(catalog, peer, conn, reason, now);
            return;
        }
        if (!catalog.updateStatus(peer, conn, &status, now.mono_ms)) return;
        row.status_due_ms = now.mono_ms +| self.options.status_interval_ms;
        if (catalog.get(peer).?.metadata == null) row.metadata_pending = true;
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
        row.desired_sequence = @max(row.desired_sequence, seq);
        row.metadata_pending = true;
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
            .over_limit => {},
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
        const peer = self.peerFor(event.peer) orelse {
            _ = service.reqresp.cancel(event.request);
            return;
        };
        std.debug.assert(event.request.index < self.responses.len);
        const response = &self.responses[event.request.index];
        std.debug.assert(response.request == null);
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
                    true,
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
                self.receivedGoodbye(catalog, peer, event.peer, code, now, false);
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
            const response = &self.responses[request.index];
            if (!std.meta.eql(response.request, request)) return;
            switch (event) {
                .chunk_sent => {
                    _ = service.reqresp.finish(request, now);
                },
                .served, .failed => response.request = null,
                else => {},
            }
            return;
        }
        for (self.operations) |*op| {
            if (!std.meta.eql(op.request, request)) continue;
            const row = self.schedule(op.peer, op.conn);
            const matched = row != null and !op.cancelled;
            switch (event) {
                .chunk => |chunk| {
                    if (matched) self.acceptChunk(catalog, op, chunk.bytes, local, now, slot);
                    _ = service.reqresp.consume(request, now);
                    op.received = true;
                },
                .done, .failed => {
                    if (matched) self.complete(catalog, op, event, now);
                    service.reqresp.inner.cleanupPending(engine, &service.router);
                    op.request = null;
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
                false,
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
                const metadata = wire.decodeMetadata(op.protocol, bytes, local.fork) catch {
                    _ = self.disconnect(catalog, op.peer, op.conn, .invalid_metadata, now);
                    return;
                };
                if (catalog.updateMetadata(op.peer, op.conn, &metadata, now.mono_ms))
                    row.metadata_pending = metadata.seq_number < row.desired_sequence;
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
                else => {
                    const timed_out = failed.reason == .timeout or
                        (failed.reason == .negotiation_failed and failed.reason.negotiation_failed == .timeout);
                    _ = self.disconnect(catalog, op.peer, op.conn, if (timed_out) .health_timeout else .health_error, now);
                },
            },
            .done => {
                if (!op.received and op.protocol != .goodbye_v1) {
                    _ = self.disconnect(catalog, op.peer, op.conn, .health_error, now);
                }
                const snapshot = catalog.get(op.peer) orelse return;
                if (op.protocol == .ping_v1 or op.protocol == .metadata_v1 or
                    op.protocol == .metadata_v2 or op.protocol == .metadata_v3)
                    row.ping_due_ms = now.mono_ms +| self.pingInterval(snapshot.direction);
                if (row.metadata_pending and (op.protocol == .metadata_v1 or
                    op.protocol == .metadata_v2 or op.protocol == .metadata_v3))
                    row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
            },
            else => unreachable,
        }
    }
    pub fn nextWakeup(self: *const Control, catalog: *const Catalog, now: Now) ?u64 {
        var due: ?u64 = null;
        for (self.schedules) |*row| {
            const peer = row.peer orelse continue;
            const snapshot = catalog.get(peer) orelse continue;
            if (!std.meta.eql(snapshot.connection, row.conn)) continue;
            const decision = decide(row, snapshot.relevant, self.active(peer, row.conn), now.mono_ms);
            if (decision.deadline_ms) |next| due = @min(due orelse next, next);
        }
        return due;
    }
};

const Decision = struct {
    request: ?enum { status, metadata, ping, goodbye } = null,
    gossip: bool = false,
    close: bool = false,
    deadline_ms: ?u64 = null,

    fn wake(self: *Decision, deadline: u64, now: u64) void {
        const bounded = @max(deadline, now);
        self.deadline_ms = @min(self.deadline_ms orelse bounded, bounded);
    }
};

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
        if (row.identify_enabled and row.identify_state == .pending) decision.wake(row.identify_retry_ms, now);
        decision.wake(row.gossip_retry_ms, now);
        decision.gossip = now >= row.gossip_retry_ms;
    }
    if (active_request) return decision;
    const request_due = if (relevant and row.metadata_pending) 0 else @min(row.status_due_ms, row.ping_due_ms);
    decision.wake(@max(request_due, row.retry_ms), now);
    if (now < row.retry_ms) return decision;
    const status_due = now >= row.status_due_ms;
    decision.request = if (!relevant and status_due)
        .status
    else if (relevant and row.metadata_pending)
        .metadata
    else if (now >= row.ping_due_ms)
        .ping
    else if (status_due)
        .status
    else
        null;
    return decision;
}
