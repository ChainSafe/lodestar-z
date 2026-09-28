const std = @import("std");
const t = @import("types.zig");
const wire = @import("../control_wire.zig");
const Catalog = @import("catalog.zig").Catalog;
const protocol_mod = @import("../control_protocol.zig");
const ControlProtocol = protocol_mod.ControlProtocol;
const rr = @import("../reqresp/root.zig");
const Now = @import("../types.zig").Now;
const client = @import("client.zig");
const goodbye = @import("goodbye.zig");
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;
const assert = std.debug.assert;
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
    /// Goodbye, or for our dial a close or a refused Status before the Status and Metadata exchange
    /// completed. None counts once a local close began.
    rejection: ?t.Rejection = null,
};
/// Peer control policy: probe scheduling, fork-transition grace, health streaks, evidence,
/// rejection attribution and disconnect decisions. It reads the control protocol's operation
/// index to key its schedules; the owner executes the requests and closes it chooses.
pub const Control = struct {
    schedules: []Schedule,
    /// Connected schedules keyed on the earliest time `decide` acts on them, in ms.
    deadlines: DeadlineHeap,
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
    /// One maintain turn: the rows taken from the heap in rotation order, and the starts left.
    pub const Pass = struct { next: usize = 0, count: usize, starts_remaining: u16 };
    /// A due schedule's work for the owner: a close, or an Identify start and a control request
    /// start within the turn's start quota.
    pub const Due = struct {
        index: u32,
        peer: t.PeerRef,
        conn: t.Handle,
        close: ?t.DisconnectReason = null,
        identify: bool = false,
        request: ?protocol_mod.Probe = null,
    };
    /// A connection whose in-flight request peer control no longer wants.
    pub const Connection = struct { peer: t.PeerRef, conn: t.Handle };

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

    pub fn init(a: std.mem.Allocator, options: Options, peer_capacity: u16) !Control {
        try validateOptions(options);
        const schedules = try a.alloc(Schedule, peer_capacity);
        errdefer a.free(schedules);
        var deadlines = try DeadlineHeap.init(a, peer_capacity);
        errdefer deadlines.deinit(a);
        const due = try a.alloc(u32, peer_capacity);
        @memset(schedules, .{});
        return .{
            .schedules = schedules,
            .deadlines = deadlines,
            .due = due,
            .options = options,
        };
    }
    pub fn deinit(self: *Control, a: std.mem.Allocator) void {
        a.free(self.due);
        self.deadlines.deinit(a);
        a.free(self.schedules);
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
        requests: *const ControlProtocol,
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
        self.rekey(catalog, requests, peer.index);
    }
    /// Rekeys one schedule from its row, the peer's catalog row and its in-flight operation.
    /// Every change to any of them calls this before the next maintain or wakeup.
    pub fn rekey(self: *Control, catalog: *const Catalog, requests: *const ControlProtocol, index: usize) void {
        const row: u32 = @intCast(index);
        if (self.keyOf(catalog, requests, index)) |key| self.deadlines.set(row, key) else self.deadlines.clear(row);
    }
    fn keyOf(self: *const Control, catalog: *const Catalog, requests: *const ControlProtocol, index: usize) ?u64 {
        const row = &self.schedules[index];
        const peer = row.peer orelse return null;
        const current = connectedRow(catalog, peer, row.conn) orelse return null;
        return dueAt(row, current.status != null, requests.busy(index));
    }
    /// The catalog row a schedule acts for, when the catalog still holds it on that connection.
    fn connectedRow(catalog: *const Catalog, peer: t.PeerRef, conn: t.Handle) ?*const @import("catalog.zig").Row {
        const current = catalog.rowFor(peer) orelse return null;
        if (current.established_slot == null or !std.meta.eql(current.connection, conn)) return null;
        return current;
    }
    fn pingInterval(self: *const Control, direction: t.Direction) u64 {
        return if (direction == .inbound)
            self.options.ping_inbound_ms
        else
            self.options.ping_outbound_ms;
    }
    /// Retires the schedule of a connection that closed or lost its catalog index to a
    /// replacement. The protocol cancels the connection's requests separately.
    pub fn retire(self: *Control, peer: t.PeerRef, conn: t.Handle) void {
        if (self.schedule(peer, conn)) |row| {
            row.peer = null;
            self.deadlines.clear(peer.index);
        }
    }
    pub fn disconnect(
        self: *Control,
        catalog: *Catalog,
        requests: *const ControlProtocol,
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
        self.rekey(catalog, requests, peer.index);
        return true;
    }
    pub fn reStatusPeer(self: *Control, catalog: *const Catalog, requests: *const ControlProtocol, peer: t.PeerRef, conn: t.Handle, now: Now) bool {
        const row = self.schedule(peer, conn) orelse return false;
        if (row.closing != null) return false;
        row.status_due_ms = @min(row.status_due_ms, now.mono_ms);
        self.rekey(catalog, requests, peer.index);
        return true;
    }
    pub fn reStatusPeers(self: *Control, catalog: *const Catalog, requests: *const ControlProtocol, now: Now) void {
        for (self.schedules, 0..) |*row, index| if (row.peer != null) {
            row.status_due_ms = @min(row.status_due_ms, now.mono_ms);
            self.rekey(catalog, requests, index);
        };
    }
    /// Invalidates one schedule's Status after the local fork changed and opens its transition
    /// grace. Returns the connection whose in-flight request the owner cancels.
    pub fn revalidate(
        self: *Control,
        catalog: *Catalog,
        requests: *const ControlProtocol,
        index: usize,
        previous: t.ForkContext,
        now: Now,
    ) ?Connection {
        const row = &self.schedules[index];
        const peer = row.peer orelse return null;
        if (row.closing != null) return null;
        const relevant = (catalog.get(peer) orelse return null).relevant;
        if (!catalog.invalidateStatus(peer, row.conn)) return null;
        row.previous_digest = previous.digest;
        row.previous_protocol = wire.statusProtocol(previous);
        row.transition_until_ms = if (relevant) now.mono_ms +| self.options.status_transition_grace_ms else 0;
        row.status_due_ms = now.mono_ms;
        row.retry_ms = 0;
        row.metadata_due_ms = row.metadata_due_ms orelse now.mono_ms;
        self.rekey(catalog, requests, index);
        return .{ .peer = peer, .conn = row.conn };
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
    /// Takes the schedules whose deadline passed, ordered as a scan of every row from the cursor
    /// would reach them.
    pub fn beginMaintenance(self: *Control, now: Now) Pass {
        var count: usize = 0;
        // Each row holds at most one key, so the heap empties within schedules.len pops.
        while (self.deadlines.popDue(now.mono_ms)) |index| {
            self.due[count] = index;
            count += 1;
        }
        self.visits +|= count;
        const due = self.due[0..count];
        // std.sort.pdq fills its stack in ReleaseSafe even when there is nothing to order.
        if (due.len > 1) std.sort.pdq(u32, due, Rotation{ .start = self.cursor, .len = self.schedules.len }, Rotation.lessThan);
        return .{ .count = count, .starts_remaining = self.options.starts_per_turn_max };
    }
    /// Returns the pass's next schedule with work, spending the start quota and advancing the
    /// cursor for each start. Rekeys the schedules it passes over; the owner executes the work,
    /// records its outcome and rekeys the returned schedule before the next call.
    pub fn nextDue(
        self: *Control,
        pass: *Pass,
        catalog: *const Catalog,
        requests: *const ControlProtocol,
        local: *const t.LocalState,
        now: Now,
    ) ?Due {
        while (pass.next < pass.count) {
            const index = self.due[pass.next];
            pass.next += 1;
            if (self.dueWork(pass, catalog, requests, index, local, now)) |due| return due;
            self.rekey(catalog, requests, index);
        }
        if (@import("builtin").is_test) self.checkSchedules(catalog, requests, now.mono_ms);
        return null;
    }
    fn dueWork(
        self: *Control,
        pass: *Pass,
        catalog: *const Catalog,
        requests: *const ControlProtocol,
        index: u32,
        local: *const t.LocalState,
        now: Now,
    ) ?Due {
        const row = &self.schedules[index];
        const peer = row.peer orelse return null;
        const current = connectedRow(catalog, peer, row.conn) orelse return null;
        const relevant = current.status != null;
        const decision = decide(row, relevant, requests.busy(index), now.mono_ms);
        var due: Due = .{ .index = index, .peer = peer, .conn = row.conn };
        if (decision.close) {
            due.close = row.closing.?.reason;
            return due;
        }
        if (pass.starts_remaining > 0 and relevant and row.closing == null and row.identify_state == .pending and now.mono_ms >= row.identify_retry_ms) {
            pass.starts_remaining -= 1;
            self.cursor = (index + 1) % self.schedules.len;
            due.identify = true;
        }
        if (decision.request) |action| if (pass.starts_remaining > 0) {
            pass.starts_remaining -= 1;
            self.cursor = (index + 1) % self.schedules.len;
            due.request = switch (action) {
                .status => .{ .protocol = wire.statusProtocol(local.fork) },
                .metadata => .{ .protocol = wire.metadataProtocol(local.fork) },
                .ping => .{ .protocol = .ping_v1 },
                .goodbye => .{ .protocol = .goodbye_v1, .code = goodbyeReason(row.closing.?.reason) },
            };
            due.request.?.after_ready = row.evidence == .ready;
        };
        return if (due.identify or due.request != null) due else null;
    }
    /// Orders row indices by their distance from `start`, wrapping at `len`.
    const Rotation = struct {
        start: usize,
        len: usize,
        fn lessThan(self: Rotation, a: u32, b: u32) bool {
            return (a + self.len - self.start) % self.len < (b + self.len - self.start) % self.len;
        }
    };
    pub fn identifyStarted(self: *Control, due: *const Due, started: bool, now: Now) void {
        const row = &self.schedules[due.index];
        if (!started) {
            row.identify_retry_ms = now.mono_ms +| 1_000;
            return;
        }
        row.identify_state = .started;
    }
    pub fn requestStarted(self: *Control, due: *const Due, started: bool, now: Now) void {
        const row = &self.schedules[due.index];
        if (!started) {
            self.counters.deferred +|= 1;
            row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
            return;
        }
        self.counters.started +|= 1;
        row.retry_ms = 0;
        if (due.request.?.protocol == .goodbye_v1) row.closing.?.sent = true;
    }

    pub fn identifyResults(self: *Control, catalog: *Catalog, requests: *const ControlProtocol, results: []const @import("../identify/root.zig").Result) void {
        std.debug.assert(results.len <= 64);
        for (results) |*completion| {
            const row = self.schedule(completion.peer, completion.conn) orelse continue;
            if (row.identify_state != .started) continue;
            row.identify_state = .done;
            defer self.rekey(catalog, requests, completion.peer.index);
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
        earlyClose(self.schedule(peer, conn) orelse return);
    }

    /// Records the remote turning our dial away before the Status and Metadata exchange completed,
    /// unless a local close began or the remote already refused us otherwise.
    fn earlyClose(row: *Schedule) void {
        if (row.closing == null and row.rejection == null and row.direction == .outbound and row.evidence == .pending)
            row.rejection = .early_close;
    }

    /// Records the close of a connection its schedule owns against the peer's identity and
    /// endpoint, then retires the schedule. Returns false when no schedule owns the connection,
    /// in which case the owner leaves it alone.
    pub fn close(
        self: *Control,
        catalog: *Catalog,
        peer: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
        now: Now,
    ) bool {
        const row = self.schedule(peer, conn) orelse return false;
        catalog.settleRejections(peer, conn, row.evidence != .pending, row.rejection, now.mono_ms);
        catalog.rememberClosed(peer, conn, row.evidence != .pending, reason, row.rejection, now);
        self.retire(peer, conn);
        self.counters.closed[@intFromEnum(reason)] +|= 1;
        return true;
    }
    fn acceptStatus(
        self: *Control,
        catalog: *Catalog,
        requests: *const ControlProtocol,
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
            _ = self.disconnect(catalog, requests, peer, conn, .invalid_status, now);
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
        if (relevance(local, &status, slot)) |reason| {
            _ = self.disconnect(catalog, requests, peer, conn, reason, now);
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
    /// Applies a peer's control request to its schedule before the owner answers it through the
    /// control protocol.
    pub fn requested(
        self: *Control,
        catalog: *Catalog,
        requests: *const ControlProtocol,
        peer: t.PeerRef,
        event: *const @FieldType(rr.Event, "request"),
        local: *const t.LocalState,
        now: Now,
        slot: u64,
    ) void {
        defer self.rekey(catalog, requests, peer.index);
        switch (event.protocol) {
            .status_v1, .status_v2 => self.acceptStatus(
                catalog,
                requests,
                peer,
                event.peer,
                event.protocol,
                event.bytes,
                local,
                now,
                slot,
            ),
            .ping_v1 => {
                if (event.bytes.len == 8) self.sequence(
                    catalog,
                    peer,
                    event.peer,
                    std.mem.readInt(u64, event.bytes[0..8], .little),
                    now,
                );
            },
            .metadata_v1, .metadata_v2, .metadata_v3 => {},
            .goodbye_v1 => {
                std.debug.assert(event.bytes.len == 8);
                const code = std.mem.readInt(u64, event.bytes[0..8], .little);
                self.receivedGoodbye(catalog, peer, event.peer, code, false);
                _ = self.disconnect(catalog, requests, peer, event.peer, .remote_goodbye, now);
                self.schedules[peer.index].closing.?.sent = true;
            },
            else => unreachable,
        }
    }
    /// Applies a reply to the schedule that started its request, before the owner settles it
    /// through the control protocol. A cancelled request's reply, or one for a connection that no
    /// longer owns its schedule, changes nothing.
    pub fn replied(
        self: *Control,
        catalog: *Catalog,
        requests: *const ControlProtocol,
        op: *const protocol_mod.Operation,
        event: rr.Event,
        local: *const t.LocalState,
        now: Now,
        slot: u64,
    ) void {
        if (self.schedule(op.peer, op.conn) == null or op.cancelled) return;
        switch (event) {
            .chunk => |chunk| self.acceptChunk(catalog, requests, op, chunk.bytes, local, now, slot),
            .done, .failed => self.complete(catalog, requests, op, event, now),
            else => {},
        }
    }
    fn acceptChunk(
        self: *Control,
        catalog: *Catalog,
        requests: *const ControlProtocol,
        op: *const protocol_mod.Operation,
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
                requests,
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
                    _ = self.disconnect(catalog, requests, op.peer, op.conn, .invalid_metadata, now);
                    return;
                };
                _ = catalog.updateMetadata(op.peer, op.conn, &metadata, now.mono_ms);
                row.metadata_due_ms = null;
                applicationReady(catalog, row, op.peer, op.conn);
            },
            else => {},
        }
    }
    fn complete(self: *Control, catalog: *Catalog, requests: *const ControlProtocol, op: *const protocol_mod.Operation, event: rr.Event, now: Now) void {
        const row = self.schedule(op.peer, op.conn) orelse return;
        if (row.closing != null) return;
        switch (event) {
            .failed => |failed| switch (failed.reason) {
                .cancelled, .host_timeout, .quota_timeout => {
                    row.retry_ms = now.mono_ms +| self.options.local_retry_ms;
                },
                .negotiation_rejected => {
                    const status = op.protocol == .status_v1 or op.protocol == .status_v2;
                    if (status and now.mono_ms < row.transition_until_ms) {
                        row.retry_ms = @min(row.transition_until_ms, now.mono_ms +| self.options.local_retry_ms);
                        return;
                    }
                    if (healthProbe(op.protocol)) |probe| self.countHealthFailure(row, op, probe, failed.reason, .immediate);
                    if (status) earlyClose(row);
                    _ = self.disconnect(catalog, requests, op.peer, op.conn, .health_error, now);
                },
                else => {
                    const probe = healthProbe(op.protocol) orelse return;
                    self.healthFailure(catalog, requests, row, op, probe, failed.reason, now);
                },
            },
            .done => {
                const probe = healthProbe(op.protocol) orelse return;
                if (!op.received) {
                    self.healthFailure(catalog, requests, row, op, probe, .empty_response, now);
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

    fn healthFailure(self: *Control, catalog: *Catalog, requests: *const ControlProtocol, row: *Schedule, op: *const protocol_mod.Operation, probe: HealthProbe, failure: rr.Failure, now: Now) void {
        const failures = &row.health_failures[@intFromEnum(probe)];
        failures.* +|= 1;
        const at_limit = failures.* >= self.options.health_failures_max;
        self.countHealthFailure(row, op, probe, failure, if (at_limit) .at_limit else .none);
        if (at_limit) {
            const timed_out = failure == .timeout or (failure == .negotiation_failed and failure.negotiation_failed == .timeout);
            _ = self.disconnect(catalog, requests, op.peer, op.conn, if (timed_out) .health_timeout else .health_error, now);
            return;
        }
        row.retry_ms = now.mono_ms +| self.options.failure_retry_ms;
    }
    /// Counts a failed probe once and logs it with the probe's streak and the close it causes:
    /// none, the streak's limit, or an immediate one for a refused probe, which skips the streak.
    fn countHealthFailure(self: *Control, row: *const Schedule, op: *const protocol_mod.Operation, probe: HealthProbe, failure: rr.Failure, closes: enum { none, at_limit, immediate }) void {
        self.counters.health_failures[@intFromEnum(probe)] +|= 1;
        std.log.scoped(.network_peers).debug("peer_health_failure connection={d}:{d} probe={s} reason={s} failures={d} limit={d} close={s}", .{ op.conn.index, op.conn.generation, @tagName(probe), @tagName(failure), row.health_failures[@intFromEnum(probe)], self.options.health_failures_max, @tagName(closes) });
    }
    /// The earliest schedule deadline, bounded below by now. O(1).
    pub fn nextWakeup(self: *const Control, catalog: *const Catalog, requests: *const ControlProtocol, now: Now) ?u64 {
        if (@import("builtin").is_test) self.checkSchedules(catalog, requests, now.mono_ms);
        const top = self.deadlines.peek() orelse return null;
        return @max(top.deadline, now.mono_ms);
    }

    /// Test builds check that each schedule's key is the deadline a scan of every row computes
    /// with `decide`, so no due schedule waits off the heap.
    fn checkSchedules(self: *const Control, catalog: *const Catalog, requests: *const ControlProtocol, now_ms: u64) void {
        for (self.schedules, 0..) |*row, index| {
            const active_request = requests.busy(index);
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

fn relevance(
    local: *const t.LocalState,
    remote: *const t.Status,
    current_slot: u64,
) ?t.DisconnectReason {
    if (!std.mem.eql(u8, &remote.fork_digest, &local.fork.digest)) return .incompatible_fork;
    if (remote.head_slot > current_slot +| 1) return .future_head;
    if (local.fork.fork.gte(.fulu) and remote.earliest_available_slot == null)
        return .missing_availability;
    const zero: [32]u8 = @splat(0);
    if (remote.finalized_epoch == local.status.finalized_epoch and
        !std.mem.eql(u8, &remote.finalized_root, &zero) and
        !std.mem.eql(u8, &local.status.finalized_root, &zero) and
        !std.mem.eql(u8, &remote.finalized_root, &local.status.finalized_root))
        return .finalized_mismatch;
    return null;
}

test {
    _ = @import("control_test.zig");
}
