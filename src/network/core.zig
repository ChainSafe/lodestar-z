const std = @import("std");
const service_mod = @import("service.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const control_mod = @import("peers/control.zig");
const dial_mod = @import("peers/dial_queue.zig");
const engine_mod = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
pub const Options = struct {
    peers: t.Options = .{},
    service: service_mod.Options = .{
        .router = .{ .outbound_control_reserved = 8 },
        .reqresp = .{
            .forks = &.{},
            .outbound_control_reserved = 8,
            .inbound_control_reserved = 8,
            .outbound_per_peer_max = 8,
            .inbound_per_peer_max = 16,
            .inbound_application_per_peer_max = 8,
        },
    },
    control: control_mod.Options = .{},
    dial: dial_mod.Options,
};
pub const DialIntent = dial_mod.DialIntent;
pub const DialToken = dial_mod.Token;
pub const Counts = struct { peers: usize, application: usize, gossipsub: usize };
pub const MemoryPlan = struct {
    inline_bytes: usize,
    allocated_bytes: usize,
    catalog_bytes: usize,
    control_bytes: usize,
    dial_bytes: usize,
    service_bytes: usize,
    scratch_bytes: usize,
};
pub const Core = struct {
    allocator: std.mem.Allocator,
    service: service_mod.Service,
    catalog: peers.Catalog,
    control: control_mod.Control,
    dial_queue: dial_mod.DialQueue,
    local_identity: t.PeerId,
    local: t.LocalState,
    snapshot_scratch: []t.Snapshot,
    stopped: bool = false,
    counters: Counters = .{},

    pub const Counters = struct { rejected: u64 = 0, displaced: u64 = 0 };
    pub const PeerCounts = struct { connected: u16, relevant: u16, outbound_relevant: u16 };

    pub fn init(
        a: std.mem.Allocator,
        identity: *const t.PeerId,
        local: *const t.LocalState,
        options: Options,
    ) !Core {
        var copied: t.LocalState = undefined;
        try peers.control_wire.copyLocal(&copied, local);
        try options.peers.validate();
        if (options.service.reqresp.peers < options.peers.engine_capacity)
            return error.InvalidOptions;
        var catalog = try peers.Catalog.init(a, options.peers);
        errdefer catalog.deinit(a);
        var control = try control_mod.Control.init(
            a,
            options.control,
            options.peers.capacity,
            options.service.reqresp.inbound_max,
        );
        errdefer control.deinit(a);
        var dial_queue = try dial_mod.DialQueue.init(a, options.dial);
        errdefer dial_queue.deinit(a);
        const scratch = try a.alloc(t.Snapshot, options.peers.capacity);
        errdefer a.free(scratch);
        var service_options = options.service;
        service_options.automatic_gossip_admission = false;
        const service = try service_mod.Service.init(a, service_options);
        return .{
            .allocator = a,
            .service = service,
            .catalog = catalog,
            .control = control,
            .dial_queue = dial_queue,
            .local_identity = identity.*,
            .local = copied,
            .snapshot_scratch = scratch,
        };
    }
    /// Call shutdown with the borrowed Engine before releasing an active Core.
    pub fn deinit(self: *Core) void {
        self.service.deinit();
        self.allocator.free(self.snapshot_scratch);
        self.dial_queue.deinit(self.allocator);
        self.control.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const Core) MemoryPlan {
        const catalog = self.catalog.memoryPlan().allocated_bytes;
        const control = self.control.memoryPlan().allocated_bytes;
        const dial = self.dial_queue.memoryPlan().allocated_bytes;
        const request = self.service.reqresp.memoryPlan();
        const gossip_plan = self.service.gossipsub.inner.memoryPlan();
        const gossip_stream = @TypeOf(self.service.gossipsub.streams[0]);
        const negotiation = @TypeOf(self.service.router.negotiator.entries[0]);
        const service_bytes = request.total_bytes - request.facade_bytes +
            gossip_plan.total_bytes - @sizeOf(gossip.Gossipsub) +
            self.service.gossipsub.streams.len * @sizeOf(gossip_stream) +
            self.service.router.supported.len * @sizeOf([]const u8) +
            self.service.router.negotiator.entries.len * @sizeOf(negotiation);
        const scratch = self.snapshot_scratch.len * @sizeOf(t.Snapshot);
        return .{
            .inline_bytes = @sizeOf(Core),
            .allocated_bytes = catalog + control + dial + service_bytes + scratch,
            .catalog_bytes = catalog,
            .control_bytes = control,
            .dial_bytes = dial,
            .service_bytes = service_bytes,
            .scratch_bytes = scratch,
        };
    }
    /// Public protocol borrows retain their Service lifetime until the next process call.
    /// Internal closes after publication perform cleanup without a second owner recycling pass.
    pub fn process(
        self: *Core,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        activity: []const engine_mod.Handle,
        now: Now,
        slot: u64,
        peer_events: []t.Event,
        application: []rr.Event,
        gossip_events: []gossip.Event,
    ) Counts {
        const per_connection = 2 * @import("quic/limits.zig").streams_per_connection + 3;
        std.debug.assert(events.len <= @as(usize, engine.limits.connections_max) * per_connection);
        if (self.stopped) return .{
            .peers = self.catalog.pollEvents(peer_events),
            .application = 0,
            .gossipsub = 0,
        };
        self.catalog.refresh(now.mono_ms);
        self.dial_queue.expire(engine, now.mono_ms);
        for (events) |event| self.transportEvent(engine, event, now);
        var controls: [32]rr.Event = undefined;
        const counts = self.service.processPartitioned(
            engine,
            events,
            activity,
            now,
            application,
            &controls,
            gossip_events,
        );
        self.control.events(
            &self.service,
            &self.catalog,
            engine,
            &self.local,
            now,
            slot,
            controls[0..counts.control],
        );
        self.control.maintain(&self.service, &self.catalog, engine, &self.local, now);
        self.refreshCandidates(now);
        return .{
            .peers = self.catalog.pollEvents(peer_events),
            .application = counts.application,
            .gossipsub = counts.gossipsub,
        };
    }
    fn transportEvent(
        self: *Core,
        engine: *engine_mod.Engine,
        event: engine_mod.Event,
        now: Now,
    ) void {
        switch (event) {
            .connected => |connected| {
                const identity = engine.peerId(connected.conn) orelse return;
                const endpoint = engine.peerAddress(connected.conn) orelse return;
                const direction = engine.direction(connected.conn) orelse return;
                switch (self.catalog.admit(
                    &identity,
                    &self.local_identity,
                    connected.conn,
                    &.{ .direction = direction, .endpoint = endpoint, .now_ms = now.mono_ms },
                )) {
                    .admitted => |admission| {
                        if (admission.displaced) |old| {
                            self.counters.displaced +|= 1;
                            self.control.cancelConnection(
                                &self.service,
                                engine,
                                admission.peer,
                                old,
                            );
                            self.service.gossipsub.transportEvents(
                                engine,
                                &.{.{ .closed = .{
                                    .conn = old,
                                    .peer_id = identity,
                                    .direction = direction,
                                    .reason = .host,
                                } }},
                                now,
                            );
                            _ = engine.close(old, 0);
                        }
                        self.control.connected(admission.peer, connected.conn, direction, now);
                        _ = self.catalog.setDirect(
                            admission.peer,
                            self.dial_queue.isDirect(&identity),
                        );
                        self.dial_queue.accepted(&identity, connected.conn, now.mono_ms);
                    },
                    else => {
                        self.counters.rejected +|= 1;
                        _ = engine.close(connected.conn, 0);
                    },
                }
            },
            .closed => |closed| {
                _ = self.dial_queue.dialClosed(closed.conn, now.mono_ms);
                if (self.control.peerFor(closed.conn)) |peer| {
                    const snapshot = self.catalog.get(peer).?;
                    self.control.close(
                        &self.service,
                        &self.catalog,
                        engine,
                        peer,
                        closed.conn,
                        snapshot.disconnect_reason orelse .transport_closed,
                        now,
                    );
                    self.dial_queue.connection(&snapshot.identity, false, now.mono_ms);
                }
            },
            else => {},
        }
    }
    fn refreshCandidates(self: *Core, now: Now) void {
        const count = self.catalog.snapshots(self.snapshot_scratch);
        for (self.snapshot_scratch[0..count]) |*snapshot| {
            self.dial_queue.syncConnection(
                &snapshot.identity,
                snapshot.connection != null,
                now.mono_ms,
            );
            if (snapshot.ban_until_ms > now.mono_ms or snapshot.score <= -50 or
                snapshot.goodbye_until_ms > now.mono_ms)
            {
                const due = @max(
                    self.catalog.nextDeadline(now.mono_ms) orelse now.mono_ms +| 1_000,
                    snapshot.goodbye_until_ms,
                );
                self.dial_queue.deferPeer(&snapshot.identity, due);
            }
        }
    }
    pub fn nextWakeup(
        self: *Core,
        now: Now,
        peer_capacity: usize,
        application_capacity: usize,
        gossip_capacity: usize,
        dial_capacity: usize,
    ) ?u64 {
        if (self.stopped) return self.peerWakeup(now, peer_capacity);
        var due = self.service.nextWakeupPartitioned(
            now,
            application_capacity,
            32,
            gossip_capacity,
        );
        for ([_]?u64{
            self.control.nextWakeup(now),
            self.catalog.nextDeadline(now.mono_ms),
            self.dial_queue.nextWakeup(now.mono_ms, dial_capacity),
            self.peerWakeup(now, peer_capacity),
        }) |next| {
            if (next) |value| due = @min(due orelse value, value);
        }
        return due;
    }
    fn peerWakeup(self: *const Core, now: Now, capacity: usize) ?u64 {
        if (capacity == 0) return null;
        if (self.catalog.eventsPending()) return now.mono_ms;
        return null;
    }
    pub fn updateStatus(self: *Core, status: *const t.Status) !void {
        var local = self.local;
        local.status = status.*;
        try peers.control_wire.copyLocal(&self.local, &local);
    }
    pub fn updateMetadata(self: *Core, metadata: *const t.Metadata) !void {
        var local = self.local;
        local.metadata = metadata.*;
        try peers.control_wire.copyLocal(&self.local, &local);
    }
    pub fn updateFork(self: *Core, local: *const t.LocalState, now: Now) !void {
        try peers.control_wire.copyLocal(&self.local, local);
        self.reStatusPeers(now);
    }
    pub fn reStatusPeers(self: *Core, now: Now) void {
        self.control.reStatusPeers(now);
    }
    pub fn reportPeer(
        self: *Core,
        peer: t.PeerRef,
        action: t.PeerAction,
        now: Now,
    ) ?t.ReputationDecision {
        const decision = self.catalog.report(peer, action, now.mono_ms) orelse return null;
        if (decision != .none) _ = self.disconnect(
            peer,
            if (decision == .ban) .banned else .reputation,
            now,
        );
        return decision;
    }
    pub fn connect(
        self: *Core,
        identity: *const t.PeerId,
        addresses: []const t.Address,
        now: Now,
    ) !void {
        if (self.stopped) return error.Stopped;
        if (identity.eql(&self.local_identity)) return error.SelfDial;
        try self.dial_queue.enqueue(identity, addresses, false, now.mono_ms);
    }
    pub fn addDirectPeer(
        self: *Core,
        identity: *const t.PeerId,
        addresses: []const t.Address,
        now: Now,
    ) !void {
        if (self.stopped) return error.Stopped;
        if (identity.eql(&self.local_identity)) return error.SelfDial;
        try self.dial_queue.enqueue(identity, addresses, true, now.mono_ms);
        if (self.catalog.find(identity)) |peer| _ = self.catalog.setDirect(peer, true);
    }
    pub fn removeDirectPeer(self: *Core, identity: *const t.PeerId) void {
        self.dial_queue.removeDirect(identity);
        self.service.gossipsub.inner.unmarkDirect(identity);
        if (self.catalog.find(identity)) |peer| _ = self.catalog.setDirect(peer, false);
    }
    pub fn disconnect(self: *Core, peer: t.PeerRef, reason: t.DisconnectReason, now: Now) bool {
        const snapshot = self.catalog.get(peer) orelse return false;
        return self.control.disconnect(
            &self.catalog,
            peer,
            snapshot.connection orelse return false,
            reason,
            now,
        );
    }
    pub fn dialIntents(
        self: *Core,
        engine: *engine_mod.Engine,
        now: Now,
        out: []dial_mod.DialIntent,
    ) usize {
        if (self.stopped) return 0;
        self.dial_queue.expire(engine, now.mono_ms);
        self.catalog.refresh(now.mono_ms);
        self.refreshCandidates(now);
        return self.dial_queue.poll(now.mono_ms, out);
    }
    pub fn dialStarted(self: *Core, token: dial_mod.Token, conn: t.Handle) bool {
        return self.dial_queue.dialStarted(token, conn);
    }
    pub fn dialFailed(self: *Core, token: dial_mod.Token, now: Now) bool {
        return self.dial_queue.dialFailed(token, now.mono_ms);
    }
    pub fn snapshots(self: *const Core, out: []t.Snapshot) usize {
        return self.catalog.snapshots(out);
    }
    pub fn peerCounts(self: *Core) PeerCounts {
        const count = self.catalog.snapshots(self.snapshot_scratch);
        var result: PeerCounts = .{ .connected = 0, .relevant = 0, .outbound_relevant = 0 };
        for (self.snapshot_scratch[0..count]) |snapshot| {
            if (snapshot.connection != null) result.connected += 1;
            if (!snapshot.relevant) continue;
            result.relevant += 1;
            if (snapshot.direction == .outbound) result.outbound_relevant += 1;
        }
        return result;
    }
    pub fn connectedPeerCount(self: *const Core) u16 {
        return self.catalog.relevantCount();
    }
    pub fn gossipScore(self: *Core, peer: t.PeerRef, now: Now) ?f64 {
        const snapshot = self.catalog.get(peer) orelse return null;
        return self.service.gossipsub.inner.scoreSnapshot(
            snapshot.connection orelse return null,
            now,
        );
    }
    pub fn sendReqRespRequest(
        self: *Core,
        engine: *engine_mod.Engine,
        conn: t.Handle,
        protocol: rr.Protocol,
        bytes: []const u8,
        sink: []u8,
        options: rr.reqresp.RequestOptions,
        now: Now,
    ) !rr.RequestHandle {
        if (self.stopped) return error.Stopped;
        if (protocol.isControl()) return error.ControlProtocol;
        return self.service.request(engine, conn, protocol, bytes, sink, options, now);
    }
    pub fn consume(self: *Core, request: rr.RequestHandle, now: Now) bool {
        return self.service.reqresp.consume(request, now);
    }
    pub fn respond(
        self: *Core,
        request: rr.RequestHandle,
        bytes: []const u8,
        fork: ?@import("config").ForkSeq,
        now: Now,
    ) !void {
        try self.service.reqresp.respond(request, bytes, fork, now);
    }
    pub fn respondError(
        self: *Core,
        request: rr.RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) !void {
        try self.service.reqresp.respondError(request, code, message, now);
    }
    pub fn finish(self: *Core, request: rr.RequestHandle, now: Now) bool {
        return self.service.reqresp.finish(request, now);
    }
    pub fn cancel(self: *Core, request: rr.RequestHandle) bool {
        return self.service.reqresp.cancel(request);
    }
    pub fn errorMessage(self: *const Core, request: rr.RequestHandle) []const u8 {
        return self.service.reqresp.errorMessage(request);
    }
    pub fn publishGossip(
        self: *Core,
        topic: []const u8,
        bytes: []const u8,
        now: Now,
    ) !gossip.Gossipsub.PublishOutcome {
        if (self.stopped) return error.Stopped;
        return self.service.gossipsub.publish(topic, bytes, now);
    }
    pub fn subscribe(self: *Core, topic: []const u8) bool {
        if (self.stopped) return false;
        return self.service.gossipsub.subscribe(topic);
    }
    pub fn unsubscribe(self: *Core, topic: []const u8) bool {
        return self.service.gossipsub.unsubscribe(topic);
    }
    pub fn reportValidation(
        self: *Core,
        handle: gossip.ValidationHandle,
        verdict: gossip.Verdict,
        now: Now,
    ) gossip.ReportOutcome {
        return self.service.gossipsub.report(handle, verdict, now);
    }
    pub fn shutdown(self: *Core, engine: *engine_mod.Engine, now: Now) void {
        if (self.stopped) return;
        self.stopped = true;
        self.service.reqresp.shutdownRouted(&self.service.router, engine);
        self.service.router.negotiator.shutdown(engine);
        const count = self.catalog.snapshots(self.snapshot_scratch);
        for (self.snapshot_scratch[0..count]) |snapshot| if (snapshot.connection) |conn| {
            self.control.close(
                &self.service,
                &self.catalog,
                engine,
                snapshot.peer,
                conn,
                .shutdown,
                now,
            );
        };
        self.dial_queue.shutdown(engine);
    }
};
