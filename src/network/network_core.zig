const std = @import("std");
const d = @import("discv5");
const manager = @import("peer_manager.zig");
const service_mod = @import("service.zig");
const transport_mod = @import("transport.zig");
const Engine = @import("quic/Engine.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
const wake_sources = @import("wake_sources.zig");
const control_wire = @import("control_wire.zig");
const control_values = @import("control_values.zig");
const ControlProtocol = @import("control_protocol.zig").ControlProtocol;
pub const wait = @import("wait.zig");

/// Discovery datagrams drained per turn, matching the QUIC receive batch.
pub const discovery_batch_max: u32 = @import("constants.zig").receive_batch_max;
pub const controls_per_turn = 32;
pub const identify_per_turn = 8;
pub const dials_per_turn = 4;
pub const candidates_per_turn = peers.discovery.candidates_per_step;
pub const ForkSchedule = peers.discovery.ForkSchedule;
const advertisement = @import("advertisement.zig");
pub const AdvertisementEndpoints = advertisement.Endpoints;
pub const AdvertisementHints = advertisement.Hints;
pub const LocalUpdate = struct {
    local: t.LocalState,
    schedule: ForkSchedule,
    endpoints: ?AdvertisementEndpoints,
    capabilities: @import("capabilities.zig").Directional,
};
pub const LocalIntent = struct {
    update: LocalUpdate,
    demand: peers.Demand,
    subscriptions: []const gossip.local_intent.Boundary,
    slot: u64 = 0,
};
pub const discovery_session_capacity = peers.discovery.discovery_session_capacity;
pub const discovery_session_idle_timeout_ms = peers.discovery.discovery_session_idle_timeout_ms;
pub const DiscoveryOptions = peers.discovery.Config;
pub const Startup = struct {
    host: *const @import("wire/keys.zig").KeyPair,
    bind: @import("udp").Sockets.Bindings,
    local: t.LocalState,
    schedule: ForkSchedule = .{},
    discovery: ?DiscoveryOptions = null,
    /// The host's wall-clock slot until its first intent.
    slot: u64 = 0,
    /// Peers an earlier run remembered, at most `peers.remembered.capacity`, replayed as paced
    /// automatic candidates. Native drops expired, unusable and duplicate records.
    remembered: []const peers.remembered.Record = &.{},
};
pub const HostProgress = struct {
    /// A per-turn cap stopped the host with work left, so the next turn is due now.
    more: bool = false,
};
/// The owner host seam. `step` calls `apply` after receive, timers and collect and before the
/// protocols run, when the host wake descriptor was readable, the previous call returned
/// `more`, or `deadline_ms` has passed, so the host's work is flushed in the same step.
pub const Host = struct {
    context: ?*anyopaque = null,
    /// Drains the host wake descriptor before reading any host queue, so a submission that
    /// lands after the drain wakes the next poll. Must not read `transportEvents()`.
    apply: ?*const fn (context: *anyopaque, core: *NetworkCore, now: Now) HostProgress = null,
    /// Earliest host-owned deadline, kept by the host without scanning its queues.
    deadline_ms: ?u64 = null,

    /// A host with no queued work that only bounds the wait.
    pub fn deadlineOnly(deadline_ms: ?u64) Host {
        return .{ .deadline_ms = deadline_ms };
    }
};
pub const Outputs = struct {
    peers: []t.Event = &.{},
    application: []rr.ReqResp.Event = &.{},
};
pub const OperationalError = transport_mod.StepError || transport_mod.DialError || peers.discovery.Error || wait.Error;
pub const Counts = struct { peers: usize, application: usize };
pub const Result = struct {
    counts: Counts = .{ .peers = 0, .application = 0 },
    transport: transport_mod.StepResult,
    readiness: wait.Result = .{},
    /// Only the discovery sockets had work, so the transport and protocols did not run.
    discovery_only: bool = false,
    failure: ?OperationalError = null,
    dial_started: u8 = 0,
    dial_deferred: u8 = 0,
    dial_failed: u8 = 0,
};
/// Dials the owner started or deferred, which the health log reports, and failed clock reads,
/// transport steps and readiness polls.
pub const Counters = struct {
    dial_started: u64 = 0,
    dial_deferred: u64 = 0,
    transport_failures: u64 = 0,
    readiness_failures: u64 = 0,
};

/// Initialize at its final address. Serialize every call, including reads and teardown.
pub const NetworkCore = struct {
    reservations: @import("reservations.zig").Reservations,
    allocator: std.mem.Allocator,
    transport: transport_mod.Transport,
    peer_manager: manager.PeerManager,
    control_protocol: ControlProtocol,
    service: service_mod.Service,
    discovery: ?*peers.Discovery,
    native_events: []Engine.Event,
    native_event_count: usize = 0,
    local_intent_workspace: *gossip.local_intent.Workspace,
    schedule: ForkSchedule,
    counters: Counters = .{},
    step_duration: @import("metrics/timing.zig").Duration = .{},
    /// Zero-wait turns, counted under every source already due; readiness tests and the idle
    /// benchmarks read them to show an idle owner does not spin.
    due_now_turns: [wake_sources.source_count]u64 = @splat(0),
    last_now: Now,
    initialized: bool = false,
    host_wake: ?i32 = null,
    /// The host's wall-clock slot for status validation. Intents only advance it.
    current_slot: u64 = 0,
    /// The last host apply stopped at a per-turn cap.
    host_more: bool = false,
    /// The Service's control events and Identify results that `process` consumes within its turn.
    /// Fields rather than locals so ReleaseSafe does not fill them every turn.
    controls: [controls_per_turn]rr.ReqResp.Event = undefined,
    identify_results: [identify_per_turn]@import("identify/root.zig").Result = undefined,

    pub fn init(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, resolved: *const @import("configuration.zig").Resolved, startup: Startup) !void {
        try @import("configuration.zig").validate(resolved.limits, resolved.core);
        try resolved.socket_buffers.validate();
        if (!wait.supported) return error.UnsupportedWait;
        if (startup.remembered.len > peers.remembered.capacity) return error.InvalidOptions;
        var local: t.LocalState = undefined;
        try control_values.copyServingLocal(&local, &startup.local, @import("router.zig").Router.initialCapabilities(resolved.core.service.router).receive);
        try validateSchedule(&local, startup.schedule);
        try validateForkTable(resolved.core.service.reqresp.forks, &local.fork);
        self.initialized = false;
        self.reservations = .{ .backing = backing, .byte_limit = resolved.byte_limit };
        errdefer std.debug.assert(self.reservations.bytes == 0);
        const allocator = self.reservations.allocator();
        self.allocator = allocator;
        self.schedule = startup.schedule;
        self.counters = .{};
        self.step_duration = .{};
        self.due_now_turns = @splat(0);
        self.host_wake = null;
        self.current_slot = startup.slot;
        self.host_more = false;
        self.native_event_count = 0;
        self.discovery = null;
        self.last_now = try transport_mod.currentTime(io);
        try self.transport.init(allocator, io, .{ .host = startup.host, .bind = startup.bind, .limits = resolved.limits, .work_limits = resolved.work_limits, .socket_buffers = resolved.socket_buffers.quic });
        errdefer self.transport.deinit(io);
        if (startup.discovery) |discovery_options| {
            const owned = try allocator.create(peers.Discovery);
            errdefer allocator.destroy(owned);
            try owned.init(allocator, io, discovery_options, resolved.socket_buffers.discovery, startup.host, &local, startup.schedule, self.transport.sockets.localAddresses(), self.last_now.mono_ms);
            self.discovery = owned;
        }
        errdefer if (self.discovery) |owned| {
            owned.deinit(io);
            allocator.destroy(owned);
        };
        var service_options = resolved.core.service;
        service_options.reqresp.request_fork = local.fork.fork;
        const identify_base = try service_options.identify.makeLocal(&self.transport.peerId(), &self.transport.sockets.localAddresses());
        const identify_local = try prepareIdentifyLocal(&identify_base, self.advertisementEndpoints(), @import("router.zig").Router.initialCapabilities(service_options.router));
        self.service = try service_mod.Service.init(allocator, service_options, &identify_local);
        errdefer self.service.deinit();
        self.peer_manager = try manager.PeerManager.init(allocator, &self.transport.peerId(), &local, resolved.core.peerManager(), self.service.router.capabilities().receive, self.transport.engine.limits.connections_max);
        errdefer self.peer_manager.deinit();
        const peer_capacity: u16 = @intCast(self.peer_manager.catalog.rows.len);
        self.control_protocol = try ControlProtocol.init(allocator, peer_capacity, resolved.core.peers.max_peers, self.service.reqresp.serving.control_reserved);
        errdefer self.control_protocol.deinit(allocator);
        self.peer_manager.loadRemembered(startup.remembered, self.last_now);
        self.service.gossipsub.clock = io;
        self.native_events = try allocator.alloc(Engine.Event, @import("quic/limits.zig").events_per_turn_max);
        errdefer allocator.free(self.native_events);
        self.local_intent_workspace = try allocator.create(gossip.local_intent.Workspace);
        errdefer allocator.destroy(self.local_intent_workspace);
        self.local_intent_workspace.* = try gossip.local_intent.Workspace.init(allocator, self.service.gossipsub.overlay.rows.len);
        errdefer self.local_intent_workspace.deinit(allocator);
        self.initialized = true;
    }

    pub fn deinit(self: *NetworkCore, io: std.Io) void {
        if (!self.initialized) return;
        self.shutdown(self.last_now);
        if (self.discovery) |owned| {
            owned.deinit(io);
            self.allocator.destroy(owned);
        }
        self.local_intent_workspace.deinit(self.allocator);
        self.allocator.destroy(self.local_intent_workspace);
        self.service.deinit();
        self.control_protocol.deinit(self.allocator);
        self.peer_manager.deinit();
        self.allocator.free(self.native_events);
        self.transport.deinit(io);
        std.debug.assert(self.reservations.bytes == 0);
        self.initialized = false;
    }
    pub fn shutdown(self: *NetworkCore, now: Now) void {
        self.host_wake = null;
        self.last_now = now;
        const pm = &self.peer_manager;
        if (pm.stop()) {
            self.service.shutdown(&self.transport.engine);
            const count = pm.catalog.snapshots(pm.snapshot_scratch);
            for (pm.snapshot_scratch[0..count]) |snapshot| if (snapshot.connection) |conn| {
                self.closeConnection(snapshot.peer, conn, .shutdown, now);
            };
            pm.dialing.shutdown(&pm.catalog, &self.transport.engine, now.mono_ms);
        }
        if (self.discovery) |owned| owned.cancel();
        self.transport.engine.shutdownAll();
    }
    pub fn isClosed(self: *const NetworkCore) bool {
        return self.peer_manager.stopped and self.transport.engine.resourceSnapshot().active == 0;
    }
    pub fn peerId(self: *const NetworkCore) t.PeerId {
        return self.transport.peerId();
    }
    pub fn localMultiaddr(self: *const NetworkCore) @import("wire/multiaddr.zig").Multiaddr {
        return self.transport.localMultiaddr();
    }
    pub fn localRecord(self: *const NetworkCore) ?*const d.identity.enr.Record {
        return if (self.discovery) |owned| owned.localRecord() else null;
    }
    pub fn advertisementEndpoints(self: *const NetworkCore) ?AdvertisementEndpoints {
        return if (self.discovery) |owned| owned.endpoints else null;
    }
    pub fn localState(self: *const NetworkCore) t.LocalState {
        return self.peer_manager.local;
    }
    pub fn peerCounts(self: *const NetworkCore) manager.PeerManager.PeerCounts {
        return self.peer_manager.peerCounts();
    }
    pub fn connectUntil(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now, deadline_ms: u64) !void {
        try self.peer_manager.connectUntil(identity, addresses, now, deadline_ms);
    }
    pub fn cancelConnect(self: *NetworkCore, identity: *const t.PeerId, now: Now) void {
        self.peer_manager.cancelConnect(&self.transport.engine, identity, now);
    }
    pub fn addDirectPeer(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now) !void {
        if (try self.peer_manager.addDirectPeer(identity, addresses, now)) |conn| self.service.gossipsub.markDirect(conn);
    }
    pub fn removeDirectPeer(self: *NetworkCore, identity: *const t.PeerId) bool {
        if (!self.peer_manager.removeDirectPeer(identity)) return false;
        self.service.gossipsub.unmarkDirect(identity);
        return true;
    }
    pub fn directPeers(self: *const NetworkCore, out: []t.PeerId) error{OutputTooSmall}!usize {
        return self.peer_manager.directPeers(out);
    }
    pub fn isConnected(self: *const NetworkCore, identity: *const t.PeerId) bool {
        const peer = self.peer_manager.catalog.find(identity) orelse return false;
        return self.peer_manager.catalog.rowFor(peer).?.connection != null;
    }
    pub fn closePeer(self: *NetworkCore, identity: *const t.PeerId, now: Now) bool {
        const peer = self.peer_manager.catalog.find(identity) orelse return false;
        const connection = self.peer_manager.catalog.rowFor(peer).?.connection orelse return false;
        if (self.peer_manager.stopped) return false;
        self.closeConnection(peer, connection, .host, now);
        self.peer_manager.cancelConnect(&self.transport.engine, identity, now);
        return true;
    }
    pub fn reStatusPeer(self: *NetworkCore, identity: *const t.PeerId, now: Now) bool {
        const peer = self.peer_manager.catalog.find(identity) orelse return false;
        const connection = self.peer_manager.catalog.rowFor(peer).?.connection orelse return false;
        return self.peer_manager.reStatusPeer(peer, connection, now);
    }
    pub fn reportPeer(self: *NetworkCore, identity: *const t.PeerId, action: t.PeerAction, now: Now) ?t.ReputationDecision {
        const peer = self.peer_manager.catalog.find(identity) orelse return null;
        return self.peer_manager.reportPeer(peer, action, now);
    }
    pub fn updateStatus(self: *NetworkCore, status: *const t.Status) !void {
        if (self.peer_manager.stopped) return error.Stopped;
        try self.peer_manager.updateStatus(self.service.router.capabilities().receive, status);
    }
    pub fn sendReqRespRequest(self: *NetworkCore, identity: *const t.PeerId, protocol: rr.Protocol, request: []const u8, sink: []u8, options: rr.ReqResp.RequestOptions, now: Now) !rr.ReqResp.RequestHandle {
        const peer = self.peer_manager.catalog.find(identity) orelse return error.StalePeer;
        const snapshot = self.peer_manager.catalog.get(peer) orelse return error.StalePeer;
        const conn = snapshot.connection orelse return error.Disconnected;
        if (self.peer_manager.stopped or self.peer_manager.quiescing) return error.Stopped;
        if (protocol.isControl()) return error.ControlProtocol;
        return self.service.request(&self.transport.engine, conn, protocol, request, sink, options, now);
    }
    pub fn consume(self: *NetworkCore, request: rr.ReqResp.RequestHandle, now: Now) bool {
        return self.service.reqresp.consume(request, now);
    }
    pub fn respond(self: *NetworkCore, request: rr.ReqResp.RequestHandle, bytes: []const u8, context: ?rr.ReqResp.ForkEntry, now: Now) !void {
        try self.service.reqresp.respond(request, bytes, context, now);
    }
    pub fn respondError(self: *NetworkCore, request: rr.ReqResp.RequestHandle, code: u8, message: []const u8, now: Now) !void {
        try self.service.reqresp.respondError(request, code, message, now);
    }
    pub fn finish(self: *NetworkCore, request: rr.ReqResp.RequestHandle, now: Now) bool {
        return self.service.reqresp.finish(request, now);
    }
    pub fn cancel(self: *NetworkCore, request: rr.ReqResp.RequestHandle) bool {
        return self.service.reqresp.cancel(request);
    }
    pub fn errorMessage(self: *const NetworkCore, request: rr.ReqResp.RequestHandle) []const u8 {
        return self.service.reqresp.errorMessage(request);
    }

    pub fn publishGossipWithOptions(self: *NetworkCore, topic: []const u8, bytes: []const u8, options: gossip.Gossipsub.PublishOptions, now: Now) !gossip.Gossipsub.PublishOutcome {
        if (self.peer_manager.stopped or self.peer_manager.quiescing) return error.Stopped;
        return self.service.gossipsub.publishWithOptions(topic, bytes, options, now);
    }
    pub fn reportValidation(self: *NetworkCore, handle: gossip.ValidationHandle, verdict: gossip.Verdict, now: Now) gossip.ReportOutcome {
        return self.service.gossipsub.report(handle, verdict, now);
    }
    /// Borrows the last step's authenticated transport events until the next step.
    pub fn transportEvents(self: *const NetworkCore) []const Engine.Event {
        return self.native_events[0..self.native_event_count];
    }
    pub fn completeSnapshots(self: *const NetworkCore, out: []t.Snapshot) error{OutputTooSmall}!usize {
        if (out.len < self.peer_manager.catalog.options.capacity) return error.OutputTooSmall;
        return self.peer_manager.snapshots(out);
    }
    /// Refreshes the remembered records of connections that qualify now and copies every
    /// unexpired record. The host persists them for the next start.
    pub fn rememberedPeers(self: *NetworkCore, now: Now, out: []peers.remembered.Record) error{OutputTooSmall}!usize {
        if (out.len < peers.remembered.capacity) return error.OutputTooSmall;
        return self.peer_manager.rememberedPeers(now, out);
    }
    /// Quiesces applications and closes every connection gracefully, sending Goodbye while
    /// control progress continues.
    pub fn beginGracefulClose(self: *NetworkCore, now: Now) void {
        const pm = &self.peer_manager;
        if (!pm.quiesce(now)) return;
        self.service.quiesceApplications();
        var active = self.service.router.active_capabilities;
        active.receive = .initEmpty();
        self.service.router.setCapabilities(active);
    }

    fn updateLocalWithEndpoints(self: *NetworkCore, desired: *const t.LocalState, schedule: ForkSchedule, endpoints: ?AdvertisementEndpoints, now: Now) !bool {
        return self.applyLocal(&.{
            .local = desired.*,
            .schedule = schedule,
            .endpoints = endpoints,
            .capabilities = self.service.router.capabilities(),
        }, now);
    }

    fn prepareIdentifyLocal(base: *const @import("identify/root.zig").Local, endpoints: ?AdvertisementEndpoints, capabilities: @import("capabilities.zig").Directional) !@import("identify/root.zig").Local {
        var local = base.*;
        if (endpoints) |announced| {
            var addresses: [2]t.Address = undefined;
            var count: usize = 0;
            if (announced.ip4) |ip| if (announced.quic) |port| {
                addresses[count] = .{ .ip4 = .{ .octets = ip, .port = port } };
                count += 1;
            };
            if (announced.ip6) |ip| if (announced.quic6) |port| {
                addresses[count] = .{ .ip6 = .{ .octets = ip, .port = port } };
                count += 1;
            };
            try local.setAddresses(addresses[0..count]);
        }
        var encoded: [@import("identify/codec.zig").frame_max + 2]u8 = undefined;
        _ = try local.encode(capabilities.receive, null, &encoded);
        return local;
    }

    const PreparedLocal = struct {
        local: t.LocalState,
        schedule: ForkSchedule,
        endpoints: ?AdvertisementEndpoints,
        capabilities: @import("capabilities.zig").Directional,
        identify: @import("identify/root.zig").Local,
        record: ?peers.Discovery.PreparedAdvertisement = null,
        changed: bool,
    };

    fn prepareLocal(self: *const NetworkCore, update: *const LocalUpdate) !PreparedLocal {
        if (self.peer_manager.stopped) return error.Stopped;
        const schedule = update.schedule;
        const endpoints = update.endpoints;
        const capabilities = update.capabilities;
        try self.service.router.validateCapabilities(capabilities);
        if ((endpoints == null) != (self.discovery == null)) return error.InvalidAdvertisement;
        if (endpoints) |value| {
            try self.discovery.?.validateEndpoints(value);
        }
        var local = update.local;
        local.metadata.seq_number = self.peer_manager.local.metadata.seq_number;
        try control_values.copyServingLocal(&local, &local, capabilities.receive);
        try validateSchedule(&local, schedule);
        const request = &self.service.reqresp;
        try validateForkTable(request.forks[0..request.fork_count], &local.fork);
        const identify_local = try prepareIdentifyLocal(&self.service.identify.local, endpoints, capabilities);
        const metadata_changed = !std.meta.eql(local.metadata, self.peer_manager.local.metadata);
        if (metadata_changed) local.metadata.seq_number = try peers.enr.nextSequence(local.metadata.seq_number);
        var prepared: PreparedLocal = .{
            .local = local,
            .schedule = schedule,
            .endpoints = endpoints,
            .capabilities = capabilities,
            .identify = identify_local,
            .changed = !(std.meta.eql(local, self.peer_manager.local) and std.meta.eql(schedule, self.schedule) and
                std.meta.eql(endpoints, self.advertisementEndpoints()) and std.meta.eql(capabilities, self.service.router.capabilities())),
        };
        if (prepared.changed) if (self.discovery) |owned| {
            const announced = advertisementFor(&local, schedule, endpoints.?);
            const previous = advertisementFor(&self.peer_manager.local, self.schedule, owned.endpoints);
            if (!std.meta.eql(announced, previous)) {
                prepared.record = try owned.prepareAdvertisement(&announced, &local.fork);
            }
        };
        return prepared;
    }

    fn publishLocal(self: *NetworkCore, prepared: *const PreparedLocal) !void {
        if (prepared.record) |*record| try self.discovery.?.installAdvertisement(record);
    }

    fn commitLocal(self: *NetworkCore, prepared: *const PreparedLocal, now: Now) void {
        std.debug.assert(prepared.changed);
        if (self.discovery) |owned| {
            owned.commitLocal(prepared.endpoints.?, &prepared.local.fork);
        }
        self.service.identify.local = prepared.identify;
        self.service.router.setCapabilities(prepared.capabilities);
        const pm = &self.peer_manager;
        if (!std.meta.eql(pm.local.fork, prepared.local.fork)) {
            for (0..pm.control.schedules.len) |index| {
                const stale = pm.revalidateConnection(index, now) orelse continue;
                self.control_protocol.cancel(&self.service.reqresp, stale.peer, stale.conn);
            }
        }
        pm.commitLocal(&prepared.local, now);
        self.service.reqresp.setRequestFork(prepared.local.fork.fork);
        self.schedule = prepared.schedule;
    }

    /// Prepares every owner before ENR publication; caller sequence input is ignored.
    fn applyLocal(self: *NetworkCore, update: *const LocalUpdate, now: Now) !bool {
        const prepared = try self.prepareLocal(update);
        if (!prepared.changed) return false;
        try self.publishLocal(&prepared);
        self.commitLocal(&prepared, now);
        return true;
    }

    /// Applies a complete copied subscription union in this serialized call without ending event borrows.
    /// Records the intent's slot as the current slot unless it would move backwards.
    pub fn applyIntent(self: *NetworkCore, intent: *const LocalIntent, now: Now) !bool {
        const prepared = try self.prepareLocal(&intent.update);
        const demand = intent.demand;
        try demand.validate(&prepared.local.fork, self.peer_manager.catalog.options.max_peers);
        const topics_changed = try self.service.gossipsub.prepareSubscriptions(intent.subscriptions, self.local_intent_workspace, now, intent.slot);
        const demand_changed = !std.meta.eql(demand, self.peer_manager.demand);
        const changed = prepared.changed or topics_changed or demand_changed;
        try self.publishLocal(&prepared);
        if (prepared.changed) self.commitLocal(&prepared, now);
        self.service.gossipsub.commitSubscriptions(self.local_intent_workspace);
        if (demand_changed) self.peer_manager.commitDemand(&demand);
        self.current_slot = @max(self.current_slot, intent.slot);
        if (changed) std.log.scoped(.network_core).debug("intent_applied local_changed={any} topics_changed={any} demand_changed={any} subscriptions={d} fork={s} digest={x}", .{ prepared.changed, topics_changed, demand_changed, intent.subscriptions.len, @tagName(prepared.local.fork.fork), prepared.local.fork.digest });
        return changed;
    }

    /// Borrows a readable OS descriptor. The host drains it after a returned
    /// readiness.host indication and detaches before closing or reusing it.
    /// Shutdown/deinit detach without draining or closing caller storage.
    pub fn setHostWake(self: *NetworkCore, descriptor: ?i32) error{ UnsupportedWait, InvalidWakeSource, Stopped }!void {
        if (descriptor) |fd| {
            if (self.peer_manager.stopped) return error.Stopped;
            if (!wait.supported) return error.UnsupportedWait;
            if (comptime wait.supported) {
                if (fd < 0) return error.InvalidWakeSource;
                for (self.transport.sockets.handles()) |socket| if (socket == fd) return error.InvalidWakeSource;
                if (self.discovery) |owned| for (owned.transport.sockets.handles()) |socket| if (socket == fd) return error.InvalidWakeSource;
            }
        }
        self.host_wake = descriptor;
    }

    /// The earliest wakeup of every source except host-owned deadlines, which only the host knows.
    pub fn nextWakeup(self: *NetworkCore, now: Now, outputs: Outputs) ?u64 {
        var wakeups: wake_sources.Wakeups = .{};
        self.collectWakeups(now, outputs, &wakeups);
        return wakeups.earliest();
    }

    fn collectWakeups(self: *NetworkCore, now: Now, outputs: Outputs, wakeups: *wake_sources.Wakeups) void {
        const pm = &self.peer_manager;
        wakeups.note(.peer_events, pm.peerWakeup(now, outputs.peers.len));
        if (!pm.stopped) {
            const application = if (pm.quiescing) 0 else outputs.application.len;
            self.service.collectWakeups(now, .{ .application = application, .control = controls_per_turn, .identify = identify_per_turn }, wakeups);
            wakeups.note(.control, pm.controlWakeup(now));
        }
        if (!pm.stopped and !pm.quiescing) {
            wakeups.note(.dial, pm.dialing.nextWakeup(&pm.catalog, now.mono_ms, @min(dials_per_turn, pm.dialRoom())));
            wakeups.note(.dial, if (pm.dialing.selectionNeeded(&pm.catalog)) now.mono_ms else null);
            wakeups.note(.dial, pm.dialing.selection_deadline);
            wakeups.note(.peer_policy, pm.policyWakeup(self.service.gossipsub, now));
            wakeups.note(.peer_policy, pm.reconciliation_deadline);
            wakeups.note(.peer_policy, if (pm.custody_pending) now.mono_ms +| 1 else null);
        }
        const quic = &self.transport.engine;
        if (quic.backlog()) wakeups.note(.transport_backlog, now.mono_ms);
        if (quic.eventsPending()) wakeups.note(.transport_events, now.mono_ms);
        if (quic.nextDeadlineNs()) |deadline| wakeups.note(.transport_timer, ceilMs(deadline));
        if (!self.peer_manager.quiescing) if (self.discovery) |owned| wakeups.note(.discovery, owned.nextWakeup(now.mono_ms));
        if (self.host_more) wakeups.note(.host, now.mono_ms);
    }

    fn observeWait(self: *NetworkCore, wakeups: *const wake_sources.Wakeups, now_ms: u64, chosen_wait: u32) void {
        if (chosen_wait != 0) return;
        for (wakeups.due, &self.due_now_turns) |deadline, *turns| {
            const value = deadline orelse continue;
            if (value <= now_ms) turns.* +|= 1;
        }
    }

    /// One Service borrow window per turn. Returned counts remain valid even when failure is set.
    /// A turn waits for the earliest wakeup of any source, host deadlines included, bounded by
    /// the readiness backstop. It then receives, expires timers, collects engine events, applies
    /// host work, runs the protocols, discovery and dials, and flushes, so its own output and the
    /// host's leave in the same turn. When only discovery has work, the turn drains discovery alone.
    pub fn step(self: *NetworkCore, io: std.Io, now: Now, outputs: Outputs, host: Host) Result {
        self.last_now = now;
        var result: Result = .{ .transport = .{ .now = now } };
        var wakeups: wake_sources.Wakeups = .{};
        self.collectWakeups(now, outputs, &wakeups);
        wakeups.note(.host, host.deadline_ms);
        const chosen_wait: u32 = if (self.peer_manager.stopped) 0 else if (wakeups.earliest()) |earliest|
            @intCast(@min(earliest -| now.mono_ms, wait.native_wait_max_ms))
        else
            wait.native_wait_max_ms;
        if (!self.peer_manager.stopped) self.observeWait(&wakeups, now.mono_ms, chosen_wait);
        if (comptime wait.supported) {
            result.readiness = wait.poll(io, .{
                .quic = self.transport.sockets.handles(),
                .discovery = if (!self.peer_manager.quiescing and self.discovery != null) self.discovery.?.transport.sockets.handles() else .{ null, null },
                .host = self.host_wake,
            }, chosen_wait);
        } else result.readiness.failure = error.UnsupportedWait;
        self.counters.readiness_failures +|= @intFromBool(result.readiness.failure != null);
        result.failure = result.readiness.failure;
        const step_start = @import("metrics/timing.zig").now(io);
        defer self.step_duration.observe(@import("metrics/timing.zig").now(io) -| step_start);
        const read = transport_mod.currentTime(io) catch |err| blk: {
            result.failure = result.failure orelse err;
            self.counters.transport_failures +|= 1;
            break :blk now;
        };
        const tick: Now = if (read.mono_ms >= now.mono_ms) read else now;
        self.last_now = tick;
        result.transport.now = tick;
        if (self.discoveryOnly(&result.readiness, tick, outputs, host)) {
            result.discovery_only = true;
            // The previous turn's events were consumed by its caller; this turn reports none.
            self.native_event_count = 0;
            self.discover(io, tick, &result);
            return result;
        }
        self.transport.engine.releaseReported();
        // A failed poll reports no readiness, so both sockets are drained anyway.
        const quic: [2]bool = if (result.readiness.failure == null) result.readiness.quic else @splat(true);
        if (quic[0] or quic[1]) {
            self.transport.receive(io, &result.transport, quic) catch |err| {
                result.failure = result.failure orelse err;
                self.counters.transport_failures +|= 1;
            };
        }
        self.transport.expire(tick);
        result.transport.events = self.transport.collect(tick, self.native_events);
        result.transport.events_pending = self.transport.engine.eventsPending();
        self.native_event_count = result.transport.events;
        if (host.apply) |apply| {
            const due = if (host.deadline_ms) |deadline| deadline <= tick.mono_ms else false;
            if (result.readiness.host or result.readiness.failure != null or self.host_more or due) {
                self.host_more = apply(host.context.?, self, tick).more;
            }
        } else self.host_more = false;
        result.counts = self.process(self.native_events[0..result.transport.events], tick, outputs);
        if (!self.peer_manager.stopped and !self.peer_manager.quiescing and (result.failure == null or result.failure.? != error.Canceled)) {
            // This turn's coverage selection already ran, without a second protocol pump.
            if (self.discovery != null) self.discover(io, tick, &result);
            var intents: [dials_per_turn]manager.DialIntent = undefined;
            const room = self.transport.engine.limits.dialing_max -| self.transport.engine.resourceSnapshot().dialing;
            const count = self.peer_manager.dialIntents(self.service.gossipsub, &self.transport.engine, tick, intents[0..@min(room, intents.len)]);
            for (intents[0..count], 0..) |intent, index| {
                const handle = self.transport.dialPeer(io, intent.address, intent.peer) catch |err| {
                    if (err == error.DestinationUnreachable) {
                        std.log.scoped(.network_core).debug("dial_failed peer={f} endpoint={any} reason={s}", .{ @import("logging.zig").peer(&intent.peer), intent.address, @errorName(err) });
                        std.debug.assert(self.peer_manager.dialFailed(intent.token, tick));
                        result.dial_failed += 1;
                    } else {
                        std.log.scoped(.network_core).debug("dial_deferred peer={f} endpoint={any} reason={s}", .{ @import("logging.zig").peer(&intent.peer), intent.address, @errorName(err) });
                        std.debug.assert(self.peer_manager.dialDeferred(intent.token, tick));
                        result.dial_deferred += 1;
                        result.failure = result.failure orelse err;
                    }
                    if (err == error.Canceled) {
                        for (intents[index + 1 .. count]) |pending| {
                            std.debug.assert(self.peer_manager.dialDeferred(pending.token, tick));
                            result.dial_deferred += 1;
                        }
                        result.failure = err;
                        break;
                    }
                    continue;
                };
                std.debug.assert(self.peer_manager.dialStarted(intent.token, handle));
                std.log.scoped(.network_core).debug("dial_started peer={f} endpoint={any} connection={d}:{d}", .{ @import("logging.zig").peer(&intent.peer), intent.address, handle.index, handle.generation });
                result.dial_started += 1;
            }
            self.counters.dial_started +|= result.dial_started;
            self.counters.dial_deferred +|= result.dial_deferred;
        }
        if ((result.failure == null or result.failure.? != error.Canceled)) self.transport.flush(io, tick, &result.transport) catch |err| {
            result.failure = err;
            self.counters.transport_failures +|= 1;
        };
        return result;
    }

    /// Delivers the turn's transport events, runs the one Service pass, applies its faults and
    /// control results, runs due control maintenance, then advances custody and selection.
    /// Application borrows stay valid until the next turn; closes after publication clean up
    /// without a second recycling pass.
    fn process(self: *NetworkCore, events: []const Engine.Event, now: Now, outputs: Outputs) Counts {
        std.debug.assert(events.len <= @import("quic/limits.zig").events_per_turn_max);
        const pm = &self.peer_manager;
        const quic = &self.transport.engine;
        if (pm.stopped) return .{
            .peers = pm.catalog.pollEvents(outputs.peers),
            .application = 0,
        };
        if (!pm.quiescing) pm.dialing.expire(&pm.catalog, quic, now.mono_ms);
        for (events) |*event| self.transportEvent(event, now);
        const controls = &self.controls;
        const identify_results = &self.identify_results;
        const counts = self.service.process(quic, events, now, .{ .application = outputs.application, .control = controls, .identify = identify_results });
        for ([_][]const rr.ReqResp.Event{ outputs.application[0..counts.application], controls[0..counts.control] }) |batch| {
            for (batch) |event| {
                const fault = self.service.reqresp.peerFault(event) orelse continue;
                const peer = pm.catalog.find(fault.identity) orelse continue;
                switch (fault.kind) {
                    .protocol => _ = pm.reportPeer(peer, .low_tolerance, now),
                    .non_completion => {
                        _ = pm.catalog.nonCompletion(peer, now.mono_ms);
                        pm.selection_revision = null;
                    },
                }
            }
        }
        pm.identified(identify_results[0..counts.identify]);
        self.controlEvents(controls[0..counts.control], now);
        self.maintainControl(now);
        if (pm.quiescing) return .{ .peers = pm.catalog.pollEvents(outputs.peers), .application = counts.application };
        var budget: u16 = peers.custody.hashes_per_turn;
        pm.custody_pending = pm.catalog.advanceCustody(&pm.local.fork, now.mono_ms, pm.metadata_freshness_ms, &budget);
        pm.counters.custody_hashes +|= peers.custody.hashes_per_turn - budget;
        pm.reconcile(self.service.gossipsub, now);
        pm.transportProgress(quic);
        return .{
            .peers = pm.catalog.pollEvents(outputs.peers),
            .application = counts.application,
        };
    }

    fn transportEvent(self: *NetworkCore, event: *const Engine.Event, now: Now) void {
        const pm = &self.peer_manager;
        const quic = &self.transport.engine;
        switch (event.*) {
            .connected => |*connected| {
                if (pm.quiescing) {
                    _ = quic.close(connected.conn, 0);
                    return;
                }
                const endpoint = quic.peerAddress(connected.conn) orelse return;
                pm.transportProgress(quic);
                const admission = pm.admit(connected, endpoint, now) orelse {
                    _ = quic.close(connected.conn, 0);
                    return;
                };
                if (admission.displaced) |old| {
                    self.control_protocol.cancelConnection(&self.service.reqresp, &self.service.router, quic, admission.peer, old);
                    self.service.gossipsub.retireConnection(&self.service.router, quic, old, now);
                    _ = quic.close(old, 0);
                }
                _ = self.service.gossipsub.peerConnected(quic, connected.conn, pm.catalog.rowFor(admission.peer).?.direct, now);
            },
            .closed => |*closed| {
                const goodbye = if (pm.catalog.findConnection(closed.conn) != null)
                    self.service.reqresp.closingGoodbye(quic, &self.service.router, closed.conn, now)
                else
                    null;
                const retired = pm.transportClosed(closed, goodbye, now) orelse return;
                self.releaseConnection(retired, now);
            },
            .path_changed => |*changed| if (pm.catalog.findConnection(changed.conn)) |peer| {
                _ = pm.catalog.updateEndpoint(peer, changed.conn, &changed.peer);
            },
            else => {},
        }
    }

    /// Peer policy settles all evidence and retry consequences before I/O releases the connection.
    fn closeConnection(self: *NetworkCore, peer: t.PeerRef, conn: t.Handle, reason: t.DisconnectReason, now: Now) void {
        const retired = self.peer_manager.retireConnection(peer, conn, reason, now) orelse return;
        self.releaseConnection(retired, now);
    }
    fn releaseConnection(self: *NetworkCore, retired: manager.PeerManager.Retired, now: Now) void {
        const quic = &self.transport.engine;
        self.control_protocol.cancelConnection(&self.service.reqresp, &self.service.router, quic, retired.peer, retired.conn);
        self.service.gossipsub.retireConnection(&self.service.router, quic, retired.conn, now);
        _ = quic.close(retired.conn, 0);
    }

    /// Routes one turn's control events. Peer control applies each request or reply before the
    /// control protocol answers, consumes or retires it. Each observed result settles before
    /// another policy evaluation.
    fn controlEvents(self: *NetworkCore, batch: []const rr.ReqResp.Event, now: Now) void {
        const pm = &self.peer_manager;
        const requests = &self.control_protocol;
        const reqresp = &self.service.reqresp;
        for (batch) |*event| switch (event.*) {
            .request => |*request| {
                const peer = pm.controlRequested(request, now, self.current_slot) orelse {
                    _ = reqresp.cancel(request.request);
                    continue;
                };
                requests.respond(reqresp, peer, request, &pm.local, now);
            },
            else => {
                const index = requests.result(reqresp, event.*, now) orelse continue;
                const reply = requests.operations[index].reply();
                pm.controlReplied(&reply, event.*, now, self.current_slot);
                requests.settle(reqresp, &self.service.router, &self.transport.engine, index, event.*, now);
            },
        };
    }

    /// Executes the due control work in peer control's order: a close, or an Identify start and
    /// a control request start, each recorded before the schedule is rekeyed.
    fn maintainControl(self: *NetworkCore, now: Now) void {
        const pm = &self.peer_manager;
        const requests = &self.control_protocol;
        const quic = &self.transport.engine;
        var pass = pm.beginControl(now);
        while (pm.nextControl(&pass, now)) |*due| {
            if (due.close) |reason| {
                self.closeConnection(due.peer, due.conn, reason, now);
                continue;
            }
            const identified = if (due.identify) blk: {
                self.service.identify.start(&self.service.router, quic, due.peer, due.conn, now) catch break :blk false;
                break :blk true;
            } else false;
            const request = if (due.request) |*probe|
                requests.start(&self.service.reqresp, &self.service.router, quic, due.peer, due.conn, probe, &pm.local, now)
            else
                null;
            pm.controlStarted(due, identified, request, now);
        }
    }

    /// A turn drains discovery alone when discovery is readable or due, the QUIC sockets and the
    /// host are not readable, and every other source, re-read at the post-poll time, is in the future.
    fn discoveryOnly(self: *NetworkCore, readiness: *const wait.Result, tick: Now, outputs: Outputs, host: Host) bool {
        if (readiness.quicReady() or readiness.host or readiness.failure != null) return false;
        if (self.discovery == null or self.peer_manager.stopped or self.peer_manager.quiescing) return false;
        var wakeups: wake_sources.Wakeups = .{};
        self.collectWakeups(tick, outputs, &wakeups);
        wakeups.note(.host, host.deadline_ms);
        const discovery_slot = &wakeups.due[@intFromEnum(wake_sources.Source.discovery)];
        const discovery_due = if (discovery_slot.*) |deadline| deadline <= tick.mono_ms else false;
        if (!readiness.discoveryReady() and !discovery_due) return false;
        discovery_slot.* = null;
        const earliest = wakeups.earliest() orelse return true;
        return earliest > tick.mono_ms;
    }

    /// Steps discovery once per datagram, up to discovery_batch_max, handling each step's
    /// candidates and learned endpoints before the next. Admission runs before decode as always.
    fn discover(self: *NetworkCore, io: std.Io, tick: Now, result: *Result) void {
        const owned = self.discovery.?;
        const need = self.peer_manager.discoveryNeed();
        owned.request(need.query(tick.mono_ms +| 1_000), tick.mono_ms) catch unreachable;
        const candidates = &owned.candidates;
        var eligible: [2]bool = if (result.readiness.failure == null) result.readiness.discovery else @splat(true);
        for (0..discovery_batch_max) |_| {
            const progress = owned.stepReady(io, tick.mono_ms, &eligible, candidates) catch |err| peers.discovery.Result{ .failure = err };
            const endpoints = owned.learnedEndpoints(progress.learned);
            if (!std.meta.eql(endpoints, owned.endpoints)) {
                _ = self.updateLocalWithEndpoints(&self.peer_manager.local, self.schedule, endpoints, tick) catch |err| {
                    std.log.scoped(.network_discovery).warn("endpoint_update_failed reason={s}", .{@errorName(err)});
                };
            }
            const intake = self.peer_manager.discoveredBatch(self.service.gossipsub, candidates[0..progress.candidates], tick);
            if (progress.candidates > 0) std.log.scoped(.network_discovery).debug("candidates_received count={d} refused={d}", .{ progress.candidates, intake.refused });
            if (progress.failure) |err| {
                std.log.scoped(.network_discovery).debug("discovery_failed stage={s} reason={s}", .{ @tagName(progress.failure_stage), @errorName(err) });
                result.failure = result.failure orelse err;
            }
            if (progress.datagrams == 0) break;
        }
    }
};

/// Rounds a monotonic nanosecond deadline up to the owner loop's millisecond clock.
fn ceilMs(ns: u64) u64 {
    return ns / std.time.ns_per_ms + @intFromBool(ns % std.time.ns_per_ms != 0);
}

fn validateForkTable(table: []const rr.ReqResp.ForkEntry, context: *const t.ForkContext) !void {
    try rr.ReqResp.validateForkTable(table);
    var found = false;
    for (table) |entry| {
        if (std.mem.eql(u8, &entry.digest, &context.digest) and entry.fork == context.fork) found = true;
    }
    if (!found) return error.UnknownFork;
}
fn validateSchedule(local: *const t.LocalState, schedule: ForkSchedule) !void {
    if (schedule.next_epoch == std.math.maxInt(u64) and !std.mem.allEqual(u8, &schedule.next_digest, 0)) return error.InvalidSchedule;
    if ((schedule.fulu_scheduled or local.fork.fork.gte(.fulu)) and local.metadata.custody_group_count == null) return error.MissingCustodyAdvertisement;
}
const advertisementFor = peers.discovery.advertisementFor;

test {
    _ = @import("network_core_test.zig");
    _ = @import("network_core_metrics_test.zig");
    _ = @import("network_core_endpoint_test.zig");
    _ = @import("network_core_turn_test.zig");
    _ = @import("network_core_peer_test.zig");
    _ = @import("network_core_control_test.zig");
    _ = @import("network_core_coverage_test.zig");
}
