const std = @import("std");
const time = @import("time.zig");
const d = @import("discv5");
const manager = @import("peer_manager.zig");
const Protocols = @import("protocols.zig").Protocols;
const Transport = @import("transport.zig").Transport;
const Engine = @import("quic/Engine.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
const wake_sources = @import("wake_sources.zig");
const control_values = @import("control_values.zig");
const ControlProtocol = @import("control_protocol.zig").ControlProtocol;
const advertisement = @import("advertisement.zig");
const constants = @import("constants.zig");
const KeyPair = @import("wire/keys.zig").KeyPair;
const Sockets = @import("udp").Sockets;
const Reservations = @import("reservations.zig").Reservations;
const timing = @import("metrics/timing.zig");
const identify_mod = @import("identify/root.zig");
const configuration = @import("configuration.zig");
const router = @import("router.zig");
const limits = @import("quic/limits.zig");
const Multiaddr = @import("wire/multiaddr.zig").Multiaddr;
const ForkEntry = @import("types.zig").ForkEntry;
const capabilities_mod = @import("capabilities.zig");
const codec = @import("identify/codec.zig");
const logging = @import("logging.zig");

/// Initialize at its final address. Serialize every call, including reads and teardown.
pub const NetworkCore = struct {
    pub const wait = @import("wait.zig");

    /// Discovery datagrams drained per turn, matching the QUIC receive batch.
    pub const discovery_batch_max: u32 = constants.receive_batch_max;
    pub const controls_per_turn = 32;
    pub const identify_per_turn = 8;
    pub const dials_per_turn = 4;
    pub const LocalIntent = struct {
        update: control_values.LocalUpdate,
        demand: peers.Demand,
        subscriptions: []const gossip.local_intent.Boundary,
        slot: u64 = 0,
    };
    pub const DiscoveryOptions = peers.Discovery.Config;
    pub const Startup = struct {
        host: *const KeyPair,
        bind: Sockets.Bindings,
        local: t.LocalState,
        schedule: control_values.ForkSchedule = .{},
        discovery: ?DiscoveryOptions = null,
        /// The host's wall-clock slot until its first intent.
        slot: u64 = 0,
        /// Peers an earlier run remembered, at most `peers.remembered.capacity`, replayed as paced
        /// automatic candidates. Native drops expired, unusable and duplicate records.
        remembered: []const peers.remembered.Record = &.{},
    };
    pub const HostProgress = struct {
        /// A per-turn cap stopped work that can continue without another external event.
        runnable: bool = false,
    };
    /// The owner host seam. `advance` calls `apply` after receive, timers and collect and before the
    /// protocols run, when the host wake descriptor was readable, the previous call returned
    /// `runnable`, or `deadline` has passed, so the host's work is flushed in the same turn.
    pub const Host = struct {
        handler: ?Handler = null,
        /// Earliest host-owned deadline, kept by the host without scanning its queues.
        deadline: ?std.Io.Clock.Timestamp = null,

        pub const Handler = struct {
            context: *anyopaque,
            /// Drains the host wake descriptor before reading any host queue, so a submission that
            /// lands after the drain wakes the next poll. Must not retain events from an earlier turn.
            /// Passes this turn's `now` to core mutations; the protocol work that follows uses it too.
            apply: *const fn (context: *anyopaque, core: *NetworkCore, now: Now) HostProgress,
        };

        /// A host with no queued work that only bounds the wait.
        pub fn deadlineOnly(deadline: ?std.Io.Clock.Timestamp) Host {
            return .{ .deadline = deadline };
        }
    };
    pub const Outputs = struct {
        peers: []t.Event = &.{},
        application: []rr.ReqResp.Event = &.{},
    };
    pub const OperationalError = Transport.AdvanceError || Transport.DialError || peers.Discovery.Error || wait.Error;
    pub const Counts = struct { peers: usize, application: usize };
    pub const Result = struct {
        counts: Counts = .{ .peers = 0, .application = 0 },
        transport: Transport.Progress,
        readiness: wait.Result = .{},
        /// Authenticated transport events, borrowed until the next advance,
        /// beginGracefulClose, shutdown or deinit.
        transport_events: []const Engine.Event = &.{},
        /// Only discovery performed protocol work; transport retirement still ran.
        discovery_only: bool = false,
        /// Stops further external I/O independently of the first diagnostic failure.
        cancelled: bool = false,
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

    reservations: Reservations,
    allocator: std.mem.Allocator,
    transport: Transport,
    peer_manager: manager.PeerManager,
    control_protocol: ControlProtocol,
    protocols: Protocols,
    discovery: ?*peers.Discovery,
    native_events: []Engine.Event,
    local_intent_workspace: *gossip.local_intent.Workspace,
    schedule: control_values.ForkSchedule,
    counters: Counters = .{},
    step_duration: timing.Duration = .{},
    /// Zero-wait turns, counted under every source already due; readiness tests and the idle
    /// benchmarks read them to show an idle owner does not spin.
    due_now_turns: [wake_sources.source_count]u64 = @splat(0),
    last_now: Now,
    initialized: bool = false,
    host_wake: ?i32 = null,
    /// The host's wall-clock slot for status validation. Intents only advance it.
    current_slot: u64 = 0,
    /// The last host apply stopped at a per-turn cap.
    host_runnable: bool = false,
    /// The Protocols's control events and Identify results that `process` consumes within its turn.
    /// Fields rather than locals so ReleaseSafe does not fill them every turn.
    controls: [controls_per_turn]rr.ReqResp.Event = undefined,
    identify_results: [identify_per_turn]identify_mod.Handler.Result = undefined,

    pub fn init(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, resolved: *const configuration.Resolved, startup: Startup) !void {
        try configuration.validate(resolved.limits, resolved.core);
        try resolved.socket_buffers.validate();
        if (!wait.supported) return error.UnsupportedWait;
        if (startup.remembered.len > peers.remembered.capacity) return error.InvalidOptions;
        var local: t.LocalState = undefined;
        try control_values.copyServingLocal(&local, &startup.local, router.Router.initialCapabilities(resolved.core.protocols.router).receive);
        try validateSchedule(&local, startup.schedule);
        try validateForkTable(resolved.core.protocols.reqresp.forks, &local.fork);
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
        self.host_runnable = false;
        self.discovery = null;
        self.last_now = try Now.read(io);
        try self.transport.init(allocator, io, .{ .host = startup.host, .bind = startup.bind, .limits = resolved.limits, .work_limits = resolved.work_limits, .socket_buffers = resolved.socket_buffers.quic });
        errdefer self.transport.deinit(io);
        if (startup.discovery) |discovery_options| {
            const owned = try allocator.create(peers.Discovery);
            errdefer allocator.destroy(owned);
            try owned.init(allocator, io, discovery_options, resolved.socket_buffers.discovery, startup.host, &local, startup.schedule, self.transport.sockets.localAddresses(), self.last_now.millis());
            self.discovery = owned;
        }
        errdefer if (self.discovery) |owned| {
            owned.deinit(io);
            allocator.destroy(owned);
        };
        var protocols_options = resolved.core.protocols;
        protocols_options.reqresp.request_fork = local.fork.fork;
        const identify_base = try protocols_options.identify.makeLocal(&self.transport.peerId(), &self.transport.sockets.localAddresses());
        const identify_local = try prepareIdentifyLocal(&identify_base, self.advertisementEndpoints(), router.Router.initialCapabilities(protocols_options.router));
        self.protocols = try Protocols.init(allocator, protocols_options, &identify_local);
        errdefer self.protocols.deinit();
        self.peer_manager = try manager.PeerManager.init(allocator, &self.transport.peerId(), &local, resolved.core.peerManager(), self.protocols.router.capabilities().receive, self.transport.engine.limits.connections_max);
        errdefer self.peer_manager.deinit();
        const peer_capacity: u16 = @intCast(self.peer_manager.catalog.rows.len);
        self.control_protocol = try ControlProtocol.init(allocator, peer_capacity, resolved.core.peers.max_peers, protocols_options.reqresp.serving_control_reserved);
        errdefer self.control_protocol.deinit(allocator);
        self.peer_manager.loadRemembered(startup.remembered, self.last_now);
        self.protocols.gossipsub.clock = io;
        self.native_events = try allocator.alloc(Engine.Event, limits.events_per_turn_max);
        errdefer allocator.free(self.native_events);
        self.local_intent_workspace = try allocator.create(gossip.local_intent.Workspace);
        errdefer allocator.destroy(self.local_intent_workspace);
        self.local_intent_workspace.* = .{};
        self.initialized = true;
    }

    /// Immediately destroys the owner, ending all borrows and discarding undelivered results.
    pub fn deinit(self: *NetworkCore, io: std.Io) void {
        if (!self.initialized) return;
        const read = Now.read(io) catch self.last_now;
        self.shutdown(read.floor(self.last_now));
        if (self.discovery) |owned| {
            owned.deinit(io);
            self.allocator.destroy(owned);
        }
        self.allocator.destroy(self.local_intent_workspace);
        self.protocols.deinit();
        self.control_protocol.deinit(self.allocator);
        self.peer_manager.deinit();
        self.allocator.free(self.native_events);
        self.transport.deinit(io);
        std.debug.assert(self.reservations.bytes == 0);
        self.initialized = false;
    }
    /// Cancels the network between turns, invalidating borrowed events and releasing the host wake
    /// descriptor. Do not advance again. The caller completes outstanding operations; deinit ends
    /// remaining payload borrows and frees storage. Final metrics remain readable until deinit.
    pub fn shutdown(self: *NetworkCore, now: Now) void {
        const pm = &self.peer_manager;
        if (!pm.stop()) return;
        self.last_now = now;
        self.host_wake = null;
        self.transport.engine.stopAdmission();
        self.protocols.shutdown(&self.transport.engine, now);
        var cursor: usize = 0;
        while (pm.retireNextConnection(&cursor, now)) |retired| self.releaseConnection(retired, now);
        var close: [peers.Dialing.attempts_max]t.Handle = undefined;
        for (pm.shutdownDials(now, &close)) |conn| self.closeDial(conn);
        if (self.discovery) |owned| owned.shutdown();
        self.transport.engine.closeAll();
    }
    pub fn phase(self: *const NetworkCore) manager.PeerManager.Phase {
        return self.peer_manager.phase;
    }
    pub fn peerId(self: *const NetworkCore) t.PeerId {
        return self.transport.peerId();
    }
    pub fn localMultiaddr(self: *const NetworkCore) Multiaddr {
        return self.transport.localMultiaddr();
    }
    pub fn localRecord(self: *const NetworkCore) ?*const d.identity.enr.Record {
        return if (self.discovery) |owned| owned.localRecord() else null;
    }
    pub fn advertisementEndpoints(self: *const NetworkCore) ?advertisement.Endpoints {
        return if (self.discovery) |owned| owned.endpoints else null;
    }
    pub fn localState(self: *const NetworkCore) t.LocalState {
        return self.peer_manager.local;
    }
    pub fn peerCounts(self: *const NetworkCore) manager.PeerManager.PeerCounts {
        return self.peer_manager.peerCounts();
    }
    /// Takes an awake-clock deadline, rounded up to the protocol timer's millisecond precision.
    pub fn connectUntil(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now, deadline: std.Io.Clock.Timestamp) !void {
        if (deadline.compare(.lte, now.monotonic)) return error.InvalidDeadline;
        try self.peer_manager.connectUntil(identity, addresses, now, time.ceilMilliseconds(deadline));
    }
    pub fn cancelConnect(self: *NetworkCore, identity: *const t.PeerId, now: Now) void {
        if (self.peer_manager.cancelConnect(identity, now)) |conn| self.closeDial(conn);
    }
    fn closeDial(self: *NetworkCore, conn: t.Handle) void {
        const engine = &self.transport.engine;
        if (engine.peerId(conn) != null) _ = engine.close(conn, 0) else _ = engine.abandon(conn);
    }
    pub fn addDirectPeer(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now) !void {
        if (try self.peer_manager.addDirectPeer(identity, addresses, now)) |conn| self.protocols.gossipsub.markDirect(conn);
    }
    pub fn removeDirectPeer(self: *NetworkCore, identity: *const t.PeerId) bool {
        if (!self.peer_manager.removeDirectPeer(identity)) return false;
        self.protocols.gossipsub.unmarkDirect(identity);
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
        if (self.peer_manager.phase == .stopped) return false;
        self.closeConnection(peer, connection, .host, now);
        if (self.peer_manager.cancelConnect(identity, now)) |conn| self.closeDial(conn);
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
        if (self.peer_manager.phase != .running) return error.Stopped;
        try self.peer_manager.updateStatus(self.protocols.router.capabilities().receive, status);
    }
    /// Borrows request bytes and the exclusive response sink until terminal delivery or deinit.
    pub fn sendReqRespRequest(self: *NetworkCore, identity: *const t.PeerId, protocol: rr.Protocol, request: []const u8, sink: []u8, options: rr.ReqResp.RequestOptions, now: Now) !rr.ReqResp.RequestHandle {
        const peer = self.peer_manager.catalog.find(identity) orelse return error.StalePeer;
        const snapshot = self.peer_manager.catalog.get(peer) orelse return error.StalePeer;
        const conn = snapshot.connection orelse return error.Disconnected;
        if (self.peer_manager.phase != .running) return error.Stopped;
        if (protocol.isControl()) return error.ControlProtocol;
        return self.protocols.request(&self.transport.engine, conn, protocol, request, sink, options, now);
    }
    /// Releases the delivered response chunk and permits the next write into the sink.
    pub fn consumeResponse(self: *NetworkCore, request: rr.ReqResp.RequestHandle, now: Now) bool {
        return self.protocols.reqresp.consume(&self.transport.engine, &self.protocols.router, request, now);
    }
    /// Borrows bytes until chunk_sent or terminal delivery. Readiness is not a reservation.
    pub fn respond(self: *NetworkCore, request: rr.ReqResp.RequestHandle, bytes: []const u8, context: ?ForkEntry, now: Now) !void {
        try self.protocols.reqresp.respond(request, bytes, context, now);
    }
    /// Copies the message; terminal delivery still ends any outstanding payload borrows.
    pub fn respondError(self: *NetworkCore, request: rr.ReqResp.RequestHandle, code: u8, message: []const u8, now: Now) !void {
        try self.protocols.reqresp.respondError(request, code, message, now);
    }
    /// Finishes the inbound response after any pending chunk acknowledgement.
    pub fn finishResponse(self: *NetworkCore, request: rr.ReqResp.RequestHandle, now: Now) bool {
        return self.protocols.reqresp.finish(request, now);
    }
    /// Cancels I/O immediately. Pending notifications precede the terminal that ends borrows.
    pub fn cancelRequest(self: *NetworkCore, request: rr.ReqResp.RequestHandle, now: Now) bool {
        return self.protocols.reqresp.cancel(&self.transport.engine, &self.protocols.router, request, now);
    }
    /// Holds host execution capacity independently of request completion, without extending borrows.
    pub fn retainServing(self: *NetworkCore, request: rr.ReqResp.RequestHandle) ?rr.ReqResp.ServingHandle {
        return self.protocols.reqresp.retainServing(request);
    }
    pub fn releaseServing(self: *NetworkCore, serving: rr.ReqResp.ServingHandle) bool {
        return self.protocols.reqresp.releaseServing(serving);
    }
    /// Observes whether an inbound request can accept a response; reserves no capacity.
    pub fn responseReadiness(self: *NetworkCore, request: rr.ReqResp.RequestHandle) rr.ReqResp.ResponseReadiness {
        return self.protocols.reqresp.responseReadiness(request);
    }
    pub fn peerIdentity(self: *const NetworkCore, connection: t.Handle) ?t.PeerId {
        return self.transport.engine.peerId(connection);
    }

    pub fn publishGossipWithOptions(self: *NetworkCore, topic: []const u8, bytes: []const u8, options: gossip.Gossipsub.PublishOptions, now: Now) !gossip.Gossipsub.PublishOutcome {
        if (self.peer_manager.phase != .running) return error.Stopped;
        return self.protocols.gossipsub.publishWithOptions(topic, bytes, options, now);
    }
    pub fn reportValidation(self: *NetworkCore, handle: gossip.Gossipsub.ValidationHandle, verdict: gossip.Gossipsub.Verdict, now: Now) gossip.Gossipsub.ReportOutcome {
        return self.protocols.gossipsub.report(handle, verdict, now);
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
    /// control progress continues. Call between turns after consuming borrowed events.
    /// The owner bounds the grace period, then calls shutdown and deinit without draining results.
    pub fn beginGracefulClose(self: *NetworkCore, now: Now) void {
        const pm = &self.peer_manager;
        if (!pm.quiesce(now)) return;
        self.transport.engine.stopAdmission();
        self.protocols.closeApplications(&self.transport.engine, now);
        var active = self.protocols.router.active_capabilities;
        active.receive = .initEmpty();
        self.protocols.router.setCapabilities(active);
    }

    fn updateLocalWithEndpoints(self: *NetworkCore, desired: *const t.LocalState, schedule: control_values.ForkSchedule, endpoints: ?advertisement.Endpoints, now: Now) !bool {
        return self.applyLocal(&.{
            .local = desired.*,
            .schedule = schedule,
            .endpoints = endpoints,
            .capabilities = self.protocols.router.capabilities(),
        }, now);
    }

    fn prepareIdentifyLocal(base: *const identify_mod.Local, endpoints: ?advertisement.Endpoints, capabilities: capabilities_mod.Directional) !identify_mod.Local {
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
        var encoded: [codec.encoded_frame_max]u8 = undefined;
        _ = try local.encode(capabilities.receive, null, &encoded);
        return local;
    }

    const PreparedLocal = struct {
        local: t.LocalState,
        schedule: control_values.ForkSchedule,
        endpoints: ?advertisement.Endpoints,
        capabilities: capabilities_mod.Directional,
        identify: identify_mod.Local,
        record: ?peers.Discovery.PreparedAdvertisement = null,
        changed: bool,
    };

    fn prepareLocal(self: *const NetworkCore, update: *const control_values.LocalUpdate) !PreparedLocal {
        if (self.peer_manager.phase != .running) return error.Stopped;
        const schedule = update.schedule;
        const endpoints = update.endpoints;
        const capabilities = update.capabilities;
        try self.protocols.router.validateCapabilities(capabilities);
        if ((endpoints == null) != (self.discovery == null)) return error.InvalidAdvertisement;
        if (endpoints) |value| {
            try self.discovery.?.validateEndpoints(value);
        }
        var local = update.local;
        local.metadata.seq_number = self.peer_manager.local.metadata.seq_number;
        try control_values.copyServingLocal(&local, &local, capabilities.receive);
        try validateSchedule(&local, schedule);
        const request = &self.protocols.reqresp;
        try validateForkTable(request.forks[0..request.fork_count], &local.fork);
        const identify_local = try prepareIdentifyLocal(&self.protocols.identify.local, endpoints, capabilities);
        const metadata_changed = !std.meta.eql(local.metadata, self.peer_manager.local.metadata);
        if (metadata_changed) local.metadata.seq_number = try peers.enr.nextSequence(local.metadata.seq_number);
        var prepared: PreparedLocal = .{
            .local = local,
            .schedule = schedule,
            .endpoints = endpoints,
            .capabilities = capabilities,
            .identify = identify_local,
            .changed = !(std.meta.eql(local, self.peer_manager.local) and std.meta.eql(schedule, self.schedule) and
                std.meta.eql(endpoints, self.advertisementEndpoints()) and std.meta.eql(capabilities, self.protocols.router.capabilities())),
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
        self.protocols.identify.local = prepared.identify;
        self.protocols.router.setCapabilities(prepared.capabilities);
        const pm = &self.peer_manager;
        if (!std.meta.eql(pm.local.fork, prepared.local.fork)) {
            var cursor: usize = 0;
            while (pm.nextRevalidation(&cursor, now)) |stale| {
                self.control_protocol.cancel(&self.protocols.reqresp, &self.protocols.router, &self.transport.engine, stale.peer, stale.conn, now);
            }
        }
        pm.commitLocal(&prepared.local, now);
        self.protocols.reqresp.setRequestFork(prepared.local.fork.fork);
        self.schedule = prepared.schedule;
    }

    /// Prepares every owner before ENR publication; caller sequence input is ignored.
    fn applyLocal(self: *NetworkCore, update: *const control_values.LocalUpdate, now: Now) !bool {
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
        const topics_changed = try self.protocols.gossipsub.prepareSubscriptions(intent.subscriptions, self.local_intent_workspace, now, intent.slot);
        const demand_changed = !std.meta.eql(demand, self.peer_manager.demand);
        const changed = prepared.changed or topics_changed or demand_changed;
        try self.publishLocal(&prepared);
        if (prepared.changed) self.commitLocal(&prepared, now);
        self.protocols.gossipsub.commitSubscriptions(self.local_intent_workspace);
        if (demand_changed) self.peer_manager.commitDemand(&demand);
        self.current_slot = @max(self.current_slot, intent.slot);
        if (changed) std.log.scoped(.network_core).debug("intent_applied local_changed={any} topics_changed={any} demand_changed={any} subscriptions={d} fork={s} digest={x}", .{ prepared.changed, topics_changed, demand_changed, intent.subscriptions.len, @tagName(prepared.local.fork.fork), prepared.local.fork.digest });
        return changed;
    }

    /// Borrows a readable OS descriptor; the host drains it after readiness.host.
    /// Detach, shutdown or deinit ends the borrow without closing the descriptor.
    /// End the borrow before closing or reusing the descriptor.
    pub fn setHostWake(self: *NetworkCore, descriptor: ?i32) error{ UnsupportedWait, InvalidWakeSource, Stopped }!void {
        if (descriptor) |fd| {
            if (self.peer_manager.phase != .running) return error.Stopped;
            if (!wait.supported) return error.UnsupportedWait;
            if (comptime wait.supported) {
                if (fd < 0) return error.InvalidWakeSource;
                for (self.transport.sockets.handles()) |socket| if (socket == fd) return error.InvalidWakeSource;
                if (self.discovery) |owned| for (owned.transport.sockets.handles()) |socket| if (socket == fd) return error.InvalidWakeSource;
            }
        }
        self.host_wake = descriptor;
    }

    /// Scheduling is a snapshot for the supplied output capacities; recompute after mutation.
    pub fn wakeups(self: *const NetworkCore, now: Now, outputs: Outputs) wake_sources.Wakeups {
        std.debug.assert(self.phase() != .stopped);
        var result: wake_sources.Wakeups = .{};
        const pm = &self.peer_manager;
        pm.collectWakeups(self.protocols.gossipsub, now, .{ .peers = outputs.peers.len, .dials = dials_per_turn }, &result);
        self.protocols.collectWakeups(.{ .application = outputs.application.len, .control = controls_per_turn, .identify = identify_per_turn }, &result);
        const quic = &self.transport.engine;
        result.note(.transport_backlog, .{ .runnable = quic.backlog() });
        result.note(.transport_events, .{ .runnable = quic.eventsPending() or quic.releasesPending() });
        result.note(.transport_timer, .{ .deadline = if (quic.nextDeadlineNs()) |deadline| .{ .clock = .awake, .raw = .fromNanoseconds(deadline) } else null });
        if (pm.phase == .running) if (self.discovery) |owned| result.note(.discovery, owned.schedule(now.millis()));
        result.note(.host, .{ .runnable = self.host_runnable });
        return result;
    }

    pub const WaitPlan = struct {
        now: Now,
        sources: wait.Sources,
        timeout: std.Io.Timeout,
        due: [wake_sources.source_count]bool,
    };

    /// Borrows descriptors until the next owner mutation. Waiting does not consume events.
    pub fn waitPlan(self: *const NetworkCore, observed: Now, outputs: Outputs, host: Host) WaitPlan {
        const now = observed.floor(self.last_now);
        var pending = self.wakeups(now, outputs);
        pending.note(.host, .{ .deadline = host.deadline });
        var plan: WaitPlan = .{
            .now = now,
            .sources = .{
                .quic = self.transport.sockets.handles(),
                .discovery = if (self.peer_manager.phase == .running and self.discovery != null)
                    self.discovery.?.transport.sockets.handles()
                else
                    .{ null, null },
                .host = self.host_wake,
            },
            .timeout = pending.schedule().timeout(now.monotonic, .fromMilliseconds(wait.native_wait_max_ms)),
            .due = undefined,
        };
        for (pending.sources, &plan.due) |source, *due| due.* = source.due(now.monotonic);
        return plan;
    }

    /// Records driver observations separately from the read-only scheduling snapshot.
    pub fn observeWait(self: *NetworkCore, plan: *const WaitPlan) void {
        for (plan.due, &self.due_now_turns) |due, *turns| turns.* +|= @intFromBool(due);
    }

    pub const Input = struct {
        now: Now,
        readiness: wait.Result = .{},
        clock_failure: ?error{ClockOutOfRange} = null,
    };

    /// Advances one bounded turn from supplied readiness and time; never waits for readiness.
    /// Receive and transport processing precede host apply, protocols, discovery, dials and flush.
    /// The I/O provider must complete datagram operations without waiting. Read event arrays before the
    /// next advance, beginGracefulClose or teardown; request payloads follow the request API's
    /// borrow contracts. Do not call after shutdown or initiate shutdown from the host callback.
    /// Time must not move backwards.
    /// Counts remain valid on failure.
    pub fn advance(self: *NetworkCore, io: std.Io, input: Input, outputs: Outputs, host: Host) Result {
        std.debug.assert(self.initialized);
        std.debug.assert(self.phase() != .stopped);
        std.debug.assert(input.now.monotonic.compare(.gte, self.last_now.monotonic));
        const tick = input.now;
        const readiness = input.readiness;
        self.counters.readiness_failures +|= @intFromBool(readiness.failure != null);
        self.counters.transport_failures +|= @intFromBool(input.clock_failure != null);
        const start = timing.now(io);
        defer self.step_duration.observe(timing.now(io) -| start);
        self.last_now = tick;
        var result: Result = .{
            .transport = self.transport.beginTurn(tick),
            .readiness = readiness,
            .cancelled = readiness.cancelled,
            .failure = readiness.failure orelse input.clock_failure,
        };
        if (!result.cancelled and self.discoveryOnly(&result.readiness, tick, outputs, host)) {
            result.discovery_only = true;
            self.discover(io, tick, &result);
            return result;
        }
        // A failed poll reports no readiness, so both sockets are drained anyway.
        const quic: [2]bool = if (result.readiness.failure == null) result.readiness.quic else @splat(true);
        if (!result.cancelled and (quic[0] or quic[1])) {
            self.transport.receive(io, &result.transport, quic) catch |err| {
                result.cancelled = err == error.Canceled;
                result.failure = result.failure orelse err;
                self.counters.transport_failures +|= 1;
            };
        }
        result.transport.events = self.transport.process(tick, self.native_events);
        result.transport.events_pending = self.transport.engine.eventsPending();
        result.transport_events = self.native_events[0..result.transport.events];
        if (!result.cancelled) {
            if (host.handler) |handler| {
                const due = if (host.deadline) |deadline| deadline.compare(.lte, tick.monotonic) else false;
                if (result.readiness.host or result.readiness.failure != null or self.host_runnable or due) {
                    self.host_runnable = handler.apply(handler.context, self, tick).runnable;
                }
            } else self.host_runnable = false;
        }
        result.counts = self.process(self.native_events[0..result.transport.events], tick, outputs);
        if (self.peer_manager.phase == .running and !result.cancelled) {
            // This turn's coverage selection already ran, without a second protocol pump.
            if (self.discovery != null) self.discover(io, tick, &result);
            if (!result.cancelled and input.clock_failure == null) self.dial(io, tick, &result);
        }
        if (!result.cancelled) self.transport.flush(io, tick, &result.transport) catch |err| {
            result.cancelled = true;
            result.failure = result.failure orelse err;
            self.counters.transport_failures +|= 1;
        };
        return result;
    }

    fn dial(self: *NetworkCore, io: std.Io, tick: Now, result: *Result) void {
        var selected: [dials_per_turn]manager.SelectedDial = undefined;
        const room = self.transport.engine.limits.dialing_max -| self.transport.engine.resourceSnapshot().dialing;
        const count = self.peer_manager.selectDials(self.protocols.gossipsub, &self.transport.engine, tick, selected[0..@min(room, selected.len)]);
        for (selected[0..count], 0..) |attempt, index| {
            const handle = self.transport.dialPeer(io, attempt.address, attempt.peer, tick) catch |err| {
                if (err == error.DestinationUnreachable) {
                    std.log.scoped(.network_core).debug("dial_failed peer={f} endpoint={any} reason={s}", .{ logging.peer(&attempt.peer), attempt.address, @errorName(err) });
                    std.debug.assert(self.peer_manager.dialFailed(attempt.token, tick));
                    result.dial_failed += 1;
                } else {
                    std.log.scoped(.network_core).debug("dial_deferred peer={f} endpoint={any} reason={s}", .{ logging.peer(&attempt.peer), attempt.address, @errorName(err) });
                    std.debug.assert(self.peer_manager.dialDeferred(attempt.token, tick));
                    result.dial_deferred += 1;
                    result.failure = result.failure orelse err;
                }
                if (err == error.Canceled) {
                    for (selected[index + 1 .. count]) |pending| {
                        std.debug.assert(self.peer_manager.dialDeferred(pending.token, tick));
                        result.dial_deferred += 1;
                    }
                    result.cancelled = true;
                    break;
                }
                continue;
            };
            std.debug.assert(self.peer_manager.dialStarted(attempt.token, handle));
            std.log.scoped(.network_core).debug("dial_started peer={f} endpoint={any} connection={d}:{d}", .{ logging.peer(&attempt.peer), attempt.address, handle.index, handle.generation });
            result.dial_started += 1;
        }
        self.peer_manager.finishDialBatch(tick);
        self.counters.dial_started +|= result.dial_started;
        self.counters.dial_deferred +|= result.dial_deferred;
    }

    /// Delivers the turn's transport events, runs the one Protocols pass, applies its faults and
    /// control results, runs due control maintenance, then advances custody and selection.
    /// Payload borrows end at their documented delivery or acknowledgment boundary.
    fn process(self: *NetworkCore, events: []const Engine.Event, now: Now, outputs: Outputs) Counts {
        std.debug.assert(events.len <= limits.events_per_turn_max);
        const pm = &self.peer_manager;
        const quic = &self.transport.engine;
        if (pm.phase == .running) {
            var close: [peers.Dialing.attempts_max]t.Handle = undefined;
            for (pm.expireDials(now, &close)) |conn| self.closeDial(conn);
        }
        for (events) |*event| self.transportEvent(event, now);
        const controls = &self.controls;
        const identify_results = &self.identify_results;
        const counts = self.protocols.process(quic, events, now, .{ .application = outputs.application, .control = controls, .identify = identify_results });
        for ([_][]const rr.ReqResp.Event{ outputs.application[0..counts.application], controls[0..counts.control] }) |batch| {
            for (batch) |*event| {
                const fault = event.peerFault() orelse continue;
                pm.requestFault(fault, now);
            }
        }
        pm.identified(identify_results[0..counts.identify]);
        self.controlEvents(controls[0..counts.control], now);
        self.maintainControl(now);
        if (pm.phase == .quiescing) return .{ .peers = pm.pollEvents(outputs.peers), .application = counts.application };
        pm.advanceCustody(now);
        pm.reconcile(self.protocols.gossipsub, now);
        pm.transportProgress(quic);
        return .{
            .peers = pm.pollEvents(outputs.peers),
            .application = counts.application,
        };
    }

    fn transportEvent(self: *NetworkCore, event: *const Engine.Event, now: Now) void {
        const pm = &self.peer_manager;
        const quic = &self.transport.engine;
        switch (event.*) {
            .connected => |*connected| {
                if (pm.phase == .quiescing) {
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
                    self.releaseConnection(.{ .peer = admission.peer, .conn = old }, now);
                }
                _ = self.protocols.gossipsub.peerConnected(quic, connected.conn, admission.direct, now);
            },
            .closed => |*closed| {
                const goodbye = if (pm.catalog.findConnection(closed.conn) != null)
                    self.protocols.reqresp.closingGoodbye(quic, &self.protocols.router, closed.conn, now)
                else
                    null;
                const retired = pm.transportClosed(closed, goodbye, now) orelse return;
                self.releaseConnection(retired, now);
            },
            .path_changed => |*changed| pm.endpointChanged(changed.conn, &changed.peer),
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
        self.control_protocol.cancelConnection(&self.protocols.reqresp, &self.protocols.router, quic, retired.peer, retired.conn, now);
        self.protocols.gossipsub.retireConnection(&self.protocols.router, quic, retired.conn, now);
        _ = quic.close(retired.conn, 0);
    }

    /// Routes one turn's control events. Peer control applies each request or reply before the
    /// control protocol answers, consumes or retires it. Each observed result settles before
    /// another policy evaluation.
    fn controlEvents(self: *NetworkCore, batch: []const rr.ReqResp.Event, now: Now) void {
        const pm = &self.peer_manager;
        const requests = &self.control_protocol;
        const reqresp = &self.protocols.reqresp;
        for (batch) |*event| switch (event.*) {
            .request => |*request| {
                const peer = pm.controlRequested(request, now, self.current_slot) orelse {
                    _ = reqresp.cancel(&self.transport.engine, &self.protocols.router, request.request, now);
                    continue;
                };
                requests.respond(reqresp, &self.protocols.router, &self.transport.engine, peer, request, &pm.local, now);
            },
            else => {
                const result = requests.result(reqresp, event.*, now) orelse continue;
                pm.controlReplied(&result.reply, event.*, now, self.current_slot);
                requests.settle(reqresp, &self.protocols.router, &self.transport.engine, result.index, event.*, now);
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
                self.protocols.identify.start(&self.protocols.router, quic, due.peer, due.conn, now) catch break :blk false;
                break :blk true;
            } else false;
            const request = if (due.request) |*probe|
                requests.start(&self.protocols.reqresp, &self.protocols.router, quic, due.peer, due.conn, probe, &pm.local, now)
            else
                null;
            pm.controlStarted(due, identified, request, now);
        }
    }

    /// A turn drains discovery alone when discovery is readable or due, the QUIC sockets and the
    /// host are not readable, and every other source, re-read at the post-poll time, is in the future.
    fn discoveryOnly(self: *NetworkCore, readiness: *const wait.Result, tick: Now, outputs: Outputs, host: Host) bool {
        if (readiness.quicReady() or readiness.host or readiness.failure != null) return false;
        if (self.discovery == null or self.peer_manager.phase != .running) return false;
        var pending = self.wakeups(tick, outputs);
        pending.note(.host, .{ .deadline = host.deadline });
        const discovery_slot = &pending.sources[@intFromEnum(wake_sources.Source.discovery)];
        const discovery_due = discovery_slot.due(tick.monotonic);
        if (!readiness.discoveryReady() and !discovery_due) return false;
        discovery_slot.* = .{};
        return !pending.schedule().due(tick.monotonic);
    }

    /// Steps discovery once per datagram, up to discovery_batch_max, handling each step's
    /// candidates and learned endpoints before the next. Admission runs before decode as always.
    fn discover(self: *NetworkCore, io: std.Io, tick: Now, result: *Result) void {
        const owned = self.discovery.?;
        const need = self.peer_manager.discoveryNeed();
        owned.request(need.query(tick.millis() +| 1_000), tick.millis()) catch unreachable;
        const candidates = &owned.candidates;
        var eligible: [2]bool = if (result.readiness.failure == null) result.readiness.discovery else @splat(true);
        for (0..discovery_batch_max) |_| {
            const progress = owned.advance(io, tick.millis(), &eligible, candidates) catch |err| peers.Discovery.Result{ .cancelled = err == error.Canceled, .failure = .{ .cause = err, .stage = .coordinator } };
            const endpoints = owned.learnedEndpoints(progress.learned);
            if (!std.meta.eql(endpoints, owned.endpoints)) {
                _ = self.updateLocalWithEndpoints(&self.peer_manager.local, self.schedule, endpoints, tick) catch |err| {
                    std.log.scoped(.network_discovery).warn("endpoint_update_failed reason={s}", .{@errorName(err)});
                };
            }
            const intake = self.peer_manager.discoveredBatch(self.protocols.gossipsub, candidates[0..progress.candidates], tick);
            if (progress.candidates > 0) std.log.scoped(.network_discovery).debug("candidates_received count={d} refused={d}", .{ progress.candidates, intake.refused });
            if (progress.failure) |failure| {
                std.log.scoped(.network_discovery).debug("discovery_failed stage={s} reason={s}", .{ @tagName(failure.stage), @errorName(failure.cause) });
                result.failure = result.failure orelse failure.cause;
            }
            result.cancelled = result.cancelled or progress.cancelled;
            if (result.cancelled or progress.datagrams == 0) break;
        }
    }
};

fn validateForkTable(table: []const ForkEntry, context: *const t.ForkContext) !void {
    try rr.ReqResp.validateForkTable(table);
    var found = false;
    for (table) |entry| {
        if (std.mem.eql(u8, &entry.digest, &context.digest) and entry.fork == context.fork) found = true;
    }
    if (!found) return error.UnknownFork;
}
fn validateSchedule(local: *const t.LocalState, schedule: control_values.ForkSchedule) !void {
    if (schedule.next_epoch == std.math.maxInt(u64) and !std.mem.allEqual(u8, &schedule.next_digest, 0)) return error.InvalidSchedule;
    if ((schedule.fulu_scheduled or local.fork.fork.gte(.fulu)) and local.metadata.custody_group_count == null) return error.MissingCustodyAdvertisement;
}
const advertisementFor = @import("peers/discovery.zig").advertisementFor;

test {
    _ = @import("network_core_test.zig");
    _ = @import("network_core_intent_test.zig");
    _ = @import("network_core_metrics_test.zig");
    _ = @import("network_core_endpoint_test.zig");
    _ = @import("network_core_advance_test.zig");
    _ = @import("network_core_peer_test.zig");
    _ = @import("network_core_dial_test.zig");
    _ = @import("network_core_lifecycle_test.zig");
    _ = @import("network_core_identify_test.zig");
    _ = @import("network_core_socket_test.zig");
    _ = @import("network_core_control_test.zig");
    _ = @import("network_core_coverage_test.zig");
}
