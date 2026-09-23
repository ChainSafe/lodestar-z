const std = @import("std");
const d = @import("discv5");
const managed = @import("managed.zig");
const manager = @import("peer_manager.zig");
const service_mod = @import("service.zig");
const transport_mod = @import("transport.zig");
const engine = @import("quic/engine.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
pub const wait = @import("wait.zig");

pub const poll_wait_max_ms: u32 = 5;
pub const ForkSchedule = struct {
    fulu_scheduled: bool = false,
    next_version: [4]u8 = @splat(0),
    next_epoch: u64 = std.math.maxInt(u64),
    next_digest: [4]u8 = @splat(0),
};
pub const AdvertisementEndpoints = struct {
    ip4: ?[4]u8 = null,
    ip6: ?[16]u8 = null,
    udp: ?u16 = null,
    udp6: ?u16 = null,
    quic: ?u16 = null,
    quic6: ?u16 = null,
};
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
pub const DiscoveryOptions = struct {
    advertisement: ?AdvertisementEndpoints = null,
    bind: @import("udp.zig").Bindings,
    sequence: u64 = 1,
    bootstrap: []const d.identity.enr.Record = &.{},
    engine: d.Engine.Config = .{},
    coordinator: peers.discovery.Options = .{},
};
pub const Options = struct {
    transport: transport_mod.Options,
    core: managed.Options,
    local: t.LocalState,
    schedule: ForkSchedule,
    discovery: ?DiscoveryOptions = null,
    byte_limit: ?usize = null,
    wait_mode: wait.Mode = .portable,
};
pub const ManagedOptions = struct {
    wait_mode: wait.Mode = .portable,
    host: *const @import("wire/keys.zig").KeyPair,
    bind: @import("udp.zig").Bindings,
    configuration: @import("configuration.zig").Request,
    local: t.LocalState,
    schedule: ForkSchedule = .{},
    discovery: ?DiscoveryOptions = null,
};
pub const Startup = struct {
    wait_mode: wait.Mode = .portable,
    keylog_path: ?[]const u8 = null,
    host: *const @import("wire/keys.zig").KeyPair,
    bind: @import("udp.zig").Bindings,
    local: t.LocalState,
    schedule: ForkSchedule = .{},
    discovery: ?DiscoveryOptions = null,
};
pub const Outputs = struct {
    peers: []t.Event = &.{},
    application: []rr.Event = &.{},
    gossipsub: []gossip.Event = &.{},
};
pub const OperationalError = transport_mod.StepError || transport_mod.DialError || peers.discovery.Error || wait.Error;
pub const Result = struct {
    counts: managed.Counts = .{ .peers = 0, .application = 0, .gossipsub = 0 },
    transport: transport_mod.StepResult,
    readiness: wait.Result = .{},
    discovery: peers.discovery.Result = .{},
    failure: ?OperationalError = null,
    dial_started: u8 = 0,
    dial_deferred: u8 = 0,
    dial_failed: u8 = 0,
};
pub const Counters = struct {
    discovered: u64 = 0,
    candidates_refused: u64 = 0,
    future_fork_mismatches: u64 = 0,
    future_fork_unknown: u64 = 0,
    dial_started: u64 = 0,
    dial_deferred: u64 = 0,
    dial_failed: u64 = 0,
    transport_failures: u64 = 0,
    discovery_failures: u64 = 0,
    readiness_calls: u64 = 0,
    readiness_nonzero_waits: u64 = 0,
    readiness_interruptions: u64 = 0,
    readiness_failures: u64 = 0,
};
pub const Diagnostics = struct {
    runtime: Counters,
    transport: engine.Counters,
    transport_resources: engine.Engine.Resources,
    core: manager.PeerManager.Diagnostics,
};
pub const MemoryPlan = struct {
    inline_bytes: usize = @sizeOf(NetworkCore),
    allocated_bytes: usize = 0,
    transport_bytes: usize = 0,
    peer_bytes: usize = 0,
    service_bytes: usize = 0,
    scratch_bytes: usize = 0,
    local_intent_bytes: usize = 0,
    discovery_bytes: usize = 0,
    transport: transport_mod.MemoryPlan,
};

const DiscoveryOwners = struct {
    transport: d.Transport,
    coordinator: peers.Discovery,
    endpoints: AdvertisementEndpoints,

    fn init(self: *DiscoveryOwners, allocator: std.mem.Allocator, io: std.Io, options: DiscoveryOptions, host: *const @import("wire/keys.zig").KeyPair, local: *const t.LocalState, schedule: ForkSchedule, quic: [2]?t.Address, now: Now) !void {
        const sockets = try @import("udp").Sockets.bind(io, options.bind);
        errdefer sockets.close(io);
        self.endpoints = options.advertisement orelse try defaultEndpoints(quic, &sockets);
        try validateEndpoints(self.endpoints);
        try validateEndpointFamilies(self.endpoints, quic, &sockets);
        const advertisement = advertisementFor(local, schedule, self.endpoints);
        const record = try peers.enr.build(&host.inner, options.sequence, &advertisement, &local.fork);
        try peers.enr.requireIdentity(&record, &t.PeerId.fromPublicKey(&host.publicKey()));
        try self.transport.init(allocator, sockets, host.inner, record, .{ .engine = options.engine, .poll_interval_ms = poll_wait_max_ms });
        errdefer self.transport.engine.deinit(allocator);
        var coordinator_options = options.coordinator;
        coordinator_options.quic_mode = if (quic[0] == null) .ip6 else if (quic[1] == null) .ip4 else .dual;
        self.coordinator = try peers.Discovery.init(allocator, &self.transport, &local.fork, options.bootstrap, now.mono_ms, coordinator_options);
    }
    fn deinit(self: *DiscoveryOwners, allocator: std.mem.Allocator, io: std.Io) void {
        self.coordinator.deinit();
        self.transport.deinit(allocator, io);
    }
};

/// Initialize at its final address. Serialize every call, including reads and teardown.
pub const NetworkCore = struct {
    reservations: @import("reservations.zig").Reservations,
    memory: MemoryPlan,
    allocator: std.mem.Allocator,
    transport: transport_mod.Transport,
    peer_manager: manager.PeerManager,
    service: service_mod.Service,
    discovery: ?*DiscoveryOwners,
    native_events: []engine.Event,
    native_event_count: usize = 0,
    activity: []engine.Handle,
    local_intent_workspace: *gossip.local_intent.Workspace,
    schedule: ForkSchedule,
    counters: Counters = .{},
    step_duration: @import("metrics/timing.zig").Duration = .{},
    last_now: Now,
    initialized: bool = false,
    wait_mode: wait.Mode,
    host_wake: ?i32 = null,

    pub fn initRaw(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, options: Options) !void {
        const resolved: @import("configuration.zig").Resolved = .{ .limits = options.transport.limits, .work_limits = options.transport.work_limits, .core = options.core, .byte_limit = options.byte_limit orelse std.math.maxInt(usize) };
        try self.init(backing, io, &resolved, .{ .host = options.transport.host, .bind = options.transport.bind, .keylog_path = options.transport.keylog_path, .local = options.local, .schedule = options.schedule, .discovery = options.discovery, .wait_mode = options.wait_mode });
    }

    pub fn init(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, resolved: *const @import("configuration.zig").Resolved, startup: Startup) !void {
        try @import("configuration.zig").validate(resolved.limits, resolved.core);
        const options: Options = .{ .transport = .{ .host = startup.host, .bind = startup.bind, .limits = resolved.limits, .work_limits = resolved.work_limits, .keylog_path = startup.keylog_path }, .core = resolved.core, .byte_limit = resolved.byte_limit, .local = startup.local, .schedule = startup.schedule, .discovery = startup.discovery, .wait_mode = startup.wait_mode };
        if (options.wait_mode == .native_poll and !wait.supported) return error.UnsupportedWait;
        var local: t.LocalState = undefined;
        try peers.control_wire.copyServingLocal(&local, &options.local, @import("router.zig").Router.initialCapabilities(options.core.service.router).receive);
        try validateSchedule(&local, options.schedule);
        try validateForkTable(options.core.service.reqresp.forks, &local.fork);
        self.initialized = false;
        self.reservations = .{ .backing = backing, .byte_limit = options.byte_limit };
        errdefer std.debug.assert(self.reservations.bytes == 0);
        const allocator = self.reservations.allocator();
        self.allocator = allocator;
        self.schedule = options.schedule;
        self.counters = .{};
        self.wait_mode = options.wait_mode;
        self.host_wake = null;
        self.native_event_count = 0;
        self.discovery = null;
        self.last_now = try transport_mod.currentTime(io);
        try self.transport.init(allocator, io, options.transport);
        errdefer self.transport.deinit(io);
        self.memory = .{ .transport_bytes = self.reservations.bytes, .transport = self.transport.memoryPlan() };
        self.service = try service_mod.Service.init(allocator, managed.serviceOptions(options.core, &local));
        errdefer self.service.deinit();
        self.peer_manager = try manager.PeerManager.init(allocator, &self.transport.peerId(), &local, managed.peerOptions(options.core), &self.service, self.transport.engine.limits.connections_max);
        errdefer self.peer_manager.deinit();
        if (self.service.identify) |*identify| identify.bind(&self.transport.engine);
        self.peer_manager.metrics_io = io;
        self.service.gossipsub.metrics_io = io;
        self.memory.peer_bytes = self.peer_manager.memoryPlan().allocated_bytes;
        self.memory.service_bytes = self.service.allocatedBytes();
        const event_capacity = @as(usize, options.transport.limits.connections_max) *
            @import("quic/limits.zig").events_per_connection;
        self.native_events = try allocator.alloc(engine.Event, event_capacity);
        errdefer allocator.free(self.native_events);
        self.activity = try allocator.alloc(engine.Handle, options.transport.limits.connections_max);
        errdefer allocator.free(self.activity);
        self.memory.scratch_bytes = self.native_events.len * @sizeOf(engine.Event) + self.activity.len * @sizeOf(engine.Handle);
        self.local_intent_workspace = try allocator.create(gossip.local_intent.Workspace);
        errdefer allocator.destroy(self.local_intent_workspace);
        self.local_intent_workspace.* = .{};
        self.memory.local_intent_bytes = @sizeOf(gossip.local_intent.Workspace);
        const before_discovery = self.reservations.bytes;
        if (options.discovery) |discovery_options| {
            const owned = try allocator.create(DiscoveryOwners);
            errdefer allocator.destroy(owned);
            try owned.init(allocator, io, discovery_options, options.transport.host, &local, options.schedule, self.transport.udp.localAddresses(), self.last_now);
            self.discovery = owned;
        }
        errdefer if (self.discovery) |owned| {
            owned.deinit(allocator, io);
            allocator.destroy(owned);
        };
        const identify_local = try self.prepareIdentifyLocal(self.advertisementEndpoints(), self.service.router.capabilities());
        if (self.service.identify) |*identify| identify.local = identify_local;
        self.memory.discovery_bytes = self.reservations.bytes - before_discovery;
        self.memory.allocated_bytes = self.reservations.bytes;
        std.debug.assert(self.memory.allocated_bytes == self.memory.transport_bytes + self.memory.peer_bytes + self.memory.service_bytes + self.memory.scratch_bytes + self.memory.local_intent_bytes + self.memory.discovery_bytes);
        self.initialized = true;
    }

    pub fn initManaged(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, options: ManagedOptions) !void {
        const resolved = try @import("configuration.zig").resolve(options.configuration);
        try self.init(backing, io, &resolved, .{ .host = options.host, .bind = options.bind, .local = options.local, .schedule = options.schedule, .discovery = options.discovery, .wait_mode = options.wait_mode });
    }

    pub fn deinit(self: *NetworkCore, io: std.Io) void {
        if (!self.initialized) return;
        self.shutdown(self.last_now);
        if (self.discovery) |owned| {
            owned.deinit(self.allocator, io);
            self.allocator.destroy(owned);
        }
        self.allocator.destroy(self.local_intent_workspace);
        self.service.deinit();
        self.peer_manager.deinit();
        self.allocator.free(self.activity);
        self.allocator.free(self.native_events);
        self.transport.deinit(io);
        std.debug.assert(self.reservations.bytes == 0);
        self.initialized = false;
    }
    pub fn shutdown(self: *NetworkCore, now: Now) void {
        self.host_wake = null;
        self.last_now = now;
        managed.shutdown(&self.peer_manager, &self.service, &self.transport.engine, now);
        if (self.discovery) |owned| owned.coordinator.cancel();
        // Include handshakes not yet admitted to the catalog.
        for (self.transport.engine.registry.slots, 0..) |slot, index| {
            const handle: engine.Handle = .{ .index = @intCast(index), .generation = slot.generation };
            if (!self.transport.engine.abandon(handle)) _ = self.transport.engine.close(handle, 0);
        }
    }
    pub fn isClosed(self: *const NetworkCore) bool {
        return self.peer_manager.stopped and self.transport.engine.registry.active_len == 0;
    }
    pub fn peerId(self: *const NetworkCore) t.PeerId {
        return self.transport.peerId();
    }
    pub fn localMultiaddr(self: *const NetworkCore) @import("wire/multiaddr.zig").Multiaddr {
        return self.transport.localMultiaddr();
    }
    pub fn localRecord(self: *const NetworkCore) ?*const d.identity.enr.Record {
        return if (self.discovery) |owned| owned.transport.engine.localRecord() else null;
    }
    pub fn advertisementEndpoints(self: *const NetworkCore) ?AdvertisementEndpoints {
        return if (self.discovery) |owned| owned.endpoints else null;
    }
    pub fn localState(self: *const NetworkCore) t.LocalState {
        return self.peer_manager.local;
    }
    /// Copied bounded observations. Does not advance time, policy, scores or event borrows.
    pub fn diagnostics(self: *const NetworkCore) Diagnostics {
        return .{ .runtime = self.counters, .transport = self.transport.engine.counters, .transport_resources = self.transport.engine.resourceSnapshot(), .core = self.peer_manager.diagnostics(&self.service) };
    }
    pub fn memoryPlan(self: *const NetworkCore) MemoryPlan {
        std.debug.assert(self.reservations.bytes == self.memory.allocated_bytes);
        return self.memory;
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
        try self.peer_manager.addDirectPeer(&self.service, identity, addresses, now);
    }
    pub fn removeDirectPeer(self: *NetworkCore, identity: *const t.PeerId) bool {
        return self.peer_manager.removeDirectPeer(&self.service, identity);
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
        return self.peer_manager.closePeer(&self.service, &self.transport.engine, peer, connection, now);
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
        try self.peer_manager.updateStatus(&self.service, status);
    }
    pub fn sendReqRespRequest(self: *NetworkCore, identity: *const t.PeerId, protocol: rr.Protocol, request: []const u8, sink: []u8, options: rr.RequestOptions, now: Now) !rr.RequestHandle {
        const peer = self.peer_manager.catalog.find(identity) orelse return error.StalePeer;
        const snapshot = self.peer_manager.catalog.get(peer) orelse return error.StalePeer;
        const conn = snapshot.connection orelse return error.Disconnected;
        return managed.sendReqRespRequest(&self.peer_manager, &self.service, &self.transport.engine, conn, protocol, request, sink, options, now);
    }
    pub fn consume(self: *NetworkCore, request: rr.RequestHandle, now: Now) bool {
        return self.service.reqresp.consume(request, now);
    }
    pub fn respond(self: *NetworkCore, request: rr.RequestHandle, bytes: []const u8, context: ?rr.ForkEntry, now: Now) !void {
        try self.service.reqresp.respond(request, bytes, context, now);
    }
    pub fn respondError(self: *NetworkCore, request: rr.RequestHandle, code: u8, message: []const u8, now: Now) !void {
        try self.service.reqresp.respondError(request, code, message, now);
    }
    pub fn finish(self: *NetworkCore, request: rr.RequestHandle, now: Now) bool {
        return self.service.reqresp.finish(request, now);
    }
    pub fn cancel(self: *NetworkCore, request: rr.RequestHandle) bool {
        return self.service.reqresp.cancel(request);
    }
    pub fn errorMessage(self: *const NetworkCore, request: rr.RequestHandle) []const u8 {
        return self.service.reqresp.errorMessage(request);
    }

    pub fn publishGossipWithOptions(self: *NetworkCore, topic: []const u8, bytes: []const u8, options: gossip.Gossipsub.PublishOptions, now: Now) !gossip.Gossipsub.PublishOutcome {
        return managed.publishGossipWithOptions(&self.peer_manager, &self.service, topic, bytes, options, now);
    }
    pub fn reportValidation(self: *NetworkCore, handle: gossip.ValidationHandle, verdict: gossip.Verdict, now: Now) gossip.ReportOutcome {
        return self.service.gossipsub.report(handle, verdict, now);
    }
    /// Borrows the last step's authenticated transport events until the next step.
    pub fn transportEvents(self: *const NetworkCore) []const engine.Event {
        return self.native_events[0..self.native_event_count];
    }
    pub fn completeSnapshots(self: *const NetworkCore, out: []t.Snapshot) error{OutputTooSmall}!usize {
        if (out.len < self.peer_manager.catalog.options.capacity) return error.OutputTooSmall;
        return self.peer_manager.snapshots(out);
    }
    pub fn beginGracefulClose(self: *NetworkCore, now: Now) void {
        managed.beginGracefulClose(&self.peer_manager, &self.service, now);
    }

    /// Caller sequence input is ignored on updates; only changed metadata advances its counter.
    pub fn updateLocal(self: *NetworkCore, desired: *const t.LocalState, schedule: ForkSchedule, now: Now) !bool {
        return self.updateLocalWithEndpoints(desired, schedule, self.advertisementEndpoints(), now);
    }

    pub fn updateLocalWithEndpoints(self: *NetworkCore, desired: *const t.LocalState, schedule: ForkSchedule, endpoints: ?AdvertisementEndpoints, now: Now) !bool {
        return self.applyLocal(&.{
            .local = desired.*,
            .schedule = schedule,
            .endpoints = endpoints,
            .capabilities = self.service.router.capabilities(),
        }, now);
    }

    fn prepareIdentifyLocal(self: *const NetworkCore, endpoints: ?AdvertisementEndpoints, capabilities: @import("capabilities.zig").Directional) !?@import("identify/root.zig").Local {
        const identify = if (self.service.identify) |*value| value else return null;
        var local = identify.local.?;
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
        identify: ?@import("identify/root.zig").Local,
        record: ?d.identity.enr.Record = null,
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
            try validateEndpoints(value);
            try validateEndpointFamilies(value, self.transport.udp.localAddresses(), &self.discovery.?.transport.sockets);
        }
        var local = update.local;
        local.metadata.seq_number = self.peer_manager.local.metadata.seq_number;
        try peers.control_wire.copyServingLocal(&local, &local, capabilities.receive);
        try validateSchedule(&local, schedule);
        const request = &self.service.reqresp;
        try validateForkTable(request.forks[0..request.fork_count], &local.fork);
        const identify_local = try self.prepareIdentifyLocal(endpoints, capabilities);
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
            const advertisement = advertisementFor(&local, schedule, endpoints.?);
            const previous = advertisementFor(&self.peer_manager.local, self.schedule, owned.endpoints);
            if (!std.meta.eql(advertisement, previous)) {
                const sequence = try peers.enr.nextSequence(owned.transport.engine.localRecord().sequence);
                prepared.record = try peers.enr.build(&owned.transport.engine.channel.local_key, sequence, &advertisement, &local.fork);
            }
        };
        return prepared;
    }

    fn publishLocal(self: *NetworkCore, prepared: *const PreparedLocal) !void {
        if (prepared.record) |*record| try self.discovery.?.transport.engine.updateLocalRecord(record);
    }

    fn commitLocal(self: *NetworkCore, prepared: *const PreparedLocal, now: Now) void {
        std.debug.assert(prepared.changed);
        if (self.discovery) |owned| {
            owned.endpoints = prepared.endpoints.?;
            owned.coordinator.updateFork(&prepared.local.fork) catch unreachable;
        }
        if (self.service.identify) |*identify| identify.local = prepared.identify;
        self.service.router.setCapabilities(prepared.capabilities);
        self.peer_manager.commitLocal(&self.service, &prepared.local, now);
        self.schedule = prepared.schedule;
    }

    /// Prepares every owner before ENR publication; caller sequence input is ignored.
    pub fn applyLocal(self: *NetworkCore, update: *const LocalUpdate, now: Now) !bool {
        const prepared = try self.prepareLocal(update);
        if (!prepared.changed) return false;
        try self.publishLocal(&prepared);
        self.commitLocal(&prepared, now);
        return true;
    }

    /// Applies a complete copied subscription union in this serialized call without ending event borrows.
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
        if (changed) std.log.scoped(.network_core).debug("intent_applied local_changed={any} topics_changed={any} demand_changed={any} subscriptions={d} fork={s} digest={x}", .{ prepared.changed, topics_changed, demand_changed, intent.subscriptions.len, @tagName(prepared.local.fork.fork), prepared.local.fork.digest });
        return changed;
    }

    /// Borrows a readable OS descriptor. The host drains it after a returned
    /// readiness.host indication and detaches before closing or reusing it.
    /// Shutdown/deinit detach without draining or closing caller storage.
    pub fn setHostWake(self: *NetworkCore, descriptor: ?i32) error{ UnsupportedWait, InvalidWakeSource, Stopped }!void {
        if (descriptor) |fd| {
            if (self.peer_manager.stopped) return error.Stopped;
            if (self.wait_mode != .native_poll or !wait.supported) return error.UnsupportedWait;
            if (comptime wait.supported) {
                if (fd < 0) return error.InvalidWakeSource;
                for (self.transport.udp.sockets.handles()) |socket| if (socket == fd) return error.InvalidWakeSource;
                if (self.discovery) |owned| for (owned.transport.sockets.handles()) |socket| if (socket == fd) return error.InvalidWakeSource;
            }
        }
        self.host_wake = descriptor;
    }

    pub fn nextWakeup(self: *NetworkCore, now: Now, outputs: Outputs) ?u64 {
        var due = managed.nextWakeup(&self.peer_manager, &self.service, now, outputs.peers.len, outputs.application.len, outputs.gossipsub.len, 4);
        if (self.transport.nextTimeoutMs(now)) |relative| due = earlier(due, now.mono_ms +| relative);
        if (!self.peer_manager.quiescing) if (self.discovery) |owned| if (owned.coordinator.nextWakeup(now.mono_ms)) |deadline| {
            due = earlier(due, deadline);
        };
        return due;
    }

    /// One Service borrow window per turn. Returned counts remain valid even when failure is set.
    /// The host bounds max_wait_ms by its next required slot update; no slot clock is inferred.
    pub fn step(self: *NetworkCore, io: std.Io, now: Now, current_slot: u64, outputs: Outputs, max_wait_ms: u32) Result {
        self.last_now = now;
        var result: Result = .{ .transport = .{ .now = now } };
        const due = self.nextWakeup(now, outputs);
        const bounded_wait: u32 = if (self.peer_manager.stopped) 0 else @intCast(@min(max_wait_ms, (due orelse std.math.maxInt(u64)) -| now.mono_ms));
        var receive_wait = @min(bounded_wait, poll_wait_max_ms);
        if (self.wait_mode == .native_poll) {
            if (comptime wait.supported) {
                result.readiness = wait.poll(io, .{
                    .quic = self.transport.udp.sockets.handles(),
                    .discovery = if (!self.peer_manager.quiescing and self.discovery != null) self.discovery.?.transport.sockets.handles() else .{ null, null },
                    .host = self.host_wake,
                }, bounded_wait);
            } else result.readiness.failure = error.UnsupportedWait;
            receive_wait = 0;
            self.counters.readiness_calls +|= 1;
            self.counters.readiness_nonzero_waits +|= @intFromBool(result.readiness.timeout_ms > 0);
            self.counters.readiness_interruptions +|= @intFromBool(result.readiness.interrupted);
            self.counters.readiness_failures +|= @intFromBool(result.readiness.failure != null);
        }
        const step_start = @import("metrics/timing.zig").now(io);
        defer self.step_duration.observe(@import("metrics/timing.zig").now(io) -| step_start);
        const progress = self.transport.step(io, self.native_events, self.activity, .{ .wait_max_ms = receive_wait });
        result.transport = progress.progress;
        self.native_event_count = result.transport.events;
        result.failure = result.readiness.failure orelse progress.failure;
        if (progress.failure != null) self.counters.transport_failures +|= 1;
        const tick: Now = if (progress.progress.now.mono_ms >= now.mono_ms) progress.progress.now else now;
        self.last_now = tick;
        result.counts = managed.process(&self.peer_manager, &self.service, &self.transport.engine, self.native_events[0..result.transport.events], self.activity[0..result.transport.activity], tick, current_slot, outputs.peers, outputs.application, outputs.gossipsub);
        if (!self.peer_manager.stopped and !self.peer_manager.quiescing) {
            // This turn's coverage selection already ran, without a second protocol pump.
            if (self.discovery) |owned| {
                const need = self.peer_manager.discoveryNeed();
                owned.coordinator.request(need.query(tick.mono_ms +| 1_000), tick.mono_ms) catch unreachable;
                var candidates: [managed.candidates_per_turn]peers.enr.Candidate = undefined;
                result.discovery = owned.coordinator.step(io, tick.mono_ms, tick.mono_ms, &candidates) catch |err| .{ .failure = err };
                for (candidates[0..result.discovery.candidates]) |*candidate| {
                    self.counters.discovered +|= 1;
                    if (futureCompatible(candidate, self.schedule)) |compatible| {
                        if (!compatible) self.counters.future_fork_mismatches +|= 1;
                    } else self.counters.future_fork_unknown +|= 1;
                }
                const intake = self.peer_manager.discoveredBatch(&self.service, candidates[0..result.discovery.candidates], tick);
                self.counters.candidates_refused +|= intake.refused;
                if (result.discovery.candidates > 0) std.log.scoped(.network_discovery).debug("candidates_received count={d} refused={d}", .{ result.discovery.candidates, intake.refused });
                if (result.discovery.failure) |err| {
                    std.log.scoped(.network_discovery).debug("discovery_failed stage={s} reason={s}", .{ @tagName(result.discovery.failure_stage), @errorName(err) });
                    self.counters.discovery_failures +|= 1;
                    result.failure = result.failure orelse err;
                }
            }
            var intents: [managed.dials_per_turn]managed.DialIntent = undefined;
            const room = self.transport.engine.limits.dialing_max -| self.transport.engine.registry.dialing;
            const count = self.peer_manager.dialIntents(&self.service, &self.transport.engine, tick, intents[0..@min(room, intents.len)]);
            for (intents[0..count]) |intent| {
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
                    continue;
                };
                std.debug.assert(self.peer_manager.dialStarted(intent.token, handle));
                std.log.scoped(.network_core).debug("dial_started peer={f} endpoint={any} connection={d}:{d}", .{ @import("logging.zig").peer(&intent.peer), intent.address, handle.index, handle.generation });
                result.dial_started += 1;
            }
            self.counters.dial_started +|= result.dial_started;
            self.counters.dial_deferred +|= result.dial_deferred;
            self.counters.dial_failed +|= result.dial_failed;
        }
        return result;
    }
};

fn earlier(current: ?u64, deadline: u64) u64 {
    return @min(current orelse deadline, deadline);
}
fn validateForkTable(table: []const rr.ForkEntry, context: *const t.ForkContext) !void {
    try rr.reqresp.validateForkTable(table);
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
pub fn futureCompatible(candidate: *const peers.enr.Candidate, schedule: ForkSchedule) ?bool {
    return compatibleHint(candidate.fork, candidate.next_fork_digest, schedule);
}
fn compatibleHint(fork: peers.enr.ForkId, next_digest: ?[4]u8, schedule: ForkSchedule) ?bool {
    if (fork.next_epoch != schedule.next_epoch or !std.mem.eql(u8, &fork.next_version, &schedule.next_version)) return false;
    return if (next_digest) |digest| std.mem.eql(u8, &digest, &schedule.next_digest) else null;
}
fn advertisementFor(local: *const t.LocalState, schedule: ForkSchedule, endpoints: AdvertisementEndpoints) peers.enr.LocalAdvertisement {
    return .{
        .fork = .{ .digest = local.fork.digest, .next_version = schedule.next_version, .next_epoch = schedule.next_epoch },
        .next_fork_digest = if (schedule.fulu_scheduled or local.fork.fork.gte(.fulu)) schedule.next_digest else null,
        .attnets = local.metadata.attnets,
        .syncnets = if (local.fork.fork.gte(.altair)) local.metadata.syncnets else null,
        .custody_group_count = local.metadata.custody_group_count,
        .ip4 = endpoints.ip4,
        .ip6 = endpoints.ip6,
        .udp = endpoints.udp,
        .udp6 = endpoints.udp6,
        .quic = endpoints.quic,
        .quic6 = endpoints.quic6,
    };
}
fn validateEndpoints(endpoints: AdvertisementEndpoints) error{InvalidAdvertisement}!void {
    if ((endpoints.udp == null and endpoints.udp6 == null) or (endpoints.quic == null and endpoints.quic6 == null)) return error.InvalidAdvertisement;
    if ((endpoints.udp != null or endpoints.quic != null) and endpoints.ip4 == null) return error.InvalidAdvertisement;
    if ((endpoints.udp6 != null or endpoints.quic6 != null) and endpoints.ip6 == null) return error.InvalidAdvertisement;
    inline for (.{ endpoints.udp, endpoints.udp6, endpoints.quic, endpoints.quic6 }) |port| if (port) |value| if (value == 0) return error.InvalidAdvertisement;
    if (endpoints.ip4) |ip| {
        const source: d.types.Address = .{ .ip4 = .{ .octets = ip, .port = d.Lookup.discovered_port_min } };
        if (!peers.discovery.relayAllowed(source, .{ .ip4 = .{ .octets = ip, .port = d.Lookup.discovered_port_min } })) return error.InvalidAdvertisement;
    }
    if (endpoints.ip6) |ip| {
        const source: d.types.Address = .{ .ip6 = .{ .octets = ip, .port = d.Lookup.discovered_port_min } };
        if (!peers.discovery.relayAllowed(source, .{ .ip6 = .{ .octets = ip, .port = d.Lookup.discovered_port_min } })) return error.InvalidAdvertisement;
    }
}
fn validateEndpointFamilies(endpoints: AdvertisementEndpoints, quic: [2]?t.Address, udp: *const @import("udp").Sockets) error{InvalidAdvertisement}!void {
    if ((endpoints.quic != null and quic[0] == null) or (endpoints.quic6 != null and quic[1] == null) or
        (endpoints.udp != null and udp.values[0] == null) or (endpoints.ip6 != null and (endpoints.udp6 orelse endpoints.udp) != null and udp.values[1] == null)) return error.InvalidAdvertisement;
}

fn defaultEndpoints(quic: [2]?t.Address, udp: *const @import("udp").Sockets) error{InvalidAdvertisement}!AdvertisementEndpoints {
    var endpoints: AdvertisementEndpoints = .{};
    for (quic) |address| if (address) |value| switch (value) {
        .ip4 => |ip| {
            endpoints.ip4 = ip.octets;
            endpoints.quic = ip.port;
        },
        .ip6 => |ip| {
            endpoints.ip6 = ip.octets;
            endpoints.quic6 = ip.port;
        },
    };
    for (udp.values) |socket| if (socket) |value| switch (value.address) {
        .ip4 => |ip| {
            if (endpoints.ip4) |advertised| if (!std.mem.eql(u8, &advertised, &ip.bytes)) return error.InvalidAdvertisement;
            endpoints.ip4 = ip.bytes;
            endpoints.udp = ip.port;
        },
        .ip6 => |ip| {
            if (endpoints.ip6) |advertised| if (!std.mem.eql(u8, &advertised, &ip.bytes)) return error.InvalidAdvertisement;
            endpoints.ip6 = ip.bytes;
            endpoints.udp6 = ip.port;
        },
    };
    return endpoints;
}

test {
    _ = @import("network_core_test.zig");
    _ = @import("network_core_metrics_test.zig");
}
