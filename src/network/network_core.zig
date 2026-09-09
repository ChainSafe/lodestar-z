const std = @import("std");
const d = @import("discv5");
const core_mod = @import("core.zig");
const transport_mod = @import("transport.zig");
const driver = @import("driver.zig");
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
    subscriptions: []const gossip.local_intent.Subscription,
};
pub const DiscoveryOptions = struct {
    advertisement: ?AdvertisementEndpoints = null,
    bind: std.Io.net.IpAddress,
    sequence: u64 = 1,
    bootstrap: []const d.identity.enr.Record = &.{},
    engine: d.Engine.Config = .{},
    coordinator: peers.discovery.Options = .{},
};
pub const Options = struct {
    transport: transport_mod.Options,
    core: core_mod.Options,
    local: t.LocalState,
    schedule: ForkSchedule,
    discovery: ?DiscoveryOptions = null,
    byte_limit: ?usize = null,
    wait_mode: wait.Mode = .portable,
};
pub const ManagedOptions = struct {
    wait_mode: wait.Mode = .portable,
    host: *const @import("wire/keys.zig").KeyPair,
    bind: std.Io.net.IpAddress,
    configuration: @import("configuration.zig").Request,
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
    counts: core_mod.Counts = .{ .peers = 0, .application = 0, .gossipsub = 0 },
    transport: driver.StepResult,
    readiness: wait.Result = .{},
    discovery: peers.discovery.Result = .{},
    failure: ?OperationalError = null,
    dial_started: u8 = 0,
    dial_deferred: u8 = 0,
    dial_failed: u8 = 0,
};
pub const FutureForkHint = struct {
    record_sequence: u64,
    fork: peers.enr.ForkId,
    next_digest: ?[4]u8,
    compatible: bool,
};
pub const Counters = struct {
    discovered: u64 = 0,
    candidates_refused: u64 = 0,
    future_fork_mismatches: u64 = 0,
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
    core: core_mod.Core.Diagnostics,
};
pub const MemoryPlan = struct {
    inline_bytes: usize = @sizeOf(NetworkCore),
    allocated_bytes: usize = 0,
    transport_bytes: usize = 0,
    core_bytes: usize = 0,
    scratch_bytes: usize = 0,
    local_intent_bytes: usize = 0,
    discovery_bytes: usize = 0,
    transport_windows: @import("quic/api.zig").MemoryPlan,
    caller_borrows_included: bool = false,
    allocator_native_os_overhead_included: bool = false,
};

const DiscoveryOwners = struct {
    udp: d.Udp,
    engine: d.Engine,
    driver: d.Driver,
    coordinator: peers.Discovery,
    endpoints: AdvertisementEndpoints,

    fn init(self: *DiscoveryOwners, allocator: std.mem.Allocator, io: std.Io, options: DiscoveryOptions, host: *const @import("wire/keys.zig").KeyPair, local: *const t.LocalState, schedule: ForkSchedule, quic: t.Address, now: Now) !void {
        self.udp = try d.Udp.bind(io, options.bind);
        errdefer self.udp.close(io);
        self.endpoints = options.advertisement orelse try defaultEndpoints(quic, self.udp.localAddress());
        try validateEndpoints(self.endpoints);
        const advertisement = advertisementFor(local, schedule, self.endpoints);
        const record = try peers.enr.build(&host.inner, options.sequence, &advertisement, &local.fork);
        try peers.enr.requireIdentity(&record, &t.PeerId.fromPublicKey(&host.publicKey()));
        try self.engine.initWithConfig(allocator, host.inner, record, options.engine);
        errdefer self.engine.deinit(allocator);
        self.driver = try d.Driver.initWithConfig(&self.engine, &self.udp, .{ .poll_interval_ms = poll_wait_max_ms });
        var coordinator_options = options.coordinator;
        coordinator_options.quic_ipv6_enabled = quic == .ip6;
        self.coordinator = try peers.Discovery.init(allocator, &self.driver, &local.fork, options.bootstrap, now.mono_ms, coordinator_options);
    }
    fn deinit(self: *DiscoveryOwners, allocator: std.mem.Allocator, io: std.Io) void {
        self.coordinator.deinit();
        self.engine.deinit(allocator);
        self.udp.close(io);
    }
};

/// Initialize at its final address. Serialize every call, including reads and teardown.
pub const NetworkCore = struct {
    reservations: @import("reservations.zig").Reservations,
    memory: MemoryPlan,
    allocator: std.mem.Allocator,
    transport: transport_mod.Transport,
    core: core_mod.Core,
    discovery: ?*DiscoveryOwners,
    native_events: []engine.Event,
    native_event_count: usize = 0,
    activity: []engine.Handle,
    local_intent_workspace: *gossip.local_intent.Workspace,
    schedule: ForkSchedule,
    counters: Counters = .{},
    last_now: Now,
    initialized: bool = false,
    wait_mode: wait.Mode,
    host_wake: ?i32 = null,

    pub fn init(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, options: Options) !void {
        if (options.wait_mode == .native_poll and !wait.supported) return error.UnsupportedWait;
        try @import("configuration.zig").validate(options.transport.limits, options.core);
        var local: t.LocalState = undefined;
        try peers.control_wire.copyLocal(&local, &options.local);
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
        self.last_now = try driver.currentTime(io);
        try self.transport.init(allocator, io, options.transport);
        errdefer self.transport.deinit(io);
        self.memory = .{ .transport_bytes = self.reservations.bytes, .transport_windows = self.transport.memoryPlan() };
        self.core = try core_mod.Core.init(allocator, &self.transport.peerId(), &local, options.core);
        errdefer self.core.deinit();
        if (self.core.service.identify) |*identify| identify.bind(&self.transport.engine);
        self.memory.core_bytes = self.core.memoryPlan().allocated_bytes;
        const event_capacity = @as(usize, options.transport.limits.connections_max) *
            (2 * @import("quic/limits.zig").streams_per_connection + 3);
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
            try owned.init(allocator, io, discovery_options, options.transport.host, &local, options.schedule, self.transport.localAddress(), self.last_now);
            self.discovery = owned;
        }
        errdefer if (self.discovery) |owned| {
            owned.deinit(allocator, io);
            allocator.destroy(owned);
        };
        const identify_local = try self.prepareIdentifyLocal(self.advertisementEndpoints(), self.core.service.router.capabilities());
        if (self.core.service.identify) |*identify| identify.local = identify_local;
        self.memory.discovery_bytes = self.reservations.bytes - before_discovery;
        self.memory.allocated_bytes = self.reservations.bytes;
        std.debug.assert(self.memory.allocated_bytes == self.memory.transport_bytes + self.memory.core_bytes + self.memory.scratch_bytes + self.memory.local_intent_bytes + self.memory.discovery_bytes);
        self.initialized = true;
    }

    pub fn initManaged(self: *NetworkCore, backing: std.mem.Allocator, io: std.Io, options: ManagedOptions) !void {
        const resolved = try @import("configuration.zig").resolve(options.configuration);
        try self.init(backing, io, .{
            .transport = .{ .host = options.host, .bind = options.bind, .limits = resolved.limits },
            .core = resolved.core,
            .local = options.local,
            .schedule = options.schedule,
            .discovery = options.discovery,
            .byte_limit = resolved.byte_limit,
            .wait_mode = options.wait_mode,
        });
    }

    pub fn deinit(self: *NetworkCore, io: std.Io) void {
        if (!self.initialized) return;
        self.shutdown(self.last_now);
        if (self.discovery) |owned| {
            owned.deinit(self.allocator, io);
            self.allocator.destroy(owned);
        }
        self.allocator.destroy(self.local_intent_workspace);
        self.core.deinit();
        self.allocator.free(self.activity);
        self.allocator.free(self.native_events);
        self.transport.deinit(io);
        std.debug.assert(self.reservations.bytes == 0);
        self.initialized = false;
    }
    pub fn shutdown(self: *NetworkCore, now: Now) void {
        self.host_wake = null;
        self.last_now = now;
        self.core.shutdown(&self.transport.engine, now);
        if (self.discovery) |owned| owned.coordinator.cancel();
        // Include handshakes not yet admitted to the catalog.
        for (self.transport.engine.registry.slots, 0..) |slot, index| {
            const handle: engine.Handle = .{ .index = @intCast(index), .generation = slot.generation };
            if (!self.transport.engine.abandon(handle)) _ = self.transport.engine.close(handle, 0);
        }
    }
    pub fn isClosed(self: *const NetworkCore) bool {
        return self.core.stopped and self.transport.engine.registry.active_len == 0;
    }
    pub fn peerId(self: *const NetworkCore) t.PeerId {
        return self.transport.peerId();
    }
    pub fn localAddress(self: *const NetworkCore) t.Address {
        return self.transport.localAddress();
    }
    pub fn localMultiaddr(self: *const NetworkCore) @import("wire/multiaddr.zig").Multiaddr {
        return self.transport.localMultiaddr();
    }
    pub fn localRecord(self: *const NetworkCore) ?*const d.identity.enr.Record {
        return if (self.discovery) |owned| owned.engine.localRecord() else null;
    }
    pub fn advertisementEndpoints(self: *const NetworkCore) ?AdvertisementEndpoints {
        return if (self.discovery) |owned| owned.endpoints else null;
    }
    pub fn localState(self: *const NetworkCore) t.LocalState {
        return self.core.local;
    }
    pub fn futureForkHint(self: *const NetworkCore, identity: *const t.PeerId, now: Now) ?FutureForkHint {
        const hints = self.core.candidateHints(identity, now) orelse return null;
        return .{ .record_sequence = hints.sequence, .fork = hints.fork, .next_digest = hints.next_fork_digest, .compatible = compatibleHint(hints.fork, hints.next_fork_digest, self.schedule) };
    }
    /// Copied bounded observations. Does not advance time, policy, scores or event borrows.
    pub fn diagnostics(self: *const NetworkCore) Diagnostics {
        return .{ .runtime = self.counters, .transport = self.transport.engine.counters, .transport_resources = self.transport.engine.resourceSnapshot(), .core = self.core.diagnostics() };
    }
    pub fn memoryPlan(self: *const NetworkCore) MemoryPlan {
        std.debug.assert(self.reservations.bytes == self.memory.allocated_bytes);
        return self.memory;
    }
    pub fn setDemand(self: *NetworkCore, demand: *const t.Demand) !void {
        try self.core.setDemand(demand);
    }
    pub fn coverageDeficits(self: *NetworkCore) peers.policy.Deficits {
        return self.core.coverageDeficits();
    }
    pub fn peerCounts(self: *const NetworkCore) core_mod.Core.PeerCounts {
        return self.core.peerCounts();
    }
    pub fn connect(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now) !void {
        try self.core.connect(identity, addresses, now);
    }
    pub fn connectUntil(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now, deadline_ms: u64) !void {
        try self.core.connectUntil(identity, addresses, now, deadline_ms);
    }
    pub fn cancelConnect(self: *NetworkCore, identity: *const t.PeerId, now: Now) void {
        self.core.dial_queue.cancelConnect(&self.transport.engine, identity, now.mono_ms);
        self.core.policy_dirty = true;
    }
    pub fn addDirectPeer(self: *NetworkCore, identity: *const t.PeerId, addresses: []const t.Address, now: Now) !void {
        try self.core.addDirectPeer(identity, addresses, now);
    }
    pub fn removeDirectPeer(self: *NetworkCore, identity: *const t.PeerId) bool {
        return self.core.removeDirectPeer(identity);
    }
    pub fn directPeers(self: *const NetworkCore, out: []t.PeerId) error{OutputTooSmall}!usize {
        return self.core.directPeers(out);
    }
    pub fn closePeer(self: *NetworkCore, peer: t.PeerRef, connection: t.Handle, now: Now) bool {
        return self.core.closePeer(&self.transport.engine, peer, connection, now);
    }
    pub fn reStatusPeer(self: *NetworkCore, peer: t.PeerRef, connection: t.Handle, now: Now) bool {
        return self.core.reStatusPeer(peer, connection, now);
    }
    pub fn disconnect(self: *NetworkCore, peer: t.PeerRef, reason: t.DisconnectReason, now: Now) bool {
        return self.core.disconnect(peer, reason, now);
    }
    pub fn reportPeer(self: *NetworkCore, peer: t.PeerRef, action: t.PeerAction, now: Now) ?t.ReputationDecision {
        return self.core.reportPeer(peer, action, now);
    }
    pub fn reStatusPeers(self: *NetworkCore, now: Now) void {
        self.core.reStatusPeers(now);
    }
    pub fn updateStatus(self: *NetworkCore, status: *const t.Status, now: Now) !void {
        var local = self.localState();
        local.status = status.*;
        _ = try self.updateLocal(&local, self.schedule, now);
    }
    pub fn updateMetadata(self: *NetworkCore, metadata: *const t.Metadata, now: Now) !void {
        var local = self.localState();
        local.metadata = metadata.*;
        _ = try self.updateLocal(&local, self.schedule, now);
    }
    pub fn sendReqRespRequest(self: *NetworkCore, peer: t.PeerRef, protocol: rr.Protocol, request: []const u8, sink: []u8, options: rr.RequestOptions, now: Now) !rr.RequestHandle {
        const snapshot = self.core.catalog.get(peer) orelse return error.StalePeer;
        const conn = snapshot.connection orelse return error.Disconnected;
        return self.core.sendReqRespRequest(&self.transport.engine, conn, protocol, request, sink, options, now);
    }
    pub fn consume(self: *NetworkCore, request: rr.RequestHandle, now: Now) bool {
        return self.core.consume(request, now);
    }
    pub fn respond(self: *NetworkCore, request: rr.RequestHandle, bytes: []const u8, context: ?rr.ForkEntry, now: Now) !void {
        try self.core.respond(request, bytes, context, now);
    }
    pub fn respondError(self: *NetworkCore, request: rr.RequestHandle, code: u8, message: []const u8, now: Now) !void {
        try self.core.respondError(request, code, message, now);
    }
    pub fn finish(self: *NetworkCore, request: rr.RequestHandle, now: Now) bool {
        return self.core.finish(request, now);
    }
    pub fn cancel(self: *NetworkCore, request: rr.RequestHandle) bool {
        return self.core.cancel(request);
    }
    pub fn errorMessage(self: *const NetworkCore, request: rr.RequestHandle) []const u8 {
        return self.core.errorMessage(request);
    }
    /// Copies topic bytes and scalar policy without publishing or invalidating event borrows.
    pub fn configureTopic(self: *NetworkCore, topic: []const u8, params: *const gossip.score.TopicParams) (gossip.Gossipsub.ConfigureTopicError || error{Stopped})!void {
        try self.core.configureTopic(topic, params);
    }

    pub fn publishGossip(self: *NetworkCore, topic: []const u8, bytes: []const u8, now: Now) !gossip.Gossipsub.PublishOutcome {
        return self.publishGossipWithOptions(topic, bytes, .{}, now);
    }

    pub fn publishGossipWithOptions(self: *NetworkCore, topic: []const u8, bytes: []const u8, options: gossip.Gossipsub.PublishOptions, now: Now) !gossip.Gossipsub.PublishOutcome {
        return self.core.publishGossipWithOptions(topic, bytes, options, now);
    }
    pub fn subscribe(self: *NetworkCore, topic: []const u8) bool {
        return self.core.subscribe(topic);
    }
    pub fn unsubscribe(self: *NetworkCore, topic: []const u8) bool {
        return self.core.unsubscribe(topic);
    }
    pub fn reportValidation(self: *NetworkCore, handle: gossip.ValidationHandle, verdict: gossip.Verdict, now: Now) gossip.ReportOutcome {
        return self.core.reportValidation(handle, verdict, now);
    }
    /// Borrows the last step's authenticated transport events until the next step.
    pub fn transportEvents(self: *const NetworkCore) []const engine.Event {
        return self.native_events[0..self.native_event_count];
    }
    pub fn completeSnapshots(self: *const NetworkCore, out: []t.Snapshot) error{OutputTooSmall}!usize {
        if (out.len < self.core.catalog.rows.len) return error.OutputTooSmall;
        return self.core.snapshots(out);
    }
    pub fn beginGracefulClose(self: *NetworkCore, now: Now) void {
        self.core.beginGracefulClose(now);
    }
    pub fn snapshots(self: *const NetworkCore, out: []t.Snapshot) usize {
        return self.core.snapshots(out);
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
            .capabilities = self.core.service.router.capabilities(),
        }, now);
    }

    fn prepareIdentifyLocal(self: *const NetworkCore, endpoints: ?AdvertisementEndpoints, capabilities: @import("capabilities.zig").Directional) !?@import("identify/root.zig").Local {
        const identify = if (self.core.service.identify) |*value| value else return null;
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
        _ = try local.encode(capabilities.receive, &encoded);
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
        if (self.core.stopped) return error.Stopped;
        const schedule = update.schedule;
        const endpoints = update.endpoints;
        const capabilities = update.capabilities;
        try self.core.service.router.validateCapabilities(capabilities);
        if ((endpoints == null) != (self.discovery == null)) return error.InvalidAdvertisement;
        if (endpoints) |value| try validateEndpoints(value);
        var local = update.local;
        local.metadata.seq_number = self.core.local.metadata.seq_number;
        try peers.control_wire.copyLocal(&local, &local);
        try validateSchedule(&local, schedule);
        const request = &self.core.service.reqresp.inner;
        try validateForkTable(request.forks[0..request.fork_count], &local.fork);
        const identify_local = try self.prepareIdentifyLocal(endpoints, capabilities);
        const metadata_changed = !std.meta.eql(local.metadata, self.core.local.metadata);
        if (metadata_changed) local.metadata.seq_number = try peers.enr.nextSequence(local.metadata.seq_number);
        var prepared: PreparedLocal = .{
            .local = local,
            .schedule = schedule,
            .endpoints = endpoints,
            .capabilities = capabilities,
            .identify = identify_local,
            .changed = !(std.meta.eql(local, self.core.local) and std.meta.eql(schedule, self.schedule) and
                std.meta.eql(endpoints, self.advertisementEndpoints()) and std.meta.eql(capabilities, self.core.service.router.capabilities())),
        };
        if (prepared.changed) if (self.discovery) |owned| {
            const advertisement = advertisementFor(&local, schedule, endpoints.?);
            const previous = advertisementFor(&self.core.local, self.schedule, owned.endpoints);
            if (!std.meta.eql(advertisement, previous)) {
                const sequence = try peers.enr.nextSequence(owned.engine.localRecord().sequence);
                prepared.record = try peers.enr.build(&owned.engine.channel.local_key, sequence, &advertisement, &local.fork);
            }
        };
        return prepared;
    }

    fn publishLocal(self: *NetworkCore, prepared: *const PreparedLocal) !void {
        if (prepared.record) |*record| try self.discovery.?.engine.updateLocalRecord(record);
    }

    fn commitLocal(self: *NetworkCore, prepared: *const PreparedLocal, now: Now) void {
        std.debug.assert(prepared.changed);
        if (self.discovery) |owned| {
            owned.endpoints = prepared.endpoints.?;
            owned.coordinator.updateFork(&prepared.local.fork) catch unreachable;
        }
        if (self.core.service.identify) |*identify| identify.local = prepared.identify;
        self.core.service.router.setCapabilities(prepared.capabilities);
        self.core.commitLocal(&prepared.local, now);
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
        try demand.validate(&prepared.local.fork, self.core.catalog.options.max_peers);
        const topics_changed = try self.core.service.gossipsub.inner.prepareSubscriptions(intent.subscriptions, self.local_intent_workspace, now);
        const demand_changed = !std.meta.eql(demand, self.core.demand);
        if (!prepared.changed and !topics_changed and !demand_changed) return false;
        try self.publishLocal(&prepared);
        if (prepared.changed) self.commitLocal(&prepared, now);
        if (topics_changed) self.core.service.gossipsub.inner.commitSubscriptions(self.local_intent_workspace);
        if (demand_changed) {
            self.core.demand = demand;
            self.core.policy_dirty = true;
        }
        std.log.scoped(.network_core).debug("intent_applied local_changed={any} topics_changed={any} demand_changed={any} subscriptions={d} fork={s} digest={x}", .{ prepared.changed, topics_changed, demand_changed, intent.subscriptions.len, @tagName(prepared.local.fork.fork), prepared.local.fork.digest });
        return true;
    }

    /// Borrows a readable OS descriptor. The host drains it after a returned
    /// readiness.host indication and detaches before closing or reusing it.
    /// Shutdown/deinit detach without draining or closing caller storage.
    pub fn setHostWake(self: *NetworkCore, descriptor: ?i32) error{ UnsupportedWait, InvalidWakeSource, Stopped }!void {
        if (descriptor) |fd| {
            if (self.core.stopped) return error.Stopped;
            if (self.wait_mode != .native_poll or !wait.supported) return error.UnsupportedWait;
            if (comptime wait.supported) {
                if (fd < 0 or fd == self.transport.udp.socket.handle or
                    (self.discovery != null and fd == self.discovery.?.udp.socket.handle)) return error.InvalidWakeSource;
            }
        }
        self.host_wake = descriptor;
    }

    pub fn nextWakeup(self: *NetworkCore, now: Now, outputs: Outputs) ?u64 {
        var due = self.core.nextWakeup(now, outputs.peers.len, outputs.application.len, outputs.gossipsub.len, 4);
        if (self.transport.nextTimeoutMs(now)) |relative| due = earlier(due, now.mono_ms +| relative);
        if (!self.core.quiescing) if (self.discovery) |owned| if (owned.coordinator.nextWakeup(now.mono_ms)) |deadline| {
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
        const bounded_wait: u32 = if (self.core.stopped) 0 else @intCast(@min(max_wait_ms, (due orelse std.math.maxInt(u64)) -| now.mono_ms));
        var receive_wait = @min(bounded_wait, poll_wait_max_ms);
        if (self.wait_mode == .native_poll) {
            if (comptime wait.supported) {
                result.readiness = wait.poll(io, .{
                    .quic = self.transport.udp.socket.handle,
                    .discovery = if (!self.core.quiescing and self.discovery != null) self.discovery.?.udp.socket.handle else null,
                    .host = self.host_wake,
                }, bounded_wait);
            } else result.readiness.failure = error.UnsupportedWait;
            receive_wait = 0;
            self.counters.readiness_calls +|= 1;
            self.counters.readiness_nonzero_waits +|= @intFromBool(result.readiness.timeout_ms > 0);
            self.counters.readiness_interruptions +|= @intFromBool(result.readiness.interrupted);
            self.counters.readiness_failures +|= @intFromBool(result.readiness.failure != null);
        }
        const progress = self.transport.stepProgress(io, self.native_events, self.activity, .{ .wait_max_ms = receive_wait });
        result.transport = progress.progress;
        self.native_event_count = result.transport.events;
        result.failure = result.readiness.failure orelse progress.failure;
        if (progress.failure != null) self.counters.transport_failures +|= 1;
        const tick: Now = if (progress.progress.now.mono_ms >= now.mono_ms) progress.progress.now else now;
        self.last_now = tick;
        result.counts = self.core.process(&self.transport.engine, self.native_events[0..result.transport.events], self.activity[0..result.transport.activity], tick, current_slot, outputs.peers, outputs.application, outputs.gossipsub);
        if (!self.core.stopped and !self.core.quiescing) {
            // Expiry and this turn's coverage selection already ran, without a second protocol pump.
            if (self.discovery) |owned| {
                const need = self.core.discoveryNeed();
                owned.coordinator.request(need.query(tick.mono_ms +| 1_000), tick.mono_ms) catch unreachable;
                var candidates: [16]peers.enr.Candidate = undefined;
                result.discovery = owned.coordinator.step(io, tick.mono_ms, tick.mono_ms, &candidates) catch |err| .{ .failure = err };
                for (candidates[0..result.discovery.candidates]) |*candidate| {
                    self.counters.discovered +|= 1;
                    if (!futureCompatible(candidate, self.schedule)) self.counters.future_fork_mismatches +|= 1;
                }
                const intake = self.core.discoveredBatch(candidates[0..result.discovery.candidates], tick);
                self.counters.candidates_refused +|= intake.refused;
                if (result.discovery.candidates > 0) std.log.scoped(.network_discovery).debug("candidates_received count={d} refused={d}", .{ result.discovery.candidates, intake.refused });
                if (result.discovery.failure) |err| {
                    std.log.scoped(.network_discovery).debug("discovery_failed stage={s} reason={s}", .{ @tagName(result.discovery.failure_stage), @errorName(err) });
                    self.counters.discovery_failures +|= 1;
                    result.failure = result.failure orelse err;
                }
            }
            var intents: [4]core_mod.DialIntent = undefined;
            const room = self.transport.engine.limits.dialing_max -| self.transport.engine.registry.dialing;
            const count = self.core.dialIntents(&self.transport.engine, tick, intents[0..@min(room, intents.len)]);
            for (intents[0..count]) |intent| {
                const handle = self.transport.dialPeer(io, intent.address, intent.peer) catch |err| {
                    if (err == error.DestinationUnreachable) {
                        std.log.scoped(.network_core).debug("dial_failed peer={f} endpoint={any} reason={s}", .{ @import("logging.zig").peer(&intent.peer), intent.address, @errorName(err) });
                        std.debug.assert(self.core.dialFailed(intent.token, tick));
                        result.dial_failed += 1;
                    } else {
                        std.log.scoped(.network_core).debug("dial_deferred peer={f} endpoint={any} reason={s}", .{ @import("logging.zig").peer(&intent.peer), intent.address, @errorName(err) });
                        std.debug.assert(self.core.dialDeferred(intent.token, tick));
                        result.dial_deferred += 1;
                    }
                    result.failure = result.failure orelse err;
                    continue;
                };
                std.debug.assert(self.core.dialStarted(intent.token, handle));
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
pub fn futureCompatible(candidate: *const peers.enr.Candidate, schedule: ForkSchedule) bool {
    return compatibleHint(candidate.fork, candidate.next_fork_digest, schedule);
}
fn compatibleHint(fork: peers.enr.ForkId, next_digest: ?[4]u8, schedule: ForkSchedule) bool {
    if (fork.next_epoch != schedule.next_epoch or !std.mem.eql(u8, &fork.next_version, &schedule.next_version)) return false;
    return if (next_digest) |digest| std.mem.eql(u8, &digest, &schedule.next_digest) else true;
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
fn defaultEndpoints(quic: t.Address, udp: d.types.Address) error{InvalidAdvertisement}!AdvertisementEndpoints {
    var endpoints: AdvertisementEndpoints = .{};
    switch (quic) {
        .ip4 => |value| {
            endpoints.ip4 = value.octets;
            endpoints.quic = value.port;
        },
        .ip6 => |value| {
            endpoints.ip6 = value.octets;
            endpoints.quic6 = value.port;
        },
    }
    switch (udp) {
        .ip4 => |value| {
            if (endpoints.ip4) |ip| if (!std.mem.eql(u8, &ip, &value.octets)) return error.InvalidAdvertisement;
            endpoints.ip4 = value.octets;
            endpoints.udp = value.port;
        },
        .ip6 => |value| {
            if (endpoints.ip6) |ip| if (!std.mem.eql(u8, &ip, &value.octets)) return error.InvalidAdvertisement;
            endpoints.ip6 = value.octets;
            endpoints.udp6 = value.port;
        },
    }
    return endpoints;
}
