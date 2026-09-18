const std = @import("std");
const service_mod = @import("service.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const control_mod = @import("peers/control.zig");
const dial_mod = @import("peers/dial_queue.zig");
const custody = peers.custody;
const engine_mod = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
pub const controls_per_turn = 32;
pub const identify_per_turn = 8;
pub const dials_per_turn = 4;
pub const candidates_per_turn = 16;

const manager = @import("peer_manager.zig");
pub const PeerManager = manager.PeerManager;

pub const Options = struct {
    peers: t.Options = .{},
    service: service_mod.Options,
    control: control_mod.Options = .{},
    dial: dial_mod.Options,
    metadata_freshness_ms: u64 = 60_000,
};
pub fn peerOptions(options: Options) manager.Options {
    return .{ .peers = options.peers, .control = options.control, .dial = options.dial, .metadata_freshness_ms = options.metadata_freshness_ms };
}

pub fn serviceOptions(options: Options, local: *const t.LocalState) service_mod.Options {
    var result = options.service;
    result.automatic_gossip_admission = false;
    result.reqresp.request_fork = local.fork.fork;
    return result;
}

pub fn validateOptions(options: Options) !void {
    try PeerManager.validateOptions(peerOptions(options));
    if (options.service.reqresp.peers < options.peers.max_peers or
        options.service.reqresp.outbound_control_reserved < options.peers.max_peers or
        options.service.router.outbound_control_reserved < options.peers.max_peers)
        return error.InvalidOptions;
    try service_mod.Service.validateOptions(options.service);
}

pub const DialIntent = manager.DialIntent;
pub const DiscoveryNeed = manager.DiscoveryNeed;
pub const Counts = struct { peers: usize, application: usize, gossipsub: usize };

/// Public protocol borrows retain their Service lifetime until the next process call.
/// Internal closes after publication perform cleanup without a second owner recycling pass.
pub fn process(
    self: *PeerManager,
    service: *service_mod.Service,
    engine: *engine_mod.Engine,
    events: []const engine_mod.Event,
    activity: []const engine_mod.Handle,
    now: Now,
    slot: u64,
    peer_events: []t.Event,
    application: []rr.Event,
    gossip_events: []gossip.Event,
) Counts {
    const per_connection = @import("quic/limits.zig").events_per_connection;
    std.debug.assert(events.len <= @as(usize, engine.limits.connections_max) * per_connection);
    if (self.stopped) return .{
        .peers = self.catalog.pollEvents(peer_events),
        .application = 0,
        .gossipsub = 0,
    };
    self.current_slot = slot;
    if (slot >= self.demand.expires_at_slot and !std.meta.eql(self.demand, t.Demand{})) {
        self.demand = .{};
        self.selection_revision = null;
    }
    if (!self.quiescing) self.dial_queue.expire(engine, now.mono_ms);
    for (events) |event| self.transportEvent(service, engine, event, now);
    var controls: [controls_per_turn]rr.Event = undefined;
    var identify_results: [identify_per_turn]@import("identify/root.zig").Result = undefined;
    const counts = service.process(engine, events, activity, now, .{ .application = application, .control = &controls, .gossipsub = gossip_events, .identify = &identify_results });
    for ([_][]const rr.Event{ application[0..counts.application], controls[0..counts.control] }) |batch| {
        for (batch) |event| {
            const conn = service.reqresp.incompleteRequestTimeout(event) orelse continue;
            if (self.control.peerFor(conn)) |peer| _ = self.reportPeer(peer, .low_tolerance, now);
        }
    }
    self.control.identifyResults(&self.catalog, identify_results[0..counts.identify]);
    self.control.events(
        service,
        &self.catalog,
        engine,
        &self.local,
        now,
        slot,
        controls[0..counts.control],
    );
    self.control.maintain(service, &self.catalog, engine, &self.local, now);
    if (self.quiescing) return .{ .peers = self.catalog.pollEvents(peer_events), .application = counts.application, .gossipsub = counts.gossipsub };
    var connected_budget: u16 = custody.hashes_per_turn / 2;
    var candidate_budget: u16 = custody.hashes_per_turn / 2;
    const connected_pending = self.catalog.advanceCustody(&self.local.fork, now.mono_ms, self.metadata_freshness_ms, &connected_budget);
    const candidate_pending = self.dial_queue.advanceCustody(&self.local.fork, now.mono_ms, &candidate_budget);
    self.custody_pending = connected_pending or candidate_pending;
    self.counters.custody_hashes +|= custody.hashes_per_turn - connected_budget - candidate_budget;
    self.reconcile(service, now);
    self.updateNativeRoom(engine);
    return .{
        .peers = self.catalog.pollEvents(peer_events),
        .application = counts.application,
        .gossipsub = counts.gossipsub,
    };
}

pub fn nextWakeup(
    self: *PeerManager,
    service: *service_mod.Service,
    now: Now,
    peer_capacity: usize,
    application_capacity: usize,
    gossip_capacity: usize,
    dial_capacity: usize,
) ?u64 {
    if (self.stopped) return self.peerWakeup(now, peer_capacity);
    if (self.quiescing) {
        var due = service.nextWakeup(now, .{ .application = 0, .control = controls_per_turn, .gossipsub = 0, .identify = identify_per_turn });
        for ([_]?u64{ self.control.nextWakeup(&self.catalog, now), self.peerWakeup(now, peer_capacity) }) |next| if (next) |deadline| {
            due = @min(due orelse deadline, deadline);
        };
        return due;
    }
    var due = service.nextWakeup(now, .{ .application = application_capacity, .control = controls_per_turn, .gossipsub = gossip_capacity, .identify = identify_per_turn });
    for ([_]?u64{
        self.control.nextWakeup(&self.catalog, now),
        self.dial_queue.nextWakeup(now.mono_ms, @min(dial_capacity, self.dialRoom())),
        if (self.policyChanged(service) or self.dial_queue.selection_dirty) now.mono_ms else null,
        self.reconciliation_deadline,
        self.dial_queue.selection_deadline,
        if (self.custody_pending) now.mono_ms +| 1 else null,
        self.peerWakeup(now, peer_capacity),
    }) |next| {
        if (next) |value| due = @min(due orelse value, value);
    }
    return due;
}

pub fn sendReqRespRequest(
    self: *PeerManager,
    service: *service_mod.Service,
    engine: *engine_mod.Engine,
    conn: t.Handle,
    protocol: rr.Protocol,
    bytes: []const u8,
    sink: []u8,
    options: rr.reqresp.RequestOptions,
    now: Now,
) !rr.RequestHandle {
    if (self.stopped or self.quiescing) return error.Stopped;
    if (protocol.isControl()) return error.ControlProtocol;
    return service.request(engine, conn, protocol, bytes, sink, options, now);
}

pub fn configureTopic(self: *PeerManager, service: *service_mod.Service, topic: []const u8, params: *const gossip.score.TopicParams) (gossip.Gossipsub.ConfigureTopicError || error{Stopped})!void {
    if (self.stopped or self.quiescing) return error.Stopped;
    try service.gossipsub.configureTopic(topic, params);
}

pub fn publishGossip(
    self: *PeerManager,
    service: *service_mod.Service,
    topic: []const u8,
    bytes: []const u8,
    now: Now,
) !gossip.Gossipsub.PublishOutcome {
    if (self.stopped or self.quiescing) return error.Stopped;
    return publishGossipWithOptions(self, service, topic, bytes, .{}, now);
}

pub fn publishGossipWithOptions(self: *PeerManager, service: *service_mod.Service, topic: []const u8, bytes: []const u8, options: gossip.Gossipsub.PublishOptions, now: Now) !gossip.Gossipsub.PublishOutcome {
    if (self.stopped or self.quiescing) return error.Stopped;
    return service.gossipsub.publishWithOptions(topic, bytes, options, now);
}

pub fn subscribe(self: *PeerManager, service: *service_mod.Service, topic: []const u8) bool {
    if (self.stopped or self.quiescing) return false;
    return service.gossipsub.subscribe(topic);
}

pub fn unsubscribe(_: *PeerManager, service: *service_mod.Service, topic: []const u8) bool {
    return service.gossipsub.unsubscribe(topic);
}

pub fn beginGracefulClose(self: *PeerManager, service: *service_mod.Service, now: Now) void {
    if (self.stopped or self.quiescing) return;
    self.quiescing = true;
    self.selection = .{};
    self.discovery_need = .{};
    service.quiesceApplications();
    var active = service.router.active_capabilities;
    active.receive = .initEmpty();
    service.router.setCapabilities(active);
    for (self.catalog.rows, 0..) |row, index| {
        if (!row.occupied or row.connection == null) continue;
        _ = self.disconnect(.{ .index = @intCast(index), .generation = row.generation }, .shutdown, now);
    }
}

pub fn shutdown(self: *PeerManager, service: *service_mod.Service, engine: *engine_mod.Engine, now: Now) void {
    if (self.stopped) return;
    self.stopped = true;
    self.selection = .{};
    self.discovery_need = .{};
    service.shutdown(engine);
    const count = self.catalog.snapshots(self.snapshot_scratch);
    for (self.snapshot_scratch[0..count]) |snapshot| if (snapshot.connection) |conn| {
        self.control.close(
            service,
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
