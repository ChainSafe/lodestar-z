const std = @import("std");
const service_mod = @import("service.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const control_mod = @import("peers/control.zig");
const dial_mod = @import("peers/dialing.zig");
const custody = peers.custody;
const engine_mod = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
const wake_sources = @import("wake_sources.zig");
pub const controls_per_turn = 32;
pub const identify_per_turn = 8;
pub const dials_per_turn = 4;
pub const candidates_per_turn = @import("discv5").types.findnode_result_max + 1;

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
    result.reqresp.request_fork = local.fork.fork;
    return result;
}

pub fn validateOptions(options: Options) !void {
    try PeerManager.validateOptions(peerOptions(options));
    try service_mod.Service.validateOptions(options.service);
}

pub const DialIntent = manager.DialIntent;
pub const DiscoveryNeed = manager.DiscoveryNeed;
pub const Counts = struct { peers: usize, application: usize };

/// Public protocol borrows retain their Service lifetime until the next process call.
/// Internal closes after publication perform cleanup without a second owner recycling pass.
pub fn process(
    self: *PeerManager,
    service: *service_mod.Service,
    engine: *engine_mod.Engine,
    events: []const engine_mod.Event,
    now: Now,
    slot: u64,
    peer_events: []t.Event,
    application: []rr.Event,
) Counts {
    std.debug.assert(events.len <= @import("quic/limits.zig").events_per_turn_max);
    if (self.stopped) return .{
        .peers = self.catalog.pollEvents(peer_events),
        .application = 0,
    };
    if (!self.quiescing) self.dialing.expire(&self.catalog, engine, now.mono_ms);
    for (events) |event| self.transportEvent(service, engine, event, now);
    var controls: [controls_per_turn]rr.Event = undefined;
    var identify_results: [identify_per_turn]@import("identify/root.zig").Result = undefined;
    const counts = service.process(engine, events, now, .{ .application = application, .control = &controls, .identify = &identify_results });
    for ([_][]const rr.Event{ application[0..counts.application], controls[0..counts.control] }) |batch| {
        for (batch) |event| {
            const fault = service.reqresp.peerFault(event) orelse continue;
            const peer = self.catalog.find(fault.identity) orelse continue;
            switch (fault.kind) {
                .protocol => _ = self.reportPeer(peer, .low_tolerance, now),
                .non_completion => {
                    _ = self.catalog.nonCompletion(peer, now.mono_ms);
                    self.selection_revision = null;
                },
            }
        }
    }
    self.control.identifyResults(&self.catalog, identify_results[0..counts.identify]);
    for (identify_results[0..counts.identify]) |*result| switch (result.outcome) {
        .success => |*metadata| service.gossipsub.identified(result.conn, @import("peers/client.zig").kind(if (metadata.agent) |*agent| agent.slice() else "")),
        .failed => {},
    };
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
    if (self.quiescing) return .{ .peers = self.catalog.pollEvents(peer_events), .application = counts.application };
    var budget: u16 = custody.hashes_per_turn;
    self.custody_pending = self.catalog.advanceCustody(&self.local.fork, now.mono_ms, self.metadata_freshness_ms, &budget);
    self.counters.custody_hashes +|= custody.hashes_per_turn - budget;
    self.reconcile(service, now);
    self.updateNativeRoom(engine);
    return .{
        .peers = self.catalog.pollEvents(peer_events),
        .application = counts.application,
    };
}

pub fn collectWakeups(
    self: *PeerManager,
    service: *service_mod.Service,
    now: Now,
    peer_capacity: usize,
    application_capacity: usize,
    dial_capacity: usize,
    wakeups: *wake_sources.Wakeups,
) void {
    wakeups.note(.peer_events, self.peerWakeup(now, peer_capacity));
    if (self.stopped) return;
    if (self.quiescing) {
        service.collectWakeups(now, .{ .application = 0, .control = controls_per_turn, .identify = identify_per_turn }, wakeups);
        wakeups.note(.control, self.control.nextWakeup(&self.catalog, now));
        return;
    }
    service.collectWakeups(now, .{ .application = application_capacity, .control = controls_per_turn, .identify = identify_per_turn }, wakeups);
    wakeups.note(.control, self.control.nextWakeup(&self.catalog, now));
    wakeups.note(.dial, self.dialing.nextWakeup(&self.catalog, now.mono_ms, @min(dial_capacity, self.dialRoom())));
    wakeups.note(.dial, if (self.dialing.selectionNeeded(&self.catalog)) now.mono_ms else null);
    wakeups.note(.dial, self.dialing.selection_deadline);
    wakeups.note(.peer_policy, self.policyWakeup(service, now));
    wakeups.note(.peer_policy, self.reconciliation_deadline);
    wakeups.note(.peer_policy, if (self.custody_pending) now.mono_ms +| 1 else null);
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

pub fn publishGossipWithOptions(self: *PeerManager, service: *service_mod.Service, topic: []const u8, bytes: []const u8, options: gossip.Gossipsub.PublishOptions, now: Now) !gossip.Gossipsub.PublishOutcome {
    if (self.stopped or self.quiescing) return error.Stopped;
    return service.gossipsub.publishWithOptions(topic, bytes, options, now);
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
    self.dialing.shutdown(&self.catalog, engine);
}

test {
    _ = @import("managed_coverage_test.zig");
    _ = @import("managed_control_test.zig");
    _ = @import("managed_test.zig");
}
