const std = @import("std");
const n = @import("network");
const d = @import("discv5");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const allocator = r.allocator;
const Config = @import("network_config.zig").Config;
const application_config = @import("network_application_config.zig");
const faults = @import("network_faults.zig");
const commands = @import("network_commands.zig");
const gossip_mod = @import("network_gossip.zig");
const incoming_mod = @import("network_incoming.zig");
const requests_mod = @import("network_requests.zig");

pub const Owner = struct {
    threaded_live: bool = false,
    core_live: bool = false,
    config: Config = undefined,
    resolved: n.configuration.Resolved = undefined,
    core: n.NetworkCore = undefined,
    threaded: std.Io.Threaded = undefined,
    key: n.KeyPair = undefined,
    records: [d.types.bootstrap_max]d.identity.enr.Record = undefined,
    outputs: [32]n.peers.Event = undefined,
    application_outputs: [32]n.reqresp.Event = undefined,
    application: application_config.Config = undefined,

    pub fn readIdentity(self: *const Owner) !r.Identity {
        var identity: r.Identity = undefined;
        identity.peer = self.core.peerId();
        identity.metadata = self.core.localState().metadata;
        identity.endpoints = self.core.transport.udp.localAddresses();
        const multiaddr = self.core.localMultiaddr();
        identity.multiaddr_len = @intCast((try multiaddr.encode(&identity.multiaddr)).len);
        identity.enr_len = 0;
        if (self.core.localRecord()) |record| {
            identity.enr_len = @intCast(record.slice().len);
            @memcpy(identity.enr[0..identity.enr_len], record.slice());
        }
        return identity;
    }
};

pub fn prepareConfiguration(self: *Runtime) !void {
    self.heavy.?.threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
    self.heavy.?.threaded_live = true;
    const io = self.heavy.?.threaded.io();
    var seed: u64 = undefined;
    try faults.check(.entropy);
    try io.randomSecure(std.mem.asBytes(&seed));
    const request = try self.heavy.?.application.buildRequest(&self.heavy.?.config, seed);
    self.heavy.?.resolved = n.configuration.resolve(request) catch |err| switch (err) {
        error.InvalidLimits => return error.InvalidNetworkConfig,
        else => return err,
    };
}

pub fn initialize(self: *Runtime) !void {
    std.debug.assert(self.thread == null and self.startup == .pending);
    const previous_log = n.logging.bind(&self.logs);
    defer _ = n.logging.bind(previous_log);
    std.log.scoped(.network_runtime).info("owner_initializing", .{});
    const io = self.heavy.?.threaded.io();
    try faults.check(.key);
    self.heavy.?.key = try n.KeyPair.fromSecretKey(&self.heavy.?.config.secret);

    self.heavy.?.config.wipe();
    for (0..self.heavy.?.config.bootstrap_count) |i| {
        try faults.check(.enr);
        self.heavy.?.records[i] = try d.identity.enr.Record.init(self.heavy.?.config.bootstrap[i].bytes[0..self.heavy.?.config.bootstrap[i].len]);
    }
    try faults.check(.core);
    try self.heavy.?.core.init(allocator, io, &self.heavy.?.resolved, .{
        .wait_mode = .native_poll,
        .host = &self.heavy.?.key,
        .bind = self.heavy.?.config.bind,
        .local = self.heavy.?.config.local,
        .schedule = self.heavy.?.config.schedule,
        .discovery = if (self.heavy.?.config.discovery_bind) |bind| .{ .bind = bind, .sequence = self.heavy.?.config.discovery_sequence, .advertisement = self.heavy.?.config.advertisement, .bootstrap = self.heavy.?.records[0..self.heavy.?.config.bootstrap_count] } else null,
    });
    self.heavy.?.core_live = true;
    try faults.check(.wake_attach);
    try self.heavy.?.core.setHostWake(self.wake.?.read_fd);

    const plan = self.heavy.?.core.memoryPlan();
    self.diag.nativeRequestedBytes = plan.inline_bytes + plan.allocated_bytes;
    self.diag.nativeAllocationCount = self.heavy.?.core.reservations.allocation_calls;
    self.diag.quicReceiveWindowBytes = plan.transport.engine.receive_window_bytes;
    self.diag.quicConnectionWindowBytes = plan.transport.engine.connection_window_bytes;
    self.diag.quicStreamWindowBytes = plan.transport.engine.stream_window_bytes;
}
pub fn run(self: *Runtime) void {
    defer self.release();
    const previous_log = n.logging.bind(&self.logs);
    defer _ = n.logging.bind(previous_log);
    const failure: ?anyerror = blk: {
        serve(self) catch |err| break :blk err;
        break :blk null;
    };
    self.finishOwner(failure);
}

fn serve(self: *Runtime) !void {
    std.debug.assert(self.heavy.?.core_live);
    const io = self.heavy.?.threaded.io();
    try publishReady(self);
    var ingress: gossip_mod.Ingress = .{ .runtime = self, .io = io };
    const sink = ingress.sink();
    self.heavy.?.core.service.gossipsub.message_sink = &sink;
    defer self.heavy.?.core.service.gossipsub.message_sink = null;
    while (true) {
        self.lock();
        const stop = self.stop;
        const graceful = self.graceful and self.active and self.reason == .requested;
        self.unlock();
        if (stop and !graceful) break;
        const timestamp = now(io);
        if (stop) {
            if (self.closing_deadline == null) {
                std.log.scoped(.network_runtime).info("owner_stopping mode=graceful peers={d}", .{self.heavy.?.core.peerCounts().connected});
                self.lock();
                self.cancelCommandsLocked();
                self.pingLocked();
                self.unlock();
                self.closing_deadline = timestamp.mono_ms +| 2000;
                self.heavy.?.core.beginGracefulClose(timestamp);
            }
            if (timestamp.mono_ms >= self.closing_deadline.? or self.heavy.?.core.peerCounts().connected == 0) break;
        } else {
            for (0..32) |_| {
                self.lock();
                const report = self.reports.next();
                self.unlock();
                const item = report orelse break;
                _ = self.heavy.?.core.reportPeer(item.peer, item.action, timestamp);
            }
            try commands.executeCommands(self, timestamp);
        }
        self.lock();
        self.wake.?.drain() catch {
            self.stop = true;
            self.reason = .failed;
            self.startup_error = error.NetworkWakeFailed;
        };
        if (self.readable_rearm) {
            self.readable_rearm = false;
            if (!self.stop and ((self.lane != null and self.lane.?.len > 0) or (self.incoming != null and self.incoming.?.oldest() != null) or (self.gossip != null and self.gossip.?.hasWork()))) self.pingLocked();
        }
        const slot = self.slot;
        self.diag.currentSlot = slot;
        const stopped = self.stop and !(self.graceful and self.active and self.reason == .requested);
        const active = self.active;
        const peer_room: usize = if (self.lane) |lane| 64 - @as(usize, lane.len) else self.heavy.?.outputs.len;
        self.unlock();
        if (stopped) break;
        if (!active) {
            var fd = std.c.pollfd{ .fd = self.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 };
            const rc = std.c.poll(@ptrCast(&fd), 1, @intCast(commands.waitLimit(self, timestamp)));
            if (rc < 0 and std.c.errno(rc) != .INTR) return error.NetworkWakeFailed;
            continue;
        }
        try gossip_mod.flags(self, io);
        requests_mod.flags(self);
        _ = try @import("network_incoming_phase_faults.zig").terminalBarrier(self, false);
        try incoming_mod.flags(self, timestamp);
        const terminal_accepted = try @import("network_incoming_phase_faults.zig").terminalBarrier(self, true);
        const sequence = try self.advanceSequence();
        const result = self.heavy.?.core.step(io, timestamp, slot, .{ .peers = self.heavy.?.outputs[0..@min(peer_room, self.heavy.?.outputs.len)], .application = &self.heavy.?.application_outputs }, commands.waitLimit(self, timestamp));
        if (ingress.failure) |err| return err;
        self.lock();
        self.reports.sync(&self.heavy.?.core.peer_manager.catalog);
        self.unlock();
        @import("network_gossip_faults.zig").afterStep(self);
        if (terminal_accepted) |proof| @import("network_incoming_phase_faults.zig").afterStep(self, &proof, self.heavy.?.application_outputs[0..result.counts.application]);
        try requests_mod.capture(self, self.heavy.?.application_outputs[0..result.counts.application], timestamp);
        commands.completeConnects(self, timestamp);

        publishTurn(self, &result, timestamp, sequence);
    }
}
fn publishReady(self: *Runtime) !void {
    if (comptime faults.enabled) {
        if (self.test_scenario == .gossip) faults.captureGossip(self.heavy.?.core.service.gossipsub, &self.heavy.?.core.peer_manager.local.fork);
    }
    const identity = try self.heavy.?.readIdentity();
    try startupBarrier(self, .before_ready);
    self.lock();
    if (self.stop) {
        self.unlock();
        return error.AbortError;
    }
    self.identity = identity;
    if (comptime faults.enabled) {
        if (self.test_scenario == .application_peer_lane) {
            if (self.lane) |lane| for (0..64) |i| {
                const event: n.peers.Event = .{ .closed = .{
                    .peer = .{ .index = @intCast(i), .generation = std.math.maxInt(u64) - i },
                    .connection = .{ .index = @intCast(i % 16), .generation = std.math.maxInt(u32) - @as(u32, @intCast(i)) },
                    .identity = identity.peer,
                    .reason = .host,
                } };
                lane.publish(&.{event}, 0);
            };
        }
    }
    self.startup = .ready;
    self.diag.state = .prepared;
    std.log.scoped(.network_runtime).info("owner_ready state={s} peer={f} target_peers={d} max_peers={d}", .{ @tagName(self.diag.state), n.logging.peer(&self.identity.peer), self.diag.resolvedCapacities.targetPeers, self.diag.resolvedCapacities.maxPeers });
    const plan = self.heavy.?.core.memoryPlan();
    self.diag.nativeRequestedBytes = plan.inline_bytes + plan.allocated_bytes;
    self.pingLocked();
    self.unlock();
}
fn publishTurn(self: *Runtime, result: *const n.network_core.Result, timestamp: n.Now, sequence: u64) void {
    const counts = self.heavy.?.core.peerCounts();
    var metrics: ?n.metrics.Snapshot = null;
    if (timestamp.mono_ms >= self.metrics_due_ms) {
        metrics = .{};
        metrics.?.collect(&self.heavy.?.core, timestamp.mono_ms);
        self.metrics_due_ms = timestamp.mono_ms +| n.metrics.interval_ms;
    }
    self.lock();
    if (metrics) |*value| {
        if (self.gossip) |*gossip| {
            const diagnostics = gossip.snapshot(timestamp.mono_ms);
            value.live.gossip_expired_executing = diagnostics.expiredExecuting;
            value.live.gossip_oldest_expired_execution_age_ms = diagnostics.oldestExpiredExecutionAgeMs;
        }
        self.metrics = value.*;
    }
    if (timestamp.mono_ms >= self.health_log_due_ms) {
        const active_requests = self.heavy.?.core.service.reqresp.active();
        std.log.scoped(.network_runtime).info("network_health peers={d} relevant={d} target={d} requests_outbound={d} requests_inbound={d} dial_started={d} dial_deferred={d} discovery_peers={d} gossip_pressure_resets={d} received_bytes={d} sent_bytes={d}", .{ counts.connected, counts.relevant, self.metrics.config.target, active_requests.outbound, active_requests.inbound, self.metrics.totals.runtime.dial_started, self.metrics.totals.runtime.dial_deferred, self.metrics.live.discovery_peers, self.metrics.totals.gossip_counts.local_pressure_resets, self.metrics.totals.udp.received_bytes, self.metrics.totals.udp.sent_bytes });
        self.health_log_due_ms = timestamp.mono_ms +| 30000;
    }
    if (self.lane) |lane| {
        const empty = lane.len == 0;
        lane.publish(self.heavy.?.outputs[0..result.counts.peers], sequence);
        if (empty and lane.len > 0) self.pingLocked();
    }
    if (result.failure) |err| {
        std.log.scoped(.network_runtime).debug("owner_turn_failed reason={s} fatal={any}", .{ @errorName(err), result.readiness.failure != null });
        self.diag.operationalFailures +|= 1;
        if (result.readiness.failure != null) {
            self.stop = true;
            self.reason = .failed;
            self.startup_error = err;
        }
    }
    self.diag.ownerTurns +|= 1;
    self.diag.lastMonotonicMs = timestamp.mono_ms;
    self.diag.peerCount = counts.connected;
    self.diag.readyPeerCount = counts.relevant;
    self.unlock();
}
fn startupBarrier(self: *Runtime, stage: faults.Scenario) !void {
    if (comptime !faults.enabled) return;
    if (self.test_scenario != stage) return;
    faults.reached.store(stage, .release);
    for (0..500) |_| {
        if (cancelled(self)) return error.AbortError;
        var fd = std.c.pollfd{ .fd = self.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 };
        const result = std.c.poll(@ptrCast(&fd), 1, 10);
        if (result < 0 and std.c.errno(result) != .INTR) return error.NetworkWakeFailed;
        if (result > 0) try self.wake.?.drain();
    }
    return error.NetworkTestBarrierTimeout;
}
fn cancelled(self: *Runtime) bool {
    self.lock();
    defer self.unlock();
    return self.stop;
}
pub fn now(io: std.Io) n.Now {
    const mono = std.Io.Timestamp.now(io, .awake);
    return .{ .mono_ms = @intCast(@max(0, mono.toMilliseconds())), .unix_s = std.Io.Timestamp.now(io, .real).toSeconds() };
}
