const std = @import("std");
const n = @import("network");
const d = @import("discv5");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const allocator = r.allocator;
const Config = @import("network_config.zig").Config;
const application_config = @import("network_application_config.zig");
const commands = @import("network_commands.zig");
const gossip_mod = @import("network_gossip.zig");
const incoming_mod = @import("network_incoming.zig");
const requests_mod = @import("network_requests.zig");
const publications = @import("network_publications.zig");
const bridge = r.bridge;

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
    /// The bridge measurements of the latest render.
    bridge: bridge.Snapshot = .{},

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
    try io.randomSecure(std.mem.asBytes(&seed));
    self.reports.seed = seed;
    const request = try self.heavy.?.application.buildRequest(&self.heavy.?.config, seed);
    self.heavy.?.resolved = n.configuration.resolve(request) catch |err| switch (err) {
        error.InvalidLimits => return error.InvalidNetworkConfig,
        else => return err,
    };
}

pub fn initialize(self: *Runtime) !void {
    std.debug.assert(self.thread == null);
    const previous_log = n.logging.bind(&self.logs);
    defer _ = n.logging.bind(previous_log);
    std.log.scoped(.network_runtime).info("owner_initializing", .{});
    const io = self.heavy.?.threaded.io();
    self.heavy.?.key = try n.KeyPair.fromSecretKey(&self.heavy.?.config.secret);

    self.heavy.?.config.wipe();
    for (0..self.heavy.?.config.bootstrap_count) |i| {
        self.heavy.?.records[i] = try d.identity.enr.Record.init(self.heavy.?.config.bootstrap[i].bytes[0..self.heavy.?.config.bootstrap[i].len]);
    }
    try self.heavy.?.core.init(allocator, io, &self.heavy.?.resolved, .{
        .host = &self.heavy.?.key,
        .bind = self.heavy.?.config.bind,
        .local = self.heavy.?.config.local,
        .schedule = self.heavy.?.config.schedule,
        .slot = self.heavy.?.config.slot,
        .slot_clock = self.heavy.?.config.slot_clock,
        .remembered = self.heavy.?.application.remembered[0..self.heavy.?.application.remembered_count],
        .discovery = if (self.heavy.?.config.discovery_bind) |bind| .{ .bind = bind, .sequence = self.heavy.?.config.discovery_sequence, .advertisement = self.heavy.?.config.advertisement, .fixed = self.heavy.?.config.fixed, .bootstrap = self.heavy.?.records[0..self.heavy.?.config.bootstrap_count] } else null,
    });
    self.heavy.?.core_live = true;
    try self.heavy.?.core.setHostWake(self.wake.?.read_fd);

    self.diag.nativeRequestedBytes = @sizeOf(n.NetworkCore) + self.heavy.?.core.reservations.bytes;
    self.diag.nativeAllocationCount = self.heavy.?.core.reservations.allocation_calls;
    const plan = self.heavy.?.core.transport.engine.memoryPlan();
    self.diag.quicReceiveWindowBytes = plan.receive_window_bytes;
    self.diag.quicConnectionWindowBytes = plan.connection_window_bytes;
    self.diag.quicStreamWindowBytes = plan.stream_window_bytes;
    try publishMetrics(self, now(io));
    std.log.scoped(.network_runtime).info("owner_initialized target_peers={d} max_peers={d}", .{ self.diag.resolvedCapacities.targetPeers, self.diag.resolvedCapacities.maxPeers });
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
    var ingress: gossip_mod.Ingress = .{ .runtime = self, .io = io };
    const sink = ingress.sink();
    self.heavy.?.core.service.gossipsub.message_sink = &sink;
    defer self.heavy.?.core.service.gossipsub.message_sink = null;
    var host: Host = .{ .runtime = self, .io = io };
    while (try turn(self, io, &host, &ingress)) |_| {}
}

/// One owner turn: the stop check, then one core step that applies host work after its readiness
/// poll, then the turn's application events, connect completions and publication. Returns null
/// once the owner stops.
fn turn(self: *Runtime, io: std.Io, host: *Host, ingress: *const gossip_mod.Ingress) !?n.network_core.Result {
    const previous = r.phase(.turn);
    defer r.restore(previous);
    self.lock();
    const stop = self.stop;
    const graceful = self.graceful and self.reason == .requested;
    self.unlock();
    if (stop and !graceful) return null;
    const timestamp = now(io);
    if (stop) {
        if (self.closing_deadline == null) {
            std.log.scoped(.network_runtime).info("owner_stopping mode=graceful peers={d}", .{self.heavy.?.core.peerCounts().connected});
            self.lock();
            self.cancelCommandsLocked();
            self.publications.?.close(self.terminal_error orelse error.NetworkClosed);
            self.refreshLocked();
            self.unlock();
            self.closing_deadline = timestamp.mono_ms +| 2000;
            self.heavy.?.core.beginGracefulClose(timestamp);
        }
        if (timestamp.mono_ms >= self.closing_deadline.? or self.heavy.?.core.peerCounts().connected == 0) return null;
    }
    self.lock();
    const peer_room: usize = if (self.lane) |lane| 64 - @as(usize, lane.len) else self.heavy.?.outputs.len;
    const deadline = hostDeadline(self, timestamp);
    self.unlock();
    const sequence = try self.advanceSequence();
    const result = self.heavy.?.core.step(io, timestamp, .{ .peers = self.heavy.?.outputs[0..@min(peer_room, self.heavy.?.outputs.len)], .application = &self.heavy.?.application_outputs }, .{ .context = host, .apply = Host.apply, .deadline_ms = deadline });
    if (host.failure) |err| return err;
    if (ingress.failure) |err| return err;
    // The step's clock was read after its poll, so deadlines that ended the wait are due.
    const tick = result.transport.now;
    try within(.capture, requests_mod.capture, .{ self, self.heavy.?.application_outputs[0..result.counts.application], tick });
    within(.commands, commands.completeConnects, .{ self, tick });
    within(.peer_lane, publishTurn, .{ self, &result, tick, sequence });
    return result;
}

/// Runs one owner step with its runtime mutex holds attributed to `value`.
fn within(value: bridge.Phase, comptime function: anytype, args: anytype) @TypeOf(@call(.auto, function, args)) {
    const previous = r.phase(value);
    defer r.restore(previous);
    return @call(.auto, function, args);
}

/// The earliest host-owned deadline, read under the lock: metrics rendering, the health log,
/// connect timeouts, the graceful close and the gossip processor's groups and expiry. Host work
/// found by the previous turn's event capture is due now.
fn hostDeadline(self: *Runtime, timestamp: n.Now) u64 {
    if (self.host_due) return timestamp.mono_ms;
    var deadline = @min(self.metrics_due_ms, self.health_log_due_ms);
    if (commands.connectDeadline(&self.table)) |value| deadline = @min(deadline, value);
    if (self.closing_deadline) |value| deadline = @min(deadline, value);
    if (self.gossip) |*table| if (table.deadline()) |value| {
        deadline = @min(deadline, value);
    };
    return deadline;
}

/// The core's host seam for this owner.
const Host = struct {
    runtime: *Runtime,
    io: std.Io,
    failure: ?anyerror = null,

    fn apply(context: *anyopaque, core: *n.NetworkCore, tick: n.Now) n.network_core.HostProgress {
        const self: *Host = @ptrCast(@alignCast(context));
        std.debug.assert(core == &self.runtime.heavy.?.core);
        if (self.failure != null) return .{};
        return applyWork(self.runtime, self.io, tick) catch |err| {
            self.failure = err;
            return .{};
        };
    }
};

/// Drains the wake pipe before reading any queue, so a submission that lands after the drain
/// wakes the next poll. Then applies reports, commands, publications and requests in admission
/// order, gossip verdicts and processor maintenance, and request and response flags.
fn applyWork(self: *Runtime, io: std.Io, tick: n.Now) !n.network_core.HostProgress {
    self.lock();
    self.wake.?.drain() catch {
        self.stop = true;
        self.reason = .failed;
        self.terminal_error = error.NetworkWakeFailed;
    };
    self.host_due = false;
    const stop = self.stop;
    const stopped = self.stop and !(self.graceful and self.reason == .requested);
    self.unlock();
    if (stopped) return .{};
    var more = false;
    if (!stop) {
        more = within(.reports, applyReports, .{ self, tick }) or more;
        more = try executeWork(self, io) or more;
    }
    more = try within(.gossip_flags, gossip_mod.flags, .{ self, io }) or more;
    within(.request_flags, requests_mod.flags, .{ self, io });
    more = try within(.incoming_flags, incoming_mod.flags, .{ self, tick }) or more;
    return .{ .more = more };
}

/// Applies up to 32 queued peer reports. Returns whether more remain.
fn applyReports(self: *Runtime, tick: n.Now) bool {
    for (0..32) |_| {
        self.lock();
        const report = self.reports.next();
        self.unlock();
        const item = report orelse return false;
        if (self.heavy.?.core.reportPeer(&item.identity, item.action, tick) == null) {
            self.lock();
            self.reports.ignored +|= 1;
            self.unlock();
        }
    }
    self.lock();
    defer self.unlock();
    return self.reports.pending != 0;
}

/// Executes queued commands, publications and requests in admission order under their per-turn
/// caps. Returns whether a cap stopped it with work left.
fn executeWork(self: *Runtime, io: std.Io) !bool {
    var controls: usize = 0;
    var requests: usize = 0;
    var publishes: usize = 0;
    var bytes: usize = 0;
    for (0..commands.turn_max + publications.turn_max + requests_mod.turn_max) |_| {
        self.lock();
        if (self.stop) {
            self.unlock();
            return false;
        }
        const command = self.table.nextQueued();
        const publication = self.publications.?.oldest();
        const request = self.requests.?.oldest();
        const control_order = if (command) |token| self.table.get(token).order else std.math.maxInt(u64);
        const publish_order = if (publication) |token| self.publications.?.get(token).?.order else std.math.maxInt(u64);
        const request_order = if (request) |token| self.requests.?.get(token).?.order else std.math.maxInt(u64);
        const order = @min(control_order, publish_order, request_order);
        if (order == std.math.maxInt(u64)) {
            self.unlock();
            return false;
        }
        if (order == control_order) {
            if (controls == commands.turn_max) {
                self.unlock();
                return true;
            }
            const cell = self.table.get(command.?);
            cell.sequence = self.table.advance() catch |err| {
                self.unlock();
                return err;
            };
            self.table.transition(cell, .executing);
            self.unlock();
            within(.commands, commands.execute, .{ self, command.?, now(io) });
            controls += 1;
        } else if (order == publish_order) {
            const len = self.publications.?.get(publication.?).?.payload.len;
            if (publishes == publications.turn_max or (publishes != 0 and len > publications.turn_bytes -| bytes)) {
                self.unlock();
                return true;
            }
            _ = self.table.advance() catch |err| {
                self.unlock();
                return err;
            };
            self.unlock();
            within(.publications, publications.execute, .{ self, publication.?, now(io) });
            publishes += 1;
            bytes += len;
        } else {
            if (requests == requests_mod.turn_max) {
                self.unlock();
                return true;
            }
            _ = self.table.advance() catch |err| {
                self.unlock();
                return err;
            };
            self.unlock();
            try within(.requests, requests_mod.submit, .{ self, request.?, now(io) });
            requests += 1;
        }
    }
    return true;
}
fn publishTurn(self: *Runtime, result: *const n.network_core.Result, timestamp: n.Now, sequence: u64) void {
    const counts = self.heavy.?.core.peerCounts();
    if (timestamp.mono_ms >= self.metrics_due_ms) {
        within(.metrics, publishMetrics, .{ self, now(self.heavy.?.threaded.io()) }) catch |err| {
            self.lock();
            self.metrics.failure = err;
            self.unlock();
        };
        self.metrics_due_ms = timestamp.mono_ms +| n.metrics.interval_ms;
    }
    self.lock();
    if (timestamp.mono_ms >= self.health_log_due_ms) {
        const active_requests = self.heavy.?.core.service.reqresp.active();
        std.log.scoped(.network_runtime).info("network_health peers={d} relevant={d} target={d} requests_outbound={d} requests_inbound={d} dial_started={d} dial_deferred={d} discovery_peers={d} gossip_pressure_resets={d} received_bytes={d} sent_bytes={d}", .{ counts.connected, counts.relevant, self.heavy.?.resolved.core.peers.target_peers, active_requests.outbound, active_requests.inbound, self.heavy.?.core.counters.dial_started, self.heavy.?.core.counters.dial_deferred, if (self.heavy.?.core.discovery) |discovery| discovery.transport.engine.peerCount() else 0, self.heavy.?.core.service.gossipsub.counters.local_pressure_resets, self.heavy.?.core.transport.udp.counters.received_bytes, self.heavy.?.core.transport.udp.counters.sent_bytes });
        self.health_log_due_ms = timestamp.mono_ms +| 30000;
    }
    if (self.lane) |lane| lane.publish(self.heavy.?.outputs[0..result.counts.peers], sequence);
    self.recomputeLocked(.peers);
    if (result.failure) |err| {
        std.log.scoped(.network_runtime).debug("owner_turn_failed reason={s} fatal={any}", .{ @errorName(err), result.readiness.failure != null });
        self.diag.operationalFailures +|= 1;
        if (result.readiness.failure != null) {
            self.stop = true;
            self.reason = .failed;
            self.terminal_error = err;
        }
    }
    self.diag.ownerTurns +|= 1;
    self.unlock();
}
pub fn now(io: std.Io) n.Now {
    const mono = std.Io.Timestamp.now(io, .awake);
    return .{ .mono_ms = @intCast(@max(0, mono.toMilliseconds())), .unix_s = std.Io.Timestamp.now(io, .real).toSeconds() };
}

fn publishMetrics(self: *Runtime, timestamp: n.Now) n.metrics.registry.Error!void {
    var context = n.metrics.Context.init(&self.heavy.?.core, timestamp, true);
    self.lock();
    if (self.gossip) |*table| {
        const state = table.snapshot(timestamp.mono_ms);
        context.expired_executing = state.expiredExecuting;
        context.oldest_expired_execution_age_ms = state.oldestExpiredExecutionAgeMs;
    }
    self.captureBridgeLocked(&self.heavy.?.bridge);
    self.unlock();
    context.bridge = &self.heavy.?.bridge;
    const index = try self.metrics.render(&context);
    self.lock();
    self.metrics.published = index;
    self.metrics.failure = null;
    self.unlock();
}

test "a command queued while the owner waits executes in the turn whose poll saw the wake" {
    if (!n.network_core.wait.supported) return error.SkipZigTest;
    const testing = std.testing.allocator;
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    const owner = try testing.create(Owner);
    defer testing.destroy(owner);
    owner.* = .{};
    owner.threaded = std.Io.Threaded.init(testing, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
    defer owner.threaded.deinit();
    const io = owner.threaded.io();
    runtime.heavy = owner;
    const key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{71}));
    const resolved = try n.configuration.resolve(.{
        .profile = .small,
        .seed = 1,
        .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }},
        .admission_policy = .{ .deneb_start_slot = 0, .blocks_pre_deneb = 1024, .blocks_deneb = 128, .blob_identifiers_deneb = 768, .blob_identifiers_electra = 1152, .number_of_columns = 128, .column_chunks = 16384, .blob_schedule = &.{.{ .start_slot = 0, .max_blobs = 6 }} },
    });
    try owner.core.init(testing, io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = .{ .metadata = .{ .custody_group_count = 1 }, .status = .{ .earliest_available_slot = 0 } },
    });
    defer owner.core.deinit(io);
    runtime.wake = try @import("network_wake.zig").Wake.init();
    defer runtime.wake.?.deinit();
    try owner.core.setHostWake(runtime.wake.?.read_fd);
    runtime.payload_budget.limit = 1 << 20;
    runtime.publications = try publications.Table.init(testing, 1, &runtime.payload_budget);
    defer runtime.publications.?.deinit();
    runtime.requests = try requests_mod.Table.init(testing, 1, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    var host: Host = .{ .runtime = &runtime, .io = io };
    const ingress: gossip_mod.Ingress = .{ .runtime = &runtime, .io = io };
    // The first turns render metrics and write the health log, then only deadlines remain.
    for (0..4) |_| _ = (try turn(&runtime, io, &host, &ingress)).?;

    const Submitter = struct {
        token: ?commands.Token = null,
        written_ns: u64 = 0,
        failure: ?anyerror = null,
        fn run(self: *@This(), target: *Runtime, clock: std.Io) void {
            clock.sleep(.fromMilliseconds(30), .awake) catch unreachable;
            self.written_ns = @intCast(std.Io.Clock.awake.now(clock).nanoseconds);
            const token = target.reserveCommand(.getIdentity) catch |err| {
                self.failure = err;
                return;
            };
            self.token = token;
            target.queueCommand(token) catch |err| {
                self.failure = err;
            };
        }
    };
    var submitter: Submitter = .{};
    const thread = try std.Thread.spawn(.{}, Submitter.run, .{ &submitter, &runtime, io });
    var woke = false;
    var returned_ns: u64 = 0;
    var turns: usize = 0;
    var executed_before_wake = false;
    for (0..64) |_| {
        const result = (try turn(&runtime, io, &host, &ingress)).?;
        returned_ns = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
        turns += 1;
        runtime.lock();
        var terminal = false;
        for (&runtime.table.cells) |*cell| terminal = terminal or cell.state == .terminal;
        runtime.unlock();
        if (result.readiness.host) {
            try std.testing.expect(terminal);
            woke = true;
            break;
        }
        executed_before_wake = executed_before_wake or terminal;
    }
    thread.join();
    try std.testing.expect(submitter.failure == null);
    try std.testing.expect(woke and !executed_before_wake);
    const latency_ns = returned_ns - submitter.written_ns;
    std.debug.print("owner command wake_to_execution_us={d} turns={d}\n", .{ latency_ns / std.time.ns_per_us, turns });
    try std.testing.expect(latency_ns < 100 * std.time.ns_per_ms);
    try std.testing.expect(runtime.table.get(submitter.token.?).failure == null);
    runtime.abortCommand(submitter.token.?);
    runtime.heavy = null;
}
