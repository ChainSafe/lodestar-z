const std = @import("std");
const Now = @import("network").Now;
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
const processor_metrics = n.metrics.processor;
const network_wake = @import("network_wake.zig");
const test_support = @import("network_test_support.zig");

pub const Owner = struct {
    threaded_live: bool = false,
    core_live: bool = false,
    config: Config = undefined,
    resolved: n.configuration.Resolved = undefined,
    core: n.NetworkCore = undefined,
    threaded: std.Io.Threaded = undefined,
    key: n.KeyPair = undefined,
    records: [n.peers.Discovery.bootstrap_max]d.identity.enr.Record = undefined,
    outputs: [32]n.peers.Event = undefined,
    application_outputs: [32]n.reqresp.ReqResp.Event = undefined,
    application: application_config.Config = undefined,
    processor_metrics: processor_metrics.Snapshot = .{},

    pub fn readIdentity(self: *const Owner) !r.Identity {
        var identity: r.Identity = undefined;
        identity.peer = self.core.peerId();
        identity.metadata = self.core.localState().metadata;
        identity.endpoints = self.core.transport.sockets.localAddresses();
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
    self.owner.?.threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
    self.owner.?.threaded_live = true;
    const io = self.owner.?.threaded.io();
    var seed: u64 = undefined;
    try io.randomSecure(std.mem.asBytes(&seed));
    self.bridge.reports.seed = seed;
    const options = try self.owner.?.application.buildOptions(&self.owner.?.config, seed);
    self.owner.?.resolved = n.configuration.resolve(options) catch |err| switch (err) {
        error.InvalidLimits => return error.InvalidNetworkConfig,
        else => return err,
    };
}

pub fn initialize(self: *Runtime) !void {
    std.debug.assert(self.thread == null);
    const previous_log = n.logging.bind(&self.logs);
    defer _ = n.logging.bind(previous_log);
    std.log.scoped(.network_runtime).info("owner_initializing", .{});
    const io = self.owner.?.threaded.io();
    self.owner.?.key = try n.KeyPair.fromSecretKey(&self.owner.?.config.secret);

    self.owner.?.config.wipe();
    for (0..self.owner.?.config.bootstrap_count) |i| {
        self.owner.?.records[i] = try d.identity.enr.Record.init(self.owner.?.config.bootstrap[i].bytes[0..self.owner.?.config.bootstrap[i].len]);
    }
    try self.owner.?.core.init(allocator, io, &self.owner.?.resolved, .{
        .host = &self.owner.?.key,
        .bind = self.owner.?.config.bind,
        .local = self.owner.?.config.local,
        .schedule = self.owner.?.config.schedule,
        .slot = self.owner.?.config.slot,
        .remembered = self.owner.?.application.remembered[0..self.owner.?.application.remembered_count],
        .discovery = if (self.owner.?.config.discovery_bind) |bind| .{ .bind = bind, .sequence = self.owner.?.config.discovery_sequence, .advertisement = self.owner.?.config.advertisement, .fixed = self.owner.?.config.fixed, .bootstrap = self.owner.?.records[0..self.owner.?.config.bootstrap_count] } else null,
    });
    self.owner.?.core_live = true;
    try self.owner.?.core.setHostWake(self.bridge.wake.?.read_fd);

    try publishMetrics(self, try Now.read(io));
    std.log.scoped(.network_runtime).info("owner_initialized target_peers={d} max_peers={d}", .{ self.owner.?.resolved.core.peers.target_peers, self.owner.?.resolved.core.peers.max_peers });
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
    std.debug.assert(self.owner.?.core_live);
    const io = self.owner.?.threaded.io();
    var ingress: gossip_mod.Ingress = .{ .runtime = self, .io = io };
    const sink = ingress.sink();
    self.owner.?.core.protocols.gossipsub.message_sink = &sink;
    defer self.owner.?.core.protocols.gossipsub.message_sink = null;
    var host: Host = .{ .runtime = self, .io = io };
    while (try turn(self, io, &host, &ingress)) |result| {
        if (result.cancelled) return error.Canceled;
    }
}

/// One owner turn: the stop check, then one core step that applies host work after its readiness
/// poll, then the turn's application events, connect completions and publication. Returns null
/// once the owner stops.
fn turn(self: *Runtime, io: std.Io, host: *Host, ingress: *const gossip_mod.Ingress) !?n.NetworkCore.Result {
    self.lock();
    const stop = self.bridge.stop;
    const graceful = self.bridge.graceful and self.bridge.reason == .requested;
    self.unlock();
    if (stop and !graceful) return null;
    const timestamp = try Now.read(io);
    if (stop) {
        if (self.closing_deadline == null) {
            std.log.scoped(.network_runtime).info("owner_stopping mode=graceful peers={d}", .{self.owner.?.core.peerCounts().connected});
            self.lock();
            self.cancelCommandsLocked();
            self.bridge.publications.?.close(self.bridge.terminal_error orelse error.NetworkClosed);
            self.notifyIfReadyLocked();
            self.unlock();
            self.closing_deadline = timestamp.millis() +| 2000;
            self.owner.?.core.beginGracefulClose(timestamp);
        }
        if (timestamp.millis() >= self.closing_deadline.? or self.owner.?.core.peerCounts().connected == 0) return null;
    }
    self.lock();
    const peer_room: usize = if (self.bridge.peer_updates) |lane| 64 - @as(usize, lane.len) else self.owner.?.outputs.len;
    const deadline = hostDeadline(self, timestamp);
    self.unlock();
    const sequence = try self.advanceSequence();
    const result = n.driver.step(&self.owner.?.core, io, timestamp, .{ .peers = self.owner.?.outputs[0..@min(peer_room, self.owner.?.outputs.len)], .application = &self.owner.?.application_outputs }, .{ .handler = .{ .context = host, .apply = Host.apply }, .deadline = n.time.optionalMilliseconds(deadline) });
    if (host.failure) |err| return err;
    if (ingress.failure) |err| return err;
    // The step's clock was read after its poll, so deadlines that ended the wait are due.
    const tick = result.transport.now;
    try requests_mod.capture(self, self.owner.?.application_outputs[0..result.counts.application], tick);
    commands.completeConnects(self, result.transport_events, tick);
    publishTurn(self, &result, tick, sequence);
    return result;
}

/// The earliest host-owned deadline, read under the lock: metrics rendering, the health log,
/// connect timeouts, the graceful close and the gossip processor's groups and expiry. Host work
/// found by the previous turn's event capture is due now.
fn hostDeadline(self: *Runtime, timestamp: n.Now) u64 {
    if (self.host_due) return timestamp.millis();
    var deadline = @min(self.metrics_due_ms, self.health_log_due_ms);
    if (commands.connectDeadline(&self.bridge.commands)) |value| deadline = @min(deadline, value);
    if (self.closing_deadline) |value| deadline = @min(deadline, value);
    if (self.bridge.gossip) |*table| if (table.deadline()) |value| {
        deadline = @min(deadline, value);
    };
    return deadline;
}

/// The core's host seam for this owner.
const Host = struct {
    runtime: *Runtime,
    io: std.Io,
    failure: ?anyerror = null,

    fn apply(context: *anyopaque, core: *n.NetworkCore, tick: n.Now) n.NetworkCore.HostProgress {
        const self: *Host = @ptrCast(@alignCast(context));
        std.debug.assert(core == &self.runtime.owner.?.core);
        if (self.failure != null) return .{};
        return applyWork(self.runtime, self.io, tick) catch |err| {
            self.failure = err;
            return .{};
        };
    }
};

/// Drains the wake pipe before reading any queue, so a submission that lands after the drain
/// wakes the next poll. Then applies reports, commands, publications and requests in admission
/// order, gossip verdicts and processor maintenance, and pending request and response actions.
fn applyWork(self: *Runtime, io: std.Io, tick: n.Now) !n.NetworkCore.HostProgress {
    self.lock();
    self.bridge.wake.?.drain() catch self.failLocked(error.NetworkWakeFailed);
    self.host_due = false;
    const stop = self.bridge.stop;
    const stopped = self.bridge.stop and !(self.bridge.graceful and self.bridge.reason == .requested);
    self.unlock();
    if (stopped) return .{};
    var more = false;
    if (!stop) {
        more = applyReports(self, tick) or more;
        more = try executeWork(self, io, tick) or more;
    }
    more = try gossip_mod.maintain(self, io, tick) or more;
    requests_mod.applyPending(self, tick);
    more = try incoming_mod.applyPending(self, tick) or more;
    return .{ .runnable = more };
}

/// Applies up to 32 queued peer reports. Returns whether more remain.
fn applyReports(self: *Runtime, tick: n.Now) bool {
    for (0..32) |_| {
        self.lock();
        const report = self.bridge.reports.next();
        self.unlock();
        const item = report orelse return false;
        if (self.owner.?.core.reportPeer(&item.identity, item.action, tick) == null) {
            self.lock();
            self.bridge.reports.ignored +|= 1;
            self.unlock();
        }
    }
    self.lock();
    defer self.unlock();
    return self.bridge.reports.pending != 0;
}

/// Executes queued commands, publications and requests in admission order under their per-turn
/// caps. Returns whether a cap stopped it with work left.
fn executeWork(self: *Runtime, io: std.Io, tick: n.Now) !bool {
    var controls: usize = 0;
    var requests: usize = 0;
    var publishes: usize = 0;
    var bytes: usize = 0;
    for (0..commands.turn_max + publications.turn_max + requests_mod.turn_max) |_| {
        self.lock();
        if (self.bridge.stop or self.bridge.operations_held) {
            self.unlock();
            return false;
        }
        const command = self.bridge.commands.nextQueued();
        const publication = self.bridge.publications.?.oldest();
        const request = self.bridge.requests.?.oldest();
        const control_order = if (command) |token| self.bridge.commands.get(token).order else std.math.maxInt(u64);
        const publish_order = if (publication) |token| self.bridge.publications.?.get(token).?.order else std.math.maxInt(u64);
        const request_order = if (request) |token| self.bridge.requests.?.get(token).?.order else std.math.maxInt(u64);
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
            const cell = self.bridge.commands.get(command.?);
            cell.sequence = self.bridge.commands.advance() catch |err| {
                self.unlock();
                return err;
            };
            self.bridge.commands.transition(cell, .executing);
            self.unlock();
            commands.execute(self, command.?, tick);
            controls += 1;
        } else if (order == publish_order) {
            const len = self.bridge.publications.?.get(publication.?).?.payload.len;
            if (publishes == publications.turn_max or (publishes != 0 and len > publications.turn_bytes -| bytes)) {
                self.unlock();
                return true;
            }
            _ = self.bridge.commands.advance() catch |err| {
                self.unlock();
                return err;
            };
            self.unlock();
            publications.execute(self, publication.?, tick, (try Now.read(io)).millis());
            publishes += 1;
            bytes += len;
        } else {
            if (requests == requests_mod.turn_max) {
                self.unlock();
                return true;
            }
            _ = self.bridge.commands.advance() catch |err| {
                self.unlock();
                return err;
            };
            self.unlock();
            try requests_mod.submit(self, request.?, tick);
            requests += 1;
        }
    }
    return true;
}

fn publishTurn(self: *Runtime, result: *const n.NetworkCore.Result, timestamp: n.Now, sequence: u64) void {
    if (timestamp.millis() >= self.metrics_due_ms) {
        publishMetrics(self, timestamp) catch |err| {
            self.lock();
            self.metrics.failure = err;
            self.unlock();
        };
        self.metrics_due_ms = timestamp.millis() +| n.metrics.interval_ms;
    }
    self.lock();
    if (timestamp.millis() >= self.health_log_due_ms) {
        const counts = self.owner.?.core.peerCounts();
        const active_requests = self.owner.?.core.protocols.reqresp.pendingCounts();
        std.log.scoped(.network_runtime).info("network_health peers={d} relevant={d} target={d} requests_outbound={d} requests_inbound={d} dial_started={d} dial_deferred={d} discovery_peers={d} gossip_pressure_resets={d} received_bytes={d} sent_bytes={d}", .{ counts.connected, counts.relevant, self.owner.?.resolved.core.peers.target_peers, active_requests.outbound, active_requests.inbound, self.owner.?.core.counters.dial_started, self.owner.?.core.counters.dial_deferred, if (self.owner.?.core.discovery) |discovery| discovery.transport.engine.peerCount() else 0, self.owner.?.core.protocols.gossipsub.counters.local_pressure_resets, self.owner.?.core.transport.counters.received_bytes, self.owner.?.core.transport.counters.sent_bytes });
        self.health_log_due_ms = timestamp.millis() +| 30000;
    }
    if (self.bridge.peer_updates) |lane| lane.publish(self.owner.?.outputs[0..result.counts.peers], sequence);
    self.notifyIfReadyLocked();
    if (result.failure) |err| {
        std.log.scoped(.network_runtime).debug("owner_turn_failed reason={s} fatal={any}", .{ @errorName(err), result.readiness.failure != null });
        self.operational_failures +|= 1;
        if (result.readiness.failure != null) self.failLocked(err);
    }
    self.owner_turns +|= 1;
    self.unlock();
}

fn publishMetrics(self: *Runtime, timestamp: n.Now) n.metrics.registry.Error!void {
    var context = n.metrics.Context.init(&self.owner.?.core, timestamp, true);
    self.lock();
    if (self.bridge.gossip) |*table| {
        const state = table.snapshot(timestamp.millis());
        context.expired_executing = state.expiredExecuting;
    }
    self.captureProcessorLocked(&self.owner.?.processor_metrics);
    self.unlock();
    context.processor = &self.owner.?.processor_metrics;
    const index = try self.metrics.render(&context);
    self.lock();
    self.metrics.published = index;
    self.metrics.failure = null;
    self.unlock();
}

test "a command queued after wait planning executes in the turn whose poll observes the wake" {
    if (!n.NetworkCore.wait.supported) return error.SkipZigTest;
    const testing = std.testing.allocator;
    var runtime: Runtime = .{ .env = undefined, .bridge = .{ .notify_live = false, .env_alive = false } };
    const owner = try testing.create(Owner);
    defer testing.destroy(owner);
    owner.* = .{};
    owner.threaded = std.Io.Threaded.init(testing, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
    defer owner.threaded.deinit();
    const io = owner.threaded.io();
    runtime.owner = owner;
    const key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{71}));
    const resolved = try n.configuration.resolve(.{
        .profile = .small,
        .seed = 1,
        .gossip = .{ .topic_policy = &test_support.topic_policy },
        .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }},
        .admission_policy = .{ .deneb_start_slot = 0, .blocks_pre_deneb = 1024, .blocks_deneb = 128, .blob_identifiers_deneb = 768, .blob_identifiers_electra = 1152, .number_of_columns = 128, .column_chunks = 16384, .blob_schedule = &.{.{ .start_slot = 0, .max_blobs = 6 }} },
    });
    try owner.core.init(testing, io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = .{ .metadata = .{ .custody_group_count = 1 }, .status = .{ .earliest_available_slot = 0 } },
    });
    defer owner.core.deinit(io);
    runtime.bridge.wake = try network_wake.Wake.init();
    defer runtime.bridge.wake.?.deinit();
    try owner.core.setHostWake(runtime.bridge.wake.?.read_fd);
    runtime.bridge.payload_budget.limit = 1 << 20;
    runtime.bridge.publications = try publications.Table.init(testing, 1, &runtime.bridge.payload_budget);
    defer runtime.bridge.publications.?.deinit();
    runtime.bridge.requests = try requests_mod.Table.init(testing, 1, &runtime.bridge.payload_budget);
    defer runtime.bridge.requests.?.deinit();
    var host: Host = .{ .runtime = &runtime, .io = io };
    const ingress: gossip_mod.Ingress = .{ .runtime = &runtime, .io = io };
    // The first turns render metrics and write the health log, then only deadlines remain.
    for (0..4) |_| _ = (try turn(&runtime, io, &host, &ingress)).?;

    const SubmitAtPoll = struct {
        threadlocal var target: ?*Runtime = null;
        threadlocal var token: ?commands.Token = null;
        threadlocal var failure: ?anyerror = null;
        threadlocal var base: std.Io = undefined;

        fn checkCancel(userdata: ?*anyopaque) std.Io.Cancelable!void {
            // The native wait checks cancellation after planning and before polling.
            if (target) |pending| {
                target = null;
                token = pending.reserveCommand(.getIdentity) catch |err| {
                    failure = err;
                    return error.Canceled;
                };
                pending.queueCommand(token.?) catch |err| {
                    failure = err;
                    return error.Canceled;
                };
            }
            return base.vtable.checkCancel(userdata);
        }
    };
    SubmitAtPoll.target = &runtime;
    defer SubmitAtPoll.target = null;
    SubmitAtPoll.token = null;
    SubmitAtPoll.failure = null;
    SubmitAtPoll.base = io;
    var vtable = io.vtable.*;
    vtable.checkCancel = SubmitAtPoll.checkCancel;
    const poll_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    const result = (try turn(&runtime, poll_io, &host, &ingress)).?;
    try std.testing.expect(SubmitAtPoll.target == null);
    try std.testing.expect(SubmitAtPoll.failure == null);
    try std.testing.expect(result.failure == null);
    try std.testing.expect(result.readiness.host);
    const token = SubmitAtPoll.token orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(.terminal, runtime.bridge.commands.get(token).state);
    try std.testing.expect(runtime.bridge.commands.get(token).failure == null);
    runtime.abortCommand(token);
    runtime.owner = null;
}

test "queued request and disconnect share the protocol turn clock while latency uses execution time" {
    const testing = std.testing.allocator;
    var runtime: Runtime = .{ .env = undefined, .bridge = .{ .notify_live = false, .env_alive = false } };
    const owner = try testing.create(Owner);
    defer testing.destroy(owner);
    owner.* = .{};
    runtime.owner = owner;
    const key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{71}));
    const resolved = try n.configuration.resolve(.{
        .profile = .small,
        .seed = 1,
        .gossip = .{ .topic_policy = &test_support.topic_policy },
        .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }},
        .admission_policy = .{ .deneb_start_slot = 0, .blocks_pre_deneb = 1024, .blocks_deneb = 128, .blob_identifiers_deneb = 768, .blob_identifiers_electra = 1152, .number_of_columns = 128, .column_chunks = 16384, .blob_schedule = &.{.{ .start_slot = 0, .max_blobs = 6 }} },
    });
    try owner.core.init(testing, std.testing.io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = .{ .metadata = .{ .custody_group_count = 1 }, .status = .{ .earliest_available_slot = 0 } },
    });
    defer owner.core.deinit(std.testing.io);
    const remote_key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{73}));
    var remote: n.Transport = .{};
    try remote.init(testing, std.testing.io, .{ .host = &remote_key, .bind = .{ .ip4 = .loopback(0) } });
    defer remote.deinit(std.testing.io);
    const remote_id = remote.peerId();
    _ = try owner.core.transport.dialPeer(std.testing.io, remote.localAddress(), remote_id, try n.Now.read(std.testing.io));
    for (0..64) |_| {
        var events: [32]n.Engine.Event = undefined;
        const progress = n.transport_driver.step(&owner.core.transport, std.testing.io, &events, .{ .wait_max = .fromMilliseconds(0) });
        if (progress.failure) |err| return err;
        for (events[0..progress.progress.events]) |event| if (event == .connected) {
            owner.core.peer_manager.transportProgress(&owner.core.transport.engine);
            try std.testing.expect(owner.core.peer_manager.admit(&event.connected, remote.localAddress(), progress.progress.now) != null);
        };
        if (owner.core.isConnected(&remote_id)) break;
        const reply = n.transport_driver.step(&remote, std.testing.io, &events, .{ .wait_max = .fromMilliseconds(0) });
        if (reply.failure) |err| return err;
    }
    try std.testing.expect(owner.core.isConnected(&remote_id));
    const tick = try n.Now.read(std.testing.io);
    const Clock = struct {
        var time: n.Now = undefined;
        fn read(_: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            return .{ .nanoseconds = if (clock == .real) @as(i96, time.unixSeconds()) * std.time.ns_per_s else @as(i96, time.millis()) * std.time.ns_per_ms };
        }
    };
    Clock.time = Now.fromMilliseconds(.{ .mono_ms = tick.millis() + 100, .unix_s = tick.unixSeconds() });
    var vtable = std.testing.io.vtable.*;
    vtable.now = Clock.read;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    runtime.bridge.payload_budget.limit = 64 << 20;
    runtime.bridge.publications = try publications.Table.init(testing, 1, &runtime.bridge.payload_budget);
    defer runtime.bridge.publications.?.deinit();
    runtime.bridge.requests = try requests_mod.Table.init(testing, 1, &runtime.bridge.payload_budget);
    defer runtime.bridge.requests.?.deinit();

    const peer_key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{72}));
    const connect = try runtime.bridge.commands.reserve(.connect);
    defer runtime.bridge.commands.retire(connect);
    const command = runtime.bridge.commands.get(connect);
    command.input.peer = n.PeerId.fromPublicKey(&peer_key.publicKey());
    command.input.addresses[0] = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9000 } };
    command.input.address_count = 1;
    command.input.timeout_ms = 1000;
    runtime.bridge.commands.transition(command, .queued);

    const publication = try runtime.bridge.publications.?.reserve(.beacon_block, 0);
    defer runtime.bridge.publications.?.retire(publication);
    const cell = runtime.bridge.publications.?.get(publication).?;
    cell.order = try runtime.bridge.commands.nextOrder();
    cell.queued_ms = tick.millis() + 50;
    runtime.bridge.publications.?.transition(cell, .queued);

    const request = try runtime.bridge.requests.?.reserve(.blocks_by_root_v2, 32);
    defer {
        owner.core.deinit(io);
        requests_mod.closeLocked(&runtime);
        runtime.bridge.requests.?.retire(request);
    }
    try runtime.bridge.requests.?.allocate(request, 32);
    const request_cell = runtime.bridge.requests.?.get(request).?;
    request_cell.peer = remote_id;
    @memset(request_cell.input, 0);
    request_cell.order = try runtime.bridge.commands.nextOrder();
    request_cell.state = .queued;
    runtime.bridge.requests.?.refresh(request_cell);

    const disconnect = try runtime.bridge.commands.reserve(.disconnect);
    defer runtime.bridge.commands.retire(disconnect);
    runtime.bridge.commands.get(disconnect).input.peer = remote_id;
    runtime.bridge.commands.transition(runtime.bridge.commands.get(disconnect), .queued);
    try std.testing.expect(!try executeWork(&runtime, io, tick));
    try std.testing.expect(command.failure == null);
    try std.testing.expectEqual(tick.millis() + 1000, command.deadline);
    try std.testing.expectEqual(error.UnknownTopic, cell.failure.?);
    try std.testing.expectEqual(tick.millis(), owner.core.protocols.gossipsub.last_now_ms);
    try std.testing.expectEqual(@as(u128, 50), runtime.bridge.publications.?.latency.sum);
    try std.testing.expect(runtime.bridge.commands.get(disconnect).failure == null);
    try std.testing.expect(!owner.core.isConnected(&remote_id));
    try std.testing.expect(request_cell.native != null);

    const counts = owner.core.protocols.process(&owner.core.transport.engine, &.{}, tick, .{ .application = &owner.application_outputs });
    try requests_mod.capture(&runtime, owner.application_outputs[0..counts.application], tick);
    try std.testing.expectEqual(@as(usize, 1), counts.application);
    try std.testing.expectEqual(requests_mod.State.terminal, request_cell.state);
    try std.testing.expectEqual(n.reqresp.ReqResp.Failure{ .negotiation_failed = .stream_closed }, request_cell.terminal.?.failed.reason);
    const counters = &owner.core.protocols.reqresp.protocol_counters[@intFromEnum(n.reqresp.Protocol.blocks_by_root_v2)];
    try std.testing.expectEqual(@as(u64, 1), counters.outgoing_time.count);
    try std.testing.expectEqual(@as(u128, 0), counters.outgoing_time.sum);
}
