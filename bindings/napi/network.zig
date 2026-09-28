const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const cfg = @import("network_config.zig");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const Value = napi.Value;
const requests = @import("network_requests.zig");
const gossip = @import("network_gossip.zig");
const publication_js = @import("network_publication_js.zig");
const publications = @import("network_publications.zig");
const gossip_js = @import("network_gossip_js.zig");
const incoming = @import("network_incoming.zig");
const incoming_js = @import("network_incoming_js.zig");
const request_js = @import("network_request_js.zig");
const exchange_mod = @import("network_exchange.zig");
const command_js = @import("network_command_js.zig");
const fatal = @import("network_fatal.zig");

pub const js_meta = js.class(.{});

runtime: ?*Runtime = null,
stopped: bool = false,

pub fn init() @This() {
    return .{};
}

pub fn initialize(self: *@This(), config: js.Value, callback: js.Value) !js.Value {
    if (self.stopped) return error.NetworkClosed;
    if (try callback.val.typeof() != .function) return error.InvalidNetworkConfig;
    const runtime = try r.create(js.env());
    errdefer runtime.release();
    errdefer runtime.disposeJsReferences();
    runtime.heavy = try r.allocator.create(r.Owner);
    runtime.heavy.?.* = .{};
    try application_cfg.parse(config.val, &runtime.heavy.?.config, &runtime.heavy.?.application);
    runtime.logs.configure(runtime.heavy.?.application.log_level);
    try @import("network_owner.zig").prepareConfiguration(runtime);
    try prepareApplicationStorage(runtime, &runtime.heavy.?.application);
    runtime.slot = runtime.heavy.?.config.slot;
    runtime.diag.currentSlot = runtime.slot;
    runtime.wake = try @import("network_wake.zig").Wake.init();
    errdefer if (runtime.wake) |*wake| wake.deinit();
    try @import("network_owner.zig").initialize(runtime);
    runtime.identity = try runtime.heavy.?.readIdentity();

    const env = js.env();
    const name = try env.createStringUtf8("NativeNetworkRuntime");
    runtime.notify = try r.Notify.create(env, callback.val, null, name, 1, 1, runtime, Runtime.finalize, onNotify);
    runtime.retain();
    errdefer runtime.notify.release(.abort) catch unreachable;
    try runtime.notify.unref(env);
    try env.addEnvCleanupHook(Runtime, runtime, Runtime.cleanup);
    runtime.hook_live = true;
    runtime.retain();
    errdefer runtime.removeHook();
    try runtime.results.prepare(env);
    const holder = try env.createObject();
    try holder.setNamedProperty("identity", try command_js.identity(env, &runtime.identity));
    try holder.setNamedProperty("limits", try resolvedLimits(env, runtime));
    try holder.setNamedProperty("capacities", try capacities(env, runtime));
    runtime.retain();
    errdefer runtime.release();
    runtime.thread = try std.Thread.spawn(.{ .stack_size = std.Thread.SpawnConfig.default_stack_size }, @import("network_owner.zig").run, .{runtime});
    self.runtime = runtime;
    return .{ .val = holder };
}

fn prepareApplicationStorage(runtime: *Runtime, app: *const application_cfg.Config) !void {
    const resolved = &runtime.heavy.?.resolved;
    runtime.peer_capacity = resolved.core.peers.capacity;
    runtime.max_peers = resolved.core.peers.max_peers;
    runtime.diag.resolvedCapacities = .{
        .peerCapacity = resolved.core.peers.capacity,
        .targetPeers = resolved.core.peers.target_peers,
        .maxPeers = resolved.core.peers.max_peers,
        .minOutbound = resolved.core.peers.min_outbound,
        .outboundReserve = resolved.core.peers.outbound_reserve,
        .connectionCapacity = resolved.limits.connections_max,
        .handshakingCapacity = resolved.limits.handshaking_max,
        .dialingCapacity = resolved.limits.dialing_max,
        .requestPeerCapacity = resolved.core.service.reqresp.peers,
        .admissionIdentityCapacity = resolved.core.service.reqresp.admission.limits.identities,
        .gossipConnectedCapacity = resolved.core.service.gossipsub.connected_capacity,
        .gossipRetainedCapacity = resolved.core.service.gossipsub.retained_capacity,
        .dialEngineCapacity = resolved.limits.dialing_max,
    };
    const limits = resolved.core.service.reqresp;
    const request_capacity: usize = limits.outbound_max - limits.outbound_control_reserved;
    const incoming_capacity: usize = limits.inbound_max - limits.inbound_control_reserved;
    const gossip_options = &resolved.core.service.gossipsub;
    const chain = &runtime.heavy.?.config.chain;
    const gossip_plan = n.gossip_processor.Plan.resolve(gossip_options, chain.forks[0..chain.boundary_count]);
    const gossip_backing = gossip.Table.backingBytes(gossip_plan.capacity, gossip_plan.bytes);
    const metrics_capacity = n.metrics.textCapacity(chain.topics[0..chain.boundary_count]);
    const publication_capacity: usize = if (runtime.heavy.?.config.profile == .small) 32 else publications.capacity_max;
    const bridge = publication_capacity * @sizeOf(publications.Cell) + 2 * metrics_capacity + gossip_backing + incoming_capacity * @sizeOf(incoming.Cell) + request_capacity * @sizeOf(requests.Cell) + @sizeOf(Runtime) + @sizeOf(r.Owner) - @sizeOf(n.NetworkCore) + r.Stores.bytes(runtime.peer_capacity) + @sizeOf(projection.Lane);
    if (bridge > app.resources.bridgeBudgetBytes) return error.NetworkBridgeBudgetExceeded;
    runtime.metrics = try @import("network_metrics.zig").Export.init(metrics_capacity);
    runtime.requests = try requests.Table.init(r.allocator, request_capacity, &runtime.payload_budget);
    runtime.payload_budget.limit = app.resources.bridgeBudgetBytes - bridge;
    var response_max: usize = 0;
    var request_max: usize = 0;
    for (0..n.reqresp.Protocol.count) |i| {
        const protocol: n.reqresp.Protocol = @enumFromInt(i);
        if (protocol.isControl()) continue;
        response_max = @max(response_max, protocol.info().response_max);
        request_max = @max(request_max, protocol.info().request_max);
    }
    // Keep one serving response, two local RPCs, and two urgent publications independently admissible.
    try runtime.payload_budget.protect(response_max + 2 * request_max * incoming_capacity, 2 * (request_max + 2 * response_max), 2 * gossip.payload_max);
    runtime.publications = try publications.Table.init(r.allocator, publication_capacity, &runtime.payload_budget);
    runtime.incoming = try incoming.Table.init(r.allocator, incoming_capacity, &runtime.payload_budget);
    runtime.gossip = try gossip.Table.init(r.allocator, gossip_plan);
    runtime.stores = try r.Stores.create(r.allocator, runtime.peer_capacity);
    runtime.lane = try r.allocator.create(projection.Lane);
    runtime.lane.?.* = .{};
    runtime.diag.bridgeRequestedBytes = bridge;
}

pub fn deinit(self: *@This()) void {
    if (self.runtime) |runtime| {
        runtime.forceStop(false);
        runtime.removeHook();
        if (runtime.notify_finalized) runtime.reclaim();
        runtime.release();
        self.runtime = null;
    }
}

fn onNotify(env: napi.Env, callback: Value, runtime: *Runtime, _: *void) void {
    // Only an environment that stopped running JavaScript fails the notification's own N-API calls.
    notify(env, callback, runtime) catch runtime.forceStop(true);
}

/// Node may disable JavaScript before running environment cleanup hooks.
fn jsStopped(err: anyerror) bool {
    return err == error.Closing or err == error.CannotRunJS or err == error.PendingException;
}

/// The notification callback only schedules: the host runs an exchange, which arms again once nothing is queued. The
/// completion owner always does, also for a collected wrapper.
fn notify(env: napi.Env, callback: Value, runtime: *Runtime) !void {
    runtime.lock();
    const alive = runtime.env_alive;
    runtime.unlock();
    if (!alive) return;
    _ = env.callFunction(callback, try env.getUndefined(), .{}) catch {
        // A throwing host may not have scheduled an exchange, so owner activity can notify again.
        runtime.lock();
        runtime.readiness.forget();
        runtime.unlock();
    };
}

/// One host exchange (network_exchange.zig): the host's actions, then the completions or the close result, and the
/// payload `demand` asks for, delivered in one result.
pub fn exchange(self: *@This(), actions_value: js.Value, demand_value: js.Value) !js.Value {
    const call = r.call(self.runtime, .exchange);
    defer call.end();
    const runtime = try self.owner();
    runtime.retain();
    defer runtime.release();
    if (runtime.in_exchange) return error.NetworkExchangeReentered;
    runtime.in_exchange = true;
    defer runtime.in_exchange = false;
    var actions: [exchange_mod.action_max]exchange_mod.Action = undefined;
    const count = try exchange_mod.parseActions(actions_value.val, &actions);
    const demand = try exchange_mod.Demand.parse(demand_value.val);
    var host: Exchange = .{ .env = js.env(), .runtime = runtime };
    const now = try gossip.monotonic();
    const result = exchange_mod.run(runtime, actions[0..count], &demand, now, &host) catch |err| {
        if (jsStopped(err)) runtime.forceStop(true);
        return err;
    };
    return .{ .val = result };
}

/// Throws what an exchange would for `action`, applying nothing, so a host's invalid input fails its own call.
pub fn checkAction(_: *@This(), action: js.Value) !void {
    _ = try exchange_mod.parseAction(action.val);
}

/// Stops the owner at once for a wrapper collected without close. JavaScript still drains every result.
pub fn abandon(self: *@This()) void {
    if (self.runtime) |runtime| runtime.abandon();
}

/// A private control for binding ownership tests: while held, the owner leaves reported verdicts unapplied, so no
/// acknowledgement follows them, though expiry still disposes of them; a release wakes the owner.
pub fn holdVerdicts(self: *@This(), held: js.Value) !void {
    const runtime = try self.owner();
    const value = try cfg.boolean(held.val);
    runtime.lock();
    defer runtime.unlock();
    runtime.verdicts_held = value;
    if (!value) runtime.signalLocked();
}

/// A private control for binding ownership tests: while held, the owner starts no admitted command, publication or
/// request, which keep their admission order; a release wakes the owner.
pub fn holdOperations(self: *@This(), held: js.Value) !void {
    const runtime = try self.owner();
    const value = try cfg.boolean(held.val);
    runtime.lock();
    defer runtime.unlock();
    runtime.operations_held = value;
    if (!value) runtime.signalLocked();
}

/// Terminates the process at a fatal site JavaScript raises (network_fatal.zig). `reason` is at most 64 printable ASCII
/// bytes.
pub fn fail(_: *@This(), site_value: js.Value, reason_value: js.Value) !void {
    var name: [fatal.name_max]u8 = undefined;
    const site = std.meta.stringToEnum(fatal.Site, name[0..try application_cfg.text(site_value.val, &name)]) orelse return error.InvalidNetworkConfig;
    switch (site) {
        .generated_batch, .failed_turns, .completion_contract => {},
        .exchange_build, .exchange_finish => return error.InvalidNetworkConfig,
    }
    var reason: [fatal.detail_max]u8 = undefined;
    fatal.terminate(js.env(), site, reason[0..try application_cfg.text(reason_value.val, &reason)]);
}

/// The N-API side of an exchange: the result's JS values.
const Exchange = struct {
    env: napi.Env,
    runtime: *Runtime,

    pub const Result = Value;

    /// A fresh result, or null when there is nothing to deliver and a prepared one serves.
    pub fn build(self: *Exchange, selection: *exchange_mod.Selection) !?Value {
        if (!selection.delivers()) return null;
        return try exchange_mod.build(self.env, self.runtime, selection);
    }
    pub fn finish(self: *Exchange, output: ?Value, outcome: exchange_mod.Outcome) !Value {
        return exchange_mod.finish(self.env, self.runtime, output, outcome);
    }
    pub fn keepAlive(self: *Exchange) void {
        self.runtime.notify.ref(self.env) catch {};
    }
    pub fn idle(self: *Exchange) void {
        self.runtime.notify.unref(self.env) catch {};
    }
    /// An exception that clears means the bridge broke its contract. One that will not clear means JavaScript cannot
    /// run, as does a pending-exception status with none pending, which N-API returns for cannot_run_js to this
    /// module version.
    pub fn classify(self: *Exchange, err: anyerror) exchange_mod.Failure {
        if (err == error.Closing or err == error.CannotRunJS) return .stopped;
        const pending = self.env.isExceptionPending() catch return .stopped;
        if (!pending) return if (err == error.PendingException) .stopped else .contract;
        _ = self.env.getAndClearLastException() catch return .stopped;
        return .contract;
    }
    pub fn terminate(self: *Exchange, site: fatal.Site, err: anyerror) noreturn {
        fatal.terminate(self.env, site, @errorName(err));
    }
};

fn owner(self: *@This()) !*Runtime {
    return self.runtime orelse error.NetworkClosed;
}

pub fn getState(self: *@This()) !js.Value {
    const runtime = try self.owner();
    runtime.lock();
    const state = runtime.diag.state;
    runtime.unlock();
    return .{ .val = try js.env().createStringUtf8(@tagName(state)) };
}
pub fn close(self: *@This()) void {
    self.stopped = true;
    if (self.runtime) |runtime| {
        runtime.lock();
        const ref_notify = runtime.env_alive and runtime.notify_live;
        runtime.unlock();
        if (ref_notify) runtime.notify.ref(runtime.env) catch {};
        runtime.lock();
        runtime.graceful = !runtime.disposed;
        runtime.unlock();
        runtime.requestStop();
    }
}

fn text(value: []const u8) !Value {
    return js.env().createStringUtf8(value);
}
/// The resolved limits a host sizes its own work by: retained peers and concurrently served requests.
fn resolvedLimits(env: napi.Env, runtime: *const Runtime) !Value {
    const object = try env.createObject();
    try object.setNamedProperty("peerCapacity", try env.createUint32(runtime.peer_capacity));
    try object.setNamedProperty("incomingCapacity", try env.createUint32(@intCast(runtime.incoming.?.diag.capacity)));
    return object;
}

/// Each operation family's cells, which size the completion owner's records.
fn capacities(env: napi.Env, runtime: *const Runtime) !Value {
    const object = try env.createObject();
    try object.setNamedProperty("publication", try env.createUint32(@intCast(runtime.publications.?.diag.capacity)));
    try object.setNamedProperty("command", try env.createUint32(commands.capacity));
    try object.setNamedProperty("request", try env.createUint32(@intCast(runtime.requests.?.diag.capacity)));
    try object.setNamedProperty("incoming", try env.createUint32(@intCast(runtime.incoming.?.diag.capacity)));
    return object;
}

pub fn getMetrics(self: *@This()) !js.String {
    const call = r.call(self.runtime, .get_metrics);
    defer call.end();
    const runtime = try self.owner();
    runtime.lock();
    defer runtime.unlock();
    const logs = runtime.logs.snapshot();
    const metrics_text = runtime.metrics.text(&logs) catch |err| return switch (err) {
        error.WriteFailed, error.MetricCapacity => error.NetworkMetricsCapacity,
        error.DuplicateMetric => error.NetworkMetricsSchema,
    };
    return js.String.from(metrics_text);
}

pub fn drainLogs(self: *@This(), limit: js.Value) !js.Value {
    return @import("network_logs.zig").drain(try self.owner(), limit.val);
}

pub fn setLogLevel(self: *@This(), level: js.Value) !void {
    try @import("network_logs.zig").configure(try self.owner(), level.val);
}

pub fn diagnostics(self: *@This()) !js.Value {
    const snapshot = try (try self.owner()).snapshot();
    const object = try @import("network_js.zig").scalarFields(js.env(), &snapshot);
    try object.setNamedProperty("state", try text(@tagName(snapshot.state)));
    try object.setNamedProperty("terminalErrorCode", if (snapshot.terminal_error) |err| try text(@errorName(err)) else try js.env().getNull());
    try object.setNamedProperty("resolvedCapacities", try @import("network_js.zig").scalarFields(js.env(), &snapshot.resolvedCapacities));
    try object.setNamedProperty("payloadBudget", try @import("network_js.zig").scalarFields(js.env(), &snapshot.payloadBudget));
    try object.setNamedProperty("publications", try @import("network_js.zig").scalarFields(js.env(), &snapshot.publications));
    try object.setNamedProperty("requests", try request_js.diagnostics(js.env(), &snapshot.requests));
    try object.setNamedProperty("gossip", try gossip_js.diagnostics(js.env(), &snapshot.gossip));
    try object.setNamedProperty("incoming", try incoming_js.diagnostics(js.env(), &snapshot.incoming));
    return .{ .val = object };
}
const commands = @import("network_commands.zig");
const application_cfg = @import("network_application_config.zig");
const projection = @import("network_peer_projection.zig");
const n = @import("network");

fn parseAddresses(value: Value, input: *commands.Input) !void {
    input.address_count = @intCast(try cfg.array(value, 2));
    if (input.address_count == 0) return error.InvalidNetworkConfig;
    for (input.addresses[0..input.address_count], 0..) |*address, i| {
        const parsed = try cfg.endpoint(try value.getElement(@intCast(i)));
        address.* = switch (parsed) {
            .ip4 => |ip| .{ .ip4 = .{ .octets = ip.bytes, .port = ip.port } },
            .ip6 => |ip| .{ .ip6 = .{ .octets = ip.bytes, .port = ip.port } },
        };
        if (address.port() == 0) return error.InvalidNetworkConfig;
    }
}
fn submit(self: *@This(), comptime command: commands.Command, args: []const Value) !js.Value {
    const runtime = try self.owner();
    const token = try runtime.reserveCommand(command);
    errdefer runtime.abortCommand(token);
    const operation = &runtime.table.cells[token.index];
    const store = runtime.table.cells[token.index].store;
    switch (command) {
        .applyIntent => {
            operation.input.slot = try cfg.bigint(args[1]);
            try application_cfg.parseIntent(args[0], &runtime.stores.?.intents[store.?], runtime.max_peers);
        },
        .updateStatus => try cfg.parseStatus(args[0], &operation.input.status),
        .getIdentity, .getPeers, .getDirectPeers, .getRememberedPeers => {},
        .getGossipDiagnostics => operation.input.diagnostics_cursor = @intCast(try cfg.integer(args[0], 512)),
        .reStatusPeers => {
            operation.input.target_count = @intCast(try cfg.array(args[0], 256));
            for (runtime.stores.?.targets[store.?][0..operation.input.target_count], 0..) |*peer, i| {
                peer.* = try cfg.peerIdFrom(try args[0].getElement(@intCast(i)));
                for (runtime.stores.?.targets[store.?][0..i]) |*prior| if (peer.eql(prior)) return error.InvalidNetworkConfig;
            }
        },
        else => {
            operation.input.peer = try cfg.peerIdFrom(args[0]);
            if (command == .connect or command == .addDirectPeer) try parseAddresses(args[1], &operation.input);
            if (command == .connect) {
                operation.input.timeout_ms = try cfg.bigint(args[2]);
                if (operation.input.timeout_ms == 0 or operation.input.timeout_ms > 60_000) return error.InvalidNetworkInteger;
            }
        },
    }
    const env = js.env();
    // Prepared before admission commits, so every admitted command has a handle to complete.
    const handle = try @import("network_js.zig").handle(env, token.index, token.generation);
    try runtime.queueCommand(token);
    runtime.notify.ref(env) catch {};
    return .{ .val = handle };
}
pub fn applyIntent(self: *@This(), intent: js.Value, slot: js.Value) !js.Value {
    return self.submit(.applyIntent, &.{ intent.val, slot.val });
}
pub fn updateStatus(self: *@This(), status: js.Value) !js.Value {
    return self.submit(.updateStatus, &.{status.val});
}
pub fn getIdentity(self: *@This()) !js.Value {
    return self.submit(.getIdentity, &.{});
}
pub fn getPeers(self: *@This()) !js.Value {
    return self.submit(.getPeers, &.{});
}
pub fn getGossipDiagnostics(self: *@This(), cursor: js.Value) !js.Value {
    return self.submit(.getGossipDiagnostics, &.{cursor.val});
}
pub fn connect(self: *@This(), peer: js.Value, addresses: js.Value, timeout: js.Value) !js.Value {
    return self.submit(.connect, &.{ peer.val, addresses.val, timeout.val });
}
pub fn disconnect(self: *@This(), peer: js.Value) !js.Value {
    return self.submit(.disconnect, &.{peer.val});
}
pub fn reStatusPeers(self: *@This(), peers: js.Value) !js.Value {
    return self.submit(.reStatusPeers, &.{peers.val});
}
pub fn addDirectPeer(self: *@This(), peer: js.Value, addresses: js.Value) !js.Value {
    return self.submit(.addDirectPeer, &.{ peer.val, addresses.val });
}
pub fn removeDirectPeer(self: *@This(), peer: js.Value) !js.Value {
    return self.submit(.removeDirectPeer, &.{peer.val});
}
pub fn getDirectPeers(self: *@This()) !js.Value {
    return self.submit(.getDirectPeers, &.{});
}
pub fn getRememberedPeers(self: *@This()) !js.Value {
    return self.submit(.getRememberedPeers, &.{});
}
pub fn requestStart(self: *@This(), peer: js.Value, protocol: js.Value, data: js.Value, options: js.Value) !js.Value {
    const call = r.call(self.runtime, .request_start);
    defer call.end();
    return .{ .val = try request_js.start(try self.owner(), peer.val, protocol.val, data.val, options.val) };
}
pub fn requestPull(self: *@This(), handle: js.Value) !void {
    const call = r.call(self.runtime, .request_pull);
    defer call.end();
    try request_js.pull(try self.owner(), handle.val);
}
pub fn requestRetire(self: *@This(), handle: js.Value, abandoned: js.Value) !void {
    const call = r.call(self.runtime, .request_retire);
    defer call.end();
    try request_js.retire(try self.owner(), handle.val, try cfg.boolean(abandoned.val));
}

pub fn incomingRespond(self: *@This(), handle: js.Value, data: js.Value, context: js.Value) !void {
    const call = r.call(self.runtime, .incoming_respond);
    defer call.end();
    try incoming_js.respond(try self.owner(), handle.val, data.val, context.val);
}
pub fn incomingRelease(self: *@This(), handle: js.Value) !void {
    const call = r.call(self.runtime, .incoming_release);
    defer call.end();
    try incoming_js.release(try self.owner(), handle.val);
}
pub fn incomingReady(self: *@This(), handle: js.Value) !void {
    const call = r.call(self.runtime, .incoming_ready);
    defer call.end();
    try incoming_js.ready(try self.owner(), handle.val);
}
pub fn incomingTerminal(self: *@This(), handle: js.Value, action: js.Value, status: js.Value, message: js.Value) !void {
    const call = r.call(self.runtime, .incoming_terminal);
    defer call.end();
    try incoming_js.terminal(try self.owner(), handle.val, action.val, status.val, message.val);
}

pub fn publishGossip(self: *@This(), topic: js.Value, data: js.Value, options: js.Value) !js.Value {
    const call = r.call(self.runtime, .publish_gossip);
    defer call.end();
    return .{ .val = try publication_js.publish(try self.owner(), topic.val, data.val, options.val) };
}

test "a notification JavaScript cannot run stops locally, and exchange failures classify as stopped or contract" {
    const shim = @import("network_runtime_test.zig");
    shim.undefined_status = napi.c.napi_cannot_run_js;
    defer shim.undefined_status = napi.c.napi_ok;
    var notified: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false };
    onNotify(undefined, undefined, &notified, undefined);
    try std.testing.expect(notified.disposed and notified.stop and !notified.env_alive);
    // An exception that clears is the bridge's contract failure; a pending-exception status with none pending is how
    // N-API reports JavaScript that cannot run.
    var classified: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false };
    var host: Exchange = .{ .env = undefined, .runtime = &classified };
    for ([_]struct { anyerror, bool, exchange_mod.Failure }{
        .{ error.Closing, true, .stopped },
        .{ error.CannotRunJS, true, .stopped },
        .{ error.PendingException, false, .stopped },
        .{ error.PendingException, true, .contract },
        .{ error.GenericFailure, false, .contract },
        .{ error.GenericFailure, true, .contract },
    }) |case| {
        shim.exception_pending = case[1];
        try std.testing.expectEqual(case[2], host.classify(case[0]));
        try std.testing.expectEqual(case[1] and case[2] == .stopped, shim.exception_pending);
    }
}
