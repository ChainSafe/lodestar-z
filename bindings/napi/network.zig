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
    if (self.stopped) return error.NetworkClosed;
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
    runtime.close_deferred = try env.createPromise();
    errdefer @import("network_js.zig").discardPromise(env, runtime.close_deferred.?);
    try prepareCloseResults(env, runtime);
    const holder = try env.createObject();
    try put(holder, "identity", try identity(env, &runtime.identity));
    try put(holder, "closed", runtime.close_deferred.?.getPromise());
    if (self.stopped) return error.NetworkClosed;
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

fn prepareCloseResults(env: napi.Env, runtime: *Runtime) !void {
    const fallback = try env.createObject();
    try put(fallback, "name", try env.createStringUtf8("Error"));
    try put(fallback, "code", try env.createStringUtf8("NetworkResultAllocationFailed"));
    try put(fallback, "message", try env.createStringUtf8("NetworkResultAllocationFailed"));
    runtime.copy_error = try napi.Ref.create(env.env, fallback, 1);
    inline for (.{ "requested", "failed" }, 0..) |reason, i| {
        const result = try env.createObject();
        try put(result, "reason", try env.createStringUtf8(reason));
        runtime.close_results[i] = try napi.Ref.create(env.env, result, 1);
    }
}

pub fn deinit(self: *@This()) void {
    if (self.runtime) |runtime| {
        runtime.forceStop(false);
        runtime.removeHook();
        if (runtime.notify_finalized) runtime.retireClosedRequests();
        runtime.release();
        self.runtime = null;
    }
}

fn onNotify(env: napi.Env, callback: Value, runtime: *Runtime, _: *void) void {
    notify(env, callback, runtime) catch |err| settlementFailed(env, runtime, err);
}

fn settlementFailed(env: napi.Env, runtime: *Runtime, err: anyerror) void {
    if (jsStopped(err)) return runtime.forceStop(true);
    // Failed settlement of valid, preallocated handles cannot notify the host reliably.
    env.fatalError("native network result settlement", @errorName(err));
}

/// Node may disable JavaScript before running environment cleanup hooks.
fn jsStopped(err: anyerror) bool {
    return err == error.Closing or err == error.CannotRunJS or err == error.PendingException;
}

/// The notification callback only schedules: a host that returns true drains through `exchange`,
/// which releases the latch this callback leaves set once native has nothing more. A callback that
/// returns anything else, such as a wrapper already collected, leaves no host drain, so the
/// results settle inline and the latch is released.
fn notify(env: napi.Env, callback: Value, runtime: *Runtime) !void {
    const started = r.bridge.now();
    defer runtime.bridge.notify.observe(r.bridge.now() -| started);
    runtime.lock();
    const alive = runtime.noticeLocked();
    runtime.unlock();
    if (!alive) return;
    const result = env.callFunction(callback, try env.getUndefined(), .{}) catch {
        // A throwing host may not have scheduled its drain, so a later ping notifies again. No
        // settlement can run until the exception propagates.
        runtime.lock();
        runtime.declineLocked();
        runtime.unlock();
        return;
    };
    if (try result.typeof() == .boolean and try result.getValueBool()) return;
    runtime.lock();
    runtime.declineLocked();
    runtime.unlock();
    for (0..2) |_| if (!try settleWithin(env, runtime, publications.capacity_max)) break;
}
fn makeError(env: napi.Env, err: anyerror) !Value {
    return @import("network_js.zig").errorValue(env, @errorName(err));
}

/// Settles up to `limit` completions per table, then the close result once the owner has
/// quiesced and nothing else awaits settlement. Returns whether more remain.
fn settleWithin(env: napi.Env, runtime: *Runtime, limit: usize) !bool {
    var more = try publication_js.settle(env, runtime, limit);
    more = try settleOperations(env, runtime, limit) or more;
    more = try request_js.settle(env, runtime, limit) or more;
    more = try incoming_js.settle(env, runtime, limit) or more;
    runtime.lock();
    const idle = runtime.table.occupied == 0 and (runtime.publications == null or !runtime.publications.?.obligated()) and !runtime.requestObligations() and runtime.notify_live and !runtime.stop;
    const closing = runtime.quiescent and !runtime.close_settled;
    // Owner quiescence is final, so completions it left before quiescing are all settleable now.
    more = more or runtime.settleableLocked();
    const reason = runtime.reason;
    runtime.unlock();
    if (idle) runtime.notify.unref(env) catch {};
    if (!closing or more) return more or closing;
    runtime.join();
    const value = try runtime.close_results[@intFromEnum(reason)].?.getValue();
    try runtime.close_deferred.?.resolve(value);
    runtime.close_settled = true;
    runtime.disposeCloseReferences();
    runtime.removeHook();
    return false;
}

/// One host drain turn: legacy settlement, then the payload `demand` asks for, delivered in one result.
pub fn exchange(self: *@This(), demand: js.Value) !js.Value {
    const call = r.call(self.runtime, .exchange);
    defer call.end();
    const runtime = try self.owner();
    runtime.retain();
    defer runtime.release();
    const parsed = exchange_mod.Demand.parse(demand.val) catch |err| return failExchange(runtime, err);
    var host: Exchange = .{ .env = js.env(), .runtime = runtime };
    const result = exchange_mod.run(runtime, &parsed, &host) catch |err| {
        if (jsStopped(err)) runtime.forceStop(true);
        return failExchange(runtime, @import("network_js.zig").copyError(err));
    };
    return .{ .val = result };
}

fn failExchange(runtime: *Runtime, err: anyerror) anyerror {
    runtime.lock();
    exchange_mod.failLocked(runtime);
    runtime.unlock();
    return err;
}

/// The N-API side of an exchange: legacy settlement, the clock, and the result's JS values.
const Exchange = struct {
    env: napi.Env,
    runtime: *Runtime,

    pub const Output = Value;

    pub fn settle(self: *Exchange, limit: usize) !exchange_mod.Settled {
        const runtime = self.runtime;
        runtime.lock();
        const due = runtime.settleableLocked() or (runtime.quiescent and !runtime.close_settled);
        runtime.unlock();
        if (!due) return .{};
        const completions = &runtime.bridge.delivered[@intFromEnum(r.bridge.Delivery.completion)];
        const before = completions.*;
        const more = settleWithin(self.env, runtime, limit) catch |err| {
            settlementFailed(self.env, runtime, err);
            return err;
        };
        return .{ .count = completions.* - before, .more = more };
    }
    pub fn now(_: *Exchange) !u64 {
        return gossip.monotonic();
    }
    pub fn build(self: *Exchange, selection: *exchange_mod.Selection, settled: usize) !Value {
        return exchange_mod.build(self.env, self.runtime, selection, settled);
    }
    pub fn discard(self: *Exchange, selection: *const exchange_mod.Selection) void {
        for (selection.closed[0..selection.closed_count]) |deferred| @import("network_js.zig").discardPromise(self.env, deferred);
    }
    pub fn keepAlive(self: *Exchange) void {
        self.runtime.notify.ref(self.env) catch {};
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

const put = @import("network_js.zig").put;
const element = @import("network_js.zig").element;
const bytes = @import("network_js.zig").bytes;
const endpoint = @import("network_js.zig").endpoint;
fn text(value: []const u8) !Value {
    return js.env().createStringUtf8(value);
}
fn identity(env: napi.Env, value: *const r.Identity) !Value {
    const object = try env.createObject();
    try put(object, "peerId", try @import("network_js.zig").peerIdValue(env, &value.peer));
    try put(object, "metadata", try projection.metadata(env, &value.metadata));
    const endpoints = try env.createArrayWithLength(@intFromBool(value.endpoints[0] != null) + @as(u32, @intFromBool(value.endpoints[1] != null)));
    var endpoint_index: u32 = 0;
    for (value.endpoints) |address| if (address) |bound| {
        try element(endpoints, endpoint_index, try endpoint(env, bound));
        endpoint_index += 1;
    };
    try put(object, "localEndpoints", endpoints);
    try put(object, "localEndpoint", try endpoint(env, value.endpoints[0] orelse value.endpoints[1].?));
    try put(object, "localMultiaddr", try bytes(env, value.multiaddr[0..value.multiaddr_len]));
    try put(object, "localEnr", if (value.enr_len == 0) try env.getNull() else try bytes(env, value.enr[0..value.enr_len]));
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
    try put(object, "state", try text(@tagName(snapshot.state)));
    try put(object, "terminalErrorCode", if (snapshot.terminal_error) |err| try text(@errorName(err)) else try js.env().getNull());
    try put(object, "resolvedCapacities", try @import("network_js.zig").scalarFields(js.env(), &snapshot.resolvedCapacities));
    try put(object, "payloadBudget", try @import("network_js.zig").scalarFields(js.env(), &snapshot.payloadBudget));
    try put(object, "publications", try @import("network_js.zig").scalarFields(js.env(), &snapshot.publications));
    try put(object, "requests", try request_js.diagnostics(js.env(), &snapshot.requests));
    try put(object, "gossip", try gossip_js.diagnostics(js.env(), &snapshot.gossip));
    try put(object, "incoming", try incoming_js.diagnostics(js.env(), &snapshot.incoming));
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
        .getIdentity, .getPeers, .getDirectPeers => {},
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
    operation.deferred = try env.createPromise();
    errdefer if (operation.deferred) |deferred| @import("network_js.zig").discardPromise(env, deferred);
    const result = if (operation.deferred) |deferred| deferred.getPromise() else try env.getUndefined();
    try runtime.queueCommand(token);
    runtime.notify.ref(env) catch {};
    return .{ .val = result };
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
pub fn reportPeer(self: *@This(), peer: js.Value, action: js.Value) !js.Value {
    const runtime = try self.owner();
    const reported_peer = try cfg.peerIdFrom(peer.val);
    var buffer: [32]u8 = undefined;
    const length = try application_cfg.text(action.val, &buffer);
    const parsed = std.meta.stringToEnum(n.peers.types.PeerAction, buffer[0..length]) orelse return error.InvalidNetworkConfig;
    const result = try js.env().getUndefined();
    runtime.lock();
    defer runtime.unlock();
    if (!runtime.stop and !runtime.quiescent) {
        runtime.reports.add(&reported_peer, parsed);
        runtime.signalLocked();
    }
    return .{ .val = result };
}

fn settleOperations(env: napi.Env, runtime: *Runtime, limit: usize) !bool {
    var settled: usize = 0;
    for (0..commands.capacity) |_| {
        runtime.lock();
        const i = runtime.table.nextTerminal(runtime.table.settle_cursor) orelse runtime.table.nextTerminal(0) orelse {
            runtime.unlock();
            return false;
        };
        if (settled == limit) {
            runtime.unlock();
            return true;
        }
        settled += 1;
        runtime.bridge.deliver(.completion, 1);
        runtime.table.settle_cursor = i + 1;
        const cell = &runtime.table.cells[i];
        runtime.table.transition(cell, .copying);
        const token: commands.Token = .{ .index = @intCast(i), .generation = cell.generation };
        runtime.unlock();
        defer runtime.abortCommand(token);
        const operation = &runtime.table.cells[i];
        if (operation.deferred) |deferred| {
            if (operation.failure) |err| {
                try deferred.reject(@import("network_js.zig").settled(env, makeError(env, err)) catch try runtime.copy_error.?.getValue());
            } else {
                const value = copyOperation(env, runtime, i) catch {
                    try deferred.reject(try runtime.copy_error.?.getValue());
                    continue;
                };
                try deferred.resolve(value);
            }
        }
    }
    return false;
}
fn copyOperation(env: napi.Env, runtime: *Runtime, index: usize) !Value {
    const operation = &runtime.table.cells[index];
    const store = runtime.table.cells[index].store;
    const object = switch (operation.input.command) {
        .getGossipDiagnostics => try @import("network_gossip_diagnostics.zig").copy(env, &runtime.stores.?.gossip_diagnostics[store.?]),
        .getIdentity => try identity(env, &operation.identity),
        .applyIntent, .getPeers, .getDirectPeers => try env.createObject(),
        .removeDirectPeer => return env.getBoolean(operation.boolean),
        else => return env.getUndefined(),
    };
    try put(object, "ownerSequence", try env.createBigintUint64(operation.sequence));
    switch (operation.input.command) {
        .applyIntent => {
            try put(object, "changed", try env.getBoolean(operation.boolean));
            try put(object, "slot", try env.createBigintUint64(operation.input.slot));
        },
        .getPeers => {
            const peers = try env.createArrayWithLength(operation.count);
            for (runtime.stores.?.snapshots[store.?][0..operation.count], 0..) |*row, i| try element(peers, i, try projection.state(env, row));
            try put(object, "peers", peers);
            try put(object, "occupiedCount", try env.createDouble(@floatFromInt(operation.count)));
            try put(object, "capacity", try env.createUint32(runtime.peer_capacity));
            const counts = try env.createObject();
            try put(counts, "connected", try env.createUint32(operation.counts.connected));
            try put(counts, "relevant", try env.createUint32(operation.counts.relevant));
            try put(counts, "outboundRelevant", try env.createUint32(operation.counts.outbound_relevant));
            try put(object, "counts", counts);
        },
        .getDirectPeers => {
            const identities = try env.createArrayWithLength(operation.count);
            for (runtime.stores.?.direct[store.?][0..operation.count], 0..) |*peer, i| try element(identities, i, try @import("network_js.zig").peerIdValue(env, peer));
            try put(object, "identities", identities);
        },
        else => {},
    }
    return object;
}
pub fn requestStart(self: *@This(), peer: js.Value, protocol: js.Value, data: js.Value, options: js.Value) !js.Value {
    const call = r.call(self.runtime, .request_start);
    defer call.end();
    return .{ .val = try request_js.start(try self.owner(), peer.val, protocol.val, data.val, options.val) };
}
pub fn requestPull(self: *@This(), handle: js.Value) !js.Value {
    const call = r.call(self.runtime, .request_pull);
    defer call.end();
    return .{ .val = try request_js.pull(try self.owner(), handle.val) };
}
pub fn requestRetire(self: *@This(), handle: js.Value, abandoned: js.Value) !js.Value {
    const call = r.call(self.runtime, .request_retire);
    defer call.end();
    return .{ .val = try request_js.retire(try self.owner(), handle.val, try cfg.boolean(abandoned.val)) };
}

pub fn incomingRespond(self: *@This(), handle: js.Value, data: js.Value, context: js.Value) !js.Value {
    const call = r.call(self.runtime, .incoming_respond);
    defer call.end();
    return .{ .val = try incoming_js.respond(try self.owner(), handle.val, data.val, context.val) };
}
pub fn incomingRelease(self: *@This(), handle: js.Value) !js.Value {
    const call = r.call(self.runtime, .incoming_release);
    defer call.end();
    return .{ .val = try incoming_js.release(try self.owner(), handle.val) };
}
pub fn incomingReady(self: *@This(), handle: js.Value) !js.Value {
    const call = r.call(self.runtime, .incoming_ready);
    defer call.end();
    return .{ .val = try incoming_js.ready(try self.owner(), handle.val) };
}
pub fn incomingTerminal(self: *@This(), handle: js.Value, action: js.Value, status: js.Value, message: js.Value) !js.Value {
    const call = r.call(self.runtime, .incoming_terminal);
    defer call.end();
    return .{ .val = try incoming_js.terminal(try self.owner(), handle.val, action.val, status.val, message.val) };
}

pub fn reportGossip(self: *@This(), handle: js.Value, verdict: js.Value) !js.Value {
    const call = r.call(self.runtime, .report_gossip);
    defer call.end();
    return .{ .val = try gossip_js.report(try self.owner(), handle.val, verdict.val) };
}
pub fn publishGossip(self: *@This(), topic: js.Value, data: js.Value, options: js.Value) !js.Value {
    const call = r.call(self.runtime, .publish_gossip);
    defer call.end();
    return .{ .val = try publication_js.publish(try self.owner(), topic.val, data.val, options.val) };
}

pub fn classifyGossip(self: *@This(), values: js.Value) !js.Value {
    const call = r.call(self.runtime, .classify_gossip);
    defer call.end();
    return .{ .val = try gossip_js.classify(try self.owner(), values.val) };
}
pub fn notifyGossipBlock(self: *@This(), root: js.Value) !js.Value {
    return .{ .val = try gossip_js.notifyBlock(try self.owner(), root.val) };
}
pub fn dropQueuedGossip(self: *@This()) !js.Value {
    return .{ .val = try gossip_js.dropQueued(try self.owner()) };
}

pub fn trackGossipSearch(self: *@This(), root: js.Value, peer: js.Value) !js.Value {
    return .{ .val = try gossip_js.trackSearch(try self.owner(), root.val, peer.val) };
}
