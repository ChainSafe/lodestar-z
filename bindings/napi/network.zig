const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const cfg = @import("network_config.zig");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const faults = @import("network_faults.zig");
const Value = napi.Value;
const requests = @import("network_requests.zig");
const gossip = @import("network_gossip.zig");
const gossip_js = @import("network_gossip_js.zig");
const incoming = @import("network_incoming.zig");
const incoming_js = @import("network_incoming_js.zig");
const request_js = @import("network_request_js.zig");

pub const js_meta = js.class(.{});

runtime: ?*Runtime = null,
started: bool = false,
stopped: bool = false,

pub fn init() @This() {
    return .{};
}

pub fn prepare(self: *@This(), config: js.Value, callback: js.Value) !js.Value {
    if (self.started) return error.NetworkAlreadyStarted;
    self.started = true;
    if (self.stopped) return error.NetworkClosed;
    if (try callback.val.typeof() != .function) return error.InvalidNetworkConfig;
    const session = try r.reserve();
    errdefer r.unreserve();
    try faults.check(.runtime_alloc);
    const runtime = try r.allocator.create(Runtime);
    faults.count(&faults.runtimes, true);
    runtime.* = .{ .env = js.env(), .diag = .{ .session = session, .currentSlot = 0 } };
    if (comptime faults.enabled) runtime.test_scenario = faults.takeScenario();
    errdefer runtime.release();
    errdefer runtime.disposeJsReferences();
    try faults.check(.owner_alloc);
    runtime.heavy = try r.allocator.create(r.Owner);
    runtime.heavy.?.* = .{};
    try application_cfg.parse(config.val, &runtime.heavy.?.config, &runtime.heavy.?.application);
    if (self.stopped) return error.NetworkClosed;
    try prepareApplicationStorage(runtime, &runtime.heavy.?.application);
    runtime.slot = runtime.heavy.?.config.slot;
    runtime.diag.currentSlot = runtime.slot;
    try faults.check(.wake);
    runtime.wake = try @import("network_wake.zig").Wake.init();
    errdefer if (runtime.wake) |*wake| wake.deinit();
    const name = try js.env().createStringUtf8("NativeNetworkRuntime");
    try faults.check(.notify);
    runtime.notify = try r.Notify.create(js.env(), callback.val, null, name, 1, 1, runtime, Runtime.finalize, onNotify);
    faults.count(&faults.notifications, true);
    runtime.retain();
    errdefer runtime.notify.release(.abort) catch unreachable;
    try faults.check(.hook);
    try js.env().addEnvCleanupHook(Runtime, runtime, Runtime.cleanup);
    runtime.hook_live = true;
    runtime.retain();
    errdefer runtime.removeHook();
    runtime.retain();
    errdefer runtime.release();
    const env = js.env();
    try faults.check(.ready_promise);
    runtime.ready_deferred = try env.createPromise();
    errdefer runtime.ready_deferred.?.resolve(env.getUndefined() catch unreachable) catch unreachable;
    try faults.check(.close_promise);
    runtime.close_deferred = try env.createPromise();
    errdefer runtime.close_deferred.?.resolve(env.getUndefined() catch unreachable) catch unreachable;
    try prepareCloseResults(env, runtime);
    try faults.check(.promise_holder);
    const holder = try env.createObject();
    try put(holder, "ready", runtime.ready_deferred.?.getPromise());
    try put(holder, "closed", runtime.close_deferred.?.getPromise());
    try @import("network_owner.zig").initialize(runtime);
    try faults.check(.spawn);
    faults.count(&faults.owners, true);
    errdefer faults.count(&faults.owners, false);
    runtime.thread = try std.Thread.spawn(.{ .stack_size = std.Thread.SpawnConfig.default_stack_size }, @import("network_owner.zig").run, .{runtime});
    self.runtime = runtime;
    return .{ .val = holder };
}

fn prepareApplicationStorage(runtime: *Runtime, app: *const application_cfg.Config) !void {
    runtime.peer_capacity = app.resources.peerCapacity;
    runtime.max_peers = app.resources.maxPeers;
    const resolved = try n.configuration.resolve(try app.buildRequest(&runtime.heavy.?.config, 1));
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
        .admissionIdentityCapacity = resolved.core.service.reqresp.admission.?.limits.identities,
        .gossipConnectedCapacity = resolved.core.service.gossipsub.connected_capacity,
        .gossipRetainedCapacity = resolved.core.service.gossipsub.retained_capacity,
        .dialEngineCapacity = resolved.limits.dialing_max,
    };
    const limits = resolved.core.service.reqresp;
    const request_capacity: usize = @min(32, limits.outbound_max - limits.outbound_control_reserved);
    const incoming_capacity: usize = @min(32, limits.inbound_max - limits.inbound_control_reserved);
    const gossip_capacity: usize = @min(1024, resolved.core.service.gossipsub.validation_capacity);
    const bridge = gossip_capacity * @sizeOf(gossip.Cell) + incoming_capacity * @sizeOf(incoming.Cell) + request_capacity * @sizeOf(requests.Cell) + @sizeOf(Runtime) + @sizeOf(r.Owner) - @sizeOf(n.NetworkCore) + r.Stores.bytes(runtime.peer_capacity) + @sizeOf(projection.Lane);
    if (bridge > app.resources.bridgeBudgetBytes) return error.NetworkBridgeBudgetExceeded;
    runtime.requests = try requests.Table.init(r.allocator, request_capacity, &runtime.payload_budget);
    runtime.payload_budget.limit = app.resources.bridgeBudgetBytes - bridge;
    try faults.check(.incoming_table);
    runtime.incoming = try incoming.Table.init(r.allocator, incoming_capacity, &runtime.payload_budget);
    try faults.check(.gossip_table);
    runtime.gossip = try gossip.Table.init(r.allocator, gossip_capacity, &runtime.payload_budget);
    runtime.stores = try r.Stores.create(r.allocator, runtime.peer_capacity);
    try faults.check(.application_lane);
    runtime.lane = try r.allocator.create(projection.Lane);
    runtime.lane.?.* = .{};
    runtime.diag.bridgeRequestedBytes = bridge;
}

fn prepareCloseResults(env: napi.Env, runtime: *Runtime) !void {
    const fallback = try env.createObject();
    try put(fallback, "name", try env.createStringUtf8("Error"));
    try put(fallback, "code", try env.createStringUtf8("NetworkResultAllocationFailed"));
    try put(fallback, "message", try env.createStringUtf8("NetworkResultAllocationFailed"));
    try faults.check(.copy_error_ref);
    runtime.copy_error = try napi.Ref.create(env.env, fallback, 1);
    inline for (.{ "requested", "startupCancelled", "failed" }, 0..) |reason, i| {
        const result = try env.createObject();
        try put(result, "reason", try env.createStringUtf8(reason));
        try faults.check(([_]faults.Stage{ .requested_ref, .cancelled_ref, .failed_ref })[i]);
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
    runtime.lock();
    runtime.notification_pending = false;
    const alive = runtime.env_alive;
    const startup = runtime.startup;
    const startup_error = runtime.startup_error;
    const session = runtime.diag.session;
    var ready_identity: r.Identity = undefined;
    if (startup == .ready) ready_identity = runtime.identity;
    runtime.unlock();
    if (!alive) return;
    if (!runtime.ready_settled and startup != .pending) {
        runtime.ready_settled = true;
        if (startup == .ready) {
            const copied = copyStartup(env, &ready_identity, session) catch |err| {
                rejectReady(env, runtime, err);
                runtime.failDelivery();
                settleOperations(env, runtime);
                settleClose(env, runtime);
                return;
            };
            runtime.ready_deferred.?.resolve(copied) catch unreachable;
        } else rejectReady(env, runtime, startup_error.?);
    }
    settleOperations(env, runtime);
    request_js.settle(env, runtime);
    incoming_js.settle(env, runtime);
    runtime.lock();
    const idle = runtime.table.occupied == 0 and !runtime.requestObligations() and runtime.notify_live and !runtime.stop;
    runtime.unlock();
    if (idle) runtime.notify.unref(env) catch {};
    settleClose(env, runtime);
    runtime.lock();
    const readable = !runtime.disposed and !runtime.quiescent and ((runtime.lane != null and runtime.lane.?.len > 0) or (runtime.incoming != null and runtime.incoming.?.oldest() != null) or (runtime.gossip != null and runtime.gossip.?.oldest() != null));
    runtime.unlock();
    if (readable) _ = env.callFunction(callback, env.getUndefined() catch return, .{}) catch return;
}
fn makeError(env: napi.Env, err: anyerror) !Value {
    const name = try env.createStringUtf8(@errorName(err));
    return env.createError(name, name);
}
fn rejectReady(env: napi.Env, runtime: *Runtime, err: anyerror) void {
    const value = makeError(env, err) catch runtime.copy_error.?.getValue() catch unreachable;
    runtime.ready_deferred.?.reject(value) catch unreachable;
}
fn copyStartup(env: napi.Env, value: *const r.Identity, session: u64) !Value {
    try faults.check(.startup_copy);
    return identity(env, value, session);
}
fn settleClose(env: napi.Env, runtime: *Runtime) void {
    runtime.lock();
    const done = runtime.quiescent;
    runtime.unlock();
    if (!done or runtime.close_settled) return;
    runtime.join();
    // The owner can quiesce after this callback's earlier result drains.
    settleOperations(env, runtime);
    request_js.settle(env, runtime);
    incoming_js.settle(env, runtime);
    runtime.lock();
    const reason = runtime.reason;
    runtime.unlock();
    runtime.removeHook();
    const value = copyClose(runtime, reason) catch copyClose(runtime, reason) catch runtime.close_results[2].?.getValue() catch unreachable;
    runtime.close_settled = true;
    runtime.close_deferred.?.resolve(value) catch unreachable;
}
fn copyClose(runtime: *Runtime, reason: r.Reason) !Value {
    try faults.check(.close_copy);
    return runtime.close_results[@intFromEnum(reason)].?.getValue();
}

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
fn identity(env: napi.Env, value: *const r.Identity, session: u64) !Value {
    try faults.check(.identity_copy);
    const object = try env.createObject();
    try put(object, "session", try env.createBigintUint64(session));
    try put(object, "peerId", try bytes(env, &value.peer.bytes));
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
    const metrics = @import("network").metrics;
    const runtime = try self.owner();
    const snapshot = runtime.metricsSnapshot();
    const logs = runtime.logs.snapshot();
    const buffer = try r.allocator.alloc(u8, metrics.text_capacity);
    defer r.allocator.free(buffer);
    var writer: std.Io.Writer = .fixed(buffer);
    metrics.write(&snapshot, &logs, &writer) catch |err| switch (err) {
        error.WriteFailed, error.MetricCapacity => return error.NetworkMetricsCapacity,
        error.DuplicateMetric => return error.NetworkMetricsSchema,
    };
    return js.String.from(writer.buffered());
}

pub fn drainLogs(self: *@This(), limit: js.Value) !js.Value {
    return @import("network_logs.zig").drain(try self.owner(), limit.val);
}

pub fn setLogLevel(self: *@This(), level: js.Value) !void {
    try @import("network_logs.zig").configure(try self.owner(), level.val);
}

pub fn diagnostics(self: *@This()) !js.Value {
    const snapshot = (try self.owner()).snapshot();
    const object = try @import("network_js.zig").scalarFields(js.env(), &snapshot);
    try put(object, "state", try text(@tagName(snapshot.state)));
    try put(object, "terminalErrorCode", if (snapshot.terminal_error) |err| try text(@errorName(err)) else try js.env().getNull());
    try put(object, "resolvedCapacities", try @import("network_js.zig").scalarFields(js.env(), &snapshot.resolvedCapacities));
    try put(object, "requests", try request_js.diagnostics(js.env(), &snapshot.requests));
    try put(object, "gossip", try gossip_js.diagnostics(js.env(), &snapshot.gossip));
    try put(object, "incoming", try incoming_js.diagnostics(js.env(), &snapshot.incoming));
    return .{ .val = object };
}
const commands = @import("network_commands.zig");
const application_cfg = @import("network_application_config.zig");
const projection = @import("network_peer_projection.zig");
const n = @import("network");

fn peerId(value: Value) !n.PeerId {
    const encoded = try cfg.fixed(n.wire.peer_id.length, value);
    return n.PeerId.fromBytes(&encoded);
}
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
                peer.* = try peerId(try args[0].getElement(@intCast(i)));
                for (runtime.stores.?.targets[store.?][0..i]) |*prior| if (peer.eql(prior)) return error.InvalidNetworkConfig;
            }
        },
        else => {
            operation.input.peer = try peerId(args[0]);
            if (command == .connect or command == .addDirectPeer) try parseAddresses(args[1], &operation.input);
            if (command == .connect) {
                operation.input.timeout_ms = try cfg.bigint(args[2]);
                if (operation.input.timeout_ms == 0 or operation.input.timeout_ms > 60_000) return error.InvalidNetworkInteger;
            }
        },
    }
    const env = js.env();
    operation.deferred = try env.createPromise();
    errdefer if (operation.deferred) |deferred| deferred.resolve(env.getUndefined() catch unreachable) catch unreachable;
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
    const reported_peer = try peerId(peer.val);
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

fn settleOperations(env: napi.Env, runtime: *Runtime) void {
    for (0..32) |i| {
        runtime.lock();
        const cell = &runtime.table.cells[i];
        if (cell.state != .terminal) {
            runtime.unlock();
            continue;
        }
        cell.state = .copying;
        const token: commands.Token = .{ .index = @intCast(i), .generation = cell.generation };
        runtime.unlock();
        const operation = &runtime.table.cells[i];
        if (operation.deferred) |deferred| {
            if (operation.failure) |err| {
                deferred.reject((if (operation.input.command == .publishGossip) gossip_js.publishError(env, err) else makeError(env, err)) catch runtime.copy_error.?.getValue() catch unreachable) catch unreachable;
            } else {
                const value = copyOperation(env, runtime, i) catch {
                    deferred.reject(runtime.copy_error.?.getValue() catch unreachable) catch unreachable;
                    runtime.failDelivery();
                    runtime.abortCommand(token);
                    continue;
                };
                deferred.resolve(value) catch unreachable;
            }
        }
        runtime.abortCommand(token);
    }
}
fn copyOperation(env: napi.Env, runtime: *Runtime, index: usize) !Value {
    try faults.check(.operation_copy);
    const operation = &runtime.table.cells[index];
    const store = runtime.table.cells[index].store;
    const object = switch (operation.input.command) {
        .publishGossip => return gossip_js.publishResult(env, operation.publication),
        .getGossipDiagnostics => try @import("network_gossip_diagnostics.zig").copy(env, &runtime.stores.?.gossip_diagnostics[store.?]),
        .getIdentity => try identity(env, &operation.identity, runtime.diag.session),
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
            for (runtime.stores.?.snapshots[store.?][0..operation.count], 0..) |*row, i| try element(peers, i, try projection.state(env, row, runtime.diag.session));
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
            for (runtime.stores.?.direct[store.?][0..operation.count], 0..) |*peer, i| try element(identities, i, try bytes(env, &peer.bytes));
            try put(object, "identities", identities);
        },
        else => {},
    }
    return object;
}
pub fn drainPeers(self: *@This(), limit: js.Value) !js.Value {
    const max = cfg.integer(limit.val, 64) catch return error.InvalidDrainLimit;
    if (max == 0) return error.InvalidDrainLimit;
    const runtime = try self.owner();
    runtime.retain();
    defer runtime.release();
    var events: [64]projection.Entry = undefined;
    runtime.lock();
    const lane = runtime.lane;
    const count = if (lane) |storage| storage.peek(events[0..@intCast(max)]) else 0;
    const sequence = runtime.table.sequence;
    const more = if (lane) |storage| storage.len > count else false;
    runtime.unlock();
    const env = js.env();
    const array = try env.createArrayWithLength(count);
    for (events[0..count], 0..) |*event, i| try element(array, i, try projection.observation(env, event, runtime.diag.session));
    const object = try env.createObject();
    try put(object, "events", array);
    try put(object, "ownerSequence", try env.createBigintUint64(sequence));
    try put(object, "more", try env.getBoolean(more));
    try put(object, "updatesReplaceState", try env.getBoolean(true));
    try faults.check(.drain_copy);
    runtime.lock();
    if (lane) |storage| {
        storage.commit(count);
        if (!more and storage.len > 0 and !runtime.quiescent) runtime.readable_rearm = true;
        if (!runtime.quiescent) runtime.signalLocked();
    }
    runtime.unlock();
    return .{ .val = object };
}

pub fn requestStart(self: *@This(), peer: js.Value, protocol: js.Value, data: js.Value, options: js.Value) !js.Value {
    return .{ .val = try request_js.start(try self.owner(), peer.val, protocol.val, data.val, options.val) };
}
pub fn requestPull(self: *@This(), handle: js.Value) !js.Value {
    return .{ .val = try request_js.pull(try self.owner(), handle.val) };
}
pub fn requestRetire(self: *@This(), handle: js.Value, abandoned: js.Value) !js.Value {
    return .{ .val = try request_js.retire(try self.owner(), handle.val, try cfg.boolean(abandoned.val)) };
}

pub fn takeIncomingRequest(self: *@This()) !js.Value {
    return .{ .val = try incoming_js.take(try self.owner()) };
}
pub fn incomingRespond(self: *@This(), handle: js.Value, data: js.Value, context: js.Value) !js.Value {
    return .{ .val = try incoming_js.respond(try self.owner(), handle.val, data.val, context.val) };
}
pub fn incomingTerminal(self: *@This(), handle: js.Value, action: js.Value, status: js.Value, message: js.Value) !js.Value {
    return .{ .val = try incoming_js.terminal(try self.owner(), handle.val, action.val, status.val, message.val) };
}

pub fn drainGossip(self: *@This()) !js.Value {
    return .{ .val = try gossip_js.drain(try self.owner()) };
}
pub fn reportGossip(self: *@This(), handle: js.Value, verdict: js.Value) !js.Value {
    return .{ .val = try gossip_js.report(try self.owner(), handle.val, verdict.val) };
}
pub fn publishGossip(self: *@This(), topic: js.Value, data: js.Value, options: js.Value) !js.Value {
    return .{ .val = try gossip_js.publish(try self.owner(), topic.val, data.val, options.val) };
}
