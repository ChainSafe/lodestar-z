const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const cfg = @import("network_config.zig");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const faults = @import("network_faults.zig");
const Value = napi.Value;

pub const js_meta = js.class(.{});

runtime: ?*Runtime = null,
started: bool = false,
stopped: bool = false,

pub fn init() @This() {
    return .{};
}

pub fn start(self: *@This(), config: js.Value, callback: js.Value) !js.Value {
    return self.acquire(config, callback, false);
}
pub fn prepare(self: *@This(), config: js.Value, callback: js.Value) !js.Value {
    return self.acquire(config, callback, true);
}
fn acquire(self: *@This(), config: js.Value, callback: js.Value, application: bool) !js.Value {
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
    if (application) {
        runtime.heavy.?.application = undefined;
        try @import("network_application_config.zig").parse(config.val, &runtime.heavy.?.config, &runtime.heavy.?.application.?);
    } else try cfg.parse(config.val, &runtime.heavy.?.config);
    if (self.stopped) return error.NetworkClosed;
    runtime.application = application;
    if (runtime.heavy.?.application) |*app| try prepareApplicationStorage(runtime, app);
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
    if (application) try runtime.initializeOwner();
    try faults.check(.spawn);
    faults.count(&faults.owners, true);
    errdefer faults.count(&faults.owners, false);
    runtime.thread = try std.Thread.spawn(.{ .stack_size = std.Thread.SpawnConfig.default_stack_size }, Runtime.run, .{runtime});
    self.runtime = runtime;
    return .{ .val = holder };
}

fn prepareApplicationStorage(runtime: *Runtime, app: *const application_cfg.Config) !void {
    runtime.peer_capacity = app.resources.peerCapacity;
    runtime.max_peers = app.resources.maxPeers;
    const bridge = @sizeOf(Runtime) + @sizeOf(r.Owner) - @sizeOf(n.NetworkCore) + r.Stores.bytes(runtime.peer_capacity) + @sizeOf(projection.Lane);
    if (bridge > app.resources.bridgeBudgetBytes) return error.NetworkBridgeBudgetExceeded;
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
        runtime.release();
        self.runtime = null;
    }
}

fn onNotify(env: napi.Env, callback: Value, runtime: *Runtime, _: *void) void {
    runtime.lock();
    runtime.notification_pending = false;
    const alive = runtime.env_alive;
    const unref_notify = alive and runtime.notify_live and !runtime.stop and runtime.startup == .ready and runtime.table.occupied == 0;
    const startup = runtime.startup;
    const startup_error = runtime.startup_error;
    const session = runtime.diag.session;
    var ready_identity: r.Identity = undefined;
    if (startup == .ready) ready_identity = runtime.identity;
    runtime.unlock();
    if (!alive) return;
    if (unref_notify) runtime.notify.unref(env) catch {};
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
    runtime.lock();
    const idle = runtime.table.occupied == 0 and runtime.notify_live and !runtime.stop;
    runtime.unlock();
    if (idle) runtime.notify.unref(env) catch {};
    settleClose(env, runtime);
    runtime.lock();
    const readable = !runtime.disposed and !runtime.quiescent and (runtime.queue.len > 0 or (runtime.lane != null and runtime.lane.?.len > 0));
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
fn settleClose(_: napi.Env, runtime: *Runtime) void {
    runtime.lock();
    const done = runtime.quiescent;
    const reason = runtime.reason;
    runtime.unlock();
    if (!done or runtime.close_settled) return;
    runtime.join();
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
    const state = (try self.owner()).snapshot().state;
    return .{ .val = try js.env().createStringUtf8(@tagName(state)) };
}
pub fn setCurrentSlot(self: *@This(), value: js.Value) !js.Value {
    const slot = try cfg.bigint(value.val);
    const revision = try (try self.owner()).setSlot(slot);
    return .{ .val = try js.env().createBigintUint64(revision) };
}
pub fn close(self: *@This()) void {
    self.stopped = true;
    if (self.runtime) |runtime| {
        runtime.lock();
        const ref_notify = runtime.env_alive and runtime.notify_live;
        runtime.unlock();
        if (ref_notify) runtime.notify.ref(runtime.env) catch {};
        runtime.lock();
        runtime.graceful = runtime.application and !runtime.disposed;
        runtime.unlock();
        runtime.requestStop();
    }
}

fn put(object: Value, name: [:0]const u8, value: Value) !void {
    try object.defineProperties(&.{.{
        .utf8name = name.ptr,
        .name = null,
        .method = null,
        .getter = null,
        .setter = null,
        .value = value.value,
        .attributes = napi.c.napi_default_jsproperty,
        .data = null,
    }});
}
fn text(value: []const u8) !Value {
    return js.env().createStringUtf8(value);
}
fn bytes(env: napi.Env, value: []const u8) !Value {
    const buffer = try env.createArrayBufferCopy(value, null);
    return env.createTypedarray(.uint8, value.len, buffer, 0);
}
fn endpoint(env: napi.Env, value: @import("network").Address) !Value {
    const object = try env.createObject();
    switch (value) {
        .ip4 => |ip| {
            try put(object, "family", try env.createUint32(4));
            try put(object, "address", try bytes(env, &ip.octets));
            try put(object, "port", try env.createUint32(ip.port));
        },
        .ip6 => |ip| {
            try put(object, "family", try env.createUint32(6));
            try put(object, "address", try bytes(env, &ip.octets));
            try put(object, "port", try env.createUint32(ip.port));
        },
    }
    return object;
}
fn identity(env: napi.Env, value: *const r.Identity, session: u64) !Value {
    try faults.check(.identity_copy);
    const object = try env.createObject();
    try put(object, "session", try env.createBigintUint64(session));
    try put(object, "peerId", try bytes(env, &value.peer.bytes));
    try put(object, "localEndpoint", try endpoint(env, value.endpoint));
    try put(object, "localMultiaddr", try bytes(env, value.multiaddr[0..value.multiaddr_len]));
    try put(object, "localEnr", if (value.enr_len == 0) try env.getNull() else try bytes(env, value.enr[0..value.enr_len]));
    return object;
}

pub fn diagnostics(self: *@This()) !js.Value {
    const snapshot = (try self.owner()).snapshot();
    const object = try js.env().createObject();
    try put(object, "state", try text(@tagName(snapshot.state)));
    try put(object, "terminalErrorCode", if (snapshot.terminal_error) |err| try text(@errorName(err)) else try js.env().getNull());
    inline for (.{ "session", "currentSlot", "clockRevision", "ownerTurns", "lastMonotonicMs", "observationsDropped", "operationalFailures" }) |name| {
        try put(object, name, try js.env().createBigintUint64(@field(snapshot, name)));
    }
    inline for (.{ "peerCount", "readyPeerCount", "queuedEvents", "queueCapacity", "queueHighWater", "nativeRequestedBytes", "bridgeRequestedBytes" }) |name| {
        try put(object, name, try js.env().createDouble(@floatFromInt(@field(snapshot, name))));
    }
    inline for (.{ "operationRefusals", "ownerSequence", "connectRefusals", "intentRefusals", "snapshotRefusals", "targetListRefusals" }) |name| try put(object, name, try js.env().createBigintUint64(@field(snapshot, name)));
    inline for (.{ "operationCapacity", "operationOccupied", "operationHighWater", "connectCapacity", "connectOccupied", "intentCapacity", "intentOccupied", "snapshotCapacity", "snapshotOccupied", "targetListCapacity", "targetListOccupied", "preparingPins", "copyingPins", "peerLaneCapacity", "peerLaneOccupied", "peerLaneHighWater", "liveNativeRequestedBytes", "liveBridgeRequestedBytes", "operationBytes", "typedStoreBytes", "peerLaneBytes", "ownerShellBytes", "ownerAllocationBytes", "nativeAllocationCount", "connectHighWater", "intentHighWater", "snapshotHighWater", "targetListHighWater" }) |name| try put(object, name, try js.env().createDouble(@floatFromInt(@field(snapshot, name))));
    const resolved = try js.env().createObject();
    inline for (@typeInfo(r.ResolvedCapacities).@"struct".fields) |field| try put(resolved, field.name, try js.env().createUint32(@field(snapshot.resolvedCapacities, field.name)));
    try put(object, "resolvedCapacities", resolved);
    return .{ .val = object };
}
fn diagnosticPeer(object: Value, value: r.Observation.Peer) !void {
    try put(object, "peerIndex", try js.env().createUint32(value.index));
    try put(object, "peerGeneration", try js.env().createBigintUint64(value.generation));
    try put(object, "peerId", try bytes(js.env(), &value.identity.bytes));
}
fn observation(value: r.Observation) !Value {
    const object = try js.env().createObject();
    try put(object, "type", try text(@tagName(value)));
    switch (value) {
        .peerReady, .peerUpdated => |p| try diagnosticPeer(object, p),
        .peerClosed => |closed| {
            try diagnosticPeer(object, closed.peer);
            try put(object, "reason", try text(@tagName(closed.reason)));
        },
        .operationalError => |err| {
            try put(object, "code", try text(@errorName(err.code)));
            try put(object, "count", try js.env().createBigintUint64(err.count));
        },
    }
    return object;
}
pub fn drain(self: *@This(), limit: js.Value) !js.Value {
    const max = cfg.integer(limit.val, 32) catch return error.InvalidDrainLimit;
    if (max == 0) return error.InvalidDrainLimit;
    const runtime = try self.owner();
    var events: [32]r.Observation = undefined;
    runtime.lock();
    const count = runtime.queue.peek(events[0..@intCast(max)]);
    const dropped = runtime.queue.dropped;
    runtime.unlock();
    const array = try js.env().createArrayWithLength(count);
    for (events[0..count], 0..) |event, i| {
        var key: [11]u8 = undefined;
        try put(array, try std.fmt.bufPrintZ(&key, "{d}", .{i}), try observation(event));
    }
    try faults.check(.drain_copy);
    const object = try js.env().createObject();
    try put(object, "events", array);
    try put(object, "dropped", try js.env().createBigintUint64(dropped));
    runtime.lock();
    const more = runtime.queue.len > count or runtime.queue.pending_error != null;
    runtime.unlock();
    try faults.publishDuringDrain(runtime);
    try put(object, "more", try js.env().getBoolean(more));
    runtime.commitDrain(count, more);
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
    const operation = &runtime.operations[token.index];
    const store = runtime.table.cells[token.index].store;
    switch (command) {
        .applyIntent => {
            operation.input.slot = try cfg.bigint(args[1]);
            try application_cfg.parseIntent(args[0], &runtime.stores.?.intents[store.?], runtime.max_peers);
        },
        .getIdentity, .getPeers, .getDirectPeers => {},
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
            if (command == .reportPeer) {
                var buffer: [32]u8 = undefined;
                const len = try application_cfg.text(args[1], &buffer);
                operation.input.action = std.meta.stringToEnum(n.peers.types.PeerAction, buffer[0..len]) orelse return error.InvalidNetworkConfig;
            }
        },
    }
    const env = js.env();
    if (command != .reportPeer) operation.deferred = try env.createPromise();
    errdefer if (operation.deferred) |deferred| deferred.resolve(env.getUndefined() catch unreachable) catch unreachable;
    const result = if (operation.deferred) |deferred| deferred.getPromise() else try env.getUndefined();
    try runtime.queueCommand(token);
    runtime.notify.ref(env) catch {};
    return .{ .val = result };
}
pub fn applyIntent(self: *@This(), intent: js.Value, slot: js.Value) !js.Value {
    return self.submit(.applyIntent, &.{ intent.val, slot.val });
}
pub fn getIdentity(self: *@This()) !js.Value {
    return self.submit(.getIdentity, &.{});
}
pub fn getPeers(self: *@This()) !js.Value {
    return self.submit(.getPeers, &.{});
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
    return self.submit(.reportPeer, &.{ peer.val, action.val });
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
        const operation = &runtime.operations[i];
        if (operation.deferred) |deferred| {
            if (operation.failure) |err| {
                deferred.reject(makeError(env, err) catch runtime.copy_error.?.getValue() catch unreachable) catch unreachable;
            } else {
                const value = copyOperation(env, runtime, i) catch {
                    deferred.reject(runtime.copy_error.?.getValue() catch unreachable) catch unreachable;
                    runtime.failDelivery();
                    runtime.abortCommand(token);
                    continue;
                };
                deferred.resolve(value) catch unreachable;
            }
        } else if (operation.failure) |err| {
            runtime.lock();
            runtime.queue.recordFailure(err);
            runtime.diag.operationalFailures +|= 1;
            runtime.unlock();
        }
        runtime.abortCommand(token);
    }
}
fn copyOperation(env: napi.Env, runtime: *Runtime, index: usize) !Value {
    try faults.check(.operation_copy);
    const operation = &runtime.operations[index];
    const store = runtime.table.cells[index].store;
    const object = switch (operation.input.command) {
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
            for (runtime.stores.?.snapshots[store.?][0..operation.count], 0..) |*row, i| try projection.element(peers, i, try projection.state(env, row, runtime.diag.session));
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
            for (runtime.stores.?.direct[store.?][0..operation.count], 0..) |*peer, i| try projection.element(identities, i, try bytes(env, &peer.bytes));
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
    if (!runtime.application) return error.NetworkClosed;
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
    for (events[0..count], 0..) |*event, i| try projection.element(array, i, try projection.observation(env, event, runtime.diag.session));
    const object = try env.createObject();
    try put(object, "events", array);
    try put(object, "ownerSequence", try env.createBigintUint64(sequence));
    try put(object, "more", try env.getBoolean(more));
    try put(object, "updatesReplaceState", try env.getBoolean(true));
    runtime.lock();
    if (lane) |storage| {
        storage.commit(count);
        if (!more and storage.len > 0 and !runtime.quiescent) runtime.observation_rearm = true;
        if (!runtime.quiescent) runtime.signalLocked();
    }
    runtime.unlock();
    return .{ .val = object };
}
