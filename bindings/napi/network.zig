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
    try cfg.parse(config.val, &runtime.config);
    if (self.stopped) return error.NetworkClosed;
    runtime.slot = runtime.config.slot;
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
    try faults.check(.promise_holder);
    const holder = try env.createObject();
    try put(holder, "ready", runtime.ready_deferred.?.getPromise());
    try put(holder, "closed", runtime.close_deferred.?.getPromise());
    try faults.check(.spawn);
    faults.count(&faults.owners, true);
    errdefer faults.count(&faults.owners, false);
    runtime.thread = try std.Thread.spawn(.{ .stack_size = std.Thread.SpawnConfig.default_stack_size }, Runtime.run, .{runtime});
    self.runtime = runtime;
    return .{ .val = holder };
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
    if (alive and runtime.notify_live and !runtime.stop and runtime.startup == .ready) runtime.notify.unref(env) catch {};
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
                settleClose(env, runtime);
                return;
            };
            runtime.ready_deferred.?.resolve(copied) catch unreachable;
        } else rejectReady(env, runtime, startup_error.?);
    }
    settleClose(env, runtime);
    runtime.lock();
    const readable = !runtime.disposed and !runtime.quiescent and runtime.queue.len > 0;
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
        if (runtime.env_alive and runtime.notify_live) runtime.notify.ref(runtime.env) catch {};
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
    return .{ .val = object };
}
fn peer(object: Value, value: r.Observation.Peer) !void {
    try put(object, "peerIndex", try js.env().createUint32(value.index));
    try put(object, "peerGeneration", try js.env().createBigintUint64(value.generation));
    try put(object, "peerId", try bytes(js.env(), &value.identity.bytes));
}
fn observation(value: r.Observation) !Value {
    const object = try js.env().createObject();
    try put(object, "type", try text(@tagName(value)));
    switch (value) {
        .peerReady, .peerUpdated => |p| try peer(object, p),
        .peerClosed => |closed| {
            try peer(object, closed.peer);
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
    try put(object, "more", try js.env().getBoolean(more));
    runtime.lock();
    runtime.queue.commit(count);
    runtime.unlock();
    return .{ .val = object };
}
