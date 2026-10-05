const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const BeaconConfig = @import("BeaconConfig.zig");
const AddonIdentity = @import("zapi_addon_identity");
const napi = zapi.napi;
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const Value = napi.Value;
const decode = @import("network_js_input.zig");
const gossip = @import("network_gossip.zig");
const publication_js = @import("network_publication_js.zig");
const incoming_js = @import("network_incoming_js.zig");
const request_js = @import("network_request_js.zig");
const exchange_mod = @import("network_exchange.zig");
const exchange_js = @import("network_exchange_js.zig");
const command_js = @import("network_command_js.zig");
const fatal = @import("network_fatal.zig");
const network_owner = @import("network_owner.zig");
const network_storage = @import("network_storage.zig");
const network_wake = @import("network_wake.zig");
const network = @import("network");
const network_logs = @import("network_logs.zig");

const commands = @import("network_commands.zig");

const application_cfg = @import("network_application_config.zig");

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
    const beacon_value = try decode.get(config.val, "beaconConfig");
    if (try beacon_value.typeof() != .object) return error.TypeMismatch;
    const beacon_config = try js.convertArg(*const BeaconConfig, AddonIdentity, beacon_value.value, beacon_value.env);
    try application_cfg.parse(config.val, &beacon_config.config_rc.instance.config, &runtime.heavy.?.config, &runtime.heavy.?.application);
    runtime.logs.configure(runtime.heavy.?.application.log_level);
    try network_owner.prepareConfiguration(runtime);
    try network_storage.initialize(runtime, &runtime.heavy.?.application);
    runtime.wake = try network_wake.Wake.init();
    errdefer {
        if (runtime.heavy.?.core_live) runtime.heavy.?.core.setHostWake(null) catch unreachable;
        if (runtime.wake) |*wake| wake.deinit();
        runtime.wake = null;
    }
    try network_owner.initialize(runtime);
    const identity = try runtime.heavy.?.readIdentity();

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
    try holder.setNamedProperty("identity", try command_js.identity(env, &identity));
    try holder.setNamedProperty("limits", try resolvedLimits(env, runtime));
    try holder.setNamedProperty("capacities", try capacities(env, runtime));
    runtime.retain();
    errdefer runtime.release();
    runtime.thread = try std.Thread.spawn(.{ .stack_size = std.Thread.SpawnConfig.default_stack_size }, network_owner.run, .{runtime});
    self.runtime = runtime;
    return .{ .val = holder };
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
    const runtime = try self.owner();
    runtime.retain();
    defer runtime.release();
    if (runtime.in_exchange) return error.NetworkExchangeReentered;
    runtime.in_exchange = true;
    defer runtime.in_exchange = false;
    var actions: [exchange_mod.action_max]exchange_mod.Action = undefined;
    const count = try exchange_js.parseActions(actions_value.val, &actions);
    const demand = try exchange_js.parseDemand(demand_value.val);
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
    _ = try exchange_js.parseAction(action.val);
}

/// Stops the owner at once for a wrapper collected without close. JavaScript still drains every result.
pub fn abandon(self: *@This()) void {
    if (self.runtime) |runtime| runtime.abandon();
}

/// A private control for binding ownership tests: while held, the owner leaves reported verdicts unapplied, so no
/// acknowledgement follows them, though expiry still disposes of them; a release wakes the owner.
pub fn holdVerdicts(self: *@This(), held: js.Value) !void {
    const runtime = try self.owner();
    const value = try decode.boolean(held.val);
    runtime.lock();
    defer runtime.unlock();
    runtime.verdicts_held = value;
    if (!value) runtime.signalLocked();
}

/// A private control for binding ownership tests: while held, the owner starts no admitted command, publication or
/// request, which keep their admission order; a release wakes the owner.
pub fn holdOperations(self: *@This(), held: js.Value) !void {
    const runtime = try self.owner();
    const value = try decode.boolean(held.val);
    runtime.lock();
    defer runtime.unlock();
    runtime.operations_held = value;
    if (!value) runtime.signalLocked();
}

/// Terminates the process at a fatal site JavaScript raises (network_fatal.zig). `reason` is at most 64 printable ASCII
/// bytes.
pub fn fail(_: *@This(), site_value: js.Value, reason_value: js.Value) !void {
    var name: [fatal.name_max]u8 = undefined;
    const site = std.meta.stringToEnum(fatal.Site, name[0..try decode.text(site_value.val, &name)]) orelse return error.InvalidNetworkConfig;
    switch (site) {
        .generated_batch, .completion_contract => {},
        .exchange_build, .exchange_finish => return error.InvalidNetworkConfig,
    }
    var reason: [fatal.detail_max]u8 = undefined;
    fatal.terminate(js.env(), site, reason[0..try decode.text(reason_value.val, &reason)]);
}

const Exchange = exchange_js.Host;

fn owner(self: *@This()) !*Runtime {
    return self.runtime orelse error.NetworkClosed;
}

pub fn getState(self: *@This()) !js.Value {
    const runtime = try self.owner();
    runtime.lock();
    const state = runtime.state;
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

/// The gossip SHA-256 implementation this process selected, for packaged qualification records.
pub fn gossipSha256Backend() js.String {
    return js.String.from(@tagName(network.gossipsub.sha256.backend()));
}

pub fn getMetrics(self: *@This()) !js.Value {
    const runtime = try self.owner();
    const metrics_text = copy: {
        runtime.lock();
        defer runtime.unlock();
        const logs = runtime.logs.snapshot();
        const borrowed = runtime.metrics.text(&logs) catch |err| return switch (err) {
            error.WriteFailed, error.MetricCapacity => error.NetworkMetricsCapacity,
            error.DuplicateMetric => error.NetworkMetricsSchema,
        };
        break :copy try r.allocator.dupe(u8, borrowed);
    };
    defer r.allocator.free(metrics_text);

    return .{ .val = try runtime.env.createStringUtf8(metrics_text) };
}

pub fn drainLogs(self: *@This(), limit: js.Value) !js.Value {
    return network_logs.drain(try self.owner(), limit.val);
}

pub fn setLogLevel(self: *@This(), level: js.Value) !void {
    try network_logs.configure(try self.owner(), level.val);
}

pub fn applyIntent(self: *@This(), intent: js.Value, slot: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .applyIntent, &.{ intent.val, slot.val }) };
}
pub fn updateStatus(self: *@This(), status: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .updateStatus, &.{status.val}) };
}
pub fn getIdentity(self: *@This()) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .getIdentity, &.{}) };
}
pub fn getPeers(self: *@This()) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .getPeers, &.{}) };
}
pub fn getGossipDiagnostics(self: *@This(), cursor: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .getGossipDiagnostics, &.{cursor.val}) };
}
pub fn connect(self: *@This(), peer: js.Value, addresses: js.Value, timeout: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .connect, &.{ peer.val, addresses.val, timeout.val }) };
}
pub fn disconnect(self: *@This(), peer: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .disconnect, &.{peer.val}) };
}
pub fn reStatusPeers(self: *@This(), peers: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .reStatusPeers, &.{peers.val}) };
}
pub fn addDirectPeer(self: *@This(), peer: js.Value, addresses: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .addDirectPeer, &.{ peer.val, addresses.val }) };
}
pub fn removeDirectPeer(self: *@This(), peer: js.Value) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .removeDirectPeer, &.{peer.val}) };
}
pub fn getDirectPeers(self: *@This()) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .getDirectPeers, &.{}) };
}
pub fn getRememberedPeers(self: *@This()) !js.Value {
    return .{ .val = try command_js.submit(js.env(), try self.owner(), .getRememberedPeers, &.{}) };
}
pub fn requestStart(self: *@This(), peer: js.Value, protocol: js.Value, data: js.Value, options: js.Value) !js.Value {
    return .{ .val = try request_js.start(try self.owner(), peer.val, protocol.val, data.val, options.val) };
}
pub fn requestPull(self: *@This(), handle: js.Value) !void {
    try request_js.pull(try self.owner(), handle.val);
}
pub fn requestRetire(self: *@This(), handle: js.Value, abandoned: js.Value) !void {
    try request_js.retire(try self.owner(), handle.val, try decode.boolean(abandoned.val));
}

pub fn incomingRespond(self: *@This(), handle: js.Value, data: js.Value, context: js.Value) !void {
    try incoming_js.respond(try self.owner(), handle.val, data.val, context.val);
}
pub fn incomingRelease(self: *@This(), handle: js.Value) !void {
    try incoming_js.release(try self.owner(), handle.val);
}
pub fn incomingReady(self: *@This(), handle: js.Value) !void {
    try incoming_js.ready(try self.owner(), handle.val);
}
pub fn incomingTerminal(self: *@This(), handle: js.Value, action: js.Value, status: js.Value, message: js.Value) !void {
    try incoming_js.terminal(try self.owner(), handle.val, action.val, status.val, message.val);
}

pub fn publishGossip(self: *@This(), topic: js.Value, data: js.Value, options: js.Value) !js.Value {
    return .{ .val = try publication_js.publish(try self.owner(), topic.val, data.val, options.val) };
}

test "a notification JavaScript cannot run stops locally" {
    const shim = @import("network_test_support.zig");
    shim.undefined_status = napi.c.napi_cannot_run_js;
    defer shim.undefined_status = napi.c.napi_ok;
    var notified: Runtime = .{ .env = undefined, .notify_live = false };
    onNotify(undefined, undefined, &notified, undefined);
    try std.testing.expect(notified.disposed and notified.stop and !notified.env_alive);
}
