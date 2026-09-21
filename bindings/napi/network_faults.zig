const std = @import("std");
const napi = @import("zapi:zapi").napi;
const gossip = @import("network").gossipsub;
pub const enabled = @import("network_runtime_options").network_runtime_test_failures;
pub const Stage = enum(u8) { none, runtime_alloc, owner_alloc, application_stores, application_snapshot_0, application_snapshot_1, application_lane, gossip_table, gossip_publication, gossip_copy, incoming_table, incoming_input, incoming_response, operation_copy, close_promise, copy_error_ref, requested_ref, failed_ref, promise_holder, wake, wake_signal, notify, hook, spawn, entropy, key, enr, core, wake_attach, identity_copy, close_copy, drain_copy };
pub const Scenario = enum(u8) { none, gossip, application_peer_lane, request_queued, request_negotiation, request_copy_close, request_copy_closed, incoming_copy_close, incoming_copy_closed, incoming_ack_close, incoming_response_close, incoming_observe, incoming_hold, incoming_prepare_buffer, incoming_prepare_deferred, incoming_terminal_before, incoming_terminal_after, gossip_copy_close, gossip_copy_close_fail, gossip_copy_closed, gossip_copy_expire, gossip_copy_expired, gossip_second_copy_fail, gossip_owner_hold, gossip_owner_held };
var selected = std.atomic.Value(Stage).init(.none);
var scenario = std.atomic.Value(Scenario).init(.none);
pub var reached = std.atomic.Value(Scenario).init(.none);
pub var runtimes = std.atomic.Value(u32).init(0);
pub var notifications = std.atomic.Value(u32).init(0);
pub var owners = std.atomic.Value(u32).init(0);
const GossipSnapshot = struct {
    options: gossip.Options,
    minimum_sampling_groups: u16,
    score: gossip.score.Params,
    topic: gossip.score.TopicParams,
    allowlist: [32][16]u8,
    allowlist_len: u8,
    topic_boundaries: [gossip.topic_policy.boundary_max]gossip.topic_policy.Boundary,
    topic_boundary_count: u8,
    topic_count: u16,
    topic_subscription_bytes: usize,
};
var gossip_mutex: std.Io.Mutex = .init;
var gossip_snapshot: ?GossipSnapshot = null;

pub fn captureGossip(owner: *const gossip.Gossipsub, context: *const @import("network").peers.ForkContext) void {
    if (comptime !enabled) return;
    std.Io.Threaded.mutexLock(&gossip_mutex);
    defer std.Io.Threaded.mutexUnlock(&gossip_mutex);
    gossip_snapshot = .{
        .options = owner.options,
        .minimum_sampling_groups = context.minimum_sampling_groups,
        .score = owner.peers.scores.params,
        .topic = owner.peers.scores.topic_params[0],
        .allowlist = owner.peers.ip_allowlist,
        .allowlist_len = owner.peers.ip_allowlist_len,
        .topic_boundaries = undefined,
        .topic_boundary_count = 0,
        .topic_count = 0,
        .topic_subscription_bytes = 0,
    };
    if (owner.overlay.namespace) |*ns| {
        const snapshot = &gossip_snapshot.?;
        @memcpy(snapshot.topic_boundaries[0..ns.boundaries.len], ns.boundaries);
        snapshot.topic_boundary_count = @intCast(ns.boundaries.len);
        snapshot.topic_count = ns.topic_count;
        snapshot.topic_subscription_bytes = ns.subscriptions.len * @sizeOf(u64);
    }
}

pub fn check(stage: Stage) !void {
    if (comptime !enabled) return;
    if (selected.cmpxchgStrong(stage, .none, .acq_rel, .acquire) == null) return error.InjectedNetworkFailure;
}
pub fn count(counter: *std.atomic.Value(u32), add: bool) void {
    if (comptime !enabled) return;
    if (add) _ = counter.fetchAdd(1, .acq_rel) else std.debug.assert(counter.fetchSub(1, .acq_rel) > 0);
}
pub fn takeScenario() Scenario {
    if (comptime !enabled) return .none;
    return scenario.swap(.none, .acq_rel);
}
pub fn register(env: napi.Env, exports: napi.Value) !void {
    if (comptime !enabled) return;
    try @import("network_js.zig").put(exports, "networkTestFail", try env.createFunction("networkTestFail", 1, fail, null));
    try @import("network_js.zig").put(exports, "networkTestStats", try env.createFunction("networkTestStats", 0, stats, null));
    try @import("network_js.zig").put(exports, "networkTestScenario", try env.createFunction("networkTestScenario", 1, selectScenario, null));
    try @import("network_js.zig").put(exports, "networkTestStage", try env.createFunction("networkTestStage", 0, getStage, null));
    try @import("network_js.zig").put(exports, "networkTestRequest", try env.createFunction("networkTestRequest", 0, getRequest, null));
    try @import("network_gossip_faults.zig").register(env, exports);
    try @import("network_incoming_faults.zig").register(env, exports);
    try @import("network_incoming_phase_faults.zig").register(env, exports);
    try @import("network_js.zig").put(exports, "networkTestGossip", try env.createFunction("networkTestGossip", 0, getGossip, null));
}
fn selectScenario(env: napi.Env, info: napi.CallbackInfo(1)) !napi.Value {
    const arg = info.getArg(0) orelse return error.InvalidNetworkConfig;
    if (try arg.typeof() != .string) return error.InvalidNetworkConfig;
    var buffer: [32]u8 = undefined;
    const value = std.meta.stringToEnum(Scenario, try arg.getValueStringUtf8(&buffer)) orelse return error.InvalidNetworkConfig;
    reached.store(.none, .release);
    @import("network_incoming_phase_faults.zig").reset();
    scenario.store(value, .release);
    return env.getUndefined();
}
fn getStage(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    return env.createStringUtf8(@tagName(reached.load(.acquire)));
}
const scalarFields = @import("network_js.zig").scalarFields;
const copyBytes = @import("network_js.zig").bytes;
fn getGossip(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    std.Io.Threaded.mutexLock(&gossip_mutex);
    const snapshot = gossip_snapshot;
    std.Io.Threaded.mutexUnlock(&gossip_mutex);
    const value = snapshot orelse return error.InvalidNetworkConfig;
    const object = try env.createObject();
    try @import("network_js.zig").put(object, "options", try scalarFields(env, &value.options));
    try @import("network_js.zig").put(object, "score", try scalarFields(env, &value.score));
    try @import("network_js.zig").put(object, "topic", try scalarFields(env, &value.topic));
    try @import("network_js.zig").put(object, "phase0Digest", if (value.options.message_id_policy.phase0_digest) |digest| try copyBytes(env, &digest) else try env.getNull());
    const allowlist = try env.createArrayWithLength(value.allowlist_len);
    for (value.allowlist[0..value.allowlist_len], 0..) |address, i| try @import("network_js.zig").element(allowlist, @intCast(i), try copyBytes(env, &address));
    try @import("network_js.zig").put(object, "ipAllowlist", allowlist);
    try @import("network_js.zig").put(object, "minimumSamplingGroups", try env.createUint32(value.minimum_sampling_groups));
    try @import("network_js.zig").put(object, "topicCount", try env.createUint32(value.topic_count));
    try @import("network_js.zig").put(object, "topicSubscriptionBytes", try env.createDouble(@floatFromInt(value.topic_subscription_bytes)));
    const boundaries = try env.createArrayWithLength(value.topic_boundary_count);
    for (value.topic_boundaries[0..value.topic_boundary_count], 0..) |*boundary, i| {
        const copied = try env.createObject();
        try @import("network_js.zig").put(copied, "digest", try copyBytes(env, &boundary.digest));
        const rules = try env.createArrayWithLength(gossip.topic_policy.kind_count);
        for (boundary.rules, 0..) |rule, k| try @import("network_js.zig").element(rules, @intCast(k), try scalarFields(env, &rule));
        try @import("network_js.zig").put(copied, "rules", rules);
        try @import("network_js.zig").element(boundaries, @intCast(i), copied);
    }
    try @import("network_js.zig").put(object, "topicPolicy", if (value.topic_boundary_count == 0) try env.getNull() else boundaries);
    return object;
}
fn fail(env: napi.Env, info: napi.CallbackInfo(1)) !napi.Value {
    const arg = info.getArg(0) orelse return error.InvalidNetworkConfig;
    if (try arg.typeof() != .string) return error.InvalidNetworkConfig;
    var buffer: [64]u8 = undefined;
    const stage = std.meta.stringToEnum(Stage, try arg.getValueStringUtf8(&buffer)) orelse return error.InvalidNetworkConfig;
    selected.store(stage, .release);
    return env.getUndefined();
}
fn stats(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    const out = try env.createObject();
    try @import("network_js.zig").put(out, "runtimes", try env.createUint32(runtimes.load(.acquire)));
    try @import("network_js.zig").put(out, "notifications", try env.createUint32(notifications.load(.acquire)));
    try @import("network_js.zig").put(out, "owners", try env.createUint32(owners.load(.acquire)));
    return out;
}

const Runtime = @import("network_runtime.zig").Runtime;
const requests = @import("network_requests.zig");
const RequestSnapshot = struct {
    bridgeGeneration: u64 = 0,
    nativeGeneration: u32 = 0,
    phase: ?@import("network").reqresp.RequestPhase = null,
    nativeOwned: bool = false,
    negotiatorMatched: bool = false,
    copying: bool = false,
    coreLive: bool = false,
    quiescent: bool = false,
    inputBytes: usize = 0,
    sinkBytes: usize = 0,
    reservedBytes: usize = 0,
    destinationBytes: usize = 0,
};
var request_mutex: std.Io.Mutex = .init;
var request_snapshot: RequestSnapshot = .{};

fn requestSnapshot(runtime: *const Runtime, cell: *const requests.Cell) RequestSnapshot {
    return .{
        .bridgeGeneration = cell.generation,
        .nativeGeneration = if (cell.native) |handle| handle.generation else 0,
        .nativeOwned = cell.native != null,
        .copying = cell.copying,
        .coreLive = runtime.heavy != null and runtime.heavy.?.core_live,
        .quiescent = runtime.quiescent,
        .inputBytes = cell.input.len,
        .sinkBytes = cell.sink.len,
        .reservedBytes = cell.reservation,
    };
}
fn publishRequest(value: *const RequestSnapshot, stage: Scenario) void {
    std.Io.Threaded.mutexLock(&request_mutex);
    request_snapshot = value.*;
    std.Io.Threaded.mutexUnlock(&request_mutex);
    reached.store(stage, .release);
}
fn getRequest(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    std.Io.Threaded.mutexLock(&request_mutex);
    const value = request_snapshot;
    std.Io.Threaded.mutexUnlock(&request_mutex);
    const object = try scalarFields(env, &value);
    inline for (.{ "nativeOwned", "negotiatorMatched", "copying", "coreLive", "quiescent" }) |name| try @import("network_js.zig").put(object, name, try env.getBoolean(@field(value, name)));
    try @import("network_js.zig").put(object, "phase", if (value.phase) |phase| try env.createStringUtf8(@tagName(phase)) else try env.getNull());
    return object;
}
pub fn requestBarrier(runtime: *Runtime, token: requests.Token, stage: Scenario) !void {
    if (comptime !enabled) return;
    std.debug.assert(stage == .request_queued or stage == .request_negotiation);
    runtime.lock();
    if (runtime.test_scenario != stage) {
        runtime.unlock();
        return;
    }
    runtime.test_scenario = .none;
    const cell = runtime.requests.?.get(token).?;
    var snapshot = requestSnapshot(runtime, cell);
    if (stage == .request_queued) {
        std.debug.assert(cell.state == .queued and cell.native == null);
    } else {
        std.debug.assert(cell.state == .native and cell.native != null);
        const handle = cell.native.?;
        const service = &runtime.heavy.?.core.service;
        std.debug.assert(handle.direction == .outbound and handle.index < service.reqresp.outbound.len);
        const client = &service.reqresp.outbound[handle.index];
        std.debug.assert(std.meta.eql(client.request.handle(handle.index), handle));
        std.debug.assert(client.request.running() and client.phase == .negotiation and client.request.stream_owner == .router);
        snapshot.phase = client.phase;
        for (service.router.negotiator.entries) |entry| {
            if (entry.state == .negotiating and std.meta.eql(entry.stream, client.request.stream)) snapshot.negotiatorMatched = true;
        }
        std.debug.assert(snapshot.phase == .negotiation and snapshot.negotiatorMatched);
    }
    publishRequest(&snapshot, stage);
    runtime.unlock();
    for (0..500) |_| {
        runtime.lock();
        const cancelled = runtime.requests.?.get(token).?.cancel or runtime.stop;
        const fd = runtime.wake.?.read_fd;
        runtime.unlock();
        if (cancelled) return;
        var poll_fd = std.c.pollfd{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 };
        const result = std.c.poll(@ptrCast(&poll_fd), 1, 10);
        if (result < 0 and std.c.errno(result) != .INTR) return error.NetworkWakeFailed;
        if (result > 0) try runtime.wake.?.drain();
    }
    return error.NetworkTestBarrierTimeout;
}
pub fn closeDuringRequestCopy(runtime: *Runtime, cell: *const requests.Cell, destination: []u8) !void {
    if (comptime !enabled) return;
    runtime.lock();
    if (runtime.test_scenario != .request_copy_close) {
        runtime.unlock();
        return;
    }
    runtime.test_scenario = .none;
    std.debug.assert(cell.copying and cell.chunk != null and cell.sink.len > 0);
    std.debug.assert(destination.len == cell.chunk.?.len and destination.ptr != cell.sink.ptr);
    runtime.unlock();
    runtime.requestStop();
    for (0..500) |_| {
        runtime.lock();
        const closed = runtime.quiescent;
        if (closed) {
            std.debug.assert(runtime.heavy == null and cell.native == null and cell.terminal.? == .closed);
            std.debug.assert(cell.copying and cell.sink.len > 0 and cell.reservation > 0);
            std.debug.assert(cell.chunk.?.len == destination.len);
            var snapshot = requestSnapshot(runtime, cell);
            snapshot.destinationBytes = destination.len;
            publishRequest(&snapshot, .request_copy_closed);
        }
        runtime.unlock();
        if (closed) return;
        var poll_fd = std.c.pollfd{ .fd = -1, .events = 0, .revents = 0 };
        const result = std.c.poll(@ptrCast(&poll_fd), 1, 10);
        if (result < 0 and std.c.errno(result) != .INTR) return error.NetworkWakeFailed;
    }
    return error.NetworkTestBarrierTimeout;
}
