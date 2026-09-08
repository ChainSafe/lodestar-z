const std = @import("std");
const napi = @import("zapi:zapi").napi;
const gossip = @import("network").gossipsub;
pub const enabled = @import("network_runtime_options").network_runtime_test_failures;
pub const Stage = enum(u8) { none, runtime_alloc, ready_promise, close_promise, copy_error_ref, requested_ref, cancelled_ref, failed_ref, promise_holder, wake, wake_signal, notify, hook, spawn, entropy, key, enr, core, wake_attach, identity_copy, startup_copy, close_copy, drain_copy };
pub const Scenario = enum(u8) { none, entry, key_ready, before_ready, observations, gossip, drain_publish };
pub const DrainPublication = enum { idle, requested, published };
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
        .score = owner.scores.params,
        .topic = owner.scores.topic_params[0],
        .allowlist = owner.ip_allowlist,
        .allowlist_len = owner.ip_allowlist_len,
        .topic_boundaries = undefined,
        .topic_boundary_count = 0,
        .topic_count = 0,
        .topic_subscription_bytes = 0,
    };
    if (owner.namespace) |*ns| {
        const snapshot = &gossip_snapshot.?;
        @memcpy(snapshot.topic_boundaries[0..ns.boundaries.len], ns.boundaries);
        snapshot.topic_boundary_count = @intCast(ns.boundaries.len);
        snapshot.topic_count = ns.topic_count;
        snapshot.topic_subscription_bytes = ns.subscriptions.len * @sizeOf(u64);
    }
}

pub fn publishDuringDrain(runtime: *@import("network_runtime.zig").Runtime) !void {
    if (comptime !enabled) return;
    runtime.lock();
    if (runtime.test_scenario != .drain_publish or runtime.test_drain_publication != .idle) {
        runtime.unlock();
        return;
    }
    runtime.test_drain_publication = .requested;
    runtime.wake.?.signal() catch |err| {
        runtime.unlock();
        return err;
    };
    runtime.unlock();
    for (0..500) |_| {
        runtime.lock();
        const published = runtime.test_drain_publication == .published;
        const stopped = runtime.stop or runtime.quiescent;
        runtime.unlock();
        if (published) return;
        if (stopped) return error.NetworkClosed;
        var wait_fd = std.c.pollfd{ .fd = -1, .events = 0, .revents = 0 };
        const result = std.c.poll(@ptrCast(&wait_fd), 1, 10);
        if (result < 0 and std.c.errno(result) != .INTR) return error.NetworkWakeFailed;
    }
    return error.NetworkTestPublicationTimeout;
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
    try exports.setNamedProperty("networkTestFail", try env.createFunction("networkTestFail", 1, fail, null));
    try exports.setNamedProperty("networkTestStats", try env.createFunction("networkTestStats", 0, stats, null));
    try exports.setNamedProperty("networkTestScenario", try env.createFunction("networkTestScenario", 1, selectScenario, null));
    try exports.setNamedProperty("networkTestStage", try env.createFunction("networkTestStage", 0, getStage, null));
    try exports.setNamedProperty("networkTestGossip", try env.createFunction("networkTestGossip", 0, getGossip, null));
}
fn selectScenario(env: napi.Env, info: napi.CallbackInfo(1)) !napi.Value {
    const arg = info.getArg(0) orelse return error.InvalidNetworkConfig;
    if (try arg.typeof() != .string) return error.InvalidNetworkConfig;
    var buffer: [32]u8 = undefined;
    const value = std.meta.stringToEnum(Scenario, try arg.getValueStringUtf8(&buffer)) orelse return error.InvalidNetworkConfig;
    reached.store(.none, .release);
    scenario.store(value, .release);
    return env.getUndefined();
}
fn getStage(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    return env.createStringUtf8(@tagName(reached.load(.acquire)));
}
fn scalarFields(env: napi.Env, value: anytype) !napi.Value {
    const fields = @typeInfo(@TypeOf(value.*)).@"struct".fields;
    comptime std.debug.assert(fields.len <= 64);
    const object = try env.createObject();
    inline for (fields) |field| {
        const copied: ?napi.Value = switch (@typeInfo(field.type)) {
            .int => if (field.type == u64) try env.createBigintUint64(@field(value, field.name)) else try env.createDouble(@floatFromInt(@field(value, field.name))),
            .float => try env.createDouble(@field(value, field.name)),
            else => null,
        };
        if (copied) |item| try object.setNamedProperty(field.name ++ "\x00", item);
    }
    return object;
}
fn copyBytes(env: napi.Env, value: []const u8) !napi.Value {
    const buffer = try env.createArrayBufferCopy(value, null);
    return env.createTypedarray(.uint8, value.len, buffer, 0);
}
fn getGossip(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    std.Io.Threaded.mutexLock(&gossip_mutex);
    const snapshot = gossip_snapshot;
    std.Io.Threaded.mutexUnlock(&gossip_mutex);
    const value = snapshot orelse return error.InvalidNetworkConfig;
    const object = try env.createObject();
    try object.setNamedProperty("options", try scalarFields(env, &value.options));
    try object.setNamedProperty("score", try scalarFields(env, &value.score));
    try object.setNamedProperty("topic", try scalarFields(env, &value.topic));
    try object.setNamedProperty("phase0Digest", if (value.options.message_id_policy.phase0_digest) |digest| try copyBytes(env, &digest) else try env.getNull());
    const allowlist = try env.createArrayWithLength(value.allowlist_len);
    for (value.allowlist[0..value.allowlist_len], 0..) |address, i| try allowlist.setElement(@intCast(i), try copyBytes(env, &address));
    try object.setNamedProperty("ipAllowlist", allowlist);
    try object.setNamedProperty("minimumSamplingGroups", try env.createUint32(value.minimum_sampling_groups));
    try object.setNamedProperty("topicCount", try env.createUint32(value.topic_count));
    try object.setNamedProperty("topicSubscriptionBytes", try env.createDouble(@floatFromInt(value.topic_subscription_bytes)));
    const boundaries = try env.createArrayWithLength(value.topic_boundary_count);
    for (value.topic_boundaries[0..value.topic_boundary_count], 0..) |*boundary, i| {
        const copied = try env.createObject();
        try copied.setNamedProperty("digest", try copyBytes(env, &boundary.digest));
        const rules = try env.createArrayWithLength(gossip.topic_policy.kind_count);
        for (boundary.rules, 0..) |rule, k| try rules.setElement(@intCast(k), try scalarFields(env, &rule));
        try copied.setNamedProperty("rules", rules);
        try boundaries.setElement(@intCast(i), copied);
    }
    try object.setNamedProperty("topicPolicy", if (value.topic_boundary_count == 0) try env.getNull() else boundaries);
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
    try out.setNamedProperty("runtimes", try env.createUint32(runtimes.load(.acquire)));
    try out.setNamedProperty("notifications", try env.createUint32(notifications.load(.acquire)));
    try out.setNamedProperty("owners", try env.createUint32(owners.load(.acquire)));
    return out;
}
