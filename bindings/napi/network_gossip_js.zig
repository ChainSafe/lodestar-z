const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const faults = @import("network_faults.zig");
const projection = @import("network_peer_projection.zig");
const Runtime = r.Runtime;

fn put(object: Value, comptime name: [:0]const u8, value: Value) !void {
    try object.defineProperties(&.{.{ .utf8name = name.ptr, .name = null, .method = null, .getter = null, .setter = null, .value = value.value, .attributes = napi.c.napi_default_jsproperty, .data = null }});
}
fn bytes(env: napi.Env, data: []const u8) !Value {
    const buffer = try env.createArrayBufferCopy(data, null);
    return env.createTypedarray(.uint8, data.len, buffer, 0);
}
pub fn drain(runtime: *Runtime) !Value {
    runtime.retain();
    defer runtime.release();
    runtime.lock();
    const mono_ms = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    if (!runtime.application or (!runtime.active and !runtime.quiescent)) {
        runtime.unlock();
        return if (runtime.application) error.NetworkNotActive else error.NetworkClosed;
    }
    const table = &runtime.gossip.?;
    const batch = if (runtime.quiescent) g.Batch{} else table.claim(mono_ms);
    runtime.unlock();
    var success = false;
    var reported_more = false;
    defer {
        runtime.lock();
        table.finish(&batch, success);
        if (runtime.quiescent) table.trim() else if (!reported_more and table.oldest() != null) {
            runtime.observation_rearm = true;
            runtime.signalLocked();
        }
        runtime.unlock();
    }
    const env = runtime.env;
    const array = try env.createArrayWithLength(batch.len);
    for (batch.tokens[0..batch.len], 0..) |token, i| {
        try projection.element(array, i, try descriptor(runtime, token, &table.cells[token.index], i));
    }
    const object = try env.createObject();
    try put(object, "messages", array);
    runtime.lock();
    const finished_ms = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    table.expire(finished_ms);
    const more = table.oldest() != null;
    runtime.unlock();
    try put(object, "more", try env.getBoolean(more));
    reported_more = more;
    success = true;
    return object;
}
fn descriptor(runtime: *Runtime, token: g.Token, cell: *const g.Cell, ordinal: usize) !Value {
    const env = runtime.env;
    const object = try env.createObject();
    const handle = try env.createObject();
    try put(handle, "session", try env.createBigintUint64(runtime.diag.session));
    try put(handle, "index", try env.createUint32(token.index));
    try put(handle, "generation", try env.createBigintUint64(token.generation));
    try put(object, "handle", handle);
    const connection = try env.createObject();
    try put(connection, "index", try env.createUint32(cell.connection.index));
    try put(connection, "generation", try env.createUint32(cell.connection.generation));
    try put(object, "connection", connection);
    try put(object, "peerId", try bytes(env, &cell.identity.bytes));
    try put(object, "topic", try env.createStringUtf8(cell.topic[0..cell.topic_len]));
    try put(object, "id", try bytes(env, &cell.id));
    var destination: [*]u8 = undefined;
    const buffer = try env.createArrayBuffer(cell.input.len, &destination);
    const data = try env.createTypedarray(.uint8, cell.input.len, buffer, 0);
    try @import("network_gossip_faults.zig").copy(runtime, token, ordinal);
    try faults.check(.gossip_copy);
    @memcpy(destination[0..cell.input.len], cell.input);
    try put(object, "data", data);
    try put(object, "receivedAtUnixMs", try env.createDouble(@floatFromInt(cell.received_at)));
    return object;
}
pub fn report(runtime: *Runtime, value: Value, verdict_value: Value) !Value {
    runtime.retain();
    defer runtime.release();
    if (!runtime.application) return error.NetworkClosed;
    try cfg.completeObject(value, &.{ "session", "index", "generation" });
    const session = try cfg.bigint(try cfg.get(value, "session"));
    const index = try cfg.integer(try cfg.get(value, "index"), 9007199254740991);
    const generation = try cfg.bigint(try cfg.get(value, "generation"));
    if (session == 0 or generation == 0) return error.InvalidGossipHandle;
    var text: [16]u8 = undefined;
    const len = try app.text(verdict_value, &text);
    const verdict = std.meta.stringToEnum(n.gossipsub.Verdict, text[0..len]) orelse return error.InvalidGossipVerdict;
    runtime.lock();
    const mono_ms = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    var accepted = false;
    if (!runtime.quiescent and !runtime.stop and runtime.active and session == runtime.diag.session and index < 1024) {
        accepted = runtime.gossip.?.report(.{ .index = @intCast(index), .generation = generation }, verdict, mono_ms);
        if (accepted) runtime.signalLocked();
    } else runtime.gossip.?.diag.staleReports +|= 1;
    runtime.unlock();
    return runtime.env.getBoolean(accepted);
}
fn optionsFor(value: Value) !n.gossipsub.Gossipsub.PublishOptions {
    var result: n.gossipsub.Gossipsub.PublishOptions = .{};
    if (try value.typeof() == .undefined) return result;
    try cfg.object(value, &.{ "allowZeroPeers", "ignoreDuplicate", "flood" });
    inline for (.{ .{ "allowZeroPeers", "allow_zero_peers" }, .{ "ignoreDuplicate", "ignore_duplicate" }, .{ "flood", "flood" } }) |field| {
        const option = try cfg.get(value, field[0]);
        if (try option.typeof() != .undefined) @field(result, field[1]) = try cfg.boolean(option);
    }
    return result;
}
pub fn publish(runtime: *Runtime, topic: Value, data: Value, options: Value) !Value {
    const token = try runtime.reserveCommand(.publishGossip);
    errdefer runtime.abortCommand(token);
    const operation = &runtime.operations[token.index];
    const input = &operation.input;
    input.topic_len = @intCast(try app.text(topic, &input.topic));
    input.publish_options = try optionsFor(options);
    if (!try data.isTypedarray()) return error.InvalidNetworkBytes;
    const view = try data.getTypedarrayInfo();
    if (view.array_type != .uint8 or try view.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    const len = view.length;
    if (len > g.payload_max) return error.PayloadTooLarge;
    runtime.lock();
    if (runtime.stop or runtime.quiescent) {
        runtime.unlock();
        return error.NetworkClosed;
    }
    runtime.gossip.?.reservePublication(len) catch |err| {
        runtime.unlock();
        return err;
    };
    input.publication_reservation = len;
    runtime.unlock();
    try faults.check(.gossip_publication);
    const copy = try r.allocator.alloc(u8, len);
    errdefer r.allocator.free(copy);
    const deferred = try runtime.env.createPromise();
    errdefer deferred.resolve(runtime.env.getUndefined() catch unreachable) catch unreachable;
    try cfg.bytes(data, copy);
    runtime.lock();
    if (runtime.stop or runtime.quiescent) {
        runtime.unlock();
        return error.NetworkClosed;
    }
    input.publication = copy;
    operation.deferred = deferred;
    runtime.gossip.?.diag.publicationCopies +|= 1;
    runtime.gossip.?.diag.publicationBytesCopied +|= len;
    runtime.table.get(token).state = .queued;
    runtime.signalLocked();
    runtime.unlock();
    runtime.notify.ref(runtime.env) catch {};
    return deferred.getPromise();
}
pub fn publishResult(env: napi.Env, result: n.gossipsub.Gossipsub.PublishOutcome) !Value {
    const object = try env.createObject();
    inline for (.{ "queued", "pressured", "selected", "unavailable" }) |name| try put(object, name, try env.createUint32(@field(result, name)));
    try put(object, "duplicate", try env.getBoolean(result.duplicate));
    return object;
}
pub fn publishError(env: napi.Env, err: anyerror) !Value {
    const reason: ?[]const u8 = switch (err) {
        error.UnknownTopic => "unknown_topic",
        error.PayloadTooSmall => "payload_too_small",
        error.PayloadTooLarge => "payload_too_large",
        error.CompressFailed => "compress_failed",
        error.ResourceExhausted => "resource_exhausted",
        error.Duplicate => "duplicate",
        error.NoPeersSubscribedToTopic => "no_peers_subscribed_to_topic",
        else => null,
    };
    const code = try env.createStringUtf8(if (reason != null) "NetworkGossipPublishFailed" else @errorName(err));
    const object = try env.createError(code, code);
    if (reason) |text| try put(object, "reason", try env.createStringUtf8(text));
    return object;
}
pub fn diagnostics(env: napi.Env, value: *const g.Diagnostics) !Value {
    const object = try env.createObject();
    const Gauge = enum { capacity, occupied, highWater, queued, pendingVerdicts, reservedBytes, reservedBytesHighWater, payloadBytes, copyingBytes, publicationBytes, publicationBytesHighWater };
    const Counter = enum { messagesCopied, bytesCopied, capacityRefusals, byteRefusals, queuedExpired, deliveredExpired, staleReports, reportsAccepted, reportsAppliedAccept, reportsAppliedReject, reportsAppliedIgnore, reportsAlreadyResolved, reportsExpired, reportsStale, publicationCopies, publicationBytesCopied, publicationQueued, publicationPressured, publicationSelected, publicationUnavailable, publicationDuplicates };
    inline for (@typeInfo(g.Diagnostics).@"struct".fields) |field| {
        const gauge = @hasField(Gauge, field.name);
        const counter = @hasField(Counter, field.name);
        comptime std.debug.assert(gauge != counter);
        try put(object, field.name, if (counter) try env.createBigintUint64(@field(value, field.name)) else try env.createDouble(@floatFromInt(@field(value, field.name))));
    }
    return object;
}
