const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const Runtime = r.Runtime;

const put = @import("network_js.zig").put;
const bytes = @import("network_js.zig").bytes;
pub fn descriptor(runtime: *Runtime, token: g.Token, cell: *const g.Cell) !Value {
    const env = runtime.env;
    const object = try env.createObject();
    const handle = try env.createObject();
    try put(handle, "index", try env.createUint32(token.index));
    try put(handle, "generation", try env.createBigintUint64(token.generation));
    try put(object, "handle", handle);
    const connection = try env.createObject();
    try put(connection, "index", try env.createUint32(cell.connection.index));
    try put(connection, "generation", try env.createUint32(cell.connection.generation));
    try put(object, "connection", connection);
    try put(object, "peerId", try @import("network_js.zig").peerIdValue(env, &cell.identity));
    try put(object, "topic", try env.createStringUtf8(cell.topic[0..cell.topic_len]));
    try put(object, "id", try bytes(env, &cell.id));
    var destination: [*]u8 = undefined;
    const buffer = try env.createArrayBuffer(cell.input.len, &destination);
    const data = try env.createTypedarray(.uint8, cell.input.len, buffer, 0);
    runtime.gossip.?.copyPayload(cell, destination[0..cell.input.len]);
    try put(object, "data", data);
    var encoded: [172]u8 = undefined;
    try put(object, "attestationData", if (cell.metadata.group) |group| try env.createStringUtf8(std.base64.standard.Encoder.encode(&encoded, &group)) else try env.getNull());
    try put(object, "slot", if (cell.metadata.slot) |slot| try env.createBigintUint64(slot) else try env.getNull());
    try put(object, "receivedAtUnixMs", try env.createDouble(@floatFromInt(cell.received_at)));
    return object;
}
pub fn report(runtime: *Runtime, value: Value, verdict_value: Value) !Value {
    runtime.retain();
    defer runtime.release();
    try cfg.completeObject(value, &.{ "index", "generation" });
    const index = try cfg.integer(try cfg.get(value, "index"), 9007199254740991);
    const generation = try cfg.bigint(try cfg.get(value, "generation"));
    if (generation == 0) return error.InvalidGossipHandle;
    var text: [16]u8 = undefined;
    const len = try app.text(verdict_value, &text);
    const verdict = std.meta.stringToEnum(n.gossipsub.Verdict, text[0..len]) orelse return error.InvalidGossipVerdict;
    runtime.lock();
    const mono_ms = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    var accepted = false;
    if (!runtime.quiescent and !runtime.stop and index < n.gossip_processor.limits_mod.capacity_max) {
        accepted = runtime.gossip.?.report(.{ .index = @intCast(index), .generation = generation }, verdict, mono_ms);
        runtime.work_rearm = true;
        runtime.signalLocked();
    }
    runtime.unlock();
    return runtime.env.getBoolean(accepted);
}
pub fn optionsFor(value: Value) !n.gossipsub.Gossipsub.PublishOptions {
    var result: n.gossipsub.Gossipsub.PublishOptions = .{};
    if (try value.typeof() == .undefined) return result;
    try cfg.object(value, &.{ "allowZeroPeers", "ignoreDuplicate", "flood" });
    inline for (.{ .{ "allowZeroPeers", "allow_zero_peers" }, .{ "ignoreDuplicate", "ignore_duplicate" }, .{ "flood", "flood" } }) |field| {
        const option = try cfg.get(value, field[0]);
        if (try option.typeof() != .undefined) @field(result, field[1]) = try cfg.boolean(option);
    }
    return result;
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
        error.PublicationQueueFull, error.NetworkBridgeFull => "admission_full",
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
    return @import("network_js.zig").scalarFields(env, value);
}

pub fn classify(runtime: *Runtime, values: Value) !Value {
    const count = try cfg.array(values, g.batch_max);
    var entries: [g.batch_max]struct { token: g.Token, available: bool } = undefined;
    for (entries[0..count], 0..) |*entry, i| {
        const value = try values.getElement(@intCast(i));
        try cfg.completeObject(value, &.{ "handle", "available" });
        const handle = try cfg.get(value, "handle");
        try cfg.completeObject(handle, &.{ "index", "generation" });
        const index = try cfg.integer(try cfg.get(handle, "index"), n.gossip_processor.limits_mod.capacity_max);
        const generation = try cfg.bigint(try cfg.get(handle, "generation"));
        if (generation == 0) return error.InvalidGossipHandle;
        entry.* = .{ .token = .{ .index = @intCast(index), .generation = generation }, .available = try cfg.boolean(try cfg.get(value, "available")) };
    }
    runtime.lock();
    defer runtime.unlock();
    var accepted: u32 = 0;
    if (!runtime.stop and !runtime.quiescent) {
        const table = &runtime.gossip.?;
        table.maintain(try g.monotonic(), table.slot);
        for (entries[0..count]) |entry| accepted += @intFromBool(table.classify(entry.token, entry.available));
        runtime.work_rearm = true;
        runtime.signalLocked();
    }
    return runtime.env.createUint32(accepted);
}

pub fn notifyBlock(runtime: *Runtime, value: Value) !Value {
    const root = try cfg.fixed(32, value);
    runtime.lock();
    defer runtime.unlock();
    if (!runtime.quiescent and !runtime.stop) {
        runtime.gossip.?.notifyBlock(root);
        runtime.work_rearm = true;
        runtime.signalLocked();
    }
    return runtime.env.getUndefined();
}

pub fn dropQueued(runtime: *Runtime) !Value {
    runtime.lock();
    defer runtime.unlock();
    if (!runtime.quiescent and !runtime.stop) {
        runtime.gossip.?.dropQueued();
        runtime.signalLocked();
    }
    return runtime.env.getUndefined();
}

pub fn trackSearch(runtime: *Runtime, root_value: Value, peer_value: Value) !Value {
    const root = try cfg.fixed(32, root_value);
    const peer: ?n.PeerId = if (try peer_value.typeof() == .null) null else try cfg.peerIdFrom(peer_value);
    runtime.lock();
    defer runtime.unlock();
    const accepted = !runtime.quiescent and !runtime.stop and runtime.gossip.?.trackSearch(root, peer, try g.monotonic());
    return runtime.env.getBoolean(accepted);
}
