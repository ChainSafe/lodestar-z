const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const element = @import("network_js.zig").element;
const Runtime = r.Runtime;

const put = @import("network_js.zig").put;
const bytes = @import("network_js.zig").bytes;
pub fn drain(runtime: *Runtime, options: Value) !Value {
    var demand: g.Table.Demand = .{};
    if (try options.typeof() != .undefined) {
        try cfg.completeObject(options, &.{ "items", "bytes", "ordinary" });
        demand = .{
            .items = @intCast(try cfg.integer(try cfg.get(options, "items"), g.batch_max)),
            .bytes = @intCast(try cfg.integer(try cfg.get(options, "bytes"), g.batch_bytes)),
            .ordinary = try cfg.boolean(try cfg.get(options, "ordinary")),
        };
    }
    runtime.retain();
    defer runtime.release();
    runtime.lock();
    const mono_ms = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    const table = &runtime.gossip.?;
    const previous = .{ table.pending(), table.deadline() };
    const batch = if (runtime.quiescent) g.Batch{} else table.claimDemand(mono_ms, demand);
    // The owner's wait reads these; a change wakes it to recompute.
    if (!std.meta.eql(previous, .{ table.pending(), table.deadline() })) runtime.signalLocked();
    runtime.unlock();
    var success = false;
    var reported_more = false;
    defer {
        runtime.lock();
        table.finish(&batch, success);
        if (runtime.quiescent) table.trim() else if (!reported_more and table.hasWork()) {
            runtime.work_rearm = true;
            runtime.signalLocked();
        }
        runtime.unlock();
    }
    const env = runtime.env;
    const array = try env.createArrayWithLength(batch.len);
    for (batch.tokens[0..batch.len], 0..) |token, i| {
        try element(array, i, try descriptor(runtime, token, &table.cells[token.index]));
    }
    const object = try env.createObject();
    try put(object, "messages", array);
    const jobs = try env.createArrayWithLength(batch.job_count);
    for (batch.jobs[0..batch.job_count], 0..) |job, i| {
        const value = try env.createObject();
        try put(value, "kind", try env.createStringUtf8(@tagName(job.kind)));
        try put(value, "start", try env.createUint32(@intCast(job.start)));
        try put(value, "length", try env.createUint32(@intCast(job.len)));
        try put(value, "grouped", try env.getBoolean(job.grouped));
        try put(value, "urgent", try env.getBoolean(n.gossip_processor.limits_mod.urgent(job.kind)));
        try element(jobs, i, value);
    }
    try put(object, "jobs", jobs);
    runtime.lock();
    const finished_ms = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    table.maintain(finished_ms, table.slot);
    const more = table.hasWork();
    runtime.unlock();
    try put(object, "more", try env.getBoolean(more));
    reported_more = more;
    success = true;
    return object;
}
fn descriptor(runtime: *Runtime, token: g.Token, cell: *const g.Cell) !Value {
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

pub fn checks(runtime: *Runtime) !Value {
    runtime.retain();
    defer runtime.release();
    runtime.lock();
    const now = g.monotonic() catch |err| {
        runtime.unlock();
        return err;
    };
    const table = &runtime.gossip.?;
    const batch = if (!runtime.quiescent and !runtime.stop) table.claimChecks(now) else g.Batch{};
    const CheckView = struct { root: [32]u8, slot: u64, identity: n.PeerId, topic: [g.topic_max]u8, topic_len: u16 };
    var cells: [g.batch_max]CheckView = undefined;
    for (batch.tokens[0..batch.len], 0..) |token, i| {
        const cell = table.get(token).?;
        cells[i] = .{ .root = cell.metadata.root.?, .slot = cell.metadata.slot.?, .identity = cell.identity, .topic = cell.topic, .topic_len = cell.topic_len };
    }
    runtime.unlock();
    var success = false;
    defer if (!success) {
        runtime.lock();
        table.retryChecks(&batch);
        runtime.work_rearm = true;
        runtime.signalLocked();
        runtime.unlock();
    };
    const env = runtime.env;
    const array = try env.createArrayWithLength(batch.len);
    for (batch.tokens[0..batch.len], 0..) |token, i| {
        const cell = &cells[i];
        const object = try env.createObject();
        const handle = try env.createObject();
        try put(handle, "index", try env.createUint32(token.index));
        try put(handle, "generation", try env.createBigintUint64(token.generation));
        try put(object, "handle", handle);
        try put(object, "root", try bytes(env, &cell.root));
        try put(object, "slot", try env.createBigintUint64(cell.slot));
        try put(object, "peerId", try @import("network_js.zig").peerIdValue(env, &cell.identity));
        try put(object, "topic", try env.createStringUtf8(cell.topic[0..cell.topic_len]));
        try element(array, i, object);
    }
    success = true;
    return array;
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
