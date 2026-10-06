const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const decode = @import("network_js_input.zig");
const r = @import("network_runtime.zig");
const p = @import("network_publications.zig");
const g = @import("network_gossip_js.zig");
const clock = @import("network_gossip.zig");
const js = @import("network_js.zig");

fn rejectInput(env: napi.Env, err: anyerror) anyerror {
    const value = g.publishError(env, err) catch |failure| return failure;
    env.throw(value) catch |failure| return failure;
    return error.PendingException;
}
fn payloadLength(data: Value) !usize {
    const len = (try decode.byteView(data)).len;
    if (len > clock.payload_max) return error.PayloadTooLarge;
    return len;
}
/// Admits one publication and returns its handle, which JavaScript's record holds before an exchange can deliver the
/// completion. A refusal leaves no cell.
pub fn publish(runtime: *r.Runtime, topic: Value, data: Value, options: Value) !Value {
    runtime.retain();
    defer runtime.release();
    var name: [n.gossipsub.topic.topic_max_len]u8 = undefined;
    const topic_len = try decode.text(topic, &name);
    const canonical = n.gossipsub.topic.parseCanonical(name[0..topic_len]) orelse return rejectInput(runtime.env, error.UnknownTopic);
    const publish_options = try g.optionsFor(options);
    const len = payloadLength(data) catch |err| return rejectInput(runtime.env, err);
    const token = runtime.reservePublication(canonical.name.kind, len) catch |err| return rejectInput(runtime.env, err);
    errdefer runtime.retirePublication(token);
    const cell = runtime.publications.?.get(token).?;
    cell.topic_len = @intCast(topic_len);
    @memcpy(cell.topic[0..topic_len], name[0..topic_len]);
    cell.options = publish_options;
    const copy = try r.allocator.alloc(u8, len);
    errdefer r.allocator.free(copy);
    // Prepared before admission commits, so every admitted publication has a handle to complete.
    const handle = try js.handle(runtime.env, token.index, token.generation);
    try decode.bytes(data, copy);
    const queued_ms = try clock.monotonic();
    runtime.lock();
    defer runtime.unlock();
    if (runtime.stop or runtime.quiescent) return error.NetworkClosed;
    cell.order = try runtime.table.nextOrder();
    cell.queued_ms = queued_ms;
    cell.payload = copy;
    runtime.publications.?.transition(cell, .queued);
    runtime.publications.?.diag.copies +|= 1;
    runtime.publications.?.diag.bytesCopied +|= len;
    runtime.signalLocked();
    // Ref does not allocate JS values or invoke JavaScript.
    runtime.notify.ref(runtime.env) catch {};
    return handle;
}

/// A completed publication's record: its outcome, or the error its operation rejects with.
pub fn completion(env: napi.Env, token: p.Token, cell: *const p.Cell) !Value {
    const object = try env.createObject();
    try object.setNamedProperty("family", try env.createStringUtf8("publication"));
    try object.setNamedProperty("handle", try js.handle(env, token.index, token.generation));
    if (cell.failure) |err| {
        try object.setNamedProperty("error", try js.settled(env, g.publishError(env, err)));
    } else try object.setNamedProperty("value", try g.publishResult(env, cell.outcome));
    return object;
}
