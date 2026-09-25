const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const r = @import("network_runtime.zig");
const p = @import("network_publications.zig");
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const g = @import("network_gossip_js.zig");
const clock = @import("network_gossip.zig");

fn rejectInput(env: napi.Env, err: anyerror) anyerror {
    const value = g.publishError(env, err) catch |failure| return failure;
    env.throw(value) catch |failure| return failure;
    return error.PendingException;
}
fn payloadLength(data: Value) !usize {
    if (!try data.isTypedarray()) return error.InvalidNetworkBytes;
    const view = try data.getTypedarrayInfo();
    if (view.array_type != .uint8 or try view.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    if (view.length > clock.payload_max) return error.PayloadTooLarge;
    return view.length;
}
pub fn publish(runtime: *r.Runtime, topic: Value, data: Value, options: Value) !Value {
    runtime.retain();
    defer runtime.release();
    var name: [n.gossipsub.topic.topic_max_len]u8 = undefined;
    const topic_len = try app.text(topic, &name);
    const canonical = n.gossipsub.topic.parseCanonical(name[0..topic_len]) orelse return rejectInput(runtime.env, error.UnknownTopic);
    const bytes = try payloadLength(data);
    const token = runtime.reservePublication(canonical.name.kind, bytes) catch |err| return rejectInput(runtime.env, err);
    errdefer runtime.retirePublication(token);
    const cell = runtime.publications.?.get(token).?;
    cell.topic_len = @intCast(topic_len);
    @memcpy(cell.topic[0..topic_len], name[0..topic_len]);
    cell.options = try g.optionsFor(options);
    const len = try payloadLength(data);
    if (len > cell.reservation) return error.PayloadTooLarge;
    const copy = try r.allocator.alloc(u8, len);
    errdefer r.allocator.free(copy);
    const deferred = try runtime.env.createPromise();
    errdefer @import("network_js.zig").discardPromise(runtime.env, deferred);
    try cfg.bytes(data, copy);
    const queued_ms = try clock.monotonic();
    runtime.lock();
    defer runtime.unlock();
    if (runtime.stop or runtime.quiescent) return error.NetworkClosed;
    cell.order = try runtime.table.nextOrder();
    cell.queued_ms = queued_ms;
    cell.payload = copy;
    cell.deferred = deferred;
    runtime.publications.?.transition(cell, .queued);
    runtime.publications.?.diag.copies +|= 1;
    runtime.publications.?.diag.bytesCopied +|= len;
    runtime.signalLocked();
    // Ref does not allocate JS values or invoke JavaScript.
    runtime.notify.ref(runtime.env) catch {};
    return deferred.getPromise();
}
/// Settles up to `limit` terminal publications. Returns whether more remain.
pub fn settle(env: napi.Env, runtime: *r.Runtime, limit: usize) !bool {
    runtime.retain();
    defer runtime.release();
    var settled: usize = 0;
    var more = false;
    var next: usize = 0;
    for (0..p.capacity_max) |_| {
        runtime.lock();
        const table = if (runtime.publications) |*table| table else {
            runtime.unlock();
            break;
        };
        const i = table.nextTerminal(next) orelse {
            runtime.unlock();
            break;
        };
        if (settled == limit) {
            runtime.unlock();
            more = true;
            break;
        }
        settled += 1;
        next = i + 1;
        const cell = &table.cells[i];
        table.transition(cell, .copying);
        const token: p.Token = .{ .index = @intCast(i), .generation = cell.generation };
        runtime.unlock();
        defer runtime.retirePublication(token);
        if (cell.deferred) |deferred| {
            if (cell.failure) |err| {
                try deferred.reject(g.publishError(env, err) catch try runtime.copy_error.?.getValue());
            } else {
                const value = copyResult(env, cell) catch {
                    try deferred.reject(try runtime.copy_error.?.getValue());
                    continue;
                };
                try deferred.resolve(value);
            }
        }
    }
    runtime.disposeTerminalReferences();
    return more;
}
fn copyResult(env: napi.Env, cell: *const p.Cell) !Value {
    return g.publishResult(env, cell.outcome);
}
