const std = @import("std");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const r = @import("network_runtime.zig");
const incoming = @import("network_incoming.zig");
const Runtime = r.Runtime;

const bytes = @import("network_js.zig").bytes;
const errorValue = @import("network_js.zig").errorValue;
fn connectionValue(env: napi.Env, connection: @import("network").quic.engine.Handle) !Value {
    const object = try env.createObject();
    try object.setNamedProperty("index", try env.createUint32(connection.index));
    try object.setNamedProperty("generation", try env.createUint32(connection.generation));
    return object;
}
fn tokenValue(runtime: *Runtime, token: incoming.Token) !Value {
    const env = runtime.env;
    const object = try env.createObject();
    try object.setNamedProperty("index", try env.createUint32(token.index));
    try object.setNamedProperty("generation", try env.createBigintUint64(token.generation));
    return object;
}
fn parseHandle(value: Value) !incoming.Token {
    try cfg.completeObject(value, &.{ "index", "generation" });
    return .{
        .index = @intCast(try cfg.integer(try cfg.get(value, "index"), 31)),
        .generation = try cfg.bigint(try cfg.get(value, "generation")),
    };
}
fn cellFor(runtime: *Runtime, token: incoming.Token) !*incoming.Cell {
    const table = if (runtime.incoming) |*table| table else return error.InvalidIncomingHandle;
    return table.get(token) orelse error.NetworkIncomingClosed;
}
/// Wakes the owner for the host's change and keeps the event loop alive for the promises it awaits.
fn refNotify(runtime: *Runtime) void {
    runtime.lock();
    const live = runtime.notify_live;
    runtime.signalLocked();
    runtime.unlock();
    if (live) runtime.notify.ref(runtime.env) catch {};
}
pub fn descriptorValue(runtime: *Runtime, token: incoming.Token, cell: *const incoming.Cell, deferred: napi.Deferred) !Value {
    const env = runtime.env;
    const object = try env.createObject();
    try object.setNamedProperty("handle", try tokenValue(runtime, token));
    try object.setNamedProperty("peerId", try @import("network_js.zig").peerIdValue(env, &cell.identity));
    try object.setNamedProperty("connection", try connectionValue(env, cell.connection));
    try object.setNamedProperty("protocol", try env.createStringUtf8(cell.protocol.id()));
    var destination: [*]u8 = undefined;
    const buffer = try env.createArrayBuffer(cell.input.len, &destination);
    const data = try env.createTypedarray(.uint8, cell.input.len, buffer, 0);
    @memcpy(destination[0..cell.input.len], cell.input);
    try object.setNamedProperty("data", data);
    try object.setNamedProperty("closed", deferred.getPromise());
    return object;
}
fn contextFor(value: Value) !?@import("network").reqresp.ForkEntry {
    if (try value.typeof() == .null) return null;
    try cfg.completeObject(value, &.{ "digest", "fork" });
    const digest = try cfg.get(value, "digest");
    const fork = try cfg.fork(try cfg.get(value, "fork"));
    return .{ .digest = try cfg.fixed(4, digest), .fork = fork };
}
fn viewLength(value: Value, max: usize) !usize {
    if (!try value.isTypedarray()) return error.InvalidNetworkBytes;
    const view = try value.getTypedarrayInfo();
    if (view.array_type != .uint8 or try view.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    if (view.length > max) return error.ChunkTooLarge;
    return view.length;
}
pub fn respond(runtime: *Runtime, value: Value, data: Value, context_value: Value) !Value {
    const handle = try parseHandle(value);
    const context = try contextFor(context_value);
    runtime.retain();
    defer runtime.release();
    runtime.lock();
    const cell = cellFor(runtime, handle) catch |err| {
        runtime.unlock();
        return err;
    };
    if (runtime.stop or !cell.native or cell.action != .none) {
        runtime.unlock();
        return error.NetworkIncomingClosed;
    }
    if (cell.pending != null or cell.permission != null or cell.state != .serving) {
        runtime.unlock();
        return error.NetworkIncomingBusy;
    }
    const len = viewLength(data, cell.protocol.info().response_max) catch |err| {
        runtime.unlock();
        if (err == error.ChunkTooLarge) return rejectInput(runtime.env, .chunk_too_large);
        return err;
    };
    runtime.incoming.?.reserveResponse(cell, len) catch |err| {
        runtime.incoming.?.diag.byteRefusals +|= 1;
        runtime.unlock();
        return err;
    };
    cell.state = .response_preparing;
    runtime.incoming.?.refresh(cell);
    runtime.unlock();
    errdefer {
        runtime.lock();
        cell.state = if (cell.native) .serving else .terminal;
        runtime.incoming.?.releasePayload(cell);
        runtime.incoming.?.refresh(cell);
        runtime.unlock();
    }
    const copy = try r.allocator.alloc(u8, len);
    errdefer r.allocator.free(copy);
    const deferred = try runtime.env.createPromise();
    errdefer @import("network_js.zig").discardPromise(runtime.env, deferred);
    try cfg.bytes(data, copy);
    runtime.lock();
    if (runtime.stop or !cell.native) {
        runtime.unlock();
        return error.NetworkClosed;
    }
    cell.response = copy;
    cell.context = context;
    cell.pending = deferred;
    cell.ack = null;
    cell.state = .response_queued;
    runtime.incoming.?.refresh(cell);
    runtime.incoming.?.diag.responseBytesCopied +|= len;
    runtime.unlock();
    refNotify(runtime);
    return deferred.getPromise();
}
pub fn terminal(runtime: *Runtime, value: Value, action_value: Value, status_value: Value, message_value: Value) !Value {
    const handle = try parseHandle(value);
    const action: incoming.Action = switch (try cfg.integer(action_value, 2)) {
        0 => .finish,
        1 => .fail,
        2 => .cancel,
        else => unreachable,
    };
    var status: u8 = 0;
    var message: [256]u8 = undefined;
    var len: usize = 0;
    if (action == .fail) {
        status = @intCast(cfg.integer(status_value, 255) catch return rejectInput(runtime.env, .invalid_error));
        if (!@import("network").reqresp.constants.isErrorResult(status)) return rejectInput(runtime.env, .invalid_error);
        len = viewLength(message_value, message.len) catch return rejectInput(runtime.env, .invalid_error);
        try cfg.bytes(message_value, message[0..len]);
    }
    runtime.lock();
    const cell = cellFor(runtime, handle) catch |err| {
        runtime.unlock();
        return err;
    };
    if (cell.native) {
        if (action != .cancel and (cell.pending != null or cell.permission != null or cell.state == .response_preparing)) {
            runtime.unlock();
            return error.NetworkIncomingBusy;
        }
        if (cell.action == .none or action == .cancel) {
            cell.action = action;
            cell.error_status = status;
            cell.error_len = @intCast(len);
            @memcpy(cell.error_message[0..len], message[0..len]);
        }
    }
    runtime.unlock();
    refNotify(runtime);
    return runtime.env.getUndefined();
}

pub fn release(runtime: *Runtime, value: Value) !Value {
    const handle = try parseHandle(value);
    runtime.lock();
    const cell = cellFor(runtime, handle) catch |err| {
        runtime.unlock();
        return err;
    };
    cell.release_requested = true;
    runtime.unlock();
    refNotify(runtime);
    return runtime.env.getUndefined();
}

pub fn ready(runtime: *Runtime, value: Value) !Value {
    const handle = try parseHandle(value);
    const deferred = try runtime.env.createPromise();
    errdefer @import("network_js.zig").discardPromise(runtime.env, deferred);
    runtime.lock();
    const cell = cellFor(runtime, handle) catch |err| {
        runtime.unlock();
        return err;
    };
    if (!cell.native or cell.action != .none or runtime.stop) {
        runtime.unlock();
        return error.NetworkIncomingClosed;
    }
    if (cell.permission != null or cell.pending != null or cell.state != .serving) {
        runtime.unlock();
        return error.NetworkIncomingBusy;
    }
    cell.permission = deferred;
    cell.permission_ready = false;
    runtime.incoming.?.refresh(cell);
    runtime.unlock();
    refNotify(runtime);
    return deferred.getPromise();
}
fn ackError(env: napi.Env, ack: incoming.Ack) !Value {
    switch (ack) {
        .sent => unreachable,
        .closed => return errorValue(env, "NetworkClosed"),
        .failed => |reason| {
            const object = try errorValue(env, "NetworkIncomingFailed");
            try object.setNamedProperty("failure", try env.createStringUtf8(@tagName(reason)));
            return object;
        },
        .rejected => |reason| {
            const object = try errorValue(env, "NetworkIncomingRejected");
            try object.setNamedProperty("reason", try env.createStringUtf8(@tagName(reason)));
            return object;
        },
    }
}
/// Settles up to `limit` incoming acknowledgements, closes and permissions. Returns whether more remain.
pub fn settle(env: napi.Env, runtime: *Runtime, limit: usize) !bool {
    if (runtime.incoming == null) return false;
    runtime.retain();
    defer runtime.release();
    var settled: usize = 0;
    var more = false;
    for (0..incoming.capacity_max) |_| {
        runtime.lock();
        const table = &runtime.incoming.?;
        const i = table.nextDue(table.settle_cursor) orelse table.nextDue(0) orelse {
            runtime.unlock();
            break;
        };
        if (settled == limit) {
            runtime.unlock();
            more = true;
            break;
        }
        settled += 1;
        runtime.bridge.deliver(.completion, 1);
        table.settle_cursor = i + 1;
        const cell = &table.cells[i];
        std.debug.assert(incoming.settleable(cell));
        const pending = if (cell.ack != null) cell.pending else null;
        const closed = if (!cell.native) cell.closed else null;
        const permission = if (cell.permission_ready or !cell.native) cell.permission else null;
        cell.copying = true;
        table.refresh(cell);
        const ack = cell.ack;
        const permitted = cell.native and cell.permission_ready;
        runtime.unlock();
        defer {
            runtime.lock();
            cell.copying = false;
            if (pending != null) {
                cell.pending = null;
                cell.ack = null;
            }
            if (closed != null) cell.closed = null;
            if (permission != null) {
                cell.permission = null;
                cell.permission_ready = false;
            }
            table.releasePayload(cell);
            table.refresh(cell);
            if (!cell.native and !cell.serving_retained and cell.closed == null and cell.pending == null and cell.permission == null) {
                table.retire(.{ .index = @intCast(i), .generation = cell.generation });
            } else if (incoming.releasable(cell)) runtime.signalLocked();
            runtime.unlock();
        }
        if (pending) |deferred| {
            if (ack.? == .sent) try deferred.resolve(try env.getUndefined()) else try deferred.reject(@import("network_js.zig").settled(env, ackError(env, ack.?)) catch try runtime.copy_error.?.getValue());
        }
        if (closed) |deferred| try deferred.resolve(try env.getUndefined());
        if (permission) |deferred| {
            if (permitted) try deferred.resolve(try env.getUndefined()) else try deferred.reject(@import("network_js.zig").settled(env, errorValue(env, "NetworkIncomingClosed")) catch try runtime.copy_error.?.getValue());
        }
    }
    runtime.lock();
    runtime.retireRequestStorageLocked();
    runtime.unlock();
    runtime.disposeTerminalReferences();
    return more;
}
pub fn diagnostics(env: napi.Env, value: *const incoming.Diagnostics) !Value {
    return @import("network_js.zig").scalarFields(env, value);
}

fn rejectInput(env: napi.Env, reason: incoming.Rejection) anyerror {
    const value = ackError(env, .{ .rejected = reason }) catch |err| return err;
    env.throw(value) catch |err| return err;
    return error.PendingException;
}
