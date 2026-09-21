const std = @import("std");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const n = @import("network");
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const r = @import("network_runtime.zig");
const requests = @import("network_requests.zig");
const Runtime = r.Runtime;

const put = @import("network_js.zig").put;
const bytes = @import("network_js.zig").bytes;
fn errorValue(env: napi.Env, comptime code: [:0]const u8) !Value {
    const name = try env.createStringUtf8(code);
    return env.createError(name, name);
}
fn result(env: napi.Env, value: ?Value) !Value {
    const object = try env.createObject();
    try put(object, "done", try env.getBoolean(value == null));
    try put(object, "value", value orelse try env.getUndefined());
    return object;
}
fn tokenValue(env: napi.Env, token: requests.Token) !Value {
    const object = try env.createObject();
    try put(object, "index", try env.createUint32(token.index));
    try put(object, "generation", try env.createBigintUint64(token.generation));
    return object;
}
fn tokenFor(value: Value) !requests.Token {
    try cfg.completeObject(value, &.{ "index", "generation" });
    const index = try cfg.integer(try cfg.get(value, "index"), 31);
    const generation = try cfg.bigint(try cfg.get(value, "generation"));
    return .{ .index = @intCast(index), .generation = generation };
}
fn optionsFor(value: Value) !n.reqresp.RequestOptions {
    var result_options: n.reqresp.RequestOptions = .{};
    if (try value.typeof() == .undefined) return result_options;
    try cfg.object(value, &.{ "expectedChunks", "negotiationTimeoutMs", "requestTimeoutMs", "responseTimeoutMs" });
    const expected = try cfg.get(value, "expectedChunks");
    if (try expected.typeof() != .undefined) result_options.expected_chunks = @intCast(try cfg.integer(expected, std.math.maxInt(u32)));
    inline for (.{ .{ "negotiationTimeoutMs", "negotiation_ms" }, .{ "requestTimeoutMs", "request_ms" }, .{ "responseTimeoutMs", "response_ms" } }) |names| {
        const duration = try cfg.get(value, names[0]);
        if (try duration.typeof() != .undefined) {
            const ms = try cfg.integer(duration, 60000);
            if (ms == 0) return error.InvalidNetworkInteger;
            @field(result_options.absolute_timeouts, names[1]) = ms;
        }
    }
    return result_options;
}
pub fn start(runtime: *Runtime, peer: Value, protocol: Value, data: Value, options: Value) !Value {
    runtime.retain();
    defer runtime.release();
    var protocol_buffer: [128]u8 = undefined;
    const protocol_len = try app.text(protocol, &protocol_buffer);
    const which = n.reqresp.Protocol.fromId(protocol_buffer[0..protocol_len]) orelse return error.UnknownProtocol;
    if (which.isControl()) return error.ControlProtocol;
    const request_options = try optionsFor(options);
    const identity = try cfg.peerIdFrom(peer);
    if (!try data.isTypedarray()) return error.InvalidNetworkBytes;
    const view = try data.getTypedarrayInfo();
    if (view.array_type != .uint8 or try view.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    const len = view.length;
    if (len < which.info().request_min) return error.RequestTooSmall;
    if (len > which.info().request_max) return error.RequestTooLarge;
    runtime.lock();
    if (runtime.stop or runtime.quiescent) {
        runtime.unlock();
        return error.NetworkClosed;
    }
    const token = runtime.requests.?.reserve(which, len) catch |err| {
        runtime.unlock();
        if (err == error.NetworkRequestFull or err == error.NetworkBridgeFull) return rejectAdmission(runtime.env);
        return err;
    };
    runtime.retain();
    runtime.unlock();
    errdefer {
        runtime.retireRequest(token);
        runtime.lock();
        runtime.retireRequestStorageLocked();
        runtime.unlock();
    }
    try runtime.requests.?.allocate(token, len);
    const cell = runtime.requests.?.get(token).?;
    cell.peer = identity;
    cell.options = request_options;
    const value = try tokenValue(runtime.env, token);
    try cfg.bytes(data, cell.input);
    runtime.lock();
    defer runtime.unlock();
    if (runtime.stop or runtime.quiescent) return error.NetworkClosed;
    cell.order = try runtime.table.nextOrder();
    cell.state = .queued;
    runtime.signalLocked();
    return value;
}
fn rejectAdmission(env: napi.Env) anyerror {
    const value = errorValue(env, "NetworkRequestRejected") catch |err| return err;
    put(value, "reason", env.createStringUtf8("slots_exhausted") catch |err| return err) catch |err| return err;
    env.throw(value) catch |err| return err;
    return error.PendingException;
}
pub fn pull(runtime: *Runtime, handle: Value) !Value {
    const token = try tokenFor(handle);
    const env = runtime.env;
    runtime.lock();
    const cell = runtime.requests.?.get(token) orelse {
        runtime.unlock();
        return error.InvalidRequestHandle;
    };
    if (cell.pull != null) {
        runtime.requests.?.diag.busyPulls +|= 1;
        runtime.unlock();
        const deferred = try env.createPromise();
        try deferred.reject(try errorValue(env, "NetworkRequestBusy"));
        return deferred.getPromise();
    }
    runtime.unlock();
    const deferred = try env.createPromise();
    runtime.lock();
    cell.pull = deferred;
    if (cell.delivered) cell.consume = true;
    runtime.signalLocked();
    runtime.pingLocked();
    const ref_notify = runtime.notify_live;
    runtime.unlock();
    if (ref_notify) runtime.notify.ref(env) catch {};
    // Closed runtimes no longer have a live TSFN producer.
    settle(env, runtime);
    return deferred.getPromise();
}
pub fn retire(runtime: *Runtime, handle: Value, abandoned: bool) !Value {
    const token = try tokenFor(handle);
    const env = runtime.env;
    runtime.lock();
    const cell = runtime.requests.?.get(token) orelse {
        runtime.unlock();
        return env.getUndefined();
    };
    if (cell.retirement) |existing| {
        runtime.unlock();
        return existing.getPromise();
    }
    runtime.unlock();
    const deferred = if (abandoned) null else try env.createPromise();
    runtime.lock();
    cell.retirement = deferred;
    cell.retiring = true;
    cell.cancel = true;
    runtime.signalLocked();
    runtime.pingLocked();
    const ref_notify = runtime.notify_live;
    runtime.unlock();
    if (ref_notify and !abandoned) runtime.notify.ref(env) catch {};
    settle(env, runtime);
    return if (deferred) |value| value.getPromise() else env.getUndefined();
}
fn terminalError(env: napi.Env, terminal: requests.Terminal, cell: *const requests.Cell) !Value {
    try @import("network_faults.zig").check(.operation_copy);
    switch (terminal) {
        .closed => return errorValue(env, "NetworkClosed"),
        .rejected => |reason| {
            const object = try errorValue(env, "NetworkRequestRejected");
            try put(object, "reason", try env.createStringUtf8(@tagName(reason)));
            return object;
        },
        .failed => |failure| {
            const object = try errorValue(env, "NetworkRequestFailed");
            try put(object, "reason", try env.createStringUtf8(@tagName(failure.reason)));
            try put(object, "phase", if (failure.phase) |phase| try env.createStringUtf8(@tagName(phase)) else try env.getNull());
            const detail: ?[]const u8 = switch (failure.reason) {
                .invalid_response => |err| @errorName(err),
                .negotiation_failed => |err| @tagName(err),
                else => null,
            };
            try put(object, "detail", if (detail) |text| try env.createStringUtf8(text) else try env.getNull());
            try put(object, "context", if (failure.reason == .unknown_context) try bytes(env, &failure.reason.unknown_context) else try env.getNull());
            try put(object, "peerStatus", if (failure.reason == .peer_error) try env.createUint32(failure.reason.peer_error.code) else try env.getNull());
            try put(object, "peerMessage", if (failure.reason == .peer_error) try bytes(env, cell.peer_message[0..cell.peer_message_len]) else try env.getNull());
            return object;
        },
        .done => unreachable,
    }
}
fn chunkResult(env: napi.Env, runtime: *Runtime, cell: *const requests.Cell) !Value {
    const chunk = cell.chunk.?;
    const object = try env.createObject();
    var destination: [*]u8 = undefined;
    const buffer = try env.createArrayBuffer(chunk.len, &destination);
    const data = try env.createTypedarray(.uint8, chunk.len, buffer, 0);
    try @import("network_faults.zig").closeDuringRequestCopy(runtime, cell, destination[0..chunk.len]);
    @memcpy(destination[0..chunk.len], cell.sink[0..chunk.len]);
    try put(object, "data", data);
    try @import("network_faults.zig").check(.operation_copy);
    try put(object, "fork", if (requests.forkLabel(chunk.fork)) |fork| try env.createStringUtf8(fork) else try env.getNull());
    try put(object, "protocol", try env.createStringUtf8(cell.protocol.id()));
    return result(env, object);
}
pub fn settle(env: napi.Env, runtime: *Runtime) void {
    if (runtime.requests == null) return;
    runtime.retain();
    defer runtime.release();
    for (0..32) |i| {
        runtime.lock();
        if (i >= runtime.requests.?.cells.len) {
            runtime.unlock();
            break;
        }
        const cell = &runtime.requests.?.cells[i];
        if (cell.state == .free or cell.state == .preparing or cell.copying) {
            runtime.unlock();
            continue;
        }
        const deliver_chunk = cell.pull != null and cell.chunk != null and !cell.delivered and !cell.retiring and !runtime.stop;
        const terminal_ready = cell.terminal != null and cell.native == null and (cell.chunk == null or cell.retiring or runtime.stop);
        if (!deliver_chunk and !terminal_ready) {
            runtime.unlock();
            continue;
        }
        if (!deliver_chunk and cell.pull == null and !cell.retiring and !runtime.disposed) {
            runtime.unlock();
            continue;
        }
        const token: requests.Token = .{ .index = @intCast(i), .generation = cell.generation };
        cell.copying = true;
        const deferred = cell.pull;
        const retirement = cell.retirement;
        const terminal = cell.terminal;
        const retiring = cell.retiring;
        runtime.unlock();
        var failed_copy = false;
        if (deferred) |pending| {
            if (deliver_chunk) {
                const value = chunkResult(env, runtime, cell) catch blk: {
                    failed_copy = true;
                    break :blk runtime.copy_error.?.getValue() catch unreachable;
                };
                if (failed_copy) pending.reject(value) catch unreachable else pending.resolve(value) catch unreachable;
            } else if (terminal.? == .done and !retiring) {
                const value = result(env, null) catch blk: {
                    failed_copy = true;
                    break :blk runtime.copy_error.?.getValue() catch unreachable;
                };
                if (failed_copy) pending.reject(value) catch unreachable else pending.resolve(value) catch unreachable;
            } else {
                const selected: requests.Terminal = if (retiring and terminal.? != .closed) .{ .failed = .{ .reason = .cancelled, .phase = if (terminal.? == .failed) terminal.?.failed.phase else if (terminal.? == .done) .response else null } } else terminal.?;
                pending.reject(terminalError(env, selected, cell) catch runtime.copy_error.?.getValue() catch unreachable) catch unreachable;
            }
        }
        if (!deliver_chunk) if (retirement) |pending| pending.resolve(env.getUndefined() catch unreachable) catch unreachable;
        runtime.lock();
        cell.copying = false;
        cell.pull = null;
        if (deliver_chunk and !failed_copy) {
            runtime.requests.?.diag.chunksCopied +|= 1;
            runtime.requests.?.diag.bytesCopied +|= cell.chunk.?.len;
            cell.delivered = true;
            if (cell.native == null) {
                cell.chunk = null;
                cell.delivered = false;
            }
        }
        if (failed_copy) {
            cell.cancel = true;
            cell.retiring = true;
            cell.chunk = null;
        }
        runtime.requests.?.releasePayload(cell);
        runtime.unlock();
        if (failed_copy) runtime.failDelivery();
        if (!deliver_chunk) runtime.retireRequest(token);
    }
    runtime.lock();
    runtime.retireRequestStorageLocked();
    runtime.unlock();
    runtime.disposeTerminalReferences();
}
pub fn diagnostics(env: napi.Env, value: *const requests.Diagnostics) !Value {
    return @import("network_js.zig").scalarFields(env, value);
}
