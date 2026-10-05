const std = @import("std");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const decode = @import("network_js_input.zig");
const n = @import("network");
const r = @import("network_runtime.zig");
const requests = @import("network_requests.zig");
const Runtime = r.Runtime;
const network_js = @import("network_js.zig");

const bytes = @import("network_js.zig").bytes;
const errorValue = @import("network_js.zig").errorValue;
fn optionsFor(value: Value) !n.reqresp.ReqResp.RequestOptions {
    var result_options: n.reqresp.ReqResp.RequestOptions = .{};
    if (try value.typeof() == .undefined) return result_options;
    try decode.object(value, &.{ "expectedChunks", "negotiationTimeoutMs", "requestTimeoutMs", "responseTimeoutMs" });
    const expected = try decode.get(value, "expectedChunks");
    if (try expected.typeof() != .undefined) result_options.expected_chunks = @intCast(try decode.integer(expected, std.math.maxInt(u32)));
    inline for (.{ .{ "negotiationTimeoutMs", "negotiation" }, .{ "requestTimeoutMs", "request" }, .{ "responseTimeoutMs", "response" } }) |names| {
        const duration = try decode.get(value, names[0]);
        if (try duration.typeof() != .undefined) {
            const ms = try decode.integer(duration, 60000);
            if (ms == 0) return error.InvalidNetworkInteger;
            @field(result_options.timeouts, names[1]) = .fromMilliseconds(@intCast(ms));
        }
    }
    return result_options;
}
pub fn start(runtime: *Runtime, peer: Value, protocol: Value, data: Value, options: Value) !Value {
    runtime.retain();
    defer runtime.release();
    var protocol_buffer: [128]u8 = undefined;
    const protocol_len = try decode.text(protocol, &protocol_buffer);
    const which = n.reqresp.Protocol.fromId(protocol_buffer[0..protocol_len]) orelse return error.UnknownProtocol;
    if (which.isControl()) return error.ControlProtocol;
    const request_options = try optionsFor(options);
    const identity = try decode.peerIdFrom(peer);
    const len = (try decode.byteView(data)).len;
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
    const value = try network_js.handle(runtime.env, token.index, token.generation);
    try decode.bytes(data, cell.input);
    runtime.lock();
    defer runtime.unlock();
    if (runtime.stop or runtime.quiescent) return error.NetworkClosed;
    cell.order = try runtime.table.nextOrder();
    cell.state = .queued;
    runtime.requests.?.refresh(cell);
    runtime.signalLocked();
    return value;
}
fn rejectAdmission(env: napi.Env) anyerror {
    const value = errorValue(env, "NetworkRequestRejected") catch |err| return err;
    value.setNamedProperty("reason", env.createStringUtf8("slots_exhausted") catch |err| return err) catch |err| return err;
    env.throw(value) catch |err| return err;
    return error.PendingException;
}
/// Arms a pull, whose chunk or terminal outcome an exchange delivers. The iterator allows one pull at a time, so a
/// second one breaks its contract.
pub fn pull(runtime: *Runtime, handle: Value) !void {
    const token = try decode.handle(requests.Token, handle, requests.capacity_max);
    runtime.lock();
    const cell = runtime.requests.?.get(token) orelse {
        runtime.unlock();
        return error.InvalidRequestHandle;
    };
    if (cell.pulling) {
        runtime.unlock();
        return error.NetworkRequestBusy;
    }
    requests.armPull(runtime, cell);
    const ref_notify = runtime.notify_live;
    runtime.unlock();
    if (ref_notify) runtime.notify.ref(runtime.env) catch {};
}
/// Cancels and retires the request. Its terminal completion ends a retirement the iterator awaits, one not
/// `abandoned`; a stale handle's request already retired.
pub fn retire(runtime: *Runtime, handle: Value, abandoned: bool) !void {
    const token = try decode.handle(requests.Token, handle, requests.capacity_max);
    runtime.lock();
    const cell = runtime.requests.?.get(token) orelse {
        runtime.unlock();
        return;
    };
    requests.armRetirement(runtime, cell, !abandoned);
    const ref_notify = runtime.notify_live;
    runtime.unlock();
    if (ref_notify and !abandoned) runtime.notify.ref(runtime.env) catch {};
}
fn terminalError(env: napi.Env, terminal: requests.Terminal, cell: *const requests.Cell) !Value {
    switch (terminal) {
        .closed => return errorValue(env, "NetworkClosed"),
        .rejected => |reason| {
            const object = try errorValue(env, "NetworkRequestRejected");
            try object.setNamedProperty("reason", try env.createStringUtf8(@tagName(reason)));
            return object;
        },
        .failed => |failure| {
            const object = try errorValue(env, "NetworkRequestFailed");
            try object.setNamedProperty("reason", try env.createStringUtf8(@tagName(failure.reason)));
            try object.setNamedProperty("phase", if (failure.phase) |phase| try env.createStringUtf8(@tagName(phase)) else try env.getNull());
            try object.setNamedProperty("peerFault", if (failure.peer_fault) |fault| try env.createStringUtf8(@tagName(fault)) else try env.getNull());
            const detail: ?[]const u8 = switch (failure.reason) {
                .invalid_response => |err| @errorName(err),
                .negotiation_failed => |err| @tagName(err),
                else => null,
            };
            try object.setNamedProperty("detail", if (detail) |text| try env.createStringUtf8(text) else try env.getNull());
            try object.setNamedProperty("context", if (failure.reason == .unknown_context) try bytes(env, &failure.reason.unknown_context) else try env.getNull());
            try object.setNamedProperty("peerStatus", if (failure.reason == .peer_error) try env.createUint32(failure.reason.peer_error.code) else try env.getNull());
            try object.setNamedProperty("peerMessage", if (failure.reason == .peer_error) try bytes(env, cell.peer_message[0..cell.peer_message_len]) else try env.getNull());
            return object;
        },
        .done => unreachable,
    }
}
/// A request completion: `value`, a copy of the chunk its pending pull resolves with, or its terminal outcome, `done`
/// or the `error` a pending pull rejects with.
pub fn completion(env: napi.Env, runtime: *Runtime, delivered: requests.Completion) !Value {
    const cell = &runtime.requests.?.cells[delivered.token.index];
    const object = try env.createObject();
    try object.setNamedProperty("family", try env.createStringUtf8("request"));
    try object.setNamedProperty("handle", try network_js.handle(env, delivered.token.index, delivered.token.generation));
    switch (delivered.value) {
        .chunk => |chunk| {
            const value = try env.createObject();
            var destination: [*]u8 = undefined;
            const buffer = try env.createArrayBuffer(chunk.len, &destination);
            @memcpy(destination[0..chunk.len], cell.sink[0..chunk.len]);
            try value.setNamedProperty("data", try env.createTypedarray(.uint8, chunk.len, buffer, 0));
            try value.setNamedProperty("fork", if (requests.forkLabel(chunk.fork)) |fork| try env.createStringUtf8(fork) else try env.getNull());
            try value.setNamedProperty("protocol", try env.createStringUtf8(cell.protocol.id()));
            try object.setNamedProperty("value", value);
        },
        .terminal => |terminal| if (terminal == .done)
            try object.setNamedProperty("done", try env.getBoolean(true))
        else
            try object.setNamedProperty("error", try network_js.settled(env, terminalError(env, terminal, cell))),
    }
    return object;
}
