const std = @import("std");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const r = @import("network_runtime.zig");
const incoming = @import("network_incoming.zig");
const Runtime = r.Runtime;

fn put(object: Value, comptime name: [:0]const u8, value: Value) !void {
    try object.defineProperties(&.{.{ .utf8name = name.ptr, .name = null, .method = null, .getter = null, .setter = null, .value = value.value, .attributes = napi.c.napi_default_jsproperty, .data = null }});
}
fn bytes(env: napi.Env, data: []const u8) !Value {
    const buffer = try env.createArrayBufferCopy(data, null);
    return env.createTypedarray(.uint8, data.len, buffer, 0);
}
fn errorValue(env: napi.Env, comptime code: [:0]const u8) !Value {
    const name = try env.createStringUtf8(code);
    return env.createError(name, name);
}
fn connectionValue(env: napi.Env, connection: @import("network").quic.engine.Handle) !Value {
    const object = try env.createObject();
    try put(object, "index", try env.createUint32(connection.index));
    try put(object, "generation", try env.createUint32(connection.generation));
    return object;
}
fn tokenValue(runtime: *Runtime, token: incoming.Token, cell: *const incoming.Cell) !Value {
    const env = runtime.env;
    const object = try env.createObject();
    try put(object, "session", try env.createBigintUint64(runtime.diag.session));
    try put(object, "direction", try env.createStringUtf8("inbound"));
    try put(object, "index", try env.createUint32(token.index));
    try put(object, "generation", try env.createBigintUint64(token.generation));
    try put(object, "nativeIndex", try env.createUint32(cell.handle.index));
    try put(object, "nativeGeneration", try env.createUint32(cell.handle.generation));
    try put(object, "connection", try connectionValue(env, cell.connection));
    return object;
}
const Handle = struct {
    token: incoming.Token,
    native_index: u16,
    native_generation: u32,
    connection: @import("network").quic.engine.Handle,
};
fn parseHandle(runtime: *Runtime, value: Value) !Handle {
    try cfg.completeObject(value, &.{ "session", "direction", "index", "generation", "nativeIndex", "nativeGeneration", "connection" });
    const session = try cfg.bigint(try cfg.get(value, "session"));
    var direction: [16]u8 = undefined;
    const len = try @import("network_application_config.zig").text(try cfg.get(value, "direction"), &direction);
    if (session != runtime.diag.session or !runtime.application or !std.mem.eql(u8, direction[0..len], "inbound")) return error.InvalidIncomingHandle;
    const index = try cfg.integer(try cfg.get(value, "index"), 31);
    const generation = try cfg.bigint(try cfg.get(value, "generation"));
    const native_index = try cfg.integer(try cfg.get(value, "nativeIndex"), std.math.maxInt(u16));
    const native_generation = try cfg.integer(try cfg.get(value, "nativeGeneration"), std.math.maxInt(u32));
    const connection = try cfg.get(value, "connection");
    try cfg.completeObject(connection, &.{ "index", "generation" });
    return .{ .token = .{ .index = @intCast(index), .generation = generation }, .native_index = @intCast(native_index), .native_generation = @intCast(native_generation), .connection = .{ .index = @intCast(try cfg.integer(try cfg.get(connection, "index"), std.math.maxInt(u16))), .generation = @intCast(try cfg.integer(try cfg.get(connection, "generation"), std.math.maxInt(u32))) } };
}
fn cellFor(runtime: *Runtime, handle: *const Handle) !*incoming.Cell {
    const table = if (runtime.incoming) |*table| table else return error.InvalidIncomingHandle;
    const cell = table.get(handle.token) orelse return error.NetworkIncomingClosed;
    if (cell.handle.direction != .inbound or cell.handle.index != handle.native_index or cell.handle.generation != handle.native_generation or !std.meta.eql(cell.connection, handle.connection)) return error.InvalidIncomingHandle;
    return cell;
}
fn refNotify(runtime: *Runtime) void {
    runtime.lock();
    const live = runtime.notify_live;
    runtime.signalLocked();
    runtime.pingLocked();
    runtime.unlock();
    if (live) runtime.notify.ref(runtime.env) catch {};
}
pub fn take(runtime: *Runtime) !Value {
    runtime.retain();
    defer runtime.release();
    runtime.lock();
    if (!runtime.application or !runtime.active or runtime.stop or runtime.quiescent) {
        runtime.unlock();
        return error.NetworkClosed;
    }
    const table = &runtime.incoming.?;
    const token = table.oldest() orelse {
        runtime.unlock();
        return runtime.env.getNull();
    };
    const cell = table.get(token).?;
    cell.copying = true;
    cell.state = .copying;
    runtime.unlock();
    errdefer {
        runtime.lock();
        cell.copying = false;
        cell.action = .cancel;
        cell.state = if (cell.native) .serving else .terminal;
        table.releasePayload(cell);
        if (!cell.native) table.retire(token);
        runtime.unlock();
        runtime.failDelivery();
    }
    try prepareResults(runtime.env, &cell.results, 0);
    errdefer retireReferences(cell);
    const deferred = try runtime.env.createPromise();
    errdefer deferred.resolve(runtime.env.getUndefined() catch unreachable) catch unreachable;
    const descriptor = try descriptorValue(runtime, token, cell, deferred);
    runtime.lock();
    cell.closed = deferred;
    cell.copying = false;
    cell.exposed = true;
    table.diag.requestsTaken +|= 1;
    table.diag.requestBytesCopied +|= cell.input.len;
    table.releaseInput(cell);
    cell.state = if (cell.native) .serving else .terminal;
    table.releasePayload(cell);
    runtime.unlock();
    refNotify(runtime);
    settle(runtime.env, runtime);
    return descriptor;
}
fn descriptorValue(runtime: *Runtime, token: incoming.Token, cell: *const incoming.Cell, deferred: napi.Deferred) !Value {
    const env = runtime.env;
    const object = try env.createObject();
    try put(object, "handle", try tokenValue(runtime, token, cell));
    try put(object, "peerId", try bytes(env, &cell.identity.bytes));
    try put(object, "connection", try connectionValue(env, cell.connection));
    try put(object, "protocol", try env.createStringUtf8(cell.protocol.id()));
    var destination: [*]u8 = undefined;
    const buffer = try env.createArrayBuffer(cell.input.len, &destination);
    const data = try env.createTypedarray(.uint8, cell.input.len, buffer, 0);
    try @import("network_incoming_faults.zig").copy(runtime, cell, destination[0..cell.input.len]);
    @memcpy(destination[0..cell.input.len], cell.input);
    try put(object, "data", data);
    try @import("network_faults.zig").check(.operation_copy);
    try put(object, "closed", deferred.getPromise());
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
    const handle = try parseHandle(runtime, value);
    const context = try contextFor(context_value);
    runtime.retain();
    defer runtime.release();
    runtime.lock();
    const cell = cellFor(runtime, &handle) catch |err| {
        runtime.unlock();
        return err;
    };
    if (runtime.stop or cell.terminal != null or cell.action != .none) {
        runtime.unlock();
        return error.NetworkIncomingClosed;
    }
    if (cell.pending != null or cell.state != .serving) {
        runtime.incoming.?.diag.busyResponses +|= 1;
        runtime.unlock();
        return error.NetworkIncomingBusy;
    }
    cell.state = .response_preparing;
    runtime.unlock();
    errdefer {
        runtime.lock();
        cell.state = if (cell.native) .serving else .terminal;
        runtime.incoming.?.releasePayload(cell);
        runtime.unlock();
    }
    try prepareResults(runtime.env, &cell.next_results, try std.math.add(u32, cell.chunks, 1));
    errdefer deleteResults(&cell.next_results);
    const len = viewLength(data, cell.protocol.info().response_max) catch |err| {
        if (err == error.ChunkTooLarge) return rejectInput(runtime.env, .chunk_too_large);
        return err;
    };
    try @import("network_faults.zig").check(.incoming_response);
    const copy = try r.allocator.alloc(u8, len);
    errdefer r.allocator.free(copy);
    const deferred = try runtime.env.createPromise();
    errdefer deferred.resolve(runtime.env.getUndefined() catch unreachable) catch unreachable;
    try cfg.bytes(data, copy);
    runtime.lock();
    if (runtime.stop or cell.terminal != null) {
        runtime.unlock();
        return error.NetworkClosed;
    }
    cell.response = copy;
    cell.context = context;
    cell.pending = deferred;
    cell.ack = null;
    cell.state = .response_queued;
    runtime.incoming.?.diag.responseBytesCopied +|= len;
    runtime.unlock();
    refNotify(runtime);
    return deferred.getPromise();
}
pub fn terminal(runtime: *Runtime, value: Value, action_value: Value, status_value: Value, message_value: Value) !Value {
    const handle = try parseHandle(runtime, value);
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
        if (status == 0) return rejectInput(runtime.env, .invalid_error);
        len = viewLength(message_value, message.len) catch return rejectInput(runtime.env, .invalid_error);
        try cfg.bytes(message_value, message[0..len]);
    }
    runtime.lock();
    const cell = cellFor(runtime, &handle) catch |err| {
        runtime.unlock();
        return err;
    };
    if (cell.terminal == null) {
        if (action != .cancel and (cell.pending != null or cell.state == .response_preparing)) {
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
    settle(runtime.env, runtime);
    return runtime.env.getUndefined();
}
fn ackError(env: napi.Env, ack: incoming.Ack) !Value {
    switch (ack) {
        .sent => unreachable,
        .closed => return errorValue(env, "NetworkClosed"),
        .failed => |reason| {
            const object = try errorValue(env, "NetworkIncomingFailed");
            try put(object, "failure", try env.createStringUtf8(@tagName(reason)));
            return object;
        },
        .rejected => |reason| {
            const object = try errorValue(env, "NetworkIncomingRejected");
            try put(object, "reason", try env.createStringUtf8(@tagName(reason)));
            return object;
        },
    }
}
fn closedValue(env: napi.Env, terminal_value: incoming.Terminal, chunks: u32) !Value {
    const object = try env.createObject();
    try put(object, "reason", try env.createStringUtf8(@tagName(terminal_value)));
    try put(object, "chunks", try env.createUint32(chunks));
    if (terminal_value == .failed) try put(object, "failure", try env.createStringUtf8(@tagName(terminal_value.failed)));
    return object;
}
pub fn settle(env: napi.Env, runtime: *Runtime) void {
    if (runtime.incoming == null) return;
    if (@import("network_incoming_faults.zig").holdSettlement(runtime)) return;
    runtime.retain();
    defer runtime.release();
    for (0..32) |i| {
        runtime.lock();
        const table = &runtime.incoming.?;
        if (i >= table.cells.len) {
            runtime.unlock();
            break;
        }
        const cell = &table.cells[i];
        if (cell.state == .free or cell.copying or cell.state == .response_preparing) {
            runtime.unlock();
            continue;
        }
        const pending = if (cell.ack != null) cell.pending else null;
        const closed = if (cell.terminal != null and !cell.native) cell.closed else null;
        if (pending == null and closed == null) {
            runtime.unlock();
            continue;
        }
        cell.copying = true;
        const ack = cell.ack;
        const terminal_value = cell.terminal;
        const chunks = cell.chunks;
        runtime.unlock();
        if (pending) |deferred| {
            if (ack.? == .sent) {
                deleteResults(&cell.results);
                cell.results = cell.next_results;
                cell.next_results = @splat(null);
            } else deleteResults(&cell.next_results);
            if (ack.? == .sent) deferred.resolve(env.getUndefined() catch unreachable) catch unreachable else deferred.reject(ackError(env, ack.?) catch runtime.copy_error.?.getValue() catch unreachable) catch unreachable;
        }
        if (closed) |deferred| {
            std.debug.assert(chunks == cell.chunks);
            const value = cell.results[resultIndex(terminal_value.?)].?.getValue() catch unreachable;
            deferred.resolve(value) catch unreachable;
            retireReferences(cell);
        }
        runtime.lock();
        cell.copying = false;
        if (pending != null) {
            cell.pending = null;
            cell.ack = null;
        }
        if (closed != null) cell.closed = null;
        table.releasePayload(cell);
        if (cell.terminal != null and !cell.native and cell.closed == null and cell.pending == null) table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        runtime.unlock();
    }
    runtime.lock();
    runtime.retireRequestStorageLocked();
    runtime.unlock();
    runtime.disposeTerminalReferences();
}
pub fn diagnostics(env: napi.Env, value: *const incoming.Diagnostics) !Value {
    const object = try env.createObject();
    inline for (@typeInfo(incoming.Diagnostics).@"struct".fields, 0..) |field, i| {
        try put(object, field.name, if (i >= 11) try env.createBigintUint64(@field(value, field.name)) else try env.createDouble(@floatFromInt(@field(value, field.name))));
    }
    return object;
}

fn rejectInput(env: napi.Env, reason: incoming.Rejection) anyerror {
    const value = ackError(env, .{ .rejected = reason }) catch |err| return err;
    env.throw(value) catch |err| return err;
    return error.PendingException;
}

fn resultIndex(terminal_value: incoming.Terminal) usize {
    return switch (terminal_value) {
        .served => 0,
        .closed => 1,
        .failed => |reason| 2 + @as(usize, @intFromEnum(reason)),
    };
}
fn prepareResults(env: napi.Env, refs: *incoming.ResultRefs, chunks: u32) !void {
    for (refs) |ref| std.debug.assert(ref == null);
    errdefer deleteResults(refs);
    for (0..refs.len) |i| {
        const terminal_value: incoming.Terminal = if (i == 0) .served else if (i == 1) .closed else .{ .failed = @enumFromInt(i - 2) };
        refs[i] = try napi.Ref.create(env.env, try closedValue(env, terminal_value, chunks), 1);
        const faults = @import("network_faults.zig");
        const stages = [_]faults.Stage{ .incoming_result_0, .incoming_result_1, .incoming_result_2, .incoming_result_3, .incoming_result_4, .incoming_result_5, .incoming_result_6, .incoming_result_7, .incoming_result_8 };
        try faults.check(stages[i]);
    }
}
fn deleteResults(refs: *incoming.ResultRefs) void {
    for (refs) |*ref| {
        if (ref.*) |value| value.delete() catch unreachable;
        ref.* = null;
    }
}
pub fn retireReferences(cell: *incoming.Cell) void {
    deleteResults(&cell.results);
    deleteResults(&cell.next_results);
}
