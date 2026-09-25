const std = @import("std");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;

/// The promise has not escaped to JavaScript; teardown may reclaim it without settlement.
pub fn discardPromise(env: napi.Env, deferred: napi.Deferred) void {
    const value = env.getUndefined() catch return;
    deferred.resolve(value) catch {};
}

/// An error whose `message` and own `code` are `code`, created without running host code: N-API assigns a code
/// argument through inherited setters, so the code is defined as an own property instead.
pub fn errorValue(env: napi.Env, code: []const u8) !Value {
    const message = try env.createStringUtf8(code);
    const value = try env.createError(.{ .env = env.env, .value = null }, message);
    try put(value, "code", message);
    return value;
}

/// Drops the stack V8 captured for a settled error, whose frames would retain the settling drain, and through it
/// the runtime facade, while the host holds the error. `created` comes from `errorValue` and was not yet exposed
/// to host code, so its own `message` and `stack` properties are V8's, and reading or assigning them runs no host
/// code.
pub fn settled(env: napi.Env, created: anyerror!Value) !Value {
    const value = try created;
    var buffer: [128]u8 = undefined;
    const prefix = "Error: ";
    @memcpy(buffer[0..prefix.len], prefix);
    const message = try (try value.getNamedProperty("message")).getValueStringUtf8(buffer[prefix.len..]);
    try value.setNamedProperty("stack", try env.createStringUtf8(buffer[0 .. prefix.len + message.len]));
    return value;
}

/// Copies result fields without invoking inherited setters.
pub fn put(object: Value, name: [:0]const u8, value: Value) !void {
    try object.defineProperties(&.{.{
        .utf8name = name.ptr,
        .name = null,
        .method = null,
        .getter = null,
        .setter = null,
        .value = value.value,
        .attributes = napi.c.napi_default_jsproperty,
        .data = null,
    }});
}

pub fn element(array: Value, index: usize, value: Value) !void {
    var buffer: [11]u8 = undefined;
    try put(array, try std.fmt.bufPrintZ(&buffer, "{d}", .{index}), value);
}

pub fn bytes(env: napi.Env, value: []const u8) !Value {
    return env.createTypedarray(.uint8, value.len, try env.createArrayBufferCopy(value, null), 0);
}

pub fn peerIdValue(env: napi.Env, identity: *const @import("network").PeerId) !Value {
    var text: [@import("network").wire.peer_id.text_length_max]u8 = undefined;
    return env.createStringUtf8(identity.toText(&text));
}

pub fn endpoint(env: napi.Env, value: @import("network").Address) !Value {
    const object = try env.createObject();
    switch (value) {
        inline else => |ip, tag| {
            try put(object, "family", try env.createUint32(if (tag == .ip4) 4 else 6));
            try put(object, "address", try bytes(env, &ip.octets));
            try put(object, "port", try env.createUint32(ip.port));
        },
    }
    return object;
}

pub fn scalarFields(env: napi.Env, value: anytype) !napi.Value {
    const fields = @typeInfo(@TypeOf(value.*)).@"struct".fields;
    comptime std.debug.assert(fields.len <= 64);
    const object = try env.createObject();
    inline for (fields) |field| {
        const copied: ?napi.Value = switch (@typeInfo(field.type)) {
            .int => if (field.type == u64) try env.createBigintUint64(@field(value, field.name)) else try env.createDouble(@floatFromInt(@field(value, field.name))),
            .float => try env.createDouble(@field(value, field.name)),
            else => null,
        };
        if (copied) |item| try put(object, field.name ++ "\x00", item);
    }
    return object;
}
