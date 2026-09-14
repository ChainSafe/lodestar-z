const std = @import("std");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;

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
