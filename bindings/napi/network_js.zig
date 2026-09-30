const napi = @import("zapi:zapi").napi;
const Value = napi.Value;

/// An error whose `message` and `code` are `code`.
pub fn errorValue(env: napi.Env, code: []const u8) !Value {
    const message = try env.createStringUtf8(code);
    return env.createError(message, message);
}

/// Drops the stack V8 captured for a settled error, whose frames would retain the settling drain, and through it
/// the runtime facade, while the host holds the error. `created` comes from `errorValue`.
pub fn settled(env: napi.Env, created: anyerror!Value) !Value {
    const value = try created;
    var buffer: [128]u8 = undefined;
    const prefix = "Error: ";
    @memcpy(buffer[0..prefix.len], prefix);
    const message = try (try value.getNamedProperty("message")).getValueStringUtf8(buffer[prefix.len..]);
    try value.setNamedProperty("stack", try env.createStringUtf8(buffer[0 .. prefix.len + message.len]));
    return value;
}

/// An operation cell's `{index, generation}` handle.
pub fn handle(env: napi.Env, index: u32, generation: u64) !Value {
    const object = try env.createObject();
    try object.setNamedProperty("index", try env.createUint32(index));
    try object.setNamedProperty("generation", try env.createBigintUint64(generation));
    return object;
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
            try object.setNamedProperty("family", try env.createUint32(if (tag == .ip4) 4 else 6));
            try object.setNamedProperty("address", try bytes(env, &ip.octets));
            try object.setNamedProperty("port", try env.createUint32(ip.port));
        },
    }
    return object;
}
