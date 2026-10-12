const js = @import("zapi:zapi").js;
const napi = @import("zapi:zapi").napi;
const n = @import("network");
const output = @import("network_js.zig");
const Runtime = @import("network_runtime.zig").Runtime;

pub fn drain(runtime: *Runtime) !js.Value {
    const capture = if (runtime.stream_capture) |*value| value else return error.StreamCaptureDisabled;
    const batch = capture.drain();
    errdefer capture.invalidate(batch.data.len);
    const env = js.env();
    const events = try env.createArrayWithLength(batch.events.len);
    const bytes = try env.createArrayBufferCopy(batch.data, null);
    for (batch.events, 0..) |*event, i| {
        const value = try env.createObject();
        try value.setNamedProperty("observedAtNs", try env.createBigintUint64(event.observed_at_ns));
        try value.setNamedProperty("type", try env.createStringUtf8(@tagName(event.payload)));
        switch (event.payload) {
            .connection => |*conn| {
                try value.setNamedProperty("id", try env.createBigintUint64(conn.id));
                try value.setNamedProperty("peerId", try output.bytes(env, &conn.peer.bytes));
                try value.setNamedProperty("remoteAddr", try address(env, conn.remote));
                try value.setNamedProperty("localAddr", try address(env, conn.local));
                try value.setNamedProperty("direction", try env.createStringUtf8(@tagName(conn.direction)));
            },
            .stream => |stream| {
                try value.setNamedProperty("id", try env.createBigintUint64(stream.id));
                try value.setNamedProperty("connection", try env.createBigintUint64(stream.connection));
                try value.setNamedProperty("protocol", try env.createStringUtf8(stream.protocol.id()));
                try value.setNamedProperty("direction", try env.createStringUtf8(@tagName(stream.direction)));
            },
            .data => |data| {
                try value.setNamedProperty("stream", try env.createBigintUint64(data.stream));
                try value.setNamedProperty("direction", try env.createStringUtf8(@tagName(data.direction)));
                try value.setNamedProperty("data", try env.createTypedarray(.uint8, data.length, bytes, data.offset));
            },
            .stream_closed => |closed| {
                try value.setNamedProperty("stream", try env.createBigintUint64(closed.stream));
                try value.setNamedProperty("reset", try env.getBoolean(closed.reset));
            },
            .connection_closed => |connection| try value.setNamedProperty("connection", try env.createBigintUint64(connection)),
        }
        try events.setElement(@intCast(i), value);
    }
    const result = try env.createObject();
    try result.setNamedProperty("events", events);
    try result.setNamedProperty("reset", try env.getBoolean(batch.reset));
    try result.setNamedProperty("pending", try env.getBoolean(batch.pending));
    try result.setNamedProperty("bufferedBytes", try env.createDouble(@floatFromInt(batch.buffered_bytes)));
    try result.setNamedProperty("droppedBytes", try env.createBigintUint64(batch.dropped_bytes));
    return .{ .val = result };
}

fn address(env: napi.Env, value: n.Address) !napi.Value {
    const addr: n.wire.multiaddr.Multiaddr = .{ .address = value };
    var buffer: [n.wire.multiaddr.text_length_max]u8 = undefined;
    return env.createStringUtf8(try addr.toText(&buffer));
}
