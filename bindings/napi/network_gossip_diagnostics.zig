const std = @import("std");
const napi = @import("zapi:zapi").napi;
const d = @import("network").gossipsub.diagnostics;
const Value = napi.Value;
const projection = @import("network_peer_projection.zig");

fn put(object: Value, comptime name: [:0]const u8, value: Value) !void {
    try object.defineProperties(&.{.{ .utf8name = name.ptr, .name = null, .method = null, .getter = null, .setter = null, .value = value.value, .attributes = napi.c.napi_default_jsproperty, .data = null }});
}
fn bytes(env: napi.Env, value: []const u8) !Value {
    const buffer = try env.createArrayBufferCopy(value, null);
    return env.createTypedarray(.uint8, value.len, buffer, 0);
}
fn weights(env: napi.Env, value: anytype) !Value {
    const object = try env.createObject();
    inline for (std.meta.fields(@TypeOf(value.*))) |field| try put(object, field.name, try env.createDouble(@field(value, field.name)));
    return object;
}

pub fn copy(env: napi.Env, page: *const d.Page) !Value {
    const object = try env.createObject();
    try put(object, "observedMonoMs", try env.createBigintUint64(page.mono_ms));
    try put(object, "observedUnixMs", try env.createBigintInt64(page.unix_s *| 1000));
    try put(object, "nextCursor", if (page.next) |next| try env.createUint32(next) else try env.getNull());
    const topics = try env.createArrayWithLength(page.topic_count);
    for (page.topics[0..page.topic_count], 0..) |*topic, i| {
        const row = try env.createObject();
        try put(row, "index", try env.createUint32(topic.index));
        try put(row, "topic", try env.createStringUtf8(topic.name[0..topic.len]));
        try put(row, "subscribed", try env.getBoolean(topic.subscribed));
        try put(row, "weight", try env.createDouble(topic.weight));
        try put(row, "meshDeliveryActivationMs", try env.createBigintUint64(topic.mesh_activation_ms));
        try projection.element(topics, i, row);
    }
    try put(object, "topics", topics);
    const peers = try env.createArrayWithLength(page.peer_count);
    for (page.peers[0..page.peer_count], 0..) |*peer, i| {
        const row = try env.createObject();
        try put(row, "identity", try bytes(env, &peer.identity.bytes));
        try put(row, "ip", try bytes(env, &peer.address));
        try put(row, "connected", try env.getBoolean(peer.connected));
        try put(row, "outboundReady", try env.getBoolean(peer.outbound_ready));
        try put(row, "expireAtMs", try env.createBigintUint64(peer.retain_until));
        try put(row, "score", try env.createDouble(peer.score));
        try put(row, "appScore", try env.createDouble(peer.app_score));
        try put(row, "behaviourPenalty", try env.createDouble(peer.behaviour));
        try put(row, "weights", try weights(env, &peer.weights));
        const scores = try env.createArrayWithLength(peer.topic_count);
        for (peer.topics[0..peer.topic_count], 0..) |*entry, j| {
            const stats = try env.createObject();
            try put(stats, "index", try env.createUint32(entry.index));
            try put(stats, "inMesh", try env.getBoolean(entry.counters.in_mesh));
            try put(stats, "meshMember", try env.getBoolean(entry.mesh_member));
            try put(stats, "graftTimeMs", try env.createBigintUint64(entry.counters.graft_ms));
            try put(stats, "meshTimeMs", try env.createBigintUint64(if (entry.counters.in_mesh) page.mono_ms -| entry.counters.graft_ms else 0));
            try put(stats, "firstMessageDeliveries", try env.createDouble(entry.counters.first_deliveries));
            try put(stats, "meshMessageDeliveries", try env.createDouble(entry.counters.mesh_deliveries));
            try put(stats, "meshFailurePenalty", try env.createDouble(entry.counters.mesh_failures));
            try put(stats, "invalidMessageDeliveries", try env.createDouble(entry.counters.invalid));
            try put(stats, "weights", try weights(env, &entry.weights));
            try projection.element(scores, j, stats);
        }
        try put(row, "topics", scores);
        try projection.element(peers, i, row);
    }
    try put(object, "peers", peers);
    return object;
}
