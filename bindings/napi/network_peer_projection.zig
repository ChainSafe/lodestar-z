const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const t = n.peers.types;
pub const Entry = struct { event: t.Event, sequence: u64 };
pub const Lane = struct {
    entries: [64]Entry = undefined,
    head: u8 = 0,
    len: u8 = 0,
    high_water: u8 = 0,
    pub fn publish(self: *Lane, events: []const t.Event, sequence: u64) void {
        std.debug.assert(events.len <= 64 - @as(usize, self.len));
        for (events) |event| {
            self.entries[(@as(usize, self.head) + self.len) % 64] = .{ .event = event, .sequence = sequence };
            self.len += 1;
        }
        self.high_water = @max(self.high_water, self.len);
    }
    pub fn peek(self: *const Lane, out: []Entry) usize {
        const count = @min(out.len, self.len);
        for (0..count) |i| out[i] = self.entries[(@as(usize, self.head) + i) % 64];
        return count;
    }
    pub fn commit(self: *Lane, count: usize) void {
        std.debug.assert(count <= self.len);
        self.head = @intCast((@as(usize, self.head) + count) % 64);
        self.len -= @intCast(count);
    }
};
pub fn put(object: Value, name: [:0]const u8, value: Value) !void {
    try object.defineProperties(&.{.{ .utf8name = name.ptr, .name = null, .method = null, .getter = null, .setter = null, .value = value.value, .attributes = napi.c.napi_default_jsproperty, .data = null }});
}
pub fn element(array: Value, index: usize, value: Value) !void {
    var buffer: [11]u8 = undefined;
    try put(array, try std.fmt.bufPrintZ(&buffer, "{d}", .{index}), value);
}
pub fn bytes(env: napi.Env, value: []const u8) !Value {
    return env.createTypedarray(.uint8, value.len, try env.createArrayBufferCopy(value, null), 0);
}
pub fn endpoint(env: napi.Env, value: n.Address) !Value {
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
fn reference(env: napi.Env, peer: t.PeerRef) !Value {
    const object = try env.createObject();
    try put(object, "index", try env.createUint32(peer.index));
    try put(object, "generation", try env.createBigintUint64(peer.generation));
    return object;
}
fn connection(env: napi.Env, handle: t.Handle) !Value {
    const object = try env.createObject();
    try put(object, "index", try env.createUint32(handle.index));
    try put(object, "generation", try env.createUint32(handle.generation));
    return object;
}
fn groups(env: napi.Env, set: ?n.peers.custody.Groups) !Value {
    const value = set orelse return env.getNull();
    const array = try env.createArrayWithLength(value.count());
    var count: usize = 0;
    for (0..128) |i| if (value.isSet(i)) {
        try element(array, count, try env.createUint32(@intCast(i)));
        count += 1;
    };
    return array;
}
fn status(env: napi.Env, value: *const t.Status) !Value {
    const object = try env.createObject();
    try put(object, "forkDigest", try bytes(env, &value.fork_digest));
    try put(object, "finalizedRoot", try bytes(env, &value.finalized_root));
    try put(object, "headRoot", try bytes(env, &value.head_root));
    try put(object, "finalizedEpoch", try env.createBigintUint64(value.finalized_epoch));
    try put(object, "headSlot", try env.createBigintUint64(value.head_slot));
    try put(object, "earliestAvailableSlot", if (value.earliest_available_slot) |slot| try env.createBigintUint64(slot) else try env.getNull());
    return object;
}
pub fn metadata(env: napi.Env, value: *const t.Metadata) !Value {
    const object = try env.createObject();
    try put(object, "sequenceNumber", try env.createBigintUint64(value.seq_number));
    try put(object, "attnets", try bytes(env, &value.attnets));
    try put(object, "syncnets", try env.createUint32(value.syncnets));
    try put(object, "custodyGroupCount", if (value.custody_group_count) |count| try env.createBigintUint64(count) else try env.getNull());
    return object;
}
fn identify(env: napi.Env, value: *const n.identify.Metadata) !Value {
    const object = try env.createObject();
    try put(object, "agent", if (value.agent) |*agent| try env.createStringUtf8(agent.slice()) else try env.getNull());
    try put(object, "protocolVersion", if (value.protocol_version) |*version| try env.createStringUtf8(version.slice()) else try env.getNull());
    const protocols = try env.createArrayWithLength(value.protocols.count());
    var index: usize = 0;
    for (0..n.capabilities.protocol_count) |i| {
        const protocol: n.router.Protocol = if (i < n.reqresp.Protocol.count) .{ .reqresp = @enumFromInt(i) } else if (i == n.capabilities.protocol_count - 1) .identify else .{ .meshsub = @enumFromInt(i - n.reqresp.Protocol.count) };
        if (value.protocols.contains(protocol)) {
            try element(protocols, index, try env.createStringUtf8(protocol.id()));
            index += 1;
        }
    }
    try put(object, "protocols", protocols);
    return object;
}
pub fn state(env: napi.Env, value: *const t.Snapshot, session: u64) !Value {
    const object = try env.createObject();
    try put(object, "session", try env.createBigintUint64(session));
    try put(object, "peer", try reference(env, value.peer));
    try put(object, "identity", try bytes(env, &value.identity.bytes));
    try put(object, "connection", if (value.connection) |handle| try connection(env, handle) else try env.getNull());
    try put(object, "direction", try env.createStringUtf8(@tagName(value.direction)));
    try put(object, "endpoint", try endpoint(env, value.endpoint));
    try put(object, "relevant", try env.getBoolean(value.relevant));
    try put(object, "disconnectReason", if (value.disconnect_reason) |reason| try env.createStringUtf8(@tagName(reason)) else try env.getNull());
    try put(object, "status", if (value.status) |*v| try status(env, v) else try env.getNull());
    try put(object, "metadata", if (value.metadata) |*v| try metadata(env, v) else try env.getNull());
    try put(object, "identify", if (value.identify) |*v| try identify(env, v) else try env.getNull());
    try put(object, "custodyGroups", try groups(env, value.custody_groups));
    try put(object, "samplingGroups", try groups(env, value.sampling_groups));
    try put(object, "direct", try env.getBoolean(value.direct));
    try put(object, "score", try env.createDouble(value.score));
    inline for (.{ .{ "statusAtMs", "status_at_ms" }, .{ "metadataAtMs", "metadata_at_ms" }, .{ "connectedAtMs", "connected_at_ms" }, .{ "banUntilMs", "ban_until_ms" }, .{ "goodbyeUntilMs", "goodbye_until_ms" } }) |pair|
        try put(object, pair[0], try env.createBigintUint64(@field(value, pair[1])));
    return object;
}
pub fn observation(env: napi.Env, entry: *const Entry, session: u64) !Value {
    const object = try env.createObject();
    try put(object, "type", try env.createStringUtf8(@tagName(entry.event)));
    try put(object, "ownerSequence", try env.createBigintUint64(entry.sequence));
    switch (entry.event) {
        .ready, .updated => |*value| try put(object, "state", try state(env, value, session)),
        .closed => |value| {
            try put(object, "session", try env.createBigintUint64(session));
            try put(object, "peer", try reference(env, value.peer));
            try put(object, "connection", try connection(env, value.connection));
            try put(object, "identity", try bytes(env, &value.identity.bytes));
            try put(object, "reason", try env.createStringUtf8(@tagName(value.reason)));
        },
    }
    return object;
}

test "production peer lane preserves closed generations at capacity" {
    var lane: Lane = .{};
    var events: [64]t.Event = undefined;
    const peer: n.PeerId = .{ .bytes = @splat(0) };
    for (&events, 0..) |*event, i| event.* = .{ .closed = .{ .peer = .{ .index = @intCast(i), .generation = std.math.maxInt(u64) - i }, .connection = .{ .index = @intCast(i), .generation = std.math.maxInt(u32) }, .identity = peer, .reason = .host } };
    lane.publish(&events, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u8, 64), lane.len);
    var copied: [64]Entry = undefined;
    try std.testing.expectEqual(@as(usize, 64), lane.peek(&copied));
    for (copied, 0..) |entry, i| {
        try std.testing.expectEqual(std.math.maxInt(u64) - i, entry.event.closed.peer.generation);
        try std.testing.expectEqual(std.math.maxInt(u32), entry.event.closed.connection.generation);
        try std.testing.expectEqual(std.math.maxInt(u64), entry.sequence);
    }
    lane.commit(32);
    lane.publish(events[0..32], 9);
    try std.testing.expectEqual(@as(usize, 64), lane.peek(&copied));
    try std.testing.expectEqual(@as(u16, 32), copied[0].event.closed.peer.index);
    try std.testing.expectEqual(@as(u64, 9), copied[32].sequence);
}

test "full production lane leaves catalog close pending until output resumes" {
    var catalog = try n.peers.Catalog.init(std.testing.allocator, .{ .capacity = 2, .outbound_reserve = 0, .target_peers = 1, .max_peers = 2, .min_outbound = 0, .engine_capacity = 2 });
    defer catalog.deinit(std.testing.allocator);
    const local_key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    const remote_key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{2}));
    const local = n.PeerId.fromPublicKey(&local_key.publicKey());
    const remote = n.PeerId.fromPublicKey(&remote_key.publicKey());
    const handle: t.Handle = .{ .index = 0, .generation = 7 };
    const peer = catalog.admit(&remote, &local, handle, &.{ .direction = .outbound, .endpoint = .unspecified, .now_ms = 0 }).admitted.peer;
    var lane: Lane = .{};
    var output: [64]t.Event = undefined;
    for (0..64) |i| {
        try std.testing.expect(catalog.updateStatus(peer, handle, &.{ .head_slot = i }, i));
        const count = catalog.pollEvents(output[0 .. 64 - lane.len]);
        try std.testing.expectEqual(@as(usize, 1), count);
        lane.publish(output[0..count], i + 1);
    }
    try std.testing.expect(catalog.disconnect(peer, handle, .host, 100));
    try std.testing.expectEqual(@as(usize, 0), catalog.pollEvents(output[0 .. 64 - lane.len]));
    try std.testing.expect(catalog.eventsPending());
    lane.commit(64);
    const count = catalog.pollEvents(&output);
    try std.testing.expectEqual(@as(usize, 1), count);
    lane.publish(output[0..count], 65);
    var copied: [1]Entry = undefined;
    _ = lane.peek(&copied);
    try std.testing.expectEqual(handle, copied[0].event.closed.connection);
    try std.testing.expectEqual(peer, copied[0].event.closed.peer);
}
