const std = @import("std");
const constants = @import("../constants.zig");
const engine_mod = @import("engine.zig");
const limits = @import("limits.zig");
const support = @import("../test_support.zig");
const types = @import("../types.zig");

const Pair = support.Pair;
const client_address = support.client_address;
const server_address = support.server_address;
const connectPair = support.connectPair;

const rebound_address = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_003 } };
const bulk = [_]u8{0x5a} ** 2_000;

fn expectPathChanged(event: engine_mod.Event, conn: engine_mod.Handle) !types.Address {
    switch (event) {
        .path_changed => |changed| {
            try std.testing.expectEqual(conn, changed.conn);
            return changed.peer;
        },
        else => return error.TestUnexpectedResult,
    }
}

fn readAll(engine: *engine_mod.Engine, stream: engine_mod.StreamHandle, sink: []u8) !usize {
    var total: usize = 0;
    var reads: usize = 0;
    while (reads < 16 and total < sink.len) : (reads += 1) {
        const read = try engine.read(stream, sink[total..]);
        if (read.len == 0) break;
        total += read.len;
    }
    return total;
}

test "engine validates a routed packet that arrives from another source path" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);
    var storage: [8]engine_mod.Event = undefined;

    pair.client_source = rebound_address;
    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(bulk.len, try pair.client.write(stream, &bulk, false));
    try pair.pump();

    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.path_changes);
    try std.testing.expectEqual(rebound_address, pair.server.peerAddress(handles.server).?);
    const events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqual(rebound_address, try expectPathChanged(events[0], handles.server));
    const inbound = try support.expectStreamOpened(events[1], handles.server);

    var sink: [bulk.len]u8 = undefined;
    try std.testing.expectEqual(bulk.len, try readAll(&pair.server, inbound, &sink));
    try std.testing.expectEqualSlices(u8, &bulk, &sink);
    try std.testing.expectEqual(@as(usize, 5), try pair.server.write(inbound, "world", false));
    try pair.pump();
    var reply: [16]u8 = undefined;
    const echoed = try pair.client.read(stream, &reply);
    try std.testing.expectEqualStrings("world", reply[0..echoed.len]);
    try std.testing.expectEqual(@as(u64, 0), pair.client.counters.path_changes);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.server, &storage).len);
}

test "engine keeps the validated path when a new source fails validation" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);
    var storage: [8]engine_mod.Event = undefined;

    pair.client_source = rebound_address;
    pair.drop_to_address = rebound_address;
    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(bulk.len, try pair.client.write(stream, &bulk, false));

    var inbound: ?engine_mod.StreamHandle = null;
    var rounds: usize = 0;
    while (rounds < 20) : (rounds += 1) {
        try pair.pump();
        pair.advance(100);
        for (pair.events(&pair.server, &storage)) |event| switch (event) {
            .path_changed => return error.TestUnexpectedResult,
            .stream_opened => |opened| inbound = opened,
            else => {},
        };
        try std.testing.expectEqual(client_address, pair.server.peerAddress(handles.server).?);
    }
    try std.testing.expect(inbound != null);
    try std.testing.expectEqual(@as(u64, 0), pair.server.counters.path_changes);

    pair.client_source = client_address;
    pair.drop_to_address = null;
    try std.testing.expectEqual(@as(usize, 3), try pair.client.write(stream, "bye", false));
    try pair.pump();
    var sink: [bulk.len + 3]u8 = undefined;
    try std.testing.expectEqual(sink.len, try readAll(&pair.server, inbound.?, &sink));
    try std.testing.expectEqualSlices(u8, &bulk, sink[0..bulk.len]);
    try std.testing.expectEqualStrings("bye", sink[bulk.len..]);
    try std.testing.expectEqual(client_address, pair.server.peerAddress(handles.server).?);
    try std.testing.expect(pair.server.peerId(handles.server) != null);
    for (pair.events(&pair.server, &storage)) |event| {
        try std.testing.expect(event != .path_changed);
        try std.testing.expect(event != .closed);
    }
}

test "engine survives an undecryptable packet routed to a live slot" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const scid = pair.client.registry.slots[handles.client.index].scid;
    var garbage: [1 + limits.local_cid_length + 32]u8 = undefined;
    garbage[0] = 0x40;
    @memcpy(garbage[1..][0..limits.local_cid_length], scid.slice());
    for (garbage[1 + limits.local_cid_length ..], 0..) |*byte, index| byte.* = @truncate(index *% 7 +% 3);

    const before_errors = pair.client.counters.recv_errors;
    const before_accepted = pair.client.counters.accepted;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.client.driverView().receive(
        &garbage,
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.client, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(before_errors, pair.client.counters.recv_errors);
    try std.testing.expectEqual(before_accepted + 1, pair.client.counters.accepted);
    try std.testing.expect(pair.client.peerId(handles.client) != null);
}

test "engine routes a replayed client Initial to the existing connection" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    try std.testing.expect(pair.first_initial_len >= limits.client_initial_min);
    var replay: [constants.datagram_size_max]u8 = undefined;
    @memcpy(replay[0..pair.first_initial_len], pair.first_initial[0..pair.first_initial_len]);

    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.server.driverView().receive(
        replay[0..pair.first_initial_len],
        &client_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.server, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
    try std.testing.expectEqual(@as(usize, 1), pair.server.driverView().activeIndices().len);
}

test "engine activity marks the slots that received datagrams" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    var taken: [4]engine_mod.Handle = undefined;
    var drains: usize = 0;
    while (drains < 8 and pair.client.driverView().takeActivity(&taken) > 0) : (drains += 1) {}
    try std.testing.expect(!pair.client.driverView().activityPending());

    const stream = try pair.server.openStream(handles.server);
    _ = try pair.server.write(stream, "x", false);
    const moved = try pair.transfer(&pair.server, &pair.client, server_address, false);
    try std.testing.expect(moved);

    try std.testing.expect(pair.client.driverView().activityPending());
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().takeActivity(taken[0..0]));
    try std.testing.expectEqual(@as(usize, 1), pair.client.driverView().takeActivity(&taken));
    try std.testing.expectEqual(handles.client, taken[0]);
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().takeActivity(&taken));
    try std.testing.expect(!pair.client.driverView().activityPending());
}

test "engine feeds an unrouted short header from a known peer to its slot" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    var reset: [1 + limits.local_cid_length + 24]u8 = undefined;
    reset[0] = 0x40;
    for (reset[1..], 0..) |*byte, index| byte.* = @truncate(index *% 37 +% 11);

    const before_unroutable = pair.client.counters.dropped_unroutable;
    const before_touched = pair.client.counters.accepted + pair.client.counters.recv_errors;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.client.driverView().receive(
        &reset,
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.client, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(before_unroutable, pair.client.counters.dropped_unroutable);
    try std.testing.expectEqual(
        before_touched + 1,
        pair.client.counters.accepted + pair.client.counters.recv_errors,
    );

    const stranger = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 9 }, .port = 4_009 } };
    try std.testing.expectEqual(
        engine_mod.ReceiveOutcome.dropped,
        pair.client.driverView().receive(
            &reset,
            &stranger,
            pair.now,
            pair.nextPool(),
            &response,
        ),
    );
    try std.testing.expectEqual(before_unroutable + 1, pair.client.counters.dropped_unroutable);
}
