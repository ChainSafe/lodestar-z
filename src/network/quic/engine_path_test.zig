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

test "engine drops a routed packet that arrives from another source path" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.server.openStream(handles.server);
    _ = try pair.server.write(stream, "spoof", false);

    var out: [constants.datagram_size_max]u8 = undefined;
    const datagram = pair.server.driverView().send(0, pair.now, &out) orelse
        return error.TestUnexpectedResult;
    var copy: [constants.datagram_size_max]u8 = undefined;
    @memcpy(copy[0..datagram.len], datagram);

    const wrong_source = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_003 } };
    const before = pair.client.counters.dropped_unroutable;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.client.driverView().receive(
        copy[0..datagram.len],
        &wrong_source,
        &client_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, outcome);
    try std.testing.expectEqual(before + 1, pair.client.counters.dropped_unroutable);
}

test "engine survives an undecryptable packet routed to a live slot" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const scid = pair.client.slots[handles.client.index].scid;
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
        &client_address,
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
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.server, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
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
    const moved =
        try pair.transfer(&pair.server, &pair.client, server_address, client_address, false);
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
        &client_address,
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
            &client_address,
            pair.now,
            pair.nextPool(),
            &response,
        ),
    );
    try std.testing.expectEqual(before_unroutable + 1, pair.client.counters.dropped_unroutable);
}
