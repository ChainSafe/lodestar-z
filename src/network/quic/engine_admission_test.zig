const std = @import("std");
const constants = @import("../constants.zig");
const engine_mod = @import("engine.zig");
const limits = @import("limits.zig");
const support = @import("../test_support.zig");
const types = @import("../types.zig");

const Event = engine_mod.Event;
const Pair = support.Pair;
const client_address = support.client_address;
const server_address = support.server_address;
const connectPair = support.connectPair;
const expectClosed = support.expectClosed;

fn dialInitial(pair: *Pair, out: []u8) ![]u8 {
    const handle = try pair.dial();
    var scratch: [constants.datagram_size_max]u8 = undefined;
    const datagram = pair.client.driverView().send(handle.index, pair.now, &scratch) orelse
        return error.TestUnexpectedResult;
    @memcpy(out[0..datagram.len], datagram);
    return out[0..datagram.len];
}

test "engine drops new handshakes when the server table is full" {
    var pair: Pair = .{};
    try pair.init(.{ .connections_max = 4, .handshaking_max = 4, .handshake_timeout_ms = 100 }, .{ .connections_max = 1, .handshaking_max = 1 });
    defer pair.deinit();
    _ = try connectPair(&pair);

    const second = try pair.dial();
    try pair.pump();
    try std.testing.expect(pair.server.counters.dropped_full > 0);
    pair.advance(100);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(engine_mod.CloseReason.handshake_timeout, try expectClosed(client_events[0], second));
    try std.testing.expectError(error.TableFull, pair.server.dial(
        &server_address,
        &client_address,
        pair.client_ctx.local_peer_id,
        pair.now,
        pair.nextEntropy(),
    ));
}

test "engine caps inbound handshakes per source address" {
    var pair: Pair = .{};
    try pair.init(
        .{ .connections_max = 8, .handshaking_max = 8 },
        .{ .connections_max = 8, .handshaking_max = 8 },
    );
    defer pair.deinit();

    var response: [constants.datagram_size_max]u8 = undefined;
    var packet: [constants.datagram_size_max]u8 = undefined;
    var admitted: u16 = 0;
    var attempt: u16 = 0;
    while (attempt < limits.handshaking_per_source_max + 1) : (attempt += 1) {
        const initial = try dialInitial(&pair, &packet);
        try std.testing.expect(initial.len >= limits.client_initial_min);
        const outcome = pair.server.driverView().receive(
            initial,
            &client_address,
            &server_address,
            pair.now,
            pair.nextPool(),
            &response,
        );
        switch (outcome) {
            .accepted => admitted += 1,
            else => {},
        }
    }

    try std.testing.expectEqual(limits.handshaking_per_source_max, admitted);
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_source_limit);
    try std.testing.expectEqual(limits.handshaking_per_source_max, pair.server.handshaking);

    const elsewhere = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 4_001 } };
    const other = try dialInitial(&pair, &packet);
    const foreign = pair.server.driverView().receive(
        other,
        &elsewhere,
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (foreign) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(limits.handshaking_per_source_max + 1, pair.server.handshaking);
}

test "engine drops an inbound Initial when the entropy pool is stale" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    var packet: [constants.datagram_size_max]u8 = undefined;
    const initial = try dialInitial(&pair, &packet);

    var stale = engine_mod.EntropyPool{};
    try std.testing.expect(stale.take() == null);
    var response: [constants.datagram_size_max]u8 = undefined;
    try std.testing.expectEqual(
        engine_mod.ReceiveOutcome.dropped,
        pair.server.driverView().receive(
            initial,
            &client_address,
            &server_address,
            pair.now,
            &stale,
            &response,
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_no_entropy);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);

    try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().activeIndices().len);
}

test "engine drops version negotiation packets instead of reflecting them" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    var packet = [_]u8{0} ** limits.client_initial_min;
    packet[0] = 0xc0;
    packet[5] = 0x08;
    @memset(packet[6..14], 0xaa);
    packet[14] = 0x05;
    @memset(packet[15..20], 0xbb);

    var response: [constants.datagram_size_max]u8 = undefined;
    const before = pair.server.counters.dropped_unroutable;
    try std.testing.expectEqual(
        engine_mod.ReceiveOutcome.dropped,
        pair.server.driverView().receive(
            &packet,
            &client_address,
            &server_address,
            pair.now,
            pair.nextPool(),
            &response,
        ),
    );
    try std.testing.expectEqual(before + 1, pair.server.counters.dropped_unroutable);
    try std.testing.expectEqual(@as(u64, 0), pair.server.counters.version_negotiations);
}

test "engine answers unsupported versions and drops unroutable packets" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    var initial = [_]u8{0} ** limits.client_initial_min;
    initial[0] = 0xc3;
    initial[1] = 0xba;
    initial[2] = 0xba;
    initial[3] = 0xba;
    initial[4] = 0xba;
    initial[5] = 0x08;
    @memset(initial[6..14], 0xaa);
    initial[14] = 0x04;
    @memset(initial[15..19], 0xbb);
    initial[19] = 0x00;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.server.driverView().receive(
        &initial,
        &client_address,
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .version_negotiation => |bytes| try std.testing.expect(bytes.len > 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.version_negotiations);

    var short = [_]u8{0x40} ++ [_]u8{0xcc} ** limits.local_cid_length ++ [_]u8{0} ** 20;
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.driverView().receive(
        &short,
        &client_address,
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    ));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_unroutable);

    var tiny = [_]u8{ 0xc3, 0, 0, 0, 1, 0x08 } ++ [_]u8{0xaa} ** 8 ++ [_]u8{0x04} ++ [_]u8{0xbb} ** 4 ++ [_]u8{0x00};
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.driverView().receive(
        &tiny,
        &client_address,
        &server_address,
        pair.now,
        pair.nextPool(),
        &response,
    ));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_short_initial);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
}
