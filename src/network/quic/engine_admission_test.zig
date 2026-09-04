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
    return pair.sendOne(&pair.client, handle.index, out) orelse error.TestUnexpectedResult;
}

fn rejectPort(context: ?*anyopaque, from: *const types.Address) bool {
    const blocked: *const u16 = @ptrCast(@alignCast(context.?));
    return from.port() != blocked.*;
}

test "engine consults the admission predicate before opening an inbound slot" {
    var blocked: u16 = client_address.port();
    var pair: Pair = .{};
    try pair.init(.{}, .{ .admit = rejectPort, .admit_context = @ptrCast(&blocked) });
    defer pair.deinit();

    _ = try pair.dial();
    try pair.pump();
    try std.testing.expect(pair.server.counters.dropped_rejected >= 1);
    try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().activeIndices().len);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);

    blocked = 0;
    _ = try pair.dial();
    try pair.pump();
    var storage: [8]Event = undefined;
    var connected = false;
    for (pair.events(&pair.server, &storage)) |event| {
        if (event == .connected) connected = true;
    }
    try std.testing.expect(connected);
    try std.testing.expectEqual(@as(usize, 1), pair.server.driverView().activeIndices().len);
}

fn countCalls(context: ?*anyopaque, _: *const types.Address) bool {
    const calls: *u32 = @ptrCast(@alignCast(context.?));
    calls.* += 1;
    return true;
}

test "engine consults the admission predicate once per new Initial and never for routed traffic" {
    var calls: u32 = 0;
    var pair: Pair = .{};
    try pair.init(.{}, .{ .admit = countCalls, .admit_context = @ptrCast(&calls) });
    defer pair.deinit();
    const handles = try connectPair(&pair);
    try std.testing.expectEqual(@as(u32, 1), calls);

    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(@as(usize, 5), try pair.client.write(stream, "hello", false));
    try pair.pump();
    var storage: [8]Event = undefined;
    const inbound = try support.expectStreamOpened(pair.events(&pair.server, &storage)[0], handles.server);
    var buffer: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), (try pair.server.read(inbound, &buffer)).len);
    try std.testing.expectEqual(@as(u32, 1), calls);

    var replay: [constants.datagram_size_max]u8 = undefined;
    @memcpy(replay[0..pair.first_initial_len], pair.first_initial[0..pair.first_initial_len]);
    var response: [constants.datagram_size_max]u8 = undefined;
    _ = pair.server.driverView().receive(
        replay[0..pair.first_initial_len],
        &client_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    try std.testing.expectEqual(@as(u32, 1), calls);
    try std.testing.expectEqual(@as(usize, 0), pair.client.counters.dropped_rejected);
}

test "engine bounds concurrent dials and outbound connections" {
    var pair: Pair = .{};
    try pair.init(.{ .dialing_max = 2, .outbound_max = 3 }, .{ .handshaking_per_source_max = 8 });
    defer pair.deinit();

    _ = try pair.dial();
    _ = try pair.dial();
    try std.testing.expectError(error.DialLimit, pair.dial());
    try std.testing.expectEqual(@as(u16, 2), pair.client.registry.dialing);
    try std.testing.expectEqual(@as(u16, 2), pair.client.registry.outbound);

    try pair.pump();
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.dialing);
    try std.testing.expectEqual(@as(u16, 2), pair.client.registry.outbound);
    const third = try pair.dial();
    try std.testing.expectError(error.DialLimit, pair.dial());
    try pair.pump();
    try std.testing.expectEqual(@as(u16, 3), pair.client.registry.outbound);

    _ = pair.client.close(third, 0);
    try pair.pump();
    var storage: [16]engine_mod.Event = undefined;
    _ = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(u16, 2), pair.client.registry.outbound);
    _ = try pair.dial();
    try std.testing.expectEqual(@as(u16, 3), pair.client.registry.outbound);
    try std.testing.expectEqual(@as(u16, 1), pair.client.registry.dialing);
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
    try std.testing.expectEqual(
        engine_mod.CloseReason.handshake_timeout,
        try expectClosed(client_events[0], second, .outbound, null),
    );
    try std.testing.expectError(error.TableFull, pair.server.dial(
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
    try std.testing.expectEqual(limits.handshaking_per_source_max, pair.server.registry.handshaking);

    const elsewhere = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 4_001 } };
    const other = try dialInitial(&pair, &packet);
    const foreign = pair.server.driverView().receive(
        other,
        &elsewhere,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (foreign) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(limits.handshaking_per_source_max + 1, pair.server.registry.handshaking);
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
            pair.now,
            &stale,
            &response,
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_no_entropy);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);

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
        pair.now,
        pair.nextPool(),
        &response,
    ));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_unroutable);

    var tiny = [_]u8{ 0xc3, 0, 0, 0, 1, 0x08 } ++ [_]u8{0xaa} ** 8 ++ [_]u8{0x04} ++ [_]u8{0xbb} ** 4 ++ [_]u8{0x00};
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.driverView().receive(
        &tiny,
        &client_address,
        pair.now,
        pair.nextPool(),
        &response,
    ));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_short_initial);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
}

test "engine wakeup includes host handshake deadline before native timeout" {
    var pair: Pair = .{};
    try pair.init(.{ .handshake_timeout_ms = 1 }, .{});
    defer pair.deinit();
    _ = try pair.dial();
    const deadline = pair.client.driverView().nextTimeoutMs(pair.now);
    try std.testing.expect(deadline != null);
    try std.testing.expect(deadline.? <= 1);
}

test "engine rejects zero requested receive window budget" {
    var pair: Pair = .{};
    if (pair.init(.{ .receive_budget_bytes = 0 }, .{})) |_| {
        pair.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.InvalidLimits, err);
}

test "engine retains a live routed stream across unrelated slot churn" {
    var pair: Pair = .{};
    try pair.init(.{ .connections_max = 4, .handshaking_max = 4 }, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);
    for (0..256) |_| {
        const transient = try pair.dial();
        try std.testing.expect(pair.client.abandon(transient));
    }
    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(@as(usize, 4), try pair.client.write(stream, "live", false));
    try pair.pump();
    var events: [8]Event = undefined;
    const inbound = try support.expectStreamOpened(pair.events(&pair.server, &events)[0], handles.server);
    var bytes: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), (try pair.server.read(inbound, &bytes)).len);
    try std.testing.expectEqualStrings("live", &bytes);
    try std.testing.expectEqual(handles.client, pair.client.findByPeerId(&pair.server_ctx.local_peer_id).?);
}

test "engine resolved memory plan reports clamped receive windows and scheduled storage" {
    var pair: Pair = .{};
    try pair.init(.{ .connections_max = 1024 }, .{});
    defer pair.deinit();
    const plan = pair.client.memoryPlan();
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), plan.receive_window_bytes);
    try std.testing.expectEqual(@as(u16, 1024), plan.scheduled_datagrams);
    try std.testing.expectEqual(@as(u64, 1024 * constants.datagram_size_max), plan.scheduled_payload_bytes);
    try std.testing.expect(plan.scheduled_storage_bytes >= plan.scheduled_payload_bytes);
    try std.testing.expect(plan.receive_window_bytes > plan.requested_receive_window_bytes);
}

test "engine rejects native timeout overflow and zero scheduling limits" {
    const invalid = [_]engine_mod.Limits{
        .{ .idle_timeout_ms = std.math.maxInt(u64) },
        .{ .send_per_step_max = 0 },
        .{ .receive_per_step_max = 0 },
        .{ .work_per_step_max = 1 },
    };
    for (invalid) |options| {
        var pair: Pair = .{};
        if (pair.init(options, .{})) |_| {
            pair.deinit();
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expectEqual(error.InvalidLimits, err);
    }
}

test "engine wakeup includes keepalive and uses the supplied current time" {
    var pair: Pair = .{};
    try pair.init(.{ .keep_alive_ms = 7 }, .{});
    defer pair.deinit();
    _ = try connectPair(&pair);
    const before = pair.client.driverView().nextTimeoutMs(pair.now).?;
    try std.testing.expect(before <= 7);
    pair.advance(7);
    try std.testing.expectEqual(@as(?u64, 0), pair.client.driverView().nextTimeoutMs(pair.now));
}

test "engine outgoing descriptor preserves native monotonic pacing timestamp" {
    const binding = @import("binding.zig");
    if (!binding.native_pacing_supported) return error.SkipZigTest;
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const before = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
    const handle = try pair.dial();
    var batch: engine_mod.SendBatch = .{};
    const count = pair.client.driverView().sendBatch(handle.index, pair.now, &batch);
    const after = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
    try std.testing.expect(count > 0);
    try std.testing.expect(batch.sent[0].transmit_at_ns >= before);
    try std.testing.expect(batch.sent[0].transmit_at_ns <= after);
}

fn allocateRegistry(allocator: std.mem.Allocator) !void {
    var registry = try @import("registry.zig").Registry.init(allocator, 4, true, 42);
    defer registry.deinit(allocator);
}

test "engine registry cleans every partial startup allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocateRegistry, .{});
}
