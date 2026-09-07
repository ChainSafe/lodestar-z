const std = @import("std");
const support = @import("../test_support.zig");
const service_mod = @import("../service.zig");
const engine_mod = @import("../quic/engine.zig");
const identify = @import("root.zig");

fn step(pair: *support.Pair, service: *service_mod.Service, server: bool, results: []identify.Result) usize {
    const engine = if (server) &pair.server else &pair.client;
    var events: [64]engine_mod.Event = undefined;
    var activity: [128]engine_mod.Handle = undefined;
    const count = engine.driverView().takeActivity(&activity);
    return service.processOutputs(engine, pair.events(engine, &events), activity[0..count], pair.now, .{ .identify = results }).identify;
}

fn options(agent: []const u8) service_mod.Options {
    return .{ .automatic_gossip_admission = false, .reqresp = .{ .forks = &.{} }, .gossipsub = .{ .random_seed = 1 }, .identify = .{ .agent = agent, .inbound_max = 1, .outbound_max = 1 } };
}

test "identify blocked responder finishes immutable advertisement while new requests observe updates" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    @import("../quic/binding.zig").c.quiche_config_set_initial_max_stream_data_bidi_local(pair.client.config.ptr, 96);
    const handles = try support.connectPair(&pair);
    var client = try service_mod.Service.init(std.testing.allocator, options("client"));
    defer client.deinit();
    var server = try service_mod.Service.init(std.testing.allocator, options("old"));
    defer server.deinit();
    try client.identify.?.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    var blocked = false;
    for (0..16) |_| {
        _ = step(&pair, &client, false, &.{});
        try pair.pump();
        _ = step(&pair, &server, true, &.{});
        if (server.identify.?.inbound[0].stream != null) {
            blocked = true;
            break;
        }
        try pair.pump();
    }
    try std.testing.expect(blocked);
    const inbound = &server.identify.?.inbound[0];
    try std.testing.expect(inbound.outbox.offset > 0 and inbound.outbox.offset < inbound.outbox.bytes.len);
    var retained: [8194]u8 = undefined;
    const length = inbound.outbox.bytes.len;
    @memcpy(retained[0..length], inbound.outbox.bytes);
    const deadline = inbound.deadline;
    server.identify.?.local.?.agent = try .init("new");
    try server.identify.?.local.?.setAddresses(&.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19001 } }});
    var active = server.router.capabilities();
    active.receive = .initEmpty();
    active.receive.insert(.identify);
    try server.router.validateCapabilities(active);
    server.router.setCapabilities(active);
    try std.testing.expectEqualSlices(u8, retained[0..length], inbound.outbox.bytes);
    try std.testing.expectEqual(deadline, inbound.deadline);
    var results: [1]identify.Result = undefined;
    var completed = false;
    for (0..256) |_| {
        try pair.pump();
        if (step(&pair, &client, false, &results) == 1) {
            completed = true;
            break;
        }
        _ = step(&pair, &server, true, &.{});
    }
    try std.testing.expect(completed);
    try std.testing.expectEqual(.success, std.meta.activeTag(results[0].outcome));
    try std.testing.expectEqualStrings("old", results[0].outcome.success.agent.?.slice());
    try std.testing.expect(results[0].outcome.success.protocols.contains(.{ .reqresp = .ping_v1 }));
    try client.identify.?.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    completed = false;
    for (0..256) |_| {
        try pair.pump();
        if (step(&pair, &client, false, &results) == 1) {
            completed = true;
            break;
        }
        _ = step(&pair, &server, true, &.{});
    }
    try std.testing.expect(completed);
    try std.testing.expectEqual(.success, std.meta.activeTag(results[0].outcome));
    try std.testing.expectEqualStrings("new", results[0].outcome.success.agent.?.slice());
    try std.testing.expectEqual(@as(u8, 1), results[0].outcome.success.protocols.count());
}

test "identify inbound timeout closes only withheld writer and shutdown releases active owners" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    @import("../quic/binding.zig").c.quiche_config_set_initial_max_stream_data_bidi_local(pair.client.config.ptr, 96);
    const handles = try support.connectPair(&pair);
    var client = try service_mod.Service.init(std.testing.allocator, options("client"));
    defer client.deinit();
    var server = try service_mod.Service.init(std.testing.allocator, options("server"));
    defer server.deinit();
    try client.identify.?.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    for (0..16) |_| {
        _ = step(&pair, &client, false, &.{});
        try pair.pump();
        _ = step(&pair, &server, true, &.{});
        if (server.identify.?.inbound[0].stream != null) break;
        try pair.pump();
    }
    const deadline = server.identify.?.inbound[0].deadline;
    try std.testing.expect(server.identify.?.inbound[0].stream != null);
    const retained = server.identify.?.inbound[0].stream.?;
    const duplicate = try client.router.beginOutbound(&pair.client, handles.client, .identify, pair.now);
    var refused = false;
    for (0..32) |_| {
        var outcomes: [8]@import("../router.zig").Outcome = undefined;
        _ = client.router.pump(&pair.client, pair.now, &outcomes);
        try pair.pump();
        _ = step(&pair, &server, true, &.{});
        try pair.pump();
        var events: [64]engine_mod.Event = undefined;
        const received = pair.events(&pair.client, &events);
        for (received) |event| if (event == .stream_closed and std.meta.eql(event.stream_closed.stream, duplicate)) {
            refused = true;
        };
        client.router.transportEvents(&pair.client, received, pair.now);
        try std.testing.expectEqual(retained, server.identify.?.inbound[0].stream.?);
        if (refused) break;
    }
    try std.testing.expect(refused);
    try std.testing.expectEqual(deadline, server.identify.?.inbound[0].deadline);
    pair.now.mono_ms = deadline;
    _ = server.identify.?.pump(&server.router, &pair.server, pair.now, &.{});
    try std.testing.expect(server.identify.?.inbound[0].stream == null);
    try std.testing.expect(pair.server.peerId(handles.server) != null);
    client.identify.?.shutdown(&client.router, &pair.client);
    var results: [1]identify.Result = undefined;
    try std.testing.expectEqual(@as(usize, 1), client.identify.?.pump(&client.router, &pair.client, pair.now, &results));
    try std.testing.expectEqual(identify.Failure.shutdown, results[0].outcome.failed);
}

test "identify remote reset and transport close retain one failed result without metadata" {
    for ([_]bool{ false, true }) |close_connection| {
        var pair: support.Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        @import("../quic/binding.zig").c.quiche_config_set_initial_max_stream_data_bidi_local(pair.client.config.ptr, 96);
        const handles = try support.connectPair(&pair);
        var client = try service_mod.Service.init(std.testing.allocator, options("client"));
        defer client.deinit();
        var server = try service_mod.Service.init(std.testing.allocator, options("server"));
        defer server.deinit();
        try client.identify.?.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
        for (0..16) |_| {
            _ = step(&pair, &client, false, &.{});
            try pair.pump();
            _ = step(&pair, &server, true, &.{});
            if (server.identify.?.inbound[0].stream != null) break;
            try pair.pump();
        }
        const stream = server.identify.?.inbound[0].stream.?;
        try pair.pump();
        _ = step(&pair, &client, false, &.{});
        try std.testing.expectEqual(.reading, client.identify.?.outbound[0].phase);
        if (close_connection) {
            _ = pair.server.close(handles.server, 42);
        } else pair.server.closeStream(stream, 42);
        var results: [1]identify.Result = undefined;
        var completed = false;
        for (0..32) |_| {
            try pair.pump();
            if (step(&pair, &client, false, &results) == 1) {
                completed = true;
                break;
            }
            _ = step(&pair, &server, true, &.{});
        }
        try std.testing.expect(completed);
        try std.testing.expectEqual(.failed, std.meta.activeTag(results[0].outcome));
        try std.testing.expectEqual(if (close_connection) identify.Failure.transport else identify.Failure.reset, results[0].outcome.failed);
        try std.testing.expectEqual(@as(usize, 0), step(&pair, &client, false, &results));
        if (!close_connection) try std.testing.expect(pair.client.peerId(handles.client) != null);
    }
}
