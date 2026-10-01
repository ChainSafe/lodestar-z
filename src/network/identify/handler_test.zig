const std = @import("std");
const support = @import("../test_support.zig");
const service = @import("../service.zig");
const engine = @import("../quic/engine.zig");
const identify = @import("root.zig");

fn options(agent: []const u8) !service.Options {
    return .{ .reqresp = .{ .forks = &.{}, .admission = try @import("../reqresp/reqresp.zig").AdmissionOptions.defaults(&@import("../reqresp/policy_fixture.zig").config(), 128, 128, 64) }, .gossipsub = .{ .random_seed = 1 }, .identify = .{ .agent = agent, .inbound_max = 1, .outbound_max = 1 } };
}

test "identify delivers retained completions before recycled lower slots" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var router = try @import("../router.zig").Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var handler = try identify.Handler.init(std.testing.allocator, .{ .outbound_max = 4 }, &try @import("../service_test_support.zig").fixtureLocal(.{}));
    defer handler.deinit();
    const conn: engine.Handle = .{ .index = 0, .generation = 1 };
    for (handler.outbound, 0..) |*slot, index| {
        const peer: @import("../peers/types.zig").PeerRef = .{ .index = @intCast(index), .generation = 1 };
        slot.* = .{ .stream = .{ .conn = conn, .id = index * 4, .slot = @intCast(index) }, .peer = peer, .phase = .terminal, .result = .{ .peer = peer, .conn = conn, .outcome = .{ .success = .{} } } };
    }
    try std.testing.expectEqual(@as(usize, 0), handler.pump(&router, &pair.client, pair.now, &.{}));
    var out: [1]identify.Result = undefined;
    for (0..4) |index| {
        try std.testing.expectEqual(@as(usize, 1), handler.pump(&router, &pair.client, pair.now, &out));
        try std.testing.expectEqual(index, out[0].peer.index);
        try std.testing.expectEqual(@as(u64, 1), out[0].peer.generation);
        if (index == 3) break;
        const peer: @import("../peers/types.zig").PeerRef = .{ .index = @intCast(index), .generation = 2 };
        handler.outbound[index] = .{ .stream = .{ .conn = conn, .id = (index + 4) * 4, .slot = @intCast(index) }, .peer = peer, .phase = .terminal, .result = .{ .peer = peer, .conn = conn, .outcome = .{ .failed = .timeout } } };
    }
    var remaining: [4]identify.Result = undefined;
    try std.testing.expectEqual(@as(usize, 3), handler.pump(&router, &pair.client, pair.now, &remaining));
    for (remaining[0..3]) |result| {
        try std.testing.expectEqual(@as(u64, 2), result.peer.generation);
        try std.testing.expectEqual(identify.Failure.timeout, result.outcome.failed);
    }
    try std.testing.expect(handler.nextWakeup(pair.now, 1) == null);
}

test "identify service completes both directions with zero application output and retains pressured results" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var client = try @import("../service_test_support.zig").initService(std.testing.allocator, try options("client"), &pair.client);
    defer client.deinit();
    var server = try @import("../service_test_support.zig").initService(std.testing.allocator, try options("server"), &pair.server);
    defer server.deinit();
    try client.identify.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    try server.identify.start(&server.router, &pair.server, .{ .index = 0, .generation = 1 }, handles.server, pair.now);
    try std.testing.expectError(error.PeerLimit, client.identify.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now));
    for (0..32) |_| {
        var events: [64]engine.Event = undefined;
        _ = client.process(&pair.client, pair.events(&pair.client, &events), pair.now, .{});
        try pair.pump();
        _ = server.process(&pair.server, pair.events(&pair.server, &events), pair.now, .{});
        try pair.pump();
    }
    try std.testing.expect(client.identify.nextWakeup(pair.now, 0) == null);
    if (client.nextWakeup(pair.now, .{})) |due| try std.testing.expect(due > pair.now.mono_ms);
    try std.testing.expectEqual(pair.now.mono_ms, client.identify.nextWakeup(pair.now, 1).?);
    var results: [1]identify.Result = undefined;
    var counts = client.process(&pair.client, &.{}, pair.now, .{ .identify = &results });
    try std.testing.expectEqual(@as(usize, 1), counts.identify);
    try std.testing.expectEqual(.success, std.meta.activeTag(results[0].outcome));
    try std.testing.expectEqualStrings("server", results[0].outcome.success.agent.?.slice());
    counts = server.process(&pair.server, &.{}, pair.now, .{ .identify = &results });
    try std.testing.expectEqual(@as(usize, 1), counts.identify);
    try std.testing.expectEqualStrings("client", results[0].outcome.success.agent.?.slice());
    counts = client.process(&pair.client, &.{}, pair.now, .{ .identify = &results });
    try std.testing.expectEqual(@as(usize, 0), counts.identify);
    try client.identify.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    client.identify.shutdown(&client.router, &pair.client);
    try std.testing.expectEqual(@as(usize, 1), client.identify.pump(&client.router, &pair.client, pair.now, &results));
    try std.testing.expectEqual(identify.Failure.shutdown, results[0].outcome.failed);
}

test "identify configured handler controls default and explicit directional capabilities" {
    var opts = try options("");
    var enabled = try service.Service.init(std.testing.allocator, opts, &try @import("../service_test_support.zig").fixtureLocal(opts.identify));
    defer enabled.deinit();
    try std.testing.expect(enabled.router.capabilities().receive.contains(.identify));
    try std.testing.expect(enabled.router.capabilities().request.contains(.identify));
    const caps = @import("../capabilities.zig");
    const empty: caps.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() };
    const both = caps.withIdentify(empty);
    try std.testing.expect(both.receive.contains(.identify) and both.request.contains(.identify));
    for ([_]caps.Directional{ empty, .{ .receive = both.receive, .request = empty.request }, .{ .receive = empty.receive, .request = both.request } }) |active| {
        opts.router.capabilities = active;
        var configured = try service.Service.init(std.testing.allocator, opts, &try @import("../service_test_support.zig").fixtureLocal(opts.identify));
        defer configured.deinit();
        try std.testing.expectEqualDeep(active, configured.router.capabilities());
    }
}

fn allocationCheck(allocator: std.mem.Allocator) !void {
    var handler = try identify.Handler.init(allocator, .{ .inbound_max = 2, .outbound_max = 3 }, &try @import("../service_test_support.zig").fixtureLocal(.{}));
    defer handler.deinit();
    try std.testing.expectEqual(2 * @sizeOf(@TypeOf(handler.inbound[0])) + 3 * @sizeOf(@TypeOf(handler.outbound[0])), handler.allocatedBytes());
}

test "identify validates capacities and cleans every allocation prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
    for ([_]u16{ 0, 65 }) |invalid| {
        try std.testing.expectError(error.InvalidLimits, identify.Handler.init(std.testing.allocator, .{ .inbound_max = invalid }, &try @import("../service_test_support.zig").fixtureLocal(.{})));
        try std.testing.expectError(error.InvalidLimits, identify.Handler.init(std.testing.allocator, .{ .outbound_max = invalid }, &try @import("../service_test_support.zig").fixtureLocal(.{})));
    }
    var agent = [_]u8{'a'};
    var handler = try identify.Handler.init(std.testing.allocator, .{ .inbound_max = 64, .outbound_max = 64 }, &try @import("../service_test_support.zig").fixtureLocal(.{ .agent = &agent }));
    defer handler.deinit();
    agent[0] = 'b';
    try std.testing.expectEqualStrings("a", handler.local.agent.slice());
}

test "identify deadline includes stalled negotiation and retained completion does not hot wake" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var client = try @import("../service_test_support.zig").initService(std.testing.allocator, try options("client"), &pair.client);
    defer client.deinit();
    const start = pair.now.mono_ms;
    try client.identify.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    pair.now.mono_ms = start + 4999;
    var results: [1]identify.Result = undefined;
    try std.testing.expectEqual(@as(usize, 0), client.identify.pump(&client.router, &pair.client, pair.now, &results));
    try std.testing.expectEqual(start + 5000, client.identify.nextWakeup(pair.now, 1).?);
    pair.now.mono_ms += 1;
    try std.testing.expectEqual(@as(usize, 0), client.identify.pump(&client.router, &pair.client, pair.now, &.{}));
    try std.testing.expect(client.identify.nextWakeup(pair.now, 0) == null);
    try std.testing.expectEqual(@as(usize, 1), client.identify.pump(&client.router, &pair.client, pair.now, &results));
    try std.testing.expectEqual(identify.Failure.timeout, results[0].outcome.failed);
    try std.testing.expectEqual(@as(usize, 0), client.identify.pump(&client.router, &pair.client, pair.now, &results));
    try client.identify.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    _ = pair.client.close(handles.client, 0);
    var events: [64]engine.Event = undefined;
    _ = client.process(&pair.client, pair.events(&pair.client, &events), pair.now, .{ .identify = &results });
    // Engine emits close on its next service turn; shutdown also releases a negotiating stream.
    client.identify.shutdown(&client.router, &pair.client);
    _ = client.identify.pump(&client.router, &pair.client, pair.now, &results);
}

test "identify saturation leaves reserved Ping negotiation usable" {
    const rr = @import("../reqresp/root.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var opts = try options("small");
    opts.router = .{ .negotiations_max = 2, .outbound_control_reserved = 1 };
    opts.reqresp.outbound_max = 2;
    opts.reqresp.outbound_control_reserved = 1;
    var client = try @import("../service_test_support.zig").initService(std.testing.allocator, opts, &pair.client);
    defer client.deinit();
    opts.router.negotiations_max = 4;
    var server = try @import("../service_test_support.zig").initService(std.testing.allocator, opts, &pair.server);
    defer server.deinit();
    try client.identify.start(&client.router, &pair.client, .{ .index = 0, .generation = 1 }, handles.client, pair.now);
    const ping = [_]u8{1} ++ [_]u8{0} ** 7;
    var sink: [8]u8 = undefined;
    _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, &sink, .{}, pair.now);
    var received = false;
    for (0..32) |_| {
        var events: [64]engine.Event = undefined;
        var requests: [4]rr.Event = undefined;
        const cc = client.process(&pair.client, pair.events(&pair.client, &events), pair.now, .{ .control = &requests });
        for (requests[0..cc.control]) |event| if (event == .chunk) {
            try std.testing.expectEqualSlices(u8, &ping, event.chunk.bytes);
            try std.testing.expect(client.reqresp.consume(event.chunk.request, pair.now));
            received = true;
        };
        try pair.pump();
        const sc = server.process(&pair.server, pair.events(&pair.server, &events), pair.now, .{ .control = &requests });
        for (requests[0..sc.control]) |event| switch (event) {
            .request => |request| try server.reqresp.respond(request.request, &ping, null, pair.now),
            .chunk_sent => |sent| _ = server.reqresp.finish(sent.request, pair.now),
            else => {},
        };
        try pair.pump();
    }
    try std.testing.expect(received);
    try std.testing.expect(client.identify.nextWakeup(pair.now, 0) == null);
    try std.testing.expectEqual(pair.now.mono_ms, client.identify.nextWakeup(pair.now, 1).?);
}

test "identify advertises each usable bound address despite another wildcard family" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const address: @import("../types.zig").Address = .{ .ip6 = .{ .octets = @import("std").Io.net.Ip6Address.loopback(9000).bytes, .port = 9000 } };
    pair.client.local = .{ .{ .ip4 = .{ .octets = @splat(0), .port = 9000 } }, address };
    const local = try (identify.Options{}).makeLocal(&pair.client_ctx.local_peer_id, &pair.client.local);
    var handler = try identify.Handler.init(std.testing.allocator, .{}, &local);
    defer handler.deinit();
    try std.testing.expectEqual(@as(u8, 1), handler.local.address_count);
    var encoded: [@import("../wire/multiaddr.zig").binary_length_max]u8 = undefined;
    const expected = try (@import("../wire/multiaddr.zig").Multiaddr{ .address = address }).encode(&encoded);
    const retained = handler.local.addresses[0];
    try std.testing.expectEqualSlices(u8, expected, retained.bytes[0..retained.len]);
}

test "identify explicit construction copies intent and complete local before any stream" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var agent = [_]u8{ 'o', 'l', 'd' };
    var addresses = [_]@import("../types.zig").Address{
        .{ .ip4 = .{ .octets = .{ 127, 3, 2, 1 }, .port = 19001 } },
        .{ .ip6 = .{ .octets = std.Io.net.Ip6Address.loopback(19002).bytes, .port = 19002 } },
    };
    const opts: identify.Options = .{ .agent = &agent, .addresses = &addresses };
    var local = try opts.makeLocal(&pair.client_ctx.local_peer_id, &pair.client.local);
    var handler = try identify.Handler.init(std.testing.allocator, opts.limits(), &local);
    defer handler.deinit();
    agent[0] = 'x';
    addresses[0].ip4.port = 19999;
    local.agent = try .init("replacement");
    local.address_count = 0;
    try std.testing.expectEqualStrings("old", handler.local.agent.slice());
    try std.testing.expectEqual(@as(u8, 2), handler.local.address_count);
    const retained = handler.local.addresses[0];
    const decoded = try @import("../wire/multiaddr.zig").Multiaddr.decode(retained.bytes[0..retained.len]);
    try std.testing.expectEqual(@as(u16, 19001), decoded.address.port());
    var encoded: [8194]u8 = undefined;
    const frame = try handler.local.encode(.initEmpty(), null, &encoded);
    var decoder = identify.codec.Decoder.init(&pair.client_ctx.local_peer_id);
    try decoder.feed(frame, true);
    try std.testing.expectEqualStrings("old", decoder.result().?.agent.?.slice());
}

test "identify constructor enforces explicit address and text bounds before handler allocation" {
    const local = try @import("../service_test_support.zig").fixtureLocal(.{});
    const peer = @import("../wire/peer_id.zig").PeerId.fromPublicKey(&try @import("../wire/keys.zig").PublicKey.decodeProtobuf(&local.public_key));
    const bound = [2]?@import("../types.zig").Address{ support.client_address, null };
    var addresses: [9]@import("../types.zig").Address = @splat(support.server_address);
    const accepted = try (identify.Options{ .addresses = addresses[0..8] }).makeLocal(&peer, &bound);
    try std.testing.expectEqual(@as(u8, 8), accepted.address_count);
    try std.testing.expectError(error.OccurrenceLimit, (identify.Options{ .addresses = &addresses }).makeLocal(&peer, &bound));
    addresses[0].ip4.port = 0;
    try std.testing.expectError(error.InvalidAddress, (identify.Options{ .addresses = addresses[0..1] }).makeLocal(&peer, &bound));
    try std.testing.expectError(error.InvalidUtf8, (identify.Options{ .agent = &.{0xff} }).makeLocal(&peer, &bound));
    try std.testing.expectError(error.StringLimit, (identify.Options{ .protocol_version = &(@as([65]u8, @splat('a'))) }).makeLocal(&peer, &bound));
    try std.testing.expectError(error.StringLimit, (identify.Options{ .agent = &(@as([257]u8, @splat('a'))) }).makeLocal(&peer, &bound));
}
