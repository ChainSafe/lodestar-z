const std = @import("std");
const support = @import("test_support.zig");
const engine = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gs = @import("gossipsub/root.zig");
const topic_mod = @import("gossipsub/topic.zig");
const multistream = @import("wire/multistream.zig");
const protobuf = @import("gossipsub/protobuf.zig");

const rr_options: rr.service.Options = .{ .reqresp = .{
    .outbound_max = 4,
    .inbound_max = 4,
    .inbound_per_peer_max = 4,
    .forks = &.{},
} };

test "router composes simultaneous ping and meshsub on one connection" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var client = try rr.Service.init(std.testing.allocator, rr_options);
    defer client.deinit();
    var server = try @import("service.zig").Service.init(std.testing.allocator, .{ .reqresp = rr_options.reqresp });
    defer server.deinit();
    const requests = &server.reqresp;
    const gossip = &server.gossipsub;
    const handles = try support.connectPair(&pair);
    gossip.peerConnected(&pair.server, handles.server, pair.now);
    var topic_buf: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(.{ 1, 2, 3, 4 }, "beacon_block", &topic_buf);
    try std.testing.expect(gossip.subscribe(topic));
    const ping = [_]u8{ 42, 0, 0, 0, 0, 0, 0, 0 };
    var response: [8]u8 = undefined;
    _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, &response, .{}, pair.now);
    const stream = try pair.client.openStream(handles.client);
    const dialer = try multistream.Dialer.init("/meshsub/1.2.0");
    var bytes: [512]u8 = undefined;
    const hello = try dialer.initialWrite(&bytes);
    var writer = protobuf.Writer.init(bytes[hello.len..]);
    writer.varint(protobuf.subscriptionSize(topic));
    protobuf.writeSubscription(&writer, true, topic);
    const len = hello.len + writer.len;
    try std.testing.expectEqual(len, try pair.client.write(stream, bytes[0..len], true));
    var subscription = false;
    var pong = false;
    for (0..32) |_| {
        var transport_events: [16]engine.Event = undefined;
        var request_events: [16]rr.Event = undefined;
        var activity: [128]engine.Handle = undefined;
        const client_active = pair.client.driverView().takeActivity(&activity);
        const client_count = client.process(&pair.client, pair.events(&pair.client, &transport_events), activity[0..client_active], pair.now, &request_events);
        for (request_events[0..client_count]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &ping, chunk.bytes);
                try std.testing.expect(client.consume(chunk.request, pair.now));
                pong = true;
            },
            else => {},
        };
        try pair.pump();
        const events = pair.events(&pair.server, &transport_events);
        var gossip_events: [16]gs.Event = undefined;
        const server_active = pair.server.driverView().takeActivity(&activity);
        const counts = server.process(&pair.server, events, activity[0..server_active], pair.now, &request_events, &gossip_events);
        const request_count = counts.reqresp;
        const gossip_count = counts.gossipsub;
        for (request_events[0..request_count]) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(rr.Protocol.ping_v1, incoming.protocol);
                try requests.respond(incoming.request, &ping, null, pair.now);
            },
            .chunk_sent => |sent| _ = requests.finish(sent.request, pair.now),
            else => {},
        };
        for (gossip_events[0..gossip_count]) |event| switch (event) {
            .subscription_change => |change| {
                try std.testing.expectEqualStrings(topic, change.topic);
                subscription = true;
            },
            else => {},
        };
        try pair.pump();
    }
    try std.testing.expect(pong);
    try std.testing.expect(subscription);
}

test "router selects typed outbound protocol independently of offer indexes" {
    const routing = @import("router.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var client = try routing.Router.init(std.testing.allocator, .{});
    defer client.deinit();
    var server = try routing.Router.init(std.testing.allocator, .{});
    defer server.deinit();
    const stream = try client.beginOutbound(&pair.client, handles.client, .{ .reqresp = .ping_v1 }, pair.now);
    var accepted = false;
    for (0..16) |_| {
        var out: [16]routing.Outcome = undefined;
        const count = client.pump(&pair.client, pair.now, &out);
        for (out[0..count]) |outcome| {
            try std.testing.expectEqual(stream, outcome.stream);
            try std.testing.expectEqual(@import("types.zig").Direction.outbound, outcome.direction);
            try std.testing.expectEqual(routing.Kind.reqresp, outcome.owner.?);
            try std.testing.expectEqual(rr.Protocol.ping_v1, outcome.result.ready.protocol.reqresp);
            accepted = true;
        }
        try pair.pump();
        var events: [16]engine.Event = undefined;
        server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
        _ = server.pump(&pair.server, pair.now, &out);
        try pair.pump();
    }
    try std.testing.expect(accepted);
}

test "router rejects unknown protocol and preserves one-byte fragmented handoff" {
    const routing = @import("router.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    const stream = try pair.client.openStream(handles.client);
    var hello: [256]u8 = undefined;
    const header = try multistream.encodeMessage(multistream.header, &hello);
    const missing = try multistream.encodeMessage("/unknown/1.0.0", hello[header.len..]);
    const ping = try multistream.encodeMessage(rr.Protocol.ping_v1.id(), hello[header.len + missing.len ..]);
    const length = header.len + missing.len + ping.len;
    hello[length] = 42;
    var accepted = false;
    var inbound: engine.StreamHandle = undefined;
    for (hello[0 .. length + 1], 0..) |_, index| {
        try std.testing.expectEqual(@as(usize, 1), try pair.client.write(stream, hello[index..][0..1], index == length));
        try pair.pump();
        var events: [16]engine.Event = undefined;
        router.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
        var out: [16]routing.Outcome = undefined;
        const count = router.pump(&pair.server, pair.now, &out);
        for (out[0..count]) |outcome| {
            try std.testing.expectEqual(rr.Protocol.ping_v1, outcome.result.ready.protocol.reqresp);
            accepted = true;
            inbound = outcome.stream;
        }
        try pair.pump();
    }
    try std.testing.expect(accepted);
    var response: [256]u8 = undefined;
    const read = try pair.client.read(stream, &response);
    const got_header = (try multistream.decodeMessage(response[0..read.len])).?;
    try std.testing.expectEqualStrings(multistream.header, got_header.token);
    const rejected = (try multistream.decodeMessage(response[got_header.consumed..read.len])).?;
    try std.testing.expectEqualStrings("na", rejected.token);
    const selected = (try multistream.decodeMessage(response[got_header.consumed + rejected.consumed .. read.len])).?;
    try std.testing.expectEqualStrings(rr.Protocol.ping_v1.id(), selected.token);
    const payload = try pair.server.read(inbound, &response);
    try std.testing.expectEqual(@as(usize, 1), payload.len);
    try std.testing.expectEqual(@as(u8, 42), response[0]);
    try std.testing.expect(payload.fin);
}

test "router wakeups separate negotiation work from outcome capacity" {
    const routing = @import("router.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    const stream = try router.beginOutbound(&pair.client, handles.client, .{ .reqresp = .ping_v1 }, pair.now);
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), router.nextWakeup(pair.now, 0));
    _ = router.pump(&pair.client, pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms + 10_000), router.nextWakeup(pair.now, 0));
    pair.advance(10_000);
    _ = router.pump(&pair.client, pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, null), router.nextWakeup(pair.now, 0));
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), router.nextWakeup(pair.now, 1));
    try std.testing.expect(!pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
    router.cancel(&pair.client, stream);
    try std.testing.expectEqual(@as(?u64, null), router.nextWakeup(pair.now, 1));
}

test "router ready handoff waits quietly for host outcome capacity" {
    const routing = @import("router.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var client = try routing.Router.init(std.testing.allocator, .{});
    defer client.deinit();
    var server = try routing.Router.init(std.testing.allocator, .{});
    defer server.deinit();
    _ = try client.beginOutbound(&pair.client, handles.client, .{ .reqresp = .ping_v1 }, pair.now);
    for (0..16) |_| {
        _ = client.pump(&pair.client, pair.now, &.{});
        try pair.pump();
        var events: [16]engine.Event = undefined;
        server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
        _ = server.pump(&pair.server, pair.now, &.{});
        try pair.pump();
    }
    try std.testing.expectEqual(@as(?u64, null), client.nextWakeup(pair.now, 0));
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), client.nextWakeup(pair.now, 1));
    var out: [1]routing.Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 1), client.pump(&pair.client, pair.now, &out));
    try std.testing.expect(out[0].result == .ready);
    client.cancel(&pair.client, out[0].stream);
}

test "router composed service retains native activity behind a partial reqresp sweep" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var client = try @import("service.zig").Service.init(std.testing.allocator, .{ .reqresp = .{
        .forks = &.{},
        .outbound_max = 1,
        .inbound_max = 1,
        .work_per_pump_max = 1,
    } });
    defer client.deinit();
    defer client.reqresp.shutdownRouted(&client.router, &pair.client);
    var server = try rr.Service.init(std.testing.allocator, rr_options);
    defer server.deinit();
    defer server.shutdown(&pair.server);
    const handles = try support.connectPair(&pair);
    const ping = [_]u8{3} ** 8;
    var sink: [8]u8 = undefined;
    _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, &sink, .{}, pair.now);
    var incoming: ?rr.RequestHandle = null;
    var transport: [16]engine.Event = undefined;
    var activity: [128]engine.Handle = undefined;
    var requests: [8]rr.Event = undefined;
    var gossip: [8]gs.Event = undefined;
    for (0..64) |_| {
        try pair.pump();
        const active = pair.client.driverView().takeActivity(&activity);
        _ = client.process(&pair.client, pair.events(&pair.client, &transport), activity[0..active], pair.now, &requests, &gossip);
        const server_active = pair.server.driverView().takeActivity(&activity);
        const count = server.process(&pair.server, pair.events(&pair.server, &transport), activity[0..server_active], pair.now, &requests);
        for (requests[0..count]) |event| if (event == .request) {
            incoming = event.request.request;
        };
        if (incoming != null and client.nextWakeup(pair.now, 1, gossip.len) != pair.now.mono_ms) break;
    }
    try std.testing.expect(incoming != null);
    try std.testing.expect(client.nextWakeup(pair.now, 1, gossip.len).? > pair.now.mono_ms);
    _ = client.process(&pair.client, &.{}, &.{}, pair.now, &requests, &gossip);
    var wire: [rr.codec.frame_scratch_max]u8 = undefined;
    const encoded = try rr.codec.encodeChunk(0, null, &ping, &wire);
    const stream = server.inner.inbound[incoming.?.index].stream;
    try std.testing.expectEqual(encoded.len, try pair.server.write(stream, encoded, false));
    try pair.pump();
    const active = pair.client.driverView().takeActivity(&activity);
    try std.testing.expect(active > 0);
    _ = client.process(&pair.client, &.{}, activity[0..active], pair.now, &requests, &gossip);
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), client.nextWakeup(pair.now, 1, gossip.len));
    const counts = client.process(&pair.client, &.{}, &.{}, pair.now, &requests, &gossip);
    try std.testing.expectEqual(@as(usize, 1), counts.reqresp);
    try std.testing.expectEqualSlices(u8, &ping, requests[0].chunk.bytes);
}
