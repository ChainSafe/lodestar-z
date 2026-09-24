const gossip_test = @import("gossipsub/test_support.zig");
const std = @import("std");
const support = @import("test_support.zig");
const engine = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gs = @import("gossipsub/root.zig");
const topic_mod = @import("gossipsub/topic.zig");
const multistream = @import("wire/multistream.zig");
const protobuf = @import("gossipsub/protobuf.zig");

fn rrOptions() !@import("service.zig").Options {
    return .{ .gossipsub = .{ .random_seed = 1 }, .reqresp = .{
        .outbound_max = 4,
        .inbound_max = 4,
        .inbound_per_peer_max = 4,
        .forks = &.{},
        .admission = try rr.reqresp.AdmissionOptions.defaults(&@import("reqresp/policy_fixture.zig").config(), 128, 128, 4),
    } };
}

test "router composes simultaneous ping and meshsub on one connection" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var client = try @import("service.zig").Service.init(std.testing.allocator, try rrOptions());
    defer client.deinit();
    var server = try @import("service.zig").Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1, .topic_policy = &.{@import("gossipsub/topic_fixture.zig").bytes(.{ 1, 2, 3, 4 })} }, .reqresp = (try rrOptions()).reqresp });
    defer server.deinit();
    const requests = &server.reqresp;
    const gossip = server.gossipsub;
    const handles = try support.connectPair(&pair);
    _ = gossip.peerConnected(&pair.server, handles.server, false, pair.now);
    var topic_buf: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(.{ 1, 2, 3, 4 }, "beacon_block", &topic_buf);
    try gossip_test.subscribe(gossip, topic);
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
    var pong = false;
    for (0..32) |_| {
        var transport_events: [16]engine.Event = undefined;
        var request_events: [16]rr.Event = undefined;
        const client_count = client.process(&pair.client, pair.events(&pair.client, &transport_events), pair.now, .{ .control = &request_events }).control;
        for (request_events[0..client_count]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &ping, chunk.bytes);
                try std.testing.expect(client.reqresp.consume(chunk.request, pair.now));
                pong = true;
            },
            else => {},
        };
        try pair.pump();
        const events = pair.events(&pair.server, &transport_events);
        const counts = server.process(&pair.server, events, pair.now, .{ .application = &.{}, .control = &request_events });
        try std.testing.expectEqual(0, counts.application);
        const request_count = counts.control;
        for (request_events[0..request_count]) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(rr.Protocol.ping_v1, incoming.protocol);
                try requests.respond(incoming.request, &ping, null, pair.now);
            },
            .chunk_sent => |sent| _ = requests.finish(sent.request, pair.now),
            else => {},
        };
        try pair.pump();
    }
    try std.testing.expect(pong);
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
        const count = pumpRouter(&client, &pair, &pair.client, pair.now, &out);
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
        _ = pumpRouter(&server, &pair, &pair.server, pair.now, &out);
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
        const count = pumpRouter(&router, &pair, &pair.server, pair.now, &out);
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
    _ = pumpRouter(&router, &pair, &pair.client, pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms + 10_000), router.nextWakeup(pair.now, 0));
    pair.advance(10_000);
    _ = pumpRouter(&router, &pair, &pair.client, pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, null), router.nextWakeup(pair.now, 0));
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), router.nextWakeup(pair.now, 1));
    try std.testing.expect(!pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
    router.cancel(&pair.client, stream);
    try std.testing.expectEqual(@as(?u64, null), router.nextWakeup(pair.now, 1));
}

test "router accepted selection survives capability changes behind outcome pressure" {
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
        _ = pumpRouter(&client, &pair, &pair.client, pair.now, &.{});
        try pair.pump();
        var events: [16]engine.Event = undefined;
        server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
        _ = pumpRouter(&server, &pair, &pair.server, pair.now, &.{});
        try pair.pump();
    }
    client.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });
    server.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });
    try std.testing.expectEqual(@as(?u64, null), client.nextWakeup(pair.now, 0));
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), client.nextWakeup(pair.now, 1));
    try std.testing.expectEqual(@as(?u64, null), server.nextWakeup(pair.now, 0));
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), server.nextWakeup(pair.now, 1));
    var out: [1]routing.Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 1), pumpRouter(&client, &pair, &pair.client, pair.now, &out));
    try std.testing.expect(out[0].result == .ready);
    try std.testing.expectEqual(rr.Protocol.ping_v1, out[0].result.ready.protocol.reqresp);
    client.cancel(&pair.client, out[0].stream);
    try std.testing.expectEqual(@as(usize, 1), pumpRouter(&server, &pair, &pair.server, pair.now, &out));
    try std.testing.expect(out[0].result == .ready);
    try std.testing.expectEqual(rr.Protocol.ping_v1, out[0].result.ready.protocol.reqresp);
    server.cancel(&pair.server, out[0].stream);
}

test "router composed service handles native activity past empty request capacity" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var client = try @import("service.zig").Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1 }, .reqresp = .{
        .forks = &.{},
        .outbound_max = 64,
        .inbound_max = 64,
        .work_per_pump_max = 1,
        .admission = try rr.reqresp.AdmissionOptions.defaults(&@import("reqresp/policy_fixture.zig").config(), 128, 128, 64),
    } });
    defer client.deinit();
    defer client.reqresp.shutdown(&pair.client, &client.router);
    var server = try @import("service.zig").Service.init(std.testing.allocator, try rrOptions());
    defer server.deinit();
    defer server.reqresp.shutdown(&pair.server, &server.router);
    const handles = try support.connectPair(&pair);
    const ping = [_]u8{3} ** 8;
    var sink: [8]u8 = undefined;
    _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, &sink, .{}, pair.now);
    var incoming: ?rr.RequestHandle = null;
    var transport: [16]engine.Event = undefined;
    var activity: [128]engine.Handle = undefined;
    var requests: [8]rr.Event = undefined;
    for (0..64) |_| {
        try pair.pump();
        _ = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .control = &requests });
        const count = server.process(&pair.server, pair.events(&pair.server, &transport), pair.now, .{ .control = &requests }).control;
        for (requests[0..count]) |event| if (event == .request) {
            incoming = event.request.request;
        };
        if (incoming != null and client.nextWakeup(pair.now, .{ .control = 1 }) != pair.now.mono_ms) break;
    }
    try std.testing.expect(incoming != null);
    try std.testing.expect(client.nextWakeup(pair.now, .{ .control = 1 }).? > pair.now.mono_ms);
    var wire: [rr.codec.frame_scratch_max]u8 = undefined;
    const encoded = try rr.codec.encodeChunk(0, null, &ping, &wire);
    const stream = server.reqresp.inbound[incoming.?.index].request.stream;
    try std.testing.expectEqual(encoded.len, try pair.server.write(stream, encoded, false));
    try pair.pump();
    const active = pair.activity(&pair.client, &activity);
    try std.testing.expect(active > 0);
    const counts = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .control = &requests });
    try std.testing.expectEqual(@as(usize, 1), counts.control);
    try std.testing.expectEqualSlices(u8, &ping, requests[0].chunk.bytes);
}

test "router gossip capacity refusal preserves reqresp and explicit host retry" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var client = try @import("service.zig").Service.init(std.testing.allocator, try rrOptions());
    defer client.deinit();
    defer client.reqresp.shutdown(&pair.client, &client.router);
    var server = try @import("service.zig").Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1 }, .reqresp = (try rrOptions()).reqresp });
    defer server.deinit();
    defer server.reqresp.shutdown(&pair.server, &server.router);
    const handles = try support.connectPair(&pair);
    const peers = @import("gossipsub/peer_book.zig");
    var retained: [peers.capacity - peers.outbound_reserve]peers.Ref = undefined;
    for (0..peers.capacity - peers.outbound_reserve) |i| {
        var metadata: peers.Metadata = .{ .identity = .{ .bytes = [_]u8{0} ** @import("wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        const ref = server.gossipsub.peers.admit(.{ .index = 0, .generation = 1 }, &metadata, pair.now.mono_ms).admitted.peer;
        retained[i] = ref;
        server.gossipsub.peers.retain(ref);
        server.gossipsub.peers.scores.penalize(ref.index, 20);
        server.gossipsub.peers.disconnect(ref, pair.now.mono_ms);
    }
    try std.testing.expectEqual(gs.Gossipsub.Admission.capacity, server.gossipsub.peerConnected(&pair.server, handles.server, false, pair.now));
    try std.testing.expect(!server.gossipsub.admitted(handles.server));
    const ping = [_]u8{7} ** 8;
    var sink: [8]u8 = undefined;
    _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, &sink, .{}, pair.now);
    var pong = false;
    for (0..64) |_| {
        var transport: [16]engine.Event = undefined;
        var requests: [16]rr.Event = undefined;
        try pair.pump();
        const count = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .control = &requests }).control;
        for (requests[0..count]) |event| if (event == .chunk) {
            try std.testing.expectEqualSlices(u8, &ping, event.chunk.bytes);
            try std.testing.expect(client.reqresp.consume(event.chunk.request, pair.now));
            pong = true;
        };
        const counts = server.process(&pair.server, pair.events(&pair.server, &transport), pair.now, .{ .control = &requests });
        for (requests[0..counts.control]) |event| switch (event) {
            .request => |request| try server.reqresp.respond(request.request, &ping, null, pair.now),
            .chunk_sent => |sent| _ = server.reqresp.finish(sent.request, pair.now),
            else => {},
        };
        if (pong) break;
    }
    try std.testing.expect(pong);
    try std.testing.expect(!server.gossipsub.admitted(handles.server));
    for (retained) |ref| server.gossipsub.peers.release(ref);
    try std.testing.expectEqual(gs.Gossipsub.Admission.admitted, server.gossipsub.peerConnected(&pair.server, handles.server, false, pair.now));
    try std.testing.expect(server.gossipsub.admitted(handles.server));
}

test "protocol compositions expose no standalone processing on shared handlers" {
    const Shared = @import("service.zig").Service;
    const RequestHandler = @FieldType(Shared, "reqresp");
    const GossipHandler = @typeInfo(@FieldType(Shared, "gossipsub")).pointer.child;
    try std.testing.expect(!@hasField(RequestHandler, "router"));
    try std.testing.expect(!@hasField(GossipHandler, "router"));
    try std.testing.expect(!@hasDecl(RequestHandler, "process"));
    try std.testing.expect(!@hasDecl(GossipHandler, "process"));
}

test "router capabilities validate service limits and preserve configured preference" {
    const routing = @import("router.zig");
    const caps = @import("capabilities.zig");
    var active: caps.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() };
    active.receive.insert(.{ .reqresp = .ping_v1 });
    active.request.insert(.{ .meshsub = .v1_0 });
    active.request.insert(.{ .meshsub = .v1_2 });
    var versions = [_]@import("gossipsub/protocol.zig").Version{ .v1_0, .v1_2 };
    var router = try routing.Router.init(std.testing.allocator, .{ .capabilities = active, .meshsub_versions = &versions });
    defer router.deinit();
    versions[0] = .v1_1;
    try std.testing.expectEqualDeep(active, router.capabilities());
    try std.testing.expectEqualStrings("/meshsub/1.0.0", router.meshsub_candidates[0].id);
    try std.testing.expectEqualStrings("/meshsub/1.2.0", router.meshsub_candidates[1].id);
    try std.testing.expectEqual(1, router.supported_count);
    try std.testing.expectEqualStrings(rr.Protocol.ping_v1.id(), router.supported[0].id);
    var invalid = active;
    invalid.receive.insert(.{ .meshsub = .v1_1 });
    try std.testing.expectError(error.InvalidCapabilities, router.validateCapabilities(invalid));
    try std.testing.expectEqualDeep(active, router.capabilities());
    active.receive = .initEmpty();
    active.request = .initEmpty();
    try router.validateCapabilities(active);
    router.setCapabilities(active);
    try std.testing.expectEqual(0, router.supported_count);
    try std.testing.expectEqual(0, router.meshsub_count);
    try std.testing.expect(routing.Protocol.fromId(rr.Protocol.ping_v1.id()) != null);
}

test "router capabilities disabled outbound preserves stream and request owners" {
    const caps = @import("capabilities.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var service = try @import("service.zig").Service.init(std.testing.allocator, .{
        .reqresp = (try rrOptions()).reqresp,
        .gossipsub = .{ .random_seed = 1 },
        .router = .{ .capabilities = caps.Directional{ .receive = .initEmpty(), .request = .initEmpty() } },
    });
    defer service.deinit();
    const before = pair.client.resourceSnapshot();
    const requests = service.reqresp.active();
    const negotiations = service.router.negotiator.active();
    var sink: [8]u8 = undefined;
    try std.testing.expectError(error.ProtocolDisabled, service.request(&pair.client, handles.client, .ping_v1, &(@as([8]u8, @splat(0))), &sink, .{}, pair.now));
    try std.testing.expectError(error.ProtocolDisabled, service.router.beginOutbound(&pair.client, handles.client, .{ .reqresp = .status_v1 }, pair.now));
    try std.testing.expectError(error.ProtocolDisabled, service.router.beginMeshsub(&pair.client, handles.client, pair.now));
    try std.testing.expectEqualDeep(before, pair.client.resourceSnapshot());
    try std.testing.expectEqualDeep(requests, service.reqresp.active());
    try std.testing.expectEqual(negotiations, service.router.negotiator.active());
}

test "router capabilities changes apply before inbound protocol selection" {
    const routing = @import("router.zig");
    const caps = @import("capabilities.zig");
    for ([_]bool{ false, true }) |enable| {
        var pair: support.Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        const handles = try support.connectPair(&pair);
        var active: caps.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() };
        if (!enable) active.receive.insert(.{ .reqresp = .ping_v1 });
        var server = try routing.Router.init(std.testing.allocator, .{ .capabilities = active });
        defer server.deinit();
        const stream = try pair.client.openStream(handles.client);
        var bytes: [256]u8 = undefined;
        const header = try multistream.encodeMessage(multistream.header, &bytes);
        try std.testing.expectEqual(header.len, try pair.client.write(stream, header, false));
        try pair.pump();
        var events: [16]engine.Event = undefined;
        server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
        _ = pumpRouter(&server, &pair, &pair.server, pair.now, &.{});
        _ = pumpRouter(&server, &pair, &pair.server, pair.now, &.{});
        try pair.pump();
        const greeting = try pair.client.read(stream, &bytes);
        const reply_header = (try multistream.decodeMessage(bytes[0..greeting.len])).?;
        try std.testing.expectEqualStrings(multistream.header, reply_header.token);
        try std.testing.expectEqual(greeting.len, reply_header.consumed);

        active.receive = .initEmpty();
        if (enable) active.receive.insert(.{ .reqresp = .ping_v1 });
        server.setCapabilities(active);
        const proposal = try multistream.encodeMessage(rr.Protocol.ping_v1.id(), &bytes);
        try std.testing.expectEqual(proposal.len, try pair.client.write(stream, proposal, false));
        try pair.pump();
        var out: [1]routing.Outcome = undefined;
        const count = pumpRouter(&server, &pair, &pair.server, pair.now, &out);
        try std.testing.expectEqual(@as(usize, if (enable) 1 else 0), count);
        if (enable) {
            try std.testing.expect(out[0].result == .ready);
            try std.testing.expectEqual(rr.Protocol.ping_v1, out[0].result.ready.protocol.reqresp);
        }
        _ = pumpRouter(&server, &pair, &pair.server, pair.now, &.{});
        try pair.pump();
        const response = try pair.client.read(stream, &bytes);
        const reply = (try multistream.decodeMessage(bytes[0..response.len])).?;
        try std.testing.expectEqualStrings(if (enable) rr.Protocol.ping_v1.id() else multistream.na, reply.token);
        try std.testing.expectEqual(response.len, reply.consumed);
    }
}

test "router capabilities enable a fallback after rejecting an earlier proposal" {
    const routing = @import("router.zig");
    const caps = @import("capabilities.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var active: caps.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() };
    active.receive.insert(.{ .reqresp = .ping_v1 });
    var server = try routing.Router.init(std.testing.allocator, .{ .capabilities = active });
    defer server.deinit();
    const stream = try pair.client.openStream(handles.client);
    const dialer = try multistream.Dialer.init("/meshsub/1.2.0");
    var bytes: [256]u8 = undefined;
    const hello = try dialer.initialWrite(&bytes);
    try std.testing.expectEqual(hello.len, try pair.client.write(stream, hello, false));
    try pair.pump();
    var events: [16]engine.Event = undefined;
    server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
    var out: [1]routing.Outcome = undefined;
    try std.testing.expectEqual(0, pumpRouter(&server, &pair, &pair.server, pair.now, &out));
    try std.testing.expectEqual(0, pumpRouter(&server, &pair, &pair.server, pair.now, &out));
    try pair.pump();
    const rejected = try pair.client.read(stream, &bytes);
    const header = (try multistream.decodeMessage(bytes[0..rejected.len])).?;
    try std.testing.expectEqualStrings(multistream.header, header.token);
    const refusal = (try multistream.decodeMessage(bytes[header.consumed..rejected.len])).?;
    try std.testing.expectEqualStrings(multistream.na, refusal.token);
    try std.testing.expectEqual(rejected.len, header.consumed + refusal.consumed);

    active.receive = .initEmpty();
    active.receive.insert(.{ .meshsub = .v1_1 });
    server.setCapabilities(active);
    const fallback = try multistream.encodeMessage("/meshsub/1.1.0", &bytes);
    bytes[fallback.len] = 42;
    try std.testing.expectEqual(fallback.len + 1, try pair.client.write(stream, bytes[0 .. fallback.len + 1], true));
    try pair.pump();
    try std.testing.expectEqual(1, pumpRouter(&server, &pair, &pair.server, pair.now, &out));
    try std.testing.expect(out[0].result == .ready);
    try std.testing.expectEqual(@import("gossipsub/protocol.zig").Version.v1_1, out[0].result.ready.protocol.meshsub);
    try std.testing.expectEqualSlices(u8, &.{42}, out[0].result.ready.leftover);
    try std.testing.expect(out[0].result.ready.fin);
    try pair.pump();
    const accepted = try pair.client.read(stream, &bytes);
    const acknowledgement = (try multistream.decodeMessage(bytes[0..accepted.len])).?;
    try std.testing.expectEqualStrings("/meshsub/1.1.0", acknowledgement.token);
    try std.testing.expectEqual(accepted.len, acknowledgement.consumed);
}

test "router accepted selection survives capability changes while ACK is flow controlled" {
    const routing = @import("router.zig");
    const caps = @import("capabilities.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    @import("quic/binding.zig").c.quiche_config_set_initial_max_stream_data_bidi_local(pair.client.config.ptr, 8);
    const handles = try support.connectPair(&pair);
    var active: caps.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() };
    active.receive.insert(.{ .reqresp = .ping_v1 });
    var server = try routing.Router.init(std.testing.allocator, .{ .capabilities = active });
    defer server.deinit();
    const stream = try pair.client.openStream(handles.client);
    const dialer = try multistream.Dialer.init(rr.Protocol.ping_v1.id());
    var bytes: [256]u8 = undefined;
    const hello = try dialer.initialWrite(&bytes);
    const payload = "tail";
    @memcpy(bytes[hello.len..][0..payload.len], payload);
    try std.testing.expectEqual(hello.len + payload.len, try pair.client.write(stream, bytes[0 .. hello.len + payload.len], true));
    try pair.pump();
    var event_storage: [16]engine.Event = undefined;
    const events = pair.events(&pair.server, &event_storage);
    const inbound = try support.expectStreamOpened(events[0], handles.server);
    server.transportEvents(&pair.server, events, pair.now);
    var out: [1]routing.Outcome = undefined;
    try std.testing.expectEqual(0, pumpRouter(&server, &pair, &pair.server, pair.now, &out));
    try std.testing.expect(server.negotiator.entries[0].selected != null);
    try std.testing.expectEqual(0, try pair.server.streamCapacity(inbound));
    server.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });

    var ack: [256]u8 = undefined;
    var ack_len: usize = 0;
    var ready = false;
    for (0..32) |_| {
        try pair.pump();
        const read = try pair.client.read(stream, ack[ack_len..]);
        ack_len += read.len;
        const count = pumpRouter(&server, &pair, &pair.server, pair.now, &out);
        if (count == 1) {
            try std.testing.expect(!ready);
            try std.testing.expect(out[0].result == .ready);
            try std.testing.expectEqual(rr.Protocol.ping_v1, out[0].result.ready.protocol.reqresp);
            try std.testing.expectEqualSlices(u8, payload, out[0].result.ready.leftover);
            try std.testing.expect(out[0].result.ready.fin);
            ready = true;
        }
        if (ready and ack_len == hello.len) break;
    }
    try std.testing.expect(ready);
    try std.testing.expectEqualSlices(u8, hello, ack[0..ack_len]);
}

test "router capabilities activation preserves negotiated response context and captured ceiling" {
    const harness = @import("reqresp/test_pair.zig");
    const ct = @import("consensus_types");
    const context: rr.ForkEntry = .{ .digest = .{ 9, 10, 11, 12 }, .fork = .phase0 };
    var setup: harness.Pair = .{};
    const limits = @import("reqresp/admission_fixture.zig").quotas(2048, 1000);
    const options: harness.Overrides = .{
        .forks = &.{context},

        .admission = .{ .policy = @import("reqresp/policy_fixture.zig").config(), .limits = .{ .identities = 2, .peer = limits, .global = limits } },
    };
    try setup.init(options, options);
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    const bytes: [129 * 32]u8 = @splat(0);
    const payload: [ct.phase0.SignedBeaconBlock.min_size]u8 = @splat(0);
    const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .blocks_by_root_v2, &bytes, sink, .{}, setup.shared.pair.now);
    var activated = false;
    var done = false;
    var served = false;
    var chunks: u32 = 0;
    for (0..64) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.shared.server.reqresp.respond(incoming.request, &payload, context, setup.shared.pair.now);
                setup.shared.client.router.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });
                setup.shared.server.router.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });
                setup.shared.client.reqresp.setRequestFork(.fulu);
                setup.shared.server.reqresp.setRequestFork(.fulu);
                try std.testing.expectEqual(129, setup.shared.client.reqresp.outbound[handle.index].request.chunks_max);
                const owner = &setup.shared.server.reqresp.inbound[incoming.request.index];
                try std.testing.expectEqual(129, owner.request.chunks_max);
                try std.testing.expectEqual(@import("config").ForkSeq.phase0, owner.request_fork);
                activated = true;
            },
            .chunk_sent => |sent| {
                if (sent.chunks == 1) {
                    try setup.shared.server.reqresp.respond(sent.request, &payload, context, setup.shared.pair.now);
                } else try std.testing.expect(setup.shared.server.reqresp.finish(sent.request, setup.shared.pair.now));
            },
            .served => served = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expect(activated);
                try std.testing.expectEqual(@as(?@import("config").ForkSeq, .phase0), chunk.fork);
                try std.testing.expectEqualSlices(u8, &payload, chunk.bytes);
                chunks += 1;
                try std.testing.expect(setup.shared.client.reqresp.consume(chunk.request, setup.shared.pair.now));
            },
            .done => done = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        if (done and served) break;
    }
    try std.testing.expect(activated and done and served);
    try std.testing.expectEqual(2, chunks);
    try std.testing.expectError(error.ProtocolDisabled, setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .blocks_by_root_v2, &bytes, sink, .{}, setup.shared.pair.now));
}

fn pumpRouter(router: *@import("router.zig").Router, pair: *support.Pair, transport: *engine.Engine, now: @import("types.zig").Now, outcomes: []@import("router.zig").Outcome) usize {
    var activity: [128]engine.Handle = undefined;
    for (activity[0..pair.activity(transport, &activity)]) |conn| router.connectionActivity(conn);
    return router.pump(transport, now, outcomes);
}
