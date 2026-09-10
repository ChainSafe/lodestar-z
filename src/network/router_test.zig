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
    var server = try @import("service.zig").Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1 }, .reqresp = rr_options.reqresp });
    defer server.deinit();
    const requests = &server.reqresp;
    const gossip = &server.gossipsub;
    const handles = try support.connectPair(&pair);
    _ = gossip.peerConnected(&pair.server, handles.server, pair.now);
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
                try std.testing.expect(client.handler.consume(chunk.request, pair.now));
                pong = true;
            },
            else => {},
        };
        try pair.pump();
        const events = pair.events(&pair.server, &transport_events);
        var gossip_events: [16]gs.Event = undefined;
        const server_active = pair.server.driverView().takeActivity(&activity);
        const counts = server.processPartitioned(
            &pair.server,
            events,
            activity[0..server_active],
            pair.now,
            &.{},
            &request_events,
            &gossip_events,
        );
        try std.testing.expectEqual(0, counts.application);
        const request_count = counts.control;
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
    var client = try @import("service.zig").Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1 }, .reqresp = .{
        .forks = &.{},
        .outbound_max = 1,
        .inbound_max = 1,
        .work_per_pump_max = 1,
    } });
    defer client.deinit();
    defer client.reqresp.shutdown(&client.router, &pair.client);
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
    for (0..2) |_| {
        if (client.reqresp.inner.work_cursor == 1) break;
        _ = client.process(&pair.client, &.{}, &.{}, pair.now, &requests, &gossip);
    }
    try std.testing.expectEqual(@as(usize, 1), client.reqresp.inner.work_cursor);
    var wire: [rr.codec.frame_scratch_max]u8 = undefined;
    const encoded = try rr.codec.encodeChunk(0, null, &ping, &wire);
    const stream = server.handler.inner.inbound[incoming.?.index].stream;
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

test "router gossip capacity refusal preserves reqresp and explicit host retry" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var client = try rr.Service.init(std.testing.allocator, rr_options);
    defer client.deinit();
    defer client.shutdown(&pair.client);
    var server = try @import("service.zig").Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1 }, .reqresp = rr_options.reqresp });
    defer server.deinit();
    defer server.reqresp.shutdown(&server.router, &pair.server);
    const handles = try support.connectPair(&pair);
    const peers = @import("gossipsub/peer_book.zig");
    for (0..peers.capacity - peers.outbound_reserve) |i| {
        var metadata: peers.Metadata = .{ .identity = .{ .bytes = [_]u8{0} ** @import("wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
        std.mem.writeInt(u16, metadata.identity.bytes[0..2], @intCast(i), .little);
        const ref = server.gossipsub.inner.peers.admit(.{ .index = 0, .generation = 1 }, &metadata, pair.now.mono_ms).admitted.peer;
        server.gossipsub.inner.peers.scores.penalize(ref.index, 20);
        _ = server.gossipsub.inner.peers.scores.setAppScore(ref.index, -1);
        server.gossipsub.inner.peers.disconnect(ref, pair.now.mono_ms);
    }
    try std.testing.expectEqual(gs.Handler.Admission.capacity, server.gossipsub.peerConnected(&pair.server, handles.server, pair.now));
    try std.testing.expect(!server.gossipsub.admitted(handles.server));
    const ping = [_]u8{7} ** 8;
    var sink: [8]u8 = undefined;
    _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, &sink, .{}, pair.now);
    var pong = false;
    for (0..64) |_| {
        var transport: [16]engine.Event = undefined;
        var requests: [16]rr.Event = undefined;
        var gossip: [16]gs.Event = undefined;
        var activity: [128]engine.Handle = undefined;
        try pair.pump();
        const active_client = pair.client.driverView().takeActivity(&activity);
        const count = client.process(&pair.client, pair.events(&pair.client, &transport), activity[0..active_client], pair.now, &requests);
        for (requests[0..count]) |event| if (event == .chunk) {
            try std.testing.expectEqualSlices(u8, &ping, event.chunk.bytes);
            try std.testing.expect(client.handler.consume(event.chunk.request, pair.now));
            pong = true;
        };
        const active_server = pair.server.driverView().takeActivity(&activity);
        const counts = server.process(&pair.server, pair.events(&pair.server, &transport), activity[0..active_server], pair.now, &requests, &gossip);
        for (requests[0..counts.reqresp]) |event| switch (event) {
            .request => |request| try server.reqresp.respond(request.request, &ping, null, pair.now),
            .chunk_sent => |sent| _ = server.reqresp.finish(sent.request, pair.now),
            else => {},
        };
        if (pong) break;
    }
    try std.testing.expect(pong);
    try std.testing.expect(!server.gossipsub.admitted(handles.server));
    server.gossipsub.inner.peers.rows[0].retain_until = pair.now.mono_ms;
    try std.testing.expectEqual(gs.Handler.Admission.admitted, server.gossipsub.peerConnected(&pair.server, handles.server, pair.now));
    try std.testing.expect(server.gossipsub.admitted(handles.server));
}

test "protocol compositions expose no standalone processing on shared handlers" {
    const Shared = @import("service.zig").Service;
    const RequestHandler = @FieldType(Shared, "reqresp");
    const GossipHandler = @FieldType(Shared, "gossipsub");
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
    var versions = [_]@import("gossipsub/sessions.zig").Version{ .v1_0, .v1_2 };
    var router = try routing.Router.init(std.testing.allocator, .{ .capabilities = active, .meshsub_versions = &versions });
    defer router.deinit();
    versions[0] = .v1_1;
    try std.testing.expectEqualDeep(active, router.capabilities());
    try std.testing.expectEqualStrings("/meshsub/1.0.0", router.meshsub_candidates[0]);
    try std.testing.expectEqualStrings("/meshsub/1.2.0", router.meshsub_candidates[1]);
    try std.testing.expectEqual(1, router.supported_count);
    try std.testing.expectEqualStrings(rr.Protocol.ping_v1.id(), router.supported[0]);
    var invalid = active;
    invalid.receive.insert(.{ .meshsub = .v1_1 });
    try std.testing.expectError(error.InvalidCapabilities, router.validateCapabilities(invalid));
    try std.testing.expectEqualDeep(active, router.capabilities());
    try std.testing.expectError(error.InvalidCapabilities, routing.Router.init(std.testing.allocator, .{ .capabilities = active, .reqresp = false }));
    active.receive = .initEmpty();
    try std.testing.expectError(error.InvalidCapabilities, routing.Router.init(std.testing.allocator, .{ .capabilities = active, .meshsub = false }));
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
        .reqresp = rr_options.reqresp,
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

test "router capabilities pending inbound listener retains old offer while new listener rejects" {
    const routing = @import("router.zig");
    const caps = @import("capabilities.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var client = try routing.Router.init(std.testing.allocator, .{});
    defer client.deinit();
    var active: caps.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() };
    active.receive.insert(.{ .reqresp = .ping_v1 });
    var server = try routing.Router.init(std.testing.allocator, .{ .capabilities = active });
    defer server.deinit();
    for (0..2) |wave| {
        _ = try client.beginOutbound(&pair.client, handles.client, .{ .reqresp = .ping_v1 }, pair.now);
        var accepted = false;
        var completed = false;
        for (0..32) |_| {
            var outcomes: [16]routing.Outcome = undefined;
            const count = client.pump(&pair.client, pair.now, &outcomes);
            for (outcomes[0..count]) |outcome| {
                if (wave == 0) {
                    try std.testing.expect(outcome.result == .ready);
                    try std.testing.expectEqual(rr.Protocol.ping_v1, outcome.result.ready.protocol.reqresp);
                } else try std.testing.expect(outcome.result == .rejected);
                completed = true;
            }
            try pair.pump();
            var events: [16]engine.Event = undefined;
            server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
            if (!accepted and server.negotiator.active() > 0) {
                accepted = true;
                if (wave == 0) {
                    active.receive = .initEmpty();
                    active.receive.insert(.{ .reqresp = .goodbye_v1 });
                    try server.validateCapabilities(active);
                    server.setCapabilities(active);
                }
            }
            _ = server.pump(&pair.server, pair.now, &outcomes);
            try pair.pump();
            if (completed) break;
        }
        try std.testing.expect(accepted and completed);
    }
    active.receive = .initEmpty();
    server.setCapabilities(active);
    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(1, try pair.client.write(stream, &.{0}, false));
    try pair.pump();
    var events: [16]engine.Event = undefined;
    server.transportEvents(&pair.server, pair.events(&pair.server, &events), pair.now);
    try std.testing.expectEqual(0, server.negotiator.active());
}

test "router capabilities activation preserves negotiated response context and captured ceiling" {
    const harness = @import("reqresp/reqresp_test.zig");
    const ct = @import("consensus_types");
    const context: rr.ForkEntry = .{ .digest = .{ 9, 10, 11, 12 }, .fork = .phase0 };
    var setup: harness.ReqRespPair = .{};
    const limits = @import("reqresp/admission_test.zig").quotas(2048, 1000);
    const options: harness.Overrides = .{
        .forks = &.{context},
        .request_policy = @import("reqresp/request_policy_test.zig").fixture(),
        .admission = .{ .identities = 2, .peer = limits, .global = limits },
    };
    try setup.init(options, options);
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    const bytes: [129 * 32]u8 = @splat(0);
    const payload: [ct.phase0.SignedBeaconBlock.min_size]u8 = @splat(0);
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, &bytes, sink, .{}, setup.pair.now);
    var activated = false;
    var done = false;
    var served = false;
    var chunks: u32 = 0;
    for (0..64) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &payload, context, setup.pair.now);
                setup.client_neg.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });
                setup.server_neg.setCapabilities(.{ .receive = .initEmpty(), .request = .initEmpty() });
                setup.client.setRequestFork(.fulu);
                setup.server.setRequestFork(.fulu);
                try std.testing.expectEqual(129, setup.client.outbound[handle.index].chunks_max);
                const owner = &setup.server.inbound[incoming.request.index];
                try std.testing.expectEqual(129, owner.chunks_max);
                try std.testing.expectEqual(@import("config").ForkSeq.phase0, owner.request_fork);
                activated = true;
            },
            .chunk_sent => |sent| {
                if (sent.chunks == 1) {
                    try setup.server.respond(sent.request, &payload, context, setup.pair.now);
                } else try std.testing.expect(setup.server.finish(sent.request, setup.pair.now));
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
                try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
            },
            .done => done = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        if (done and served) break;
    }
    try std.testing.expect(activated and done and served);
    try std.testing.expectEqual(2, chunks);
    try std.testing.expectError(error.ProtocolDisabled, setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, &bytes, sink, .{}, setup.pair.now));
}
