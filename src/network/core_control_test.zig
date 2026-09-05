const std = @import("std");
const Setup = @import("core_test.zig").Setup;
const t = @import("peers/types.zig");
const wire = @import("peers/control_wire.zig");
const rr = @import("reqresp/root.zig");
const Engine = @import("quic/engine.zig");

test "core control native Fulu serves older schemas but old Status cannot establish relevance" {
    const local: t.LocalState = .{
        .fork = .{ .fork = .fulu },
        .status = .{ .earliest_available_slot = 0 },
        .metadata = .{ .seq_number = 8, .custody_group_count = 1 },
    };
    for ([_]rr.Protocol{
        .status_v1,
        .status_v2,
        .metadata_v1,
        .metadata_v2,
        .metadata_v3,
        .ping_v1,
        .goodbye_v1,
    }) |protocol| {
        var setup: Setup = .{};
        try setup.init(&local);
        defer setup.deinit();
        for (0..50) |_| try setup.step(0);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.client.snapshots(&snapshots);
        const conn = snapshots[0].connection.?;
        var request_bytes: [92]u8 = @splat(0);
        const length: usize = switch (protocol) {
            .status_v1, .status_v2 => try wire.encodeStatus(
                protocol,
                &local.status,
                &request_bytes,
            ),
            .ping_v1, .goodbye_v1 => 8,
            else => 0,
        };
        var sink: [92]u8 = undefined;
        const request = try setup.client.service.request(
            &setup.pair.client,
            conn,
            protocol,
            request_bytes[0..length],
            &sink,
            .{},
            setup.pair.now,
        );
        defer setup.client.shutdown(&setup.pair.client, setup.pair.now);
        var chunks: usize = 0;
        var terminal = false;
        for (0..50) |_| {
            try setup.pair.pump();
            var transport: [32]Engine.Event = undefined;
            _ = setup.server.process(&setup.pair.server, setup.pair.events(
                &setup.pair.server,
                &transport,
            ), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
            var output: [1]rr.Event = undefined;
            const counts = setup.client.service.processPartitioned(&setup.pair.client, setup.pair.events(
                &setup.pair.client,
                &transport,
            ), &.{}, setup.pair.now, &.{}, &output, &.{});
            if (counts.control == 0) continue;
            switch (output[0]) {
                .chunk => |chunk| {
                    try std.testing.expectEqualDeep(request, chunk.request);
                    try std.testing.expectEqual(protocol.info().response_min, chunk.bytes.len);
                    try std.testing.expect(setup.client.consume(request, setup.pair.now));
                    chunks += 1;
                },
                .done => terminal = true,
                .request => |incoming| {
                    try std.testing.expectEqual(rr.Protocol.goodbye_v1, incoming.protocol);
                    _ = setup.client.finish(incoming.request, setup.pair.now);
                },
                .served => {},
                else => return error.UnexpectedControlResult,
            }
        }
        try std.testing.expect(terminal);
        try std.testing.expectEqual(@as(usize, if (protocol == .goodbye_v1) 0 else 1), chunks);
        if (protocol == .status_v1 or protocol == .goodbye_v1) {
            setup.pair.advance(2_001);
            _ = setup.server.process(
                &setup.pair.server,
                &.{},
                &.{},
                setup.pair.now,
                100,
                &.{},
                &.{},
                &.{},
            );
            var event: [1]t.Event = undefined;
            try std.testing.expectEqual(@as(usize, 1), setup.server.catalog.pollEvents(&event));
            try std.testing.expectEqual(if (protocol == .status_v1)
                t.DisconnectReason.missing_availability
            else
                t.DisconnectReason.remote_goodbye, event[0].closed.reason);
        }
    }
}

test "core native application response borrows survive same turn hard close" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const size = rr.Protocol.blocks_by_root_v2.info().response_max;
    const sink = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(sink);
    defer setup.client.shutdown(&setup.pair.client, setup.pair.now);
    const request = try setup.client.sendReqRespRequest(
        &setup.pair.client,
        snapshots[0].connection.?,
        .blocks_by_root_v2,
        &.{},
        sink,
        .{ .expected_chunks = 1 },
        setup.pair.now,
    );
    var response = [_]u8{7} ** rr.Protocol.blocks_by_root_v2.info().response_min;
    var received = false;
    var sent = false;
    for (0..50) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        var output: [1]rr.Event = undefined;
        const server = setup.server.process(&setup.pair.server, setup.pair.events(
            &setup.pair.server,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &output, &.{});
        if (server.application == 1) switch (output[0]) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &response, .phase0, setup.pair.now);
            },
            .chunk_sent => |chunk| {
                _ = setup.server.finish(chunk.request, setup.pair.now);
                sent = true;
            },
            else => {},
        };
        if (sent and !received) {
            _ = setup.client.disconnect(peer, .host, setup.pair.now);
            // The queued application response and hard-close cleanup share the next Core turn.
            setup.pair.advance(2_000);
            try setup.pair.pump();
        }
        const client = setup.client.process(&setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &output, &.{});
        if (client.application == 1 and output[0] == .chunk) {
            try std.testing.expectEqualDeep(request, output[0].chunk.request);
            try std.testing.expectEqualSlices(u8, &response, output[0].chunk.bytes);
            try std.testing.expect(setup.client.consume(request, setup.pair.now));
            try std.testing.expectEqualSlices(u8, &response, output[0].chunk.bytes);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectError(
        error.StaleHandle,
        setup.server.respondError(
            .{ .index = 65535, .generation = 42, .direction = .inbound },
            2,
            "busy",
            setup.pair.now,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        setup.client.errorMessage(.{
            .index = 65535,
            .generation = 42,
            .direction = .outbound,
        }).len,
    );
}

test "core native inbound meshsub before Status never creates managed gossip relevance" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    try setup.pair.pump();
    var transport: [32]Engine.Event = undefined;
    const client_events = setup.pair.events(&setup.pair.client, &transport);
    var conn: ?Engine.Handle = null;
    for (client_events) |event| if (event == .connected) {
        conn = event.connected.conn;
    };
    try std.testing.expect(conn != null);
    _ = setup.client.service.gossipsub.peerConnected(&setup.pair.client, conn.?, setup.pair.now);
    for (0..30) |_| {
        try setup.pair.pump();
        _ = setup.server.process(&setup.pair.server, setup.pair.events(
            &setup.pair.server,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        _ = setup.client.service.processPartitioned(&setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, &.{}, &.{}, &.{});
    }
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.snapshots(&snapshots));
    try std.testing.expect(!snapshots[0].relevant);
    try std.testing.expect(!setup.server.service.gossipsub.admitted(snapshots[0].connection.?));
    try std.testing.expectEqual(@as(f64, 0), snapshots[0].score);
    try std.testing.expectEqual(@as(u16, 0), setup.server.connectedPeerCount());
}

test "core native shutdown cancels shared negotiations before native retirement without outputs" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    _ = try setup.client.service.router.beginMeshsub(&setup.pair.client, conn, setup.pair.now);
    try std.testing.expect(setup.client.service.router.negotiator.active() > 0);
    setup.client.shutdown(&setup.pair.client, setup.pair.now);
    setup.client.shutdown(&setup.pair.client, setup.pair.now);
    try std.testing.expectEqual(@as(usize, 0), setup.client.service.router.negotiator.active());
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
}

test "core native inbound application per peer cap protects control from extra raw bulk owners" {
    var setup: Setup = .{};
    var options = @import("core_test.zig").options();
    options.service.reqresp.inbound_max = 24;
    options.service.reqresp.outbound_max = 24;
    options.service.reqresp.inbound_per_peer_max = 16;
    options.service.reqresp.outbound_per_peer_max = 0;
    options.service.reqresp.inbound_application_per_peer_max = 8;
    try setup.initOwnersWithOptions(&.{}, options);
    defer setup.deinit();
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    const size = rr.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, size * 9);
    defer std.testing.allocator.free(sinks);
    defer setup.client.shutdown(&setup.pair.client, setup.pair.now);
    const protocols = [_]rr.Protocol{
        .blocks_by_range_v2,
        .blocks_by_root_v2,
        .blob_sidecars_by_range_v1,
        .blob_sidecars_by_root_v1,
        .data_column_sidecars_by_root_v1,
    };
    const bytes: [24]u8 = @splat(0);
    for (0..9) |index| {
        const protocol = protocols[index / 2];
        _ = try setup.client.service.request(
            &setup.pair.client,
            conn,
            protocol,
            bytes[0..protocol.info().request_min],
            sinks[index * size ..][0..size],
            .{},
            setup.pair.now,
        );
    }
    setup.client.reStatusPeers(setup.pair.now);
    for (0..40) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 1), setup.client.connectedPeerCount());
    var count: usize = 0;
    var first: ?rr.RequestHandle = null;
    for (0..20) |_| {
        var output: [1]rr.Event = undefined;
        const result = setup.server.process(
            &setup.pair.server,
            &.{},
            &.{},
            setup.pair.now,
            100,
            &.{},
            &output,
            &.{},
        );
        if (result.application == 1 and output[0] == .request) {
            count += 1;
            first = first orelse output[0].request.request;
        }
    }
    try std.testing.expectEqual(@as(usize, 8), count);
    _ = setup.server.snapshots(&snapshots);
    const server_conn = snapshots[0].connection.?;
    try std.testing.expect(setup.server.cancel(first.?));
    setup.server.service.reqresp.inner.cleanupPending(
        &setup.pair.server,
        &setup.server.service.router,
    );
    try std.testing.expectEqual(
        @as(u16, 8),
        setup.server.service.reqresp.inner.inboundApplicationCount(server_conn),
    );
    var stale = server_conn;
    stale.generation += 1;
    try std.testing.expectEqual(
        @as(u16, 0),
        setup.server.service.reqresp.inner.inboundApplicationCount(stale),
    );
}

test "core native older Ping sequence cannot confirm cached metadata freshness" {
    var setup: Setup = .{};
    try setup.init(&.{ .metadata = .{ .seq_number = 10 } });
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const before = snapshots[0].metadata_at_ms;
    try setup.server.updateMetadata(&.{ .seq_number = 9 });
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(u64, 10), snapshots[0].metadata.?.seq_number);
    try std.testing.expectEqual(before, snapshots[0].metadata_at_ms);
    try std.testing.expect(snapshots[0].relevant);
}

test "core native immutable Status writer survives local update" {
    var setup: Setup = .{};
    const original: t.LocalState = .{ .status = .{ .head_slot = 40 } };
    try setup.init(&original);
    defer setup.deinit();
    var pending = false;
    for (0..40) |_| {
        try setup.step(0);
        for (setup.server.control.responses) |response| if (response.request) |request| {
            const slot = setup.server.service.reqresp.inner.inboundSlot(request).?;
            if (slot.protocol != .status_v1) continue;
            try std.testing.expect(slot.io.writing);
            try setup.server.updateStatus(&.{ .head_slot = 80 });
            pending = true;
            break;
        };
        if (pending) break;
    }
    try std.testing.expect(pending);
    for (0..40) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(original.status, snapshots[0].status.?);
    setup.client.reStatusPeers(setup.pair.now);
    for (0..40) |_| try setup.step(0);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(u64, 80), snapshots[0].status.?.head_slot);
}
