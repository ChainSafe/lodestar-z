const std = @import("std");
const Setup = @import("core_test.zig").Setup;
const t = @import("peers/types.zig");
const wire = @import("peers/control_wire.zig");
const rr = @import("reqresp/root.zig");
const Engine = @import("quic/engine.zig");

test "core records a buffered Goodbye before transport cancellation and preserves selected local reasons" {
    const multistream = @import("wire/multistream.zig");
    const codec = @import("reqresp/codec.zig");
    for ([_]bool{ false, true }) |local_ban| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..50) |_| try setup.step(1);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.client.snapshots(&snapshots);
        const conn = snapshots[0].connection.?;
        _ = setup.server.snapshots(&snapshots);
        const peer = snapshots[0].peer;
        const stream = try setup.pair.client.openStream(conn);
        var wire_bytes: [512]u8 = undefined;
        const header = try multistream.encodeMessage(multistream.header, &wire_bytes);
        const selected = try multistream.encodeMessage(rr.Protocol.goodbye_v1.id(), wire_bytes[header.len..]);
        const size = header.len + selected.len;
        try std.testing.expectEqual(size, try setup.pair.client.write(stream, wire_bytes[0..size], false));
        var ready = false;
        for (0..40) |_| {
            try setup.step(0);
            for (setup.server.service.reqresp.inner.inbound) |slot| if (slot.state == .receiving_request and slot.protocol == .goodbye_v1) {
                ready = true;
            };
            if (ready) break;
        }
        try std.testing.expect(ready);
        var reason: [8]u8 = undefined;
        std.mem.writeInt(u64, &reason, 129, .little);
        const body = try codec.encodeRequest(&reason, &wire_bytes);
        try std.testing.expectEqual(body.len, try setup.pair.client.write(stream, body, true));
        try setup.pair.pump();
        if (local_ban) try std.testing.expectEqual(t.ReputationDecision.ban, setup.server.reportPeer(peer, .fatal, setup.pair.now).?);
        try std.testing.expect(setup.pair.client.close(conn, 0));
        try setup.pair.pump();
        var events: [32]Engine.Event = undefined;
        _ = setup.server.process(&setup.pair.server, setup.pair.events(&setup.pair.server, &events), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        const snapshot = setup.server.catalog.get(peer).?;
        try std.testing.expect(snapshot.connection == null);
        var closed: [1]t.Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.server.catalog.pollEvents(&closed));
        try std.testing.expectEqual(if (local_ban) t.DisconnectReason.banned else .remote_goodbye, closed[0].closed.reason);
        try std.testing.expect(snapshot.goodbye_until_ms >= setup.pair.now.mono_ms + 300_000);
        try std.testing.expectEqual(@as(u64, 1), setup.server.control.counters.goodbyes[@intFromEnum(@import("peers/goodbye.zig").Reason.too_many_peers)]);
        try std.testing.expectEqual(@as(u64, 1), setup.server.service.reqresp.inner.counters.goodbyes_recovered_on_close);
    }
}

test "core local head and metadata updates preserve periodic status scheduling" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..80) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.snapshots(&snapshots));
    const peer = snapshots[0].peer;
    try std.testing.expect(snapshots[0].relevant);
    const due = setup.client.control.schedules[peer.index].status_due_ms;
    const started = setup.client.service.reqresp.inner.protocol_counters[@intFromEnum(rr.Protocol.status_v1)].outgoing;
    for (0..3) |_| {
        var local = setup.client.local;
        local.status.head_slot += 1;
        local.metadata.seq_number += 1;
        setup.client.commitLocal(&local, setup.pair.now);
        for (0..40) |_| try setup.step(1);
        try std.testing.expectEqual(due, setup.client.control.schedules[peer.index].status_due_ms);
        try std.testing.expectEqual(started, setup.client.service.reqresp.inner.protocol_counters[@intFromEnum(rr.Protocol.status_v1)].outgoing);
    }
    setup.pair.advance(1);
    setup.client.reStatusPeers(setup.pair.now);
    for (0..40) |_| try setup.step(1);
    try std.testing.expectEqual(started + 1, setup.client.service.reqresp.inner.protocol_counters[@intFromEnum(rr.Protocol.status_v1)].outgoing);
    try std.testing.expect(setup.client.control.schedules[peer.index].status_due_ms > due);
}

test "core native stalled fork transition only wakes for eligible work" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..80) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    try std.testing.expect(snapshots[0].relevant);
    try std.testing.expect(setup.client.service.gossipsub.admitted(conn));
    const gossip_due = setup.client.control.schedules[peer.index].gossip_retry_ms;
    try std.testing.expect(gossip_due > setup.pair.now.mono_ms);
    try std.testing.expectEqual(gossip_due, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    const updated: t.LocalState = .{
        .fork = .{ .fork = .fulu, .digest = @splat(1) },
        .status = .{ .fork_digest = @splat(1), .earliest_available_slot = 0 },
        .metadata = .{ .seq_number = 1, .custody_group_count = 1 },
    };
    try setup.client.updateFork(&updated, setup.pair.now);
    setup.pair.advance(1500);
    for (0..8) |_| {
        _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    }
    try std.testing.expect(!setup.client.catalog.get(peer).?.relevant);
    try std.testing.expect(gossip_due < setup.pair.now.mono_ms);
    try std.testing.expect(setup.client.service.gossipsub.admitted(conn));
    var active: usize = 0;
    for (setup.client.control.operations) |op| if (op.request != null and !op.cancelled) {
        active += 1;
    };
    try std.testing.expect(active > 0);
    const service_due = setup.client.service.nextWakeupPartitioned(setup.pair.now, 0, 32, 0).?;
    try std.testing.expect(service_due > setup.pair.now.mono_ms);
    try std.testing.expect(setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now) == null);
    const core_due = setup.client.nextWakeup(setup.pair.now, 0, 0, 0, 0).?;
    try std.testing.expect(core_due > setup.pair.now.mono_ms and core_due <= service_due);
    try setup.server.updateFork(&updated, setup.pair.now);
    for (0..80) |_| try setup.step(0);
    try std.testing.expect(setup.client.catalog.get(peer).?.relevant);
    const resumed = setup.client.control.schedules[peer.index].gossip_retry_ms;
    try std.testing.expectEqual(setup.pair.now.mono_ms + 1_000, resumed);
    try std.testing.expectEqual(resumed, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    setup.pair.advance(1_000);
    try std.testing.expectEqual(setup.pair.now.mono_ms, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(setup.pair.now.mono_ms + 1_000, setup.client.control.schedules[peer.index].gossip_retry_ms);
}

test "core native host fork transition cancels old maintenance without reviving closing peers" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const before = snapshots[0];
    setup.client.reStatusPeers(setup.pair.now);
    setup.server.reStatusPeers(setup.pair.now);
    try setup.step(0);
    var old_operations: usize = 0;
    for (setup.client.control.operations) |op| if (op.request != null) {
        old_operations += 1;
    };
    try std.testing.expect(old_operations > 0);
    const updated: t.LocalState = .{
        .fork = .{ .fork = .fulu, .digest = @splat(1) },
        .status = .{ .fork_digest = @splat(1), .earliest_available_slot = 0 },
        .metadata = .{ .seq_number = 1, .custody_group_count = 1 },
    };
    try setup.client.updateFork(&updated, setup.pair.now);
    try setup.server.updateFork(&updated, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().relevant);
    const invalidated = setup.client.catalog.get(before.peer).?;
    try std.testing.expectEqualDeep(before.connection, invalidated.connection);
    try std.testing.expect(invalidated.status == null and invalidated.disconnect_reason == null);
    for (setup.client.control.operations) |op| if (op.request != null) {
        try std.testing.expect(op.cancelled);
    };
    for (0..80) |_| try setup.step(1);
    const confirmed = setup.client.catalog.get(before.peer).?;
    try std.testing.expect(confirmed.relevant);
    try std.testing.expectEqualDeep(before.connection, confirmed.connection);
    try std.testing.expectEqual(@as(u64, 0), confirmed.status.?.earliest_available_slot.?);
    try std.testing.expectEqual(@as(u64, 1), confirmed.metadata.?.seq_number);
    try std.testing.expect(setup.client.disconnect(before.peer, .host, setup.pair.now));
    const deadline = setup.client.control.schedules[before.peer.index].closing.?.deadline_ms;
    var next = updated;
    next.fork.digest = @splat(2);
    next.status.fork_digest = @splat(2);
    try setup.client.updateFork(&next, setup.pair.now);
    try std.testing.expectEqual(t.DisconnectReason.host, setup.client.catalog.get(before.peer).?.disconnect_reason.?);
    try std.testing.expectEqual(deadline, setup.client.control.schedules[before.peer.index].closing.?.deadline_ms);
}

test "core native previous fork request grace does not refresh relevance and expires" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.server.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const updated: t.LocalState = .{
        .fork = .{ .fork = .fulu, .digest = @splat(1) },
        .status = .{ .fork_digest = @splat(1), .earliest_available_slot = 0 },
        .metadata = .{ .seq_number = 1, .custody_group_count = 1 },
    };
    try setup.client.updateFork(&updated, setup.pair.now);
    try setup.server.updateFork(&updated, setup.pair.now);
    for (0..80) |_| try setup.step(1);
    const before = setup.server.catalog.get(peer).?;
    const deadline = setup.server.control.schedules[peer.index].transition_until_ms;
    setup.pair.advance(100);
    try previousStatus(&setup);
    const after = setup.server.catalog.get(peer).?;
    try std.testing.expectEqualDeep(before.status, after.status);
    try std.testing.expectEqual(before.status_at_ms, after.status_at_ms);
    try std.testing.expectEqual(before.metadata_at_ms, after.metadata_at_ms);
    try std.testing.expect(after.relevant and after.disconnect_reason == null);
    try std.testing.expectEqual(deadline, setup.server.control.schedules[peer.index].transition_until_ms);
    setup.pair.advance(10_001);
    try previousStatus(&setup);
    try std.testing.expectEqual(t.DisconnectReason.incompatible_fork, setup.server.catalog.get(peer).?.disconnect_reason.?);
}

fn previousStatus(setup: *Setup) !void {
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    var bytes: [84]u8 = @splat(0);
    var sink: [84]u8 = undefined;
    const handle = try setup.client.service.request(&setup.pair.client, snapshots[0].connection.?, .status_v1, &bytes, &sink, .{}, setup.pair.now);
    var done = false;
    for (0..80) |_| {
        try setup.pair.pump();
        var events: [32]Engine.Event = undefined;
        _ = setup.server.process(&setup.pair.server, setup.pair.events(&setup.pair.server, &events), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        var out: [1]rr.Event = undefined;
        const count = setup.client.service.processPartitioned(&setup.pair.client, setup.pair.events(&setup.pair.client, &events), &.{}, setup.pair.now, &.{}, &out, &.{});
        for (out[0..count.control]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualDeep(handle, chunk.request);
                try std.testing.expect(setup.client.consume(handle, setup.pair.now));
            },
            .done => {
                done = true;
            },
            .request => |request| {
                try setup.client.respond(request.request, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, null, setup.pair.now);
            },
            .chunk_sent => |sent| {
                _ = setup.client.finish(sent.request, setup.pair.now);
            },
            else => {},
        };
        if (done) break;
    }
    try std.testing.expect(done);
}

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
        var goodbye_writer = false;
        const goodbye_reply: [8]u8 = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
        for (0..50) |_| {
            try setup.pair.pump();
            var transport: [32]Engine.Event = undefined;
            _ = setup.server.process(&setup.pair.server, setup.pair.events(
                &setup.pair.server,
                &transport,
            ), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
            if (protocol == .goodbye_v1) {
                for (setup.server.control.responses) |response| if (response.request) |inbound| {
                    const owner = setup.server.service.reqresp.inner.inboundSlot(inbound).?;
                    if (owner.protocol != .goodbye_v1 or !owner.io.writing) continue;
                    try std.testing.expectEqualSlices(u8, &goodbye_reply, response.bytes[0..8]);
                    goodbye_writer = true;
                };
            }
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
                    if (protocol == .goodbye_v1) {
                        try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, chunk.bytes[0..8], .little));
                    }
                    try std.testing.expect(setup.client.consume(request, setup.pair.now));
                    chunks += 1;
                },
                .done => terminal = true,
                .request => |incoming| {
                    try std.testing.expectEqual(rr.Protocol.goodbye_v1, incoming.protocol);
                    try setup.client.respond(incoming.request, &goodbye_reply, null, setup.pair.now);
                },
                .chunk_sent => |sent| {
                    try std.testing.expect(setup.client.finish(sent.request, setup.pair.now));
                },
                .served => {},
                else => return error.UnexpectedControlResult,
            }
        }
        try std.testing.expect(terminal);
        try std.testing.expectEqual(@as(usize, 1), chunks);
        if (protocol == .goodbye_v1) try std.testing.expect(goodbye_writer);
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
                try setup.server.respond(incoming.request, &response, .{ .digest = @splat(0), .fork = .phase0 }, setup.pair.now);
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
    try std.testing.expectEqual(@as(u16, 0), setup.server.peerCounts().relevant);
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
    try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
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

test "core control native Goodbye maps shutdown incompatibility and fault wire reasons" {
    const cases = [_]struct { reason: t.DisconnectReason, wire_reason: u64 }{
        .{ .reason = .shutdown, .wire_reason = 1 },
        .{ .reason = .incompatible_fork, .wire_reason = 2 },
        .{ .reason = .invalid_metadata, .wire_reason = 3 },
    };
    for (cases) |case| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..50) |_| try setup.step(0);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.client.snapshots(&snapshots);
        try std.testing.expect(setup.client.disconnect(snapshots[0].peer, case.reason, setup.pair.now));
        var received = false;
        for (0..40) |_| {
            try setup.pair.pump();
            var transport: [32]Engine.Event = undefined;
            _ = setup.client.process(&setup.pair.client, setup.pair.events(&setup.pair.client, &transport), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
            var control: [1]rr.Event = undefined;
            const counts = setup.server.service.processPartitioned(&setup.pair.server, setup.pair.events(&setup.pair.server, &transport), &.{}, setup.pair.now, &.{}, &control, &.{});
            if (counts.control == 0) continue;
            try std.testing.expectEqual(rr.Protocol.goodbye_v1, control[0].request.protocol);
            try std.testing.expectEqual(@as(usize, 8), control[0].request.bytes.len);
            try std.testing.expectEqual(case.wire_reason, std.mem.readInt(u64, control[0].request.bytes[0..8], .little));
            received = true;
            break;
        }
        try std.testing.expect(received);
    }
}

test "core control irrelevant metadata cannot create an ineligible wakeup" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..80) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    try std.testing.expect(setup.client.catalog.invalidateStatus(peer, conn));
    const row = &setup.client.control.schedules[peer.index];
    row.metadata_pending = true;
    row.gossip_retry_ms = 0;
    row.status_due_ms = setup.pair.now.mono_ms + 100;
    row.ping_due_ms = setup.pair.now.mono_ms + 200;
    const started = setup.client.control.counters.started;
    setup.client.control.maintain(&setup.client.service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    try std.testing.expectEqual(started, setup.client.control.counters.started);
    try std.testing.expectEqual(setup.pair.now.mono_ms + 100, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    setup.pair.advance(100);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(started + 1, setup.client.control.counters.started);
}

test "core control initial gossip admission wakes alongside active request" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..80) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const row = &setup.client.control.schedules[peer.index];
    setup.client.reStatusPeers(setup.pair.now);
    setup.client.control.maintain(&setup.client.service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    const started = setup.client.control.counters.started;
    row.gossip_retry_ms = 0;
    try std.testing.expectEqual(setup.pair.now.mono_ms, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    setup.client.control.maintain(&setup.client.service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    try std.testing.expectEqual(setup.pair.now.mono_ms + 1000, row.gossip_retry_ms);
    try std.testing.expectEqual(started, setup.client.control.counters.started);
    try std.testing.expect(setup.client.disconnect(peer, .host, setup.pair.now));
    const deadline = row.closing.?.deadline_ms;
    try std.testing.expectEqual(deadline, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    setup.pair.advance(2000);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expect(setup.client.catalog.get(peer).?.connection == null);
}

test "core control cancelled canonical requests retain buffers through local retry" {
    var setup: Setup = .{};
    var opts = @import("core_test.zig").options();
    opts.control.operations_max = 1;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    _ = try setup.pair.dial();
    for (0..80) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    setup.client.reStatusPeers(setup.pair.now);
    setup.client.control.maintain(&setup.client.service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    const op = &setup.client.control.operations[0];
    const request = op.request.?;
    const bytes = op.bytes;
    const updated: t.LocalState = .{
        .fork = .{ .fork = .fulu, .digest = @splat(1) },
        .status = .{ .fork_digest = @splat(1), .earliest_available_slot = 0 },
        .metadata = .{ .custody_group_count = 1 },
    };
    try setup.client.updateFork(&updated, setup.pair.now);
    try std.testing.expect(op.cancelled);
    const started = setup.client.control.counters.started;
    const deferred = setup.client.control.counters.deferred;
    setup.client.control.maintain(&setup.client.service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    try std.testing.expectEqual(request, op.request.?);
    try std.testing.expectEqualSlices(u8, bytes[0..84], op.bytes[0..84]);
    try std.testing.expectEqual(started, setup.client.control.counters.started);
    try std.testing.expectEqual(deferred + 1, setup.client.control.counters.deferred);
    try std.testing.expectEqual(setup.pair.now.mono_ms + 1000, setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?);
    const grace = setup.client.control.schedules[peer.index].transition_until_ms;
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expect(op.request == null);
    setup.pair.advance(1000);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expect(op.request != null);
    try std.testing.expect(!std.meta.eql(request, op.request.?));
    try std.testing.expect(!op.cancelled);
    try std.testing.expectEqual(grace, setup.client.control.schedules[peer.index].transition_until_ms);
}

test "core control capabilities pre-Fulu Metadata3 serves configured custody count" {
    const local: t.LocalState = .{ .metadata = .{ .custody_group_count = 1 } };
    var setup: Setup = .{};
    try setup.init(&local);
    defer setup.deinit();
    const active = try @import("capabilities.zig").forFork(.phase0, false, &.{ .v1_2, .v1_1 });
    setup.client.service.router.setCapabilities(active);
    setup.server.service.router.setCapabilities(active);
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    var sink: [32]u8 = undefined;
    const request = try setup.client.service.request(&setup.pair.client, snapshots[0].connection.?, .metadata_v3, &.{}, &sink, .{}, setup.pair.now);
    var received = false;
    var done = false;
    for (0..50) |_| {
        try setup.pair.pump();
        var events: [32]Engine.Event = undefined;
        _ = setup.server.process(&setup.pair.server, setup.pair.events(&setup.pair.server, &events), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        var out: [1]rr.Event = undefined;
        const counts = setup.client.service.processPartitioned(&setup.pair.client, setup.pair.events(&setup.pair.client, &events), &.{}, setup.pair.now, &.{}, &out, &.{});
        for (out[0..counts.control]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualDeep(request, chunk.request);
                const metadata = try wire.decodeMetadata(.metadata_v3, chunk.bytes, local.fork);
                try std.testing.expectEqual(local.metadata.custody_group_count, metadata.custody_group_count);
                try std.testing.expect(setup.client.consume(request, setup.pair.now));
                received = true;
            },
            .done => done = true,
            else => return error.TestUnexpectedResult,
        };
        if (done) break;
    }
    try std.testing.expect(received and done);
}

test "identify core schedules once after Status and completes without public output" {
    var setup: Setup = .{};
    var options = @import("core_test.zig").options();
    options.service.identify = .{ .agent = "core-test", .inbound_max = 1, .outbound_max = 1 };
    try setup.initOwnersWithOptions(&.{}, options);
    defer setup.deinit();
    _ = try setup.pair.dial();
    for (0..100) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.snapshots(&snapshots));
    const before = snapshots[0];
    try std.testing.expect(before.relevant);
    try std.testing.expectEqualStrings("core-test", before.identify.?.agent.?.slice());
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.identify_started);
    setup.client.reStatusPeers(setup.pair.now);
    for (0..100) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.identify_started);
    try std.testing.expectEqualDeep(before.identify, setup.client.catalog.get(before.peer).?.identify);
}

test "identify remote refusal completes generation without losing accepted Status" {
    const caps = @import("capabilities.zig");
    var setup: Setup = .{};
    var options = @import("core_test.zig").options();
    options.service.identify = .{ .agent = "core-test", .inbound_max = 1, .outbound_max = 1 };
    try setup.initOwnersWithOptions(&.{}, options);
    defer setup.deinit();
    var active = setup.server.service.router.capabilities();
    const only_identify = caps.withIdentify(.{ .receive = .initEmpty(), .request = .initEmpty() });
    active.receive.bits &= ~only_identify.receive.bits;
    setup.server.service.router.setCapabilities(active);
    _ = try setup.pair.dial();
    for (0..100) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].relevant and snapshots[0].identify == null);
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.identify_started);
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.identify_failures[@intFromEnum(@import("identify/root.zig").Failure.negotiation)]);
    setup.client.reStatusPeers(setup.pair.now);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.identify_started);
    try std.testing.expect(setup.client.catalog.get(snapshots[0].peer).?.relevant);
}

test "identify replacement generation starts a fresh query and rejects stale completion" {
    var setup: Setup = .{};
    var options = @import("core_test.zig").options();
    options.service.identify = .{ .agent = "first", .inbound_max = 1, .outbound_max = 1 };
    try setup.initOwnersWithOptions(&.{}, options);
    defer setup.deinit();
    _ = try setup.pair.server.dial(&@import("test_support.zig").client_address, setup.pair.client_ctx.local_peer_id, setup.pair.now, setup.pair.nextEntropy());
    for (0..100) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const old = snapshots[0];
    try std.testing.expectEqualStrings("first", old.identify.?.agent.?.slice());
    setup.server.service.identify.?.local.?.agent = try .init("replacement");
    _ = try setup.pair.dial();
    for (0..100) |_| try setup.step(1);
    _ = setup.client.snapshots(&snapshots);
    const selected = snapshots[0];
    try std.testing.expectEqualDeep(old.peer, selected.peer);
    try std.testing.expect(!std.meta.eql(old.connection, selected.connection));
    try std.testing.expectEqualStrings("replacement", selected.identify.?.agent.?.slice());
    try std.testing.expectEqual(@as(u64, 2), setup.client.control.counters.identify_started);
    setup.client.control.identifyResults(&setup.client.catalog, &.{.{ .peer = old.peer, .conn = old.connection.?, .outcome = .{ .success = old.identify.? } }});
    try std.testing.expectEqualDeep(selected, setup.client.catalog.get(selected.peer).?);
}

test "identify local refusal retries after one second without resetting accepted Status" {
    var setup: Setup = .{};
    var options = @import("core_test.zig").options();
    options.service.identify = .{ .agent = "core", .inbound_max = 1, .outbound_max = 1 };
    try setup.initOwnersWithOptions(&.{}, options);
    defer setup.deinit();
    _ = try setup.pair.dial();
    var snapshots: [4]t.Snapshot = undefined;
    for (0..16) |_| {
        try setup.step(0);
        if (setup.client.snapshots(&snapshots) == 1) break;
    }
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    try std.testing.expect(!snapshots[0].relevant);
    try setup.client.service.identify.?.start(&setup.client.service.router, &setup.pair.client, .{ .index = 3, .generation = 99 }, conn, setup.pair.now);
    try std.testing.expect(setup.client.catalog.updateStatus(peer, conn, &.{}, setup.pair.now.mono_ms));
    setup.client.control.maintain(&setup.client.service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    const retry = setup.pair.now.mono_ms + 1000;
    try std.testing.expectEqual(retry, setup.client.control.schedules[peer.index].identify_retry_ms);
    try std.testing.expectEqual(@as(u64, 0), setup.client.control.counters.identify_started);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u64, 0), setup.client.control.counters.identify_started);
    setup.pair.now.mono_ms = retry - 1;
    try setup.step(0);
    try std.testing.expectEqual(@as(u64, 0), setup.client.control.counters.identify_started);
    setup.pair.now.mono_ms = retry;
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.identify_started);
    try std.testing.expectEqualStrings("core", setup.client.catalog.get(peer).?.identify.?.agent.?.slice());
}

test "core native targeted Status only schedules the full current nonclosing owner" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..60) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const selected = snapshots[0];
    const other_peer: t.PeerRef = .{ .index = 3, .generation = 55 };
    const other_conn: t.Handle = .{ .index = 3, .generation = 56 };
    setup.client.control.connected(other_peer, other_conn, .inbound, setup.pair.now);
    const other_before = setup.client.control.schedules[3];
    const before = setup.client.control.schedules[selected.peer.index];
    var stale_peer = selected.peer;
    stale_peer.generation += 1;
    var stale_conn = selected.connection.?;
    stale_conn.generation += 1;
    try std.testing.expect(!setup.client.reStatusPeer(stale_peer, selected.connection.?, setup.pair.now));
    try std.testing.expect(!setup.client.reStatusPeer(selected.peer, stale_conn, setup.pair.now));
    try std.testing.expectEqualDeep(before, setup.client.control.schedules[selected.peer.index]);
    try std.testing.expect(setup.client.reStatusPeer(selected.peer, selected.connection.?, setup.pair.now));
    var expected = before;
    expected.status_due_ms = setup.pair.now.mono_ms;
    try std.testing.expectEqualDeep(expected, setup.client.control.schedules[selected.peer.index]);
    try std.testing.expectEqualDeep(other_before, setup.client.control.schedules[3]);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    var selected_started = false;
    for (setup.client.control.operations) |op| {
        if (op.request != null and op.protocol == .status_v1 and std.meta.eql(op.peer, selected.peer)) selected_started = true;
    }
    try std.testing.expect(selected_started);
    try std.testing.expect(setup.client.disconnect(selected.peer, .host, setup.pair.now));
    try std.testing.expect(!setup.client.reStatusPeer(selected.peer, selected.connection.?, setup.pair.now));
    try std.testing.expect(setup.client.closePeer(&setup.pair.client, selected.peer, selected.connection.?, setup.pair.now));
    try std.testing.expect(!setup.client.reStatusPeer(selected.peer, selected.connection.?, setup.pair.now));
}

test "core native application response borrows survive immediate public close" {
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
                try setup.server.respond(incoming.request, &response, .{ .digest = @splat(0), .fork = .phase0 }, setup.pair.now);
            },
            .chunk_sent => |chunk| {
                _ = setup.server.finish(chunk.request, setup.pair.now);
            },
            else => {},
        };
        const client = setup.client.process(&setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &output, &.{});
        if (client.application == 1 and output[0] == .chunk) {
            try std.testing.expectEqualDeep(request, output[0].chunk.request);
            try std.testing.expectEqualSlices(u8, &response, output[0].chunk.bytes);
            try std.testing.expect(setup.client.closePeer(&setup.pair.client, peer, snapshots[0].connection.?, setup.pair.now));
            try std.testing.expectEqualSlices(u8, &response, output[0].chunk.bytes);
            try std.testing.expect(setup.client.consume(request, setup.pair.now));
            try std.testing.expectEqualSlices(u8, &response, output[0].chunk.bytes);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
}

test "application graceful quiescence sends shutdown Goodbye and suppresses admission" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    setup.client.beginGracefulClose(setup.pair.now);
    try std.testing.expect(setup.client.quiescing);
    try std.testing.expectEqual(@as(u8, 0), setup.client.service.router.capabilities().receive.count());
    var received = false;
    for (0..80) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        _ = setup.client.process(&setup.pair.client, setup.pair.events(&setup.pair.client, &transport), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        var control: [1]rr.Event = undefined;
        const counts = setup.server.service.processPartitioned(&setup.pair.server, setup.pair.events(&setup.pair.server, &transport), &.{}, setup.pair.now, &.{}, &control, &.{});
        if (counts.control == 0) continue;
        try std.testing.expectEqual(rr.Protocol.goodbye_v1, control[0].request.protocol);
        try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, control[0].request.bytes[0..8], .little));
        received = true;
        break;
    }
    try std.testing.expect(received);
}

fn expectQuiescentGoodbye(setup: *Setup, admitted: u64) !void {
    var received = false;
    for (0..80) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        var gossip: [8]@import("gossipsub/root.zig").Event = undefined;
        const counts_local = setup.client.process(&setup.pair.client, setup.pair.events(&setup.pair.client, &transport), &.{}, setup.pair.now, 100, &.{}, &.{}, &gossip);
        for (gossip[0..counts_local.gossipsub]) |event| try std.testing.expect(event != .message);
        try std.testing.expectEqual(@as(u64, 0), setup.client.service.gossipsub.counters().messages_received);
        try std.testing.expectEqual(admitted, setup.client.service.reqresp.counters().admitted);
        for (setup.client.service.reqresp.inner.inbound) |slot| {
            if (slot.state != .free and !slot.protocol.isControl()) try std.testing.expect(slot.pending_event == null);
        }
        var control: [8]rr.Event = undefined;
        const counts = setup.server.service.processPartitioned(&setup.pair.server, setup.pair.events(&setup.pair.server, &transport), &.{}, setup.pair.now, &.{}, &control, &.{});
        for (control[0..counts.control]) |event| {
            if (event != .request or event.request.protocol != .goodbye_v1) continue;
            try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, event.request.bytes[0..8], .little));
            received = true;
        }
    }
    try std.testing.expect(received);
}

fn quiescenceRequest(mode: enum { fin, selection, borrowed }) !void {
    const hold_selection = mode == .selection;
    const multistream = @import("wire/multistream.zig");
    var setup: Setup = .{};
    var opts = @import("core_test.zig").options();
    opts.service.reqresp.request_policy = @import("reqresp/request_policy_test.zig").fixture();
    const quotas = @import("reqresp/admission_test.zig").quotas(1000, 1000);
    opts.service.reqresp.admission = .{ .identities = 4, .peer = quotas, .global = quotas };
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    var peers: [4]t.Snapshot = undefined;
    _ = setup.server.snapshots(&peers);
    const stream = try setup.pair.server.openStream(peers[0].connection.?);
    var bytes: [512]u8 = undefined;
    const header = try multistream.encodeMessage(multistream.header, &bytes);
    const proposal = try multistream.encodeMessage(rr.Protocol.blocks_by_root_v2.id(), bytes[header.len..]);
    const body = try rr.codec.encodeRequest(&([_]u8{7} ** 32), bytes[header.len + proposal.len ..]);
    const total = header.len + proposal.len + body.len;
    const first = if (hold_selection) header.len else total;
    try std.testing.expectEqual(first, try setup.pair.server.write(stream, bytes[0..first], mode == .borrowed));
    for (0..20) |_| try setup.step(0);
    var held = false;
    if (hold_selection) {
        for (setup.client.service.router.negotiator.entries) |entry| {
            if (entry.state == .negotiating and entry.role == .listener and entry.stream.id == stream.id) held = true;
        }
    } else {
        for (setup.client.service.reqresp.inner.inbound) |slot| {
            if (slot.state != .free and slot.protocol == .blocks_by_root_v2 and (slot.state == .receiving_request or mode == .borrowed) and slot.io.decoder.isDone()) held = true;
        }
    }
    try std.testing.expect(held);
    var borrowed: []const u8 = &.{};
    if (mode == .borrowed) {
        var application: [1]rr.Event = undefined;
        const counts = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &application, &.{});
        try std.testing.expectEqual(@as(usize, 1), counts.application);
        borrowed = application[0].request.bytes;
        try std.testing.expectEqualSlices(u8, &([_]u8{7} ** 32), borrowed);
    }
    const admitted = setup.client.service.reqresp.counters().admitted;
    setup.client.beginGracefulClose(setup.pair.now);
    if (mode == .borrowed) {
        try std.testing.expectEqualSlices(u8, &([_]u8{7} ** 32), borrowed);
    } else try std.testing.expectEqual(total - first, try setup.pair.server.write(stream, bytes[first..total], true));
    try expectQuiescentGoodbye(&setup, admitted);
}

test "application quiescence rejects the final request FIN on an existing application stream" {
    try quiescenceRequest(.fin);
}

test "application quiescence rejects a held listener application selection" {
    try quiescenceRequest(.selection);
}

fn quiescenceGossip(hold_selection: bool) !void {
    const protobuf = @import("gossipsub/protobuf.zig");
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.subscribe(topic));
    try std.testing.expect(setup.server.subscribe(topic));
    for (0..50) |_| try setup.step(0);
    setup.pair.advance(1001);
    for (0..30) |_| try setup.step(0);
    var peers: [4]t.Snapshot = undefined;
    _ = setup.server.snapshots(&peers);
    const index = setup.server.service.gossipsub.inner.state.findPeer(peers[0].connection.?).?;
    var stream = setup.server.service.gossipsub.inner.state.outStream(index).?;
    if (hold_selection) {
        stream = try setup.pair.server.openStream(peers[0].connection.?);
        var header_bytes: [64]u8 = undefined;
        const ms = @import("wire/multistream.zig");
        const header = try ms.encodeMessage(ms.header, &header_bytes);
        try std.testing.expectEqual(header.len, try setup.pair.server.write(stream, header, false));
        for (0..10) |_| try setup.step(0);
        var held = false;
        for (setup.client.service.router.negotiator.entries) |entry| {
            if (entry.state == .negotiating and entry.role == .listener and entry.stream.id == stream.id) held = true;
        }
        try std.testing.expect(held);
    }
    var compressed: [128]u8 = undefined;
    const size = try @import("snappy").raw.compress("quiescence wire payload", &compressed);
    var bytes: [256]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    writer.varint(protobuf.messageSize(compressed[0..size], topic));
    protobuf.writeMessage(&writer, compressed[0..size], topic);
    const frame = writer.written();
    if (!hold_selection) try std.testing.expectEqual(frame.len - 1, try setup.pair.server.write(stream, frame[0 .. frame.len - 1], false));
    for (0..10) |_| try setup.step(0);
    try std.testing.expectEqual(@as(usize, 0), setup.client.service.gossipsub.resourceSnapshot().pending_validations);
    setup.client.beginGracefulClose(setup.pair.now);
    if (hold_selection) {
        var proposal_bytes: [64]u8 = undefined;
        const proposal = try @import("wire/multistream.zig").encodeMessage("/meshsub/1.2.0", &proposal_bytes);
        try std.testing.expectEqual(proposal.len, try setup.pair.server.write(stream, proposal, false));
    }
    const remaining = if (hold_selection) frame else frame[frame.len - 1 ..];
    try std.testing.expectEqual(remaining.len, try setup.pair.server.write(stream, remaining, false));
    try expectQuiescentGoodbye(&setup, 0);
    try std.testing.expectEqual(@as(usize, 0), setup.client.service.gossipsub.resourceSnapshot().pending_validations);
}

test "application quiescence rejects a partial message on an existing gossip stream" {
    try quiescenceGossip(false);
}

test "application quiescence rejects a held gossip listener message handoff" {
    try quiescenceGossip(true);
}

test "application quiescence preserves the current request borrow before deferred cancellation" {
    try quiescenceRequest(.borrowed);
}
