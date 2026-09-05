const std = @import("std");
const support = @import("../test_support.zig");
const engine = @import("engine.zig");

test "engine notifications deliver a later close during sustained earlier stream churn" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    const victim = try pair.server.dial(&support.client_address, pair.client_ctx.local_peer_id, pair.now, pair.nextEntropy());
    pair.server.driverView().failSend(victim.index);
    var one: [1]engine.Event = undefined;
    var delivered = false;
    for (0..8) |turn| {
        const outgoing = try pair.client.openStream(handles.client);
        _ = try pair.client.write(outgoing, "x", true);
        try pair.pump();
        try std.testing.expectEqual(@as(usize, 0), pair.server.pollEvents(&.{}));
        for (0..2) |_| {
            const count = pair.server.pollEvents(&one);
            if (count == 0) continue;
            switch (one[0]) {
                .stream_opened => |stream| pair.server.closeStream(stream, 1),
                .stream_closed => |event| try std.testing.expectEqual(handles.server, event.stream.conn),
                .closed => {
                    _ = try support.expectClosed(one[0], victim, .outbound, null);
                    try std.testing.expect(!delivered);
                    delivered = true;
                },
                else => return error.UnexpectedEvent,
            }
            try pair.pump();
            pair.server.driverView().releaseReported();
        }
        if (turn >= 1) try std.testing.expect(delivered);
    }
    try std.testing.expectEqual(@as(u16, 1), pair.server.registry.active_len);
    try std.testing.expect(pair.server.peerId(victim) == null);
}

test "engine notifications deliver later native activity during sustained earlier traffic" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var newcomer: support.Pair = .{};
    try newcomer.init(.{}, .{});
    defer newcomer.deinit();
    newcomer.entropy = 100;
    const pending_dial = try newcomer.dial();
    var bytes: [1452]u8 = undefined;
    const initial = newcomer.client.driverView().sendOne(pending_dial.index, newcomer.now, &bytes).?;
    var saved_initial: [1452]u8 = undefined;
    @memcpy(saved_initial[0..initial.bytes.len], initial.bytes);
    const source = engine.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4003 } };
    var response: [1452]u8 = undefined;
    const victim = pair.server.driverView().receive(bytes[0..initial.bytes.len], &source, pair.now, pair.nextPool(), &response).accepted;
    try std.testing.expect(victim.index != handles.server.index);
    pair.drop_to_address = source;
    const stream = try pair.client.openStream(handles.client);
    var activity: [1]engine.Handle = undefined;
    var delivered = false;
    for (0..32) |turn| {
        _ = try pair.client.write(stream, "x", false);
        try pair.pump();
        try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().takeActivity(&.{}));
        try std.testing.expectEqual(@as(usize, 1), pair.server.driverView().takeActivity(&activity));
        if (std.meta.eql(activity[0], victim)) {
            try std.testing.expect(!delivered);
            delivered = true;
        } else try std.testing.expectEqual(handles.server, activity[0]);
        if (turn >= 1) try std.testing.expect(delivered);
    }
    try std.testing.expect(!pair.server.registry.activity[victim.index]);
    try std.testing.expect(pair.server.abandon(victim));
    _ = pair.server.driverView().takeActivity(&activity);
    try std.testing.expect(!pair.server.driverView().activityPending());
    const replacement = pair.server.driverView().receive(saved_initial[0..initial.bytes.len], &source, pair.now, pair.nextPool(), &response).accepted;
    try std.testing.expectEqual(victim.index, replacement.index);
    try std.testing.expect(victim.generation != replacement.generation);
    try std.testing.expectEqual(@as(usize, 1), pair.server.driverView().takeActivity(&activity));
    try std.testing.expectEqual(replacement, activity[0]);
}

test "engine notifications deliver higher stream slot while lower slots recycle" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var outgoing = try pair.client.openStream(handles.client);
    _ = try pair.client.write(outgoing, "x", true);
    const victim = try pair.client.openStream(handles.client);
    _ = try pair.client.write(victim, "y", true);
    try pair.pump();
    var one: [1]engine.Event = undefined;
    var delivered = false;
    var low_opens: usize = 0;
    var opened: [128]?u64 = [_]?u64{null} ** 128;
    for (0..32) |turn| {
        if (turn > 0) {
            outgoing = try pair.client.openStream(handles.client);
            _ = try pair.client.write(outgoing, "x", true);
            try pair.pump();
        }
        for (0..2) |_| {
            try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
            switch (one[0]) {
                .stream_opened => |stream| {
                    try std.testing.expectEqual(handles.server, stream.conn);
                    try std.testing.expect(opened[stream.slot] == null);
                    opened[stream.slot] = stream.id;
                    if (stream.id == victim.id) {
                        try std.testing.expect(!delivered);
                        try std.testing.expectEqual(@as(u8, 65), stream.slot);
                        delivered = true;
                    } else {
                        if (stream.slot == 64) low_opens += 1;
                        pair.server.closeStream(stream, 1);
                    }
                },
                .stream_closed => |event| {
                    try std.testing.expectEqual(@as(?u64, event.stream.id), opened[event.stream.slot]);
                    opened[event.stream.slot] = null;
                },
                else => return error.UnexpectedEvent,
            }
            try pair.pump();
        }
        if (turn >= 1) try std.testing.expect(delivered);
    }
    try std.testing.expect(low_opens > 1);
}

test "engine notifications preserve generations through active swaps retirement and wrap" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{ .connections_max = 4, .handshaking_max = 4, .dialing_max = 4, .outbound_max = 4 });
    defer pair.deinit();
    _ = try support.connectPair(&pair);
    var owners: [3]engine.Handle = undefined;
    for (&owners) |*owner| {
        owner.* = try pair.server.dial(&support.client_address, pair.client_ctx.local_peer_id, pair.now, pair.nextEntropy());
        pair.server.driverView().failSend(owner.index);
    }
    var one: [1]engine.Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.server.pollEvents(&.{}));
    try std.testing.expect(pair.server.eventsPending());
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    _ = try support.expectClosed(one[0], owners[0], .outbound, null);
    pair.server.driverView().releaseReported();
    try std.testing.expectEqual(owners[2].index, pair.server.registry.active[1]);
    const replacement = try pair.server.dial(&support.client_address, pair.client_ctx.local_peer_id, pair.now, pair.nextEntropy());
    try std.testing.expectEqual(owners[0].index, replacement.index);
    try std.testing.expect(replacement.generation != owners[0].generation);
    pair.server.driverView().failSend(replacement.index);
    const expected = [_]engine.Handle{ owners[1], owners[2], replacement };
    for (expected) |owner| {
        try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
        _ = try support.expectClosed(one[0], owner, .outbound, null);
        pair.server.driverView().releaseReported();
    }
    try std.testing.expectEqual(@as(u16, 1), pair.server.registry.active_len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.pollEvents(&one));
    var activity: [4]engine.Handle = undefined;
    const count = pair.server.driverView().takeActivity(&activity);
    for (activity[0..count]) |owner| try std.testing.expectEqual(@as(u16, 0), owner.index);
    try std.testing.expect(!pair.server.driverView().activityPending());
}

test "engine notifications preserve lifecycle order across one-event polls" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const client = try pair.dial();
    try pair.pump();
    const server = pair.server.driverView().sendOwner(0).?;
    const rebound = engine.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4003 } };
    pair.client_source = rebound;
    const outgoing = try pair.client.openStream(client);
    _ = try pair.client.write(outgoing, &([_]u8{1} ** 2000), false);
    try pair.pump();
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.path_changes);
    var one: [1]engine.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    _ = try support.expectConnected(one[0], .inbound, &pair.client_ctx);
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    try std.testing.expectEqual(server, one[0].path_changed.conn);
    try std.testing.expectEqual(rebound, one[0].path_changed.peer);
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    const incoming = try support.expectStreamOpened(one[0], server);
    pair.server.closeStream(incoming, 1);
    pair.server.driverView().failSend(server.index);
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    _ = try support.expectStreamClosed(one[0], incoming);
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    _ = try support.expectClosed(one[0], server, .inbound, &pair.client_ctx);
    pair.server.driverView().releaseReported();
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.active_len);
}
