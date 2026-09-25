const std = @import("std");
const binding = @import("binding.zig");
const constants = @import("../constants.zig");
const engine_mod = @import("engine.zig");
const support = @import("../test_support.zig");

const Event = engine_mod.Event;
const Pair = support.Pair;

fn drainEvents(pair: *Pair, engine: *engine_mod.Engine) usize {
    var storage: [64]Event = undefined;
    var total: usize = 0;
    for (0..16) |_| {
        const polled = pair.events(engine, &storage).len;
        total += polled;
        if (polled == 0) break;
    }
    return total;
}

fn sleepMs(ms: i64) void {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    std.Io.sleep(threaded.io(), std.Io.Duration.fromMilliseconds(ms), .awake) catch {};
}

test "engine idle connections cost no timer, collect or flush visits" {
    var pair: Pair = .{};
    try pair.init(.{}, .{ .handshaking_per_source_max = 32 });
    defer pair.deinit();
    for (0..32) |_| _ = try pair.dial();
    try pair.pump();
    _ = drainEvents(&pair, &pair.client);
    _ = drainEvents(&pair, &pair.server);
    try std.testing.expectEqual(@as(usize, 32), pair.client.activeIndices().len);
    try std.testing.expectEqual(@as(usize, 32), pair.server.activeIndices().len);
    for (pair.client.activeIndices()) |index| try std.testing.expect(pair.client.registry.slots[index].state == .established);

    const engines = [_]*engine_mod.Engine{ &pair.client, &pair.server };
    var visits: [2]engine_mod.Visits = undefined;
    var fired: [2]u64 = undefined;
    for (engines, &visits, &fired) |engine, *before, *timeouts| {
        before.* = engine.visits;
        timeouts.* = engine.counters.timeouts_fired;
    }
    for (0..100) |_| {
        pair.advance(1);
        try pair.pump();
    }
    for (engines, visits, fired) |engine, before, timeouts| {
        try std.testing.expectEqualDeep(before, engine.visits);
        try std.testing.expectEqual(timeouts, engine.counters.timeouts_fired);
        try std.testing.expect(!engine.backlog());
        try std.testing.expect(!engine.eventsPending());
    }
}

test "engine writable event re-arms only when send capacity grows" {
    var pair: Pair = .{};
    try pair.init(.{}, .{ .keep_alive_ms = 50 });
    defer pair.deinit();
    binding.c.quiche_config_set_initial_max_stream_data_bidi_remote(pair.server.config.ptr, 4096);
    const handles = try support.connectPair(&pair);
    const stream = try pair.client.openStream(handles.client);
    var payload: [8192]u8 = @splat(0x61);
    try std.testing.expectEqual(@as(usize, 4096), try pair.client.write(stream, &payload, false));
    const slot = &pair.client.registry.slots[handles.client.index];
    try std.testing.expect(slot.table.entries[stream.slot].write_lowat > 0);
    try pair.pump();
    try std.testing.expectEqual(@as(usize, 0), countWritable(&pair, stream));

    // A repeated WouldBlock at the armed watermark queues nothing.
    try std.testing.expectError(error.WouldBlock, pair.client.write(stream, payload[4096..], false));
    try std.testing.expect(!pair.client.backlog());

    // A PING and a duplicate of it carry no credit.
    pair.advance(50);
    pair.settle(&pair.server);
    const server_index = handles.server.index;
    var datagram: [constants.datagram_size_max]u8 = undefined;
    var copy: [constants.datagram_size_max]u8 = undefined;
    const ping = pair.server.sendOne(server_index, pair.now, &datagram).?;
    @memcpy(copy[0..ping.bytes.len], ping.bytes);
    try std.testing.expect(pair.server.sendOne(server_index, pair.now, &datagram) == null);
    pair.server.sent(server_index, pair.now, true);
    var response: [constants.datagram_size_max]u8 = undefined;
    for (0..2) |_| {
        var replay: [constants.datagram_size_max]u8 = undefined;
        @memcpy(replay[0..ping.bytes.len], copy[0..ping.bytes.len]);
        _ = pair.client.receive(replay[0..ping.bytes.len], &support.server_address, pair.now, &response);
        pair.settle(&pair.client);
        try std.testing.expectEqual(@as(usize, 0), countWritable(&pair, stream));
    }
    try pair.pump();
    try std.testing.expectEqual(@as(usize, 0), countWritable(&pair, stream));

    // The peer's MAX_STREAM_DATA grants credit and reports the stream once.
    var events: [16]Event = undefined;
    var inbound: ?engine_mod.StreamHandle = null;
    for (pair.events(&pair.server, &events)) |event| if (event == .stream_opened) {
        inbound = event.stream_opened;
    };
    var sink: [4096]u8 = undefined;
    var consumed: usize = 0;
    for (0..8) |_| {
        const read = try pair.server.read(inbound.?, sink[consumed..]);
        consumed += read.len;
        if (read.len == 0 or consumed == 4096) break;
    }
    try std.testing.expectEqual(@as(usize, 4096), consumed);
    try pair.pump();
    try std.testing.expectEqual(@as(usize, 1), countWritable(&pair, stream));
    try pair.pump();
    try std.testing.expectEqual(@as(usize, 0), countWritable(&pair, stream));

    // Writing past the new credit blocks again and re-arms, queuing the blocked frame.
    const accepted = try pair.client.write(stream, &payload, false);
    try std.testing.expect(accepted > 0 and accepted < payload.len);
    try std.testing.expect(slot.table.entries[stream.slot].write_lowat > 0);
    try std.testing.expect(pair.client.backlog());
}

test "engine send state names the limit a blocked write waits on and arms nothing" {
    const Window = enum { stream, connection, congestion };
    for ([_]Window{ .stream, .connection, .congestion }) |window| {
        var pair: Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        switch (window) {
            .stream => binding.c.quiche_config_set_initial_max_stream_data_bidi_remote(pair.server.config.ptr, 4096),
            .connection => binding.c.quiche_config_set_initial_max_data(pair.server.config.ptr, 4096),
            .congestion => {},
        }
        const handles = try support.connectPair(&pair);
        const stream = try pair.client.openStream(handles.client);
        var payload: [65536]u8 = @splat(0x61);
        const accepted = try pair.client.write(stream, &payload, false);
        try std.testing.expect(accepted > 0 and accepted < payload.len);
        const slot = &pair.client.registry.slots[handles.client.index];
        const armed = slot.table.entries[stream.slot].write_lowat;
        const dirty = pair.client.dirtyCount();
        const state = pair.client.sendState(stream).?;
        try std.testing.expectEqual(armed, state.watermark);
        try std.testing.expect(state.watermark > 0 and !state.writable_pending);
        try std.testing.expectEqual(@as(?u64, 0), state.available());
        // Nothing is sent before the flush.
        try std.testing.expectEqual(@as(u64, accepted), state.capacity.?.stream_unsent);
        try std.testing.expectEqual(switch (window) {
            .stream => engine_mod.SendLimit.stream_credit,
            .connection => .connection_credit,
            .congestion => .cwnd,
        }, state.limit());
        try std.testing.expectEqual(armed, slot.table.entries[stream.slot].write_lowat);
        try std.testing.expectEqual(dirty, pair.client.dirtyCount());
        try pair.pump();
        const flushed = pair.client.sendState(stream).?;
        try std.testing.expect(flushed.transport.cwnd > 0 and flushed.transport.rtt_ns > 0);
        try std.testing.expectEqual(@as(u64, @intFromBool(window == .connection)), flushed.transport.counts.data_blocked);
        try std.testing.expectEqual(@as(u64, @intFromBool(window == .stream)), flushed.transport.counts.stream_data_blocked);
        if (window != .stream) continue;
        try std.testing.expectEqual(@as(u64, 0), flushed.capacity.?.stream_unsent);

        // The server reads: credit reaches the watermark and the edge waits undelivered.
        var events: [16]Event = undefined;
        var inbound: ?engine_mod.StreamHandle = null;
        for (pair.events(&pair.server, &events)) |event| if (event == .stream_opened) {
            inbound = event.stream_opened;
        };
        var sink: [4096]u8 = undefined;
        var consumed: usize = 0;
        for (0..8) |_| {
            const read = try pair.server.read(inbound.?, sink[consumed..]);
            consumed += read.len;
            if (read.len == 0 or consumed == sink.len) break;
        }
        try pair.pump();
        const credited = pair.client.sendState(stream).?;
        try std.testing.expect(credited.writable_pending);
        try std.testing.expectEqual(engine_mod.SendLimit.none, credited.limit());

        // A stream the peer stopped has no capacity to decompose.
        pair.server.shutdown(inbound.?, .read, 7);
        try pair.pump();
        try std.testing.expectEqual(engine_mod.SendLimit.unknown, pair.client.sendState(stream).?.limit());
    }
}

fn countWritable(pair: *Pair, stream: engine_mod.StreamHandle) usize {
    var storage: [32]Event = undefined;
    var count: usize = 0;
    for (pair.events(&pair.client, &storage)) |event| switch (event) {
        .stream_ready => |ready| if (std.meta.eql(ready.stream, stream) and ready.ready.writable) {
            count += 1;
        },
        else => {},
    };
    return count;
}

test "engine wakeup is its timer heap top" {
    var pair: Pair = .{};
    try pair.init(.{ .keep_alive_ms = 7_000 }, .{ .handshaking_per_source_max = 8 });
    defer pair.deinit();
    for (0..4) |_| _ = try pair.dial();
    try pair.pump();
    _ = drainEvents(&pair, &pair.client);
    var recomputed: ?u64 = null;
    var keyed: ?u64 = null;
    for (pair.client.activeIndices()) |index| {
        const slot = &pair.client.registry.slots[index];
        var due = (slot.last_send_ms + 7_000) * std.time.ns_per_ms;
        if (slot.timeoutNs()) |remaining| due = @min(due, pair.now.nanos() + remaining);
        recomputed = @min(recomputed orelse due, due);
        const key = pair.client.registry.timers.get(index).?;
        keyed = @min(keyed orelse key, key);
    }
    const top = pair.client.nextDeadlineNs().?;
    try std.testing.expectEqual(keyed.?, top);
    // quiche's own clock moved on since the keys were set, so its timer reads slightly earlier.
    try std.testing.expect(top >= recomputed.?);
    try std.testing.expect(top - recomputed.? <= std.time.ns_per_ms);
}

test "engine calls on_timeout only for keys whose quiche timer expired" {
    var pair: Pair = .{};
    try pair.init(.{ .idle_timeout_ms = 300, .keep_alive_ms = 60_000 }, .{ .idle_timeout_ms = 300, .keep_alive_ms = 60_000 });
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    try pair.pump();
    var fired = pair.client.counters.timeouts_fired;
    var closed = false;
    for (0..40) |_| {
        sleepMs(25);
        pair.advance(25);
        const top = pair.client.nextDeadlineNs();
        const pops = pair.client.visits.timer;
        pair.settle(&pair.client);
        if (pair.client.counters.timeouts_fired > fired) {
            try std.testing.expect(top.? <= pair.now.nanos());
            try std.testing.expect(pair.client.visits.timer > pops);
            fired = pair.client.counters.timeouts_fired;
        }
        var storage: [8]Event = undefined;
        for (pair.events(&pair.client, &storage)) |event| if (event == .closed) {
            try std.testing.expectEqual(handles.client, event.closed.conn);
            try std.testing.expect(event.closed.reason == .idle_timeout);
            closed = true;
        };
        if (closed) break;
    }
    try std.testing.expect(closed);
    try std.testing.expect(fired >= 1);
    try std.testing.expect(pair.client.visits.timer >= pair.client.counters.timeouts_fired);
}

test "engine events drain connections in arrival order across one-event polls" {
    var pair: Pair = .{};
    try pair.init(.{}, .{ .handshaking_per_source_max = 8 });
    defer pair.deinit();
    const first = try pair.dial();
    try pair.pump();
    const second = try pair.dial();
    try pair.pump();
    var one: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.client.pollEvents(&one));
    try std.testing.expectEqual(first, one[0].connected.conn);
    try std.testing.expectEqual(@as(usize, 1), pair.client.pollEvents(&one));
    try std.testing.expectEqual(second, one[0].connected.conn);
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&one));
    try std.testing.expect(!pair.client.eventsPending());
}
