//! Exercises quiche's internal monotonic clock, which the engine's supplied time cannot advance.
const std = @import("std");
const Engine = @import("Engine.zig");
const support = @import("test_support.zig");

const Event = Engine.Event;
const Pair = support.Pair;
const connectPair = support.connectPair;
const expectClosed = support.expectClosed;

test "engine keep-alive survives a short idle timeout" {
    var pair: Pair = .{};
    try pair.init(.{ .idle_timeout_ms = 1_000, .keep_alive_ms = 200 }, .{ .idle_timeout_ms = 1_000, .keep_alive_ms = 200 });
    defer pair.deinit();
    pair.now = readClock();
    const handles = try connectPair(&pair);

    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try std.Io.sleep(std.testing.io, .fromMilliseconds(200), .awake);
        pair.now = readClock();
        try pair.pump();
    }
    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
    try std.testing.expect(pair.client.peerId(handles.client) != null);
}

test "engine reports idle timeout without keep-alive" {
    var pair: Pair = .{};
    try pair.init(.{ .idle_timeout_ms = 600, .keep_alive_ms = 60_000 }, .{ .idle_timeout_ms = 600, .keep_alive_ms = 60_000 });
    defer pair.deinit();
    pair.now = readClock();
    const handles = try connectPair(&pair);

    try std.Io.sleep(std.testing.io, .fromMilliseconds(900), .awake);
    pair.now = readClock();
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(
        Engine.CloseReason.idle_timeout,
        try expectClosed(client_events[0], handles.client, .outbound, &pair.server_ctx),
    );
}

test "engine calls on_timeout only for keys whose quiche timer expired" {
    var pair: Pair = .{};
    try pair.init(.{ .idle_timeout_ms = 300, .keep_alive_ms = 60_000 }, .{ .idle_timeout_ms = 300, .keep_alive_ms = 60_000 });
    defer pair.deinit();
    pair.now = readClock();
    const handles = try support.connectPair(&pair);
    try pair.pump();
    var fired = pair.client.visits.timeouts;
    var closed = false;
    for (0..40) |_| {
        try std.Io.sleep(std.testing.io, .fromMilliseconds(25), .awake);
        pair.now = readClock();
        const top = pair.client.nextDeadlineNs();
        const pops = pair.client.visits.timer;
        pair.settle(&pair.client);
        if (pair.client.visits.timeouts > fired) {
            try std.testing.expect(top.? <= pair.now.nanos());
            try std.testing.expect(pair.client.visits.timer > pops);
            fired = pair.client.visits.timeouts;
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
    try std.testing.expect(pair.client.visits.timer >= pair.client.visits.timeouts);
}

fn readClock() Engine.Now {
    const ns: u64 = @intCast(std.Io.Clock.awake.now(std.testing.io).nanoseconds);
    return .{ .mono_ms = ns / std.time.ns_per_ms, .mono_ns = ns, .unix_s = support.now_unix };
}

test "engine timer invariants tolerate time passing after scheduling" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    pair.now = readClock();
    pair.drop_to_server = true;
    _ = try pair.dial();
    try pair.flush(&pair.client);
    const scheduled = pair.client.nextDeadlineNs().?;

    try std.Io.sleep(std.testing.io, .fromMilliseconds(400), .awake);
    pair.client.finishFlush(pair.now);
    try std.testing.expectEqual(scheduled, pair.client.nextDeadlineNs());
}
