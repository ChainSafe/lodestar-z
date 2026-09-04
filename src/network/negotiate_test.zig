const std = @import("std");
const engine_mod = @import("quic/engine.zig");
const multistream = @import("wire/multistream.zig");
const negotiate = @import("negotiate.zig");
const support = @import("test_support.zig");

const Pair = support.Pair;
const Negotiator = negotiate.Negotiator;
const Outcome = negotiate.Outcome;
const connectPair = support.connectPair;

const ping = "/ipfs/ping/1.0.0";
const supported = [_][]const u8{ ping, "/other/1.0.0" };

const Setup = struct {
    pair: Pair = .{},
    dialer: Negotiator = undefined,
    listener: Negotiator = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,

    fn init(self: *Setup, negotiations_max: u16) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.dialer = try Negotiator.init(std.testing.allocator, negotiations_max);
        errdefer self.dialer.deinit();
        self.listener = try Negotiator.init(std.testing.allocator, negotiations_max);
        const handles = try connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
    }

    fn deinit(self: *Setup) void {
        self.listener.deinit();
        self.dialer.deinit();
        self.pair.deinit();
    }

    fn acceptOpened(self: *Setup) !void {
        var storage: [8]engine_mod.Event = undefined;
        for (self.pair.events(&self.pair.server, &storage)) |event| {
            if (event != .stream_opened) continue;
            try self.listener.acceptInbound(event.stream_opened, &supported, self.pair.now);
        }
    }

    fn run(self: *Setup, rounds_max: usize) !struct { dialer: ?Outcome, listener: ?Outcome } {
        var dialer_outcome: ?Outcome = null;
        var listener_outcome: ?Outcome = null;
        var rounds: usize = 0;
        while (rounds < rounds_max and (dialer_outcome == null or listener_outcome == null)) : (rounds += 1) {
            var outcomes: [4]Outcome = undefined;
            const dialed = self.dialer.pump(&self.pair.client, self.pair.now, &outcomes);
            if (dialed > 0) dialer_outcome = outcomes[0];
            try self.pair.pump();
            try self.acceptOpened();
            const listened = self.listener.pump(&self.pair.server, self.pair.now, &outcomes);
            if (listened > 0) listener_outcome = outcomes[0];
            try self.pair.pump();
        }
        return .{ .dialer = dialer_outcome, .listener = listener_outcome };
    }
};

test "negotiator selects a shared protocol on both sides and hands over usable streams" {
    var setup: Setup = .{};
    try setup.init(4);
    defer setup.deinit();

    const stream = try setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, ping, setup.pair.now);
    try std.testing.expectEqual(@as(usize, 1), setup.dialer.active());
    const outcomes = try setup.run(16);
    const accepted = outcomes.dialer orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(stream, accepted.stream);
    try std.testing.expectEqual(@as(u8, 0), accepted.result.ready.protocol_index);
    try std.testing.expectEqual(@as(usize, 0), accepted.result.ready.leftover.len);
    const selected = outcomes.listener orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 0), selected.result.ready.protocol_index);
    try std.testing.expectEqual(@as(usize, 0), selected.result.ready.leftover.len);

    try std.testing.expectEqual(@as(usize, 2), try setup.pair.client.write(stream, "hi", false));
    try setup.pair.pump();
    var buffer: [8]u8 = undefined;
    const read = try setup.pair.server.read(selected.stream, &buffer);
    try std.testing.expectEqualStrings("hi", buffer[0..read.len]);

    var storage: [4]Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.dialer.pump(&setup.pair.client, setup.pair.now, &storage));
    try std.testing.expectEqual(@as(usize, 0), setup.dialer.active());
    try std.testing.expectEqual(@as(usize, 0), setup.listener.active());
}

test "negotiator reports rejection to the dialer and a closed stream to the listener" {
    var setup: Setup = .{};
    try setup.init(4);
    defer setup.deinit();

    _ = try setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, "/missing/1.0.0", setup.pair.now);
    const outcomes = try setup.run(16);
    const rejected = outcomes.dialer orelse return error.TestUnexpectedResult;
    try std.testing.expect(rejected.result == .rejected);
    const closed = outcomes.listener orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(negotiate.Failure.stream_closed, closed.result.failed);
}

test "negotiator fails a listener fed with garbage" {
    var setup: Setup = .{};
    try setup.init(4);
    defer setup.deinit();

    const stream = try setup.pair.client.openStream(setup.handles.client);
    const garbage = [_]u8{ 3, 'a', 'b', 'c' };
    try std.testing.expectEqual(garbage.len, try setup.pair.client.write(stream, &garbage, false));
    const outcomes = try setup.run(8);
    try std.testing.expect(outcomes.dialer == null);
    const failed = outcomes.listener orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(negotiate.Failure.malformed, failed.result.failed);
}

test "negotiator expires a stalled negotiation" {
    var setup: Setup = .{};
    try setup.init(4);
    defer setup.deinit();

    const stream = try setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, ping, setup.pair.now);
    setup.pair.advance(negotiate.negotiate_timeout_ms);
    var outcomes: [4]Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.dialer.pump(&setup.pair.client, setup.pair.now, &outcomes));
    try std.testing.expectEqual(stream, outcomes[0].stream);
    try std.testing.expectEqual(negotiate.Failure.timeout, outcomes[0].result.failed);
    try std.testing.expectEqual(@as(usize, 0), setup.dialer.pump(&setup.pair.client, setup.pair.now, &outcomes));
    try std.testing.expectEqual(@as(usize, 0), setup.dialer.active());
}

test "negotiator delivers payload bytes that arrive with the proposal as leftover" {
    var setup: Setup = .{};
    try setup.init(4);
    defer setup.deinit();

    const stream = try setup.pair.client.openStream(setup.handles.client);
    var dialer = try multistream.Dialer.init(ping);
    var hello: [2 * multistream.message_length_max + 8]u8 = undefined;
    const prefix = try dialer.initialWrite(&hello);
    @memcpy(hello[prefix.len..][0..5], "ping!");
    const message = hello[0 .. prefix.len + 5];
    try std.testing.expectEqual(message.len, try setup.pair.client.write(stream, message, true));
    const outcomes = try setup.run(8);
    const selected = outcomes.listener orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("ping!", selected.result.ready.leftover);
    try std.testing.expect(selected.result.ready.fin);
}

test "negotiator refuses to track more negotiations than its table holds" {
    var setup: Setup = .{};
    try setup.init(2);
    defer setup.deinit();

    _ = try setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, ping, setup.pair.now);
    _ = try setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, ping, setup.pair.now);
    try std.testing.expectError(
        error.NegotiationTableFull,
        setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, ping, setup.pair.now),
    );
    try std.testing.expectEqual(@as(usize, 2), setup.dialer.active());
    try std.testing.expectError(error.InvalidLimits, Negotiator.init(std.testing.allocator, 0));
}

test "negotiator falls back on the same stream to meshsub v1.1" {
    var setup: Setup = .{};
    try setup.init(4);
    defer setup.deinit();
    const stream = try setup.dialer.beginOutboundCandidates(&setup.pair.client, setup.handles.client, &.{ "/meshsub/1.2.0", "/meshsub/1.1.0" }, setup.pair.now);
    var accepted = false;
    for (0..16) |_| {
        var out: [4]Outcome = undefined;
        const count = setup.dialer.pump(&setup.pair.client, setup.pair.now, &out);
        for (out[0..count]) |result| {
            try std.testing.expect(result.result == .ready);
            try std.testing.expectEqual(stream, result.stream);
            try std.testing.expectEqualStrings("/meshsub/1.1.0", result.result.ready.protocol_id);
            accepted = true;
        }
        try setup.pair.pump();
        var events: [8]engine_mod.Event = undefined;
        for (setup.pair.events(&setup.pair.server, &events)) |event| {
            if (event == .stream_opened) try setup.listener.acceptInbound(event.stream_opened, &.{"/meshsub/1.1.0"}, setup.pair.now);
        }
        _ = setup.listener.pump(&setup.pair.server, setup.pair.now, &out);
        try setup.pair.pump();
    }
    try std.testing.expect(accepted);
}

test "negotiator expires with no outcome capacity and reports later" {
    var setup: Setup = .{};
    try setup.init(1);
    defer setup.deinit();
    _ = try setup.dialer.beginOutbound(&setup.pair.client, setup.handles.client, ping, setup.pair.now);
    setup.pair.advance(negotiate.negotiate_timeout_ms);
    try std.testing.expectEqual(@as(usize, 0), setup.dialer.pump(&setup.pair.client, setup.pair.now, &.{}));
    try std.testing.expectEqual(@as(usize, 0), setup.dialer.active());
    var out: [1]Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.dialer.pump(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(negotiate.Failure.timeout, out[0].result.failed);
}
