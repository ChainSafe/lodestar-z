const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../negotiate.zig");
const support = @import("../test_support.zig");

const Event = gossipsub.Event;
const Gossipsub = gossipsub.Gossipsub;

const meshsub_1_2 = "/meshsub/1.2.0";
pub const meshsub_ids = [_][]const u8{ "/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0" };

const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };

pub const GossipPair = struct {
    pair: support.Pair = .{},
    client_neg: negotiate.Negotiator = undefined,
    server_neg: negotiate.Negotiator = undefined,
    client: Gossipsub = undefined,
    server: Gossipsub = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    client_send: engine_mod.StreamHandle = undefined,
    server_send: engine_mod.StreamHandle = undefined,
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,

    pub fn init(self: *GossipPair) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client_neg = try negotiate.Negotiator.init(std.testing.allocator, 8);
        errdefer self.client_neg.deinit();
        self.server_neg = try negotiate.Negotiator.init(std.testing.allocator, 8);
        errdefer self.server_neg.deinit();
        self.client = try Gossipsub.init(std.testing.allocator, .{});
        errdefer self.client.deinit();
        self.server = try Gossipsub.init(std.testing.allocator, .{});
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        _ = self.client.addPeer(handles.client, .v1_2).?;
        _ = self.server.addPeer(handles.server, .v1_2).?;
        self.client_send = try self.client_neg.beginOutbound(
            &self.pair.client,
            handles.client,
            meshsub_1_2,
            self.pair.now,
        );
        self.server_send = try self.server_neg.beginOutbound(
            &self.pair.server,
            handles.server,
            meshsub_1_2,
            self.pair.now,
        );
    }

    pub fn deinit(self: *GossipPair) void {
        self.server.deinit();
        self.client.deinit();
        self.server_neg.deinit();
        self.client_neg.deinit();
        self.pair.deinit();
    }

    pub fn pumpOnce(self: *GossipPair) !void {
        try self.pair.pump();
        const now = self.pair.now;
        try self.drive(&self.client, &self.client_neg, &self.pair.client, self.client_send);
        try self.drive(&self.server, &self.server_neg, &self.pair.server, self.server_send);
        self.client_count = self.client.pump(&self.pair.client, now, &self.client_events);
        self.server_count = self.server.pump(&self.pair.server, now, &self.server_events);
        try self.pair.pump();
    }

    fn drive(
        self: *GossipPair,
        gs: *Gossipsub,
        neg: *negotiate.Negotiator,
        engine: *engine_mod.Engine,
        send: engine_mod.StreamHandle,
    ) !void {
        const now = self.pair.now;
        var storage: [8]engine_mod.Event = undefined;
        for (self.pair.events(engine, &storage)) |event| switch (event) {
            .stream_opened => |stream| try neg.acceptInbound(stream, &meshsub_ids, now),
            .closed => |closed| gs.connectionClosed(closed.conn),
            else => {},
        };
        var outcomes: [8]negotiate.Outcome = undefined;
        const ready = neg.pump(engine, now, &outcomes);
        for (outcomes[0..ready]) |outcome| switch (outcome.result) {
            .ready => {
                const index = gs.state.findPeer(outcome.stream.conn) orelse continue;
                if (std.meta.eql(outcome.stream, send)) {
                    gs.setStreams(index, outcome.stream, null);
                } else {
                    gs.setStreams(index, null, outcome.stream);
                }
            },
            else => {},
        };
    }

    pub fn clientEvents(self: *const GossipPair) []const Event {
        return self.client_events[0..self.client_count];
    }

    pub fn serverEvents(self: *const GossipPair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

fn buildTopic(name: []const u8, out: []u8) []const u8 {
    return topic_mod.build(digest, name, out);
}

test "gossipsub peers exchange subscriptions over the mesh streams" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var client_saw = false;
    var server_saw = false;
    var rounds: usize = 0;
    while (rounds < 20 and !(client_saw and server_saw)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| switch (event) {
            .subscription_change => |change| {
                try std.testing.expectEqualStrings(beacon_block, change.topic);
                try std.testing.expect(change.subscribed);
                client_saw = true;
            },
            else => {},
        };
        for (setup.serverEvents()) |event| switch (event) {
            .subscription_change => |change| {
                try std.testing.expectEqualStrings(beacon_block, change.topic);
                server_saw = true;
            },
            else => {},
        };
    }
    try std.testing.expect(client_saw);
    try std.testing.expect(server_saw);

    // each side now records the other as a subscriber of the topic
    const server_topic = setup.server.state.findTopic(beacon_block).?;
    try std.testing.expect(setup.server.state.subscribers(server_topic).count() == 1);
}
