const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const service_mod = @import("service.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");
const support = @import("../test_support.zig");

const Event = gossipsub.Event;
const Service = service_mod.Service;
const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
const heartbeat = @import("constants.zig").heartbeat_interval_ms;

const ServicePair = struct {
    pair: support.Pair = .{},
    client: Service = undefined,
    server: Service = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,

    fn init(self: *ServicePair) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client = try Service.init(std.testing.allocator, .{});
        errdefer self.client.deinit();
        self.server = try Service.init(std.testing.allocator, .{});
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        // connectPair consumed the connected events, so open the meshsub streams now
        self.client.peerConnected(&self.pair.client, handles.client, self.pair.now);
        self.server.peerConnected(&self.pair.server, handles.server, self.pair.now);
    }

    fn deinit(self: *ServicePair) void {
        self.server.deinit();
        self.client.deinit();
        self.pair.deinit();
    }

    fn pumpOnce(self: *ServicePair) !void {
        try self.pair.pump();
        const now = self.pair.now;
        var storage: [16]engine_mod.Event = undefined;
        const server_ev = self.pair.events(&self.pair.server, &storage);
        self.server_count = self.server.process(
            &self.pair.server,
            server_ev,
            now,
            &self.server_events,
        );
        var storage2: [16]engine_mod.Event = undefined;
        const client_ev = self.pair.events(&self.pair.client, &storage2);
        self.client_count = self.client.process(
            &self.pair.client,
            client_ev,
            now,
            &self.client_events,
        );
        try self.pair.pump();
    }

    fn serverEvents(self: *const ServicePair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

test "gossipsub service composes the mesh and delivers a message" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = topic_mod.build(digest, "beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a block delivered through the gossipsub service";
    try std.testing.expect(setup.client.publish(beacon_block, payload, setup.pair.now));

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualStrings(payload, m.bytes);
                setup.server.report(m.handle, .accept);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters().messages_received);
}
