const gossip = @import("gossipsub.zig");
const engine = @import("../quic/engine.zig");

pub const Pair = struct {
    shared: @import("../service_test_support.zig").ServicePair = .{},
    client_events: [16]gossip.Event = undefined,
    server_events: [16]gossip.Event = undefined,
    client_count: usize = 0,
    server_count: usize = 0,
    client_event_capacity: usize = 16,
    server_event_capacity: usize = 16,

    pub fn init(self: *Pair) !void {
        try self.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1 });
    }

    pub fn initOpts(self: *Pair, client: gossip.Options, server: gossip.Options) !void {
        const reqresp: @import("../reqresp/reqresp.zig").Options = .{ .forks = &.{}, .peers = 128, .outbound_max = 1, .inbound_max = 1, .inbound_per_peer_max = 1 };
        const topics = &.{ @import("topic_fixture.zig").bytes(.{ 1, 2, 3, 4 }), @import("topic_fixture.zig").bytes(.{ 0x6a, 0x95, 0xa1, 0xa9 }) };
        var client_options = client;
        client_options.topic_policy = client.topic_policy orelse topics;
        var server_options = server;
        server_options.topic_policy = server.topic_policy orelse topics;
        try self.shared.init(.{ .reqresp = reqresp, .gossipsub = client_options, .router = .{ .negotiations_max = 8 } }, .{ .reqresp = reqresp, .gossipsub = server_options, .router = .{ .negotiations_max = 8 } });
    }

    pub fn deinit(self: *Pair) void {
        self.shared.deinit();
    }

    pub fn pumpOnce(self: *Pair) !void {
        const counts = try self.shared.step(.{ .gossipsub = self.client_events[0..self.client_event_capacity] }, .{ .gossipsub = self.server_events[0..self.server_event_capacity] });
        self.client_count = counts.client.gossipsub;
        self.server_count = counts.server.gossipsub;
    }

    pub fn clientStream(self: *const Pair) engine.StreamHandle {
        const sessions = self.shared.client.gossipsub.sessions;
        return sessions.outStream(sessions.findPeer(self.shared.handles.client).?).?;
    }

    pub fn serverStream(self: *const Pair) engine.StreamHandle {
        const sessions = self.shared.server.gossipsub.sessions;
        return sessions.outStream(sessions.findPeer(self.shared.handles.server).?).?;
    }

    pub fn clientEvents(self: *const Pair) []const gossip.Event {
        return self.client_events[0..self.client_count];
    }

    pub fn serverEvents(self: *const Pair) []const gossip.Event {
        return self.server_events[0..self.server_count];
    }
};
