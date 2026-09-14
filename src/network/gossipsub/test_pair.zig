const std = @import("std");
const Service = @import("../service.zig").Service;
const gossip = @import("gossipsub.zig");
const engine = @import("../quic/engine.zig");
const support = @import("../test_support.zig");

pub const Pair = struct {
    pair: support.Pair = .{},
    client: Service = undefined,
    server: Service = undefined,
    handles: struct { client: engine.Handle, server: engine.Handle } = undefined,
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
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        const reqresp = @import("../reqresp/reqresp.zig").Options{ .forks = &.{}, .peers = 128, .outbound_max = 1, .inbound_max = 1, .inbound_per_peer_max = 1 };
        self.client = try Service.init(std.testing.allocator, .{ .reqresp = reqresp, .gossipsub = client, .router = .{ .negotiations_max = 8 } });
        errdefer self.client.deinit();
        self.server = try Service.init(std.testing.allocator, .{ .reqresp = reqresp, .gossipsub = server, .router = .{ .negotiations_max = 8 } });
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        _ = self.client.gossipsub.peerConnected(&self.pair.client, handles.client, self.pair.now);
        _ = self.server.gossipsub.peerConnected(&self.pair.server, handles.server, self.pair.now);
    }

    pub fn deinit(self: *Pair) void {
        self.server.gossipsub.shutdown(&self.server.router, &self.pair.server);
        self.client.gossipsub.shutdown(&self.client.router, &self.pair.client);
        self.server.deinit();
        self.client.deinit();
        self.pair.deinit();
    }

    pub fn pumpOnce(self: *Pair) !void {
        try self.pair.pump();
        var events: [16]engine.Event = undefined;
        var activity: [128]engine.Handle = undefined;
        const server_activity = self.pair.server.takeActivity(&activity);
        self.server_count = self.server.process(&self.pair.server, self.pair.events(&self.pair.server, &events), activity[0..server_activity], self.pair.now, .{ .gossipsub = self.server_events[0..self.server_event_capacity] }).gossipsub;
        const client_activity = self.pair.client.takeActivity(&activity);
        self.client_count = self.client.process(&self.pair.client, self.pair.events(&self.pair.client, &events), activity[0..client_activity], self.pair.now, .{ .gossipsub = self.client_events[0..self.client_event_capacity] }).gossipsub;
        try self.pair.pump();
    }

    pub fn clientStream(self: *const Pair) engine.StreamHandle {
        const sessions = self.client.gossipsub.inner.sessions;
        return sessions.outStream(sessions.findPeer(self.handles.client).?).?;
    }

    pub fn serverStream(self: *const Pair) engine.StreamHandle {
        const sessions = self.server.gossipsub.inner.sessions;
        return sessions.outStream(sessions.findPeer(self.handles.server).?).?;
    }

    pub fn clientEvents(self: *const Pair) []const gossip.Event {
        return self.client_events[0..self.client_count];
    }

    pub fn serverEvents(self: *const Pair) []const gossip.Event {
        return self.server_events[0..self.server_count];
    }
};
