const std = @import("std");
const support = @import("test_support.zig");
const service = @import("service.zig");
const engine = @import("quic/engine.zig");
const Inbox = @import("gossipsub/test_support.zig").Inbox;

/// Services admit gossip peers explicitly, as PeerManager does, and deliver gossip through inboxes.
pub const ServicePair = struct {
    pair: support.Pair = .{},
    client: service.Service = undefined,
    server: service.Service = undefined,
    client_inbox: Inbox = .{},
    server_inbox: Inbox = .{},
    handles: struct { client: engine.Handle, server: engine.Handle } = undefined,

    pub fn init(self: *ServicePair, client: service.Options, server: service.Options) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        var client_options = client;
        client_options.automatic_gossip_admission = false;
        self.client = try service.Service.init(std.testing.allocator, client_options);
        errdefer self.client.deinit();
        var server_options = server;
        server_options.automatic_gossip_admission = false;
        self.server = try service.Service.init(std.testing.allocator, server_options);
        errdefer self.server.deinit();
        self.client_inbox.attach(self.client.gossipsub);
        self.server_inbox.attach(self.server.gossipsub);
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        _ = self.client.gossipsub.peerConnected(&self.pair.client, handles.client, false, self.pair.now);
        _ = self.server.gossipsub.peerConnected(&self.pair.server, handles.server, false, self.pair.now);
    }

    pub fn deinit(self: *ServicePair) void {
        self.client.shutdown(&self.pair.client);
        self.server.shutdown(&self.pair.server);
        self.server.deinit();
        self.client.deinit();
        self.server_inbox.deinit();
        self.client_inbox.deinit();
        self.pair.deinit();
    }

    /// Deliver gossip messages as events in the step outputs instead of the inboxes.
    pub fn useEventDelivery(self: *ServicePair) void {
        self.client.gossipsub.message_sink = null;
        self.server.gossipsub.message_sink = null;
    }

    pub const Counts = struct { client: service.OutputCounts, server: service.OutputCounts };

    /// Processes each Service exactly once. Transport delivery does not advance the clock.
    /// Gossip delivered in earlier steps is cleared first.
    pub fn step(self: *ServicePair, client: service.Outputs, server: service.Outputs) !Counts {
        self.client_inbox.clear();
        self.server_inbox.clear();
        try self.pair.pump();
        const server_count = self.processServer(server);
        const client_count = self.processClient(client);
        try self.pair.pump();
        return .{ .client = client_count, .server = server_count };
    }

    pub fn processClient(self: *ServicePair, outputs: service.Outputs) service.OutputCounts {
        return self.process(&self.client, &self.pair.client, outputs);
    }

    pub fn processServer(self: *ServicePair, outputs: service.Outputs) service.OutputCounts {
        return self.process(&self.server, &self.pair.server, outputs);
    }

    fn process(self: *ServicePair, owner: *service.Service, transport: *engine.Engine, outputs: service.Outputs) service.OutputCounts {
        var events: [128 * @import("quic/limits.zig").events_per_connection]engine.Event = undefined;
        var activity: [128]engine.Handle = undefined;
        std.debug.assert(transport.limits.connections_max <= activity.len);
        const count = transport.takeActivity(&activity);
        return owner.process(transport, self.pair.events(transport, &events), activity[0..count], self.pair.now, outputs);
    }
};
