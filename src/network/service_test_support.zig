const std = @import("std");
const support = @import("test_support.zig");
const service = @import("service.zig");
const engine = @import("quic/engine.zig");
const Inbox = @import("gossipsub/test_support.zig").Inbox;

pub fn initService(allocator: std.mem.Allocator, options: service.Options, transport: *const engine.Engine) !service.Service {
    const local = try options.identify.makeLocal(&transport.tls.local_peer_id, &transport.local);
    return service.Service.init(allocator, options, &local);
}

pub fn fixtureLocal(options: @import("identify/root.zig").Options) !@import("identify/root.zig").Local {
    const key = try @import("wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    const peer = @import("wire/peer_id.zig").PeerId.fromPublicKey(&key.publicKey());
    return @import("identify/root.zig").Local.init(&peer, options.agent, options.protocol_version, if (options.addresses.len == 0) &.{support.client_address} else options.addresses);
}

/// Services admit gossip peers explicitly, as PeerManager does, and deliver gossip through inboxes.
pub const ServicePair = struct {
    pair: support.Pair = .{},
    client: service.Service = undefined,
    server: service.Service = undefined,
    client_inbox: Inbox = .{},
    server_inbox: Inbox = .{},
    handles: struct { client: engine.Handle, server: engine.Handle } = undefined,

    pub fn init(self: *ServicePair, client: service.Options, server: service.Options) !void {
        try self.initWindow(client, server, null);
    }

    /// As `init`, with the server granting `stream_window` bytes of credit on each stream the
    /// client opens until it reads them.
    pub fn initWindow(self: *ServicePair, client: service.Options, server: service.Options, stream_window: ?u64) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        if (stream_window) |window| @import("quic/binding.zig").c.quiche_config_set_initial_max_stream_data_bidi_remote(self.pair.server.config.ptr, window);
        self.client = try initService(std.testing.allocator, client, &self.pair.client);
        errdefer self.client.deinit();
        self.server = try initService(std.testing.allocator, server, &self.pair.server);
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
        var events: [@import("quic/limits.zig").events_per_turn_max]engine.Event = undefined;
        return owner.process(transport, self.pair.events(transport, &events), self.pair.now, outputs);
    }
};
