const gossip = @import("gossipsub.zig");
const engine = @import("../quic/engine.zig");
const MessageEvent = @import("messages.zig").MessageEvent;

pub const Pair = struct {
    shared: @import("../service_test_support.zig").ServicePair = .{},

    pub fn init(self: *Pair) !void {
        try self.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1 });
    }

    pub fn initOpts(self: *Pair, client: gossip.Options, server: gossip.Options) !void {
        const reqresp: @import("../reqresp/reqresp.zig").Options = .{ .forks = &.{}, .peers = 128, .outbound_max = 1, .inbound_max = 1, .inbound_per_peer_max = 1, .admission = try @import("../reqresp/reqresp.zig").AdmissionOptions.defaults(&@import("../reqresp/policy_fixture.zig").config(), 128, 128, 1) };
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
        _ = try self.shared.step(.{}, .{});
    }

    pub fn clientStream(self: *const Pair) engine.StreamHandle {
        const sessions = self.shared.client.gossipsub.sessions;
        return sessions.outStream(sessions.findPeer(self.shared.handles.client).?).?;
    }

    pub fn serverStream(self: *const Pair) engine.StreamHandle {
        const sessions = self.shared.server.gossipsub.sessions;
        return sessions.outStream(sessions.findPeer(self.shared.handles.server).?).?;
    }

    /// Messages the client admitted in the last step.
    pub fn clientMessages(self: *const Pair) []const MessageEvent {
        return self.shared.client_inbox.messages();
    }

    /// Messages the server admitted in the last step.
    pub fn serverMessages(self: *const Pair) []const MessageEvent {
        return self.shared.server_inbox.messages();
    }
};
