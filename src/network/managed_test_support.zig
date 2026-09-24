const std = @import("std");
const support = @import("test_support.zig");
const managed = @import("managed.zig");
const t = @import("peers/types.zig");
const Engine = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Inbox = @import("gossipsub/test_support.zig").Inbox;

pub fn localState(overrides: t.LocalState) t.LocalState {
    var local = overrides;
    local.metadata.custody_group_count = local.metadata.custody_group_count orelse 1;
    local.status.earliest_available_slot = local.status.earliest_available_slot orelse 0;
    return local;
}

pub fn updateLocal(manager: *managed.PeerManager, service: *@import("service.zig").Service, local: *const t.LocalState, now: @import("types.zig").Now) !void {
    var copied: t.LocalState = undefined;
    try @import("peers/control_wire.zig").copyServingLocal(&copied, local, service.router.capabilities().receive);
    manager.commitLocal(service, &copied, now);
}

/// The small resolved profile with the harness's peer, dial, request and gossip values.
pub fn request() @import("configuration.zig").Request {
    const gc = @import("gossipsub/constants.zig");
    return .{
        .profile = .small,
        .seed = 1,
        .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }},
        .limits = .{
            .connections_max = 4,
            .handshaking_max = 4,
            .handshaking_per_source_max = 4,
            .dialing_max = 1,
        },
        .peers = .{
            .capacity = 4,
            .outbound_reserve = 1,
            .max_peers = 3,
            .target_peers = 2,
            .min_outbound = 1,
        },
        .dial = .{ .capacity = 4, .concurrent_max = 1, .outbound_reserved = 1, .seed = 7 },
        .router = .{ .negotiations_max = 24 },
        .reqresp = .{
            .outbound_max = 16,
            .inbound_max = 16,
            .outbound_per_peer_max = 8,
            .inbound_per_peer_max = 16,
            .inbound_application_per_peer_max = 8,
        },
        .gossip = .{
            .topic_policy = comptime &.{@import("gossipsub/topic_fixture.zig").bytes(@splat(0))},
            .seen_capacity = 16,
            .mcache_capacity = 8,
            .validation_capacity = 2,
            .mcache_arena_bytes = gc.maxCompressedLen(gc.MAX_PAYLOAD_SIZE) + 4096,
            .receive_arena_bytes = std.mem.alignForward(usize, gc.GOSSIP_MAX_SIZE, 4096),
            .body_buffer_bytes = 256,
            .control_bytes = 512,
            .critical_bytes = 512,
        },
        .admission_policy = @import("reqresp/policy_fixture.zig").config(),
    };
}

pub fn options() managed.Options {
    return (@import("configuration.zig").resolve(request()) catch unreachable).core;
}

pub const Setup = struct {
    pair: support.Pair = .{},
    client: managed.PeerManager = undefined,
    client_service: @import("service.zig").Service = undefined,
    server: managed.PeerManager = undefined,
    server_service: @import("service.zig").Service = undefined,
    client_inbox: Inbox = .{},
    server_inbox: Inbox = .{},
    client_events: [1]t.Event = undefined,
    server_events: [1]t.Event = undefined,
    pub fn init(self: *Setup, local: *const t.LocalState) !void {
        try self.initDirection(local, false);
    }
    pub fn initDirection(self: *Setup, local: *const t.LocalState, reverse: bool) !void {
        try self.initOwners(local);
        errdefer self.deinit();
        if (reverse) {
            _ = try self.pair.server.dial(
                &support.client_address,
                self.pair.client_ctx.local_peer_id,
                self.pair.now,
            );
        } else _ = try self.pair.dial();
    }
    pub fn initOwners(self: *Setup, local: *const t.LocalState) !void {
        try self.initOwnersWithOptions(local, options());
    }
    pub fn initOwnersWithOptions(
        self: *Setup,
        overrides: *const t.LocalState,
        opts: managed.Options,
    ) !void {
        const local = &localState(overrides.*);
        const limits: Engine.Limits = .{
            .connections_max = 4,
            .handshaking_max = 4,
            .handshaking_per_source_max = 4,
            .dialing_max = 2,
        };
        try self.pair.init(limits, limits);
        errdefer self.pair.deinit();
        self.client_service = try @import("service.zig").Service.init(std.testing.allocator, managed.serviceOptions(opts, local));
        errdefer self.client_service.deinit();
        self.client_inbox.attach(self.client_service.gossipsub);
        self.client = try managed.PeerManager.init(
            std.testing.allocator,
            &self.pair.client_ctx.local_peer_id,
            local,
            managed.peerOptions(opts),
            &self.client_service,
            self.pair.client.limits.connections_max,
        );
        errdefer self.client.deinit();
        self.server_service = try @import("service.zig").Service.init(std.testing.allocator, managed.serviceOptions(opts, local));
        errdefer self.server_service.deinit();
        self.server_inbox.attach(self.server_service.gossipsub);
        self.server = try managed.PeerManager.init(
            std.testing.allocator,
            &self.pair.server_ctx.local_peer_id,
            local,
            managed.peerOptions(opts),
            &self.server_service,
            self.pair.server.limits.connections_max,
        );
    }
    pub fn deinit(self: *Setup) void {
        managed.shutdown(&self.client, &self.client_service, &self.pair.client, self.pair.now);
        managed.shutdown(&self.server, &self.server_service, &self.pair.server, self.pair.now);
        self.server_service.deinit();
        self.server.deinit();
        self.client_service.deinit();
        self.client.deinit();
        self.server_inbox.deinit();
        self.client_inbox.deinit();
        self.pair.deinit();
    }
    /// Gossip delivered in earlier steps is cleared first.
    pub fn step(self: *Setup, capacity: usize) !void {
        self.client_inbox.clear();
        self.server_inbox.clear();
        try self.pair.pump();
        var events: [32]Engine.Event = undefined;
        _ = managed.process(
            &self.server,
            &self.server_service,
            &self.pair.server,
            self.pair.events(&self.pair.server, &events),
            self.pair.now,
            100,
            self.server_events[0..capacity],
            &.{},
        );
        _ = managed.process(
            &self.client,
            &self.client_service,
            &self.pair.client,
            self.pair.events(&self.pair.client, &events),
            self.pair.now,
            100,
            self.client_events[0..capacity],
            &.{},
        );
    }
};
