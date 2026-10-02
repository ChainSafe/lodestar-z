const std = @import("std");
const d = @import("discv5");
const adapter = @import("enr.zig");
const discovery = @import("discovery.zig");
const types = @import("types.zig");
const context = types.ForkContext{ .digest = .{ 1, 2, 3, 4 } };

pub const Node = struct {
    io: std.Io,
    owner: discovery.Discovery,
    transport: *d.Transport,

    pub const Options = struct {
        fork: types.ForkContext = context,
        bootstrap: []const d.identity.enr.Record = &.{},
        discovery: discovery.Discovery.Options = .{},
        bindings: @import("udp").Sockets.Bindings = .{ .ip4 = .loopback(0) },
        alternate_ip4: ?[4]u8 = null,
    };

    pub fn init(self: *Node, io: std.Io, scalar: u8, quic: ?u16, options: *const Options) !void {
        self.io = io;
        var sockets = try @import("udp").Sockets.bind(io, options.bindings);
        errdefer sockets.close(io);
        const address = sockets.localAddress();
        const key = try d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{scalar}));
        const local = adapter.LocalAdvertisement{
            .fork = .{ .digest = options.fork.digest, .next_version = @splat(0), .next_epoch = std.math.maxInt(u64) },
            .ip4 = switch (address) {
                .ip4 => |value| value.octets,
                .ip6 => options.alternate_ip4,
            },
            .ip6 = if (sockets.values[1]) |socket| socket.address.ip6.bytes else null,
            .udp = if (address == .ip4) address.port() else if (options.alternate_ip4 != null) @as(u16, 9000) else null,
            .udp6 = if (sockets.values[1]) |socket| socket.address.getPort() else null,
            .quic = quic,
        };
        const record = try adapter.build(&key, 1, &local, &options.fork);
        const now = try d.Transport.monotonicMilliseconds(io);
        try self.owner.initBound(std.testing.allocator, sockets, &key, &record, &options.fork, options.bootstrap, now, options.discovery, .{ .poll_interval_ms = 1, .engine = .{
            .session_capacity = 8,
            .challenge_capacity = 8,
            .call_capacity = 8,
        } });
        self.transport = &self.owner.transport;
    }
    pub fn deinit(self: *Node) void {
        self.owner.deinit(self.io);
    }
};

pub fn handoff(candidate: *const adapter.Candidate) !void {
    const support = @import("../quic/test_support.zig");
    const dial = @import("dialing.zig");
    var pair = support.Pair{};
    try pair.init(.{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 }, .{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 });
    defer pair.deinit();
    const opts = @import("../network_core_test_support.zig").options().core;
    const local = @import("../network_core_test_support.zig").localState(.{ .fork = context, .status = .{ .fork_digest = context.digest } });
    var service = try @import("../service_test_support.zig").initService(std.testing.allocator, opts.service, &pair.client);
    defer service.deinit();
    const gossipsub = service.gossipsub;
    var core = try @import("../peer_manager.zig").PeerManager.init(std.testing.allocator, &pair.client_ctx.local_peer_id, &local, opts.peerManager(), service.router.capabilities().receive, pair.client.limits.connections_max);
    defer core.deinit();
    try std.testing.expectEqual(@as(u16, 1), core.discoveredBatch(gossipsub, &.{candidate.*}, pair.now).accepted);
    try std.testing.expectEqual(candidate.sequence, core.catalog.rows[0].intent.hints.?.sequence);
    var intents: [2]dial.Dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), core.dialIntents(gossipsub, &pair.client, pair.now, &intents));
    try std.testing.expect(intents[0].peer.eql(&candidate.peer));
    try std.testing.expectEqual(candidate.addresses[0], intents[0].address);
    try std.testing.expect(core.dialFailed(intents[0].token, pair.now));
    try std.testing.expectEqual(@as(u16, 1), core.discoveredBatch(gossipsub, &.{candidate.*}, pair.now).accepted);
    try std.testing.expectEqual(@as(usize, 0), core.dialIntents(gossipsub, &pair.client, pair.now, &intents));
    for (3..6) |scalar| {
        const key = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{@as(u8, @intCast(scalar))}));
        const identity = types.PeerId.fromPublicKey(&key.publicKey());
        try core.connect(&identity, candidate.addresses[0..candidate.address_count], pair.now);
    }
    const key = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{6}));
    try std.testing.expectError(error.Capacity, core.connect(&types.PeerId.fromPublicKey(&key.publicKey()), candidate.addresses[0..candidate.address_count], pair.now));
    try std.testing.expectEqual(@as(u16, 1), core.discoveredBatch(gossipsub, &.{candidate.*}, pair.now).accepted);
    const count = core.dialIntents(gossipsub, &pair.client, pair.now, &intents);
    try std.testing.expectEqual(@as(usize, opts.dial.concurrent_max), count);
    for (intents[0..count]) |intent| try std.testing.expect(!intent.peer.eql(&candidate.peer));
}

pub fn admitBatch(candidates: []const adapter.Candidate) !void {
    const support = @import("../quic/test_support.zig");
    var pair = support.Pair{};
    try pair.init(.{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 }, .{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 });
    defer pair.deinit();
    const opts = @import("../network_core_test_support.zig").options().core;
    const local = @import("../network_core_test_support.zig").localState(.{ .fork = context, .status = .{ .fork_digest = context.digest } });
    var service = try @import("../service_test_support.zig").initService(std.testing.allocator, opts.service, &pair.client);
    defer service.deinit();
    var options = opts.peerManager();
    options.peers.capacity = discovery.Discovery.candidates_per_step;
    options.dial.capacity = discovery.Discovery.candidates_per_step;
    var manager = try @import("../peer_manager.zig").PeerManager.init(std.testing.allocator, &pair.client_ctx.local_peer_id, &local, options, service.router.capabilities().receive, pair.client.limits.connections_max);
    defer manager.deinit();
    const result = manager.discoveredBatch(service.gossipsub, candidates, pair.now);
    try std.testing.expectEqual(candidates.len, result.accepted);
    try std.testing.expectEqual(@as(u16, 0), result.refused);
    try std.testing.expectEqual(candidates.len, manager.catalog.intents.count());
    for (candidates) |*candidate| {
        const ref = manager.catalog.find(&candidate.peer).?;
        const row = manager.catalog.rowFor(ref).?;
        try std.testing.expectEqual(candidate.sequence, row.intent.hints.?.sequence);
        try std.testing.expectEqualSlices(types.Address, candidate.addresses[0..candidate.address_count], row.intent.addresses[0..row.intent.address_count]);
    }
}
