const std = @import("std");
const d = @import("discv5");
const core_test = @import("test_support.zig");
const runtime = @import("network_core.zig");
const keys = @import("wire/keys.zig");

const Peers = struct {
    nodes: []d.Transport,
    fn init() !Peers {
        const nodes = try std.testing.allocator.alloc(d.Transport, 10);
        errdefer std.testing.allocator.free(nodes);
        var initialized: usize = 0;
        errdefer for (nodes[0..initialized]) |*node| node.deinit(std.testing.allocator, std.testing.io);
        for (nodes, 0..) |*node, i| {
            const key = try d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{@as(u8, @intCast(100 + i))}));
            const sockets = try d.sockets.Sockets.bind(std.testing.io, .{ .ip4 = .{ .bytes = .{ 127, 1, @intCast(i), 1 }, .port = 0 } });
            errdefer sockets.close(std.testing.io);
            const record = try d.identity.enr.Record.create(&key, 1, d.types.Address.fromNetwork(sockets.primary().address));
            try node.init(std.testing.allocator, sockets, key, record, .{});
            initialized += 1;
        }
        return .{ .nodes = nodes };
    }
    fn deinit(self: *Peers) void {
        for (self.nodes) |*node| node.deinit(std.testing.allocator, std.testing.io);
        std.testing.allocator.free(self.nodes);
    }
    fn observe(self: *Peers, node: *runtime.NetworkCore, peers: usize, id: u8) !void {
        const owner = node.discovery.?;
        for (self.nodes[0..peers]) |*remote| {
            const record = remote.engine.localRecord();
            _ = try owner.transport.startCall(std.testing.io, .{ .node_id = record.node_id, .address = remote.localAddress() }, record, &.{ .ping = .{
                .request_id = try .init(&.{id}),
                .enr_sequence = node.localRecord().?.sequence,
            } });
            var expired: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
            var completed = false;
            for (0..100) |_| {
                const now = try @import("transport.zig").currentTime(std.testing.io);
                const response = try remote.stepUntil(std.testing.io, &expired, now.mono_ms);
                if (response.failure) |err| return err;
                const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
                if (result.failure) |err| return err;
                if (owner.transport.engine.calls.count() == 0) {
                    completed = true;
                    break;
                }
            }
            try std.testing.expect(completed);
        }
    }
};

test "address-less discovery learns from ten authenticated prefixes and updates ENR and Identify together" {
    var peers = try Peers.init();
    defer peers.deinit();
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{92}));
    var opts = core_test.networkOptions(&key);
    opts.resolved.core.service.identify = .{};
    opts.resolved.core.peers.target_peers = 0;
    opts.resolved.core.peers.min_outbound = 0;
    opts.startup.bind = .{ .ip4 = .{ .bytes = @splat(0), .port = 0 } };
    opts.startup.discovery = .{ .bind = opts.startup.bind };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    try std.testing.expect(node.localRecord().?.ip4 == null);
    const initial = node.localRecord().?.sequence;
    try peers.observe(&node, 9, 1);
    try std.testing.expect(node.localRecord().?.ip4 == null);
    try peers.observe(&node, 10, 2);
    const learned = node.advertisementEndpoints().?;
    try std.testing.expect(learned.ip4 != null);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, learned.ip4.?);
    try std.testing.expectEqual(node.discovery.?.transport.localAddress().port(), learned.udp.?);
    try std.testing.expectEqual(node.transport.localAddress().port(), learned.quic.?);
    try std.testing.expectEqual(initial + 1, node.localRecord().?.sequence);
    const identify = node.service.identify.local.?;
    try std.testing.expect(identify.address_count > 0);
    try peers.observe(&node, 10, 3);
    try std.testing.expectEqual(initial + 1, node.localRecord().?.sequence);
    var intent = core_test.intent(&node, &.{});
    intent.update.local.metadata.attnets[0] = 1;
    _ = try node.applyIntent(&intent, node.last_now);
    try std.testing.expectEqualDeep(learned, node.advertisementEndpoints().?);
    try std.testing.expectEqualDeep(identify, node.service.identify.local.?);
}

test "failed learned endpoint publication preserves the previous ENR and Identify" {
    var peers = try Peers.init();
    defer peers.deinit();
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{93}));
    var opts = core_test.networkOptions(&key);
    opts.resolved.core.service.identify = .{};
    opts.resolved.core.peers.target_peers = 0;
    opts.resolved.core.peers.min_outbound = 0;
    opts.startup.bind = .{ .ip4 = .{ .bytes = @splat(0), .port = 0 } };
    opts.startup.discovery = .{ .bind = opts.startup.bind, .sequence = std.math.maxInt(u64) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const before = node.localRecord().?.*;
    const identify = node.service.identify.local.?;
    try peers.observe(&node, 10, 1);
    try std.testing.expectEqualSlices(u8, before.slice(), node.localRecord().?.slice());
    try std.testing.expectEqualDeep(identify, node.service.identify.local.?);
    try std.testing.expect(node.advertisementEndpoints().?.ip4 == null);
}
