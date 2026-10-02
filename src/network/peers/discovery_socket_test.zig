const std = @import("std");
const d = @import("discv5");
const adapter = @import("enr.zig");

const support = @import("discovery_test_support.zig");
const Node = support.Node;
const handoff = support.handoff;

test "peer discovery independent local nodes confirm signed candidates and cancel all owned work" {
    const io = std.testing.io;
    var b: Node = undefined;
    try b.init(io, 2, 9002, &.{});
    defer b.deinit();
    var a: Node = undefined;
    try a.init(io, 1, 9001, &.{ .bootstrap = &.{b.transport.engine.localRecord().*} });
    defer a.deinit();
    const now = try d.Transport.monotonicMilliseconds(io);
    const controller = &a.owner;
    try controller.request(.{ .general = true }, now);
    var output: [1]adapter.Candidate = undefined;
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    var found = false;
    for (0..100) |_| {
        const tick = try d.Transport.monotonicMilliseconds(io);
        const result = try controller.step(io, tick, tick, &output);
        if (result.failure) |err| return err;
        const remote = try b.transport.stepUntil(io, &expiries, tick);
        if (remote.failure) |err| return err;
        for (output[0..result.candidates]) |candidate| {
            try adapter.requireIdentity(b.transport.engine.localRecord(), &candidate.peer);
            try std.testing.expectEqual(@as(u16, 9002), candidate.addresses[0].port());
            found = true;
        }
        if (found) break;
    }
    try std.testing.expect(found);
    try std.testing.expect(controller.lookup != null);
    try std.testing.expectEqual(@as(u64, 1), controller.counters.candidates_published);
    try std.testing.expect(controller.counters.lookups_started > 0);
    try handoff(&output[0]);
    controller.cancel();
    controller.cancel();
    try std.testing.expectEqual(@as(usize, 0), a.transport.engine.calls.count());
    try std.testing.expect(controller.nextWakeup(now) == null);
    try std.testing.expectError(error.Stopped, controller.request(.{ .general = true }, now));
}

test "dual-stack discovery confirms both families in one routing table" {
    const io = std.testing.io;
    var ipv4: Node = undefined;
    try ipv4.init(io, 92, null, &.{});
    defer ipv4.deinit();
    var ipv6: Node = undefined;
    try ipv6.init(io, 93, null, &.{ .bindings = .{ .ip6 = .loopback(0) } });
    defer ipv6.deinit();
    var hub: Node = undefined;
    try hub.init(io, 91, null, &.{ .bindings = .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } }, .bootstrap = &.{ ipv4.transport.engine.localRecord().*, ipv6.transport.engine.localRecord().* } });
    defer hub.deinit();
    const now = try d.Transport.monotonicMilliseconds(io);
    const controller = &hub.owner;
    try controller.request(.{ .general = true }, now);
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    for (0..400) |_| {
        const tick = try d.Transport.monotonicMilliseconds(io);
        const result = try controller.step(io, tick, tick, &.{});
        if (result.failure) |err| return err;
        for ([_]*Node{ &ipv4, &ipv6 }) |node| {
            const remote = try node.transport.stepUntil(io, &expiries, tick);
            if (remote.failure) |err| return err;
        }
        if (hub.transport.engine.peerRecord(&ipv4.transport.engine.localRecord().node_id).?.last_verified_ms != null and
            hub.transport.engine.peerRecord(&ipv6.transport.engine.localRecord().node_id).?.last_verified_ms != null) break;
    }
    try std.testing.expectEqual(@as(usize, 2), hub.transport.engine.peerCount());
    try std.testing.expect(hub.transport.engine.peerRecord(&ipv4.transport.engine.localRecord().node_id).?.last_verified_ms != null);
    try std.testing.expect(hub.transport.engine.peerRecord(&ipv6.transport.engine.localRecord().node_id).?.last_verified_ms != null);
    try std.testing.expect(hub.transport.engine.peerRecord(&ipv4.transport.engine.localRecord().node_id).?.peer.address == .ip4);
    try std.testing.expect(hub.transport.engine.peerRecord(&ipv6.transport.engine.localRecord().node_id).?.peer.address == .ip6);
}

test "IPv6-only discovery bootstraps a dual-stack record over IPv6" {
    const io = std.testing.io;
    var seed: Node = undefined;
    try seed.init(io, 95, null, &.{ .bindings = .{ .ip6 = .loopback(0) }, .alternate_ip4 = .{ 127, 0, 0, 1 } });
    defer seed.deinit();
    var node: Node = undefined;
    try node.init(io, 94, null, &.{ .bindings = .{ .ip6 = .loopback(0) }, .bootstrap = &.{seed.transport.engine.localRecord().*} });
    defer node.deinit();
    const now = try d.Transport.monotonicMilliseconds(io);
    const controller = &node.owner;
    try controller.request(.{ .general = true }, now);
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    for (0..100) |_| {
        const tick = try d.Transport.monotonicMilliseconds(io);
        const result = try controller.step(io, tick, tick, &.{});
        if (result.failure) |err| return err;
        const response = try seed.transport.stepUntil(io, &expiries, tick);
        if (response.failure) |err| return err;
        if (node.transport.engine.peerRecord(&seed.transport.engine.localRecord().node_id).?.last_verified_ms != null) break;
    }
    try std.testing.expect(node.transport.engine.peerRecord(&seed.transport.engine.localRecord().node_id).?.peer.address == .ip6);
    try std.testing.expect(node.transport.engine.peerRecord(&seed.transport.engine.localRecord().node_id).?.last_verified_ms != null);
}
