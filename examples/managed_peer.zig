const std = @import("std");
const network = @import("network");
const d = @import("discv5");

const turns_max = 2000;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3 or args[1].len != 64) {
        std.debug.print("usage: managed_peer <64 hex secret key> [trusted bootstrap ENR]\n", .{});
        return error.Usage;
    }
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, args[1]);
    defer std.crypto.secureZero(u8, &secret);
    const key = try network.KeyPair.fromSecretKey(&secret);
    var bootstrap: [1]d.identity.enr.Record = undefined;
    const count: usize = if (args.len == 3) 1 else 0;
    if (count > 0) bootstrap[0] = try d.identity.enr.Record.initText(args[2]);
    var allocator: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(allocator.deinit() == .ok);
    const a = allocator.allocator();
    const node = try a.create(network.NetworkCore);
    defer a.destroy(node);
    const local: network.peers.types.LocalState = .{
        .fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } },
        .status = .{ .fork_digest = .{ 1, 2, 3, 4 }, .head_slot = 100, .earliest_available_slot = 0 },
        .metadata = .{ .custody_group_count = 4 },
    };
    var seed: [8]u8 = undefined;
    try init.io.randomSecure(&seed);
    var core: network.core.Options = .{ .dial = .{ .seed = std.mem.readInt(u64, &seed, .little) } };
    core.peers.engine_capacity = (network.quic.engine.Limits{}).connections_max;
    core.service.reqresp.forks = &.{.{ .digest = local.fork.digest, .fork = local.fork.fork }};
    core.service.gossipsub.random_seed = core.dial.seed;
    try node.init(a, init.io, .{
        .transport = .{ .host = &key, .bind = .{ .ip4 = .loopback(0) } },
        .core = core,
        .local = local,
        .schedule = .{ .fulu_scheduled = true },
        .discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .bootstrap = bootstrap[0..count] },
    });
    defer node.deinit(init.io);
    std.debug.print("memory={any}\n", .{node.memoryPlan()});
    var events: [1]network.peers.types.Event = undefined;
    for (0..if (count == 0) 1 else turns_max) |_| {
        const now = try network.driver.currentTime(init.io);
        const result = node.step(init.io, now, 100, .{ .peers = &events }, 5);
        if (result.failure) |err| return err;
        for (events[0..result.counts.peers]) |event| std.debug.print("peer={s}\n", .{@tagName(event)});
        if (node.connectedPeerCount() > 0) break;
    }
    node.shutdown(try network.driver.currentTime(init.io));
    for (0..100) |_| {
        _ = node.step(init.io, try network.driver.currentTime(init.io), 100, .{}, 0);
        if (node.isClosed()) break;
    }
    if (!node.isClosed()) return error.ShutdownIncomplete;
    std.debug.print("closed=true\n", .{});
}
