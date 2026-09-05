const std = @import("std");
const config = @import("config");
const ct = @import("consensus_types");
const fork_types = @import("fork_types");
const network = @import("network");
const preset = @import("preset");

const engine_mod = network.quic.engine;
const keys = network.wire.keys;
const multiaddr = network.wire.multiaddr;
const peer_id = network.wire.peer_id;
const gossipsub = network.gossipsub;
const Service = network.Service;
const BeaconConfig = config.BeaconConfig;
const AnyBlock = fork_types.AnySignedBeaconBlock;

const steps_max = 200_000;
const ping_sequence = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
const slots_per_epoch = preset.preset.SLOTS_PER_EPOCH;

const Network = struct {
    name: []const u8,
    config: *const BeaconConfig,
    genesis_time: i64,
};

const networks = [_]Network{
    .{ .name = "mainnet", .config = &config.mainnet.config, .genesis_time = 1_606_824_023 },
    .{ .name = "hoodi", .config = &config.hoodi.config, .genesis_time = 1_742_213_400 },
    .{ .name = "minimal", .config = &config.minimal.config, .genesis_time = 0 },
};

const Options = struct {
    target: []const u8,
    network: *const Network = &networks[0],
    blocks: u32 = 1,
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(gpa.deinit() == .ok);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const options = parseArgs(args) catch {
        std.debug.print(
            "usage: {s} dial <multiaddr> [--network mainnet|hoodi|minimal] [--blocks N]\n",
            .{args[0]},
        );
        std.process.exit(2);
    };
    try dial(gpa.allocator(), init.io, options);
}

fn parseArgs(args: []const [:0]const u8) !Options {
    if (args.len < 3 or !std.mem.eql(u8, args[1], "dial")) return error.Usage;
    var options = Options{ .target = args[2] };
    var index: usize = 3;
    while (index + 1 < args.len) : (index += 2) {
        const flag = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, flag, "--network")) {
            options.network = for (&networks) |*entry| {
                if (std.mem.eql(u8, entry.name, value)) break entry;
            } else return error.Usage;
        } else if (std.mem.eql(u8, flag, "--blocks")) {
            options.blocks = try std.fmt.parseInt(u32, value, 10);
        } else return error.Usage;
    }
    if (index != args.len) return error.Usage;
    return options;
}

fn currentEpoch(net: *const Network, unix_s: i64) u64 {
    const chain = net.config.chain;
    const scheduled: i64 = @intCast(chain.MIN_GENESIS_TIME + chain.GENESIS_DELAY);
    const genesis = if (net.genesis_time != 0) net.genesis_time else scheduled;
    const elapsed: u64 = if (unix_s > genesis) @intCast(unix_s - genesis) else 0;
    return elapsed / (chain.SECONDS_PER_SLOT * slots_per_epoch);
}

fn hex(bytes: anytype) [2 * bytes.len]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

fn printBlock(allocator: std.mem.Allocator, ssz: []const u8, fork: config.ForkSeq) !void {
    const block = try AnyBlock.deserialize(allocator, .full, fork, ssz);
    defer block.deinit(allocator);
    const message = block.beaconBlock();
    var root: [32]u8 = undefined;
    try message.hashTreeRoot(allocator, &root);
    std.debug.print("block fork={s} slot={d} proposer={d} root=0x{s}\n", .{
        @tagName(fork),
        message.slot(),
        message.proposerIndex(),
        &hex(root),
    });
}

fn dial(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const target = try multiaddr.Multiaddr.parse(options.target);
    const bind: std.Io.net.IpAddress = switch (target.address) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{
            .bytes = [_]u8{0} ** 16,
            .port = 0,
            .flow = 0,
            .interface = .{ .index = 0 },
        } },
    };
    var node: network.Transport = .{};
    const key = keys.KeyPair.generate(io);
    try node.init(allocator, io, .{ .host = &key, .bind = bind });
    defer node.deinit(io);

    var service = try Service.init(allocator, .{ .reqresp = .{
        .outbound_max = 4,
        .inbound_max = 4,
        .inbound_per_peer_max = 4,
        .forks = &.{},
    } });
    defer service.deinit();
    defer service.reqresp.shutdownRouted(&service.router, &node.engine);
    const conn = try node.dial(io, &target);

    var events: [16]engine_mod.Event = undefined;
    var activity: [8]engine_mod.Handle = undefined;
    var gossip_events: [16]gossipsub.Event = undefined;
    var request_events: [16]network.reqresp.Event = undefined;
    var subscribed = false;
    var topic_buf: [gossipsub.topic.topic_max_len]u8 = undefined;
    var beacon_block: []const u8 = &.{};
    var fork: config.ForkSeq = .fulu;
    var received: u32 = 0;
    var steps: u32 = 0;
    while (steps < steps_max and received < options.blocks) : (steps += 1) {
        const now = try network.driver.currentTime(io);
        const due = service.nextWakeup(now, request_events.len);
        const wait_ms: u32 = @intCast(@min(network.constants.poll_interval_ms, if (due) |deadline| deadline -| now.mono_ms else network.constants.poll_interval_ms));
        const result = try node.step(io, &events, &activity, .{ .wait_max_ms = wait_ms });
        for (events[0..result.events]) |event| switch (event) {
            .connected => |c| {
                var text: [peer_id.text_length_max]u8 = undefined;
                std.debug.print("connected peer={s}\n", .{c.peer_id.toText(&text)});
                const epoch = currentEpoch(options.network, result.now.unix_s);
                const digest = config.fork_digest.computeForkDigest(options.network.config, epoch);
                fork = options.network.config.forkSeqAtEpoch(epoch);
                beacon_block = gossipsub.topic.build(digest, "beacon_block", &topic_buf);
                std.debug.print("subscribing to {s}\n", .{beacon_block});
            },
            .closed => |closed| {
                std.debug.print("closed reason={s}\n", .{@tagName(closed.reason)});
                return error.ConnectionClosed;
            },
            else => {},
        };
        if (!subscribed and beacon_block.len > 0) {
            _ = service.gossipsub.subscribe(beacon_block);
            subscribed = true;
        }
        const transport_events = events[0..result.events];
        const counts = service.process(&node.engine, transport_events, activity[0..result.activity], result.now, &request_events, &gossip_events);
        try serveRequests(&service, request_events[0..counts.reqresp], result.now);
        for (gossip_events[0..counts.gossipsub]) |event| switch (event) {
            .message => |m| {
                printBlock(allocator, m.bytes, fork) catch |err| {
                    std.debug.print("decode failed: {s}\n", .{@errorName(err)});
                };
                service.gossipsub.report(m.handle, .ignore);
                received += 1;
            },
            .subscription_change => |change| {
                std.debug.print("peer subscribed={} {s}\n", .{ change.subscribed, change.topic });
            },
        };
    }
    if (received == 0) return error.NoBlock;
    _ = node.engine.close(conn, 0);
    _ = try node.step(io, &events, &activity, .{});
}

fn serveRequests(service: *Service, events: []const network.reqresp.Event, now: network.Now) !void {
    for (events) |event| switch (event) {
        .request => |request| {
            if (request.protocol == .ping_v1) {
                try service.reqresp.respond(request.request, &ping_sequence, null, now);
            } else {
                try service.reqresp.respondError(request.request, 2, "unsupported by gossip example", now);
            }
        },
        .chunk_sent => |sent| _ = service.reqresp.finish(sent.request, now),
        else => {},
    };
}
