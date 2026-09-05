const std = @import("std");
const config = @import("config");
const constants = @import("constants");
const ct = @import("consensus_types");
const fork_types = @import("fork_types");
const network = @import("network");
const preset = @import("preset");

const engine_mod = network.quic.engine;
const keys = network.wire.keys;
const multiaddr = network.wire.multiaddr;
const peer_id = network.wire.peer_id;
const reqresp = network.reqresp;
const Protocol = reqresp.Protocol;
const RequestHandle = reqresp.RequestHandle;
const BeaconConfig = config.BeaconConfig;
const StatusV2 = ct.fulu.StatusV2;
const MetaDataV3 = ct.fulu.MetaDataV3;
const AnyBlock = fork_types.AnySignedBeaconBlock;

const steps_max = 20_000;
const forks_max = 16;
const inbound_max = 2;
const slots_per_epoch = preset.preset.SLOTS_PER_EPOCH;
const zeros = [_]u8{0} ** StatusV2.fixed_size;

const Network = struct {
    name: []const u8,
    config: *const config.BeaconConfig,
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
    start_slot: ?u64 = null,
    count: u64 = 2,
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(gpa.deinit() == .ok);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const options = parseArgs(args) catch {
        std.debug.print(
            "usage: {s} dial <multiaddr> [--network mainnet|hoodi|minimal] " ++
                "[--start-slot N] [--count N]\n",
            .{args[0]},
        );
        std.process.exit(2);
    };
    var peer_status: ?StatusV2.Type = null;
    dial(gpa.allocator(), init.io, options, &peer_status) catch |err| {
        if (err != error.ConnectionClosed or peer_status == null) return err;
        std.debug.print("redialing with the peer's finalized checkpoint\n", .{});
        try dial(gpa.allocator(), init.io, options, &peer_status);
    };
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
        } else if (std.mem.eql(u8, flag, "--start-slot")) {
            options.start_slot = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, flag, "--count")) {
            options.count = try std.fmt.parseInt(u64, value, 10);
        } else return error.Usage;
    }
    if (index != args.len) return error.Usage;
    return options;
}

fn forkTable(cfg: *const BeaconConfig, out: []reqresp.ForkEntry) []const reqresp.ForkEntry {
    var len: usize = 0;
    for (cfg.forks_ascending_epoch_order) |info| len = addFork(cfg, out, len, info.epoch);
    for (cfg.chain.BLOB_SCHEDULE) |entry| len = addFork(cfg, out, len, entry.EPOCH);
    return out[0..len];
}

fn addFork(cfg: *const BeaconConfig, out: []reqresp.ForkEntry, len: usize, epoch: u64) usize {
    if (epoch == constants.FAR_FUTURE_EPOCH or len == out.len) return len;
    const digest = config.fork_digest.computeForkDigest(cfg, epoch);
    for (out[0..len]) |entry| {
        if (std.mem.eql(u8, &entry.digest, &digest)) return len;
    }
    out[len] = .{ .digest = digest, .fork = cfg.forkSeqAtEpoch(epoch) };
    return len + 1;
}

fn currentDigest(net: *const Network, unix_s: i64) [4]u8 {
    const chain = net.config.chain;
    const scheduled: i64 = @intCast(chain.MIN_GENESIS_TIME + chain.GENESIS_DELAY);
    const genesis = if (net.genesis_time != 0) net.genesis_time else scheduled;
    const elapsed: u64 = if (unix_s > genesis) @intCast(unix_s - genesis) else 0;
    const epoch = elapsed / (chain.SECONDS_PER_SLOT * slots_per_epoch);
    return config.fork_digest.computeForkDigest(net.config, epoch);
}

fn hex(bytes: anytype) [2 * bytes.len]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

fn parseStatus(bytes: []const u8) !StatusV2.Type {
    var padded = zeros;
    @memcpy(padded[0..bytes.len], bytes);
    var status: StatusV2.Type = undefined;
    try StatusV2.deserializeFromBytes(&padded, &status);
    return status;
}

fn printStatus(status: *const StatusV2.Type) void {
    std.debug.print("peer status digest=0x{s} finalized={d}/0x{s} head={d}/0x{s} earliest={d}\n", .{
        &hex(status.fork_digest),
        status.finalized_epoch,
        &hex(status.finalized_root),
        status.head_slot,
        &hex(status.head_root),
        status.earliest_available_slot,
    });
}

fn printMetadata(bytes: []const u8) !void {
    var padded = zeros;
    @memcpy(padded[0..bytes.len], bytes);
    var metadata: MetaDataV3.Type = undefined;
    try MetaDataV3.deserializeFromBytes(padded[0..MetaDataV3.fixed_size], &metadata);
    std.debug.print("metadata seq={d} attnets=0x{s} syncnets=0x{s} custody_groups={d}\n", .{
        metadata.seq_number,
        &hex(metadata.attnets.data),
        &hex(metadata.syncnets.data),
        metadata.custody_group_count,
    });
}

const Session = struct {
    allocator: std.mem.Allocator,
    options: Options,
    engine: *engine_mod.Engine,
    svc: *reqresp.Service,
    conn: engine_mod.Handle,
    sink: []u8,
    now: network.types.Now = .{ .mono_ms = 0, .unix_s = 0 },
    current: ?Protocol = null,
    peer_status: ?StatusV2.Type = null,
    finished: bool = false,
    request_ssz: [StatusV2.fixed_size]u8 = undefined,
    response_ssz: [inbound_max][StatusV2.fixed_size]u8 = undefined,

    fn send(self: *Session, which: Protocol) !void {
        const body = self.encode(which, &self.request_ssz);
        _ = try self.svc.request(self.engine, self.conn, which, body, self.sink, .{}, self.now);
        self.current = which;
        std.debug.print("request {s}\n", .{which.id()});
    }

    fn encode(self: *Session, which: Protocol, out: *[StatusV2.fixed_size]u8) []const u8 {
        switch (which) {
            .status_v1, .status_v2 => {
                var status = self.peer_status orelse std.mem.zeroes(StatusV2.Type);
                status.fork_digest = currentDigest(self.options.network, self.now.unix_s);
                status.earliest_available_slot = 0;
                _ = StatusV2.serializeIntoBytes(&status, out);
            },
            .blocks_by_range_v2 => {
                const request = ct.phase0.BeaconBlocksByRangeRequest.Type{
                    .start_slot = self.options.start_slot orelse 0,
                    .count = self.options.count,
                    .step = 1,
                };
                _ = ct.phase0.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, out);
            },
            else => @memset(out, 0),
        }
        return out[0..which.info().request_max];
    }

    fn handle(self: *Session, event: reqresp.Event) !void {
        switch (event) {
            .chunk => |chunk| {
                try self.onChunk(chunk.bytes, chunk.fork);
                _ = self.svc.consume(chunk.request, self.now);
            },
            .done => |done| try self.advance(done.chunks),
            .failed => |failed| try self.onFailure(failed.request, failed.reason),
            .request => |req| try self.serve(req.request, req.protocol, req.bytes),
            .chunk_sent => |sent| _ = self.svc.finish(sent.request, self.now),
            .served, .over_limit => {},
        }
    }

    fn onChunk(self: *Session, bytes: []const u8, fork: ?config.ForkSeq) !void {
        const current = self.current orelse return error.UnexpectedChunk;
        switch (current) {
            .status_v1, .status_v2 => {
                const status = try parseStatus(bytes);
                self.peer_status = status;
                printStatus(&status);
                if (self.options.start_slot == null) {
                    self.options.start_slot = status.finalized_epoch * slots_per_epoch;
                }
            },
            .ping_v1 => {
                std.debug.print("pong seq={d}\n", .{std.mem.readInt(u64, bytes[0..8], .little)});
            },
            .metadata_v2, .metadata_v3 => try printMetadata(bytes),
            .blocks_by_range_v2 => try self.printBlock(bytes, fork orelse return error.NoFork),
            else => return error.UnexpectedChunk,
        }
    }

    fn printBlock(self: *Session, bytes: []const u8, fork: config.ForkSeq) !void {
        const allocator = self.allocator;
        const block = try AnyBlock.deserialize(allocator, .full, fork, bytes);
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

    fn advance(self: *Session, chunks: u32) !void {
        const current = self.current orelse return;
        std.debug.print("done {s} chunks={d}\n", .{ current.id(), chunks });
        const next: ?Protocol = switch (current) {
            .status_v1, .status_v2 => .ping_v1,
            .ping_v1 => .metadata_v3,
            .metadata_v2, .metadata_v3 => .blocks_by_range_v2,
            else => null,
        };
        if (next) |which| try self.send(which) else self.finished = true;
    }

    fn onFailure(self: *Session, request: RequestHandle, reason: reqresp.Failure) !void {
        if (request.direction == .inbound) return;
        const current = self.current orelse return error.RequestFailed;
        const fallback: ?Protocol = switch (current) {
            .status_v2 => .status_v1,
            .metadata_v3 => .metadata_v2,
            else => null,
        };
        if (reason == .negotiation_rejected and fallback != null) {
            std.debug.print("{s} rejected, falling back\n", .{current.id()});
            return self.send(fallback.?);
        }
        if (reason == .peer_error) {
            const message = self.svc.errorMessage(request);
            const code = reason.peer_error.code;
            std.debug.print("peer error code={d} message={s}\n", .{ code, message });
        }
        const detail: []const u8 = switch (reason) {
            .invalid_response, .invalid_request => |err| @errorName(err),
            .negotiation_failed => |err| @tagName(err),
            else => "",
        };
        const id = current.id();
        std.debug.print("request {s} failed: {s} {s}\n", .{ id, @tagName(reason), detail });
        return error.RequestFailed;
    }

    fn serve(self: *Session, request: RequestHandle, which: Protocol, bytes: []const u8) !void {
        std.debug.print("serving {s}\n", .{which.id()});
        switch (which) {
            .status_v1, .status_v2 => {
                const status = try parseStatus(bytes);
                if (self.peer_status == null) printStatus(&status);
                self.peer_status = status;
            },
            .ping_v1, .metadata_v2, .metadata_v3 => {},
            .goodbye_v1 => {
                const reason = std.mem.readInt(u64, bytes[0..8], .little);
                std.debug.print("goodbye reason={d}\n", .{reason});
                _ = self.svc.finish(request, self.now);
                return;
            },
            else => return self.svc.respondError(request, 3, "unavailable", self.now),
        }
        const response: []const u8 = switch (which) {
            .status_v1, .status_v2 => self.encode(which, &self.response_ssz[request.index]),
            else => zeros[0..which.info().response_max],
        };
        try self.svc.respond(request, response, null, self.now);
    }
};

fn dial(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    peer_status: *?StatusV2.Type,
) !void {
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
    var table: [forks_max]reqresp.ForkEntry = undefined;
    var svc = try reqresp.Service.init(allocator, .{ .reqresp = .{
        .forks = forkTable(options.network.config, &table),
        .inbound_max = inbound_max,
        .inbound_per_peer_max = inbound_max,
    } });
    defer svc.deinit();
    defer svc.shutdown(&node.engine);
    const sink = try allocator.alloc(u8, Protocol.blocks_by_range_v2.info().response_max);
    defer allocator.free(sink);

    var session = Session{
        .allocator = allocator,
        .options = options,
        .engine = &node.engine,
        .svc = &svc,
        .conn = try node.dial(io, &target),
        .sink = sink,
        .peer_status = peer_status.*,
    };
    defer peer_status.* = session.peer_status;

    var events: [16]engine_mod.Event = undefined;
    var activity: [8]engine_mod.Handle = undefined;
    var rr_events: [8]reqresp.Event = undefined;
    var steps: u32 = 0;
    while (steps < steps_max and !session.finished) : (steps += 1) {
        const now = try network.driver.currentTime(io);
        const due = svc.nextWakeup(now, rr_events.len);
        const wait_ms: u32 = @intCast(@min(network.constants.poll_interval_ms, if (due) |deadline| deadline -| now.mono_ms else network.constants.poll_interval_ms));
        const result = try node.step(io, &events, &activity, .{ .wait_max_ms = wait_ms });
        session.now = result.now;
        for (events[0..result.events]) |event| switch (event) {
            .connected => |connected| {
                var text: [peer_id.text_length_max]u8 = undefined;
                std.debug.print("connected peer={s} our digest=0x{s}\n", .{
                    connected.peer_id.toText(&text),
                    &hex(currentDigest(options.network, result.now.unix_s)),
                });
                try session.send(.status_v2);
            },
            .closed => |closed| {
                std.debug.print("closed reason={s}\n", .{@tagName(closed.reason)});
                return error.ConnectionClosed;
            },
            else => {},
        };
        const count = svc.process(&node.engine, events[0..result.events], activity[0..result.activity], result.now, &rr_events);
        for (rr_events[0..count]) |event| try session.handle(event);
    }
    if (!session.finished) return error.Timeout;
    _ = node.engine.close(session.conn, 0);
    _ = try node.step(io, &events, &activity, .{});
}
