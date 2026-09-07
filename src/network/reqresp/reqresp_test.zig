const std = @import("std");
const ct = @import("consensus_types");
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../router.zig");
const support = @import("../test_support.zig");

const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const ReqResp = reqresp.ReqResp;

pub const deneb_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xa9 };
pub const fulu_digest = [4]u8{ 0x2f, 0x2f, 0x2f, 0x2f };
const sink_count = 8;

pub const Overrides = struct {
    outbound_max: u16 = 8,
    inbound_max: u16 = 8,
    inbound_per_peer_max: u8 = 8,
    progress_timeout_ms: u64 = 10_000,
    host_timeout_ms: u64 = 60_000,
    quota_timeout_ms: u64 = 60_000,
    quotas: ?@import("limiter.zig").Quotas = null,
    forks: ?[]const reqresp.ForkEntry = null,
    request_policy: ?@import("request_policy.zig").Config = null,
    request_fork: @import("config").ForkSeq = .phase0,
    admission: ?@import("admission.zig").Options = null,
};

pub const ReqRespPair = struct {
    pair: support.Pair = .{},
    client_neg: negotiate.Router = undefined,
    server_neg: negotiate.Router = undefined,
    client: ReqResp = undefined,
    server: ReqResp = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    forks: [2]reqresp.ForkEntry = .{
        .{ .digest = deneb_digest, .fork = .deneb },
        .{ .digest = fulu_digest, .fork = .fulu },
    },
    sinks: []u8 = &.{},
    next_sink: usize = 0,
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,
    server_event_capacity: usize = 16,
    unclaimed: usize = 0,

    pub fn init(self: *ReqRespPair, client: Overrides, server: Overrides) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client_neg = try negotiate.Router.init(std.testing.allocator, .{ .negotiations_max = 16, .meshsub = false });
        errdefer self.client_neg.deinit();
        self.server_neg = try negotiate.Router.init(std.testing.allocator, .{ .negotiations_max = 16, .meshsub = false });
        errdefer self.server_neg.deinit();
        self.client = try ReqResp.init(std.testing.allocator, options(client, &self.forks));
        errdefer self.client.deinit();
        self.server = try ReqResp.init(std.testing.allocator, options(server, &self.forks));
        errdefer self.server.deinit();
        self.sinks = try std.testing.allocator.alloc(u8, sink_count * protocol.requestMaxAll());
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        self.next_sink = 0;
        self.client_count = 0;
        self.server_count = 0;
        self.unclaimed = 0;
    }

    fn options(overrides: Overrides, forks: []const reqresp.ForkEntry) reqresp.Options {
        return .{
            .peers = 128,
            .outbound_max = overrides.outbound_max,
            .inbound_max = overrides.inbound_max,
            .inbound_per_peer_max = overrides.inbound_per_peer_max,
            .progress_timeout_ms = overrides.progress_timeout_ms,
            .forks = overrides.forks orelse forks,
            .quotas = overrides.quotas,
            .request_policy = overrides.request_policy,
            .request_fork = overrides.request_fork,
            .admission = overrides.admission,
            .host_timeout_ms = overrides.host_timeout_ms,
            .quota_timeout_ms = overrides.quota_timeout_ms,
        };
    }

    pub fn deinit(self: *ReqRespPair) void {
        self.client.shutdown(&self.pair.client, &self.client_neg);
        self.server.shutdown(&self.pair.server, &self.server_neg);
        std.testing.allocator.free(self.sinks);
        self.server.deinit();
        self.client.deinit();
        self.server_neg.deinit();
        self.client_neg.deinit();
        self.pair.deinit();
    }

    pub fn requestSink(self: *ReqRespPair) []u8 {
        const size = protocol.requestMaxAll();
        const start = (self.next_sink % sink_count) * size;
        self.next_sink += 1;
        return self.sinks[start..][0..size];
    }

    pub fn pumpOnce(self: *ReqRespPair) !void {
        try self.pair.pump();
        const now = self.pair.now;
        self.client.cleanupPending(&self.pair.client, &self.client_neg);
        self.server.cleanupPending(&self.pair.server, &self.server_neg);
        var storage: [16]engine_mod.Event = undefined;
        for (self.pair.events(&self.pair.server, &storage)) |event| switch (event) {
            .stream_opened => |stream| try self.server_neg.negotiator.acceptInbound(stream, &protocol.ids, now),
            .closed => |closed| self.server.connectionClosed(closed.conn),
            else => {},
        };
        for (self.pair.events(&self.pair.client, &storage)) |event| switch (event) {
            .closed => |closed| self.client.connectionClosed(closed.conn),
            else => {},
        };
        var outcomes: [8]negotiate.Outcome = undefined;
        const dialed = self.client_neg.pump(&self.pair.client, now, &outcomes);
        for (outcomes[0..dialed]) |outcome| {
            if (!self.client.negotiated(outcome, now)) self.unclaimed += 1;
        }
        const listened = self.server_neg.pump(&self.pair.server, now, &outcomes);
        for (outcomes[0..listened]) |outcome| switch (outcome.result) {
            .ready => |ready| {
                _ = try self.server.accept(&self.pair.server, outcome.stream, ready, self.requestSink(), now);
            },
            else => return error.TestUnexpectedResult,
        };
        var activity: [128]engine_mod.Handle = undefined;
        const client_active = self.pair.client.driverView().takeActivity(&activity);
        for (activity[0..client_active]) |conn| self.client.connectionActivity(conn);
        const server_active = self.pair.server.driverView().takeActivity(&activity);
        for (activity[0..server_active]) |conn| self.server.connectionActivity(conn);
        self.client_count = self.client.pump(&self.pair.client, &self.client_neg, now, &self.client_events);
        self.server_count = self.server.pump(&self.pair.server, &self.server_neg, now, self.server_events[0..self.server_event_capacity]);
        try self.pair.pump();
    }

    pub fn clientEvents(self: *const ReqRespPair) []const Event {
        return self.client_events[0..self.client_count];
    }

    pub fn serverEvents(self: *const ReqRespPair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

pub fn statusBytes(seed: u8) [ct.phase0.Status.fixed_size]u8 {
    const status = ct.phase0.Status.Type{
        .fork_digest = deneb_digest,
        .finalized_root = [_]u8{seed} ** 32,
        .finalized_epoch = seed,
        .head_root = [_]u8{seed +% 1} ** 32,
        .head_slot = @as(u64, seed) * 32,
    };
    var bytes: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = ct.phase0.Status.serializeIntoBytes(&status, &bytes);
    return bytes;
}

const Exchange = struct {
    request_seen: bool = false,
    served: bool = false,
    chunks: u32 = 0,
    done: bool = false,
    failed: ?reqresp.Failure = null,
};

fn serveStatus(setup: *ReqRespPair, reply: []const u8, exchange: *Exchange) !void {
    for (setup.serverEvents()) |event| switch (event) {
        .request => |incoming| {
            exchange.request_seen = true;
            try std.testing.expectError(error.InvalidContext, setup.server.respond(incoming.request, reply, .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now));
            try setup.server.respond(incoming.request, reply, null, setup.pair.now);
            try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
        },
        .served => exchange.served = true,
        .failed => |failure| exchange.failed = failure.reason,
        else => {},
    };
}

fn drainClient(setup: *ReqRespPair, expected: []const u8, exchange: *Exchange) !void {
    for (setup.clientEvents()) |event| switch (event) {
        .chunk => |chunk| {
            try std.testing.expectEqualSlices(u8, expected, chunk.bytes);
            exchange.chunks += 1;
            try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
        },
        .done => |finished| {
            exchange.done = true;
            try std.testing.expectEqual(exchange.chunks, finished.chunks);
        },
        .failed => |failure| exchange.failed = failure.reason,
        else => {},
    };
}

test "reqresp rejects non-null status context then completes a status round trip" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const request_ssz = statusBytes(3);
    const reply_ssz = statusBytes(9);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    const handle = try setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        &sink,
        .{},
        setup.pair.now,
    );
    try std.testing.expectEqual(engine_mod.Direction.outbound, handle.direction);

    var exchange = Exchange{};
    var rounds: usize = 0;
    while (rounds < 30 and !(exchange.done and exchange.served)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(Protocol.status_v1, incoming.protocol);
                try std.testing.expectEqual(setup.handles.server, incoming.peer);
                try std.testing.expectEqualSlices(u8, &request_ssz, incoming.bytes);
            },
            else => {},
        };
        try serveStatus(&setup, &reply_ssz, &exchange);
        try drainClient(&setup, &reply_ssz, &exchange);
    }
    try std.testing.expect(exchange.request_seen);
    try std.testing.expect(exchange.served);
    try std.testing.expect(exchange.done);
    try std.testing.expectEqual(@as(u32, 1), exchange.chunks);
    try std.testing.expect(exchange.failed == null);
    try std.testing.expectEqual(@as(usize, 0), setup.unclaimed);
    try std.testing.expectEqual(@as(u64, 1), setup.client.counters.requests_sent);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.requests_served);
    try std.testing.expectEqual(@as(u64, 1), setup.client.counters.chunks_received);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
}

test "reqresp completes ping and metadata round trips" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var ping_request: [8]u8 = undefined;
    std.mem.writeInt(u64, &ping_request, 41, .little);
    var ping_reply: [8]u8 = undefined;
    std.mem.writeInt(u64, &ping_reply, 42, .little);
    var ping_sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &ping_request, &ping_sink, .{}, setup.pair.now);

    var metadata_reply = [_]u8{0} ** 17;
    metadata_reply[0] = 8;
    metadata_reply[16] = 0x0f;
    var metadata_sink: [17]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .metadata_v2, &.{}, &metadata_sink, .{}, setup.pair.now);

    var pings = Exchange{};
    var metadatas = Exchange{};
    var rounds: usize = 0;
    while (rounds < 40 and !(pings.done and metadatas.done)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| switch (incoming.protocol) {
                .ping_v1 => {
                    try std.testing.expectEqualSlices(u8, &ping_request, incoming.bytes);
                    try setup.server.respond(incoming.request, &ping_reply, null, setup.pair.now);
                    try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
                    pings.request_seen = true;
                },
                .metadata_v2 => {
                    try std.testing.expectEqual(@as(usize, 0), incoming.bytes.len);
                    try setup.server.respond(incoming.request, &metadata_reply, null, setup.pair.now);
                    try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
                    metadatas.request_seen = true;
                },
                else => return error.TestUnexpectedResult,
            },
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                if (chunk.bytes.len == 8) {
                    try std.testing.expectEqualSlices(u8, &ping_reply, chunk.bytes);
                    pings.chunks += 1;
                } else {
                    try std.testing.expectEqualSlices(u8, &metadata_reply, chunk.bytes);
                    metadatas.chunks += 1;
                }
                try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
            },
            .done => |finished| {
                if (finished.chunks == 1 and pings.chunks == 1 and !pings.done) pings.done = true else metadatas.done = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(pings.request_seen and metadatas.request_seen);
    try std.testing.expect(pings.done and metadatas.done);
    try std.testing.expectEqual(@as(u32, 1), pings.chunks);
    try std.testing.expectEqual(@as(u32, 1), metadatas.chunks);
}

test "reqresp streams blocks by range chunks with fork context" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const request = ct.phase0.BeaconBlocksByRangeRequest.Type{ .start_slot = 100, .count = 3, .step = 1 };
    var request_ssz: [24]u8 = undefined;
    _ = ct.phase0.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_ssz);
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_range_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_range_v2, &request_ssz, sink, .{}, setup.pair.now);

    var blocks: [3][5_000]u8 = undefined;
    for (&blocks, 0..) |*block, which| {
        for (block, 0..) |*byte, index| byte.* = @truncate(index *% (which + 3) +% which);
    }
    var served_handle: ?reqresp.RequestHandle = null;
    var sent: u32 = 0;
    var received: u32 = 0;
    var done = false;
    var served = false;
    var rounds: usize = 0;
    while (rounds < 200 and !(done and served)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(Protocol.blocks_by_range_v2, incoming.protocol);
                try std.testing.expectEqualSlices(u8, &request_ssz, incoming.bytes);
                served_handle = incoming.request;
                try setup.server.respond(incoming.request, &blocks[0], .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now);
            },
            .chunk_sent => |progress| {
                sent = progress.chunks;
                if (sent < 3) {
                    try setup.server.respond(served_handle.?, &blocks[sent], .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now);
                } else {
                    try std.testing.expect(setup.server.finish(served_handle.?, setup.pair.now));
                }
            },
            .served => |finished| {
                try std.testing.expectEqual(@as(u32, 3), finished.chunks);
                served = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqual(@as(?@import("config").ForkSeq, .deneb), chunk.fork);
                try std.testing.expectEqualSlices(u8, &blocks[received], chunk.bytes);
                received += 1;
                try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
            },
            .done => |finished| {
                try std.testing.expectEqual(@as(u32, 3), finished.chunks);
                done = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done and served);
    try std.testing.expectEqual(@as(u32, 3), received);
    try std.testing.expectEqual(@as(u64, 3), setup.server.counters.chunks_sent);
}

test "reqresp rejects undersized sinks and stale handles" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var small: [8]u8 = undefined;
    const request_ssz = statusBytes(1);
    try std.testing.expectError(error.SinkTooSmall, setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        &small,
        .{},
        setup.pair.now,
    ));
    try std.testing.expectError(error.RequestTooLarge, setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .ping_v1,
        &request_ssz,
        &small,
        .{},
        setup.pair.now,
    ));
    const stale = reqresp.RequestHandle{ .index = 0, .generation = 99, .direction = .outbound };
    try std.testing.expect(!setup.client.consume(stale, setup.pair.now));
    try std.testing.expect(!setup.server.finish(.{ .index = 0, .generation = 99, .direction = .inbound }, setup.pair.now));
    try std.testing.expectEqual(@as(usize, 0), setup.client.errorMessage(stale).len);
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
}
