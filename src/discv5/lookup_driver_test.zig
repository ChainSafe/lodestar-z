const std = @import("std");
const CallTable = @import("CallTable.zig");
const Driver = @import("Driver.zig");
const Engine = @import("Engine.zig");
const Lookup = @import("Lookup.zig");
const RoutingTable = @import("RoutingTable.zig");
const Udp = @import("Udp.zig");
const enr = @import("identity/enr.zig");
const lookup_driver = @import("lookup_driver.zig");
const message = @import("wire/message.zig");
const packet = @import("wire/packet.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

test "lookup driver rotates priority under one-call contention" {
    var network: Network = undefined;
    try network.init(1);
    defer network.deinit();
    const seeds_a = [_]RoutingTable.Entry{ network.seed(1), network.seed(2) };
    const seeds_b = [_]RoutingTable.Entry{ network.seed(3), network.seed(4) };
    var a: Lookup = undefined;
    var b: Lookup = undefined;
    var candidates_a: Lookup.Candidates = undefined;
    var candidates_b: Lookup.Candidates = undefined;
    try a.init(&candidates_a, network.core.localRecord().node_id, [_]u8{0} ** 32, &seeds_a);
    defer a.cancel(&network.core);
    try b.init(&candidates_b, network.core.localRecord().node_id, [_]u8{0} ** 32, &seeds_b);
    defer b.cancel(&network.core);
    const operations = [_]*Lookup{ &a, &b };
    var cursor = lookup_driver.Cursor{};
    var expired: [1]CallTable.Expired = undefined;

    for (0..4) |round| {
        const result = try lookup_driver.step(
            &network.driver,
            std.testing.io,
            &operations,
            &cursor,
            &expired,
        );
        try std.testing.expectEqual(@as(u16, 1), result.progress.started);
        const expected_owner = operations[round % 2];
        try std.testing.expectEqual(@as(usize, 1), expected_owner.waitingCount());
        try std.testing.expectEqual(@as(usize, 0), operations[(round + 1) % 2].waitingCount());
        try expected_owner.onFailure(&network.core, waitingCall(expected_owner));
    }
    try std.testing.expectEqual(@as(usize, 0), network.core.calls.count());
}

test "lookup driver preserves response and unrelated expiry after refill failure" {
    var network: Network = undefined;
    try network.init(3);
    defer network.deinit();
    const unrelated = network.seed(3);
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0xff}),
        .enr_sequence = 1,
    } };
    const unrelated_handle = try network.core.calls.begin(
        unrelated.peer,
        &unrelated.record.public_key,
        &request,
        0,
        1_000,
        .caller,
    );
    const seeds = [_]RoutingTable.Entry{ network.seed(1), network.seed(2) };
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    try operation.init(&candidates, network.core.localRecord().node_id, [_]u8{0} ** 32, &seeds);
    defer operation.cancel(&network.core);
    const request_id = try message.RequestId.init(&.{1});
    var buffer: [1_280]u8 = undefined;
    _ = (try operation.startNext(
        &network.core,
        &buffer,
        request_id,
        try Driver.monotonicMilliseconds(std.testing.io),
        &test_support.sealEntropy(1),
    )).?;
    network.core.calls.next_generations[2] = std.math.maxInt(u64);
    try network.sendNodes(seeds[0].peer.node_id, request_id);
    var expired: [3]CallTable.Expired = undefined;
    var cursor = lookup_driver.Cursor{};

    const result = try lookup_driver.step(
        &network.driver,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(error.GenerationExhausted, result.failure.?);
    try std.testing.expectEqual(@as(u16, 1), result.progress.responses);
    try std.testing.expectEqual(@as(?u16, 0), result.consumed);
    try std.testing.expectEqual(@as(usize, 1), result.driver.calls_expired);
    try std.testing.expectEqual(unrelated_handle, expired[0].handle);
    try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
    try std.testing.expectEqual(@as(u16, 1), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(usize, 0), network.core.calls.count());
}

test "lookup driver consumes expiry before reporting a driver fault" {
    var network: Network = undefined;
    try network.init(1);
    defer network.deinit();
    const seeds = [_]RoutingTable.Entry{ network.seed(1), network.seed(2) };
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    try operation.init(&candidates, network.core.localRecord().node_id, [_]u8{0} ** 32, &seeds);
    defer operation.cancel(&network.core);
    var buffer: [1_280]u8 = undefined;
    const started = (try operation.startNext(
        &network.core,
        &buffer,
        try message.RequestId.init(&.{1}),
        try Driver.monotonicMilliseconds(std.testing.io),
        &test_support.sealEntropy(1),
    )).?;
    network.core.calls.entries[started.call.handle.index].?.deadline_ms = 0;
    network.local.next_generation = std.math.maxInt(u64);
    try network.remote.send(std.testing.io, network.local.localAddress(), &.{0xff});
    var expired: [1]CallTable.Expired = undefined;
    var cursor = lookup_driver.Cursor{};

    const result = try lookup_driver.step(
        &network.driver,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(error.GenerationExhausted, result.failure.?);
    try std.testing.expectEqual(error.GenerationExhausted, result.driver.failure.?);
    try std.testing.expectEqual(@as(u16, 1), result.progress.failures);
    try std.testing.expectEqual(@as(usize, 0), result.driver.calls_expired);
    try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
    try std.testing.expectEqual(@as(u16, 1), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(usize, 0), network.core.calls.count());
}

test "lookup driver consumes only owned failed-call events" {
    var network: Network = undefined;
    try network.init(1);
    defer network.deinit();
    const seed = network.seed(1);
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    var expired: [1]CallTable.Expired = undefined;
    var cursor = lookup_driver.Cursor{};
    try operation.init(&candidates, network.core.localRecord().node_id, [_]u8{0} ** 32, &.{seed});
    defer operation.cancel(&network.core);

    for (0..2) |round| {
        var buffer: [1_280]u8 = undefined;
        const now_ms = try Driver.monotonicMilliseconds(std.testing.io);
        const request_id = try message.RequestId.init(&.{@intCast(round)});
        const entropy = test_support.sealEntropy(@intCast(round));
        const started = if (round == 0) (try operation.startNext(
            &network.core,
            &buffer,
            request_id,
            now_ms,
            &entropy,
        )).?.call else try network.core.startCall(
            &buffer,
            seed.peer,
            &seed.record,
            &.{ .ping = .{ .request_id = request_id, .enr_sequence = 1 } },
            now_ms,
            &entropy,
        );
        try network.challenge(buffer[0..started.packet_length]);
        const result = try lookup_driver.step(
            &network.driver,
            std.testing.io,
            &.{&operation},
            &cursor,
            &expired,
        );
        try std.testing.expectEqual(@as(?lookup_driver.Error, null), result.failure);
        try std.testing.expect(result.driver.event == .failed);
        try std.testing.expectEqual(started.handle, result.driver.event.failed.handle);
        try std.testing.expectEqual(error.InvalidPublicKey, result.driver.event.failed.reason);
        if (round == 0) {
            try std.testing.expectEqual(@as(?u16, 0), result.consumed);
            try std.testing.expectEqual(@as(u16, 1), result.progress.failures);
            try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
            try std.testing.expectEqual(Lookup.FinishReason.exhausted, operation.finishReason().?);
        } else {
            try std.testing.expectEqual(@as(?u16, null), result.consumed);
            try std.testing.expectEqual(@as(u16, 0), result.progress.failures);
            try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
        }
        try std.testing.expectEqual(@as(usize, 0), network.core.calls.count());
    }
}

const Network = struct {
    local: Udp,
    remote: Udp,
    core: Engine,
    driver: Driver,

    fn init(self: *Network, call_capacity: usize) !void {
        const loopback = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
        self.local = try Udp.bind(std.testing.io, loopback);
        errdefer self.local.close(std.testing.io);
        self.remote = try Udp.bind(std.testing.io, loopback);
        errdefer self.remote.close(std.testing.io);
        const key = try test_support.keyPair(0x11);
        const record = try enr.Record.create(&key, 1, self.local.localAddress());
        try self.core.initWithConfig(std.testing.allocator, key, record, .{
            .session_capacity = 8,
            .challenge_capacity = 4,
            .call_capacity = call_capacity,
            .request_timeout_ms = 100_000,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        });
        errdefer self.core.deinit(std.testing.allocator);
        self.driver = try Driver.initWithConfig(
            &self.core,
            &self.local,
            .{ .poll_interval_ms = 1 },
        );
    }

    fn deinit(self: *Network) void {
        self.core.deinit(std.testing.allocator);
        self.remote.close(std.testing.io);
        self.local.close(std.testing.io);
    }

    fn seed(self: *Network, id: u8) RoutingTable.Entry {
        const peer = types.Endpoint{
            .node_id = [_]u8{id} ** 32,
            .address = self.remote.localAddress(),
        };
        test_support.installSession(&self.core, peer, 0x55);
        return .{
            .peer = peer,
            .record = test_support.fakeRecord(peer.node_id, peer.address, 1),
            .last_verified_ms = 0,
        };
    }

    fn sendNodes(self: *Network, source_id: types.NodeId, request_id: message.RequestId) !void {
        const response = message.Message{ .nodes = .{
            .request_id = request_id,
            .total = 1,
            .enrs = &.{},
        } };
        var plaintext: [1_000]u8 = undefined;
        var out: [1_280]u8 = undefined;
        const bytes = try packet.encodeOrdinary(&out, .{
            .source_id = &source_id,
            .packet = .{
                .masking_iv = &([_]u8{0x22} ** 16),
                .recipient_id = &self.core.localRecord().node_id,
                .nonce = &([_]u8{0x77} ** 12),
                .write_key = &([_]u8{0x55} ** 16),
                .plaintext = try response.encode(&plaintext),
            },
        });
        try self.remote.send(std.testing.io, self.local.localAddress(), bytes);
    }

    fn challenge(self: *Network, request: []const u8) !void {
        var scratch: packet.DecodeScratch = .{};
        const source_id = [_]u8{1} ** 32;
        const decoded = try packet.decode(request, &source_id, &scratch);
        var out: [1_280]u8 = undefined;
        const bytes = try packet.encodeWhoareyou(&out, .{
            .masking_iv = &([_]u8{0x33} ** 16),
            .recipient_id = &self.core.localRecord().node_id,
            .request_nonce = &decoded.static_header.nonce,
            .id_nonce = &([_]u8{0x44} ** 16),
            .enr_sequence = 0,
        }, null);
        try self.remote.send(std.testing.io, self.local.localAddress(), bytes);
    }
};

fn waitingCall(operation: *const Lookup) CallTable.Handle {
    for (operation.candidates[0..operation.candidateCount()]) |*candidate| {
        if (candidate.state == .waiting) return candidate.state.waiting;
    }
    unreachable;
}
