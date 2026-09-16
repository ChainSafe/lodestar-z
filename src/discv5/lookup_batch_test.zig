const std = @import("std");
const CallTable = @import("CallTable.zig");
const Transport = @import("Transport.zig");
const Engine = @import("Engine.zig");
const Lookup = @import("Lookup.zig");
const RoutingTable = @import("RoutingTable.zig");
const Sockets = @import("udp").Sockets;
const enr = @import("identity/enr.zig");
const lookup_batch = @import("lookup_batch.zig");
const message = @import("wire/message.zig");
const packet = @import("wire/packet.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

test "lookup batch rotates priority under one-call contention" {
    var network: Network = undefined;
    try network.init(1);
    defer network.deinit();
    const seeds_a = [_]RoutingTable.Entry{ network.seed(1), network.seed(2) };
    const seeds_b = [_]RoutingTable.Entry{ network.seed(3), network.seed(4) };
    var a: Lookup = undefined;
    var b: Lookup = undefined;
    var candidates_a: Lookup.Candidates = undefined;
    var candidates_b: Lookup.Candidates = undefined;
    try a.init(&candidates_a, network.transport.engine.localRecord().node_id, [_]u8{0} ** 32, &seeds_a, .dual);
    defer a.cancel(&network.transport.engine);
    try b.init(&candidates_b, network.transport.engine.localRecord().node_id, [_]u8{0} ** 32, &seeds_b, .dual);
    defer b.cancel(&network.transport.engine);
    const operations = [_]*Lookup{ &a, &b };
    var cursor = lookup_batch.Cursor{};
    var expired: [1]CallTable.Expired = undefined;

    for (0..4) |round| {
        const result = try lookup_batch.step(
            &network.transport,
            std.testing.io,
            &operations,
            &cursor,
            &expired,
        );
        try std.testing.expectEqual(@as(u16, 1), result.progress.started);
        const expected_owner = operations[round % 2];
        try std.testing.expectEqual(@as(usize, 1), expected_owner.waitingCount());
        try std.testing.expectEqual(@as(usize, 0), operations[(round + 1) % 2].waitingCount());
        try expected_owner.onFailure(&network.transport.engine, waitingCall(expected_owner));
    }
    try std.testing.expectEqual(@as(usize, 0), network.transport.engine.calls.count());
}

test "lookup batch preserves response and unrelated expiry after refill failure" {
    var network: Network = undefined;
    try network.init(3);
    defer network.deinit();
    const unrelated = network.seed(3);
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0xff}),
        .enr_sequence = 1,
    } };
    const unrelated_handle = try network.transport.engine.calls.begin(
        unrelated.peer,
        &unrelated.record.public_key,
        &request,
        0,
        1_000,
    );
    const seeds = [_]RoutingTable.Entry{ network.seed(1), network.seed(2) };
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    try operation.init(&candidates, network.transport.engine.localRecord().node_id, [_]u8{0} ** 32, &seeds, .dual);
    defer operation.cancel(&network.transport.engine);
    const request_id = try message.RequestId.init(&.{1});
    var buffer: [1_280]u8 = undefined;
    _ = (try operation.startNext(
        &network.transport.engine,
        &buffer,
        request_id,
        try Transport.monotonicMilliseconds(std.testing.io),
        &test_support.sealEntropy(1),
    )).?;
    network.transport.engine.calls.next_generations[2] = std.math.maxInt(u64);
    try network.sendNodes(seeds[0].peer.node_id, request_id);
    var expired: [3]CallTable.Expired = undefined;
    var cursor = lookup_batch.Cursor{};

    const result = try lookup_batch.step(
        &network.transport,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(error.GenerationExhausted, result.failure.?);
    try std.testing.expectEqual(@as(u16, 1), result.progress.responses);
    try std.testing.expectEqual(@as(?u16, 0), result.consumed);
    try std.testing.expectEqual(@as(usize, 1), result.transport.calls_expired);
    try std.testing.expectEqual(unrelated_handle, expired[0].handle);
    try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
    try std.testing.expectEqual(@as(u16, 1), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(usize, 0), network.transport.engine.calls.count());
}

test "lookup batch consumes expiry before reporting a transport fault" {
    var network: Network = undefined;
    try network.init(1);
    defer network.deinit();
    const seeds = [_]RoutingTable.Entry{ network.seed(1), network.seed(2) };
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    try operation.init(&candidates, network.transport.engine.localRecord().node_id, [_]u8{0} ** 32, &seeds, .dual);
    defer operation.cancel(&network.transport.engine);
    var buffer: [1_280]u8 = undefined;
    const started = (try operation.startNext(
        &network.transport.engine,
        &buffer,
        try message.RequestId.init(&.{1}),
        try Transport.monotonicMilliseconds(std.testing.io),
        &test_support.sealEntropy(1),
    )).?;
    network.transport.engine.calls.entries[started.call.handle.index].?.deadline_ms = 0;
    const Fault = struct {
        fn receive(_: ?*anyopaque, _: *std.Io.Batch, _: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
            return error.Canceled;
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.batchAwaitConcurrent = Fault.receive;
    const failed_io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try network.remote.sendTo(std.testing.io, @import("types.zig").Address.fromNetwork(network.transport.sockets.primary().address), &.{0xff}, @import("wire/constants.zig").packet_size_max);
    var expired: [1]CallTable.Expired = undefined;
    var cursor = lookup_batch.Cursor{};

    const result = try lookup_batch.step(
        &network.transport,
        failed_io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(error.Canceled, result.failure.?);
    try std.testing.expectEqual(error.Canceled, result.transport.failure.?);
    try std.testing.expectEqual(@as(u16, 1), result.progress.failures);
    try std.testing.expectEqual(@as(usize, 0), result.transport.calls_expired);
    try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
    try std.testing.expectEqual(@as(u16, 1), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(usize, 0), network.transport.engine.calls.count());
}

test "lookup batch consumes only owned failed-call events" {
    var network: Network = undefined;
    try network.init(1);
    defer network.deinit();
    const seed = network.seed(1);
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    var expired: [1]CallTable.Expired = undefined;
    var cursor = lookup_batch.Cursor{};
    try operation.init(&candidates, network.transport.engine.localRecord().node_id, [_]u8{0} ** 32, &.{seed}, .dual);
    defer operation.cancel(&network.transport.engine);

    for (0..2) |round| {
        var buffer: [1_280]u8 = undefined;
        const now_ms = try Transport.monotonicMilliseconds(std.testing.io);
        const request_id = try message.RequestId.init(&.{@intCast(round)});
        const entropy = test_support.sealEntropy(@intCast(round));
        const started = if (round == 0) (try operation.startNext(
            &network.transport.engine,
            &buffer,
            request_id,
            now_ms,
            &entropy,
        )).?.call else try network.transport.engine.startCall(
            &buffer,
            seed.peer,
            &seed.record,
            &.{ .ping = .{ .request_id = request_id, .enr_sequence = 1 } },
            now_ms,
            &entropy,
        );
        try network.challenge(buffer[0..started.packet_length]);
        const result = try lookup_batch.step(
            &network.transport,
            std.testing.io,
            &.{&operation},
            &cursor,
            &expired,
        );
        try std.testing.expectEqual(@as(?lookup_batch.Error, null), result.failure);
        try std.testing.expect(result.transport.event == .failed);
        try std.testing.expectEqual(started.handle, result.transport.event.failed.handle);
        try std.testing.expectEqual(error.InvalidPublicKey, result.transport.event.failed.reason);
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
        try std.testing.expectEqual(@as(usize, 0), network.transport.engine.calls.count());
    }
}

const Network = struct {
    remote: Sockets,
    transport: Transport,

    fn init(self: *Network, call_capacity: usize) !void {
        const loopback = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
        self.transport.sockets = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.transport.sockets.close(std.testing.io);
        self.remote = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.remote.close(std.testing.io);
        const key = try test_support.keyPair(0x11);
        const record = try enr.Record.create(&key, 1, @import("types.zig").Address.fromNetwork(self.transport.sockets.primary().address));
        try self.transport.init(std.testing.allocator, self.transport.sockets, key, record, .{ .poll_interval_ms = 1, .engine = .{
            .session_capacity = 8,
            .challenge_capacity = 4,
            .call_capacity = call_capacity,
            .request_timeout_ms = 100_000,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        } });
    }

    fn deinit(self: *Network) void {
        self.transport.deinit(std.testing.allocator, std.testing.io);
        self.remote.close(std.testing.io);
    }

    fn seed(self: *Network, id: u8) RoutingTable.Entry {
        const peer = types.Endpoint{
            .node_id = [_]u8{id} ** 32,
            .address = @import("types.zig").Address.fromNetwork(self.remote.primary().address),
        };
        test_support.installSession(&self.transport.engine, peer, 0x55);
        return .{
            .peer = peer,
            .record = test_support.fakeRecord(peer.node_id, peer.address, 1),
            .last_verified_ms = 0,
            .direction = .outgoing,
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
                .recipient_id = &self.transport.engine.localRecord().node_id,
                .nonce = &([_]u8{0x77} ** 12),
                .write_key = &([_]u8{0x55} ** 16),
                .plaintext = try response.encode(&plaintext),
            },
        });
        try self.remote.sendTo(std.testing.io, @import("types.zig").Address.fromNetwork(self.transport.sockets.primary().address), bytes, @import("wire/constants.zig").packet_size_max);
    }

    fn challenge(self: *Network, request: []const u8) !void {
        var scratch: packet.DecodeScratch = .{};
        const source_id = [_]u8{1} ** 32;
        const decoded = try packet.decode(request, &source_id, &scratch);
        var out: [1_280]u8 = undefined;
        const bytes = try packet.encodeWhoareyou(&out, .{
            .masking_iv = &([_]u8{0x33} ** 16),
            .recipient_id = &self.transport.engine.localRecord().node_id,
            .request_nonce = &decoded.static_header.nonce,
            .id_nonce = &([_]u8{0x44} ** 16),
            .enr_sequence = 0,
        }, null);
        try self.remote.sendTo(std.testing.io, @import("types.zig").Address.fromNetwork(self.transport.sockets.primary().address), bytes, @import("wire/constants.zig").packet_size_max);
    }
};

fn waitingCall(operation: *const Lookup) CallTable.Handle {
    for (operation.candidates[0..operation.candidateCount()]) |*candidate| {
        if (candidate.state == .waiting) return candidate.state.waiting;
    }
    unreachable;
}
