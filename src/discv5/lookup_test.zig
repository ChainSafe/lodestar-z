const std = @import("std");
const Engine = @import("Engine.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const Lookup = @import("Lookup.zig");
const message = @import("wire/message.zig");
const RoutingTable = @import("RoutingTable.zig");
const SessionStore = @import("SessionStore.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

const address4 = test_support.address4;
const fakeRecord = test_support.fakeRecord;
const installSession = test_support.installSession;
const keyPair = test_support.keyPair;
const sealEntropy = test_support.sealEntropy;

test "lookup requests the target distance and adjacent buckets" {
    const zero = [_]u8{0} ** 32;
    var distance_255 = zero;
    distance_255[0] = 0x40;
    try std.testing.expectEqualSlices(
        u16,
        &.{ 255, 256, 254 },
        &Lookup.requestDistances(&zero, &distance_255),
    );
    try std.testing.expectEqualSlices(
        u16,
        &.{ 0, 1, 2 },
        &Lookup.requestDistances(&zero, &zero),
    );
    var distance_256 = zero;
    distance_256[0] = 0x80;
    try std.testing.expectEqualSlices(
        u16,
        &.{ 256, 255, 254 },
        &Lookup.requestDistances(&zero, &distance_256),
    );
}

test "lookup uses the call table for bounded parallel queries" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    var seeds: [4]RoutingTable.Entry = undefined;
    for (&seeds, 0..) |*seed, index| {
        seed.* = fakeEntry(@intCast(index + 1));
        installSession(&core, seed.peer, 0x55);
    }
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        core.localRecord().node_id,
        [_]u8{0} ** 32,
        &seeds,
    );

    var packet_buffer: [1_280]u8 = undefined;
    var started: [4]Lookup.Started = undefined;
    for (0..3) |index| {
        started[index] = (try operation.startNext(
            &core,
            &packet_buffer,
            try message.RequestId.init(&.{@intCast(index + 1)}),
            1,
            &sealEntropy(@intCast(index + 1)),
        )).?;
        try std.testing.expect(operation.knownRecord(started[index].call.handle) != null);
    }
    try std.testing.expectEqual(Lookup.parallelism, operation.waitingCount());
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{9}),
        1,
        &sealEntropy(9),
    )) == null);

    try operation.onFailure(&core, started[0].call.handle);
    started[3] = (try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{4}),
        2,
        &sealEntropy(4),
    )).?;
    try std.testing.expectEqual(Lookup.parallelism, operation.waitingCount());
    for (1..4) |index| try completeNodes(
        &core,
        &operation,
        started[index],
        try message.RequestId.init(&.{@intCast(index + 1)}),
        &.{},
        3 + index,
    );
    try std.testing.expectEqual(@as(usize, 0), operation.waitingCount());
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{10}),
        10,
        &sealEntropy(10),
    )) == null);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(Lookup.FinishReason.exhausted, operation.finishReason().?);
    try std.testing.expectEqual(@as(u16, 4), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(u32, 0), operation.statistics().capacity_drops);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());

    var results: [Lookup.result_max]enr.Record = undefined;
    try std.testing.expectEqual(@as(usize, 3), operation.results(&results).len);
}

test "lookup skips the busy closest peer and retries it after release" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const seeds = [_]RoutingTable.Entry{ fakeEntry(1), fakeEntry(2), fakeEntry(3) };
    for (&seeds) |*seed| installSession(&core, seed.peer, 0x55);
    var packet_buffer: [1_280]u8 = undefined;
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{1}),
        .enr_sequence = 1,
    } };
    const unrelated = try core.startCall(
        &packet_buffer,
        seeds[0].peer,
        &seeds[0].record,
        &request,
        1,
        &sealEntropy(1),
    );
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    try operation.init(&candidates, core.localRecord().node_id, [_]u8{0} ** 32, &seeds);
    defer operation.cancel(&core);

    for (2..4) |id| {
        const started = (try operation.startNext(
            &core,
            &packet_buffer,
            try message.RequestId.init(&.{@intCast(id)}),
            2,
            &sealEntropy(@intCast(id)),
        )).?;
        try std.testing.expectEqual(nodeId(@intCast(id)), started.peer.node_id);
        try operation.onFailure(&core, started.call.handle);
    }
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{4}),
        3,
        &sealEntropy(4),
    )) == null);
    try std.testing.expect(!operation.isFinished());
    try std.testing.expect(core.cancelCall(unrelated.handle));
    const retried = (try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{5}),
        4,
        &sealEntropy(5),
    )).?;
    try std.testing.expectEqual(nodeId(1), retried.peer.node_id);
    try std.testing.expectEqual(@as(usize, 1), core.calls.count());
}

test "lookup rejects relayed private and low-port candidates" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const seed = fakeEntry(1);
    installSession(&core, seed.peer, 0x55);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        core.localRecord().node_id,
        [_]u8{0} ** 32,
        &.{seed},
    );

    var packet_buffer: [1_280]u8 = undefined;
    const request_id = try message.RequestId.init(&.{1});
    const started = (try operation.startNext(
        &core,
        &packet_buffer,
        request_id,
        1,
        &sealEntropy(1),
    )).?;
    var records = [_]enr.Record{
        fakeRecord(nodeId(20), address4(198, 51, 100, 20, 9_020), 1),
        fakeRecord(nodeId(21), address4(10, 0, 0, 21, 9_021), 1),
        fakeRecord(nodeId(22), address4(198, 51, 100, 22, 80), 1),
    };
    try completeNodes(
        &core,
        &operation,
        started,
        request_id,
        &records,
        2,
    );
    try std.testing.expectEqual(@as(usize, 2), operation.candidateCount());

    const next = (try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{2}),
        3,
        &sealEntropy(2),
    )).?;
    try std.testing.expectEqual(nodeId(20), next.peer.node_id);
    operation.cancel(&core);
    try std.testing.expectEqual(Lookup.FinishReason.cancelled, operation.finishReason().?);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "lookup stops after the closest sixteen successful peers" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    var seeds: [Lookup.result_max]RoutingTable.Entry = undefined;
    for (&seeds, 0..) |*seed, index| {
        seed.* = fakeEntry(@intCast(index + 1));
        installSession(&core, seed.peer, 0x55);
    }
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        core.localRecord().node_id,
        [_]u8{0} ** 32,
        &seeds,
    );

    var packet_buffer: [1_280]u8 = undefined;
    var farther_id = [_]u8{0xff} ** 32;
    farther_id[31] = 1;
    const farther = fakeRecord(farther_id, address4(198, 51, 100, 40, 9_040), 1);
    for (0..Lookup.result_max) |index| {
        const request_id = try message.RequestId.init(&.{@intCast(index + 1)});
        const started = (try operation.startNext(
            &core,
            &packet_buffer,
            request_id,
            @intCast(index + 1),
            &sealEntropy(@intCast(index + 1)),
        )).?;
        const records: []const enr.Record = if (index == 0) &.{farther} else &.{};
        try completeNodes(
            &core,
            &operation,
            started,
            request_id,
            records,
            @intCast(index + 2),
        );
    }
    try std.testing.expectEqual(Lookup.result_max + 1, operation.candidateCount());
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{20}),
        20,
        &sealEntropy(20),
    )) == null);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(Lookup.FinishReason.converged, operation.finishReason().?);
    var results: [Lookup.result_max + 1]enr.Record = undefined;
    const selected = operation.results(&results);
    try std.testing.expectEqual(Lookup.result_max, selected.len);
    for (selected, 1..) |record, id| try std.testing.expectEqual(
        nodeId(@intCast(id)),
        record.node_id,
    );
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "lookup initialization cleans up after an invalid seed" {
    var seed = fakeEntry(1);
    seed.record.node_id = nodeId(2);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try std.testing.expectError(Lookup.Error.InvalidSeed, operation.init(
        &operation_candidates,
        [_]u8{0} ** 32,
        [_]u8{0xff} ** 32,
        &.{seed},
    ));
}

test "empty lookup finishes without creating a call" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        core.localRecord().node_id,
        [_]u8{0} ** 32,
        &.{},
    );
    var packet_buffer: [1_280]u8 = undefined;
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{1}),
        1,
        &sealEntropy(1),
    )) == null);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(Lookup.FinishReason.exhausted, operation.finishReason().?);
    try std.testing.expectEqual(@as(u16, 0), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "lookup reports candidate budget exhaustion after dropping a closer peer" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    var operation: Lookup = undefined;
    var candidates: Lookup.Candidates = undefined;
    const seed = budgetEntry(272);
    try operation.init(&candidates, core.localRecord().node_id, [_]u8{0} ** 32, &.{seed});
    var packet_buffer: [1_280]u8 = undefined;

    for (0..272) |index| {
        const current = budgetEntry(@intCast(272 - index));
        installSession(&core, current.peer, 0x55);
        const request_id = try message.RequestId.init(&.{ @intCast(index >> 8), @truncate(index) });
        const started = (try operation.startNext(
            &core,
            &packet_buffer,
            request_id,
            index * 2,
            &sealEntropy(@truncate(index)),
        )).?;
        try std.testing.expectEqual(current.peer.node_id, started.peer.node_id);
        const next = budgetEntry(@intCast(271 - index));
        try completeNodes(
            &core,
            &operation,
            started,
            request_id,
            &.{ next.record, seed.record },
            index * 2 + 1,
        );
    }
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{0xff}),
        600,
        &sealEntropy(1),
    )) == null);
    try std.testing.expectEqual(@as(usize, 272), operation.candidateCount());
    try std.testing.expectEqual(@as(u16, 272), operation.statistics().queries_started);
    try std.testing.expectEqual(@as(u32, 1), operation.statistics().capacity_drops);
    try std.testing.expectEqual(Lookup.FinishReason.budget_exhausted, operation.finishReason().?);
    var records: [16]enr.Record = undefined;
    try std.testing.expectEqual(@as(usize, 16), operation.results(&records).len);
    try std.testing.expectEqual(budgetEntry(1).peer.node_id, records[0].node_id);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

fn budgetEntry(id: u16) RoutingTable.Entry {
    var entry = fakeEntry(1);
    std.mem.writeInt(u16, entry.peer.node_id[30..32], id, .big);
    entry.record.node_id = entry.peer.node_id;
    return entry;
}

fn initEngine() !Engine {
    const key = try keyPair(0x11);
    const local_record = try enr.Record.create(
        &key,
        1,
        address4(203, 0, 113, 1, 9_000),
    );
    var core: Engine = undefined;
    try core.initWithConfig(std.testing.allocator, key, local_record, .{
        .session_capacity = 8,
        .challenge_capacity = 4,
        .call_capacity = 8,
        .request_timeout_ms = 100,
        .challenge_timeout_ms = 100,
        .session_idle_timeout_ms = 1_000,
    });
    return core;
}

fn completeNodes(
    core: *Engine,
    operation: *Lookup,
    started: Lookup.Started,
    request_id: message.RequestId,
    records: []const enr.Record,
    now_ms: u64,
) !void {
    var node_ids: [Lookup.result_max]types.NodeId = undefined;
    for (records, node_ids[0..records.len]) |record, *node_id| node_id.* = record.node_id;
    const raw_records = [_][]const u8{};
    const response_message = message.Message{ .nodes = .{
        .request_id = request_id,
        .total = 1,
        .enrs = &raw_records,
    } };
    const handle = try core.calls.match(started.peer, &response_message, now_ms);
    var nonce = [_]u8{0} ** 12;
    std.mem.writeInt(u64, nonce[0..8], now_ms, .big);
    const matched = try core.calls.accept(handle, &response_message, node_ids[0..0], &nonce);
    var response = Engine.AuthenticatedResponse{
        .peer = started.peer,
        .matched = matched.matched,
        .record = null,
        .node_records = records,
    };
    try operation.onResponse(core, &response, now_ms);
}

fn fakeEntry(id: u8) RoutingTable.Entry {
    const peer = types.Endpoint{
        .node_id = nodeId(id),
        .address = address4(203, id, 1, 1, 9_000 + @as(u16, id)),
    };
    return .{
        .peer = peer,
        .record = fakeRecord(peer.node_id, peer.address, 1),
        .last_verified_ms = 0,
    };
}

fn nodeId(id: u8) types.NodeId {
    var node_id = [_]u8{0} ** 32;
    node_id[0] = 0x80;
    node_id[31] = id;
    return node_id;
}

test "lookup confirmed result retains global IPv6 provenance over private IPv4 record preference" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const key = try crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{2}));
    const public_key = crypto.compressedPublicKey(&key);
    const ip4: [4]u8 = .{ 10, 0, 0, 1 };
    const ip6: [16]u8 = .{ 0x26, 0x06, 0x47, 0x00 } ++ .{0} ** 11 ++ .{1};
    const record = try enr.Record.createFields(&key, 1, &.{
        .{ .key = "id", .value = .{ .bytes = "v4" } },
        .{ .key = "ip", .value = .{ .bytes = &ip4 } },
        .{ .key = "ip6", .value = .{ .bytes = &ip6 } },
        .{ .key = "quic", .value = .{ .uint = 9001 } },
        .{ .key = "secp256k1", .value = .{ .bytes = &public_key } },
        .{ .key = "udp", .value = .{ .uint = 9000 } },
        .{ .key = "udp6", .value = .{ .uint = 9000 } },
    });
    const source = types.Endpoint{ .node_id = record.node_id, .address = .{ .ip6 = .{ .octets = ip6, .port = 9000 } } };
    const target = address4(10, 0, 0, 1, 9001);
    _ = try core.confirmPeer(&source, &record, 0);
    installSession(&core, source, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var operation: Lookup = undefined;
    try operation.init(&candidates, core.localRecord().node_id, record.node_id, &.{core.peerRecord(&record.node_id).?});
    defer operation.cancel(&core);
    var output: [1280]u8 = undefined;
    const request_id = try message.RequestId.init(&.{1});
    const started = (try operation.startNext(&core, &output, request_id, 1, &sealEntropy(1))).?;
    try std.testing.expectEqualDeep(source, started.peer);
    try completeNodes(&core, &operation, started, request_id, &.{}, 2);
    try std.testing.expect((try operation.startNext(&core, &output, try message.RequestId.init(&.{2}), 3, &sealEntropy(2))) == null);
    try std.testing.expect(operation.isFinished());
    var results: [Lookup.result_max]Lookup.Confirmed = undefined;
    const confirmed = operation.confirmedResults(&results);
    try std.testing.expectEqual(@as(usize, 1), confirmed.len);
    try std.testing.expectEqualDeep(source, confirmed[0].peer);
    try std.testing.expectEqualSlices(u8, record.slice(), confirmed[0].record.slice());
    try std.testing.expect(!RoutingTable.relayAllowed(confirmed[0].peer.address, target));
    try std.testing.expect(RoutingTable.relayAllowed(confirmed[0].record.endpoint().?, target));
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}
