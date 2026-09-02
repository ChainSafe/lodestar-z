const std = @import("std");
const engine = @import("engine.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const lookup = @import("lookup.zig");
const message = @import("wire/message.zig");
const routing = @import("routing.zig");
const session = @import("session.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

test "lookup requests the target distance and adjacent buckets" {
    const zero = [_]u8{0} ** 32;
    var distance_255 = zero;
    distance_255[0] = 0x40;
    try std.testing.expectEqualSlices(
        u16,
        &.{ 255, 256, 254 },
        &lookup.requestDistances(&zero, &distance_255),
    );
    try std.testing.expectEqualSlices(
        u16,
        &.{ 0, 1, 2 },
        &lookup.requestDistances(&zero, &zero),
    );
    var distance_256 = zero;
    distance_256[0] = 0x80;
    try std.testing.expectEqualSlices(
        u16,
        &.{ 256, 255, 254 },
        &lookup.requestDistances(&zero, &distance_256),
    );
}

test "lookup uses the call table for bounded parallel queries" {
    var core = try initEngine();
    defer core.deinit();
    var seeds: [4]routing.Entry = undefined;
    for (&seeds, 0..) |*seed, index| {
        seed.* = fakeEntry(@intCast(index + 1));
        installSession(&core, seed.peer);
    }
    var operation: lookup.Lookup = undefined;
    var operation_candidates: lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        core.localRecord().node_id,
        [_]u8{0} ** 32,
        &seeds,
    );

    var packet_buffer: [1_280]u8 = undefined;
    var started: [4]lookup.Started = undefined;
    for (0..3) |index| {
        started[index] = (try operation.startNext(
            &core,
            &packet_buffer,
            try message.RequestId.init(&.{@intCast(index + 1)}),
            1,
            &startEntropy(@intCast(index + 1)),
        )).?;
        try std.testing.expect(operation.knownRecord(started[index].call.handle) != null);
    }
    try std.testing.expectEqual(lookup.parallelism, operation.waitingCount());
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{9}),
        1,
        &startEntropy(9),
    )) == null);

    try operation.onFailure(&core, started[0].call.handle);
    started[3] = (try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{4}),
        2,
        &startEntropy(4),
    )).?;
    try std.testing.expectEqual(lookup.parallelism, operation.waitingCount());
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
        &startEntropy(10),
    )) == null);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());

    var results: [lookup.result_max]enr.Record = undefined;
    try std.testing.expectEqual(@as(usize, 3), operation.results(&results).len);
}

test "lookup rejects relayed private and low-port candidates" {
    var core = try initEngine();
    defer core.deinit();
    const seed = fakeEntry(1);
    installSession(&core, seed.peer);
    var operation: lookup.Lookup = undefined;
    var operation_candidates: lookup.Candidates = undefined;
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
        &startEntropy(1),
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
        &startEntropy(2),
    )).?;
    try std.testing.expectEqual(nodeId(20), next.peer.node_id);
    operation.cancel(&core);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "lookup stops after the closest sixteen successful peers" {
    var core = try initEngine();
    defer core.deinit();
    var seeds: [lookup.result_max]routing.Entry = undefined;
    for (&seeds, 0..) |*seed, index| {
        seed.* = fakeEntry(@intCast(index + 1));
        installSession(&core, seed.peer);
    }
    var operation: lookup.Lookup = undefined;
    var operation_candidates: lookup.Candidates = undefined;
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
    for (0..lookup.result_max) |index| {
        const request_id = try message.RequestId.init(&.{@intCast(index + 1)});
        const started = (try operation.startNext(
            &core,
            &packet_buffer,
            request_id,
            @intCast(index + 1),
            &startEntropy(@intCast(index + 1)),
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
    try std.testing.expectEqual(lookup.result_max + 1, operation.candidateCount());
    try std.testing.expect((try operation.startNext(
        &core,
        &packet_buffer,
        try message.RequestId.init(&.{20}),
        20,
        &startEntropy(20),
    )) == null);
    try std.testing.expect(operation.isFinished());
    var results: [lookup.result_max + 1]enr.Record = undefined;
    const selected = operation.results(&results);
    try std.testing.expectEqual(lookup.result_max, selected.len);
    for (selected, 1..) |record, id| try std.testing.expectEqual(nodeId(@intCast(id)), record.node_id);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "lookup initialization cleans up after an invalid seed" {
    var seed = fakeEntry(1);
    seed.record.node_id = nodeId(2);
    var operation: lookup.Lookup = undefined;
    var operation_candidates: lookup.Candidates = undefined;
    try std.testing.expectError(lookup.Error.InvalidSeed, operation.init(
        &operation_candidates,
        [_]u8{0} ** 32,
        [_]u8{0xff} ** 32,
        &.{seed},
    ));
}

test "empty lookup finishes without creating a call" {
    var core = try initEngine();
    defer core.deinit();
    var operation: lookup.Lookup = undefined;
    var operation_candidates: lookup.Candidates = undefined;
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
        &startEntropy(1),
    )) == null);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

fn initEngine() !engine.Engine {
    const key = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const local_record = try test_support.buildRecord(
        &key,
        1,
        address4(203, 0, 113, 1, 9_000),
    );
    var core: engine.Engine = undefined;
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
    core: *engine.Engine,
    operation: *lookup.Lookup,
    started: lookup.Started,
    request_id: message.RequestId,
    records: []const enr.Record,
    now_ms: u64,
) !void {
    var node_ids: [lookup.result_max]types.NodeId = undefined;
    for (records, node_ids[0..records.len]) |record, *node_id| node_id.* = record.node_id;
    const raw_records = [_][]const u8{};
    const response_message = message.Message{ .nodes = .{
        .request_id = request_id,
        .total = 1,
        .enrs = &raw_records,
    } };
    const handle = try core.calls.match(started.peer, &response_message, now_ms);
    const matched = try core.calls.accept(handle, &response_message, node_ids[0..0]);
    var response = engine.AuthenticatedResponse{
        .peer = started.peer,
        .matched = matched.matched,
        .record = null,
        .node_records = records,
    };
    try operation.onResponse(core, &response, now_ms);
}

fn fakeEntry(id: u8) routing.Entry {
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

fn fakeRecord(node_id: types.NodeId, endpoint: types.Address, sequence: u64) enr.Record {
    var record = std.mem.zeroes(enr.Record);
    record.node_id = node_id;
    record.sequence = sequence;
    switch (endpoint) {
        .ip4 => |value| {
            record.ip4 = value.octets;
            record.udp = value.port;
        },
        .ip6 => |value| {
            record.ip6 = value.octets;
            record.udp6 = value.port;
        },
    }
    return record;
}

fn nodeId(id: u8) types.NodeId {
    var node_id = [_]u8{0} ** 32;
    node_id[0] = 0x80;
    node_id[31] = id;
    return node_id;
}

fn installSession(core: *engine.Engine, peer: types.Endpoint) void {
    const key = [_]u8{0x55} ** 16;
    const active = session.Session{ .read_key = key, .write_key = key };
    core.channel.sessions.install(peer, &active, 0);
}

fn startEntropy(seed: u8) engine.StartEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce = [_]u8{seed +% 1} ** 12,
        .nonce_tail = [_]u8{seed +% 2} ** 8,
        .sessionless_key = [_]u8{seed +% 3} ** 16,
    };
}

fn address4(a: u8, b: u8, c: u8, d: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ a, b, c, d }, .port = port } };
}
