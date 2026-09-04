const std = @import("std");
const CallTable = @import("CallTable.zig");
const Engine = @import("Engine.zig");
const enr = @import("identity/enr.zig");
const Lookup = @import("Lookup.zig");
const Maintenance = @import("Maintenance.zig");
const message = @import("wire/message.zig");
const test_support = @import("test_support.zig");

const sealEntropy = test_support.sealEntropy;

test "maintenance probes a quiet partial table on its explicit timer and retries only twice" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const remote = try record(2, 1);
    const peer = test_support.endpoint(&remote);
    _ = try core.confirmPeer(&peer, &remote, 0);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    try std.testing.expectEqual(@as(?u64, 10), controller.nextDeadlineMs());
    try std.testing.expect((try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{1}),
        9,
        &sealEntropy(1),
    )) == null);
    const first = (try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{1}),
        10,
        &sealEntropy(1),
    )).?;
    try std.testing.expectEqual(peer, first.peer);
    try std.testing.expectEqual(@as(usize, 1), core.calls.count());
    var expired: [4]CallTable.Expired = undefined;
    const tick = core.tick(110, &expired);
    try std.testing.expectEqual(@as(usize, 1), tick.calls);
    try std.testing.expect(controller.onFailure(&core, expired[0].handle, 110, .expired));
    try std.testing.expectEqual(@as(?u64, 115), controller.nextDeadlineMs());
    const retry = (try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{2}),
        115,
        &sealEntropy(2),
    )).?;
    _ = core.tick(215, &expired);
    try std.testing.expect(controller.onFailure(&core, retry.call.handle, 215, .expired));
    try std.testing.expectEqual(@as(usize, 0), core.peerCount());
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "maintenance preserves unrelated failures and local send failure retains peer" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const remote = try record(2, 1);
    const peer = test_support.endpoint(&remote);
    _ = try core.confirmPeer(&peer, &remote, 0);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const first = (try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{1}),
        10,
        &sealEntropy(1),
    )).?;
    var unrelated = first.call.handle;
    unrelated.generation += 1;
    try std.testing.expect(!controller.onFailure(&core, unrelated, 11, .expired));
    try std.testing.expect(controller.onFailure(&core, first.call.handle, 11, .local));
    try std.testing.expectEqual(@as(usize, 1), core.peerCount());
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

fn testConfig() Maintenance.Config {
    return .{
        .probe_interval_ms = 10,
        .stale_after_ms = 10,
        .refresh_interval_ms = 1_000,
        .bootstrap_interval_ms = 1_000,
        .discovery_stall_ms = 1_000,
        .retry_interval_ms = 5,
    };
}

fn record(seed: u8, sequence: u64) !enr.Record {
    const key = try test_support.keyPair(seed);
    return enr.Record.create(
        &key,
        sequence,
        test_support.address4(203, seed, 1, 1, 9_000 + @as(u16, seed)),
    );
}

fn initEngine() !Engine {
    const key = try test_support.keyPair(1);
    const local_record = try record(1, 1);
    var core: Engine = undefined;
    try core.initWithConfig(std.testing.allocator, key, local_record, test_support.engineConfig());
    return core;
}

test "maintenance retrieves a newer self ENR from authenticated PONG through FINDNODE zero" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const old_record = try record(2, 1);
    const newer_record = try record(2, 2);
    const peer = test_support.endpoint(&old_record);
    _ = try core.confirmPeer(&peer, &old_record, 0);
    test_support.installSession(&core, peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const ping_id = try message.RequestId.init(&.{1});
    _ = (try controller.startNext(&core, &out, ping_id, 10, &sealEntropy(1))).?;
    const pong = message.Message{ .pong = .{
        .request_id = ping_id,
        .enr_sequence = 2,
        .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
        .recipient_port = 9_001,
    } };
    try respond(&core, &controller, &newer_record, &pong, 11, 20);
    const nodes_id = try message.RequestId.init(&.{2});
    const fetch = (try controller.startNext(&core, &out, nodes_id, 11, &sealEntropy(2))).?;
    var decode_scratch: message.DecodeScratch = .{};
    const request = try message.Message.decode(
        core.calls.requestBytes(fetch.call.handle).?,
        &decode_scratch,
    );
    try std.testing.expectEqualSlices(u16, &.{0}, request.find_node.distances);
    const raw = [_][]const u8{newer_record.slice()};
    const nodes = message.Message{ .nodes = .{ .request_id = nodes_id, .total = 1, .enrs = &raw } };
    try respond(&core, &controller, &newer_record, &nodes, 12, 21);
    try std.testing.expectEqual(@as(u64, 2), core.peerRecord(&peer.node_id).?.record.sequence);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "maintenance rotates bucket refresh lookups and bootstrap recovers stalled discovery" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const remote = try record(2, 1);
    const bootstrap = try record(3, 1);
    const peer = test_support.endpoint(&remote);
    _ = try core.confirmPeer(&peer, &remote, 0);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    var config = testConfig();
    config.probe_interval_ms = 1_000;
    config.refresh_interval_ms = 10;
    config.bootstrap_interval_ms = 20;
    config.discovery_stall_ms = 30;
    try controller.init(&candidates, &.{bootstrap}, 0, config);
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    try std.testing.expect((try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{1}),
        0,
        &sealEntropy(1),
    )) == null);
    const first = (try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{1}),
        10,
        &sealEntropy(1),
    )).?;
    try std.testing.expectEqual(@as(u16, 240), @import("types.zig").logDistance(
        &core.localRecord().node_id,
        &controller.lookup.target,
    ));
    try std.testing.expect(controller.onFailure(&core, first.call.handle, 11, .local));
    _ = try start(&controller, &core, &out, 2, 11);
    const second = (try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{2}),
        20,
        &sealEntropy(2),
    )).?;
    try std.testing.expectEqual(@as(u16, 241), @import("types.zig").logDistance(
        &core.localRecord().node_id,
        &controller.lookup.target,
    ));
    try std.testing.expect(controller.onFailure(&core, second.call.handle, 21, .local));
    _ = try start(&controller, &core, &out, 3, 21);
    const reseed = (try controller.startNext(
        &core,
        &out,
        try message.RequestId.init(&.{3}),
        30,
        &sealEntropy(3),
    )).?;
    try std.testing.expectEqual(bootstrap.node_id, reseed.peer.node_id);
}

fn observeResponse(
    core: *Engine,
    controller: *Maintenance,
    remote_record: *const enr.Record,
    response: *const message.Message,
    now_ms: u64,
    entropy_seed: u8,
) !bool {
    const remote_key = try test_support.keyPair(2);
    var remote: Engine = undefined;
    try remote.initWithConfig(
        std.testing.allocator,
        remote_key,
        remote_record.*,
        test_support.engineConfig(),
    );
    defer remote.deinit(std.testing.allocator);
    const local_peer = test_support.endpoint(core.localRecord());
    test_support.installSession(&remote, local_peer, 0x55);
    var packet: [1_280]u8 = undefined;
    const length = try remote.sendResponse(
        &packet,
        local_peer,
        response,
        now_ms,
        &sealEntropy(entropy_seed),
    );
    var out: [1_280]u8 = undefined;
    var scratch: Engine.Scratch = .{};
    const outcome = try core.receive(
        &out,
        packet[0..length],
        remote_record.endpoint().?,
        test_support.receiveArgs(now_ms, entropy_seed),
        &scratch,
    );
    try std.testing.expect(outcome == .accepted);
    return controller.onEvent(core, &outcome.accepted.event, now_ms);
}

test "maintenance ENR refresh rejects an advertised endpoint that did not authenticate" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const old_record = try record(2, 1);
    const peer = test_support.endpoint(&old_record);
    const remote_key = try test_support.keyPair(2);
    const moved_record = try enr.Record.create(
        &remote_key,
        2,
        test_support.address4(198, 1, 2, 3, 9_999),
    );
    _ = try core.confirmPeer(&peer, &old_record, 0);
    test_support.installSession(&core, peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const ping_id = try message.RequestId.init(&.{1});
    _ = (try controller.startNext(&core, &out, ping_id, 10, &sealEntropy(1))).?;
    const pong = message.Message{ .pong = .{
        .request_id = ping_id,
        .enr_sequence = 2,
        .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
        .recipient_port = 9_001,
    } };
    try respond(&core, &controller, &old_record, &pong, 11, 20);
    const nodes_id = try message.RequestId.init(&.{2});
    _ = (try controller.startNext(&core, &out, nodes_id, 11, &sealEntropy(2))).?;
    const raw = [_][]const u8{moved_record.slice()};
    const nodes = message.Message{ .nodes = .{ .request_id = nodes_id, .total = 1, .enrs = &raw } };
    try respond(&core, &controller, &old_record, &nodes, 12, 21);
    const retained = core.peerRecord(&peer.node_id).?;
    try std.testing.expectEqual(@as(u64, 1), retained.record.sequence);
    try std.testing.expectEqual(peer, retained.peer);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "maintenance configuration and bootstrap work stay bounded" {
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    var config = testConfig();
    config.retry_interval_ms = 0;
    try std.testing.expectError(
        Maintenance.Error.InvalidConfig,
        controller.init(&candidates, &.{}, 0, config),
    );
    var seeds: [Maintenance.bootstrap_max + 1]enr.Record = undefined;
    try std.testing.expectError(
        Maintenance.Error.TooManyBootstraps,
        controller.init(&candidates, &seeds, 0, testConfig()),
    );
    const invalid = test_support.fakeRecord(
        [_]u8{2} ** 32,
        test_support.address4(0, 0, 0, 0, 0),
        1,
    );
    try std.testing.expectError(
        Maintenance.Error.InvalidBootstrap,
        controller.init(&candidates, &.{invalid}, 0, testConfig()),
    );
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const bootstrap = try record(2, 1);
    try controller.init(&candidates, &.{bootstrap}, 0, testConfig());
    var out: [1_280]u8 = undefined;
    const started = (try start(&controller, &core, &out, 1, 0)).?;
    try std.testing.expectEqual(bootstrap.node_id, started.peer.node_id);
    controller.cancel(&core);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
    try std.testing.expect(controller.nextDeadlineMs() == null);
    try std.testing.expect((try start(&controller, &core, &out, 2, 1)) == null);
    try controller.init(&candidates, &.{}, std.math.maxInt(u64), testConfig());
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), controller.nextDeadlineMs());
}

test "maintenance preserves unrelated events and does not monopolize a busy peer" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const first_record = try record(2, 1);
    const second_record = try record(3, 1);
    const first_peer = test_support.endpoint(&first_record);
    const second_peer = test_support.endpoint(&second_record);
    _ = try core.confirmPeer(&first_peer, &first_record, 0);
    _ = try core.confirmPeer(&second_peer, &second_record, 0);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{99}),
        .enr_sequence = 1,
    } };
    var cursor: usize = 0;
    const target = core.maintenanceTarget(&cursor, 10, 10).?;
    const unrelated = try core.startCall(
        &out,
        target.peer,
        &target.record,
        &request,
        1,
        &sealEntropy(99),
    );
    try std.testing.expect((try start(&controller, &core, &out, 1, 10)) == null);
    const started = (try start(&controller, &core, &out, 2, 20)).?;
    try std.testing.expect(!std.mem.eql(u8, &target.peer.node_id, &started.peer.node_id));
    const unrelated_event = Engine.Event{ .failed = .{
        .handle = unrelated.handle,
        .peer = target.peer,
        .reason = error.SessionRequired,
    } };
    try std.testing.expect(!try controller.onEvent(&core, &unrelated_event, 21));
    try std.testing.expect(core.cancelCall(unrelated.handle));
    const owned_event = Engine.Event{ .failed = .{
        .handle = started.call.handle,
        .peer = started.peer,
        .reason = error.SessionRequired,
    } };
    try std.testing.expect(try controller.onEvent(&core, &owned_event, 21));
    try std.testing.expectEqual(@as(usize, 2), core.peerCount());
}

test "maintenance backs off on shared call capacity without dropping a live operation" {
    const key = try test_support.keyPair(1);
    var core: Engine = undefined;
    var core_config = test_support.engineConfig();
    core_config.call_capacity = 1;
    try core.initWithConfig(std.testing.allocator, key, try record(1, 1), core_config);
    defer core.deinit(std.testing.allocator);
    for (2..4) |seed| {
        const remote = try record(@intCast(seed), 1);
        const peer = test_support.endpoint(&remote);
        _ = try core.confirmPeer(&peer, &remote, 0);
    }
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    var config = testConfig();
    config.refresh_interval_ms = 10;
    try controller.init(&candidates, &.{}, 0, config);
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const active = (try start(&controller, &core, &out, 1, 10)).?;
    try std.testing.expect((try start(&controller, &core, &out, 2, 10)) == null);
    try std.testing.expectEqual(@as(?u64, 15), controller.nextDeadlineMs());
    try std.testing.expectEqual(@as(usize, 1), core.calls.count());
    try std.testing.expect(controller.onFailure(&core, active.call.handle, 11, .local));
    try std.testing.expect((try start(&controller, &core, &out, 3, 11)) != null);
}

test "maintenance bootstrap authentication seeds a bounded periodic lookup" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const bootstrap = try record(2, 1);
    const peer = test_support.endpoint(&bootstrap);
    test_support.installSession(&core, peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{bootstrap}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const request_id = try message.RequestId.init(&.{1});
    _ = (try controller.startNext(&core, &out, request_id, 0, &sealEntropy(1))).?;
    try std.testing.expectEqual(@as(usize, 0), core.peerCount());
    const pong = message.Message{ .pong = .{
        .request_id = request_id,
        .enr_sequence = 1,
        .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
        .recipient_port = 9_001,
    } };
    try respond(&core, &controller, &bootstrap, &pong, 1, 20);
    try std.testing.expectEqual(@as(usize, 1), core.peerCount());
    const refresh = (try start(&controller, &core, &out, 2, 1)).?;
    var scratch: message.DecodeScratch = .{};
    const request = try message.Message.decode(
        core.calls.requestBytes(refresh.call.handle).?,
        &scratch,
    );
    try std.testing.expect(request == .find_node);
    try std.testing.expectEqual(@as(usize, 1), controller.lookup.waitingCount());
}

test "maintenance owns at most one probe and three lookup calls" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    for (2..7) |seed| {
        const remote = try record(@intCast(seed), 1);
        const peer = test_support.endpoint(&remote);
        _ = try core.confirmPeer(&peer, &remote, 0);
    }
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    var config = testConfig();
    config.refresh_interval_ms = 10;
    try controller.init(&candidates, &.{}, 0, config);
    var out: [1_280]u8 = undefined;
    for (1..5) |id| {
        try std.testing.expect((try start(&controller, &core, &out, @intCast(id), 10)) != null);
    }
    try std.testing.expect((try start(&controller, &core, &out, 5, 10)) == null);
    try std.testing.expectEqual(@as(usize, 4), core.calls.count());
    try std.testing.expectEqual(Lookup.parallelism, controller.lookup.waitingCount());
    controller.cancel(&core);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

fn start(
    controller: *Maintenance,
    core: *Engine,
    out: []u8,
    id: u8,
    now_ms: u64,
) !?Lookup.Started {
    return controller.startNext(
        core,
        out,
        try message.RequestId.init(&.{id}),
        now_ms,
        &sealEntropy(id),
    );
}

fn respond(
    core: *Engine,
    controller: *Maintenance,
    remote_record: *const enr.Record,
    response: *const message.Message,
    now_ms: u64,
    entropy_seed: u8,
) !void {
    try std.testing.expect(try observeResponse(
        core,
        controller,
        remote_record,
        response,
        now_ms,
        entropy_seed,
    ));
}

test "maintenance observes unrelated authenticated PONG without consuming the caller event" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const original = try record(2, 1);
    const updated = try record(2, 2);
    const peer = test_support.endpoint(&original);
    _ = try core.confirmPeer(&peer, &original, 0);
    test_support.installSession(&core, peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const request_id = try message.RequestId.init(&.{1});
    const request = message.Message{ .ping = .{
        .request_id = request_id,
        .enr_sequence = 1,
    } };
    _ = try core.startCall(&out, peer, &original, &request, 0, &sealEntropy(1));
    const pong = message.Message{ .pong = .{
        .request_id = request_id,
        .enr_sequence = 2,
        .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
        .recipient_port = 9_001,
    } };
    try std.testing.expect(!try observeResponse(&core, &controller, &original, &pong, 1, 20));
    try std.testing.expectEqual(@as(?u64, 1), controller.nextDeadlineMs());
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
    const fetch = (try start(&controller, &core, &out, 2, 1)).?;
    var scratch: message.DecodeScratch = .{};
    const fetch_request = try message.Message.decode(
        core.calls.requestBytes(fetch.call.handle).?,
        &scratch,
    );
    try std.testing.expectEqualSlices(u16, &.{0}, fetch_request.find_node.distances);
    const raw = [_][]const u8{updated.slice()};
    const nodes = message.Message{ .nodes = .{
        .request_id = try message.RequestId.init(&.{2}),
        .total = 1,
        .enrs = &raw,
    } };
    try respond(&core, &controller, &original, &nodes, 2, 21);
    try std.testing.expectEqual(@as(u64, 2), core.peerRecord(&peer.node_id).?.record.sequence);
    try std.testing.expectEqual(@as(usize, 0), core.calls.count());
}

test "maintenance bootstrap skips a busy first seed" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const seeds = [_]enr.Record{ try record(2, 1), try record(3, 1) };
    var out: [1_280]u8 = undefined;
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{99}),
        .enr_sequence = 1,
    } };
    const occupied = try core.startCall(
        &out,
        test_support.endpoint(&seeds[0]),
        &seeds[0],
        &request,
        0,
        &sealEntropy(99),
    );
    defer _ = core.cancelCall(occupied.handle);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &seeds, 0, testConfig());
    defer controller.cancel(&core);
    const next = try start(&controller, &core, &out, 1, 0);
    try std.testing.expect(next != null);
    try std.testing.expectEqual(seeds[1].node_id, next.?.peer.node_id);
}

test "maintenance retries fully busy bootstraps without reserving a seed" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const seeds = [_]enr.Record{ try record(2, 1), try record(3, 1) };
    var out: [1_280]u8 = undefined;
    var occupied: [2]Engine.StartResult = undefined;
    for (&seeds, &occupied, 0..) |*seed, *call, index| {
        const id: u8 = @intCast(98 + index);
        const request = message.Message{ .ping = .{
            .request_id = try message.RequestId.init(&.{id}),
            .enr_sequence = 1,
        } };
        call.* = try core.startCall(
            &out,
            test_support.endpoint(seed),
            seed,
            &request,
            0,
            &sealEntropy(id),
        );
    }
    defer _ = core.cancelCall(occupied[0].handle);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &seeds, 0, testConfig());
    defer controller.cancel(&core);
    try std.testing.expect((try start(&controller, &core, &out, 1, 0)) == null);
    try std.testing.expect(controller.pending == null);
    try std.testing.expectEqual(@as(?u64, 5), controller.nextDeadlineMs());
    try std.testing.expect(core.cancelCall(occupied[1].handle));
    const next = (try start(&controller, &core, &out, 2, 5)).?;
    try std.testing.expectEqual(seeds[1].node_id, next.peer.node_id);
}

test "maintenance PONG hints preserve occupied and cancelled controller state" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const remote = try record(2, 1);
    const bootstrap = try record(3, 1);
    const peer = test_support.endpoint(&remote);
    test_support.installSession(&core, peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{bootstrap}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    _ = (try start(&controller, &core, &out, 1, 0)).?;
    _ = try core.confirmPeer(&peer, &remote, 0);
    const occupied = controller.pending.?.entry.peer;
    for (2..4) |id_number| {
        const id: u8 = @intCast(id_number);
        const request_id = try message.RequestId.init(&.{id});
        const request = message.Message{ .ping = .{
            .request_id = request_id,
            .enr_sequence = 1,
        } };
        _ = try core.startCall(&out, peer, &remote, &request, 1, &sealEntropy(id));
        const pong = message.Message{ .pong = .{
            .request_id = request_id,
            .enr_sequence = 2,
            .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
            .recipient_port = 9_001,
        } };
        try std.testing.expect(!try observeResponse(
            &core,
            &controller,
            &remote,
            &pong,
            2,
            id + 20,
        ));
        if (id == 2) {
            try std.testing.expectEqual(occupied, controller.pending.?.entry.peer);
            controller.cancel(&core);
        } else {
            try std.testing.expect(controller.pending == null);
            try std.testing.expect(controller.nextDeadlineMs() == null);
        }
    }
}

test "maintenance ignores unrelated PONG hints from an unconfirmed endpoint" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const original = try record(2, 1);
    const original_peer = test_support.endpoint(&original);
    const key = try test_support.keyPair(2);
    const moved = try enr.Record.create(&key, 2, test_support.address4(198, 1, 2, 3, 9_999));
    const moved_peer = test_support.endpoint(&moved);
    _ = try core.confirmPeer(&original_peer, &original, 0);
    test_support.installSession(&core, moved_peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const request_id = try message.RequestId.init(&.{1});
    const request = message.Message{ .ping = .{
        .request_id = request_id,
        .enr_sequence = 1,
    } };
    _ = try core.startCall(&out, moved_peer, &moved, &request, 0, &sealEntropy(1));
    const pong = message.Message{ .pong = .{
        .request_id = request_id,
        .enr_sequence = 2,
        .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
        .recipient_port = 9_001,
    } };
    try std.testing.expect(!try observeResponse(&core, &controller, &moved, &pong, 1, 20));
    try std.testing.expectEqual(@as(?u64, 10), controller.nextDeadlineMs());
    try std.testing.expect(controller.pending == null);
    try std.testing.expectEqual(original_peer, core.peerRecord(&original.node_id).?.peer);
}

test "maintenance abandons an unstarted bootstrap that becomes busy after capacity backoff" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    var out: [1_280]u8 = undefined;
    var occupied: [4]CallTable.Handle = undefined;
    for (&occupied, 4..) |*handle, seed_number| {
        const seed: u8 = @intCast(seed_number);
        const remote = try record(seed, 1);
        const request = message.Message{ .ping = .{
            .request_id = try message.RequestId.init(&.{seed}),
            .enr_sequence = 1,
        } };
        const call = try core.startCall(
            &out,
            test_support.endpoint(&remote),
            &remote,
            &request,
            0,
            &sealEntropy(seed),
        );
        handle.* = call.handle;
    }
    const seeds = [_]enr.Record{ try record(2, 1), try record(3, 1) };
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &seeds, 0, testConfig());
    defer controller.cancel(&core);
    try std.testing.expect((try start(&controller, &core, &out, 1, 0)) == null);
    try std.testing.expectEqual(seeds[0].node_id, controller.pending.?.entry.peer.node_id);
    try std.testing.expect(controller.pending.?.handle == null);
    for (occupied) |handle| try std.testing.expect(core.cancelCall(handle));
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{99}),
        .enr_sequence = 1,
    } };
    const caller = try core.startCall(
        &out,
        test_support.endpoint(&seeds[0]),
        &seeds[0],
        &request,
        1,
        &sealEntropy(99),
    );
    defer _ = core.cancelCall(caller.handle);
    const next = try start(&controller, &core, &out, 2, 5);
    try std.testing.expect(next != null);
    try std.testing.expectEqual(seeds[1].node_id, next.?.peer.node_id);
    try std.testing.expect(core.isPeerBusy(&seeds[0].node_id));
    try std.testing.expectEqual(@as(usize, 2), core.calls.count());
}

test "maintenance drops an unstarted ENR hint when a caller reuses the peer" {
    var core = try initEngine();
    defer core.deinit(std.testing.allocator);
    const remote = try record(2, 1);
    const peer = test_support.endpoint(&remote);
    _ = try core.confirmPeer(&peer, &remote, 0);
    test_support.installSession(&core, peer, 0x55);
    var candidates: Lookup.Candidates = undefined;
    var controller: Maintenance = undefined;
    try controller.init(&candidates, &.{}, 0, testConfig());
    defer controller.cancel(&core);
    var out: [1_280]u8 = undefined;
    const request_id = try message.RequestId.init(&.{1});
    var request = message.Message{ .ping = .{
        .request_id = request_id,
        .enr_sequence = 1,
    } };
    _ = try core.startCall(&out, peer, &remote, &request, 0, &sealEntropy(1));
    const pong = message.Message{ .pong = .{
        .request_id = request_id,
        .enr_sequence = 2,
        .recipient_ip = .{ .ip4 = .{ 203, 1, 1, 1 } },
        .recipient_port = 9_001,
    } };
    try std.testing.expect(!try observeResponse(&core, &controller, &remote, &pong, 1, 20));
    try std.testing.expect(controller.pending.?.kind == .enr);
    request.ping.request_id = try message.RequestId.init(&.{99});
    const caller = try core.startCall(&out, peer, &remote, &request, 1, &sealEntropy(99));
    defer _ = core.cancelCall(caller.handle);
    try std.testing.expect((try start(&controller, &core, &out, 2, 1)) == null);
    try std.testing.expect(controller.pending == null);
    try std.testing.expect(core.isPeerBusy(&peer.node_id));
    try std.testing.expectEqual(@as(usize, 1), core.calls.count());
}
