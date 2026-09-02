const std = @import("std");
const CallTable = @import("CallTable.zig");
const crypto = @import("identity/crypto.zig");
const Driver = @import("Driver.zig");
const Engine = @import("Engine.zig");
const enr = @import("identity/enr.zig");
const Lookup = @import("Lookup.zig");
const lookup_driver = @import("lookup_driver.zig");
const message = @import("wire/message.zig");
const RoutingTable = @import("RoutingTable.zig");
const Udp = @import("Udp.zig");
const SessionStore = @import("SessionStore.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

const address4 = test_support.address4;
const endpoint = test_support.endpoint;
const fakeRecord = test_support.fakeRecord;
const installSession = test_support.installSession;
const keyPair = test_support.keyPair;

const net = std.Io.net;

test "driver rejects invalid polling and missing expiry storage" {
    var core: Engine = undefined;
    var adapter = Udp.init(undefined);
    try std.testing.expectError(
        error.InvalidPollInterval,
        Driver.initWithConfig(&core, &adapter, .{ .poll_interval_ms = 0 }),
    );
    var instance = Driver.init(&core, &adapter);
    try std.testing.expectError(
        error.MissingExpiryStorage,
        instance.step(undefined, &.{}),
    );
}

test "driver retains a routing incumbent that answers revalidation" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();
    try pair.fillBucket();

    var expired: [4]CallTable.Expired = undefined;
    const started = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(started.progress.maintenance_started);
    try std.testing.expectEqual(@as(usize, 0), started.calls_expired);
    try std.testing.expectEqual(@as(usize, 0), started.progress.maintenance_expired);

    const answered = try pair.driver_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.progress.standard_responses);
    try std.testing.expect(answered.event == .none);

    const completed = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .none);
    try std.testing.expectEqual(@as(usize, 0), completed.calls_expired);
    try std.testing.expectEqual(@as(usize, 0), completed.progress.maintenance_expired);
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.routing.pendingCount());
    try std.testing.expect(pair.node_a.routing.contains(&pair.record_b.node_id));
    try std.testing.expect(!pair.node_a.routing.contains(&pair.candidate_id));
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.calls.count());
}

test "driver replaces a routing incumbent when revalidation expires" {
    var pair: Pair = undefined;
    try pair.init(1, true);
    defer pair.deinit();
    try pair.fillBucket();

    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(result.progress.maintenance_started);
    try std.testing.expectEqual(@as(usize, 0), result.calls_expired);
    try std.testing.expectEqual(@as(usize, 1), result.progress.maintenance_expired);
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.routing.pendingCount());
    try std.testing.expect(!pair.node_a.routing.contains(&pair.record_b.node_id));
    try std.testing.expect(pair.node_a.routing.contains(&pair.candidate_id));
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.calls.count());
}

test "driver completes a cold call through challenge and handshake" {
    var pair: Pair = undefined;
    try pair.init(1_000, false);
    defer pair.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x42}),
        .enr_sequence = pair.record_a.sequence,
    } };
    const handle = try pair.driver_a.startCall(
        std.testing.io,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    var expired: [4]CallTable.Expired = undefined;
    try std.testing.expect((try pair.driver_b.step(std.testing.io, &expired)).event == .none);
    try std.testing.expect((try pair.driver_a.step(std.testing.io, &expired)).event == .none);
    const request_step = try pair.driver_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), request_step.progress.standard_responses);
    const response_step = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(response_step.event == .response);
    try std.testing.expectEqual(handle, response_step.event.response.matched.handle);
    try std.testing.expect(response_step.event.response.matched.response == .pong);
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.calls.count());
}

test "driver leaves TALK response policy with the application" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();

    const request_id = try message.RequestId.init(&.{0x43});
    const request = message.Message{ .talk_request = .{
        .request_id = request_id,
        .protocol = "test",
        .request = "request",
    } };
    const handle = try pair.driver_a.startCall(
        std.testing.io,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    var expired: [4]CallTable.Expired = undefined;
    const received = try pair.driver_b.step(std.testing.io, &expired);
    try std.testing.expect(received.event == .request);
    try std.testing.expect(received.event.request.message == .talk_request);
    try std.testing.expectEqual(@as(u8, 0), received.progress.standard_responses);

    const response = message.Message{ .talk_response = .{
        .request_id = request_id,
        .response = "response",
    } };
    try pair.driver_b.sendResponse(
        std.testing.io,
        endpoint(&pair.record_a),
        &response,
    );
    const completed = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .response);
    try std.testing.expectEqual(handle, completed.event.response.matched.handle);
    try std.testing.expectEqualStrings(
        "response",
        completed.event.response.matched.response.talk_response.response,
    );
}

test "driver releases a malformed datagram before the next step" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();

    try pair.udp_b.send(
        std.testing.io,
        pair.udp_a.localAddress(),
        &.{0xff},
    );
    var expired: [4]CallTable.Expired = undefined;
    const rejected = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(rejected.datagram == .rejected);
    try std.testing.expectEqual(types.RejectReason.malformed_packet, rejected.datagram.rejected);

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x44}),
        .enr_sequence = pair.record_b.sequence,
    } };
    const handle = try pair.driver_b.startCall(
        std.testing.io,
        endpoint(&pair.record_a),
        &pair.record_a,
        &request,
    );
    const answered = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.progress.standard_responses);
    const completed = try pair.driver_b.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .response);
    try std.testing.expectEqual(handle, completed.event.response.matched.handle);
}

test "driver returns call expiries when rejecting a malformed datagram" {
    var pair: Pair = undefined;
    try pair.init(1, true);
    defer pair.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x45}),
        .enr_sequence = pair.record_a.sequence,
    } };
    const handle = try pair.driver_a.startCall(
        std.testing.io,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    try std.Io.sleep(std.testing.io, .fromMilliseconds(2), .awake);
    try pair.udp_b.send(
        std.testing.io,
        pair.udp_a.localAddress(),
        &.{0xff},
    );

    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(result.datagram == .rejected);
    try std.testing.expectEqual(types.RejectReason.malformed_packet, result.datagram.rejected);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(handle, expired[0].handle);
}

test "driver completes a caller-owned lookup across multiple peers" {
    var network: LookupNetwork = undefined;
    try network.init(1_000);
    defer network.deinit();

    var seed_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds = network.node_a.closestNodes(&network.record_c.node_id, &seed_buffer);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        network.record_a.node_id,
        network.record_c.node_id,
        seeds,
    );

    var expired: [4]CallTable.Expired = undefined;
    const first = try lookup_driver.step(
        &network.driver_a,
        std.testing.io,
        &.{&operation},
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), first.progress.started);
    try std.testing.expectEqual(@as(usize, 0), first.driver.calls_expired);

    const from_b = try network.driver_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), from_b.progress.standard_responses);
    const second = try lookup_driver.step(
        &network.driver_a,
        std.testing.io,
        &.{&operation},
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), second.progress.responses);
    try std.testing.expectEqual(@as(u16, 1), second.progress.started);
    try std.testing.expectEqual(@as(?u16, 0), second.consumed);

    const from_c = try network.driver_c.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), from_c.progress.standard_responses);
    const completed = try lookup_driver.step(
        &network.driver_a,
        std.testing.io,
        &.{&operation},
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), completed.progress.responses);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(@as(usize, 0), network.node_a.calls.count());
    try std.testing.expect(network.node_a.routing.contains(&network.record_c.node_id));

    var records: [Lookup.result_max]enr.Record = undefined;
    const results = operation.results(&records);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqual(network.record_c.node_id, results[0].node_id);
    try std.testing.expectEqual(network.record_b.node_id, results[1].node_id);
}

test "lookup expiry is consumed without hiding an unrelated call expiry" {
    var network: LookupNetwork = undefined;
    try network.init(1);
    defer network.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x24}),
        .enr_sequence = network.record_a.sequence,
    } };
    const caller_handle = try network.driver_a.startCall(
        std.testing.io,
        endpoint(&network.record_c),
        &network.record_c,
        &request,
    );
    var seed_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds = network.node_a.closestNodes(&network.record_c.node_id, &seed_buffer);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        network.record_a.node_id,
        network.record_c.node_id,
        seeds,
    );

    var expired: [4]CallTable.Expired = undefined;
    const result = try lookup_driver.step(
        &network.driver_a,
        std.testing.io,
        &.{&operation},
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), result.progress.started);
    try std.testing.expectEqual(@as(u16, 1), result.progress.failures);
    try std.testing.expectEqual(@as(usize, 1), result.driver.calls_expired);
    try std.testing.expectEqual(caller_handle, expired[0].handle);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(@as(usize, 0), network.node_a.calls.count());
}

test "lookup step preserves an unrelated response event" {
    var network: LookupNetwork = undefined;
    try network.init(1_000);
    defer network.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x25}),
        .enr_sequence = network.record_a.sequence,
    } };
    const caller_handle = try network.driver_a.startCall(
        std.testing.io,
        endpoint(&network.record_c),
        &network.record_c,
        &request,
    );
    var expired: [4]CallTable.Expired = undefined;
    const answered = try network.driver_c.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.progress.standard_responses);

    var seed_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds = network.node_a.closestNodes(&network.record_c.node_id, &seed_buffer);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(
        &operation_candidates,
        network.record_a.node_id,
        network.record_c.node_id,
        seeds,
    );
    defer operation.cancel(&network.node_a);

    const result = try lookup_driver.step(
        &network.driver_a,
        std.testing.io,
        &.{&operation},
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), result.progress.started);
    try std.testing.expectEqual(@as(u16, 0), result.progress.responses);
    try std.testing.expect(result.consumed == null);
    try std.testing.expect(result.driver.event == .response);
    try std.testing.expectEqual(
        caller_handle,
        result.driver.event.response.matched.handle,
    );
}

test "two caller-owned lookups share one driver" {
    var network: LookupNetwork = undefined;
    try network.init(1_000);
    defer network.deinit();

    const peer_c = endpoint(&network.record_c);
    _ = try network.node_a.confirmPeer(&peer_c, &network.record_c, 0);
    var seeds_b_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds_b = network.node_a.closestNodes(
        &network.record_b.node_id,
        &seeds_b_buffer,
    );
    var operation_b: Lookup = undefined;
    var operation_b_candidates: Lookup.Candidates = undefined;
    try operation_b.init(
        &operation_b_candidates,
        network.record_a.node_id,
        network.record_b.node_id,
        seeds_b,
    );
    defer operation_b.cancel(&network.node_a);
    var seeds_c_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds_c = network.node_a.closestNodes(
        &network.record_c.node_id,
        &seeds_c_buffer,
    );
    var operation_c: Lookup = undefined;
    var operation_c_candidates: Lookup.Candidates = undefined;
    try operation_c.init(
        &operation_c_candidates,
        network.record_a.node_id,
        network.record_c.node_id,
        seeds_c,
    );
    defer operation_c.cancel(&network.node_a);

    var expired: [4]CallTable.Expired = undefined;
    var responses_b: usize = 0;
    var responses_c: usize = 0;
    for (0..32) |_| {
        if (operation_b.isFinished() and operation_c.isFinished()) break;
        const result = try lookup_driver.step(
            &network.driver_a,
            std.testing.io,
            &.{ &operation_b, &operation_c },
            &expired,
        );
        try std.testing.expect(result.driver.event != .response or result.consumed != null);
        if (result.consumed) |index| switch (index) {
            0 => responses_b += 1,
            1 => responses_c += 1,
            else => return error.TestUnexpectedResult,
        };
        _ = try network.driver_b.step(std.testing.io, &expired);
        _ = try network.driver_c.step(std.testing.io, &expired);
    }
    try std.testing.expect(operation_b.isFinished());
    try std.testing.expect(operation_c.isFinished());
    try std.testing.expectEqual(@as(usize, 2), responses_b);
    try std.testing.expectEqual(@as(usize, 2), responses_c);
    try std.testing.expectEqual(@as(usize, 0), network.node_a.calls.count());

    var records: [Lookup.result_max]enr.Record = undefined;
    const results_b = operation_b.results(&records);
    try std.testing.expectEqual(@as(usize, 2), results_b.len);
    try std.testing.expectEqual(network.record_b.node_id, results_b[0].node_id);
    const results_c = operation_c.results(&records);
    try std.testing.expectEqual(@as(usize, 2), results_c.len);
    try std.testing.expectEqual(network.record_c.node_id, results_c[0].node_id);
}

const Pair = struct {
    udp_a: Udp,
    udp_b: Udp,
    record_a: enr.Record,
    record_b: enr.Record,
    node_a: Engine,
    node_b: Engine,
    driver_a: Driver,
    driver_b: Driver,
    candidate_id: types.NodeId,

    fn init(self: *Pair, request_timeout_ms: u64, install_session: bool) !void {
        const loopback = net.IpAddress{ .ip4 = .loopback(0) };
        self.udp_a = try Udp.bind(std.testing.io, loopback);
        errdefer self.udp_a.close(std.testing.io);
        self.udp_b = try Udp.bind(std.testing.io, loopback);
        errdefer self.udp_b.close(std.testing.io);

        const key_a = try keyPair(0x11);
        const key_b = try keyPair(0x22);
        self.record_a = try enr.Record.create(&key_a, 1, self.udp_a.localAddress());
        self.record_b = try enr.Record.create(&key_b, 1, self.udp_b.localAddress());
        const config = Engine.Config{
            .session_capacity = 4,
            .challenge_capacity = 4,
            .call_capacity = 4,
            .request_timeout_ms = request_timeout_ms,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        };
        try self.node_a.initWithConfig(std.testing.allocator, key_a, self.record_a, config);
        errdefer self.node_a.deinit(std.testing.allocator);
        try self.node_b.initWithConfig(std.testing.allocator, key_b, self.record_b, config);
        errdefer self.node_b.deinit(std.testing.allocator);

        if (install_session) {
            const peer_a = endpoint(&self.record_a);
            const peer_b = endpoint(&self.record_b);
            const session_key = [_]u8{0x55} ** 16;
            const active = SessionStore.Session{
                .read_key = session_key,
                .write_key = session_key,
            };
            self.node_a.channel.sessions.install(peer_b, &active, 0);
            self.node_b.channel.sessions.install(peer_a, &active, 0);
        }
        self.driver_a = try Driver.initWithConfig(
            &self.node_a,
            &self.udp_a,
            .{ .poll_interval_ms = 10 },
        );
        self.driver_b = try Driver.initWithConfig(
            &self.node_b,
            &self.udp_b,
            .{ .poll_interval_ms = 10 },
        );
    }

    fn deinit(self: *Pair) void {
        self.node_b.deinit(std.testing.allocator);
        self.node_a.deinit(std.testing.allocator);
        self.udp_b.close(std.testing.io);
        self.udp_a.close(std.testing.io);
    }

    fn fillBucket(self: *Pair) !void {
        const incumbent_peer = endpoint(&self.record_b);
        try std.testing.expect(types.logDistance(
            &self.record_a.node_id,
            &self.record_b.node_id,
        ) > 8);
        try std.testing.expectEqual(
            RoutingTable.PutResult.inserted,
            try self.node_a.confirmPeer(&incumbent_peer, &self.record_b, 0),
        );
        for (1..RoutingTable.bucket_size) |index| {
            const node_id = variantNodeId(self.record_b.node_id, @intCast(index));
            const address = address4(10, @intCast(index), 0, 1, @intCast(10_000 + index));
            var record = fakeRecord(node_id, address, 0);
            const peer = types.Endpoint{ .node_id = node_id, .address = address };
            try std.testing.expectEqual(
                RoutingTable.PutResult.inserted,
                try self.node_a.confirmPeer(&peer, &record, @intCast(index)),
            );
        }
        self.candidate_id = variantNodeId(self.record_b.node_id, RoutingTable.bucket_size);
        const candidate_address = address4(10, 200, 0, 1, 10_200);
        var candidate_record = fakeRecord(self.candidate_id, candidate_address, 0);
        const candidate_peer = types.Endpoint{
            .node_id = self.candidate_id,
            .address = candidate_address,
        };
        const pending = try self.node_a.confirmPeer(&candidate_peer, &candidate_record, 20);
        switch (pending) {
            .pending => |node_id| try std.testing.expectEqualSlices(
                u8,
                &self.record_b.node_id,
                &node_id,
            ),
            else => return error.TestUnexpectedResult,
        }
    }
};

const LookupNetwork = struct {
    udp_a: Udp,
    udp_b: Udp,
    udp_c: Udp,
    record_a: enr.Record,
    record_b: enr.Record,
    record_c: enr.Record,
    node_a: Engine,
    node_b: Engine,
    node_c: Engine,
    driver_a: Driver,
    driver_b: Driver,
    driver_c: Driver,

    fn init(self: *LookupNetwork, request_timeout_ms: u64) !void {
        const loopback = net.IpAddress{ .ip4 = .loopback(0) };
        self.udp_a = try Udp.bind(std.testing.io, loopback);
        errdefer self.udp_a.close(std.testing.io);
        self.udp_b = try Udp.bind(std.testing.io, loopback);
        errdefer self.udp_b.close(std.testing.io);
        self.udp_c = try Udp.bind(std.testing.io, loopback);
        errdefer self.udp_c.close(std.testing.io);

        const key_a = try keyPair(0x11);
        const key_b = try keyPair(0x22);
        const key_c = try keyPair(0x33);
        self.record_a = try enr.Record.create(&key_a, 1, self.udp_a.localAddress());
        self.record_b = try enr.Record.create(&key_b, 1, self.udp_b.localAddress());
        self.record_c = try enr.Record.create(&key_c, 1, self.udp_c.localAddress());
        const config = Engine.Config{
            .session_capacity = 4,
            .challenge_capacity = 4,
            .call_capacity = 4,
            .request_timeout_ms = request_timeout_ms,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        };
        try self.node_a.initWithConfig(std.testing.allocator, key_a, self.record_a, config);
        errdefer self.node_a.deinit(std.testing.allocator);
        try self.node_b.initWithConfig(std.testing.allocator, key_b, self.record_b, config);
        errdefer self.node_b.deinit(std.testing.allocator);
        try self.node_c.initWithConfig(std.testing.allocator, key_c, self.record_c, config);
        errdefer self.node_c.deinit(std.testing.allocator);

        installSession(&self.node_a, endpoint(&self.record_b), 0x51);
        installSession(&self.node_b, endpoint(&self.record_a), 0x51);
        installSession(&self.node_a, endpoint(&self.record_c), 0x52);
        installSession(&self.node_c, endpoint(&self.record_a), 0x52);
        self.driver_a = try makeDriver(&self.node_a, &self.udp_a);
        self.driver_b = try makeDriver(&self.node_b, &self.udp_b);
        self.driver_c = try makeDriver(&self.node_c, &self.udp_c);

        const peer_b = endpoint(&self.record_b);
        const peer_c = endpoint(&self.record_c);
        _ = try self.node_a.confirmPeer(&peer_b, &self.record_b, 0);
        _ = try self.node_b.confirmPeer(&peer_c, &self.record_c, 0);
    }

    fn deinit(self: *LookupNetwork) void {
        self.node_c.deinit(std.testing.allocator);
        self.node_b.deinit(std.testing.allocator);
        self.node_a.deinit(std.testing.allocator);
        self.udp_c.close(std.testing.io);
        self.udp_b.close(std.testing.io);
        self.udp_a.close(std.testing.io);
    }
};

fn makeDriver(core: *Engine, adapter: *Udp) !Driver {
    return Driver.initWithConfig(core, adapter, .{ .poll_interval_ms = 10 });
}

fn variantNodeId(base: types.NodeId, salt: u8) types.NodeId {
    var result = base;
    result[31] ^= salt;
    return result;
}
