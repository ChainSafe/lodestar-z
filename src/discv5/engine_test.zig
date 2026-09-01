const std = @import("std");
const calls = @import("calls.zig");
const engine = @import("engine.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const message = @import("wire/message.zig");
const packet = @import("wire/packet.zig");
const engine_session = @import("session.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

const TestEngine = engine.Engine;

test "paired engines recover a session and complete one call without queues" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const recovery = try pair.beginRecovery();
    const request = try pair.authenticate(recovery.handshake_length);
    try pair.completePong(recovery.started, &request);
    try pair.standardFindNodeResponse();
    try pair.filterFindNodeRecords();
    try pair.directSessionTimeout();
}

const Pair = struct {
    address_a: types.Address,
    address_b: types.Address,
    record_a: enr.Record,
    record_b: enr.Record,
    node_a: TestEngine,
    node_b: TestEngine,
    a_to_b: [1_280]u8,
    b_to_a: [1_280]u8,
    scratch_a: engine.Scratch,
    scratch_b: engine.Scratch,

    const Recovery = struct {
        started: engine.StartResult,
        handshake_length: u16,
    };

    fn init(self: *Pair) !void {
        self.address_a = address(1, 9_001);
        self.address_b = address(2, 9_002);
        const key_a = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
        const key_b = try crypto.keyPairFromSecret(&([_]u8{0x22} ** 32));
        self.record_a = try test_support.buildRecord(&key_a, 1, self.address_a);
        self.record_b = try test_support.buildRecord(&key_b, 1, self.address_b);
        try self.node_a.initWithConfig(std.testing.allocator, key_a, self.record_a, testConfig());
        errdefer self.node_a.deinit();
        try self.node_b.initWithConfig(std.testing.allocator, key_b, self.record_b, testConfig());
        self.scratch_a = .{};
        self.scratch_b = .{};
    }

    fn deinit(self: *Pair) void {
        self.node_b.deinit();
        self.node_a.deinit();
    }

    fn beginRecovery(self: *Pair) !Recovery {
        const ping_message = self.ping(1);
        var too_small: [1]u8 = undefined;
        try std.testing.expectError(packet.Error.BufferTooSmall, self.node_a.startCall(
            &too_small,
            self.peerB(),
            &self.record_b,
            &ping_message,
            1,
            startEntropy(0x08),
        ));
        try std.testing.expectEqual(@as(usize, 0), self.node_a.calls.count());
        const started = try self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &self.record_b,
            &ping_message,
            1,
            startEntropy(0x10),
        );
        try std.testing.expectError(calls.Error.PeerBusy, self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &self.record_b,
            &ping_message,
            1,
            startEntropy(0x20),
        ));
        const challenge = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..started.packet_length],
            self.address_a,
            receiveArgs(2, 0x30),
            &self.scratch_b,
        );
        try std.testing.expectEqual(@as(u16, 63), challenge.packet_length);
        const response = try self.node_a.receive(
            &self.a_to_b,
            self.b_to_a[0..challenge.packet_length],
            self.address_b,
            receiveArgs(3, 0x40),
            &self.scratch_a,
        );
        try std.testing.expect(response.packet_length > 63);
        const handshake_packet = try packet.decode(
            self.a_to_b[0..response.packet_length],
            &self.record_b.node_id,
            &self.scratch_b.packet_decode,
        );
        try std.testing.expectEqualSlices(
            u8,
            &.{ 0, 0, 0, 1 },
            handshake_packet.static_header.nonce[0..4],
        );
        return .{ .started = started, .handshake_length = response.packet_length };
    }

    fn authenticate(self: *Pair, handshake_length: u16) !engine.AuthenticatedRequest {
        var corrupted = self.a_to_b;
        corrupted[handshake_length - 1] ^= 1;
        try std.testing.expectError(packet.Error.DecryptionFailed, self.node_b.receive(
            &self.b_to_a,
            corrupted[0..handshake_length],
            self.address_a,
            receiveArgs(4, 0x50),
            &self.scratch_b,
        ));
        try std.testing.expectEqual(@as(usize, 0), self.node_b.sessions.sessionCount());
        try std.testing.expectEqual(@as(usize, 1), self.node_b.sessions.challengeCount());
        const authenticated = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..handshake_length],
            self.address_a,
            receiveArgs(5, 0x60),
            &self.scratch_b,
        );
        try std.testing.expect(authenticated.event == .request);
        try std.testing.expect(authenticated.event.request.record != null);
        try std.testing.expectEqual(
            self.record_a.node_id,
            authenticated.event.request.record.?.node_id,
        );
        try std.testing.expect(self.node_b.routing.contains(&self.record_a.node_id));
        try std.testing.expectEqual(@as(usize, 1), self.node_b.sessions.sessionCount());
        try std.testing.expectEqual(@as(usize, 0), self.node_b.sessions.challengeCount());
        return authenticated.event.request;
    }

    fn completePong(
        self: *Pair,
        started: engine.StartResult,
        request: *const engine.AuthenticatedRequest,
    ) !void {
        var response: engine.StandardResponse = undefined;
        try self.node_b.prepareStandardResponse(request, &response);
        var too_small: [1]u8 = undefined;
        try std.testing.expectError(packet.Error.BufferTooSmall, self.node_b.sendNextStandardResponse(
            &too_small,
            &response,
            6,
            startEntropy(0x70),
        ));
        try std.testing.expect(!response.complete());
        const length = (try self.node_b.sendNextStandardResponse(
            &self.b_to_a,
            &response,
            6,
            startEntropy(0x70),
        )).?;
        const response_packet = try packet.decode(
            self.b_to_a[0..length],
            &self.record_a.node_id,
            &self.scratch_a.packet_decode,
        );
        try std.testing.expectEqualSlices(
            u8,
            &.{ 0, 0, 0, 1 },
            response_packet.static_header.nonce[0..4],
        );
        try std.testing.expect(response.complete());
        try std.testing.expect((try self.node_b.sendNextStandardResponse(
            &self.b_to_a,
            &response,
            6,
            startEntropy(0x70),
        )) == null);
        const completed = try self.node_a.receive(
            &self.a_to_b,
            self.b_to_a[0..length],
            self.address_b,
            receiveArgs(7, 0x80),
            &self.scratch_a,
        );
        try std.testing.expect(completed.event == .response);
        try std.testing.expect(completed.event.response.matched.terminal);
        try std.testing.expectEqual(started.handle, completed.event.response.matched.handle);
        const pong = completed.event.response.matched.response.pong;
        try std.testing.expectEqual(self.record_b.sequence, pong.enr_sequence);
        try std.testing.expectEqual(self.address_a.ip4.octets, pong.recipient_ip.ip4);
        try std.testing.expectEqual(self.address_a.ip4.port, pong.recipient_port);
        const peer_b = self.peerB();
        _ = try self.node_a.confirmPeer(&peer_b, &self.record_b, 7);
        try std.testing.expect(self.node_a.routing.contains(&self.record_b.node_id));

        var records: [2]enr.Record = undefined;
        const distance = types.logDistance(&self.record_a.node_id, &self.record_b.node_id);
        const selected = try self.node_a.findNodes(self.address_b, &.{ 0, distance }, &records);
        try std.testing.expectEqual(@as(usize, 2), selected.len);
        try std.testing.expectEqual(self.record_a.node_id, selected[0].node_id);
        try std.testing.expectEqual(self.record_b.node_id, selected[1].node_id);
    }

    fn directSessionTimeout(self: *Pair) !void {
        const ping_message = self.ping(2);
        const started = try self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &self.record_b,
            &ping_message,
            16,
            startEntropy(0x90),
        );
        const direct_packet = try packet.decode(
            self.a_to_b[0..started.packet_length],
            &self.record_b.node_id,
            &self.scratch_b.packet_decode,
        );
        try std.testing.expectEqualSlices(
            u8,
            &.{ 0, 0, 0, 4 },
            direct_packet.static_header.nonce[0..4],
        );
        const received = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..started.packet_length],
            self.address_a,
            receiveArgs(17, 0xa0),
            &self.scratch_b,
        );
        try std.testing.expectEqual(@as(u16, 0), received.packet_length);
        try std.testing.expect(received.event == .request);
        try std.testing.expect(received.event.request.record == null);
        var expired: [1]calls.Expired = undefined;
        const tick = self.node_a.tick(116, &expired);
        try std.testing.expectEqual(@as(usize, 1), tick.calls);
        try std.testing.expectEqual(started.handle, expired[0].handle);
    }

    fn filterFindNodeRecords(self: *Pair) !void {
        const requested_distance = types.logDistance(&self.record_b.node_id, &self.record_a.node_id);
        const request = message.Message{ .find_node = .{
            .request_id = try message.RequestId.init(&.{0x03}),
            .distances = &.{requested_distance},
        } };
        const started = try self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &self.record_b,
            &request,
            12,
            startEntropy(0x81),
        );
        const received = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..started.packet_length],
            self.address_a,
            receiveArgs(13, 0x82),
            &self.scratch_b,
        );
        try std.testing.expect(received.event == .request);

        const raw_records = [_][]const u8{ self.record_a.slice(), self.record_b.slice() };
        const response = message.Message{ .nodes = .{
            .request_id = request.find_node.request_id,
            .total = 1,
            .enrs = &raw_records,
        } };
        const response_length = try self.node_b.sendResponse(
            &self.b_to_a,
            self.peerA(),
            &response,
            14,
            startEntropy(0x83),
        );
        const completed = try self.node_a.receive(
            &self.a_to_b,
            self.b_to_a[0..response_length],
            self.address_b,
            receiveArgs(15, 0x84),
            &self.scratch_a,
        );
        try std.testing.expect(completed.event == .response);
        try std.testing.expectEqual(@as(usize, 1), completed.event.response.node_records.len);
        try std.testing.expectEqual(
            self.record_a.node_id,
            completed.event.response.node_records[0].node_id,
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            completed.event.response.matched.response.nodes.enrs.len,
        );
    }

    fn standardFindNodeResponse(self: *Pair) !void {
        const request = message.Message{ .find_node = .{
            .request_id = try message.RequestId.init(&.{0x04}),
            .distances = &.{0},
        } };
        const started = try self.node_b.startCall(
            &self.b_to_a,
            self.peerA(),
            &self.record_a,
            &request,
            8,
            startEntropy(0xb0),
        );
        const received = try self.node_a.receive(
            &self.a_to_b,
            self.b_to_a[0..started.packet_length],
            self.address_b,
            receiveArgs(9, 0xb1),
            &self.scratch_a,
        );
        try std.testing.expect(received.event == .request);
        var response: engine.StandardResponse = undefined;
        try self.node_a.prepareStandardResponse(
            &received.event.request,
            &response,
        );
        const response_length = (try self.node_a.sendNextStandardResponse(
            &self.a_to_b,
            &response,
            10,
            startEntropy(0xb2),
        )).?;
        try std.testing.expect(response.complete());
        const completed = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..response_length],
            self.address_a,
            receiveArgs(11, 0xb3),
            &self.scratch_b,
        );
        try std.testing.expect(completed.event == .response);
        try std.testing.expectEqual(started.handle, completed.event.response.matched.handle);
        try std.testing.expectEqual(@as(usize, 1), completed.event.response.node_records.len);
        try std.testing.expectEqual(
            self.record_a.node_id,
            completed.event.response.node_records[0].node_id,
        );
    }

    fn ping(self: *const Pair, id: u8) message.Message {
        return .{ .ping = .{
            .request_id = message.RequestId.init(&.{id}) catch unreachable,
            .enr_sequence = self.record_a.sequence,
        } };
    }

    fn peerA(self: *const Pair) types.Endpoint {
        return .{ .node_id = self.record_a.node_id, .address = self.address_a };
    }

    fn peerB(self: *const Pair) types.Endpoint {
        return .{ .node_id = self.record_b.node_id, .address = self.address_b };
    }
};

test "engine rejects a local record owned by another key" {
    const key_a = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const key_b = try crypto.keyPairFromSecret(&([_]u8{0x22} ** 32));
    const record_b = try test_support.buildRecord(&key_b, 1, address(2, 9_002));
    var invalid: TestEngine = undefined;
    try std.testing.expectError(
        engine.Error.InvalidLocalRecord,
        invalid.init(std.testing.allocator, key_a, record_b),
    );
}

test "cold oversized requests fail before transmission" {
    const key = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const local_record = try test_support.buildRecord(&key, 1, address(1, 9_001));
    var node: TestEngine = undefined;
    try node.initWithConfig(std.testing.allocator, key, local_record, testConfig());
    defer node.deinit();
    const remote_key = try crypto.keyPairFromSecret(&([_]u8{0x22} ** 32));
    const remote_record = try test_support.buildRecord(&remote_key, 1, address(2, 9_002));
    const peer = types.Endpoint{
        .node_id = remote_record.node_id,
        .address = address(2, 9_002),
    };
    const payload = [_]u8{0x55} ** 1_100;
    const request = message.Message{ .talk_request = .{
        .request_id = try message.RequestId.init(&.{0x01}),
        .protocol = &.{},
        .request = &payload,
    } };
    var output = [_]u8{0xa5} ** 1_280;
    const before = output;
    try std.testing.expectError(engine.Error.SessionRequired, node.startCall(
        &output,
        peer,
        &remote_record,
        &request,
        1,
        startEntropy(0x10),
    ));
    try std.testing.expectEqualSlices(u8, &before, &output);
    try std.testing.expectEqual(@as(usize, 0), node.calls.count());

    const session_key = [_]u8{0x33} ** 16;
    const active = engine_session.Session{
        .read_key = session_key,
        .write_key = session_key,
    };
    node.sessions.install(peer, &active, 2);
    const started = try node.startCall(
        &output,
        peer,
        &remote_record,
        &request,
        3,
        startEntropy(0x20),
    );
    try std.testing.expect(started.packet_length > 1_100);
}

test "engine configuration rejects zero retention windows" {
    const key = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const local_record = try test_support.buildRecord(&key, 1, address(1, 9_001));
    var node: TestEngine = undefined;
    var config = testConfig();
    config.challenge_timeout_ms = 0;
    try std.testing.expectError(
        engine.Error.InvalidTimeout,
        node.initWithConfig(std.testing.allocator, key, local_record, config),
    );
}

fn startEntropy(seed: u8) engine.StartEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce = [_]u8{seed +% 1} ** 12,
        .nonce_tail = [_]u8{seed +% 2} ** 8,
        .sessionless_key = [_]u8{seed +% 3} ** 16,
    };
}

fn receiveArgs(now_ms: u64, seed: u8) engine.ReceiveArgs {
    return .{
        .now_ms = now_ms,
        .entropy = .{
            .challenge_masking_iv = [_]u8{seed} ** 16,
            .id_nonce = [_]u8{seed +% 1} ** 16,
            .handshake_masking_iv = [_]u8{seed +% 2} ** 16,
            .handshake_nonce_tail = [_]u8{seed +% 3} ** 8,
            .ephemeral_secret = [_]u8{seed +% 4} ** 32,
        },
    };
}

fn testConfig() engine.Config {
    return .{
        .session_capacity = 4,
        .challenge_capacity = 4,
        .call_capacity = 4,
        .request_timeout_ms = 100,
        .challenge_timeout_ms = 100,
        .session_idle_timeout_ms = 1_000,
    };
}

fn address(id: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ 127, 0, 0, id }, .port = port } };
}
