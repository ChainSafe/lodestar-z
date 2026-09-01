const std = @import("std");
const calls = @import("calls.zig");
const engine = @import("engine.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const message = @import("wire/message.zig");
const packet = @import("wire/packet.zig");
const rlp = @import("wire/rlp.zig");
const types = @import("types.zig");

const TestEngine = engine.Engine;

test "paired engines recover a session and complete one call without queues" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const recovery = try pair.beginRecovery();
    const request_id = try pair.authenticate(recovery.handshake_length);
    try pair.completePong(recovery.started, request_id);
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
        self.record_a = try buildRecord(&key_a, 1, self.address_a);
        self.record_b = try buildRecord(&key_b, 1, self.address_b);
        try self.node_a.initWithLimits(key_a, self.record_a, .{ .sessions = 4, .calls = 4 });
        errdefer self.node_a.deinit();
        try self.node_b.initWithLimits(key_b, self.record_b, .{ .sessions = 4, .calls = 4 });
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
            &ping_message,
            1,
            100,
            startEntropy(0x08),
        ));
        try std.testing.expectEqual(@as(usize, 0), self.node_a.calls.count());
        const started = try self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &ping_message,
            1,
            100,
            startEntropy(0x10),
        );
        try std.testing.expectError(calls.Error.PeerBusy, self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &ping_message,
            1,
            100,
            startEntropy(0x20),
        ));
        const challenge = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..started.packet_length],
            self.address_a,
            receiveArgs(2, null, 0x30),
            &self.scratch_b,
        );
        try std.testing.expectEqual(@as(u16, 63), challenge.packet_length);
        const response = try self.node_a.receive(
            &self.a_to_b,
            self.b_to_a[0..challenge.packet_length],
            self.address_b,
            receiveArgs(3, &self.record_b, 0x40),
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

    fn authenticate(self: *Pair, handshake_length: u16) !message.RequestId {
        var corrupted = self.a_to_b;
        corrupted[handshake_length - 1] ^= 1;
        try std.testing.expectError(packet.Error.DecryptionFailed, self.node_b.receive(
            &self.b_to_a,
            corrupted[0..handshake_length],
            self.address_a,
            receiveArgs(4, null, 0x50),
            &self.scratch_b,
        ));
        try std.testing.expectEqual(@as(usize, 0), self.node_b.sessions.sessionCount());
        try std.testing.expectEqual(@as(usize, 1), self.node_b.sessions.challengeCount());
        const authenticated = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..handshake_length],
            self.address_a,
            receiveArgs(5, null, 0x60),
            &self.scratch_b,
        );
        try std.testing.expect(authenticated.event == .request);
        try std.testing.expect(authenticated.event.request.record != null);
        try std.testing.expectEqual(
            self.record_a.node_id,
            authenticated.event.request.record.?.node_id,
        );
        try std.testing.expectEqual(@as(usize, 1), self.node_b.sessions.sessionCount());
        try std.testing.expectEqual(@as(usize, 0), self.node_b.sessions.challengeCount());
        return authenticated.event.request.message.ping.request_id;
    }

    fn completePong(
        self: *Pair,
        started: engine.StartResult,
        request_id: message.RequestId,
    ) !void {
        const pong = message.Message{ .pong = .{
            .request_id = request_id,
            .enr_sequence = self.record_b.sequence,
            .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
            .recipient_port = 9_001,
        } };
        const length = try self.node_b.sendResponse(
            &self.b_to_a,
            self.peerA(),
            &pong,
            6,
            startEntropy(0x70),
        );
        const completed = try self.node_a.receive(
            &self.a_to_b,
            self.b_to_a[0..length],
            self.address_b,
            receiveArgs(7, null, 0x80),
            &self.scratch_a,
        );
        try std.testing.expect(completed.event == .response);
        try std.testing.expect(completed.event.response.matched.terminal);
        try std.testing.expectEqual(started.handle, completed.event.response.matched.handle);
    }

    fn directSessionTimeout(self: *Pair) !void {
        const ping_message = self.ping(2);
        const started = try self.node_a.startCall(
            &self.a_to_b,
            self.peerB(),
            &ping_message,
            8,
            10,
            startEntropy(0x90),
        );
        const direct_packet = try packet.decode(
            self.a_to_b[0..started.packet_length],
            &self.record_b.node_id,
            &self.scratch_b.packet_decode,
        );
        try std.testing.expectEqualSlices(
            u8,
            &.{ 0, 0, 0, 2 },
            direct_packet.static_header.nonce[0..4],
        );
        const received = try self.node_b.receive(
            &self.b_to_a,
            self.a_to_b[0..started.packet_length],
            self.address_a,
            receiveArgs(9, null, 0xa0),
            &self.scratch_b,
        );
        try std.testing.expectEqual(@as(u16, 0), received.packet_length);
        try std.testing.expect(received.event == .request);
        try std.testing.expect(received.event.request.record == null);
        var expired: [1]calls.Handle = undefined;
        const tick = self.node_a.tick(18, 100, &expired);
        try std.testing.expectEqual(@as(usize, 1), tick.calls);
        try std.testing.expectEqual(started.handle, expired[0]);
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
    const record_b = try buildRecord(&key_b, 1, address(2, 9_002));
    var invalid: TestEngine = undefined;
    try std.testing.expectError(
        engine.Error.InvalidLocalRecord,
        invalid.init(key_a, record_b),
    );
}

fn buildRecord(
    key_pair: *const crypto.KeyPair,
    sequence: u64,
    endpoint: types.Address,
) !enr.Record {
    const ip4 = switch (endpoint) {
        .ip4 => |value| value,
        .ip6 => return error.UnsupportedTestAddress,
    };
    const public_key = crypto.compressedPublicKey(key_pair);
    var content_buffer: [300]u8 = undefined;
    var content_writer = rlp.Writer.init(&content_buffer);
    const content = try content_writer.beginList();
    try content_writer.writeUint(sequence);
    try content_writer.writeBytes("id");
    try content_writer.writeBytes("v4");
    try content_writer.writeBytes("ip");
    try content_writer.writeBytes(&ip4.octets);
    try content_writer.writeBytes("secp256k1");
    try content_writer.writeBytes(&public_key);
    try content_writer.writeBytes("udp");
    try content_writer.writeUint(ip4.port);
    content_writer.finishList(content);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(content_writer.bytes(), &digest, .{});
    const signature = try crypto.sign(&digest, key_pair);

    var full_buffer: [300]u8 = undefined;
    var full_writer = rlp.Writer.init(&full_buffer);
    const full = try full_writer.beginList();
    try full_writer.writeBytes(&signature);
    var content_reader = rlp.Reader.init(content_writer.bytes());
    var fields = try content_reader.readList();
    for (0..16) |_| {
        if (fields.atEnd()) break;
        try full_writer.writeRawItem(try fields.readRawItem());
    }
    try std.testing.expect(fields.atEnd());
    full_writer.finishList(full);
    return enr.Record.init(full_writer.bytes());
}

fn startEntropy(seed: u8) engine.StartEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce = [_]u8{seed +% 1} ** 12,
        .nonce_tail = [_]u8{seed +% 2} ** 8,
        .sessionless_key = [_]u8{seed +% 3} ** 16,
    };
}

fn receiveArgs(
    now_ms: u64,
    known_record: ?*const enr.Record,
    seed: u8,
) engine.ReceiveArgs {
    return .{
        .now_ms = now_ms,
        .response_timeout_ms = 100,
        .known_record = known_record,
        .entropy = .{
            .challenge_masking_iv = [_]u8{seed} ** 16,
            .id_nonce = [_]u8{seed +% 1} ** 16,
            .handshake_masking_iv = [_]u8{seed +% 2} ** 16,
            .handshake_nonce_tail = [_]u8{seed +% 3} ** 8,
            .ephemeral_secret = [_]u8{seed +% 4} ** 32,
        },
    };
}

fn address(id: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ 127, 0, 0, id }, .port = port } };
}
