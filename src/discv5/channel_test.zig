const std = @import("std");
const channel = @import("channel.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const packet = @import("wire/packet.zig");

test "cold packet is challenged and the handshake delivers the sender record" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const plaintext = "ping";
    const length = try pair.challengeAndHandshake(plaintext, null, 1);
    const handshake_packet = try packet.decode(
        pair.a_to_b[0..length],
        &pair.record_b.node_id,
        &pair.scratch.packet_decode,
    );
    try std.testing.expect(handshake_packet.form.handshake.enr != null);

    const inbound = pair.node_b.receive(
        pair.a_to_b[0..length],
        pair.address_a,
        2,
        &pair.scratch,
    );
    try std.testing.expect(inbound == .authenticated);
    try std.testing.expectEqualSlices(u8, plaintext, inbound.authenticated.plaintext);
    try std.testing.expectEqual(pair.record_a.node_id, inbound.authenticated.record.?.node_id);
    try std.testing.expect(pair.node_a.hasSession(pair.peerB()));
    try std.testing.expect(pair.node_b.hasSession(pair.peerA()));
    try std.testing.expectEqual(@as(usize, 0), pair.node_b.sessions.challengeCount());

    const entropy = sealEntropy(0x40);
    const reply = try pair.node_b.sealEstablished(&pair.b_to_a, pair.peerA(), "pong", &entropy, 3);
    const answered = pair.node_a.receive(
        pair.b_to_a[0..reply.packet_length],
        pair.address_b,
        3,
        &pair.scratch,
    );
    try std.testing.expect(answered == .authenticated);
    try std.testing.expectEqualSlices(u8, "pong", answered.authenticated.plaintext);
    try std.testing.expect(answered.authenticated.record == null);
}

test "handshake omits the local record when the challenger already knows it" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const length = try pair.challengeAndHandshake("ping", pair.identityA(), 1);
    const handshake_packet = try packet.decode(
        pair.a_to_b[0..length],
        &pair.record_b.node_id,
        &pair.scratch.packet_decode,
    );
    try std.testing.expect(handshake_packet.form.handshake.enr == null);

    const inbound = pair.node_b.receive(
        pair.a_to_b[0..length],
        pair.address_a,
        2,
        &pair.scratch,
    );
    try std.testing.expect(inbound == .authenticated);
    try std.testing.expect(inbound.authenticated.record == null);
    try std.testing.expect(pair.node_b.hasSession(pair.peerA()));
}

test "handshake without a record needs an identity captured at challenge time" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const who = try pair.challenge("ping", null, 1);
    const entropy = handshakeEntropy(0x30);
    const handshake = try pair.node_a.handshake(&pair.a_to_b, .{
        .peer = pair.peerB(),
        .remote_public_key = &pair.record_b.public_key,
        .plaintext = "ping",
        .challenge_data = &who.challenge_data,
        .enr_sequence = pair.record_a.sequence,
        .entropy = &entropy,
        .now_ms = 1,
    });
    const inbound = pair.node_b.receive(
        pair.a_to_b[0..handshake.packet_length],
        pair.address_a,
        2,
        &pair.scratch,
    );
    try std.testing.expectEqual(types.RejectReason.invalid_handshake, inbound.rejected);
    try std.testing.expectEqual(@as(usize, 0), pair.node_b.sessions.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), pair.node_b.sessions.challengeCount());
}

test "corrupted handshake fails decryption and keeps the challenge" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const length = try pair.challengeAndHandshake("ping", null, 1);
    pair.a_to_b[length - 1] ^= 1;
    const corrupted = pair.node_b.receive(pair.a_to_b[0..length], pair.address_a, 2, &pair.scratch);
    try std.testing.expectEqual(types.RejectReason.invalid_handshake, corrupted.rejected);
    try std.testing.expectEqual(@as(usize, 0), pair.node_b.sessions.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), pair.node_b.sessions.challengeCount());

    pair.a_to_b[length - 1] ^= 1;
    const inbound = pair.node_b.receive(
        pair.a_to_b[0..length],
        pair.address_a,
        3,
        &pair.scratch,
    );
    try std.testing.expect(inbound == .authenticated);
    try std.testing.expectEqual(@as(usize, 0), pair.node_b.sessions.challengeCount());
}

test "a pending challenge is not reissued for the same peer" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const entropy = sealEntropy(0x10);
    const sealed = try pair.node_a.seal(&pair.a_to_b, pair.peerB(), "ping", &entropy, 1);
    const inbound = pair.node_b.receive(
        pair.a_to_b[0..sealed.packet_length],
        pair.address_a,
        1,
        &pair.scratch,
    );
    const unauthenticated = inbound.unauthenticated;
    const challenge_entropy = challengeEntropy(0x20);
    try std.testing.expect((try pair.node_b.challenge(
        &pair.b_to_a,
        unauthenticated.peer,
        &unauthenticated.request_nonce,
        null,
        &challenge_entropy,
        1,
    )) != null);
    try std.testing.expect((try pair.node_b.challenge(
        &pair.b_to_a,
        unauthenticated.peer,
        &unauthenticated.request_nonce,
        null,
        &challenge_entropy,
        2,
    )) == null);
    try std.testing.expectEqual(@as(usize, 1), pair.node_b.sessions.challengeCount());
}

test "handshake rejects a request that cannot fit beside the local record" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const plaintext = [_]u8{0x55} ** 1_100;
    const who = try pair.challenge(&plaintext, null, 1);
    const entropy = handshakeEntropy(0x30);
    try std.testing.expectError(channel.Error.RequestTooLargeForHandshake, pair.node_a.handshake(
        &pair.a_to_b,
        .{
            .peer = pair.peerB(),
            .remote_public_key = &pair.record_b.public_key,
            .plaintext = &plaintext,
            .challenge_data = &who.challenge_data,
            .enr_sequence = who.enr_sequence,
            .entropy = &entropy,
            .now_ms = 1,
        },
    ));
    try std.testing.expect(!pair.node_a.hasSession(pair.peerB()));
}

test "established seal requires a session" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    const entropy = sealEntropy(0x10);
    try std.testing.expectError(
        channel.Error.MissingSession,
        pair.node_a.sealEstablished(&pair.a_to_b, pair.peerB(), "ping", &entropy, 1),
    );
}

test "expire removes stale challenges and idle sessions" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();

    _ = try pair.challenge("ping", null, 1);
    try std.testing.expectEqual(@as(usize, 1), pair.node_b.sessions.challengeCount());
    const challenges = pair.node_b.expire(1 + testConfig().challenge_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), challenges.challenges);
    try std.testing.expectEqual(@as(usize, 0), pair.node_b.sessions.challengeCount());

    const length = try pair.challengeAndHandshake("ping", null, 200);
    _ = pair.node_b.receive(pair.a_to_b[0..length], pair.address_a, 200, &pair.scratch);
    try std.testing.expect(pair.node_b.hasSession(pair.peerA()));
    const sessions = pair.node_b.expire(200 + testConfig().session_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), sessions.sessions);
    try std.testing.expect(!pair.node_b.hasSession(pair.peerA()));
}

test "channel rejects a foreign local record and zero timeouts" {
    const key_a = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const key_b = try crypto.keyPairFromSecret(&([_]u8{0x22} ** 32));
    const record_b = try test_support.buildRecord(&key_b, 1, address(2, 9_002));
    var invalid: channel.Channel = undefined;
    try std.testing.expectError(
        channel.Error.InvalidLocalRecord,
        invalid.init(std.testing.allocator, key_a, record_b, testConfig()),
    );
    var config = testConfig();
    config.session_idle_timeout_ms = 0;
    try std.testing.expectError(
        channel.Error.InvalidTimeout,
        invalid.init(std.testing.allocator, key_b, record_b, config),
    );
}

const Pair = struct {
    address_a: types.Address,
    address_b: types.Address,
    record_a: enr.Record,
    record_b: enr.Record,
    node_a: channel.Channel,
    node_b: channel.Channel,
    scratch: channel.Scratch,
    a_to_b: [constants.packet_size_max]u8,
    b_to_a: [constants.packet_size_max]u8,

    fn init(self: *Pair) !void {
        self.address_a = address(1, 9_001);
        self.address_b = address(2, 9_002);
        const key_a = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
        const key_b = try crypto.keyPairFromSecret(&([_]u8{0x22} ** 32));
        self.record_a = try test_support.buildRecord(&key_a, 1, self.address_a);
        self.record_b = try test_support.buildRecord(&key_b, 1, self.address_b);
        try self.node_a.init(std.testing.allocator, key_a, self.record_a, testConfig());
        errdefer self.node_a.deinit();
        try self.node_b.init(std.testing.allocator, key_b, self.record_b, testConfig());
        self.scratch = .{};
    }

    fn deinit(self: *Pair) void {
        self.node_b.deinit();
        self.node_a.deinit();
    }

    fn peerA(self: *const Pair) types.Endpoint {
        return .{ .node_id = self.record_a.node_id, .address = self.address_a };
    }

    fn peerB(self: *const Pair) types.Endpoint {
        return .{ .node_id = self.record_b.node_id, .address = self.address_b };
    }

    fn identityA(self: *const Pair) channel.KnownIdentity {
        return .{ .sequence = self.record_a.sequence, .public_key = self.record_a.public_key };
    }

    /// A sends a cold packet and B challenges it. Returns the WHOAREYOU as A decoded it.
    fn challenge(
        self: *Pair,
        plaintext: []const u8,
        known: ?channel.KnownIdentity,
        now_ms: u64,
    ) !channel.Whoareyou {
        const seal_entropy = sealEntropy(0x10);
        const sealed = try self.node_a.seal(
            &self.a_to_b,
            self.peerB(),
            plaintext,
            &seal_entropy,
            now_ms,
        );
        const inbound = self.node_b.receive(
            self.a_to_b[0..sealed.packet_length],
            self.address_a,
            now_ms,
            &self.scratch,
        );
        try std.testing.expect(inbound == .unauthenticated);
        try std.testing.expectEqual(sealed.nonce, inbound.unauthenticated.request_nonce);
        const challenge_entropy = challengeEntropy(0x20);
        const length = (try self.node_b.challenge(
            &self.b_to_a,
            inbound.unauthenticated.peer,
            &inbound.unauthenticated.request_nonce,
            known,
            &challenge_entropy,
            now_ms,
        )).?;
        try std.testing.expectEqual(@as(u16, constants.whoareyou_packet_size), length);
        const who = self.node_a.receive(
            self.b_to_a[0..length],
            self.address_b,
            now_ms,
            &self.scratch,
        );
        try std.testing.expect(who == .whoareyou);
        try std.testing.expectEqual(sealed.nonce, who.whoareyou.request_nonce);
        return who.whoareyou;
    }

    /// Runs `challenge` and answers it. Returns the handshake packet length in `a_to_b`.
    fn challengeAndHandshake(
        self: *Pair,
        plaintext: []const u8,
        known: ?channel.KnownIdentity,
        now_ms: u64,
    ) !u16 {
        const who = try self.challenge(plaintext, known, now_ms);
        const entropy = handshakeEntropy(0x30);
        const handshake = try self.node_a.handshake(&self.a_to_b, .{
            .peer = self.peerB(),
            .remote_public_key = &self.record_b.public_key,
            .plaintext = plaintext,
            .challenge_data = &who.challenge_data,
            .enr_sequence = who.enr_sequence,
            .entropy = &entropy,
            .now_ms = now_ms,
        });
        try std.testing.expectEqual(channel.handshakeNonce(&entropy), handshake.nonce);
        return handshake.packet_length;
    }
};

fn testConfig() channel.Config {
    return .{
        .session_capacity = 4,
        .challenge_capacity = 4,
        .challenge_timeout_ms = 100,
        .session_idle_timeout_ms = 1_000,
    };
}

fn sealEntropy(seed: u8) channel.SealEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce = [_]u8{seed +% 1} ** 12,
        .nonce_tail = [_]u8{seed +% 2} ** 8,
        .sessionless_key = [_]u8{seed +% 3} ** 16,
    };
}

fn challengeEntropy(seed: u8) channel.ChallengeEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .id_nonce = [_]u8{seed +% 1} ** 16,
    };
}

fn handshakeEntropy(seed: u8) channel.HandshakeEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce_tail = [_]u8{seed +% 1} ** 8,
        .ephemeral_secret = [_]u8{seed +% 2} ** 32,
    };
}

fn address(id: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ 127, 0, 0, id }, .port = port } };
}
