const std = @import("std");
const session = @import("session.zig");
const types = @import("types.zig");

test "session table keeps key direction and bounded nonces" {
    var table: session.Store = undefined;
    try table.init(std.testing.allocator, 2, 2);
    defer table.deinit();
    const peer = endpoint(1, 9_001);
    const read_key = [_]u8{0x11} ** 16;
    const write_key = [_]u8{0x22} ** 16;
    const active = session.Session{ .read_key = read_key, .write_key = write_key };
    table.install(peer, &active, 1);

    try std.testing.expectEqual(read_key, table.readKey(peer).?);
    try std.testing.expect(table.touch(peer, 2));
    const first = (try table.outbound(peer, &([_]u8{0x33} ** 8), 3)).?;
    try std.testing.expectEqual(write_key, first.write_key);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1 }, first.nonce[0..4]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x33} ** 8), first.nonce[4..]);
    const second = (try table.outbound(peer, &([_]u8{0x44} ** 8), 4)).?;
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 2 }, second.nonce[0..4]);
}

test "session table rejects zero and excessive configured capacities" {
    var table: session.Store = undefined;
    try std.testing.expectError(
        session.Error.InvalidCapacity,
        table.init(std.testing.allocator, 0, 1),
    );
    try std.testing.expectError(
        session.Error.InvalidCapacity,
        table.init(std.testing.allocator, session.session_capacity_max + 1, 1),
    );
    try std.testing.expectError(
        session.Error.InvalidCapacity,
        table.init(std.testing.allocator, 1, session.challenge_capacity_max + 1),
    );
}

test "nonce exhaustion retires the unusable session" {
    var table: session.Store = undefined;
    try table.init(std.testing.allocator, 1, 1);
    defer table.deinit();
    const peer = endpoint(1, 9_001);
    const key = [_]u8{0x11} ** 16;
    const active = session.Session{
        .read_key = key,
        .write_key = key,
        .nonce_counter = std.math.maxInt(u32),
    };
    table.install(peer, &active, 1);
    try std.testing.expectError(
        session.Error.NonceExhausted,
        table.outbound(peer, &([_]u8{0x22} ** 8), 2),
    );
    try std.testing.expectEqual(@as(usize, 0), table.sessionCount());
    try std.testing.expect((try table.outbound(peer, &([_]u8{0x22} ** 8), 3)) == null);
}

test "challenge churn preserves established sessions" {
    var table: session.Store = undefined;
    try table.init(std.testing.allocator, 1, 2);
    defer table.deinit();
    const established = endpoint(1, 9_001);
    const key = [_]u8{0x11} ** 16;
    const active = session.Session{ .read_key = key, .write_key = key };
    table.install(established, &active, 1);
    const challenge = [_]u8{0x55} ** 63;
    try std.testing.expect(table.putChallenge(endpoint(2, 9_002), &challenge, null, 2));
    try std.testing.expect(table.putChallenge(endpoint(3, 9_003), &challenge, null, 3));
    try std.testing.expect(table.putChallenge(endpoint(4, 9_004), &challenge, null, 4));

    try std.testing.expectEqual(@as(usize, 1), table.sessionCount());
    try std.testing.expectEqual(key, table.readKey(established).?);
    try std.testing.expect(table.getChallenge(endpoint(2, 9_002)) == null);
    try std.testing.expect(table.getChallenge(endpoint(3, 9_003)) != null);
    try std.testing.expect(table.getChallenge(endpoint(4, 9_004)) != null);
}

test "install consumes a challenge and expiration removes pending challenges" {
    var table: session.Store = undefined;
    try table.init(std.testing.allocator, 2, 2);
    defer table.deinit();
    const peer = endpoint(1, 9_001);
    const challenge = [_]u8{0x55} ** 63;
    try std.testing.expect(table.putChallenge(peer, &challenge, null, 10));
    var replacement = challenge;
    replacement[0] = 0x66;
    try std.testing.expect(!table.putChallenge(peer, &replacement, null, 11));
    try std.testing.expectEqual(challenge, table.getChallenge(peer).?.data);
    try std.testing.expectEqual(@as(usize, 0), table.expireChallenges(19, 10));
    const key = [_]u8{0x11} ** 16;
    const active = session.Session{ .read_key = key, .write_key = key };
    table.install(peer, &active, 20);
    try std.testing.expectEqual(@as(usize, 0), table.challengeCount());

    try std.testing.expect(table.putChallenge(endpoint(2, 9_002), &challenge, null, 30));
    try std.testing.expectEqual(@as(usize, 1), table.expireChallenges(40, 10));
    try std.testing.expectEqual(@as(usize, 0), table.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), table.sessionCount());
}

test "idle session expiration is independent from challenges" {
    var table: session.Store = undefined;
    try table.init(std.testing.allocator, 1, 1);
    defer table.deinit();
    const peer = endpoint(1, 9_001);
    const key = [_]u8{0x11} ** 16;
    const active = session.Session{ .read_key = key, .write_key = key };
    table.install(peer, &active, 10);
    const challenge = [_]u8{0x55} ** 63;
    try std.testing.expect(table.putChallenge(endpoint(2, 9_002), &challenge, null, 15));
    try std.testing.expectEqual(key, table.readKey(peer).?);
    try std.testing.expectEqual(@as(usize, 1), table.expireSessions(20, 10));
    try std.testing.expectEqual(@as(usize, 0), table.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), table.challengeCount());
}

fn endpoint(id: u8, port: u16) types.Endpoint {
    return .{
        .node_id = [_]u8{id} ** 32,
        .address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, id }, .port = port } },
    };
}
