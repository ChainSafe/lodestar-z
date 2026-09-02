const std = @import("std");
const Channel = @import("Channel.zig");
const crypto = @import("identity/crypto.zig");
const Engine = @import("Engine.zig");
const enr = @import("identity/enr.zig");
const SessionStore = @import("SessionStore.zig");
const types = @import("types.zig");

pub fn keyPair(seed: u8) !crypto.KeyPair {
    return crypto.keyPairFromSecret(&([_]u8{seed} ** 32));
}

pub fn address4(a: u8, b: u8, c: u8, d: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ a, b, c, d }, .port = port } };
}

pub fn address6(octets: [16]u8, port: u16) types.Address {
    return .{ .ip6 = .{ .octets = octets, .port = port } };
}

pub fn loopback(id: u8, port: u16) types.Address {
    return address4(127, 0, 0, id, port);
}

pub fn endpoint(rec: *const enr.Record) types.Endpoint {
    return .{ .node_id = rec.node_id, .address = rec.endpoint().? };
}

pub fn fakeEndpoint(id: u8, port: u16) types.Endpoint {
    return .{ .node_id = [_]u8{id} ** 32, .address = loopback(id, port) };
}

pub fn fakeRecord(node_id: types.NodeId, address: types.Address, sequence: u64) enr.Record {
    var rec = std.mem.zeroes(enr.Record);
    rec.node_id = node_id;
    rec.sequence = sequence;
    switch (address) {
        .ip4 => |value| {
            rec.ip4 = value.octets;
            rec.udp = value.port;
        },
        .ip6 => |value| {
            rec.ip6 = value.octets;
            rec.udp6 = value.port;
        },
    }
    return rec;
}

pub fn installSession(core: *Engine, peer: types.Endpoint, key_byte: u8) void {
    const key = [_]u8{key_byte} ** 16;
    const active = SessionStore.Session{ .read_key = key, .write_key = key };
    core.channel.sessions.install(peer, &active, 0);
}

pub fn sealEntropy(seed: u8) Channel.SealEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce = [_]u8{seed +% 1} ** 12,
        .nonce_tail = [_]u8{seed +% 2} ** 8,
        .sessionless_key = [_]u8{seed +% 3} ** 16,
    };
}

pub fn challengeEntropy(seed: u8) Channel.ChallengeEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .id_nonce = [_]u8{seed +% 1} ** 16,
    };
}

pub fn handshakeEntropy(seed: u8) Channel.HandshakeEntropy {
    return .{
        .masking_iv = [_]u8{seed} ** 16,
        .nonce_tail = [_]u8{seed +% 1} ** 8,
        .ephemeral_secret = [_]u8{seed +% 2} ** 32,
    };
}

pub fn receiveArgs(now_ms: u64, seed: u8) Engine.ReceiveArgs {
    return .{
        .now_ms = now_ms,
        .entropy = .{
            .challenge = challengeEntropy(seed),
            .handshake = handshakeEntropy(seed +% 2),
        },
    };
}

pub fn engineConfig() Engine.Config {
    return .{
        .session_capacity = 4,
        .challenge_capacity = 4,
        .call_capacity = 4,
        .request_timeout_ms = 100,
        .challenge_timeout_ms = 100,
        .session_idle_timeout_ms = 1_000,
    };
}

pub fn channelConfig() Channel.Config {
    return .{
        .session_capacity = 4,
        .challenge_capacity = 4,
        .challenge_timeout_ms = 100,
        .session_idle_timeout_ms = 1_000,
    };
}
