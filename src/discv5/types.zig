const std = @import("std");

pub const NodeId = [32]u8;

pub fn logDistance(left: *const NodeId, right: *const NodeId) u16 {
    for (left, right, 0..) |left_byte, right_byte, index| {
        const difference = left_byte ^ right_byte;
        if (difference == 0) continue;
        const leading: u16 = @intCast(@clz(difference));
        return @intCast(256 - index * 8 - leading);
    }
    return 0;
}

pub fn xorCloser(
    left: *const NodeId,
    right: *const NodeId,
    target: *const NodeId,
) bool {
    for (left, right, target) |left_byte, right_byte, target_byte| {
        const left_distance = left_byte ^ target_byte;
        const right_distance = right_byte ^ target_byte;
        if (left_distance != right_distance) return left_distance < right_distance;
    }
    return false;
}

pub const Address = union(enum) {
    ip4: struct {
        octets: [4]u8,
        port: u16,
    },
    ip6: struct {
        octets: [16]u8,
        port: u16,
        interface: u32 = 0,
    },

    pub fn port(self: Address) u16 {
        return switch (self) {
            inline else => |value| value.port,
        };
    }

    pub fn isUsable(self: Address) bool {
        return switch (self) {
            inline else => |value| value.port != 0 and !std.mem.allEqual(u8, &value.octets, 0),
        };
    }
};

pub fn relayAllowed(source: Address, candidate: Address) bool {
    const source_class = addressClass(source);
    const candidate_class = addressClass(candidate);
    if (source_class == .invalid or candidate_class == .invalid) return false;
    return switch (candidate_class) {
        .public => true,
        .private, .loopback, .link_local => source_class == candidate_class and
            std.meta.activeTag(source) == std.meta.activeTag(candidate),
        .invalid => false,
    };
}

pub const Endpoint = struct {
    node_id: NodeId,
    address: Address,
};

/// Why an authenticated-or-not datagram was not acted on. Every arm is caused by the peer.
pub const RejectReason = enum {
    malformed_packet,
    malformed_message,
    invalid_record,
    unexpected_handshake,
    invalid_handshake,
    unexpected_challenge,
    request_too_large,
    unsolicited_response,
    invalid_response,
};

/// Keeps `out[0..length]` ordered by XOR distance to `target`, dropping the farthest when full.
pub fn insertClosest(
    comptime T: type,
    comptime nodeIdOf: fn (*const T) *const NodeId,
    out: []T,
    length: usize,
    item: T,
    target: *const NodeId,
) usize {
    std.debug.assert(length <= out.len);
    var position: usize = 0;
    while (position < length and !xorCloser(nodeIdOf(&item), nodeIdOf(&out[position]), target)) {
        position += 1;
    }
    if (position == out.len) return length;
    const new_length = @min(length + 1, out.len);
    std.mem.copyBackwards(T, out[position + 1 .. new_length], out[position .. new_length - 1]);
    out[position] = item;
    return new_length;
}

const AddressClass = enum {
    invalid,
    public,
    private,
    loopback,
    link_local,
};

fn addressClass(address: Address) AddressClass {
    return switch (address) {
        .ip4 => |value| classifyIp4(value.octets),
        .ip6 => |value| classifyIp6(value.octets),
    };
}

fn classifyIp4(ip: [4]u8) AddressClass {
    if (ip[0] == 0 or ip[0] >= 224) return .invalid;
    if (ip[0] == 127) return .loopback;
    if (ip[0] == 169 and ip[1] == 254) return .link_local;
    if (ip[0] == 10 or
        (ip[0] == 100 and ip[1] >= 64 and ip[1] <= 127) or
        (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) or
        (ip[0] == 192 and ip[1] == 168)) return .private;
    return .public;
}

fn classifyIp6(ip: [16]u8) AddressClass {
    if (std.mem.eql(u8, &ip, &([_]u8{0} ** 16)) or ip[0] == 0xff) return .invalid;
    if (std.mem.eql(u8, ip[0..15], &([_]u8{0} ** 15)) and ip[15] == 1)
        return .loopback;
    if (std.mem.eql(u8, ip[0..10], &([_]u8{0} ** 10)) and
        ip[10] == 0xff and ip[11] == 0xff)
    {
        return classifyIp4(ip[12..16].*);
    }
    if (std.mem.eql(u8, ip[0..12], &([_]u8{0} ** 12))) return .invalid;
    if (ip[0] == 0xfe and ip[1] & 0xc0 == 0x80) return .link_local;
    if (ip[0] & 0xfe == 0xfc or
        (ip[0] == 0xfe and ip[1] & 0xc0 == 0xc0)) return .private;
    return .public;
}
