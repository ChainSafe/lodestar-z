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

    pub fn eql(left: Address, right: Address) bool {
        return switch (left) {
            .ip4 => |value| switch (right) {
                .ip4 => |other| value.port == other.port and
                    std.mem.eql(u8, &value.octets, &other.octets),
                .ip6 => false,
            },
            .ip6 => |value| switch (right) {
                .ip4 => false,
                .ip6 => |other| value.port == other.port and
                    value.interface == other.interface and
                    std.mem.eql(u8, &value.octets, &other.octets),
            },
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

    pub fn eql(left: Endpoint, right: Endpoint) bool {
        return std.mem.eql(u8, &left.node_id, &right.node_id) and
            Address.eql(left.address, right.address);
    }
};

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
