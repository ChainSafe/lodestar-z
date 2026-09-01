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

pub const Address = union(enum) {
    ip4: struct {
        octets: [4]u8,
        port: u16,
    },
    ip6: struct {
        octets: [16]u8,
        port: u16,
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
                    std.mem.eql(u8, &value.octets, &other.octets),
            },
        };
    }
};

pub const Endpoint = struct {
    node_id: NodeId,
    address: Address,

    pub fn eql(left: Endpoint, right: Endpoint) bool {
        return std.mem.eql(u8, &left.node_id, &right.node_id) and
            Address.eql(left.address, right.address);
    }
};
