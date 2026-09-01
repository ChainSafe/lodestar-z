const std = @import("std");

pub const NodeId = [32]u8;

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
