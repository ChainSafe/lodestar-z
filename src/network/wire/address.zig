const std = @import("std");

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

    pub const unspecified: Address = .{ .ip4 = .{ .octets = .{ 0, 0, 0, 0 }, .port = 0 } };

    pub fn port(self: Address) u16 {
        return switch (self) {
            .ip4 => |value| value.port,
            .ip6 => |value| value.port,
        };
    }

    pub fn eql(self: Address, other: Address) bool {
        return std.meta.eql(self, other);
    }

    pub fn sameHost(self: Address, other: Address) bool {
        return switch (self) {
            .ip4 => |value| switch (other) {
                .ip4 => |peer| std.mem.eql(u8, &value.octets, &peer.octets),
                .ip6 => false,
            },
            .ip6 => |value| switch (other) {
                .ip4 => false,
                .ip6 => |peer| std.mem.eql(u8, &value.octets, &peer.octets),
            },
        };
    }
};
