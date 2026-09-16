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

    pub fn isUsable(self: Address) bool {
        if (self == .ip6 and isIp4Mapped(self.ip6.octets)) return false;
        return switch (self) {
            inline else => |value| value.port != 0 and !std.mem.allEqual(u8, &value.octets, 0),
        };
    }

    pub fn isIp4Mapped(ip: [16]u8) bool {
        return std.mem.allEqual(u8, ip[0..10], 0) and ip[10] == 0xff and ip[11] == 0xff;
    }

    pub fn fromNetwork(address: std.Io.net.IpAddress) Address {
        return switch (address) {
            .ip4 => |ip| .{ .ip4 = .{ .octets = ip.bytes, .port = ip.port } },
            .ip6 => |ip| if (isIp4Mapped(ip.bytes))
                .{ .ip4 = .{ .octets = ip.bytes[12..16].*, .port = ip.port } }
            else
                .{ .ip6 = .{ .octets = ip.bytes, .port = ip.port, .interface = ip.interface.index } },
        };
    }

    pub fn toNetwork(self: Address) std.Io.net.IpAddress {
        return switch (self) {
            .ip4 => |ip| .{ .ip4 = .{ .bytes = ip.octets, .port = ip.port } },
            .ip6 => |ip| .{ .ip6 = .{ .bytes = ip.octets, .port = ip.port, .flow = 0, .interface = .{ .index = ip.interface } } },
        };
    }

    pub fn eql(self: Address, other: Address) bool {
        return std.meta.eql(self, other);
    }

    /// Handshake admission groups IPv4 hosts and IPv6 /64 prefixes.
    pub fn sameSourceGroup(self: Address, other: Address) bool {
        return switch (self) {
            .ip4 => |value| switch (other) {
                .ip4 => |peer| std.mem.eql(u8, &value.octets, &peer.octets),
                .ip6 => false,
            },
            .ip6 => |value| switch (other) {
                .ip4 => false,
                .ip6 => |peer| std.mem.eql(u8, value.octets[0..8], peer.octets[0..8]),
            },
        };
    }
};

test "handshake source grouping ignores ports and groups IPv6 prefixes" {
    const a: Address = .{ .ip6 = .{ .octets = .{ 0x20, 1, 0xd, 0xb8 } ++ .{0} ** 11 ++ .{1}, .port = 1 } };
    var b = a;
    b.ip6.octets[15] = 2;
    b.ip6.port = 2;
    b.ip6.interface = 3;
    try std.testing.expect(a.sameSourceGroup(b));
    b.ip6.octets[7] = 1;
    try std.testing.expect(!a.sameSourceGroup(b));
    const v4: Address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } };
    try std.testing.expect(v4.sameSourceGroup(.{ .ip4 = .{ .octets = v4.ip4.octets, .port = 2 } }));
    try std.testing.expect(!v4.sameSourceGroup(.{ .ip4 = .{ .octets = .{ 192, 0, 2, 2 }, .port = 1 } }));
    try std.testing.expect(!a.sameSourceGroup(v4));
}
