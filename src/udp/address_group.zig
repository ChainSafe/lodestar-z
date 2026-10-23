const std = @import("std");
const Address = @import("address.zig").Address;

/// IPv4 /24 and IPv6 /48 resource groups, independent of ports and interface scopes.
pub const Group = union(enum) {
    ip4: [3]u8,
    ip6: [6]u8,

    pub fn fromAddress(address: *const Address) Group {
        return switch (address.*) {
            .ip4 => |ip| .{ .ip4 = ip.octets[0..3].* },
            .ip6 => |ip| if (Address.isIp4Mapped(ip.octets))
                .{ .ip4 = ip.octets[12..15].* }
            else
                .{ .ip6 = ip.octets[0..6].* },
        };
    }

    pub fn eql(self: Group, other: Group) bool {
        return std.meta.eql(self, other);
    }
};

test {
    _ = @import("address_group_test.zig");
}
