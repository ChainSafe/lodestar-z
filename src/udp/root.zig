//! UDP address values and owned sockets for native and supplied I/O providers.

pub const Address = @import("address.zig").Address;
pub const Sockets = @import("sockets.zig").Sockets;

test {
    _ = Address;
    _ = @import("sockets.zig");
}
