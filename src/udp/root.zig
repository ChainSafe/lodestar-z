//! UDP address values and owned sockets for native and supplied I/O providers.

pub const Address = @import("address.zig").Address;
pub const Sockets = @import("sockets.zig").Sockets;
pub const testing = if (@import("builtin").is_test) @import("test_io.zig") else struct {};

test {
    _ = Address;
    _ = @import("sockets.zig");
    _ = testing;
}
