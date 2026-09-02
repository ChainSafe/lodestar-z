pub const keys = @import("keys.zig");
pub const peer_id = @import("peer_id.zig");
pub const multiaddr = @import("multiaddr.zig");

test {
    _ = keys;
    _ = peer_id;
    _ = multiaddr;
    _ = @import("keys_test.zig");
    _ = @import("peer_id_test.zig");
    _ = @import("multiaddr_test.zig");
}
