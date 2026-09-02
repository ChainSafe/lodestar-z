pub const keys = @import("keys.zig");
pub const peer_id = @import("peer_id.zig");

test {
    _ = keys;
    _ = peer_id;
    _ = @import("keys_test.zig");
    _ = @import("peer_id_test.zig");
}
