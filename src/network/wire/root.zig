pub const protobuf = @import("protobuf.zig");
pub const constants = @import("constants.zig");
pub const address = @import("address.zig");
pub const varint = @import("varint.zig");
pub const keys = @import("keys.zig");
pub const peer_id = @import("peer_id.zig");
pub const multiaddr = @import("multiaddr.zig");
pub const signed_key = @import("signed_key.zig");
pub const multistream = @import("multistream.zig");

test {
    _ = constants;
    _ = address;
    _ = varint;
    _ = keys;
    _ = peer_id;
    _ = multiaddr;
    _ = signed_key;
    _ = multistream;
    _ = @import("varint_test.zig");
    _ = @import("multistream_test.zig");
    _ = @import("keys_test.zig");
    _ = @import("peer_id_test.zig");
    _ = @import("multiaddr_test.zig");
    _ = @import("signed_key_test.zig");
}

test {
    _ = @import("protobuf_test.zig");
}
