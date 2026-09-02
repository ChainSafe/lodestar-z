pub const constants = @import("constants.zig");
pub const types = @import("types.zig");
pub const varint = @import("varint.zig");
pub const multistream = @import("multistream.zig");
pub const keys = @import("identity/keys.zig");
pub const peer_id = @import("identity/peer_id.zig");
pub const multiaddr = @import("identity/multiaddr.zig");
pub const signed_key = @import("tls/signed_key.zig");

test {
    _ = constants;
    _ = types;
    _ = varint;
    _ = multistream;
    _ = keys;
    _ = peer_id;
    _ = multiaddr;
    _ = signed_key;
    _ = @import("varint_test.zig");
    _ = @import("multistream_test.zig");
    _ = @import("identity/keys_test.zig");
    _ = @import("identity/peer_id_test.zig");
    _ = @import("identity/multiaddr_test.zig");
    _ = @import("tls/signed_key_test.zig");
}
