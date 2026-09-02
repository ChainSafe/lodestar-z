pub const codec = @import("codec.zig");
pub const constants = @import("constants.zig");
pub const protocol = @import("protocol.zig");

pub const Protocol = protocol.Protocol;
pub const Info = protocol.Info;

test {
    _ = codec;
    _ = constants;
    _ = protocol;
    _ = @import("codec_test.zig");
    _ = @import("protocol_test.zig");
}
