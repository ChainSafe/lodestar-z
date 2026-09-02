pub const constants = @import("constants.zig");
pub const types = @import("types.zig");
pub const varint = @import("varint.zig");
pub const multistream = @import("multistream.zig");
pub const identity = @import("identity/root.zig");
pub const quic = @import("quic/root.zig");
pub const tls = @import("tls/root.zig");
pub const runtime = @import("runtime.zig");
pub const driver = @import("driver.zig");

test {
    _ = constants;
    _ = types;
    _ = varint;
    _ = multistream;
    _ = identity;
    _ = quic;
    _ = tls;
    _ = runtime;
    _ = driver;
    _ = @import("varint_test.zig");
    _ = @import("multistream_test.zig");
    _ = @import("runtime_test.zig");
    _ = @import("driver_test.zig");
}
