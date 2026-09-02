pub const signed_key = @import("signed_key.zig");
pub const cert = @import("cert.zig");

test {
    _ = signed_key;
    _ = cert;
    _ = @import("signed_key_test.zig");
    _ = @import("cert_test.zig");
}
