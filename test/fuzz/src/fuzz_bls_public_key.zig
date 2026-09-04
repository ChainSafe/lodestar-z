const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");

const PublicKey = bls.PublicKey;
const blstError = bls.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    const input = buf[0..len];

    const pk = PublicKey.keyValidate(input) catch |err| {
        switch (err) {
            blstError.BadEncoding, blstError.PointNotOnCurve, blstError.PointNotInGroup, blstError.PkIsInfinity => return,
            else => @panic("unexpected public key decode error"),
        }
    };

    const encoded = pk.serialize();
    const pk2 = PublicKey.keyValidate(&encoded) catch
        @panic("validated public key failed revalidation");
    const encoded2 = pk2.serialize();
    assert(std.mem.eql(u8, &encoded, &encoded2));
}
