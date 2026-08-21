const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");

const Signature = bls.Signature;
const BlstError = bls.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len == 0 or len > Signature.SERIALIZE_SIZE) return;
    const input = buf[0..len];

    const sig = Signature.sigValidate(input, true) catch |err| {
        switch (err) {
            BlstError.BadEncoding, BlstError.PointNotOnCurve, BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
            else => @panic("unexpected signature decode error"),
        }
    };

    const encoded = sig.serialize();
    const sig2 = Signature.sigValidate(&encoded, true) catch
        @panic("validated signature failed revalidation");
    const encoded2 = sig2.serialize();
    assert(std.mem.eql(u8, &encoded, &encoded2));
}
