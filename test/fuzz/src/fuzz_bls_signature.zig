const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");

const Signature = bls.Signature;
const BlstError = bls.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len == 0 or len > Signature.SERIALIZE_SIZE) return;
    const input = buf[0..len];

    const sig = Signature.deserialize(input) catch |err| {
        switch (err) {
            BlstError.BadEncoding, BlstError.PointNotOnCurve, BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
            else => @panic("unexpected signature decode error"),
        }
    };

    sig.validate(true) catch |err| {
        switch (err) {
            BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
            else => @panic("unexpected signature validation error"),
        }
    };

    const encoded = sig.serialize();
    const sig2 = Signature.deserialize(&encoded) catch |err| {
        switch (err) {
            BlstError.BadEncoding, BlstError.PointNotOnCurve, BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
            else => @panic("unexpected signature roundtrip error"),
        }
    };
    sig2.validate(true) catch |err| {
        switch (err) {
            BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
            else => @panic("unexpected signature validation error"),
        }
    };
    const encoded2 = sig2.serialize();
    assert(std.mem.eql(u8, &encoded, &encoded2));
}
