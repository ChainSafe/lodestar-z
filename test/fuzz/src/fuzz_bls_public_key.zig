const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");

const PublicKey = bls.PublicKey;
const blstError = bls.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len == 0) return;
    if (len > PublicKey.SERIALIZE_SIZE) return;
    const input = buf[0..len];

    const pk = PublicKey.keyValidate(input) catch |err| {
        switch (err) {
            blstError.BadEncoding, blstError.PointNotOnCurve, blstError.PointNotInGroup, blstError.PkIsInfinity => return,
            else => @panic("unexpected public key decode error"),
        }
    };

    const encoded = pk.serialize();
    const pk2 = PublicKey.keyValidate(&encoded) catch |err| {
        switch (err) {
            blstError.BadEncoding, blstError.PointNotOnCurve, blstError.PointNotInGroup, blstError.PkIsInfinity => return,
            else => @panic("unexpected public key roundtrip error"),
        }
    };
    const encoded2 = pk2.serialize();
    assert(std.mem.eql(u8, &encoded, &encoded2));
}
