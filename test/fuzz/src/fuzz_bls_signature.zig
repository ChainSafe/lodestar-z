const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");
const oracle = @import("bls_oracle.zig");

const Signature = bls.Signature;
const BlstError = bls.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    const input = buf[0..len];
    if (len <= oracle.generated_input_len_max) fuzzGenerated(input);

    const sig = Signature.sigValidate(input, true) catch |err| {
        switch (err) {
            BlstError.BadEncoding, BlstError.PointNotOnCurve, BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
            else => @panic("unexpected signature decode error"),
        }
    };

    const encoded = sig.serialize();
    if (input.len == Signature.COMPRESS_SIZE) {
        const compressed = sig.compress();
        assert(std.mem.eql(u8, input, &compressed));
    } else {
        assert(std.mem.eql(u8, input, &encoded));
    }
    const sig2 = Signature.sigValidate(&encoded, true) catch
        @panic("validated signature failed revalidation");
    assert(sig.isEqual(&sig2));
}

fn fuzzGenerated(input: []const u8) void {
    var message: bls.SigningRoot = @splat(0);
    @memcpy(message[0..input.len], input);
    const scalar = @as(u64, std.mem.readInt(u32, message[0..4], .little)) + 1;
    const secret_key = oracle.secretKey(scalar);
    const public_key = secret_key.toPublicKey();
    const expected = secret_key.sign(&message, bls.DST, null);
    const compressed = expected.compress();
    const decoded_compressed = Signature.sigValidate(&compressed, true) catch
        @panic("generated compressed signature rejected");
    assert(expected.isEqual(&decoded_compressed));
    const serialized = expected.serialize();
    const decoded_serialized = Signature.sigValidate(&serialized, true) catch
        @panic("generated serialized signature rejected");
    assert(expected.isEqual(&decoded_serialized));
    decoded_compressed.verify(true, &message, bls.DST, null, &public_key, true) catch
        @panic("generated signature failed verification");
    message[0] ^= 1;
    if (decoded_compressed.verify(true, &message, bls.DST, null, &public_key, true)) {
        @panic("signature accepted a changed message");
    } else |err| {
        assert(err == BlstError.VerifyFail);
    }
}

test "signature oracle covers generated signatures and both raw encodings" {
    for ([_]u8{ 0, 1, 255 }) |byte| {
        const message: bls.SigningRoot = @splat(byte);
        zig_fuzz_test(&message, 0);
        zig_fuzz_test(&message, message.len);
        const secret_key = oracle.secretKey(@as(u64, byte) + 1);
        const signature = secret_key.sign(&message, bls.DST, null);
        const compressed = signature.compress();
        zig_fuzz_test(&compressed, compressed.len);
        const serialized = signature.serialize();
        zig_fuzz_test(&serialized, serialized.len);
    }
}
