const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");
const oracle = @import("bls_oracle.zig");

const PublicKey = bls.PublicKey;
const blstError = bls.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    const input = buf[0..len];
    if (len <= oracle.generated_input_len_max) fuzzGenerated(input);

    const pk = PublicKey.keyValidate(input) catch |err| {
        switch (err) {
            blstError.BadEncoding, blstError.PointNotOnCurve, blstError.PointNotInGroup, blstError.PkIsInfinity => return,
            else => @panic("unexpected public key decode error"),
        }
    };

    const encoded = pk.serialize();
    if (input.len == PublicKey.COMPRESS_SIZE) {
        const compressed = pk.compress();
        assert(std.mem.eql(u8, input, &compressed));
    } else {
        assert(std.mem.eql(u8, input, &encoded));
    }
    const pk2 = PublicKey.keyValidate(&encoded) catch
        @panic("validated public key failed revalidation");
    assert(pk.isEqual(&pk2));
}

fn fuzzGenerated(input: []const u8) void {
    var seed: [oracle.generated_input_len_max]u8 = @splat(0);
    @memcpy(seed[0..input.len], input);
    const scalar = @as(u64, std.mem.readInt(u32, seed[0..4], .little)) + 1;
    const secret_key = oracle.secretKey(scalar);
    const expected = secret_key.toPublicKey();
    const compressed = expected.compress();
    const decoded_compressed = PublicKey.keyValidate(&compressed) catch
        @panic("generated compressed public key rejected");
    assert(expected.isEqual(&decoded_compressed));
    const serialized = expected.serialize();
    const decoded_serialized = PublicKey.keyValidate(&serialized) catch
        @panic("generated serialized public key rejected");
    assert(expected.isEqual(&decoded_serialized));
}

test "public key oracle covers generated keys and both raw encodings" {
    for ([_]u8{ 0, 1, 255 }) |byte| {
        const input: [oracle.generated_input_len_max]u8 = @splat(byte);
        zig_fuzz_test(&input, 0);
        zig_fuzz_test(&input, input.len);
        const secret_key = oracle.secretKey(@as(u64, byte) + 1);
        const public_key = secret_key.toPublicKey();
        const compressed = public_key.compress();
        zig_fuzz_test(&compressed, compressed.len);
        const serialized = public_key.serialize();
        zig_fuzz_test(&serialized, serialized.len);
    }
}
