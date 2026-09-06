// Fuzz target for SSZ BitVectorType deserialization.
//
// Input format: [selector_byte] [ssz_data...]
//   selector 0x00 → BitVector(4)
//   selector 0x01 → BitVector(32)
//   selector 0x02 → BitVector(64)
//   selector 0x03 → BitVector(512)
//
// Tests: fixed-length bitfield validation, trailing zeros enforcement.

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const ssz = @import("ssz");
const oracle = @import("ssz_oracle.zig");

const selector_count: u32 = 4;

pub export fn zig_fuzz_init() callconv(.c) void {
    // No initialization needed for fixed-size types.
    // BitVector uses stack-only deserialization.
}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len < 1) return;

    const selector = buf[0];
    const data = buf[1..len];

    switch (selector % selector_count) {
        0 => fuzzBitVector(ssz.BitVectorType(4), data),
        1 => fuzzBitVector(ssz.BitVectorType(32), data),
        2 => fuzzBitVector(ssz.BitVectorType(64), data),
        3 => fuzzBitVector(ssz.BitVectorType(512), data),
        else => unreachable,
    }
}

fn fuzzBitVector(
    comptime BitVectorT: type,
    data: []const u8,
) void {
    const valid = data.len == BitVectorT.fixed_size and
        (BitVectorT.length % 8 == 0 or data[data.len - 1] <
            (@as(u16, 1) << @intCast(BitVectorT.length % 8)));
    var value: BitVectorT.Type = undefined;
    BitVectorT.deserializeFromBytes(data, &value) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.invalidLength, error.trailingData => return,
            else => panicUnexpected("deserializing bitvector", err),
        }
    };
    assert(valid);
    for (0..BitVectorT.length) |i| {
        assert((value.get(i) catch |err| panicUnexpected("reading bitvector", err)) == oracle.bit(data, i));
    }

    // Round-trip invariant.
    var serialized: [BitVectorT.fixed_size]u8 = undefined;
    const written = BitVectorT.serializeIntoBytes(
        &value,
        &serialized,
    );
    assert(written == BitVectorT.fixed_size);
    assert(std.mem.eql(u8, &serialized, data));
}

test "bitvector decoder checks all padding patterns and fixed sizes" {
    for (0..256) |byte| {
        const input = [_]u8{ 0, @intCast(byte) };
        zig_fuzz_test(&input, input.len);
    }
    var input = [_]u8{0xa5} ** 66;
    for (1..4) |selector| {
        input[0] = @intCast(selector);
        for (1..input.len + 1) |len| zig_fuzz_test(&input, len);
    }
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}
