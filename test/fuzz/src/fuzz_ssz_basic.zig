// Fuzz target for SSZ basic types: Bool, Uint8/16/32/64/128/256.
//
// Input format: [selector_byte] [ssz_data...]
//   selector 0x00 → Bool
//   selector 0x01 → Uint8
//   selector 0x02 → Uint16
//   selector 0x03 → Uint32
//   selector 0x04 → Uint64
//   selector 0x05 → Uint128
//   selector 0x06 → Uint256
//
// Round-trip invariant: serialize(deserialize(data)) == data.

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const ssz = @import("ssz");
const oracle = @import("ssz_oracle.zig");

const selector_count: u32 = 7;

pub export fn zig_fuzz_init() callconv(.c) void {
    // No initialization needed for basic types.
    // They use stack-only deserialization.
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
        0 => fuzzBool(data),
        1 => fuzzUint(ssz.UintType(8), data),
        2 => fuzzUint(ssz.UintType(16), data),
        3 => fuzzUint(ssz.UintType(32), data),
        4 => fuzzUint(ssz.UintType(64), data),
        5 => fuzzUint(ssz.UintType(128), data),
        6 => fuzzUint(ssz.UintType(256), data),
        else => unreachable,
    }
}

fn fuzzBool(data: []const u8) void {
    const BoolType = ssz.BoolType();
    const valid = data.len == 1 and data[0] <= 1;

    var value: BoolType.Type = undefined;
    BoolType.deserializeFromBytes(data, &value) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.InvalidSize, error.invalidBoolean => return,
            else => panicUnexpected("deserializing bool", err),
        }
    };
    assert(valid);
    assert(value == (data[0] == 1));

    // Round-trip invariant.
    var serialized: [BoolType.fixed_size]u8 = undefined;
    const written = BoolType.serializeIntoBytes(
        &value,
        &serialized,
    );
    assert(written == BoolType.fixed_size);
    assert(std.mem.eql(u8, &serialized, data));
}

fn fuzzUint(comptime UintT: type, data: []const u8) void {
    const valid = data.len == UintT.fixed_size;
    var value: UintT.Type = undefined;
    UintT.deserializeFromBytes(data, &value) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.InvalidSize => return,
            else => panicUnexpected("deserializing uint", err),
        }
    };
    assert(valid);
    assert(value == oracle.uint(UintT.Type, data));

    // Round-trip invariant.
    var serialized: [UintT.fixed_size]u8 = undefined;
    const written = UintT.serializeIntoBytes(
        &value,
        &serialized,
    );
    assert(written == UintT.fixed_size);
    assert(std.mem.eql(u8, &serialized, data));
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}

test "basic decoder accepts canonical values and rejects invalid sizes and booleans" {
    for (0..256) |byte| {
        const input = [_]u8{ 0, @intCast(byte) };
        zig_fuzz_test(&input, input.len);
    }
    inline for (.{ 1, 2, 3, 4, 5, 6 }) |selector| {
        var input: [34]u8 = undefined;
        input[0] = selector;
        for (input[1..], 1..) |*byte, i| byte.* = @intCast(i);
        for (1..input.len + 1) |len| zig_fuzz_test(&input, len);
    }
}
