// Fuzz target for SSZ BitListType deserialization.
//
// Input format: [selector_byte] [ssz_data...]
//   selector 0x00 → BitList(8)
//   selector 0x01 → BitList(64)
//   selector 0x02 → BitList(2048)
//
// Tests: padding bit parsing, sentinel validation, length limits.

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const ssz = @import("ssz");
const oracle = @import("ssz_oracle.zig");

const selector_count: u32 = 3;
const fuzz_buffer_size: u32 = 64 * 1024 * 1024;

var fuzz_buf: [fuzz_buffer_size]u8 = undefined;

pub export fn zig_fuzz_init() callconv(.c) void {
    // No initialization needed.
    // FixedBufferAllocator is reset per iteration.
}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len < 1) return;

    var fixed_buffer_allocator =
        std.heap.FixedBufferAllocator.init(&fuzz_buf);
    var tracking = std.testing.FailingAllocator.init(fixed_buffer_allocator.allocator(), .{});
    defer assert(tracking.allocated_bytes == tracking.freed_bytes);
    const allocator = tracking.allocator();

    const selector = buf[0];
    const data = buf[1..len];

    switch (selector % selector_count) {
        0 => fuzzBitList(ssz.BitListType(8), allocator, data),
        1 => fuzzBitList(ssz.BitListType(64), allocator, data),
        2 => fuzzBitList(
            ssz.BitListType(2048),
            allocator,
            data,
        ),
        else => unreachable,
    }
}

fn fuzzBitList(
    comptime BitListT: type,
    allocator: std.mem.Allocator,
    data: []const u8,
) void {
    const expected_length = oracle.bitLength(data, BitListT.limit);
    var value: BitListT.Type = BitListT.Type.empty;
    defer BitListT.deinit(allocator, &value);
    BitListT.deserializeFromBytes(
        allocator,
        data,
        &value,
    ) catch |err| {
        assert(expected_length == null);
        switch (@as(anyerror, err)) {
            error.InvalidSize, error.noPaddingBit, error.tooLarge => return,
            else => panicUnexpected("deserializing bitlist", err),
        }
    };
    assert(expected_length != null);
    assert(value.bit_len == expected_length.?);
    for (0..value.bit_len) |i| {
        assert((value.get(i) catch |err| panicUnexpected("reading bitlist", err)) == oracle.bit(data, i));
    }
    // Postcondition: serialized form must be non-empty
    // (sentinel bit requires at least 1 byte).
    const serialized_size = BitListT.serializedSize(&value);
    assert(serialized_size > 0);

    // Round-trip invariant.
    const output = allocator.alloc(
        u8,
        serialized_size,
    ) catch |err| panicUnexpected("allocating bitlist output", err);
    defer allocator.free(output);
    const written = BitListT.serializeIntoBytes(
        &value,
        output,
    );
    assert(written == serialized_size);
    assert(std.mem.eql(u8, output, data));
}

test "bitlist decoder checks sentinel position and capacity boundaries" {
    var input = [_]u8{0} ** 259;
    for (0..3) |selector| {
        input[0] = @intCast(selector);
        const limit: usize = switch (selector) {
            0 => 8,
            1 => 64,
            else => 2048,
        };
        for ([_]usize{ 0, 1, limit / 8, limit / 8 + 1, limit / 8 + 2 }) |len| {
            for (0..256) |last| {
                if (len > 0) input[len] = @intCast(last);
                zig_fuzz_test(&input, len + 1);
            }
        }
    }
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}
