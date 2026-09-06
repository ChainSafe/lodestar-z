// Fuzz target for SSZ ByteListType deserialization.
//
// Input format: [selector_byte] [ssz_data...]
//   selector 0x00 → ByteList(32)
//   selector 0x01 → ByteList(256)
//   selector 0x02 → ByteList(1024)
//
// Tests: variable-length byte sequence validation, length limits.

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const ssz = @import("ssz");

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
        0 => fuzzByteList(
            ssz.ByteListType(32),
            allocator,
            data,
        ),
        1 => fuzzByteList(
            ssz.ByteListType(256),
            allocator,
            data,
        ),
        2 => fuzzByteList(
            ssz.ByteListType(1024),
            allocator,
            data,
        ),
        else => unreachable,
    }
}

fn fuzzByteList(
    comptime ByteListT: type,
    allocator: std.mem.Allocator,
    data: []const u8,
) void {
    const valid = data.len <= ByteListT.limit;
    var value: ByteListT.Type = ByteListT.Type.empty;
    defer ByteListT.deinit(allocator, &value);
    ByteListT.deserializeFromBytes(
        allocator,
        data,
        &value,
    ) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.invalidLength => return,
            else => panicUnexpected("deserializing bytelist", err),
        }
    };
    assert(valid);
    assert(std.mem.eql(u8, value.items, data));
    // Postcondition: round-trip size must match input.
    const serialized_size = ByteListT.serializedSize(&value);
    assert(serialized_size == data.len);

    // Round-trip invariant.
    const output = allocator.alloc(
        u8,
        serialized_size,
    ) catch |err| panicUnexpected("allocating bytelist output", err);
    defer allocator.free(output);
    const written = ByteListT.serializeIntoBytes(
        &value,
        output,
    );
    assert(written == serialized_size);
    assert(std.mem.eql(u8, output, data));
}

test "bytelist decoder checks empty and maximum lengths" {
    var input = [_]u8{0xa5} ** 1026;
    for ([_]usize{ 32, 256, 1024 }, 0..) |limit, selector| {
        input[0] = @intCast(selector);
        for ([_]usize{ 0, 1, limit, limit + 1 }) |len| zig_fuzz_test(&input, len + 1);
    }
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}
