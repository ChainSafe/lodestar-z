// Fuzz target for SSZ list type deserialization.
//
// Input format: [selector_byte] [ssz_data...]
//
// FixedListType (fixed-size elements):
//   0x00 → FixedList(Uint64, 128)
//   0x01 → FixedList(Uint32, 256)
//   0x02 → FixedList(Bool, 64)
//
// VariableListType (variable-size elements):
//   0x03 → VariableList(ByteList(256), 16)

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const ssz = @import("ssz");
const oracle = @import("ssz_oracle.zig");

const selector_count: u32 = 4;
const fuzz_buffer_size: u32 = 64 * 1024 * 1024;

var fuzz_buf: [fuzz_buffer_size]u8 = undefined;

const Uint64 = ssz.UintType(64);
const Uint32 = ssz.UintType(32);
const BoolT = ssz.BoolType();

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
        0 => fuzzFixedList(
            ssz.FixedListType(Uint64, 128, .{}),
            allocator,
            data,
        ),
        1 => fuzzFixedList(
            ssz.FixedListType(Uint32, 256, .{}),
            allocator,
            data,
        ),
        2 => fuzzFixedList(
            ssz.FixedListType(BoolT, 64, .{}),
            allocator,
            data,
        ),
        3 => fuzzVariableList(
            ssz.VariableListType(ssz.ByteListType(256), 16),
            allocator,
            data,
        ),
        else => unreachable,
    }
}

fn fuzzFixedList(
    comptime ListT: type,
    allocator: std.mem.Allocator,
    data: []const u8,
) void {
    var valid = data.len % ListT.Element.fixed_size == 0 and
        data.len / ListT.Element.fixed_size <= ListT.limit;
    if (comptime ListT.Element == BoolT) {
        for (data) |byte| valid = valid and byte <= 1;
    }
    var value: ListT.Type = ListT.Type.empty;
    defer ListT.deinit(allocator, &value);

    ListT.deserializeFromBytes(
        allocator,
        data,
        &value,
    ) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.UnexpectedRemainder, error.gtLimit, error.invalidBoolean => return,
            else => panicUnexpected("deserializing fixed list", err),
        }
    };
    assert(valid);
    assert(value.items.len == data.len / ListT.Element.fixed_size);
    for (value.items, 0..) |element, i| {
        if (comptime ListT.Element == BoolT) {
            assert(element == (data[i] == 1));
        } else {
            const start = i * ListT.Element.fixed_size;
            assert(element == oracle.uint(ListT.Element.Type, data[start..][0..ListT.Element.fixed_size]));
        }
    }

    // Round-trip invariant.
    const serialized_size = ListT.serializedSize(&value);
    assert(serialized_size == data.len);
    const output = allocator.alloc(
        u8,
        serialized_size,
    ) catch |err| panicUnexpected("allocating fixed list output", err);
    defer allocator.free(output);
    const written = ListT.serializeIntoBytes(&value, output);
    assert(written == serialized_size);
    assert(std.mem.eql(u8, output, data));

    if (comptime ListT.Element == BoolT) {
        assertBooleanListHash(ListT, allocator, &value);
    }
}

fn fuzzVariableList(
    comptime ListT: type,
    allocator: std.mem.Allocator,
    data: []const u8,
) void {
    const expected_length = variableListLength(ListT, data);
    var value: ListT.Type = ListT.Type.empty;
    defer ListT.deinit(allocator, &value);

    ListT.deserializeFromBytes(
        allocator,
        data,
        &value,
    ) catch |err| {
        assert(expected_length == null);
        switch (@as(anyerror, err)) {
            error.offsetOutOfRange,
            error.zeroOffset,
            error.offsetNotDivisibleBy4,
            error.invalidOffsetCount,
            error.offsetNotIncreasing,
            error.invalidLength,
            => return,
            else => panicUnexpected("deserializing variable list", err),
        }
    };
    assert(expected_length != null);
    assert(value.items.len == expected_length.?);
    for (value.items, 0..) |element, i| {
        const start = oracle.uint(u32, data[i * 4 ..][0..4]);
        const end = if (i + 1 == value.items.len) data.len else oracle.uint(u32, data[(i + 1) * 4 ..][0..4]);
        assert(std.mem.eql(u8, element.items, data[start..end]));
    }

    // Round-trip invariant.
    const serialized_size = ListT.serializedSize(&value);
    assert(serialized_size == data.len);
    const output = allocator.alloc(
        u8,
        serialized_size,
    ) catch |err| panicUnexpected("allocating variable list output", err);
    defer allocator.free(output);
    const written = ListT.serializeIntoBytes(&value, output);
    assert(written == serialized_size);
    assert(std.mem.eql(u8, output, data));
}

fn variableListLength(comptime ListT: type, data: []const u8) ?usize {
    if (data.len == 0) return 0;
    if (data.len < 4) return null;
    const first = oracle.uint(u32, data[0..4]);
    if (first == 0 or first % 4 != 0 or first > data.len) return null;
    const count = first / 4;
    if (count > ListT.limit) return null;
    var start: usize = first;
    for (0..count) |i| {
        const end = if (i + 1 == count) data.len else oracle.uint(u32, data[(i + 1) * 4 ..][0..4]);
        if (end < start or end > data.len) return null;
        if (end - start > ListT.Element.limit) return null;
        start = end;
    }
    return count;
}

fn assertBooleanListHash(
    comptime ListT: type,
    allocator: std.mem.Allocator,
    value: *const ListT.Type,
) void {
    var expected: [32]u8 = undefined;
    ListT.hashTreeRoot(allocator, value, &expected) catch |err|
        panicUnexpected("hashing boolean list", err);

    var scratch = ssz.Hasher(ListT).init(allocator) catch |err|
        panicUnexpected("allocating boolean list hasher", err);
    defer scratch.deinit(allocator);

    var actual: [32]u8 = undefined;
    ssz.Hasher(ListT).hash(&scratch, value, &actual) catch |err|
        panicUnexpected("incrementally hashing boolean list", err);
    assert(std.mem.eql(u8, &expected, &actual));
}

test "list decoder checks element values, list limits, and malformed child cleanup" {
    var input = [_]u8{0} ** 1026;
    for (0..3) |selector| {
        input[0] = @intCast(selector);
        for ([_]usize{ 0, 1, 3, 4, 7, 8, 64, 65, 1024, 1025 }) |len| {
            zig_fuzz_test(&input, len + 1);
        }
    }
    input[0] = 2;
    input[2] = 2;
    zig_fuzz_test(&input, 4);

    for ([_][]const u8{
        &.{3},
        &.{ 3, 4, 0, 0, 0 },
        &.{ 3, 8, 0, 0, 0, 8, 0, 0, 0 },
        &.{ 3, 8, 0, 0, 0, 9, 0, 0, 0, 0xa5, 0x12, 0x34 },
        &.{ 3, 0, 0, 0, 0 },
        &.{ 3, 5, 0, 0, 0, 0 },
        &.{ 3, 8, 0, 0, 0, 7, 0, 0, 0 },
        &.{ 3, 8, 0, 0, 0, 10, 0, 0, 0 },
        &.{ 3, 68, 0, 0, 0 },
    }) |case| zig_fuzz_test(case.ptr, case.len);

    var malformed = [_]u8{0xa5} ** (1 + 8 + 1 + 257);
    malformed[0] = 3;
    @memcpy(malformed[1..9], &[_]u8{ 8, 0, 0, 0, 9, 0, 0, 0 });
    zig_fuzz_test(&malformed, malformed.len);
}

test "variable list decoder OOM releases offset table and initialized child prefix" {
    const List = ssz.VariableListType(ssz.ByteListType(256), 16);
    const data = [_]u8{ 8, 0, 0, 0, 9, 0, 0, 0, 0xa5, 0x12, 0x34 };
    var completed = false;
    for (0..5) |fail_index| {
        var tracking = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        const allocator = tracking.allocator();
        var value: List.Type = .empty;
        const result = List.deserializeFromBytes(allocator, &data, &value);
        List.deinit(allocator, &value);
        try std.testing.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);
        if (tracking.has_induced_failure) {
            try std.testing.expectError(error.OutOfMemory, result);
        } else {
            try result;
            completed = true;
            break;
        }
    }
    try std.testing.expect(completed);
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}
