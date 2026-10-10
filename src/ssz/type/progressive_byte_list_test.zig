const std = @import("std");
const testing = std.testing;
const ssz = @import("root.zig");
const Node = @import("persistent_merkle_tree").Node;

fn decode(comptime ST: type, allocator: std.mem.Allocator, text: []const u8, out: *ST.Type) !void {
    var scanner = std.json.Scanner.initCompleteInput(allocator, text);
    defer scanner.deinit();
    try ST.deserializeFromJson(allocator, &scanner, out);
}

test "progressive byte lists use hex JSON while uint8 lists retain arrays" {
    const Bytes = ssz.ProgressiveByteListType();
    const Numbers = ssz.FixedProgressiveListType(ssz.UintType(8));
    try testing.expect(ssz.isByteListType(Bytes));
    try testing.expect(ssz.isProgressiveByteListType(Bytes));
    try testing.expect(!ssz.isByteListType(Numbers));
    try testing.expect(Bytes.TreeView.SszType == Bytes);
    var value = Bytes.default_value;
    defer Bytes.deinit(testing.allocator, &value);
    try decode(Bytes, testing.allocator, "\"0x00fF12\"", &value);
    try testing.expectEqualSlices(u8, &.{ 0, 255, 18 }, value.items);

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();
    var writer: std.json.Stringify = .{ .writer = &output.writer };
    try Bytes.serializeIntoJson(testing.allocator, &writer, &value);
    try testing.expectEqualStrings("\"0x00ff12\"", output.written());
    output.clearRetainingCapacity();
    writer = .{ .writer = &output.writer };
    try Numbers.serializeIntoJson(testing.allocator, &writer, &value);
    try testing.expectEqualStrings("[\"0\",\"255\",\"18\"]", output.written());
    try decode(Bytes, testing.allocator, "\"0x\"", &value);
    try testing.expectEqual(@as(usize, 0), value.items.len);
}

test "progressive byte lists preserve generic roots and mutable view identity" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 2048 });
    defer pool.deinit();
    const baseline = pool.getNodesInUse();
    inline for (.{ false, true }) |chunked| {
        const Bytes = ssz.ProgressiveByteListTypeWithOptions(.{ .chunked_leaf = chunked });
        const Numbers = ssz.FixedProgressiveListTypeWithOptions(ssz.UintType(8), .{ .chunked_leaf = chunked });
        for ([_]usize{ 0, 1, 31, 32, 33, 672, 673, 2079 }) |length| {
            var value = Bytes.default_value;
            defer Bytes.deinit(allocator, &value);
            try value.resize(allocator, length);
            for (value.items, 0..) |*byte, i| byte.* = @truncate(i);
            var expected: [32]u8 = undefined;
            try Numbers.hashTreeRoot(allocator, &value, &expected);
            const view = try Bytes.TreeView.fromValue(allocator, &pool, &value);
            defer view.deinit();
            try testing.expectEqualSlices(u8, &expected, try view.hashTreeRoot());
            const copy = try view.clone(.{});
            defer copy.deinit();
            if (length > 0) {
                try copy.set(length - 1, 77);
                try copy.commit();
                try testing.expectEqual(@as(u8, @truncate(length - 1)), try view.get(length - 1));
                try testing.expectEqual(@as(u8, 77), try copy.get(length - 1));
            }
        }
    }
    try testing.expectEqual(baseline, pool.getNodesInUse());
}

test "progressive byte JSON rejects malformed and oversized input without replacing output" {
    const Bytes = ssz.ProgressiveByteListTypeWithOptions(.{ .limit = 3 });
    var value = Bytes.default_value;
    defer Bytes.deinit(testing.allocator, &value);
    try value.append(testing.allocator, 170);
    for ([_][]const u8{ "\"\"", "\"0\"", "\"00\"", "\"0x0\"", "\"0xgg\"", "[]", "null" }) |text| {
        try testing.expectError(error.InvalidJson, decode(Bytes, testing.allocator, text, &value));
        try testing.expectEqualSlices(u8, &.{170}, value.items);
    }
    try testing.expectError(error.LengthOverLimit, decode(Bytes, testing.allocator, "\"0x00112233\"", &value));
    try testing.expectEqualSlices(u8, &.{170}, value.items);
    try decode(Bytes, testing.allocator, "\"0x001122\"", &value);
    try testing.expectEqualSlices(u8, &.{ 0, 17, 34 }, value.items);
}

test "memory_safety: progressive byte JSON preserves old output on every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const Bytes = ssz.ProgressiveByteListType();
            var value = Bytes.default_value;
            defer Bytes.deinit(allocator, &value);
            try value.append(allocator, 170);
            decode(Bytes, allocator, "\"0x00112233445566778899aabbccddeeff\"", &value) catch |err| {
                try testing.expectEqualSlices(u8, &.{170}, value.items);
                return err;
            };
            try testing.expectEqual(@as(usize, 16), value.items.len);
            try testing.expectEqual(@as(u8, 255), value.items[15]);
        }
    }.run, .{});
}
