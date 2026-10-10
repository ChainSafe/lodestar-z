//! Tests for `compatible_union.zig`.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const FixedListType = @import("list.zig").FixedListType;
const UintType = @import("uint.zig").UintType;
const BoolType = @import("bool.zig").BoolType;
const FixedProgressiveListType = @import("progressive_list.zig").FixedProgressiveListType;
const CompatibleUnionType = @import("compatible_union.zig").CompatibleUnionType;
const initValue = @import("value_init.zig").initValue;

test "memory_safety: composed compatible unions decode with no SSZ default and survive OOM" {
    const Items = FixedProgressiveListType(BoolType());
    const Inner = CompatibleUnionType(.{ .{ 1, Items }, .{ 2, Items } });
    const Nested = CompatibleUnionType(.{ .{ 3, Inner }, .{ 4, Inner } });
    const Container = @import("progressive_container.zig").VariableProgressiveContainerType(struct { body: Nested }, &.{ 0, 1 });
    const List = @import("progressive_list.zig").VariableProgressiveListType(Nested);
    try std.testing.expect(!@hasDecl(Inner, "default_value"));
    try std.testing.expect(!@hasDecl(Nested, "default_value"));
    inline for (.{ Nested, Container, List }) |ST| {
        const bytes: []const u8 = if (ST == Nested) &.{ 4, 2, 1, 0, 1 } else &.{ 4, 0, 0, 0, 4, 2, 1, 0, 1 };
        try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
            fn run(allocator: std.mem.Allocator, data: []const u8) !void {
                var out = initValue(ST);
                defer ST.deinit(allocator, &out);
                try ST.deserializeFromBytes(allocator, data, &out);
                var actual: [32]u8 = undefined;
                const size = ST.serializeIntoBytes(&out, &actual);
                try std.testing.expectEqualSlices(u8, data, actual[0..size]);
            }
        }.run, .{bytes});
    }

    var out = initValue(Nested);
    defer Nested.deinit(std.testing.allocator, &out);
    try std.testing.expectError(error.invalidBoolean, Nested.deserializeFromBytes(std.testing.allocator, &.{ 4, 2, 1, 2 }, &out));
    try std.testing.expectEqual(3, Nested.getSelector(&out));
    try std.testing.expectEqual(1, Inner.getSelector(&out.option_3));
    try std.testing.expectEqual(0, out.option_3.option_1.items.len);
}

fn expectProgressiveFromValuePoolExhaustionReclaimsNodes(
    comptime ST: type,
    value: *const ST.Type,
    max_available_nodes: usize,
) !void {
    var saw_failure = false;

    // Start with no room and add one slot per attempt. This walks each partial build until the
    // first capacity that can finish the value.
    for (0..max_available_nodes + 1) |available_nodes| {
        var pool = try Node.Pool.init(.{
            .page_allocator = std.testing.allocator,
            .allocator = std.testing.allocator,
            .pool_size = @intCast(available_nodes),
        });
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const root = ST.tree.fromValue(&pool, value) catch |err| {
            try std.testing.expectEqual(error.PoolExhausted, err);
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            saw_failure = true;
            continue;
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
        try std.testing.expect(saw_failure);
        return;
    }
    return error.TestUnexpectedResult;
}

test "memory_safety: compatible union tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Union = CompatibleUnionType(.{
        .{ 1, UintType(64) },
        .{ 2, UintType(64) },
    });
    const value: Union.Type = @unionInit(Union.Type, "option_1", 42);

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Union, &value, 32);
}

test "memory_safety: compatible union JSON deserialization preserves out after trailing error" {
    const Items = FixedListType(UintType(8), 8, .{});
    const Union = CompatibleUnionType(.{
        .{ 1, Items },
        .{ 2, Items },
    });
    var out: Union.Type = @unionInit(Union.Type, "option_1", Items.default_value);
    defer Union.deinit(std.testing.allocator, &out);

    var scanner = std.json.Scanner.initCompleteInput(
        std.testing.allocator,
        "{\"selector\":\"2\",\"data\":[\"1\",\"2\"]",
    );
    defer scanner.deinit();

    var failed = false;
    Union.deserializeFromJson(std.testing.allocator, &scanner, &out) catch {
        failed = true;
    };
    try std.testing.expect(failed);
    try std.testing.expectEqual(@as(u8, 1), Union.getSelector(&out));
    try std.testing.expectEqual(@as(usize, 0), out.option_1.items.len);
}

test "memory_safety: compatible union clone preserves out on OOM" {
    const Items = FixedListType(UintType(8), 8, .{});
    const Union = CompatibleUnionType(.{
        .{ 1, Items },
        .{ 2, Items },
    });

    var source_data: ?Items.Type = Items.default_value;
    errdefer if (source_data) |*value| value.deinit(std.testing.allocator);
    try source_data.?.append(std.testing.allocator, 1);
    var source: Union.Type = @unionInit(Union.Type, "option_2", source_data.?);
    source_data = null;
    defer Union.deinit(std.testing.allocator, &source);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, input: *const Union.Type) !void {
            var out: Union.Type = @unionInit(Union.Type, "option_1", Items.default_value);
            defer Union.deinit(allocator, &out);
            Union.clone(allocator, input, &out) catch |err| {
                try std.testing.expectEqual(@as(u8, 1), Union.getSelector(&out));
                try std.testing.expectEqual(@as(usize, 0), out.option_1.items.len);
                return err;
            };
            try std.testing.expect(Union.equals(input, &out));
        }
    }.run, .{&source});
}

test "memory_safety: compatible union byte deserialization preserves out on malformed input" {
    const Items = FixedProgressiveListType(BoolType());
    const Union = CompatibleUnionType(.{
        .{ 1, Items },
        .{ 2, Items },
    });
    var out: Union.Type = @unionInit(Union.Type, "option_1", Items.default_value);
    defer Union.deinit(std.testing.allocator, &out);

    try std.testing.expectError(
        error.invalidBoolean,
        Union.deserializeFromBytes(std.testing.allocator, &.{ 2, 1, 2 }, &out),
    );
    try std.testing.expectEqual(@as(u8, 1), Union.getSelector(&out));
    try std.testing.expectEqual(@as(usize, 0), out.option_1.items.len);
}
