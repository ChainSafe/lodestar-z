const std = @import("std");
const ssz = @import("ssz");
const hex = @import("hex");
const Node = @import("persistent_merkle_tree").Node;
const Allocator = std.mem.Allocator;

fn unwrapData(json: std.json.Value) std.json.Value {
    return if (json == .object) json.object.get("data") orelse json else json;
}

fn numberString(json: std.json.Value) ![]const u8 {
    return switch (json) {
        .string, .number_string => |value| value,
        else => error.InvalidFixtureNumber,
    };
}

fn containsUnion(comptime ST: type) bool {
    switch (ST.kind) {
        .compatible_union => return true,
        .container, .progressive_container => {
            inline for (ST.fields) |field| if (containsUnion(field.type)) return true;
        },
        .list, .progressive_list, .vector => return containsUnion(ST.Element),
        else => {},
    }
    return false;
}

/// Read the fixture's independent value representation without decoding its SSZ
/// bytes. parse_numbers=false is required: uint256 fixtures exceed f64 and i64.
fn parseValue(comptime ST: type, allocator: Allocator, json: std.json.Value, out: *ST.Type) !void {
    if (comptime ssz.isBitListType(ST) or ssz.isProgressiveBitListType(ST) or ssz.isBitVectorType(ST)) {
        const values = unwrapData(json).array.items;
        out.* = ST.default_value;
        if (comptime ssz.isBitVectorType(ST)) {
            try std.testing.expectEqual(ST.length, values.len);
            for (values, 0..) |value, i| try out.set(i, value.bool);
        } else {
            try out.resize(allocator, values.len);
            for (values, 0..) |value, i| try out.set(allocator, i, value.bool);
        }
    } else if (comptime ssz.isByteVectorType(ST) or ssz.isByteListType(ST)) {
        const encoded = unwrapData(json).string;
        const bytes = try decodeHex(allocator, encoded);
        if (comptime ssz.isByteVectorType(ST)) {
            try std.testing.expectEqual(ST.fixed_size, bytes.len);
            out.* = bytes[0..ST.fixed_size].*;
        } else {
            out.* = ST.default_value;
            try out.appendSlice(allocator, bytes);
        }
    } else switch (ST.kind) {
        .bool => out.* = json.bool,
        .uint => out.* = try std.fmt.parseInt(ST.Type, try numberString(json), 10),
        .container, .progressive_container => {
            inline for (ST.fields) |field| {
                try parseValue(field.type, allocator, json.object.get(field.name).?, &@field(out, field.name));
            }
        },
        .list, .progressive_list => {
            const values = unwrapData(json).array.items;
            out.* = ST.default_value;
            try out.resize(allocator, values.len);
            for (values, 0..) |value, i| try parseValue(ST.Element, allocator, value, &out.items[i]);
        },
        .vector => {
            const values = unwrapData(json).array.items;
            try std.testing.expectEqual(ST.length, values.len);
            for (values, 0..) |value, i| try parseValue(ST.Element, allocator, value, &out[i]);
        },
        .compatible_union => {
            const selector = try std.fmt.parseInt(u8, try numberString(json.object.get("selector").?), 10);
            inline for (ST._union_options) |option| {
                if (selector == option.@"0") {
                    const name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});
                    out.* = @unionInit(ST.Type, name, undefined);
                    try parseValue(option.@"1", allocator, json.object.get("data").?, &@field(out, name));
                    return;
                }
            }
            return error.InvalidFixtureSelector;
        },
        else => @compileError("Unsupported SSZ fixture type"),
    }
}

fn decodeHex(allocator: Allocator, encoded: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, hex.hexByteLen(encoded));
    return try hex.hexToBytes(result, encoded);
}

/// Resource failure must never satisfy an invalid-encoding fixture.
fn expectInvalid(result: anyerror!void) !void {
    if (result) |_| return error.ExpectedInvalidSSZ else |err| switch (err) {
        error.OutOfMemory, error.PoolExhausted, error.RefCountOverflow => return err,
        else => {},
    }
}

pub fn run(comptime ST: type, gpa: Allocator, file: []const u8, test_id: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const content = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, file, allocator, .limited(16 * 1024 * 1024));
    const fixture_file = try std.json.parseFromSlice(std.json.Value, allocator, content, .{ .parse_numbers = false });
    const fixture = fixture_file.value.object.get(test_id) orelse return error.MissingTestCase;
    const bytes = try decodeHex(allocator, (fixture.object.get("rawBytes") orelse fixture.object.get("serialized").?).string);
    var pool = try Node.Pool.init(.{ .allocator = gpa, .page_allocator = gpa, .pool_size = 100_000 });
    defer pool.deinit();
    const initial_nodes = pool.getNodesInUse();
    defer std.debug.assert(pool.getNodesInUse() == initial_nodes);

    if (fixture.object.contains("rejectionReason")) {
        try expectInvalid(ST.serialized.validate(bytes));
        var actual = ssz.initValue(ST);
        try expectInvalid(if (comptime ssz.isFixedType(ST)) ST.deserializeFromBytes(bytes, &actual) else ST.deserializeFromBytes(allocator, bytes, &actual));
        const tree_result = ST.tree.deserializeFromBytes(&pool, bytes);
        if (tree_result) |node| {
            pool.unref(node);
            return error.ExpectedInvalidSSZ;
        } else |err| try expectInvalid(@as(anyerror!void, err));
        return;
    }

    var expected: ST.Type = undefined;
    try parseValue(ST, allocator, fixture.object.get("value").?, &expected);
    const root_hex = fixture.object.get("root").?.string;
    try std.testing.expectEqual(66, root_hex.len);
    const root = try hex.hexToRoot(root_hex[0..66]);
    const size = if (comptime ssz.isFixedType(ST)) ST.fixed_size else ST.serializedSize(&expected);
    try std.testing.expectEqual(bytes.len, size);
    const serialized = try allocator.alloc(u8, size);
    try std.testing.expectEqual(bytes.len, ST.serializeIntoBytes(&expected, serialized));
    try std.testing.expectEqualSlices(u8, bytes, serialized);

    try ST.serialized.validate(bytes);
    var actual = ssz.initValue(ST);
    if (comptime ssz.isFixedType(ST)) try ST.deserializeFromBytes(bytes, &actual) else try ST.deserializeFromBytes(allocator, bytes, &actual);
    try std.testing.expect(ST.equals(&expected, &actual));

    var actual_root: [32]u8 = undefined;
    if (comptime ssz.isFixedType(ST)) try ST.hashTreeRoot(&expected, &actual_root) else try ST.hashTreeRoot(allocator, &expected, &actual_root);
    try std.testing.expectEqualSlices(u8, &root, &actual_root);
    if (comptime ssz.isFixedType(ST)) try ST.serialized.hashTreeRoot(bytes, &actual_root) else try ST.serialized.hashTreeRoot(allocator, bytes, &actual_root);
    try std.testing.expectEqualSlices(u8, &root, &actual_root);

    const value_node = try ST.tree.fromValue(&pool, &expected);
    defer pool.unref(value_node);
    try pool.ref(value_node);
    try std.testing.expectEqualSlices(u8, &root, value_node.getRoot(&pool));
    const node = try ST.tree.deserializeFromBytes(&pool, bytes);
    defer pool.unref(node);
    try pool.ref(node);
    try std.testing.expectEqualSlices(u8, &root, node.getRoot(&pool));
    const tree_size = if (comptime ssz.isFixedType(ST)) ST.fixed_size else try ST.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(bytes.len, tree_size);
    try std.testing.expectEqual(bytes.len, try ST.tree.serializeIntoBytes(node, &pool, serialized));
    try std.testing.expectEqualSlices(u8, bytes, serialized);
    var tree_value = ssz.initValue(ST);
    if (comptime ssz.isFixedType(ST)) try ST.tree.toValue(node, &pool, &tree_value) else try ST.tree.toValue(allocator, node, &pool, &tree_value);
    try std.testing.expect(ST.equals(&expected, &tree_value));
    // Compatible unions currently expose value/tree APIs only. Their containing
    // types still exercise every fixture above; supported mutable views add this check.
    if (comptime !containsUnion(ST) and @hasDecl(ST, "TreeView")) {
        const view = try ST.TreeView.init(gpa, &pool, node);
        defer view.deinit();
        try view.commit();
        try std.testing.expectEqualSlices(u8, &root, view.getRoot().getRoot(&pool));
        if (comptime @hasDecl(ST.TreeView, "serializeIntoBytes")) {
            try std.testing.expectEqual(bytes.len, try view.serializeIntoBytes(serialized));
            try std.testing.expectEqualSlices(u8, bytes, serialized);
        }
        const clone = try view.clone(.{});
        defer clone.deinit();
        try clone.commit();
        try std.testing.expectEqualSlices(u8, &root, clone.getRoot().getRoot(&pool));
    }
}

test "invalid JSON fixture runner preserves resource errors" {
    try expectInvalid(error.InvalidLength);
    try std.testing.expectError(error.OutOfMemory, expectInvalid(error.OutOfMemory));
    try std.testing.expectError(error.PoolExhausted, expectInvalid(error.PoolExhausted));
    try std.testing.expectError(error.RefCountOverflow, expectInvalid(error.RefCountOverflow));
    try std.testing.expectError(error.ExpectedInvalidSSZ, expectInvalid({}));
}
