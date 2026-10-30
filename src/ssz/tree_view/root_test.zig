//! Serializes a value and a tree view of it for every view type and checks
//! that the bytes, the size and the hash tree root agree with each other and
//! with the pinned vectors.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const UintType = @import("../type/uint.zig").UintType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const VariableContainerType = @import("../type/container.zig").VariableContainerType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;
const FixedListType = @import("../type/list.zig").FixedListType;

const pool_size = 4096;
const list_limit = 128;

const Uint8 = UintType(8);
const Uint64 = UintType(64);
const Root32 = ByteVectorType(32);
const Pair = FixedContainerType(struct { a: Uint64, b: Uint64 });
const ListU64 = FixedListType(Uint64, list_limit, .{});
const PairWithList = VariableContainerType(struct { a: ListU64, b: Uint64 });

// Decodes a pinned vector at comptime so the table can hold hex strings
// instead of byte arrays.
fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const four_u64_values = [4]u64{ 100000, 200000, 300000, 400000 };
const eight_u8_values = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
const four_roots = [4][32]u8{ [_]u8{0xaa} ** 32, [_]u8{0xbb} ** 32, [_]u8{0xcc} ** 32, [_]u8{0xdd} ** 32 };
const pair_zero: Pair.Type = .{ .a = 0, .b = 0 };
const pair_some: Pair.Type = .{ .a = 123456, .b = 654321 };
const four_pairs = [4]Pair.Type{ pair_zero, pair_some, .{ .a = 234567, .b = 765432 }, .{ .a = 345678, .b = 876543 } };

const four_u64_serialized = hex("a086010000000000400d030000000000e093040000000000801a060000000000");
const pair_zero_serialized = [_]u8{0} ** 16;
const pair_some_serialized = hex("40e2010000000000f1fb090000000000");
const empty_composite_list_root = hex("96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57");

// One row per (type, value) pair: the expected serialization and, for most
// rows, the expected hash tree root. Rows with `items` are lists built by
// appending; the rest hold the value literal.
const serialize_cases = .{
    .{
        .T = FixedVectorType(Uint64, four_u64_values.len, .{}),
        .value = four_u64_values,
        .serialized = &four_u64_serialized,
        .root = four_u64_serialized,
    },
    .{
        .T = FixedVectorType(Uint8, eight_u8_values.len, .{}),
        .value = eight_u8_values,
        .serialized = &eight_u8_values,
    },
    .{
        .T = FixedVectorType(Root32, four_roots.len, .{}),
        .value = four_roots,
        .serialized = &([_]u8{0xaa} ** 32 ++ [_]u8{0xbb} ** 32 ++ [_]u8{0xcc} ** 32 ++ [_]u8{0xdd} ** 32),
    },
    .{
        .T = FixedVectorType(Pair, four_pairs.len, .{}),
        .value = four_pairs,
        .serialized = &hex("0000000000000000000000000000000040e2010000000000f1fb0900000000004794030000000000f8ad0b00000000004e46050000000000ff5f0d0000000000"),
        .root = hex("b1a797eb50654748ba239010edccea7b46b55bf740730b700684f48b0c478372"),
    },
    .{
        .T = Pair,
        .value = pair_zero,
        .serialized = &pair_zero_serialized,
        .root = hex("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    },
    .{
        .T = Pair,
        .value = pair_some,
        .serialized = &pair_some_serialized,
        .root = hex("53b38aff7bf2dd1a49903d07a33509b980c6acc9f2235a45aac342b0a9528c22"),
    },
    .{
        .T = PairWithList,
        .value = PairWithList.Type{ .a = ListU64.default_value, .b = 0 },
        .serialized = &hex("0c0000000000000000000000"),
        .root = hex("dc3619cbbc5ef0e0a3b38e3ca5d31c2b16868eacb6e4bcf8b4510963354315f5"),
    },
    .{
        .T = FixedListType(Uint8, list_limit, .{}),
        .items = &[_]u8{},
        .serialized = &[_]u8{},
        .root = hex("28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30"),
    },
    .{
        .T = FixedListType(Uint8, list_limit, .{}),
        .items = &[_]u8{ 1, 2, 3, 4 },
        .serialized = &[_]u8{ 1, 2, 3, 4 },
        .root = hex("bac511d1f641d6b8823200bb4b3cced3bd4720701f18571dff35a5d2a40190fa"),
    },
    .{
        .T = ListU64,
        .items = &[_]u64{},
        .serialized = &[_]u8{},
        .root = hex("52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3"),
    },
    .{
        .T = ListU64,
        .items = &four_u64_values,
        .serialized = &four_u64_serialized,
        .root = hex("d1daef215502b7746e5ff3e8833e399cb249ab3f81d824be60e174ff5633c1bf"),
    },
    .{
        .T = FixedListType(Root32, list_limit, .{}),
        .items = &[_][32]u8{},
        .serialized = &[_]u8{},
        .root = empty_composite_list_root,
    },
    .{
        .T = FixedListType(Root32, list_limit, .{}),
        .items = &[_][32]u8{ [_]u8{0xdd} ** 32, [_]u8{0xee} ** 32 },
        .serialized = &([_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32),
        .root = hex("0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8"),
    },
    .{
        .T = FixedListType(Pair, list_limit, .{}),
        .items = &[_]Pair.Type{},
        .serialized = &[_]u8{},
        .root = empty_composite_list_root,
    },
    .{
        .T = FixedListType(Pair, list_limit, .{}),
        .items = &[_]Pair.Type{ pair_zero, pair_some },
        .serialized = &(pair_zero_serialized ++ pair_some_serialized),
        .root = hex("8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210"),
    },
};

// ArrayBasicTreeView.serializedSize returns a plain usize, the other views an
// error union.
fn viewSerializedSize(view: anytype) !usize {
    const size = view.serializedSize();
    return if (@typeInfo(@TypeOf(size)) == .error_union) try size else size;
}

// Expect the view serializes to the same bytes as the value type and as the
// pinned bytes, reports exactly that size, and, when a root is given, hashes
// to it.
fn expectViewSerializesLikeValue(
    comptime T: type,
    pool: *Node.Pool,
    value: *const T.Type,
    expected_serialized: []const u8,
    expected_root: ?[32]u8,
) !void {
    const allocator = std.testing.allocator;

    const value_size = if (@hasDecl(T, "fixed_size")) T.fixed_size else T.serializedSize(value);
    const value_serialized = try allocator.alloc(u8, value_size);
    defer allocator.free(value_serialized);
    _ = T.serializeIntoBytes(value, value_serialized);

    const view = try T.TreeView.init(allocator, pool, try T.tree.fromValue(pool, value));
    defer view.deinit();

    const view_size = try viewSerializedSize(view);
    try std.testing.expectEqual(expected_serialized.len, view_size);
    const view_serialized = try allocator.alloc(u8, view_size);
    defer allocator.free(view_serialized);
    try std.testing.expectEqual(view_size, try view.serializeIntoBytes(view_serialized));

    try std.testing.expectEqualSlices(u8, expected_serialized, view_serialized);
    try std.testing.expectEqualSlices(u8, value_serialized, view_serialized);

    if (expected_root) |root| {
        var actual_root: [32]u8 = undefined;
        try view.hashTreeRootInto(&actual_root);
        try std.testing.expectEqualSlices(u8, &root, &actual_root);
    }
}

// Expect every row passes the check above, building list rows by appending
// their items.
test "TreeView serialize matches the value type and the pinned vectors" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    inline for (serialize_cases) |case| {
        const T = case.T;
        const root: ?[32]u8 = if (@hasField(@TypeOf(case), "root")) case.root else null;
        var value: T.Type = if (@hasField(@TypeOf(case), "items")) T.default_value else case.value;
        defer if (@hasDecl(T, "deinit")) T.deinit(allocator, &value);
        if (@hasField(@TypeOf(case), "items")) {
            for (case.items) |item| try value.append(allocator, item);
        }
        try expectViewSerializesLikeValue(T, &pool, &value, case.serialized, root);
    }
}
