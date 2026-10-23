//! Tests for `array_composite.zig`.

const std = @import("std");
const Gindex = @import("persistent_merkle_tree").Gindex;
const Node = @import("persistent_merkle_tree").Node;
const UintType = @import("../type/uint.zig").UintType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;
const VariableVectorType = @import("../type/vector.zig").VariableVectorType;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const ByteListType = @import("../type/byte_list.zig").ByteListType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;

test "ArrayCompositeTreeView fromValue should support variable vectors" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
    defer pool.deinit();

    const Bytes = ByteListType(8);
    const VectorType = VariableVectorType(Bytes, 2);

    var value = VectorType.default_value;
    defer VectorType.deinit(allocator, &value);
    try value[0].appendSlice(allocator, &[_]u8{ 1, 2 });
    try value[1].appendSlice(allocator, &[_]u8{ 3, 4, 5 });

    var view = try VectorType.TreeView.fromValue(allocator, &pool, &value);
    defer view.deinit();

    var roundtrip = VectorType.default_value;
    defer VectorType.deinit(allocator, &roundtrip);
    try view.toValue(allocator, &roundtrip);

    try std.testing.expect(VectorType.equals(&value, &roundtrip));
}

test "TreeView vector composite element set/get/commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 512 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct {
        a: Uint32,
        b: ByteVectorType(4),
    });
    const VectorType = FixedVectorType(Inner, 2, .{});

    const v0: Inner.Type = .{ .a = 1, .b = [_]u8{ 1, 1, 1, 1 } };
    const v1: Inner.Type = .{ .a = 2, .b = [_]u8{ 2, 2, 2, 2 } };
    const original: VectorType.Type = .{ v0, v1 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const e0_view = try view.get(0);
    var e0_value: Inner.Type = undefined;
    try Inner.tree.toValue(e0_view.getRoot(), &pool, &e0_value);
    try std.testing.expectEqual(@as(u32, 1), e0_value.a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1 }, e0_value.b[0..]);

    const replacement: Inner.Type = .{ .a = 9, .b = [_]u8{ 9, 9, 9, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?*Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |v| v.deinit();
    try view.set(1, replacement_view.?);
    replacement_view = null;

    try view.commit();

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRootInto(&actual_root);

    var expected: VectorType.Type = .{ v0, replacement };
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: VectorType.Type = undefined;
    try VectorType.tree.toValue(view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqual(@as(u32, 1), roundtrip[0].a);
    try std.testing.expectEqual(@as(u32, 9), roundtrip[1].a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 9, 9, 9, 9 }, roundtrip[1].b[0..]);
}

test "TreeView vector composite index bounds" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Inner = FixedContainerType(struct { x: UintType(64) });
    const VectorType = FixedVectorType(Inner, 2, .{});
    const original: VectorType.Type = .{ .{ .x = 1 }, .{ .x = 2 } };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectError(error.IndexOutOfBounds, view.get(2));

    const replacement: Inner.Type = .{ .x = 3 };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    const replacement_view: ?*Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |v| v.deinit();
    try std.testing.expectError(error.IndexOutOfBounds, view.set(2, replacement_view.?));
}

test "TreeView vector composite clearCache does not break subsequent commits" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 512 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const InnerVec = FixedVectorType(Uint32, 2, .{});
    const Inner = FixedContainerType(struct {
        id: Uint32,
        vec: InnerVec,
    });
    const VectorType = FixedVectorType(Inner, 2, .{});

    const v0: Inner.Type = .{ .id = 1, .vec = [_]u32{ 0, 1 } };
    const v1: Inner.Type = .{ .id = 2, .vec = [_]u32{ 2, 3 } };
    const original: VectorType.Type = .{ v0, v1 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    view.clearCache();

    const replacement: Inner.Type = .{ .id = 1, .vec = [_]u32{ 0, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?*Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |v| v.deinit();
    try view.set(0, replacement_view.?);
    replacement_view = null;

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRootInto(&actual_root);

    var expected: VectorType.Type = .{ replacement, v1 };
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/vector/tree.test.ts
test "ArrayCompositeTreeView - get and set" {
    const allocator = std.testing.allocator;

    const Root32 = ByteVectorType(32);
    const VecRootsType = FixedVectorType(Root32, 4, .{});

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const value = [4][32]u8{
        [_]u8{0xaa} ** 32,
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
        [_]u8{0xdd} ** 32,
    };

    const tree_node = try VecRootsType.tree.fromValue(&pool, &value);
    var view = try VecRootsType.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var elem0 = try view.get(0);
    // no need to deinit elem0 as it's borrowed from view
    var bytes0: [Root32.fixed_size]u8 = undefined;
    const bytes0_written = try elem0.serializeIntoBytes(&bytes0);
    try std.testing.expectEqual(bytes0.len, bytes0_written);
    try std.testing.expectEqualSlices(u8, &value[0], &bytes0);

    const new_val = [_]u8{0xff} ** 32;
    const new_node = try Root32.tree.fromValue(&pool, &new_val);
    const new_elem = try Root32.TreeView.init(allocator, &pool, new_node);
    try view.set(1, new_elem);

    var elem1 = try view.get(1);
    // no need to deinit elem1 as it's borrowed from view
    var bytes1: [Root32.fixed_size]u8 = undefined;
    const bytes1_written = try elem1.serializeIntoBytes(&bytes1);
    try std.testing.expectEqual(bytes1.len, bytes1_written);
    try std.testing.expectEqualSlices(u8, &new_val, &bytes1);
}

test "memory_safety: ArrayCompositeTreeView get should leave caches unchanged on OOM" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 128,
    });
    defer pool.deinit();

    const Inner = FixedContainerType(struct { x: UintType(64) });
    const VectorType = FixedVectorType(Inner, 2, .{});
    const value: VectorType.Type = .{ .{ .x = 1 }, .{ .x = 2 } };
    const root = try VectorType.tree.fromValue(&pool, &value);
    var view = try VectorType.TreeView.init(failing.allocator(), &pool, root);
    defer view.deinit();

    try view.chunks.state.changed.ensureUnusedCapacity(failing.allocator(), 1);

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, view.get(0));
    failing.fail_index = std.math.maxInt(usize);

    // A failed mutable get must not publish the index as changed.
    try std.testing.expectEqual(@as(usize, 0), view.chunks.state.changed.count());

    _ = try view.get(0);
}

test "memory_safety: ArrayCompositeTreeView getReadonly should reclaim unpublished child view on OOM" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 128,
    });
    defer pool.deinit();

    const Inner = FixedContainerType(struct { x: UintType(64) });
    const VectorType = FixedVectorType(Inner, 2, .{});
    const value: VectorType.Type = .{ .{ .x = 1 }, .{ .x = 2 } };
    const root = try VectorType.tree.fromValue(&pool, &value);
    var view = try VectorType.TreeView.init(failing.allocator(), &pool, root);
    defer view.deinit();

    try view.chunks.state.children_nodes.ensureUnusedCapacity(failing.allocator(), 1);
    const gindex = Gindex.fromDepth(VectorType.chunk_depth, 0);
    const child_node = try view.chunks.state.getChildNode(gindex);
    const child_ref_count = child_node.getState(&pool).refCount();
    const outstanding_bytes = failing.allocated_bytes - failing.freed_bytes;

    failing.fail_index = failing.alloc_index + 1;
    try std.testing.expectError(error.OutOfMemory, view.getReadonly(0));
    failing.fail_index = std.math.maxInt(usize);

    // A failed readonly cache insertion must release the child view's node ref and allocation.
    try std.testing.expectEqual(child_ref_count, child_node.getState(&pool).refCount());
    try std.testing.expectEqual(outstanding_bytes, failing.allocated_bytes - failing.freed_bytes);

    _ = try view.getReadonly(0);
}
