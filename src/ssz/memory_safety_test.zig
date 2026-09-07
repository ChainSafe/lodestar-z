const std = @import("std");
const pmt = @import("persistent_merkle_tree");
const Gindex = pmt.Gindex;
const Node = pmt.Node;
const ChunkedLeafType = pmt.ChunkedLeaf;
const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;
const ArmOnSizeAllocator = @import("testing_allocators").ArmOnSizeAllocator;
const Hasher = @import("hasher.zig").Hasher;
const isFixedType = @import("type/type_kind.zig").isFixedType;
const FixedContainerType = @import("type/container.zig").FixedContainerType;
const VariableContainerType = @import("type/container.zig").VariableContainerType;
const FixedListType = @import("type/list.zig").FixedListType;
const VariableListType = @import("type/list.zig").VariableListType;
const FixedVectorType = @import("type/vector.zig").FixedVectorType;
const UintType = @import("type/uint.zig").UintType;
const BoolType = @import("type/bool.zig").BoolType;
const BitVectorType = @import("type/bit_vector.zig").BitVectorType;
const ByteListType = @import("type/byte_list.zig").ByteListType;
const ByteVectorType = @import("type/byte_vector.zig").ByteVectorType;
const FixedProgressiveListType = @import("type/progressive_list.zig").FixedProgressiveListType;
const VariableProgressiveListType = @import("type/progressive_list.zig").VariableProgressiveListType;
const ProgressiveBitListType = @import("type/progressive_bit_list.zig").ProgressiveBitListType;
const FixedProgressiveContainerType = @import("type/progressive_container.zig").FixedProgressiveContainerType;
const VariableProgressiveContainerType = @import("type/progressive_container.zig").VariableProgressiveContainerType;
const CompatibleUnionType = @import("type/compatible_union.zig").CompatibleUnionType;

const Checkpoint = FixedContainerType(struct {
    epoch: UintType(64),
    root: ByteVectorType(32),
});

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

test "ByteVector tree.deserializeFromBytes should reclaim partial leaves on pool exhaustion" {
    const VectorType = ByteVectorType(64);
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();
    const bytes = [_]u8{0} ** VectorType.fixed_size;

    try std.testing.expectError(
        error.PoolExhausted,
        VectorType.tree.deserializeFromBytes(&pool, &bytes),
    );
    // The first leaf must not remain in the pool after the second leaf allocation fails.
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "ByteVector tree.fromValue should reclaim leaves when the pool is exhausted" {
    const VectorType = ByteVectorType(64);
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 2 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();

    try std.testing.expectError(
        error.PoolExhausted,
        VectorType.tree.fromValue(&pool, &VectorType.default_value),
    );
    // The two leaves must not remain in the pool after parent construction fails.
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "BitVector tree.deserializeFromBytes should reclaim partial leaves on pool exhaustion" {
    const VectorType = BitVectorType(512);
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();
    const bytes = [_]u8{0} ** VectorType.fixed_size;

    try std.testing.expectError(
        error.PoolExhausted,
        VectorType.tree.deserializeFromBytes(&pool, &bytes),
    );
    // The first leaf must not remain in the pool after the second leaf allocation fails.
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "BitVector tree.fromValue should reclaim leaves when the pool is exhausted" {
    const VectorType = BitVectorType(512);
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 2 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();

    try std.testing.expectError(
        error.PoolExhausted,
        VectorType.tree.fromValue(&pool, &VectorType.default_value),
    );
    // The two leaves must not remain in the pool after parent construction fails.
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "getAllReadonlyValues should deinit completed prefix and current value on conversion OOM" {
    const allocator = std.testing.allocator;
    const Bytes = ByteListType(32);
    const Element = VariableContainerType(struct {
        first: Bytes,
        second: Bytes,
    });
    const ListType = VariableListType(Element, 2);

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 256,
    });
    defer pool.deinit();

    var source: ListType.Type = .empty;
    defer ListType.deinit(allocator, &source);

    try source.append(allocator, Element.default_value);
    try source.append(allocator, Element.default_value);
    try source.items[0].first.appendSlice(allocator, &.{1});
    try source.items[0].second.appendSlice(allocator, &.{2});
    try source.items[1].first.appendSlice(allocator, &.{3});
    try source.items[1].second.appendSlice(allocator, &.{4});

    const root = try ListType.tree.fromValue(&pool, &source);
    var view = try ListType.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    // Fail the second element's second field after its first field and the prefix own memory.
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 8,
        .resize_fail_index = 0,
    });

    try std.testing.expectError(
        error.OutOfMemory,
        view.getAllReadonlyValues(failing.allocator()),
    );
    // The completed prefix and current partially converted value must not leak.
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "iterator nextValue should deinit current value on conversion OOM" {
    const allocator = std.testing.allocator;
    const Bytes = ByteListType(32);
    const Element = VariableContainerType(struct {
        first: Bytes,
        second: Bytes,
    });
    const ListType = VariableListType(Element, 1);

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 256,
    });
    defer pool.deinit();

    var source: ListType.Type = .empty;
    defer ListType.deinit(allocator, &source);

    try source.append(allocator, Element.default_value);
    try source.items[0].first.appendSlice(allocator, &.{1});
    try source.items[0].second.appendSlice(allocator, &.{2});

    const root = try ListType.tree.fromValue(&pool, &source);
    var view = try ListType.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    var iterator = view.iteratorReadonly(0);
    // Fail the second field after the first field owns an allocation.
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 2,
        .resize_fail_index = 0,
    });

    try std.testing.expectError(error.OutOfMemory, iterator.nextValue(failing.allocator()));
    // The current partially converted value must not leak.
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "VariableList deserializeFromBytes should free offsets on malformed later offset" {
    const ListType = VariableListType(ByteListType(8), 4);
    // Offset 8 declares two elements, so decoding allocates the output list.
    // Offset 4 then moves backward, triggering offsetNotIncreasing after allocation.
    const serialized = [_]u8{ 8, 0, 0, 0, 4, 0, 0, 0 };
    var tracking = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = tracking.allocator();

    var out = ListType.default_value;
    defer out.deinit(allocator);

    try std.testing.expectError(
        error.offsetNotIncreasing,
        ListType.deserializeFromBytes(allocator, &serialized, &out),
    );
    // The partially initialized output must not leak after malformed input is rejected.
    try std.testing.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);
}

test "Hasher init container should not leak initialized prefix on later child OOM" {
    const ChildType = FixedVectorType(UintType(64), 8, .{});
    const ContainerType = FixedContainerType(struct {
        first: ChildType,
        second: ChildType,
    });
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 2 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        Hasher(ContainerType).init(failing.allocator()),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "Hasher init composite vector should not leak initialized child on parent OOM" {
    const ChildType = FixedVectorType(UintType(64), 8, .{});
    const VectorType = FixedVectorType(ChildType, 2, .{});
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 2 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        Hasher(VectorType).init(failing.allocator()),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "Hasher init composite list should not leak children slice on recursive child OOM" {
    const ChildType = FixedVectorType(UintType(64), 8, .{});
    const ListType = FixedListType(ChildType, 4, .{});
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        Hasher(ListType).init(failing.allocator()),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

// std.testing.allocator can't see pool-slot leaks, so check getNodesInUse() against a baseline.
test "TreeView composite list sliceTo does not leak pool nodes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 512 });
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    for (0..8) |i| try list.append(allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const baseline = pool.getNodesInUse();
    for (0..7) |idx| {
        var sliced = try view.sliceTo(idx);
        sliced.deinit();
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
}

// set takes ownership only on success; setValue/push errdefer the view for the OOM path.
test "TreeView composite list setValue - OOM does not double-free the element view" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var saw_oom = false;
    // Build a fresh view with failures disabled, then fail one allocation made by setValue().
    for (0..200) |fail_after| {
        var oom = DoubleFreeDetectAllocator.init(
            std.testing.allocator,
            std.math.maxInt(usize),
        );
        defer oom.deinit();

        var operation_succeeded = false;
        {
            const allocator = oom.allocator();
            var pool = try Node.Pool.init(.{
                .page_allocator = std.testing.allocator,
                .allocator = allocator,
                .pool_size = 256,
            });
            defer pool.deinit();

            const root = try ListType.tree.fromValue(&pool, &list);
            var view = try ListType.TreeView.init(allocator, &pool, root);
            defer view.deinit();

            oom.failing.fail_index = oom.failing.alloc_index + fail_after;
            var operation_error: ?anyerror = null;
            view.setValue(0, &newval) catch |err| {
                operation_error = err;
            };
            if (operation_error) |err| {
                switch (err) {
                    error.OutOfMemory => saw_oom = true,
                    else => return err,
                }
            } else {
                operation_succeeded = true;
            }
        }
        // Both the view and Pool have now run their cleanup, so any overlapping free is visible.
        try std.testing.expect(!oom.double_free);

        if (operation_succeeded) {
            try std.testing.expect(saw_oom);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "TreeView composite list push - OOM does not double-free" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var saw_oom = false;
    // Build a fresh view with failures disabled, then fail one allocation made by pushValue().
    for (0..200) |fail_after| {
        var oom = DoubleFreeDetectAllocator.init(
            std.testing.allocator,
            std.math.maxInt(usize),
        );
        defer oom.deinit();

        var operation_succeeded = false;
        {
            const allocator = oom.allocator();
            var pool = try Node.Pool.init(.{
                .page_allocator = std.testing.allocator,
                .allocator = allocator,
                .pool_size = 256,
            });
            defer pool.deinit();

            const root = try ListType.tree.fromValue(&pool, &list);
            var view = try ListType.TreeView.init(allocator, &pool, root);
            defer view.deinit();

            oom.failing.fail_index = oom.failing.alloc_index + fail_after;
            var operation_error: ?anyerror = null;
            view.pushValue(&newval) catch |err| {
                operation_error = err;
            };
            if (operation_error) |err| {
                switch (err) {
                    error.OutOfMemory => saw_oom = true,
                    else => return err,
                }
            } else {
                operation_succeeded = true;
            }
        }
        // Both the view and Pool have now run their cleanup, so any overlapping free is visible.
        try std.testing.expect(!oom.double_free);

        if (operation_succeeded) {
            try std.testing.expect(saw_oom);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "TreeView composite list set(index, ownedView) - failed set leaves the element view to the caller" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var saw_oom = false;
    // Create both views before enabling failures so every failed attempt belongs to set().
    for (0..200) |fail_after| {
        var oom = DoubleFreeDetectAllocator.init(
            std.testing.allocator,
            std.math.maxInt(usize),
        );
        defer oom.deinit();

        var operation_succeeded = false;
        {
            const allocator = oom.allocator();
            var pool = try Node.Pool.init(.{
                .page_allocator = std.testing.allocator,
                .allocator = allocator,
                .pool_size = 256,
            });
            defer pool.deinit();

            const root = try ListType.tree.fromValue(&pool, &list);
            var view = try ListType.TreeView.init(allocator, &pool, root);
            defer view.deinit();

            const elem_node = try Checkpoint.tree.fromValue(&pool, &newval);
            const elem_view = try Checkpoint.TreeView.init(allocator, &pool, elem_node);
            var caller_owns_element = true;
            defer if (caller_owns_element) elem_view.deinit();

            const elem_addr = @intFromPtr(elem_view);
            // The caller still owns elem_view until set succeeds, so it must remain live on error.
            oom.failing.fail_index = oom.failing.alloc_index + fail_after;
            var operation_error: ?anyerror = null;
            view.set(0, elem_view) catch |err| {
                operation_error = err;
            };
            if (operation_error) |err| {
                switch (err) {
                    error.OutOfMemory => {
                        saw_oom = true;
                        try std.testing.expect(oom.live.contains(elem_addr));
                    },
                    else => return err,
                }
            } else {
                caller_owns_element = false;
                operation_succeeded = true;
            }
        }
        // Both possible owners have now run their cleanup, so a double-free cannot be hidden.
        try std.testing.expect(!oom.double_free);

        if (operation_succeeded) {
            try std.testing.expect(saw_oom);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "TreeView composite list commit - OOM does not double-free" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var saw_oom = false;
    // Stage the update before enabling failures so this sweep covers commit() only.
    for (0..200) |fail_after| {
        var oom = DoubleFreeDetectAllocator.init(
            std.testing.allocator,
            std.math.maxInt(usize),
        );
        defer oom.deinit();

        var operation_succeeded = false;
        {
            const allocator = oom.allocator();
            var pool = try Node.Pool.init(.{
                .page_allocator = std.testing.allocator,
                .allocator = allocator,
                .pool_size = 256,
            });
            defer pool.deinit();

            const root = try ListType.tree.fromValue(&pool, &list);
            var view = try ListType.TreeView.init(allocator, &pool, root);
            defer view.deinit();

            try view.setValue(0, &newval);

            oom.failing.fail_index = oom.failing.alloc_index + fail_after;
            var operation_error: ?anyerror = null;
            view.commit() catch |err| {
                operation_error = err;
            };
            if (operation_error) |err| {
                switch (err) {
                    error.OutOfMemory => saw_oom = true,
                    else => return err,
                }
            } else {
                operation_succeeded = true;
            }
        }
        // The view and Pool have both been released before checking their cleanup paths.
        try std.testing.expect(!oom.double_free);

        if (operation_succeeded) {
            try std.testing.expect(saw_oom);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "TreeView composite list fromValue - pool exhaustion leaves no orphan nodes" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    var saw_exhaustion = false;
    // Adding one slot per attempt moves the failure through element construction and then the
    // list parents.
    for (0..64) |pool_size| {
        var pool = try Node.Pool.init(.{
            .page_allocator = std.testing.allocator,
            .allocator = std.testing.allocator,
            .pool_size = @intCast(pool_size),
        });
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const root = ListType.tree.fromValue(&pool, &list) catch |err| switch (err) {
            error.PoolExhausted => {
                saw_exhaustion = true;
                try std.testing.expectEqual(baseline, pool.getNodesInUse());
                continue;
            },
            else => return err,
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
        try std.testing.expect(saw_exhaustion);
        return;
    }
    return error.TestUnexpectedResult;
}

test "TreeView composite list deserializeFromBytes - pool exhaustion leaves no orphan nodes" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    const bytes = try std.testing.allocator.alloc(u8, ListType.serializedSize(&list));
    defer std.testing.allocator.free(bytes);
    _ = ListType.serializeIntoBytes(&list, bytes);

    var saw_exhaustion = false;
    // Adding one slot per attempt moves the failure through element parsing and then the list
    // parents.
    for (0..64) |pool_size| {
        var pool = try Node.Pool.init(.{
            .page_allocator = std.testing.allocator,
            .allocator = std.testing.allocator,
            .pool_size = @intCast(pool_size),
        });
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const root = ListType.tree.deserializeFromBytes(&pool, bytes) catch |err| switch (err) {
            error.PoolExhausted => {
                saw_exhaustion = true;
                try std.testing.expectEqual(baseline, pool.getNodesInUse());
                continue;
            },
            else => return err,
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
        try std.testing.expect(saw_exhaustion);
        return;
    }
    return error.TestUnexpectedResult;
}

test "TreeView composite list deserializeFromBytes - malformed input errors without leaking" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    const bytes = try std.testing.allocator.alloc(u8, ListType.serializedSize(&list));
    defer std.testing.allocator.free(bytes);
    _ = ListType.serializeIntoBytes(&list, bytes);

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 512 });
    defer pool.deinit();
    const baseline = pool.getNodesInUse();

    // Every truncated prefix must either parse cleanly (a shorter valid list) or error, and
    // never leak pool nodes either way.
    var len: usize = 0;
    while (len <= bytes.len) : (len += 1) {
        const root = ListType.tree.deserializeFromBytes(&pool, bytes[0..len]) catch {
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            continue;
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
}

test "TreeView composite list sliceTo doesn't leak pool nodes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 1024, .{});
    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    for (0..16) |i| try list.append(allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    {
        var w = try view.sliceTo(7);
        w.deinit();
    }

    const before = pool.getNodesInUse();
    for (0..50) |_| {
        var s = try view.sliceTo(7);
        s.deinit();
    }
    const after = pool.getNodesInUse();

    try std.testing.expectEqual(before, after);
}

test "TreeView container setValue/commit - OOM does not double-free" {
    const new_root_bytes: [32]u8 = [_]u8{0xee} ** 32;

    var saw_oom = false;
    // Create the original view before enabling failures. The sweep then walks allocations made by
    // setValue() and commit().
    for (0..200) |fail_after| {
        var oom = DoubleFreeDetectAllocator.init(
            std.testing.allocator,
            std.math.maxInt(usize),
        );
        defer oom.deinit();

        var operation_succeeded = false;
        {
            const allocator = oom.allocator();
            var pool = try Node.Pool.init(.{
                .page_allocator = std.testing.allocator,
                .allocator = allocator,
                .pool_size = 256,
            });
            defer pool.deinit();

            const checkpoint: Checkpoint.Type = .{ .epoch = 1, .root = [_]u8{1} ** 32 };
            const root_node = try Checkpoint.tree.fromValue(&pool, &checkpoint);
            var view = try Checkpoint.TreeView.init(allocator, &pool, root_node);
            defer view.deinit();

            oom.failing.fail_index = oom.failing.alloc_index + fail_after;
            var operation_error: ?anyerror = null;
            view.setValue("root", &new_root_bytes) catch |err| {
                operation_error = err;
            };
            if (operation_error == null) {
                view.commit() catch |err| {
                    operation_error = err;
                };
            }
            if (operation_error) |err| {
                switch (err) {
                    error.OutOfMemory => saw_oom = true,
                    else => return err,
                }
            } else {
                operation_succeeded = true;
            }
        }
        // The child view, container view, and Pool have all completed cleanup at this point.
        try std.testing.expect(!oom.double_free);

        if (operation_succeeded) {
            try std.testing.expect(saw_oom);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "ContainerTreeView commit should reclaim basic nodes after pool exhaustion" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 32 });
    defer pool.deinit();

    const TwoBasic = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const value: TwoBasic.Type = .{ .a = 1, .b = 2 };
    const root = try TwoBasic.tree.fromValue(&pool, &value);
    var view = try TwoBasic.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    const old_root = view.getRoot();
    const old_a = try view.getRootNode("a");
    try view.set("a", 10);
    try view.set("b", 20);

    var filler: std.ArrayList(Node.Id) = .empty;
    defer {
        for (filler.items) |node| pool.unref(node);
        filler.deinit(allocator);
    }
    fill: for (0..pool.nodes.len) |_| {
        const node = pool.createLeafFromUint(0) catch |err| switch (err) {
            error.PoolExhausted => break :fill,
        };
        errdefer pool.unref(node);

        try filler.append(allocator, node);
    }
    try std.testing.expectEqual(
        pool.nodes.len,
        @as(usize, @intFromEnum(pool.next_free_node)),
    );
    try std.testing.expect(filler.items.len >= 2);
    // Reserve two slots for the basic leaves; their parent exhausts the pool.
    pool.unref(filler.pop().?);
    pool.unref(filler.pop().?);
    const baseline = pool.getNodesInUse();

    try std.testing.expectError(error.PoolExhausted, view.commit());
    try std.testing.expectEqual(old_root, view.getRoot());
    // The field cache must remain aligned with the unchanged root after rebuild failure.
    try std.testing.expectEqual(old_a, try view.getRootNode("a"));
    try std.testing.expect(!old_a.getState(&pool).isFree());
    // Fresh leaves must be reclaimed when no rebuilt parent adopts them.
    try std.testing.expectEqual(baseline, pool.getNodesInUse());

    pool.unref(filler.pop().?);
    pool.unref(filler.pop().?);
    const nodes_in_use_before_retry = pool.getNodesInUse();
    try view.commit();
    const committed_root = view.getRoot();
    // A retry must publish the values that remained staged after the failed rebuild.
    try std.testing.expect(committed_root != old_root);
    try std.testing.expect((try view.getRootNode("a")) != old_a);
    try view.commit();
    try std.testing.expectEqual(committed_root, view.getRoot());

    var committed: TwoBasic.Type = undefined;
    try TwoBasic.tree.toValue(view.getRoot(), &pool, &committed);
    try std.testing.expectEqual(@as(u64, 10), committed.a);
    try std.testing.expectEqual(@as(u64, 20), committed.b);
    try std.testing.expectEqual(nodes_in_use_before_retry, pool.getNodesInUse());
}

test "ContainerTreeView retry should adopt a child committed before outer pool exhaustion" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 32 });
    defer pool.deinit();
    const pool_baseline = pool.getNodesInUse();

    {
        const Inner = FixedContainerType(struct { a: UintType(64), b: UintType(64) });
        const Outer = FixedContainerType(struct { inner: Inner, c: UintType(64) });
        const value: Outer.Type = .{ .inner = .{ .a = 1, .b = 2 }, .c = 3 };
        const root = try Outer.tree.fromValue(&pool, &value);
        var outer = try Outer.TreeView.init(allocator, &pool, root);
        defer outer.deinit();

        const old_outer_root = outer.getRoot();
        const old_inner_root = try outer.getRootNode("inner");
        var inner = try outer.get("inner");
        try inner.set("a", 10);

        var filler: std.ArrayList(Node.Id) = .empty;
        defer {
            for (filler.items) |node| pool.unref(node);
            filler.deinit(allocator);
        }
        fill: for (0..pool.nodes.len) |_| {
            const node = pool.createLeafFromUint(0) catch |err| switch (err) {
                error.PoolExhausted => break :fill,
            };
            errdefer pool.unref(node);

            try filler.append(allocator, node);
        }
        try std.testing.expectEqual(
            pool.nodes.len,
            @as(usize, @intFromEnum(pool.next_free_node)),
        );
        try std.testing.expect(filler.items.len >= 2);
        // Reserve two slots for the child leaf and inner branch; the outer parent exhausts
        // the pool.
        pool.unref(filler.pop().?);
        pool.unref(filler.pop().?);

        try std.testing.expectError(error.PoolExhausted, outer.commit());
        try std.testing.expectEqual(old_outer_root, outer.getRoot());
        // A failed outer rebuild must not publish the committed child through its field cache.
        try std.testing.expectEqual(old_inner_root, try outer.getRootNode("inner"));
        try std.testing.expect(inner.getRoot() != old_inner_root);

        var committed_inner: Inner.Type = undefined;
        try Inner.tree.toValue(inner.getRoot(), &pool, &committed_inner);
        try std.testing.expectEqual(@as(u64, 10), committed_inner.a);
        try std.testing.expectEqual(@as(u64, 2), committed_inner.b);

        pool.unref(filler.pop().?);
        try outer.commit();
        // A retry must adopt the child root that committed before the outer rebuild failed.
        try std.testing.expect(outer.getRoot() != old_outer_root);
        try std.testing.expectEqual(inner.getRoot(), try outer.getRootNode("inner"));

        var committed_outer: Outer.Type = undefined;
        try Outer.tree.toValue(outer.getRoot(), &pool, &committed_outer);
        try std.testing.expectEqual(@as(u64, 10), committed_outer.inner.a);
        try std.testing.expectEqual(@as(u64, 2), committed_outer.inner.b);
        try std.testing.expectEqual(@as(u64, 3), committed_outer.c);
    }
    try std.testing.expectEqual(pool_baseline, pool.getNodesInUse());
}

test "TreeView container fromValue - view allocation OOM leaves no orphan pool nodes" {
    const checkpoint: Checkpoint.Type = .{ .epoch = 7, .root = [_]u8{7} ** 32 };
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 64 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();
    try std.testing.expectError(
        error.OutOfMemory,
        Checkpoint.TreeView.fromValue(failing.allocator(), &pool, &checkpoint),
    );
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "TreeView container getFieldRoot on a dirty basic field leaves no orphan pool nodes" {
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 256 });
    defer pool.deinit();

    const checkpoint: Checkpoint.Type = .{ .epoch = 1, .root = [_]u8{1} ** 32 };
    const root_node = try Checkpoint.tree.fromValue(&pool, &checkpoint);
    var view = try Checkpoint.TreeView.init(std.testing.allocator, &pool, root_node);
    defer view.deinit();

    try view.set("epoch", 99);
    const baseline = pool.getNodesInUse();

    var expected = [_]u8{0} ** 32;
    std.mem.writeInt(u64, expected[0..8], 99, .little);
    for (0..10) |_| {
        const field_root = try view.getFieldRoot("epoch");
        try std.testing.expectEqualSlices(u8, &expected, field_root);
    }
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "TreeView container deserialize - view allocation OOM leaves no orphan pool nodes" {
    const value: Checkpoint.Type = .{ .epoch = 7, .root = [_]u8{0x5a} ** 32 };
    var bytes: [Checkpoint.fixed_size]u8 = undefined;
    _ = Checkpoint.serializeIntoBytes(&value, &bytes);

    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 64 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();
    try std.testing.expectError(
        error.OutOfMemory,
        Checkpoint.TreeView.deserialize(failing.allocator(), &pool, &bytes),
    );
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "TreeView list basic clone(transfer_cache) on a dirty view leaves no orphan pool nodes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
    defer pool.deinit();

    const ListType = FixedListType(UintType(32), 16, .{});
    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    for (0..4) |i| try list.append(allocator, @as(u32, @intCast(i + 1)));

    const baseline = pool.getNodesInUse();
    {
        const root = try ListType.tree.fromValue(&pool, &list);
        var view = try ListType.TreeView.init(allocator, &pool, root);
        try view.set(0, @as(u32, 42));
        var cloned = try view.clone(.{});
        cloned.deinit();
        view.deinit();
    }
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

// std.testing.allocator can't see pool-slot leaks, so check getNodesInUse() against a baseline.
test "TreeView basic list sliceTo does not leak pool nodes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 2048 });
    defer pool.deinit();

    const Uint64 = UintType(64);
    const ListType = FixedListType(Uint64, 1024, .{});

    var empty_list: ListType.Type = .empty;
    defer empty_list.deinit(allocator);
    const root_node = try ListType.tree.fromValue(&pool, &empty_list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    for (0..16) |i| try view.push(@intCast(i));
    try view.commit();

    const baseline = pool.getNodesInUse();
    for (0..15) |idx| {
        var sliced = try view.sliceTo(idx);
        sliced.deinit();
        // Any difference means an intermediate orphan root leaked.
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
}

test "ListBasicTreeView chunked_leaf: sliceTo doesn't leak pool nodes" {
    // sliceTo allocates transient roots via setNodeAtDepth / truncate /
    // setNode. Those calls don't consume their input root_node, so the
    // caller must unref the intermediates. The test asserts node count
    // returns to baseline after repeated sliceTo+deinit.
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    for (0..100) |i| try src.append(allocator, @as(u64, @intCast(i)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    // One warmup so any one-time lazy initialization isn't counted.
    {
        var w = try view.sliceTo(50);
        w.deinit();
    }

    const before = pool.getNodesInUse();
    for (0..50) |_| {
        var s = try view.sliceTo(50);
        s.deinit();
    }
    const after = pool.getNodesInUse();

    try std.testing.expectEqual(before, after);
}

test "ListBasicTreeView non-chunked_leaf: sliceTo doesn't leak pool nodes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{});
    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    for (0..100) |i| try src.append(allocator, @as(u64, @intCast(i)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    {
        var w = try view.sliceTo(50);
        w.deinit();
    }

    const before = pool.getNodesInUse();
    for (0..50) |_| {
        var s = try view.sliceTo(50);
        s.deinit();
    }
    const after = pool.getNodesInUse();

    try std.testing.expectEqual(before, after);
}

// Path 3 (shared chunked_leaf) CoWs a fresh node + 2KB blob; if setChildNode OOMs
// it must be reclaimed. Leak shows as getNodesInUse (slot) + testing.allocator (blob).
test "ListBasicTreeView chunked_leaf: set OOM in setChildNode reclaims the CoW chunked_leaf (no leak)" {
    const allocator = std.testing.allocator;
    var view_failing = std.testing.FailingAllocator.init(allocator, .{});
    // Arm the view allocator to OOM on the CoW blob alloc → fails setChildNode's changed.put.
    var armer = ArmOnSizeAllocator{ .backing = allocator, .target = &view_failing, .trigger_len = @sizeOf(ChunkedLeafType) };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = armer.allocator(), .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);

    for (0..100) |i| try src.append(allocator, @as(u64, @intCast(i)));
    const root_id = try ListT.tree.fromValue(&pool, &src);

    var view = try ListT.TreeView.init(view_failing.allocator(), &pool, root_id);
    defer view.deinit();

    const baseline = pool.getNodesInUse();

    // First set on the committed (shared, rc>=1) chunked_leaf takes Path 3.
    armer.armed = true;
    try std.testing.expectError(error.OutOfMemory, view.set(0, 999));
    view_failing.fail_index = std.math.maxInt(usize); // disarm for cleanup
    armer.armed = false;

    // The freshly-CoW'd node + its 2KB blob were reclaimed, not leaked.
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "progressive list tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const List = FixedProgressiveListType(UintType(64));
    var value: List.Type = .empty;
    defer value.deinit(std.testing.allocator);
    for (0..8) |i| try value.append(std.testing.allocator, @intCast(i));

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(List, &value, 32);
}

test "progressive bit list tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Bits = ProgressiveBitListType();
    var value = try Bits.Type.fromBitLen(std.testing.allocator, 300);
    defer value.deinit(std.testing.allocator);

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Bits, &value, 32);
}

test "progressive container tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Container = FixedProgressiveContainerType(struct {
        a: UintType(64),
        b: ByteVectorType(32),
    }, &.{ 1, 1 });
    const value: Container.Type = .{ .a = 1, .b = [_]u8{2} ** 32 };

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Container, &value, 32);
}

test "nested progressive tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Items = FixedProgressiveListType(UintType(8));
    const Container = VariableProgressiveContainerType(struct {
        a: UintType(64),
        items: Items,
    }, &.{ 1, 1 });

    var value = Container.default_value;
    defer Container.deinit(std.testing.allocator, &value);
    try value.items.append(std.testing.allocator, 1);

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Container, &value, 32);
}

test "compatible union tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Union = CompatibleUnionType(.{
        .{ 1, UintType(64) },
        .{ 2, UintType(64) },
    });
    const value: Union.Type = @unionInit(Union.Type, "option_1", 42);

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Union, &value, 32);
}

test "progressive tree deserialization uses the standard pool API" {
    const List = FixedProgressiveListType(UintType(64));
    const Bits = ProgressiveBitListType();
    const Container = FixedProgressiveContainerType(struct {
        a: UintType(64),
    }, &.{1});
    const Union = CompatibleUnionType(.{
        .{ 1, UintType(64) },
        .{ 2, UintType(64) },
    });

    inline for (.{ List, Bits, Container, Union }) |ST| {
        try std.testing.expect(@hasDecl(ST.tree, "deserializeFromBytes"));
        if (comptime @hasDecl(ST.tree, "deserializeFromBytes")) {
            try std.testing.expectEqual(2, @typeInfo(@TypeOf(ST.tree.deserializeFromBytes)).@"fn".params.len);
        }
    }
}

test "progressive fixed list byte deserialization preserves out on malformed input" {
    const List = FixedProgressiveListType(BoolType());
    var out: List.Type = .empty;
    defer out.deinit(std.testing.allocator);
    try out.appendSlice(std.testing.allocator, &.{ false, false });

    try std.testing.expectError(
        error.invalidBoolean,
        List.deserializeFromBytes(std.testing.allocator, &.{ 1, 2 }, &out),
    );
    try std.testing.expectEqualSlices(bool, &.{ false, false }, out.items);
}

test "progressive list tree.toValue preserves out on malformed tree" {
    const List = FixedProgressiveListType(UintType(64));
    var pool = try Node.Pool.init(.{
        .page_allocator = std.testing.allocator,
        .allocator = std.testing.allocator,
        .pool_size = 8,
    });
    defer pool.deinit();

    const invalid_contents = try pool.createLeaf(&([_]u8{0} ** 32));
    errdefer pool.unref(invalid_contents);
    const length = try pool.createLeafFromUint(2);
    errdefer pool.unref(length);
    const root = try pool.createBranch(invalid_contents, length);
    defer pool.unref(root);

    var out: List.Type = .empty;
    defer out.deinit(std.testing.allocator);
    try out.append(std.testing.allocator, 99);

    try std.testing.expectError(
        error.InvalidNode,
        List.tree.toValue(std.testing.allocator, root, &pool, &out),
    );
    try std.testing.expectEqualSlices(u64, &.{99}, out.items);
}

test "variable progressive container clone preserves out on OOM" {
    const Items = FixedListType(UintType(8), 8, .{});
    const Container = VariableProgressiveContainerType(struct {
        a: Items,
        b: Items,
    }, &.{ 1, 1 });

    var value = Container.default_value;
    defer Container.deinit(std.testing.allocator, &value);
    try value.a.append(std.testing.allocator, 1);
    try value.b.append(std.testing.allocator, 2);

    var out = Container.default_value;
    defer Container.deinit(std.testing.allocator, &out);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });

    try std.testing.expectError(
        error.OutOfMemory,
        Container.clone(failing.allocator(), &value, &out),
    );
    try std.testing.expectEqual(@as(usize, 0), out.a.items.len);
    try std.testing.expectEqual(@as(usize, 0), out.b.items.len);
}

test "compatible union JSON deserialization preserves out after trailing error" {
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

test "variable progressive list byte deserialization preserves out on OOM" {
    const Bits = ProgressiveBitListType();
    const List = VariableProgressiveListType(Bits);
    var source: List.Type = .empty;
    defer List.deinit(std.testing.allocator, &source);
    for (0..2) |i| {
        var bits = try Bits.Type.fromBitLen(std.testing.allocator, 16 + i);
        errdefer bits.deinit(std.testing.allocator);
        try bits.setAssumeCapacity(i, true);
        try source.append(std.testing.allocator, bits);
    }

    const bytes = try std.testing.allocator.alloc(u8, List.serializedSize(&source));
    defer std.testing.allocator.free(bytes);
    _ = List.serializeIntoBytes(&source, bytes);

    var saw_failure = false;
    var saw_success = false;
    for (0..16) |fail_after| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var out: List.Type = .empty;
        defer List.deinit(failing.allocator(), &out);
        var sentinel: ?Bits.Type = try Bits.Type.fromBitLen(failing.allocator(), 5);
        errdefer if (sentinel) |*value| value.deinit(failing.allocator());
        try sentinel.?.setAssumeCapacity(4, true);
        try out.append(failing.allocator(), sentinel.?);
        sentinel = null;

        failing.fail_index = failing.alloc_index + fail_after;
        List.deserializeFromBytes(failing.allocator(), bytes, &out) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), out.items.len);
            try std.testing.expectEqual(@as(usize, 5), out.items[0].bit_len);
            try std.testing.expect(try out.items[0].get(4));
            saw_failure = true;
            continue;
        };
        try std.testing.expect(List.equals(&source, &out));
        saw_success = true;
    }
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "variable progressive list tree.toValue preserves out on OOM" {
    const Bits = ProgressiveBitListType();
    const List = VariableProgressiveListType(Bits);
    var source: List.Type = .empty;
    defer List.deinit(std.testing.allocator, &source);
    for (0..2) |i| {
        var bits = try Bits.Type.fromBitLen(std.testing.allocator, 300 + i);
        errdefer bits.deinit(std.testing.allocator);
        try bits.setAssumeCapacity(i, true);
        try source.append(std.testing.allocator, bits);
    }

    var pool = try Node.Pool.init(.{
        .page_allocator = std.testing.allocator,
        .allocator = std.testing.allocator,
        .pool_size = 64,
    });
    defer pool.deinit();
    const root = try List.tree.fromValue(&pool, &source);
    defer pool.unref(root);

    var saw_failure = false;
    var saw_success = false;
    for (0..24) |fail_after| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var out: List.Type = .empty;
        defer List.deinit(failing.allocator(), &out);
        var sentinel: ?Bits.Type = try Bits.Type.fromBitLen(failing.allocator(), 5);
        errdefer if (sentinel) |*value| value.deinit(failing.allocator());
        try sentinel.?.setAssumeCapacity(4, true);
        try out.append(failing.allocator(), sentinel.?);
        sentinel = null;

        failing.fail_index = failing.alloc_index + fail_after;
        List.tree.toValue(failing.allocator(), root, &pool, &out) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), out.items.len);
            try std.testing.expectEqual(@as(usize, 5), out.items[0].bit_len);
            try std.testing.expect(try out.items[0].get(4));
            saw_failure = true;
            continue;
        };
        try std.testing.expect(List.equals(&source, &out));
        saw_success = true;
    }
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "fixed progressive container byte deserialization preserves out on malformed input" {
    const Container = FixedProgressiveContainerType(struct {
        a: BoolType(),
        b: BoolType(),
    }, &.{ 1, 1 });
    var out: Container.Type = .{ .a = false, .b = false };

    try std.testing.expectError(
        error.invalidBoolean,
        Container.deserializeFromBytes(&.{ 1, 2 }, &out),
    );
    try std.testing.expect(!out.a);
    try std.testing.expect(!out.b);
}

test "variable progressive container byte deserialization preserves out on malformed input" {
    const Items = FixedProgressiveListType(BoolType());
    const Container = VariableProgressiveContainerType(struct {
        a: UintType(8),
        items: Items,
    }, &.{ 1, 1 });
    var out = Container.default_value;
    defer Container.deinit(std.testing.allocator, &out);
    out.a = 7;
    try out.items.appendSlice(std.testing.allocator, &.{ false, false });

    try std.testing.expectError(
        error.invalidBoolean,
        Container.deserializeFromBytes(
            std.testing.allocator,
            &.{ 9, 5, 0, 0, 0, 1, 2 },
            &out,
        ),
    );
    try std.testing.expectEqual(@as(u8, 7), out.a);
    try std.testing.expectEqualSlices(bool, &.{ false, false }, out.items.items);
}

test "compatible union clone preserves out on OOM" {
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

    var out: Union.Type = @unionInit(Union.Type, "option_1", Items.default_value);
    defer Union.deinit(std.testing.allocator, &out);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });

    try std.testing.expectError(
        error.OutOfMemory,
        Union.clone(failing.allocator(), &source, &out),
    );
    try std.testing.expectEqual(@as(u8, 1), Union.getSelector(&out));
    try std.testing.expectEqual(@as(usize, 0), out.option_1.items.len);
}

test "compatible union byte deserialization preserves out on malformed input" {
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

test "ArrayBasicTreeView set should reclaim unpublished node on OOM" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 128,
    });
    defer pool.deinit();

    const VectorType = FixedVectorType(UintType(64), 4, .{});
    const value: VectorType.Type = .{ 11, 22, 33, 44 };
    const root = try VectorType.tree.fromValue(&pool, &value);
    var view = try VectorType.TreeView.init(failing.allocator(), &pool, root);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 11), try view.get(0));
    const nodes_in_use = pool.getNodesInUse();

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, view.set(0, 99));
    failing.fail_index = std.math.maxInt(usize);

    // The failed update must not leave an extra in-use pool node.
    try std.testing.expectEqual(nodes_in_use, pool.getNodesInUse());
    try std.testing.expectEqual(@as(u64, 11), try view.get(0));

    try view.set(0, 99);
    try std.testing.expectEqual(@as(u64, 99), try view.get(0));
}

test "ArrayCompositeTreeView get should leave caches unchanged on OOM" {
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

test "ArrayCompositeTreeView getReadonly should reclaim unpublished child view on OOM" {
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

test "BitVectorTreeView set should reclaim unpublished node on OOM" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 128,
    });
    defer pool.deinit();

    const Bits = BitVectorType(44);
    const root = try Bits.tree.fromValue(&pool, &Bits.default_value);
    var view = try Bits.TreeView.init(failing.allocator(), &pool, root);
    defer view.deinit();

    try std.testing.expect(!try view.get(0));
    const nodes_in_use = pool.getNodesInUse();

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, view.set(0, true));
    failing.fail_index = std.math.maxInt(usize);

    // The failed update must not leave an extra in-use pool node.
    try std.testing.expectEqual(nodes_in_use, pool.getNodesInUse());
    try std.testing.expect(!try view.get(0));

    try view.set(0, true);
    try std.testing.expect(try view.get(0));
}
