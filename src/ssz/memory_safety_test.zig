const std = @import("std");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const ChunkedLeafType = pmt.ChunkedLeaf;
const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;
const ArmOnSizeAllocator = @import("testing_allocators").ArmOnSizeAllocator;
const Hasher = @import("hasher.zig").Hasher;
const FixedContainerType = @import("type/container.zig").FixedContainerType;
const FixedListType = @import("type/list.zig").FixedListType;
const FixedVectorType = @import("type/vector.zig").FixedVectorType;
const UintType = @import("type/uint.zig").UintType;
const ByteVectorType = @import("type/byte_vector.zig").ByteVectorType;

const Checkpoint = FixedContainerType(struct {
    epoch: UintType(64),
    root: ByteVectorType(32),
});

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

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = alloc, .allocator = alloc, .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const root = ListType.tree.fromValue(&pool, &list) catch continue;
        var view = ListType.TreeView.init(alloc, &pool, root) catch {
            pool.unref(root);
            continue;
        };
        defer view.deinit();

        // We only care that no path double-frees; the OOM itself is expected.
        view.setValue(0, &newval) catch {};
        try std.testing.expect(!oom.double_free);
    }
}

test "TreeView composite list push - OOM does not double-free" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = alloc, .allocator = alloc, .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const root = ListType.tree.fromValue(&pool, &list) catch continue;
        var view = ListType.TreeView.init(alloc, &pool, root) catch {
            pool.unref(root);
            continue;
        };
        defer view.deinit();

        view.pushValue(&newval) catch {};
        try std.testing.expect(!oom.double_free);
    }
}

test "TreeView composite list set(index, ownedView) - failed set leaves the element view to the caller" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = alloc, .allocator = alloc, .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const root = ListType.tree.fromValue(&pool, &list) catch continue;
        var view = ListType.TreeView.init(alloc, &pool, root) catch {
            pool.unref(root);
            continue;
        };
        defer view.deinit();

        const elem_node = Checkpoint.tree.fromValue(&pool, &newval) catch continue;
        var elem_view = Checkpoint.TreeView.init(alloc, &pool, elem_node) catch {
            pool.unref(elem_node);
            continue;
        };
        const elem_addr = @intFromPtr(elem_view);

        if (view.set(0, elem_view)) |_| {} else |_| {
            try std.testing.expect(oom.live.contains(elem_addr));
            elem_view.deinit();
        }
        try std.testing.expect(!oom.double_free);
    }
}

test "TreeView composite list clone(transfer_cache) - OOM does not double-free cached children" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = alloc, .allocator = alloc, .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const root = ListType.tree.fromValue(&pool, &list) catch continue;
        var view = ListType.TreeView.init(alloc, &pool, root) catch {
            pool.unref(root);
            continue;
        };
        defer view.deinit();

        // Cache a child so the transfer_cache path has something to move.
        _ = view.get(0) catch {};
        const cloned = view.clone(.{ .transfer_cache = true }) catch {
            try std.testing.expect(!oom.double_free);
            continue;
        };
        cloned.deinit();
        try std.testing.expect(!oom.double_free);
    }
}

test "TreeView composite list commit - OOM does not double-free" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..3) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });
    const newval: Checkpoint.Type = .{ .epoch = 99, .root = [_]u8{0xee} ** 32 };

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = alloc, .allocator = alloc, .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const root = ListType.tree.fromValue(&pool, &list) catch continue;
        var view = ListType.TreeView.init(alloc, &pool, root) catch {
            pool.unref(root);
            continue;
        };
        defer view.deinit();

        // Stage a change so commit has work; the sweep injects OOM inside commit too.
        view.setValue(0, &newval) catch {
            try std.testing.expect(!oom.double_free);
            continue;
        };
        view.commit() catch {};
        try std.testing.expect(!oom.double_free);
    }
}

test "TreeView composite list fromValue - OOM leaves no orphan pool nodes" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    var fail_at: usize = 0;
    while (fail_at < 400) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_at, .resize_fail_index = 0 });
        var pool = Node.Pool.init(.{ .page_allocator = failing.allocator(), .allocator = failing.allocator(), .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const root = ListType.tree.fromValue(&pool, &list) catch {
            // OOM mid-build: the error path must release every partial node.
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            continue;
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
}

test "TreeView composite list deserializeFromBytes - OOM leaves no orphan pool nodes" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    const bytes = try std.testing.allocator.alloc(u8, ListType.serializedSize(&list));
    defer std.testing.allocator.free(bytes);
    _ = ListType.serializeIntoBytes(&list, bytes);

    var fail_at: usize = 0;
    while (fail_at < 400) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_at, .resize_fail_index = 0 });
        var pool = Node.Pool.init(.{ .page_allocator = failing.allocator(), .allocator = failing.allocator(), .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const root = ListType.tree.deserializeFromBytes(&pool, bytes) catch {
            // OOM mid-build: the error path must release every partial node.
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            continue;
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
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

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = alloc, .allocator = alloc, .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const checkpoint: Checkpoint.Type = .{ .epoch = 1, .root = [_]u8{1} ** 32 };
        const root_node = Checkpoint.tree.fromValue(&pool, &checkpoint) catch continue;
        var view = Checkpoint.TreeView.init(alloc, &pool, root_node) catch {
            pool.unref(root_node);
            continue;
        };
        defer view.deinit();

        view.setValue("root", &new_root_bytes) catch {
            try std.testing.expect(!oom.double_free);
            continue;
        };
        view.commit() catch {};
        try std.testing.expect(!oom.double_free);
    }
}

test "TreeView container fromValue - OOM leaves no orphan pool nodes" {
    const checkpoint: Checkpoint.Type = .{ .epoch = 7, .root = [_]u8{7} ** 32 };

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_at, .resize_fail_index = 0 });
        var pool = Node.Pool.init(.{ .page_allocator = failing.allocator(), .allocator = failing.allocator(), .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const view = Checkpoint.TreeView.fromValue(failing.allocator(), &pool, &checkpoint) catch {
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            continue;
        };
        view.deinit();
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
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

test "TreeView container deserialize - OOM leaves no orphan pool nodes" {
    const value: Checkpoint.Type = .{ .epoch = 7, .root = [_]u8{0x5a} ** 32 };
    var bytes: [Checkpoint.fixed_size]u8 = undefined;
    _ = Checkpoint.serializeIntoBytes(&value, &bytes);

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_at, .resize_fail_index = 0 });
        var pool = Node.Pool.init(.{ .page_allocator = failing.allocator(), .allocator = failing.allocator(), .pool_size = 0 }) catch continue;
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const view = Checkpoint.TreeView.deserialize(failing.allocator(), &pool, &bytes) catch {
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            continue;
        };
        view.deinit();
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
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
