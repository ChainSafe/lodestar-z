const std = @import("std");
const pmt = @import("persistent_merkle_tree");
const Gindex = pmt.Gindex;
const Node = pmt.Node;
const ChunkedLeafType = pmt.ChunkedLeaf;
const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;
const ArmOnSizeAllocator = @import("testing_allocators").ArmOnSizeAllocator;
const Hasher = @import("hasher.zig").Hasher;
const FixedContainerType = @import("type/container.zig").FixedContainerType;
const VariableContainerType = @import("type/container.zig").VariableContainerType;
const FixedListType = @import("type/list.zig").FixedListType;
const VariableListType = @import("type/list.zig").VariableListType;
const FixedVectorType = @import("type/vector.zig").FixedVectorType;
const UintType = @import("type/uint.zig").UintType;
const BitVectorType = @import("type/bit_vector.zig").BitVectorType;
const ByteListType = @import("type/byte_list.zig").ByteListType;
const ByteVectorType = @import("type/byte_vector.zig").ByteVectorType;

const Checkpoint = FixedContainerType(struct {
    epoch: UintType(64),
    root: ByteVectorType(32),
});

fn fillPoolLeavingFreeSlots(pool: *Node.Pool, free_slot_count: usize) !void {
    const available_free_count = pool.nodes.len - @intFromEnum(pool.next_free_node);
    std.debug.assert(free_slot_count <= available_free_count);

    const filler_count = available_free_count - free_slot_count;
    for (0..filler_count) |_| {
        _ = try pool.createLeaf(&[_]u8{0} ** 32);
    }
}

test "ByteVector tree.deserializeFromBytes should reclaim partial leaves on pool exhaustion" {
    const VectorType = ByteVectorType(64);
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1 });
    defer pool.deinit();

    try fillPoolLeavingFreeSlots(&pool, 1);

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

    try fillPoolLeavingFreeSlots(&pool, 2);

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

    try fillPoolLeavingFreeSlots(&pool, 1);

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

    try fillPoolLeavingFreeSlots(&pool, 2);

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
    // Offset 8 declares two elements, so decoding allocates the offsets array.
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
    // The temporary offsets must not leak after malformed input is rejected.
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

    var fail_at: usize = 0;
    while (fail_at < 200) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();
        const alloc = oom.allocator();

        var pool = Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = alloc, .pool_size = 256 }) catch continue;
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

        var pool = Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = alloc, .pool_size = 256 }) catch continue;
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

        var pool = Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = alloc, .pool_size = 256 }) catch continue;
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

        var pool = Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = alloc, .pool_size = 256 }) catch continue;
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

        var pool = Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = alloc, .pool_size = 256 }) catch continue;
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

test "TreeView composite list fromValue - pool exhaustion leaves no orphan nodes" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 6 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();
    try std.testing.expectError(error.PoolExhausted, ListType.tree.fromValue(&pool, &list));
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "TreeView composite list deserializeFromBytes - pool exhaustion leaves no orphan nodes" {
    const ListType = FixedListType(Checkpoint, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(std.testing.allocator);
    for (0..6) |i| try list.append(std.testing.allocator, .{ .epoch = @intCast(i), .root = [_]u8{@intCast(i)} ** 32 });

    const bytes = try std.testing.allocator.alloc(u8, ListType.serializedSize(&list));
    defer std.testing.allocator.free(bytes);
    _ = ListType.serializeIntoBytes(&list, bytes);

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 6 });
    defer pool.deinit();

    const baseline = pool.getNodesInUse();
    try std.testing.expectError(
        error.PoolExhausted,
        ListType.tree.deserializeFromBytes(&pool, bytes),
    );
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
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

        var pool = Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = alloc, .pool_size = 256 }) catch continue;
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
