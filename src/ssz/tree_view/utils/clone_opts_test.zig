//! Checks the clone contract on every tree view type: writes on one side are
//! invisible to the other until committed, cloning drops uncommitted writes,
//! and transfer_cache decides which side keeps the child cache.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const UintType = @import("../../type/uint.zig").UintType;
const ByteVectorType = @import("../../type/byte_vector.zig").ByteVectorType;
const BitListType = @import("../../type/bit_list.zig").BitListType;
const BitVectorType = @import("../../type/bit_vector.zig").BitVectorType;
const FixedContainerType = @import("../../type/container.zig").FixedContainerType;
const FixedVectorType = @import("../../type/vector.zig").FixedVectorType;
const FixedListType = @import("../../type/list.zig").FixedListType;

const pool_size = 4096;
const list_limit = 16;

// One adapter per view type. Each names the SSZ type, builds the fixture root,
// writes and reads one element as a u64, pins the value read before and after
// that write, and exposes the child cache count, so the scenarios below never
// mention a concrete view.
const ArrayBasicCase = struct {
    const T = FixedVectorType(UintType(16), 4, .{});
    const index = 1;
    const initial: u64 = 2;
    const written: u64 = 9;

    fn root(_: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        const value: T.Type = .{ 1, 2, 3, 4 };
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, _: std.mem.Allocator, _: *Node.Pool, n: u64) !void {
        try view.set(index, @as(u16, @intCast(n)));
    }

    fn read(view: *T.TreeView, _: *Node.Pool) !u64 {
        return try view.get(index);
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return view.chunks.state.children_nodes.count();
    }
};

const ArrayCompositeCase = struct {
    const Inner = FixedContainerType(struct { a: UintType(32) });
    const T = FixedVectorType(Inner, 2, .{});
    const index = 1;
    const initial: u64 = 2;
    const written: u64 = 9;

    fn root(_: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        const value: T.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, allocator: std.mem.Allocator, pool: *Node.Pool, n: u64) !void {
        const replacement: Inner.Type = .{ .a = @intCast(n) };
        const replacement_root = try Inner.tree.fromValue(pool, &replacement);
        const replacement_view = try Inner.TreeView.init(allocator, pool, replacement_root);
        errdefer replacement_view.deinit();
        try view.set(index, replacement_view);
    }

    fn read(view: *T.TreeView, pool: *Node.Pool) !u64 {
        const element = try view.get(index);
        var value: Inner.Type = undefined;
        try Inner.tree.toValue(element.getRoot(), pool, &value);
        return value.a;
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return view.chunks.children_data.count();
    }
};

const BitListCase = struct {
    const T = BitListType(64);
    const fixture_len = 12;
    const fixture_set_bits = [_]usize{ 1, 9 };
    const index = 2;
    const initial: u64 = 0;
    const written: u64 = 1;

    fn root(allocator: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        var value = try T.Type.fromBitLen(allocator, fixture_len);
        defer value.deinit(allocator);
        for (fixture_set_bits) |i| value.setAssumeCapacity(i, true);
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, _: std.mem.Allocator, _: *Node.Pool, n: u64) !void {
        try view.set(index, n != 0);
    }

    fn read(view: *T.TreeView, _: *Node.Pool) !u64 {
        return @intFromBool(try view.get(index));
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return view.data.state.children_nodes.count();
    }
};

const BitVectorCase = struct {
    const T = BitVectorType(44);
    const fixture_set_bits = [_]usize{ 1, 7, 31 };
    const index = 2;
    const initial: u64 = 0;
    const written: u64 = 1;

    fn root(_: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        var value: T.Type = T.default_value;
        for (fixture_set_bits) |i| try value.set(i, true);
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, _: std.mem.Allocator, _: *Node.Pool, n: u64) !void {
        try view.set(index, n != 0);
    }

    fn read(view: *T.TreeView, _: *Node.Pool) !u64 {
        return @intFromBool(try view.get(index));
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return view.data.state.children_nodes.count();
    }
};

const ContainerCase = struct {
    const T = FixedContainerType(struct { n: UintType(64) });
    const initial: u64 = 1;
    const written: u64 = 9;

    fn root(_: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        const value: T.Type = .{ .n = 1 };
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, _: std.mem.Allocator, _: *Node.Pool, n: u64) !void {
        try view.set("n", n);
    }

    fn read(view: *T.TreeView, _: *Node.Pool) !u64 {
        return try view.get("n");
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return @intFromBool(view.child_data[0] != null);
    }
};

const ListBasicCase = struct {
    const T = FixedListType(UintType(32), list_limit, .{});
    const index = 1;
    const initial: u64 = 2;
    const written: u64 = 9;

    fn root(allocator: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        var value: T.Type = .empty;
        defer value.deinit(allocator);
        try value.appendSlice(allocator, &[_]u32{ 1, 2, 3 });
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, _: std.mem.Allocator, _: *Node.Pool, n: u64) !void {
        try view.set(index, @as(u32, @intCast(n)));
    }

    fn read(view: *T.TreeView, _: *Node.Pool) !u64 {
        return try view.get(index);
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return view.chunks.state.children_nodes.count();
    }
};

const ListCompositeCase = struct {
    const Checkpoint = FixedContainerType(struct {
        epoch: UintType(64),
        root: ByteVectorType(32),
    });
    const T = FixedListType(Checkpoint, list_limit, .{});
    const index = 0;
    const initial: u64 = 1;
    const written: u64 = 9;

    fn root(allocator: std.mem.Allocator, pool: *Node.Pool) !Node.Id {
        var value: T.Type = .empty;
        defer value.deinit(allocator);
        try value.append(allocator, .{ .epoch = 1, .root = [_]u8{1} ** 32 });
        return T.tree.fromValue(pool, &value);
    }

    fn write(view: *T.TreeView, allocator: std.mem.Allocator, pool: *Node.Pool, n: u64) !void {
        const replacement: Checkpoint.Type = .{ .epoch = n, .root = [_]u8{9} ** 32 };
        const replacement_root = try Checkpoint.tree.fromValue(pool, &replacement);
        const replacement_view = try Checkpoint.TreeView.init(allocator, pool, replacement_root);
        errdefer replacement_view.deinit();
        try view.set(index, replacement_view);
    }

    fn read(view: *T.TreeView, pool: *Node.Pool) !u64 {
        const element = try view.get(index);
        var value: Checkpoint.Type = undefined;
        try Checkpoint.tree.toValue(element.getRoot(), pool, &value);
        return value.epoch;
    }

    fn cachedChildren(view: *T.TreeView) usize {
        return view.chunks.children_data.count();
    }
};

// The view types whose per-file clone tests this file replaces.
const cases = .{
    ArrayBasicCase,
    ArrayCompositeCase,
    BitListCase,
    BitVectorCase,
    ContainerCase,
    ListBasicCase,
    ListCompositeCase,
};

fn initView(comptime Case: type, allocator: std.mem.Allocator, pool: *Node.Pool) !*Case.T.TreeView {
    return Case.T.TreeView.init(allocator, pool, try Case.root(allocator, pool));
}

// Expect a write committed on the clone changes the clone's value and leaves
// the source's value unchanged.
fn expectCloneWriteIsolated(comptime Case: type) !void {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();
    const source = try initView(Case, allocator, &pool);
    defer source.deinit();
    const cloned = try source.clone(.{});
    defer cloned.deinit();

    try Case.write(cloned, allocator, &pool, Case.written);
    try cloned.commit();

    try std.testing.expectEqual(Case.initial, try Case.read(source, &pool));
    try std.testing.expectEqual(Case.written, try Case.read(cloned, &pool));
}

// Expect a clone taken after a committed write on the source reads the
// written value.
fn expectCloneReadsCommittedWrite(comptime Case: type) !void {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();
    const source = try initView(Case, allocator, &pool);
    defer source.deinit();

    try Case.write(source, allocator, &pool, Case.written);
    try source.commit();
    const cloned = try source.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(Case.written, try Case.read(cloned, &pool));
}

// Expect cloning a source with an uncommitted write discards it, so both
// source and clone read the initial value afterwards.
fn expectCloneDropsUncommittedWrite(comptime Case: type) !void {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();
    const source = try initView(Case, allocator, &pool);
    defer source.deinit();

    try Case.write(source, allocator, &pool, Case.written);
    try std.testing.expectEqual(Case.written, try Case.read(source, &pool));
    const cloned = try source.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(Case.initial, try Case.read(source, &pool));
    try std.testing.expectEqual(Case.initial, try Case.read(cloned, &pool));
}

// Expect clone with transfer_cache = false keeps the child cache on the
// source and gives the clone an empty one.
fn expectCloneWithoutCacheTransfer(comptime Case: type) !void {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();
    const source = try initView(Case, allocator, &pool);
    defer source.deinit();

    _ = try Case.read(source, &pool);
    try source.commit();
    try std.testing.expect(Case.cachedChildren(source) > 0);
    const cloned = try source.clone(.{ .transfer_cache = false });
    defer cloned.deinit();

    try std.testing.expect(Case.cachedChildren(source) > 0);
    try std.testing.expectEqual(@as(usize, 0), Case.cachedChildren(cloned));
}

// Expect the default clone moves the child cache to the clone and leaves the
// source with none.
fn expectCloneTransfersCache(comptime Case: type) !void {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();
    const source = try initView(Case, allocator, &pool);
    defer source.deinit();

    _ = try Case.read(source, &pool);
    try source.commit();
    try std.testing.expect(Case.cachedChildren(source) > 0);
    const cloned = try source.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), Case.cachedChildren(source));
    try std.testing.expect(Case.cachedChildren(cloned) > 0);
}

test "TreeView clone isolates updates, reads committed state, drops uncommitted changes, and honors transfer_cache" {
    inline for (cases) |Case| {
        try expectCloneWriteIsolated(Case);
        try expectCloneReadsCommittedWrite(Case);
        try expectCloneDropsUncommittedWrite(Case);
        try expectCloneWithoutCacheTransfer(Case);
        try expectCloneTransfersCache(Case);
    }
}
