const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const BitArray = @import("bit_array.zig").BitArray;
const assertTreeViewType = @import("utils/assert.zig").assertTreeViewType;
const CloneOpts = @import("utils/clone_opts.zig").CloneOpts;

pub fn BitListTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("BitListTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or ST.Element.kind != .bool) {
            @compileError("BitListTreeView can only be used with BitList (List of bool)");
        }
    }

    const TreeView = struct {
        allocator: Allocator,
        data: BitOps,

        pub const SszType = ST;
        pub const Element = bool;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const BitOps = BitArray(chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self {
            const ptr = try allocator.create(Self);
            errdefer allocator.destroy(ptr);

            try BitOps.init(&ptr.data, allocator, pool, root);
            ptr.allocator = allocator;
            return ptr;
        }

        pub fn clone(self: *Self, opts: CloneOpts) !*Self {
            const ptr = try self.allocator.create(Self);
            errdefer self.allocator.destroy(ptr);

            try self.data.clone(opts, &ptr.data);
            ptr.allocator = self.allocator;
            return ptr;
        }

        pub fn deinit(self: *Self) void {
            self.data.deinit();
            self.allocator.destroy(self);
        }

        pub fn commit(self: *Self) !void {
            try self.data.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.data.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.data.root.getRoot(self.data.pool).*;
        }

        pub fn getRoot(self: *const Self) Node.Id {
            return self.data.root;
        }

        fn readLength(self: *Self) !usize {
            const length_node = try self.data.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.data.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.readLength();
            return try self.data.get(index, list_length);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.readLength();
            try self.data.set(index, value, list_length);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const list_length = try self.readLength();
            const values = try allocator.alloc(bool, list_length);
            errdefer allocator.free(values);
            try self.data.fillBools(values, list_length);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            const list_length = try self.readLength();
            if (out.len != list_length) return error.InvalidSize;
            try self.data.fillBools(out, list_length);
        }
    };

    assertTreeViewType(TreeView);
    return TreeView;
}

const BitListType = @import("../type/bit_list.zig").BitListType;
test "BitListTreeView get/set roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var expected = try Bits.Type.fromBitLen(allocator, 12);
    defer expected.deinit(allocator);
    try expected.setAssumeCapacity(1, true);
    try expected.setAssumeCapacity(9, true);

    const root = try Bits.tree.fromValue(&pool, &expected);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    for (0..12) |i| {
        try std.testing.expectEqual(try expected.get(i), try view.get(i));
    }

    try view.set(0, true);
    try view.set(1, false);
    try view.set(10, true);
    try view.set(11, false);

    try expected.setAssumeCapacity(0, true);
    try expected.setAssumeCapacity(1, false);
    try expected.setAssumeCapacity(10, true);
    try expected.setAssumeCapacity(11, false);

    var expected_root: [32]u8 = undefined;
    var view_root: [32]u8 = undefined;
    try Bits.hashTreeRoot(allocator, &expected, &expected_root);
    try view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
}

test "BitListTreeView clone(true) does not transfer cache" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 12);
    defer value.deinit(allocator);
    try value.setAssumeCapacity(1, true);
    try value.setAssumeCapacity(9, true);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    _ = try view.get(0);
    try std.testing.expect(view.data.children_nodes.count() > 0);

    var cloned_no_cache = try view.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(view.data.children_nodes.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.data.children_nodes.count());
}

test "BitListTreeView clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 12);
    defer value.deinit(allocator);
    try value.setAssumeCapacity(1, true);
    try value.setAssumeCapacity(9, true);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    _ = try view.get(0);
    try std.testing.expect(view.data.children_nodes.count() > 0);

    var cloned = try view.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), view.data.children_nodes.count());
    try std.testing.expect(cloned.data.children_nodes.count() > 0);
}

test "BitListTreeView clone isolates updates" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 12);
    defer value.deinit(allocator);

    const root = try Bits.tree.fromValue(&pool, &value);
    var v1 = try Bits.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try v2.set(0, true);
    try v2.commit();

    try std.testing.expect(!try v1.get(0));
    try std.testing.expect(try v2.get(0));
}

test "BitListTreeView clone reads committed state" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 12);
    defer value.deinit(allocator);

    const root = try Bits.tree.fromValue(&pool, &value);
    var v1 = try Bits.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    try v1.set(1, true);
    try v1.commit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try std.testing.expect(try v2.get(1));
}

test "BitListTreeView clone drops uncommitted changes" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 12);
    defer value.deinit(allocator);

    const root = try Bits.tree.fromValue(&pool, &value);
    var v = try Bits.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    try v.set(2, true);
    try std.testing.expect(try v.get(2));

    var dropped = try v.clone(.{});
    defer dropped.deinit();

    try std.testing.expect(!try v.get(2));
    try std.testing.expect(!try dropped.get(2));
}

test "BitListTreeView toBoolArray roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(16);

    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const expected_bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true };
    var value = try Bits.Type.fromBoolSlice(allocator, &expected_bools);
    defer value.deinit(allocator);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    const actual_bools = try view.toBoolArray(allocator);
    defer allocator.free(actual_bools);
    try std.testing.expectEqualSlices(bool, &expected_bools, actual_bools);
}

test "BitListTreeView toBoolArrayInto roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(16);

    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const expected_bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true };
    var value = try Bits.Type.fromBoolSlice(allocator, &expected_bools);
    defer value.deinit(allocator);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    var out: [expected_bools.len]bool = undefined;
    try view.toBoolArrayInto(&out);
    try std.testing.expectEqualSlices(bool, &expected_bools, &out);
}

test "BitListTreeView set reflects in toBoolArray" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(16);

    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 8);
    defer value.deinit(allocator);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    try view.set(0, true);
    try view.set(3, true);
    try view.set(7, true);

    const expected_bools = [_]bool{ true, false, false, true, false, false, false, true };
    const actual_bools = try view.toBoolArray(allocator);
    defer allocator.free(actual_bools);
    try std.testing.expectEqualSlices(bool, &expected_bools, actual_bools);
}

test "BitListTreeView multi-chunk" {
    const allocator = std.testing.allocator;
    // 300 bits requires 2 chunks (256 bits per chunk)
    const Bits = BitListType(512);

    var pool = try Node.Pool.init(allocator, 8192);
    defer pool.deinit();

    var value = try Bits.Type.fromBitLen(allocator, 300);
    defer value.deinit(allocator);
    try value.setAssumeCapacity(0, true);
    try value.setAssumeCapacity(255, true); // last bit of first chunk
    try value.setAssumeCapacity(256, true); // first bit of second chunk
    try value.setAssumeCapacity(299, true); // last bit

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    try std.testing.expect(try view.get(0));
    try std.testing.expect(try view.get(255));
    try std.testing.expect(try view.get(256));
    try std.testing.expect(try view.get(299));
    try std.testing.expect(!try view.get(1));
    try std.testing.expect(!try view.get(254));

    try view.set(255, false);
    try view.set(256, false);
    try view.set(128, true);
    try view.set(280, true);

    try std.testing.expect(!try view.get(255));
    try std.testing.expect(!try view.get(256));
    try std.testing.expect(try view.get(128));
    try std.testing.expect(try view.get(280));

    try value.setAssumeCapacity(255, false);
    try value.setAssumeCapacity(256, false);
    try value.setAssumeCapacity(128, true);
    try value.setAssumeCapacity(280, true);

    var expected_root: [32]u8 = undefined;
    var view_root: [32]u8 = undefined;
    try Bits.hashTreeRoot(allocator, &value, &expected_root);
    try view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
}

test "BitListTreeView padding bit roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    const test_cases = [_]usize{ 1, 7, 8, 9, 15, 16, 17, 31, 32, 33 };

    for (test_cases) |bit_len| {
        // Create value with alternating bits
        var value = try Bits.Type.fromBitLen(allocator, bit_len);
        defer value.deinit(allocator);

        for (0..bit_len) |i| {
            try value.setAssumeCapacity(i, i % 2 == 0);
        }

        const serialized = try allocator.alloc(u8, Bits.serializedSize(&value));
        defer allocator.free(serialized);
        _ = Bits.serializeIntoBytes(&value, serialized);

        var deserialized: Bits.Type = Bits.Type.empty;
        defer deserialized.deinit(allocator);
        try Bits.deserializeFromBytes(allocator, serialized, &deserialized);

        const root = try Bits.tree.fromValue(&pool, &deserialized);
        var view = try Bits.TreeView.init(allocator, &pool, root);
        defer view.deinit();

        const bools = try view.toBoolArray(allocator);
        defer allocator.free(bools);

        try std.testing.expectEqual(bit_len, bools.len);
        for (0..bit_len) |i| {
            try std.testing.expectEqual(i % 2 == 0, bools[i]);
        }
    }
}

test "BitListTreeView remainder edge cases (1 and 255)" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(1024);

    var pool = try Node.Pool.init(allocator, 8192);
    defer pool.deinit();

    inline for ([_]usize{ 257, 511 }) |bit_len| {
        var value = try Bits.Type.fromBitLen(allocator, bit_len);
        defer value.deinit(allocator);

        try value.setAssumeCapacity(0, true);
        try value.setAssumeCapacity(255, true);
        try value.setAssumeCapacity(256, true);
        try value.setAssumeCapacity(bit_len - 1, true);

        const root = try Bits.tree.fromValue(&pool, &value);
        var view = try Bits.TreeView.init(allocator, &pool, root);
        defer view.deinit();

        const bools = try view.toBoolArray(allocator);
        defer allocator.free(bools);
        try std.testing.expectEqual(bit_len, bools.len);

        try std.testing.expect(bools[0]);
        try std.testing.expect(bools[255]);
        try std.testing.expect(bools[256]);
        try std.testing.expect(bools[bit_len - 1]);

        if (bit_len > 2) try std.testing.expect(!bools[1]);
        if (bit_len > 258) try std.testing.expect(!bools[257]);

        var expected_root: [32]u8 = undefined;
        var view_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(allocator, &value, &expected_root);
        try view.hashTreeRoot(&view_root);
        try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
    }
}

test "BitListTreeView full-chunk edge cases (remainder=0)" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(1024);

    var pool = try Node.Pool.init(allocator, 8192);
    defer pool.deinit();

    inline for ([_]usize{ 256, 512 }) |bit_len| {
        var value = try Bits.Type.fromBitLen(allocator, bit_len);
        defer value.deinit(allocator);

        try value.setAssumeCapacity(0, true);
        try value.setAssumeCapacity(255, true);
        if (bit_len > 256) {
            try value.setAssumeCapacity(256, true);
            try value.setAssumeCapacity(511, true);
        }

        const root = try Bits.tree.fromValue(&pool, &value);
        var view = try Bits.TreeView.init(allocator, &pool, root);
        defer view.deinit();

        const bools = try view.toBoolArray(allocator);
        defer allocator.free(bools);
        try std.testing.expectEqual(bit_len, bools.len);

        try std.testing.expect(bools[0]);
        try std.testing.expect(bools[255]);
        if (bit_len > 256) {
            try std.testing.expect(bools[256]);
            try std.testing.expect(bools[511]);
        }

        if (bit_len > 2) try std.testing.expect(!bools[1]);
        if (bit_len > 258) try std.testing.expect(!bools[257]);

        var expected_root: [32]u8 = undefined;
        var view_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(allocator, &value, &expected_root);
        try view.hashTreeRoot(&view_root);
        try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
    }
}
