//! Runs the BitArray scenarios through both `BitListTreeView` and
//! `BitVectorTreeView`:
//! 1) get,
//! 2) set,
//! 3) toBoolArray,
//! 4) bits on either side of a chunk boundary,
//! 5) lengths that end exactly on one, and
//! 6) and a `set()` whose allocation fails and must return its pool node.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const BitListType = @import("../type/bit_list.zig").BitListType;
const BitVectorType = @import("../type/bit_vector.zig").BitVectorType;

const bits_per_chunk: usize = 256;
const scenario_pool_size = 8192;
const oom_pool_size = 128;

const BitUpdate = struct { index: usize, bit: bool };

// Every single-chunk scenario shares one list limit; the limit only changes
// the tree depth once it exceeds a chunk.
const limit = 64;

const len = 44;
const roundtrip_set_bits = [_]usize{ 1, 7, 31, 43 };
const roundtrip_updates = [_]BitUpdate{
    .{ .index = 0, .bit = true },
    .{ .index = 7, .bit = false },
    .{ .index = 12, .bit = true },
};

const bool_array_bits = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true };

const uncommitted_len = 8;
const uncommitted_set_bits = [_]usize{ 0, 3, 7 };
const uncommitted_expected = blk: {
    var bits = [_]bool{false} ** uncommitted_len;
    for (uncommitted_set_bits) |i| bits[i] = true;
    break :blk bits;
};

const two_chunk_limit = 2 * bits_per_chunk;
const two_chunk_len = 300;
const two_chunk_set_bits = [_]usize{ 0, bits_per_chunk - 1, bits_per_chunk, two_chunk_len - 1 };
const two_chunk_clear_bits = [_]usize{ 1, bits_per_chunk - 2 };
const two_chunk_updates = [_]BitUpdate{
    .{ .index = bits_per_chunk - 1, .bit = false },
    .{ .index = bits_per_chunk, .bit = false },
    .{ .index = bits_per_chunk / 2, .bit = true },
    .{ .index = bits_per_chunk + 24, .bit = true },
};

const boundary_limit = 4 * bits_per_chunk;
const remainder_lens = [_]usize{ bits_per_chunk + 1, 2 * bits_per_chunk - 1 };
const full_chunk_lens = [_]usize{ bits_per_chunk, 2 * bits_per_chunk };

const ListCase = struct {
    fn Bits(comptime limit: usize, comptime _: usize) type {
        return BitListType(limit);
    }

    fn initValue(allocator: std.mem.Allocator, comptime B: type, len: usize) !B.Type {
        return B.Type.fromBitLen(allocator, len);
    }

    fn deinitValue(allocator: std.mem.Allocator, value: anytype) void {
        value.deinit(allocator);
    }

    fn setBit(value: anytype, index: usize, bit: bool) !void {
        value.setAssumeCapacity(index, bit);
    }

    fn hashTreeRoot(allocator: std.mem.Allocator, comptime B: type, value: *B.Type, out: *[32]u8) !void {
        try B.hashTreeRoot(allocator, value, out);
    }
};

const VectorCase = struct {
    fn Bits(comptime _: usize, comptime len: usize) type {
        return BitVectorType(len);
    }

    fn initValue(_: std.mem.Allocator, comptime B: type, _: usize) !B.Type {
        return B.default_value;
    }

    fn deinitValue(_: std.mem.Allocator, _: anytype) void {}

    fn setBit(value: anytype, index: usize, bit: bool) !void {
        try value.set(index, bit);
    }

    fn hashTreeRoot(_: std.mem.Allocator, comptime B: type, value: *B.Type, out: *[32]u8) !void {
        try B.hashTreeRoot(value, out);
    }
};

fn expectSameRoot(comptime Case: type, comptime B: type, value: *B.Type, view: *B.TreeView) !void {
    var expected_root: [32]u8 = undefined;
    var view_root: [32]u8 = undefined;
    try Case.hashTreeRoot(std.testing.allocator, B, value, &expected_root);
    try view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
}

// Expect a view built from a 44-bit value returns the value's bit at every
// index, and that the same three sets applied to both leave their hash tree
// roots equal.
fn expectViewMatchesValue(comptime Case: type, pool: *Node.Pool) !void {
    const allocator = std.testing.allocator;
    const B = Case.Bits(limit, len);
    var value = try Case.initValue(allocator, B, len);
    defer Case.deinitValue(allocator, &value);
    for (roundtrip_set_bits) |i| try Case.setBit(&value, i, true);

    const view = try B.TreeView.init(allocator, pool, try B.tree.fromValue(pool, &value));
    defer view.deinit();
    for (0..len) |i| try std.testing.expectEqual(try value.get(i), try view.get(i));

    for (roundtrip_updates) |u| {
        try view.set(u.index, u.bit);
        try Case.setBit(&value, u.index, u.bit);
    }
    try expectSameRoot(Case, B, &value, view);
}

// Expect toBoolArray and toBoolArrayInto both return the 12 stored bits in
// order.
fn expectToBoolArrayRoundTrip(comptime Case: type, pool: *Node.Pool) !void {
    const allocator = std.testing.allocator;
    const B = Case.Bits(limit, bool_array_bits.len);
    var value = try Case.initValue(allocator, B, bool_array_bits.len);
    defer Case.deinitValue(allocator, &value);
    for (bool_array_bits, 0..) |bit, i| try Case.setBit(&value, i, bit);

    const view = try B.TreeView.init(allocator, pool, try B.tree.fromValue(pool, &value));
    defer view.deinit();

    const bools = try view.toBoolArray(allocator);
    defer allocator.free(bools);
    try std.testing.expectEqualSlices(bool, &bool_array_bits, bools);

    var out: [bool_array_bits.len]bool = undefined;
    try view.toBoolArrayInto(&out);
    try std.testing.expectEqualSlices(bool, &bool_array_bits, &out);
}

// Expect bits set on the view without a commit show up in toBoolArray.
fn expectUncommittedSetsVisible(comptime Case: type, pool: *Node.Pool) !void {
    const allocator = std.testing.allocator;
    const B = Case.Bits(limit, uncommitted_len);
    var value = try Case.initValue(allocator, B, uncommitted_len);
    defer Case.deinitValue(allocator, &value);

    const view = try B.TreeView.init(allocator, pool, try B.tree.fromValue(pool, &value));
    defer view.deinit();
    for (uncommitted_set_bits) |i| try view.set(i, true);

    const bools = try view.toBoolArray(allocator);
    defer allocator.free(bools);
    try std.testing.expectEqualSlices(bool, &uncommitted_expected, bools);
}

// Expect a 300-bit view spanning two chunks returns the bits set at 0, 255,
// 256 and 299, clears and sets bits on both sides of the boundary, and
// hashes to the same root as the value.
fn expectChunkBoundaryReadsAndWrites(comptime Case: type, pool: *Node.Pool) !void {
    const allocator = std.testing.allocator;
    const B = Case.Bits(two_chunk_limit, two_chunk_len);
    var value = try Case.initValue(allocator, B, two_chunk_len);
    defer Case.deinitValue(allocator, &value);
    for (two_chunk_set_bits) |i| try Case.setBit(&value, i, true);

    const view = try B.TreeView.init(allocator, pool, try B.tree.fromValue(pool, &value));
    defer view.deinit();
    for (two_chunk_set_bits) |i| try std.testing.expect(try view.get(i));
    for (two_chunk_clear_bits) |i| try std.testing.expect(!try view.get(i));

    for (two_chunk_updates) |u| try view.set(u.index, u.bit);
    for (two_chunk_updates) |u| try std.testing.expectEqual(u.bit, try view.get(u.index));

    for (two_chunk_updates) |u| try Case.setBit(&value, u.index, u.bit);
    try expectSameRoot(Case, B, &value, view);
}

// Expect a 257-bit and a 511-bit view return exactly len bools, with bits 0,
// 255, 256 and len - 1 set, bits 1 and 257 clear, and the same root as the
// value.
fn expectRemainderLength(comptime Case: type, comptime len: usize, pool: *Node.Pool) !void {
    const allocator = std.testing.allocator;
    const B = Case.Bits(boundary_limit, len);
    const set_bits = [_]usize{ 0, bits_per_chunk - 1, bits_per_chunk, len - 1 };
    var value = try Case.initValue(allocator, B, len);
    defer Case.deinitValue(allocator, &value);
    for (set_bits) |i| try Case.setBit(&value, i, true);

    const view = try B.TreeView.init(allocator, pool, try B.tree.fromValue(pool, &value));
    defer view.deinit();

    const bools = try view.toBoolArray(allocator);
    defer allocator.free(bools);
    try std.testing.expectEqual(len, bools.len);
    for (set_bits) |i| try std.testing.expect(bools[i]);
    try std.testing.expect(!bools[1]);
    if (len > bits_per_chunk + 2) try std.testing.expect(!bools[bits_per_chunk + 1]);
    try expectSameRoot(Case, B, &value, view);
}

// Expect a 256-bit and a 512-bit view return exactly len bools, with the
// first and last bit of each chunk set, bits 1 and 257 clear, and the same
// root as the value.
fn expectFullChunkLength(comptime Case: type, comptime len: usize, pool: *Node.Pool) !void {
    const allocator = std.testing.allocator;
    const B = Case.Bits(boundary_limit, len);
    var value = try Case.initValue(allocator, B, len);
    defer Case.deinitValue(allocator, &value);
    try Case.setBit(&value, 0, true);
    try Case.setBit(&value, bits_per_chunk - 1, true);
    if (len > bits_per_chunk) {
        try Case.setBit(&value, bits_per_chunk, true);
        try Case.setBit(&value, 2 * bits_per_chunk - 1, true);
    }

    const view = try B.TreeView.init(allocator, pool, try B.tree.fromValue(pool, &value));
    defer view.deinit();

    const bools = try view.toBoolArray(allocator);
    defer allocator.free(bools);
    try std.testing.expectEqual(len, bools.len);
    try std.testing.expect(bools[0]);
    try std.testing.expect(bools[bits_per_chunk - 1]);
    if (len > bits_per_chunk) {
        try std.testing.expect(bools[bits_per_chunk]);
        try std.testing.expect(bools[2 * bits_per_chunk - 1]);
        try std.testing.expect(!bools[bits_per_chunk + 1]);
    }
    try std.testing.expect(!bools[1]);
    try expectSameRoot(Case, B, &value, view);
}

test "BitArray views agree with their value types across chunk boundaries" {
    inline for (.{ ListCase, VectorCase }) |Case| {
        const allocator = std.testing.allocator;
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = scenario_pool_size });
        defer pool.deinit();

        try expectViewMatchesValue(Case, &pool);
        try expectToBoolArrayRoundTrip(Case, &pool);
        try expectUncommittedSetsVisible(Case, &pool);
        try expectChunkBoundaryReadsAndWrites(Case, &pool);
        inline for (remainder_lens) |r_len| try expectRemainderLength(Case, r_len, &pool);
        inline for (full_chunk_lens) |fc_len| try expectFullChunkLength(Case, fc_len, &pool);
    }
}

/// Expect a set whose allocation fails returns OutOfMemory, leaves the pool's
/// in-use node count unchanged, keeps the old bit readable, and succeeds when
/// retried.
fn expectSetReclaimsUnpublishedNodeOnOom(comptime Case: type) !void {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = oom_pool_size });
    defer pool.deinit();

    const B = Case.Bits(limit, len);
    var value = try Case.initValue(allocator, B, len);
    defer Case.deinitValue(allocator, &value);

    const view = try B.TreeView.init(failing.allocator(), &pool, try B.tree.fromValue(&pool, &value));
    defer view.deinit();

    try std.testing.expect(!try view.get(0));
    const nodes_in_use = pool.getNodesInUse();

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, view.set(0, true));
    failing.fail_index = std.math.maxInt(usize);

    try std.testing.expectEqual(nodes_in_use, pool.getNodesInUse());
    try std.testing.expect(!try view.get(0));

    try view.set(0, true);
    try std.testing.expect(try view.get(0));
}

test "memory_safety: BitArray set should reclaim unpublished node on OOM" {
    inline for (.{ ListCase, VectorCase }) |Case| {
        try expectSetReclaimsUnpublishedNodeOnOom(Case);
    }
}
