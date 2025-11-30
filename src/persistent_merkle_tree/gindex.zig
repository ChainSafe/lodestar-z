const std = @import("std");

const GindexUint = @import("hashing").GindexUint;
const Depth = @import("hashing").Depth;
const max_depth = @import("hashing").max_depth;

pub const Gindex = enum(GindexUint) {
    _,

    pub const Uint = GindexUint;

    pub inline fn fromUint(gindex: GindexUint) Gindex {
        return @enumFromInt(gindex);
    }

    pub fn fromDepth(depth: Depth, index: usize) Gindex {
        std.debug.assert(depth <= max_depth);
        const gindex_at_depth = @as(GindexUint, 1) << depth;
        std.debug.assert(index < gindex_at_depth);
        return @enumFromInt(gindex_at_depth | index);
    }

    pub fn pathLen(gindex: Gindex) Depth {
        // sub 1 for the leading 1 bit, which isn't part of the path
        return if (@intFromEnum(gindex) == 0) 0 else @intCast(@bitSizeOf(Gindex) - @clz(@intFromEnum(gindex)) - 1);
    }

    pub fn toPathBits(gindex: Gindex, out: []u1) []u1 {
        const len_u8 = gindex.pathLen();
        std.debug.assert(len_u8 <= out.len);

        var len: usize = len_u8;
        var path = @as(GindexUint, @intFromEnum(gindex)) & ((@as(GindexUint, 1) << @intCast(len_u8)) - 1);

        while (len > 0) {
            len -= 1;
            out[len] = @intCast(path & 1);
            path >>= 1;
        }
        return out[0..len_u8];
    }

    // A Gindex is a prefix path if it is part of the path of another Gindex.
    pub fn isPrefixPath(self: Gindex, maybe_child: Gindex) bool {
        const parent_path_len = self.pathLen();
        const child_path_len = maybe_child.pathLen();

        if (parent_path_len > child_path_len) return false;

        var parent_path = self.toPath();
        var child_path = maybe_child.toPath();

        for (0..parent_path_len) |_| {
            if (parent_path.left() != child_path.left()) {
                return false;
            }
            parent_path.next();
            child_path.next();
        }
        return true;
    }

    /// Assumes that `child` is a prefix path of `self`.
    pub fn getChildGindex(self: Gindex, child: Gindex) Gindex {
        const self_path_len = self.pathLen();
        const child_path_len = child.pathLen();

        // The self path is a prefix of the child path, so we can just shift
        // the child path to the right by the difference in lengths.
        const shift = child_path_len - self_path_len;
        return @enumFromInt(@intFromEnum(child) >> shift);
    }

    pub fn toPath(gindex: Gindex) Path {
        return @enumFromInt(if (@intFromEnum(gindex) == 0) 0 else @as(GindexUint, @intCast(@bitReverse(@intFromEnum(gindex)) >> @intCast(@clz(@intFromEnum(gindex)) + 1))));
    }

    pub const Path = enum(GindexUint) {
        _,

        pub inline fn left(path: Path) bool {
            return @intFromEnum(path) & 1 == 0;
        }

        pub inline fn right(path: Path) bool {
            return @intFromEnum(path) & 1 == 1;
        }

        pub inline fn next(path: *Path) void {
            path.* = @enumFromInt(@intFromEnum(path.*) >> 1);
        }

        pub inline fn nextN(path: *Path, n: Depth) void {
            path.* = @enumFromInt(@intFromEnum(path.*) >> n);
        }
    };

    pub fn sortAsc(items: []Gindex) void {
        std.sort.pdq(Gindex, items, {}, struct {
            pub fn lessThan(_: void, a: Gindex, b: Gindex) bool {
                return @intFromEnum(a) < @intFromEnum(b);
            }
        }.lessThan);
    }

    /// Concatenate multiple Generalized Indices.
    /// Given generalized indices i1 for A -> B, i2 for B -> C, ..., i_n for Y -> Z,
    /// returns the generalized index for A -> Z.
    ///
    pub fn concat(gindices: []const Gindex) Gindex {
        if (gindices.len == 0) {
            return Gindex.fromUint(1); // Root gindex
        }

        var result = gindices[0];
        for (gindices[1..]) |gindex| {
            const path_len = gindex.pathLen();
            const gindex_path = @intFromEnum(gindex) & ((@as(GindexUint, 1) << @intCast(path_len)) - 1);
            result = @enumFromInt((@intFromEnum(result) << @intCast(path_len)) | gindex_path);
        }
        return result;
    }
};

test {
    var bits: [max_depth]u1 = undefined;

    const a: Gindex = @enumFromInt(9);
    try std.testing.expectEqualSlices(u1, &[_]u1{ 0, 0, 1 }, a.toPathBits(&bits));
    try std.testing.expectEqual(@as(Gindex.Path, @enumFromInt(4)), a.toPath());

    const b: Gindex = @enumFromInt(10);
    try std.testing.expectEqualSlices(u1, &[_]u1{ 0, 1, 0 }, b.toPathBits(&bits));
    try std.testing.expectEqual(@as(Gindex.Path, @enumFromInt(2)), b.toPath());
}

test "concat gindices" {
    // [2, 3] -> 5
    const case1: []const Gindex = &.{ Gindex.fromUint(2), Gindex.fromUint(3) };
    try std.testing.expectEqual(@as(GindexUint, 5), @intFromEnum(Gindex.concat(case1)));

    // [31, 3] -> 63
    const case2: []const Gindex = &.{ Gindex.fromUint(31), Gindex.fromUint(3) };
    try std.testing.expectEqual(@as(GindexUint, 63), @intFromEnum(Gindex.concat(case2)));

    // [31, 6] -> 126
    const case3: []const Gindex = &.{ Gindex.fromUint(31), Gindex.fromUint(6) };
    try std.testing.expectEqual(@as(GindexUint, 126), @intFromEnum(Gindex.concat(case3)));

    const empty: []const Gindex = &.{};
    try std.testing.expectEqual(@as(GindexUint, 1), @intFromEnum(Gindex.concat(empty)));

    const single: []const Gindex = &.{Gindex.fromUint(42)};
    try std.testing.expectEqual(@as(GindexUint, 42), @intFromEnum(Gindex.concat(single)));

    // [1, 5] -> 5
    const with_root: []const Gindex = &.{ Gindex.fromUint(1), Gindex.fromUint(5) };
    try std.testing.expectEqual(@as(GindexUint, 5), @intFromEnum(Gindex.concat(with_root)));

    // [5, 1] -> 5
    const root_suffix: []const Gindex = &.{ Gindex.fromUint(5), Gindex.fromUint(1) };
    try std.testing.expectEqual(@as(GindexUint, 5), @intFromEnum(Gindex.concat(root_suffix)));

    // [2, 2, 2] -> 8 (going left 3 times from root)
    const three_lefts: []const Gindex = &.{ Gindex.fromUint(2), Gindex.fromUint(2), Gindex.fromUint(2) };
    try std.testing.expectEqual(@as(GindexUint, 8), @intFromEnum(Gindex.concat(three_lefts)));

    // [3, 3, 3] -> 15 (going right 3 times from root)
    // concat(3, 3) = 7, concat(7, 3) = 15
    const three_rights: []const Gindex = &.{ Gindex.fromUint(3), Gindex.fromUint(3), Gindex.fromUint(3) };
    try std.testing.expectEqual(@as(GindexUint, 15), @intFromEnum(Gindex.concat(three_rights)));
}
