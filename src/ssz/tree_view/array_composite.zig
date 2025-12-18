const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const tree_view_root = @import("root.zig");
const BaseTreeView = tree_view_root.BaseTreeView;
const CompositeChunks = @import("chunks.zig").CompositeChunks;

/// A specialized tree view for SSZ vector types with composite element types.
/// Each element occupies its own subtree.
pub fn ArrayCompositeTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("ArrayCompositeTreeView can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ArrayCompositeTreeView can only be used with Vector of composite element types");
        }
    }

    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = ST.Element.TreeView;
        pub const length = ST.length;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const Chunks = CompositeChunks(ST, chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.base_view.hashTreeRoot(out);
        }

        pub fn get(self: *Self, index: usize) !Element {
            if (index >= length) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
        }

        pub fn getReadonly(self: *Self, index: usize) !Element {
            // TODO: Implement read-only access after other PRs land.
            _ = self;
            _ = index;
            return error.NotImplemented;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= length) return error.IndexOutOfBounds;
            try Chunks.set(&self.base_view, index, value);
        }

        pub fn getAllReadonly(self: *Self, allocator: Allocator) ![]Element {
            // TODO: Implement bulk read-only access after other PRs land.
            _ = self;
            _ = allocator;
            return error.NotImplemented;
        }
    };
}
