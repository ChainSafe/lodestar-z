const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;
const tree_view_root = @import("root.zig");
const TreeViewData = tree_view_root.TreeViewData;
const BaseTreeView = tree_view_root.BaseTreeView;

/// A specialized tree view for SSZ container types, enabling efficient access and modification of container fields, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView` and provides methods to get and set fields by name.
///
/// For basic-type fields, it returns or accepts values directly; for complex fields, it returns or accepts corresponding tree views.
pub fn ContainerTreeView(comptime ST: type) type {
    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn clone(self: *Self, opts: BaseTreeView.CloneOpts) !Self {
            return Self{ .base_view = try self.base_view.clone(opts) };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.base_view.hashTreeRoot(out);
        }

        pub fn Field(comptime field_name: []const u8) type {
            comptime {
                @setEvalBranchQuota(20000);
            }
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            } else {
                return ChildST.TreeView;
            }
        }

        pub fn FieldValue(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            return ChildST.Type;
        }

        pub fn getGindex(comptime field_name: []const u8) Gindex {
            const field_index = comptime ST.getFieldIndex(field_name);
            return Gindex.fromDepth(ST.chunk_depth, field_index);
        }

        pub fn getRootNode(self: *const Self, comptime field_name: []const u8) !Node.Id {
            const field_gindex = Self.getGindex(field_name);
            return try @constCast(&self.base_view).getChildNode(field_gindex);
        }

        pub fn setRootNode(self: *Self, comptime field_name: []const u8, root: Node.Id) !void {
            const field_gindex = Self.getGindex(field_name);
            return try self.base_view.setChildNode(field_gindex, root);
        }

        pub fn getRoot(self: *const Self, comptime field_name: []const u8) !*const [32]u8 {
            const field_node = try self.getRootNode(field_name);
            return field_node.getRoot(self.base_view.pool);
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn get(self: *const Self, comptime field_name: []const u8) !Field(field_name) {
            comptime {
                @setEvalBranchQuota(20000);
            }
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try @constCast(&self.base_view).getChildNode(child_gindex);
                try ChildST.tree.toValue(child_node, self.base_view.pool, &value);
                return value;
            } else {
                const child_data = try @constCast(&self.base_view).getChildData(child_gindex);

                return .{
                    .base_view = .{
                        .allocator = self.base_view.allocator,
                        .pool = self.base_view.pool,
                        .data = child_data,
                    },
                };
            }
        }

        /// Set a field by name. If the field is a basic type, pass the value directly.
        /// If the field is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            comptime {
                @setEvalBranchQuota(20000);
            }
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                try self.base_view.setChildNode(
                    child_gindex,
                    try ChildST.tree.fromValue(
                        self.base_view.pool,
                        &value,
                    ),
                );
            } else {
                try self.base_view.setChildData(child_gindex, value.base_view.data);
            }
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.base_view.data.root, self.base_view.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return ST.fixed_size;
            } else {
                return try ST.tree.serializedSize(self.base_view.data.root, self.base_view.pool);
            }
        }

        pub fn deserialize(allocator: Allocator, pool: *Node.Pool, bytes: []const u8) !Self {
            const root = try ST.tree.deserializeFromBytes(pool, bytes);
            return try Self.init(allocator, pool, root);
        }

        pub fn fromValue(allocator: Allocator, pool: *Node.Pool, value: *const ST.Type) !Self {
            const root = try ST.tree.fromValue(pool, value);
            errdefer pool.unref(root);
            return try Self.init(allocator, pool, root);
        }

        pub fn toValue(self: *Self, allocator: Allocator, out: *ST.Type) !void {
            try self.commit();
            if (comptime isFixedType(ST)) {
                try ST.tree.toValue(self.base_view.data.root, self.base_view.pool, out);
            } else {
                try ST.tree.toValue(allocator, self.base_view.data.root, self.base_view.pool, out);
            }
        }

        pub fn setValue(self: *Self, comptime field_name: []const u8, value: *const FieldValue(field_name)) !void {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                try self.set(field_name, value.*);
            } else {
                const root = try ChildST.tree.fromValue(self.base_view.pool, value);
                errdefer self.base_view.pool.unref(root);
                const child_view = try ChildST.TreeView.init(
                    self.base_view.allocator,
                    self.base_view.pool,
                    root,
                );
                try self.set(field_name, child_view);
            }
        }
    };
}
