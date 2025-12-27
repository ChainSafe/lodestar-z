const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const tree_view_root = @import("root.zig");
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
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            } else {
                return ChildST.TreeView;
            }
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try self.base_view.getChildNode(child_gindex);
                try ChildST.tree.toValue(child_node, self.base_view.pool, &value);
                return value;
            } else {
                const child_data = try self.base_view.getChildData(child_gindex);
                return .{
                    .base_view = BaseTreeView.initFromData(
                        self.base_view.allocator,
                        self.base_view.pool,
                        child_data,
                    ),
                };
            }
        }

        /// Set a field by name. If the field is a basic type, pass the value directly.
        /// If the field is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
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
    };
}
