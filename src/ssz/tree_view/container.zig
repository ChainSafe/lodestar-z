const std = @import("std");
const Allocator = std.mem.Allocator;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

const setChildViewValue = @import("chunks.zig").setChildViewValue;

pub fn ContainerTreeView(comptime ST: type) type {
    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;

        const Self = @This();

        pub fn init(store: *ViewStore, root: Node.Id) !Self {
            const view_id = try store.createView(root);
            return fromStore(store, view_id);
        }

        pub fn fromStore(store: *ViewStore, view_id: ViewId) Self {
            return .{
                .allocator = store.allocator,
                .pool = store.pool,
                .store = store,
                .view_id = view_id,
            };
        }

        pub fn clone(self: *Self, opts: ViewStore.CloneOpts) !Self {
            const new_id = try self.store.cloneView(self.view_id, opts);
            return fromStore(self.store, new_id);
        }

        pub fn deinit(_: *Self) void {}

        pub fn commit(self: *Self) !void {
            try self.store.commit(self.view_id);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.store.rootNode(self.view_id).getRoot(self.pool).*;
        }

        pub fn rootNodeId(self: *const Self) Node.Id {
            return self.store.rootNode(self.view_id);
        }

        pub fn Field(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            }
            // Use ChildST.TreeView directly instead of TreeViewFor to avoid import cycle
            return ChildST.TreeView;
        }

        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);

            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try self.store.getChildNode(self.view_id, child_gindex);
                try ChildST.tree.toValue(child_node, self.pool, &value);
                return value;
            }

            const child_id = try self.store.getOrCreateChildView(self.view_id, child_gindex);
            return ChildST.TreeView.fromStore(self.store, child_id);
        }

        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);

            if (comptime isBasicType(ChildST)) {
                try self.store.setChildNode(
                    self.view_id,
                    child_gindex,
                    try ChildST.tree.fromValue(self.pool, &value),
                );
                return;
            }

            try setChildViewValue(self.store, self.view_id, child_gindex, value);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return try ST.tree.serializeIntoBytes(self.store.rootNode(self.view_id), self.pool, out);
            } else {
                return try ST.tree.serializeIntoBytes(self.allocator, self.store.rootNode(self.view_id), self.pool, out);
            }
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return ST.tree.serializedSize(self.store.rootNode(self.view_id), self.pool);
            } else {
                return try ST.tree.serializedSize(self.allocator, self.store.rootNode(self.view_id), self.pool);
            }
        }
    };
}
