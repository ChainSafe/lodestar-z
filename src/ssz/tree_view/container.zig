const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const UintType = @import("../type/uint.zig").UintType;
const assertTreeViewType = @import("utils/assert.zig").assertTreeViewType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;
const CloneOpts = @import("utils/clone_opts.zig").CloneOpts;

/// A specialized tree view for SSZ container types, enabling efficient access and modification of container fields, given a backing merkle tree.
///
/// This struct stores a tuples of either reference to child TreeView or basic type and provides methods to get and set fields by name.
///
/// For basic-type fields, it returns or accepts values directly; for complex fields, it returns or accepts corresponding tree view references.
pub fn ContainerTreeView(comptime ST: type) type {
    comptime var opt_treeview_fields: [ST.fields.len]std.builtin.Type.StructField = undefined;
    inline for (ST.fields, 0..) |field, i| {
        opt_treeview_fields[i] = .{
            .name = std.fmt.comptimePrint("{}", .{i}),
            .type = if (isBasicType(field.type)) @Type(.{
                .optional = .{
                    .child = field.type.Type,
                },
            }) else blk: {
                assertTreeViewType(field.type.TreeView);
                break :blk @Type(.{
                    .optional = .{
                        .child = *field.type.TreeView,
                    },
                });
            },
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = if (isBasicType(field.type)) @alignOf(field.type.Type) else @alignOf(*field.type.TreeView),
        };
    }

    const TreeViewData = @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .backing_integer = null,
            .fields = opt_treeview_fields[0..],
            // TODO: do we need to assign this value?
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = true,
        },
    });

    const TreeView = struct {
        allocator: Allocator,
        pool: *Node.Pool,
        root: Node.Id,

        /// specific fields for this TreeView
        /// a tuple of either Optional(Value) for basic type or Optional(ChildTreeView) for composite type
        child_data: TreeViewData,
        /// whether the corresponding child node/data has changed since the last update of the root
        changed: std.AutoArrayHashMapUnmanaged(usize, void),
        original_nodes: [ST.chunk_count]?Node.Id,
        pub const SszType = ST;

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self {
            try pool.ref(root);
            errdefer pool.unref(root);

            const ptr = try allocator.create(Self);
            ptr.* = .{
                .allocator = allocator,
                .pool = pool,
                .child_data = .{null} ** ST.chunk_count,
                .original_nodes = .{null} ** ST.chunk_count,
                .root = root,
                .changed = .empty,
            };
            return ptr;
        }

        pub fn clone(self: *Self, opts: CloneOpts) !*Self {
            const ptr = try init(self.allocator, self.pool, self.root);
            if (!opts.transfer_cache) {
                return ptr;
            }

            ptr.child_data = self.child_data;
            ptr.original_nodes = self.original_nodes;

            inline for (0..ST.fields.len) |i| {
                if (self.changed.contains(i)) {
                    if (ptr.child_data[i]) |child_view_ptr| {
                        if (!comptime isBasicType(ST.fields[i].type)) {
                            @constCast(child_view_ptr).deinit();
                        }
                    }
                    ptr.child_data[i] = null;
                }
            }

            // clear self's caches
            self.child_data = .{null} ** ST.chunk_count;
            self.original_nodes = .{null} ** ST.chunk_count;
            self.changed.clearRetainingCapacity();

            return ptr;
        }

        pub fn deinit(self: *Self) void {
            self.clearChildrenDataCache();
            self.pool.unref(self.root);
            self.allocator.destroy(self);
        }

        pub fn clearChildrenDataCache(self: *Self) void {
            inline for (self.child_data, 0..) |child_opt, i| {
                if (child_opt) |child| {
                    if (!comptime isBasicType(ST.fields[i].type)) {
                        @constCast(child).deinit();
                    }
                    self.child_data[i] = null;
                }
            }
            inline for (0..ST.chunk_count) |i| {
                // these nodes are unref by root
                self.original_nodes[i] = null;
            }
            self.changed.deinit(self.allocator);
        }

        pub fn commit(self: *Self) !void {
            if (self.changed.count() == 0) {
                return;
            }

            var nodes: [ST.chunk_count]Node.Id = undefined;
            var indices: [ST.chunk_count]usize = undefined;

            var changed_idx: usize = 0;
            inline for (ST.fields, 0..) |field, i| {
                if (self.changed.get(i) != null) {
                    const ChildST = ST.getFieldType(field.name);
                    if (comptime isBasicType(ChildST)) {
                        const child_value = self.child_data[i] orelse return error.MissingChildValue;
                        const child_node = try ChildST.tree.fromValue(
                            self.pool,
                            &child_value,
                        );
                        nodes[changed_idx] = child_node;
                        indices[changed_idx] = i;
                        self.original_nodes[i] = child_node;
                        changed_idx += 1;
                    } else {
                        var child_view = self.child_data[i] orelse return error.MissingChildView;
                        try child_view.commit();
                        const child_changed = if (self.original_nodes[i]) |orig_node| blk: {
                            break :blk orig_node != child_view.getRoot();
                        } else true;
                        if (child_changed) {
                            nodes[changed_idx] = child_view.getRoot();
                            self.original_nodes[i] = child_view.getRoot();
                            indices[changed_idx] = i;
                            changed_idx += 1;
                        }
                        // else child_view is not changed
                    }
                }
            }

            self.changed.clearRetainingCapacity();
            if (changed_idx == 0) {
                return;
            }
            const new_root = try self.root.setNodesAtDepth(self.pool, ST.chunk_depth, indices[0..changed_idx], nodes[0..changed_idx]);
            try self.pool.ref(new_root);
            self.pool.unref(self.root);
            self.root = new_root;
        }

        pub fn getRoot(self: *const Self) Node.Id {
            return self.root;
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.root.getRoot(self.pool).*;
        }

        pub fn Field(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            } else {
                return *ChildST.TreeView;
            }
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a reference to child value so there is no need to deinit it.
        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                const existing = self.child_data[field_index];
                if (existing) |child_value| {
                    return child_value;
                } else {
                    const node = try self.root.getNodeAtDepth(self.pool, ST.chunk_depth, field_index);
                    var child_value: ChildST.Type = undefined;
                    try ChildST.tree.toValue(node, self.pool, &child_value);
                    self.original_nodes[field_index] = node;
                    self.child_data[field_index] = child_value;
                    return child_value;
                }
            } else {
                try self.changed.put(self.allocator, field_index, {});

                const existing_ptr = self.child_data[field_index];
                if (existing_ptr) |child_view_ptr| {
                    return child_view_ptr;
                } else {
                    const node = try self.root.getNodeAtDepth(self.pool, ST.chunk_depth, field_index);
                    self.original_nodes[field_index] = node;
                    self.child_data[field_index] = try ChildST.TreeView.init(self.allocator, self.pool, node);
                    return self.child_data[field_index].?;
                }
            }
        }

        /// Set a field by name. If the field is a basic type, pass the value directly.
        /// If the field is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);

            if (comptime isBasicType(ChildST)) {
                const existing = self.child_data[field_index];
                if (existing) |child_value| {
                    if (child_value == value) {
                        // if consumer keeps setting a new value, do nothing
                        return;
                    }
                }

                self.child_data[field_index] = value;
            } else {
                const existing_ptr = self.child_data[field_index];
                if (existing_ptr) |old_ptr| {
                    if (old_ptr != value) {
                        old_ptr.deinit();
                    }
                }

                self.child_data[field_index] = value;
            }

            try self.changed.put(self.allocator, field_index, {});
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.root, self.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return ST.fixed_size;
            } else {
                return ST.tree.serializedSize(self.root, self.pool);
            }
        }
    };

    assertTreeViewType(TreeView);
    return TreeView;
}

test "ContainerTreeView" {
    const Foo = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    var pool = try Node.Pool.init(std.testing.allocator, 1000);
    defer pool.deinit();

    const foo_value: Foo.Type = .{
        .a = 123,
        .b = 456,
    };
    const root_node = try Foo.tree.fromValue(&pool, &foo_value);
    var foo_view = try ContainerTreeView(Foo).init(std.testing.allocator, &pool, root_node);
    defer foo_view.deinit();

    // test get() and set() and commit()
    try std.testing.expectEqual(123, try foo_view.get("a"));
    try std.testing.expectEqual(456, try foo_view.get("b"));
    try foo_view.set("a", 1230);
    try std.testing.expectEqual(1230, try foo_view.get("a"));
    try foo_view.commit();
    try std.testing.expectEqual(1230, try foo_view.get("a"));

    // test hashTreeRoot()
    var value_root: [32]u8 = undefined;
    var expected_foo_value: Foo.Type = .{ .a = 1230, .b = 456 };
    try Foo.hashTreeRoot(&expected_foo_value, &value_root);
    var view_root: [32]u8 = undefined;
    try foo_view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);

    const Bar = FixedContainerType(struct {
        foo: Foo,
        c: UintType(32),
    });

    const bar_value: Bar.Type = .{
        .foo = foo_value,
        .c = 789,
    };
    const bar_root_node = try Bar.tree.fromValue(&pool, &bar_value);
    var bar_view = try ContainerTreeView(Bar).init(std.testing.allocator, &pool, bar_root_node);
    defer bar_view.deinit();

    // test nested get() and set() and commit()
    var foo_field_view = try bar_view.get("foo");
    try std.testing.expectEqual(123, try foo_field_view.get("a"));
    try std.testing.expectEqual(456, try foo_field_view.get("b"));
    try std.testing.expectEqual(789, try bar_view.get("c"));

    try foo_field_view.set("a", 1230);
    try std.testing.expectEqual(1230, try foo_field_view.get("a"));
    try bar_view.commit();
    try std.testing.expectEqual(1230, try foo_field_view.get("a"));

    // test hashTreeRoot() after nested modification
    const expected_bar_value: Bar.Type = .{
        .foo = .{ .a = 1230, .b = 456 },
        .c = 789,
    };
    try Bar.hashTreeRoot(&expected_bar_value, &value_root);
    try bar_view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);

    const cloned_foo_view_node = try Foo.tree.fromValue(&pool, &expected_foo_value);
    const cloned_foo_view = try ContainerTreeView(Foo).init(std.testing.allocator, &pool, cloned_foo_view_node);
    // do not deinit cloned_foo_view, it will be transferred
    try bar_view.set("foo", cloned_foo_view);
    try bar_view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);
}
