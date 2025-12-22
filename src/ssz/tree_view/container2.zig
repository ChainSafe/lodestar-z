const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const UintType = @import("../type/uint.zig").UintType;

/// A specialized tree view for SSZ container types, enabling efficient access and modification of container fields, given a backing merkle tree.
///
/// This struct stores a tuples of either child TreeView or basic type and provides methods to get and set fields by name.
///
/// For basic-type fields, it returns or accepts values directly; for complex fields, it returns or accepts corresponding tree views.
pub fn ContainerTreeView(comptime ST: type) type {
    comptime var opt_treeview_fields: [ST.fields.len]std.builtin.Type.StructField = undefined;
    inline for (ST.fields, 0..) |field, i| {
        opt_treeview_fields[i] = .{
            .name = std.fmt.comptimePrint("{}", .{i}),
            .type = if (isBasicType(field.type)) @Type(.{
                .optional = .{
                    .child = Node.Id,
                },
            }) else @Type(.{
                .optional = .{
                    .child = field.type.TreeView,
                },
            }),
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = if (isBasicType(field.type)) @alignOf(Node.Id) else @alignOf(field.type.TreeView),
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

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        /// a tuple of either Optional(Node.Id) for basic type or Optional(ChildTreeView) for composite type
        child_data: TreeViewData,
        root: Node.Id,
        /// whether the corresponding child node/data has changed since the last update of the root
        changed: std.AutoArrayHashMapUnmanaged(usize, void),
        // TODO: track original_nodes like ts
        pub const SszType = ST;

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            try pool.ref(root);
            var child_data: TreeViewData = undefined;
            inline for (child_data, 0..) |_, i| {
                child_data[i] = null;
            }
            return .{
                .allocator = allocator,
                .pool = pool,
                .child_data = child_data,
                .root = root,
                .changed = .empty,
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.unref(self.root);
            self.clearChildrenDataCache(self.pool);
        }

        pub fn clearChildrenDataCache(self: *Self, pool: *Node.Pool) void {
            inline for (self.child_data, 0..) |child_opt, i| {
                if (child_opt) |*child| {
                    if (@TypeOf(child.*) == Node.Id) {
                        pool.unref(child.*);
                    } else {
                        @constCast(child).deinit();
                    }
                    self.child_data[i] = null;
                }
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
                        const child_node = self.child_data[i] orelse return error.MissingChildNode;
                        nodes[changed_idx] = child_node;
                        indices[changed_idx] = i;
                    } else {
                        var child_view = self.child_data[i] orelse return error.MissingChildView;
                        try child_view.commit();
                        nodes[changed_idx] = child_view.root;
                        indices[changed_idx] = i;
                    }
                    changed_idx += 1;
                }
            }

            if (changed_idx == 0) {
                return;
            }

            const new_root = try self.root.setNodesAtDepth(self.pool, ST.chunk_depth, indices[0..changed_idx], nodes[0..changed_idx]);
            try self.pool.ref(new_root);
            self.pool.unref(self.root);
            self.root = new_root;

            self.changed.clearRetainingCapacity();
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
                // this pointer means caller can mutate the child view
                return *ChildST.TreeView;
            }
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const existing = self.child_data[field_index];
                if (existing) |child_node| {
                    try ChildST.tree.toValue(child_node, self.pool, &value);
                    return value;
                } else {
                    const node = try self.root.getNodeAtDepth(self.pool, ST.chunk_depth, field_index);
                    self.child_data[field_index] = node;
                    try ChildST.tree.toValue(node, self.pool, &value);
                    return value;
                }
            } else {
                // TODO only update changed if the subview is mutable
                try self.changed.put(self.allocator, field_index, {});

                const existing_ptr = &self.child_data[field_index];
                if (existing_ptr.*) |*child_view| {
                    return child_view;
                } else {
                    // TODO: also track this node in original_nodes like ts
                    const node = try self.root.getNodeAtDepth(self.pool, ST.chunk_depth, field_index);
                    existing_ptr.* = try ChildST.TreeView.init(self.allocator, self.pool, node);
                    return &existing_ptr.*.?;
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
            try self.changed.put(self.allocator, field_index, {});

            if (comptime isBasicType(ChildST)) {
                const existing = self.child_data[field_index];
                if (existing) |old_node| {
                    // Multiple set() calls before commit() leave our previous temp nodes cached with refcount 0.
                    // Tree-owned nodes already have a refcount, so skip unref in that case.
                    if (old_node.getState(self.pool).getRefCount() == 0) {
                        self.pool.unref(old_node);
                    }
                }

                self.child_data[field_index] = try ChildST.tree.fromValue(
                    self.pool,
                    &value,
                );
            } else {
                const existing_ptr = &self.child_data[field_index];
                if (existing_ptr.*) |*old_view| {
                    old_view.deinit();
                }

                existing_ptr.* = value.*;
            }
        }
    };
}

test "ContainerTreeView2" {
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

    // // test hashTreeRoot()
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
    var cloned_foo_view = try ContainerTreeView(Foo).init(std.testing.allocator, &pool, cloned_foo_view_node);
    // do not deinit cloned_foo_view, it will be transferred
    try bar_view.set("foo", &cloned_foo_view);
    try bar_view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);
}
