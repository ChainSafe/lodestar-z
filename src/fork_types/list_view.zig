const std = @import("std");
const Allocator = std.mem.Allocator;
const CloneOpts = @import("ssz").CloneOpts;
const Node = @import("persistent_merkle_tree").Node;

/// Borrows a list owned by its parent state. Clones and slices own their views until
/// transferred into a state or released with deinit(). Both layouts share element types.
pub fn ListView(comptime Before: type, comptime After: type) type {
    return union(enum) {
        pre_gloas: *Before.TreeView,
        gloas: *After.TreeView,

        const Self = @This();
        pub const Element = Before.TreeView.Element;
        pub const Value = Before.Type;

        comptime {
            if (Before.Element != After.Element or Before.Type != After.Type) {
                @compileError("fork list views must have identical element and value types");
            }
        }

        pub fn length(self: Self) !usize {
            return switch (self) {
                inline else => |view| view.length(),
            };
        }

        pub fn commit(self: Self) !void {
            return switch (self) {
                inline else => |view| view.commit(),
            };
        }

        pub fn clearCache(self: Self) void {
            switch (self) {
                inline else => |view| view.clearCache(),
            }
        }

        pub fn getRoot(self: Self) Node.Id {
            return switch (self) {
                inline else => |view| view.getRoot(),
            };
        }

        pub fn get(self: Self, index: usize) !Element {
            return switch (self) {
                inline else => |view| view.get(index),
            };
        }

        pub fn getReadonly(self: Self, index: usize) !Element {
            return switch (self) {
                inline else => |view| view.getReadonly(index),
            };
        }

        pub fn set(self: Self, index: usize, value: Element) !void {
            return switch (self) {
                inline else => |view| view.set(index, value),
            };
        }

        pub fn getValue(self: Self, allocator: Allocator, index: usize, out: *Before.Element.Type) !void {
            return switch (self) {
                inline else => |view| view.getValue(allocator, index, out),
            };
        }

        pub fn setValue(self: Self, index: usize, value: *const Before.Element.Type) !void {
            return switch (self) {
                inline else => |view| view.setValue(index, value),
            };
        }

        pub fn getFieldRoot(self: Self, index: usize) !*const [32]u8 {
            return switch (self) {
                inline else => |view| view.getFieldRoot(index),
            };
        }

        pub fn getAll(self: Self, allocator: ?Allocator) ![]Element {
            return switch (self) {
                inline else => |view| view.getAll(allocator),
            };
        }

        pub fn getAllInto(self: Self, out: []Element) ![]Element {
            return switch (self) {
                inline else => |view| view.getAllInto(out),
            };
        }

        pub fn getAllReadonlyValues(self: Self, allocator: Allocator) ![]Before.Element.Type {
            return switch (self) {
                inline else => |view| view.getAllReadonlyValues(allocator),
            };
        }

        pub fn push(self: Self, value: Element) !void {
            return switch (self) {
                inline else => |view| view.push(value),
            };
        }

        pub fn pushValue(self: Self, value: *const Before.Element.Type) !void {
            return switch (self) {
                inline else => |view| view.pushValue(value),
            };
        }

        pub fn growTo(self: Self, new_length: usize) !void {
            return switch (self) {
                inline else => |view| view.growTo(new_length),
            };
        }

        pub fn clone(self: Self, opts: CloneOpts) !Self {
            return switch (self) {
                .pre_gloas => |view| .{ .pre_gloas = try view.clone(opts) },
                .gloas => |view| .{ .gloas = try view.clone(opts) },
            };
        }

        pub fn sliceTo(self: Self, index: usize) !Self {
            return switch (self) {
                .pre_gloas => |view| .{ .pre_gloas = try view.sliceTo(index) },
                .gloas => |view| .{ .gloas = try view.sliceTo(index) },
            };
        }

        pub fn sliceFrom(self: Self, index: usize) !Self {
            return switch (self) {
                .pre_gloas => |view| .{ .pre_gloas = try view.sliceFrom(index) },
                .gloas => |view| .{ .gloas = try view.sliceFrom(index) },
            };
        }

        pub fn deinit(self: Self) void {
            switch (self) {
                inline else => |view| view.deinit(),
            }
        }

        pub fn toValue(self: Self, allocator: Allocator, out: *Value) !void {
            return switch (self) {
                inline else => |view| view.toValue(allocator, out),
            };
        }

        pub fn hashTreeRoot(self: Self) !*const [32]u8 {
            return switch (self) {
                inline else => |view| view.hashTreeRoot(),
            };
        }

        pub fn serializeIntoBytes(self: Self, out: []u8) !usize {
            return switch (self) {
                inline else => |view| view.serializeIntoBytes(out),
            };
        }

        pub fn serializedSize(self: Self) !usize {
            return switch (self) {
                inline else => |view| view.serializedSize(),
            };
        }

        pub fn iteratorReadonly(self: Self, start_index: usize) ReadonlyIterator {
            return switch (self) {
                .pre_gloas => |view| .{ .pre_gloas = view.iteratorReadonly(start_index) },
                .gloas => |view| .{ .gloas = view.iteratorReadonly(start_index) },
            };
        }

        pub const ReadonlyIterator = union(enum) {
            pre_gloas: Before.TreeView.ReadonlyIterator,
            gloas: After.TreeView.ReadonlyIterator,

            pub fn nextValue(self: *ReadonlyIterator) !Before.Element.Type {
                return switch (self.*) {
                    inline else => |*iterator| iterator.nextValue(),
                };
            }

            pub fn nextValuePtr(self: *ReadonlyIterator) !*const Before.Element.Type {
                return switch (self.*) {
                    inline else => |*iterator| iterator.nextValuePtr(),
                };
            }

            pub fn nextRoot(self: *ReadonlyIterator) !*const [32]u8 {
                return switch (self.*) {
                    inline else => |*iterator| iterator.nextRoot(),
                };
            }
        };
    };
}
