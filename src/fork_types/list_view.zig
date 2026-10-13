const std = @import("std");
const Allocator = std.mem.Allocator;
const CloneOpts = @import("ssz").CloneOpts;
const Node = @import("persistent_merkle_tree").Node;

/// Borrows a list owned by its parent state. Clones and slices own their views until
/// transferred into a state or released with deinit(). Variants describe SSZ layouts,
/// not forks; multiple forks can share either schema.
pub fn ListView(comptime Bounded: type, comptime Progressive: type) type {
    return union(enum) {
        bounded: *Bounded.TreeView,
        progressive: *Progressive.TreeView,

        const Self = @This();
        pub const Element = Bounded.TreeView.Element;
        pub const Value = Bounded.Type;

        comptime {
            if (Bounded.kind != .list or Progressive.kind != .progressive_list) {
                @compileError("list views require bounded and progressive list schemas");
            }
            if (Bounded.Element != Progressive.Element or Bounded.Type != Progressive.Type) {
                @compileError("list views must have identical element and value types");
            }
        }

        pub fn fromView(comptime List: type, view: *List.TreeView) Self {
            if (List == Bounded) return .{ .bounded = view };
            if (List == Progressive) return .{ .progressive = view };
            @compileError("unsupported list schema; extend ListView for the new representation");
        }

        pub fn unwrap(self: Self, comptime List: type) error{IncompatibleListType}!*List.TreeView {
            if (List == Bounded) return switch (self) {
                .bounded => |view| view,
                .progressive => error.IncompatibleListType,
            };
            if (List == Progressive) return switch (self) {
                .progressive => |view| view,
                .bounded => error.IncompatibleListType,
            };
            @compileError("unsupported list schema; extend ListView for the new representation");
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

        pub fn getValue(self: Self, allocator: Allocator, index: usize, out: *Bounded.Element.Type) !void {
            return switch (self) {
                inline else => |view| view.getValue(allocator, index, out),
            };
        }

        pub fn setValue(self: Self, index: usize, value: *const Bounded.Element.Type) !void {
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

        pub fn getAllReadonlyValues(self: Self, allocator: Allocator) ![]Bounded.Element.Type {
            return switch (self) {
                inline else => |view| view.getAllReadonlyValues(allocator),
            };
        }

        pub fn push(self: Self, value: Element) !void {
            return switch (self) {
                inline else => |view| view.push(value),
            };
        }

        pub fn pushValue(self: Self, value: *const Bounded.Element.Type) !void {
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
                inline else => |view, tag| @unionInit(Self, @tagName(tag), try view.clone(opts)),
            };
        }

        pub fn sliceTo(self: Self, index: usize) !Self {
            return switch (self) {
                inline else => |view, tag| @unionInit(Self, @tagName(tag), try view.sliceTo(index)),
            };
        }

        pub fn sliceFrom(self: Self, index: usize) !Self {
            return switch (self) {
                inline else => |view, tag| @unionInit(Self, @tagName(tag), try view.sliceFrom(index)),
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
                inline else => |view, tag| @unionInit(ReadonlyIterator, @tagName(tag), view.iteratorReadonly(start_index)),
            };
        }

        pub const ReadonlyIterator = union(enum) {
            bounded: Bounded.TreeView.ReadonlyIterator,
            progressive: Progressive.TreeView.ReadonlyIterator,

            pub fn nextValue(self: *ReadonlyIterator) !Bounded.Element.Type {
                return switch (self.*) {
                    inline else => |*iterator| iterator.nextValue(),
                };
            }

            pub fn nextValuePtr(self: *ReadonlyIterator) !*const Bounded.Element.Type {
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
