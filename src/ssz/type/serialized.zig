const std = @import("std");
const isFixedType = @import("type_kind.zig").isFixedType;
const PathItem = @import("path.zig").PathItem;
const PathType = @import("path.zig").PathType;
const getPathItems = @import("path.zig").getPathItems;

pub fn Serialized(comptime ST: type) type {
    if (comptime isFixedType(ST)) {
        return FixedSerialized(ST);
    } else {
        return VariableSerialized(ST);
    }
}

fn FixedSerialized(comptime ST: type) type {
    return struct {
        data: []u8,

        const Self = @This();

        pub const SszType = ST;

        pub fn init(data: []u8) !Self {
            try ST.serialized.validate(data);
            return Self{ .data = data };
        }

        pub fn deserialize(self: Self) ST.Type {
            var out: ST.Type = undefined;
            ST.deserializeFromBytes(self.data, &out) catch unreachable;
            return out;
        }

        pub fn seekTo(self: Self, comptime path_str: []const u8) Serialized(PathType(ST, path_str)) {
            const ChildST = PathType(ST, path_str);
            const offset = getOffset(path_str);
            return Serialized(ChildST){ .data = self.data[offset .. offset + ChildST.fixed_size] };
        }
    };
}

pub fn getOffsetFromPath(comptime path: []const PathItem) usize {
    var offset: usize = 0;
    inline for (path) |path_item| {
        switch (path_item.item_type) {
            .length => @compileError("Cannot get an offset for 'length'"),
            .child => |child| {
                switch (path_item.ST.kind) {
                    .container => {
                        offset += path_item.ST.field_offsets[comptime path_item.ST.getFieldIndex(child.index)];
                    },
                    .vector, .list => {
                        if (!comptime isFixedType(path_item.ST.Element)) {
                            @compileError("Cannot get an offset for variable-length array elements");
                        }
                        offset += path_item.ST.Element.fixed_size * child.index;
                    },
                    else => @compileError("invalid"),
                }
            },
        }
    }
    return offset;
}

pub fn getOffset(comptime ST: type, comptime path_str: []const u8) usize {
    const path = getPathItems(ST, path_str);
    return getOffsetFromPath(&path);
}

fn VariableSerialized(comptime ST: type) type {
    return struct {
        data: []u8,

        const Self = @This();

        pub fn init(data: []const u8) !Self {
            try ST.validate(data);
            return Self{ .data = data };
        }

        pub fn deserialize(self: Self, allocator: std.mem.Allocator) !ST.Type {
            var out: ST.Type = undefined;
            try ST.deserializeFromBytes(allocator, self.data, &out);
            return out;
        }

        pub fn seekTo(self: Self, comptime path_str: []const u8) !Serialized(PathType(ST, path_str)) {
            const path = getPathItems(path_str);
            const ChildST = PathType(ST, path_str);

            var d = self.data;

            inline for (path) |item| {
                switch (item.item_type) {
                    .child => |child| {
                        switch (item.ST.kind) {
                            .vector, .list => {
                                if (item.ST.kind == .list and item.ST.Element.kind == .bool) {
                                    return error.InvalidType;
                                }
                                const length = if (item.ST.kind == .vector) item.ST.length else item.ST.deserializedLength(d);
                                if (child.index >= length) {
                                    return error.OutOfBounds;
                                }
                                if (comptime isFixedType(item.ST.Element)) {
                                    const element_fixed_size = item.ST.Element.fixed_size;
                                    d = d[child.index * element_fixed_size .. (child.index + 1) * element_fixed_size];
                                } else {
                                    const start = std.mem.readInt(u32, d[child.index * 4 ..][0..4], .little);
                                    const end = if (child.index == length - 1) d.len else std.mem.readInt(u32, d[(child.index + 1) * 4 ..][0..4], .little);
                                    d = d[start..end];
                                }
                            },
                            .container => {
                                const range = try item.ST.readFieldRanges(d)[child.index];
                                d = d[range[0]..range[1]];
                            },
                        }
                    },
                    .length => @compileError("'length' not supported"),
                }
            }

            return Serialized(ChildST){ .data = d };
        }
    };
}

const types = @import("root.zig");

test {
    std.testing.refAllDecls(@This());

    const Root = types.ByteVectorType(32);
    const Checkpoint = types.FixedContainerType(struct {
        slot: types.UintType(64),
        root: Root,
    });

    const o1 = getOffset(Checkpoint, "root.20");
    std.debug.print("{d}\n", .{o1});

    var c_buf: [Checkpoint.fixed_size]u8 = undefined;
    const x = Serialized(Checkpoint){ .data = &c_buf };
    const s = x.seekTo("slot");
    // const r = x.seekTo("root");

    std.debug.print("{any}\n", .{s.foo});
}
