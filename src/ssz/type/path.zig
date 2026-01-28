const std = @import("std");
const isBasicType = @import("type_kind.zig").isBasicType;
const Gindex = @import("persistent_merkle_tree").Gindex;
const BYTES_PER_CHUNK = @import("root.zig").BYTES_PER_CHUNK;

const PathItemType = union(enum) {
    child: struct {
        index: usize,
        ST: type,
    },
    length,
};

pub const PathItem = struct {
    item_type: PathItemType,
    ST: type,
};

pub fn getPathItem(comptime ST: type, comptime path_str_item: []const u8) PathItem {
    switch (ST.kind) {
        .uint, .bool => @compileError("Invalid path"),
        .vector => {
            const element_index = std.fmt.parseInt(usize, path_str_item, 10) catch @compileError("Invalid index");
            if (element_index >= ST.length) {
                @compileError("Index past length");
            }

            return .{
                .ST = ST,
                .item_type = .{
                    .child = .{
                        .index = element_index,
                        .ST = ST.Element,
                    },
                },
            };
        },
        .list => {
            if (std.mem.eql(u8, path_str_item, "length")) {
                return .{
                    .ST = ST,
                    .item_type = .length,
                };
            }

            const element_index = std.fmt.parseInt(usize, path_str_item, 10) catch @compileError("Invalid index");
            if (element_index >= ST.limit) {
                @compileError("Index past limit");
            }

            return .{
                .ST = ST,
                .item_type = .{
                    .child = .{
                        .index = element_index,
                        .ST = ST.Element,
                    },
                },
            };
        },
        .container => {
            const field_index = ST.getFieldIndex(path_str_item);
            return .{
                .ST = ST,
                .item_type = .{
                    .child = .{
                        .index = field_index,
                        .ST = ST.fields[field_index].type,
                    },
                },
            };
        },
    }
}

const NextPathItem = union(enum) {
    last: PathItem,
    not_last: struct {
        next: PathItem,
        rest_path_str: []const u8,
    },
};

fn nextPathItem(comptime ST: type, comptime path_str: []const u8) NextPathItem {
    const first_delimiter = std.mem.indexOfScalar(u8, path_str, '.');
    if (first_delimiter == null) {
        return .{ .last = getPathItem(ST, path_str) };
    } else {
        return .{
            .not_last = .{
                .next = getPathItem(ST, path_str[0..first_delimiter.?]),
                .rest_path_str = path_str[first_delimiter.? + 1 ..],
            },
        };
    }
}

pub fn getPathItems(ST: type, comptime path_str: []const u8) [std.mem.count(u8, path_str, ".") + 1]PathItem {
    const path_len = std.mem.count(u8, path_str, ".") + 1;
    var path: [path_len]PathItem = undefined;

    var T = ST;
    var rest_path_str = path_str;
    for (0..path_len) |i| {
        switch (nextPathItem(T, rest_path_str)) {
            .last => |last| {
                path[i] = last;
            },
            .not_last => |not_last| {
                T = not_last.next.item_type.child.ST;
                rest_path_str = not_last.rest_path_str;

                path[i] = not_last.next;
            },
        }
    }
    return path;
}

pub fn PathType(comptime ST: type, comptime path_str: []const u8) type {
    var T = ST;
    var rest_path_str = path_str;
    while (true) {
        switch (nextPathItem(T, rest_path_str)) {
            .last => |last| {
                return last.item_type.child.ST;
            },
            .not_last => |not_last| {
                T = not_last.next.item_type.child.ST;
                rest_path_str = not_last.rest_path_str;
            },
        }
    }
}

/// Get the gindex for a field/element relative to the parent type.
fn getFieldGindex(comptime item: PathItem) Gindex {
    const ST = item.ST;
    switch (item.item_type) {
        .child => |child| {
            switch (ST.kind) {
                .container => {
                    return Gindex.fromDepth(ST.chunk_depth, child.index);
                },
                .vector, .list => {
                    // Lists have an extra depth level for the length mixin
                    const depth = ST.chunk_depth + @as(u8, if (ST.kind == .list) 1 else 0);
                    const chunk_index = if (comptime isBasicType(ST.Element))
                        child.index / (BYTES_PER_CHUNK / ST.Element.fixed_size)
                    else
                        child.index;
                    return Gindex.fromDepth(depth, chunk_index);
                },
                else => @compileError("Cannot get field gindex for basic types"),
            }
        },
        .length => {
            // Length node is at gindex 3 (right child of root in list structure)
            return Gindex.fromDepth(1, 1);
        },
    }
}

/// Get the gindex for a path relative to the root of the type.
pub fn getPathGindex(comptime ST: type, comptime path_str: []const u8) Gindex {
    const items = getPathItems(ST, path_str);
    var gindices: [items.len + 1]Gindex = undefined;
    gindices[0] = Gindex.fromUint(1); // root

    inline for (items, 0..) |item, i| {
        gindices[i + 1] = getFieldGindex(item);
    }

    return Gindex.concat(&gindices);
}

const types = @import("root.zig");

test "PathType" {
    const Root = types.ByteVectorType(32);
    const Checkpoint = types.FixedContainerType(struct {
        slot: types.UintType(64),
        root: Root,
    });

    _ = PathType(Checkpoint, "slot");
}

test "getPathGindex" {
    const Root = types.ByteVectorType(32);
    const Checkpoint = types.FixedContainerType(struct {
        epoch: types.UintType(64),
        root: Root,
    });

    try std.testing.expectEqual(@as(Gindex.Uint, 2), @intFromEnum(getPathGindex(Checkpoint, "epoch")));
    try std.testing.expectEqual(@as(Gindex.Uint, 3), @intFromEnum(getPathGindex(Checkpoint, "root")));

    const BeaconState = types.FixedContainerType(struct {
        slot: types.UintType(64),
        finalized_checkpoint: Checkpoint,
    });

    try std.testing.expectEqual(@as(Gindex.Uint, 7), @intFromEnum(getPathGindex(BeaconState, "finalized_checkpoint.root")));

    const Balances = types.FixedListType(types.UintType(64), 4);
    const SimpleState = types.VariableContainerType(struct {
        slot: types.UintType(64),
        balances: Balances,
    });

    try std.testing.expectEqual(@as(Gindex.Uint, 6), @intFromEnum(getPathGindex(SimpleState, "balances.0")));
}
