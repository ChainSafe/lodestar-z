const std = @import("std");
const isFixedType = @import("type_kind.zig").isFixedType;

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

const types = @import("root.zig");

test {
    // std.testing.refAllDecls(@This());

    const Root = types.ByteVectorType(32);
    const Checkpoint = types.FixedContainerType(struct {
        slot: types.UintType(64),
        root: Root,
    });

    _ = PathType(Checkpoint, "slot");
    // _ = getPath(Checkpoint, "root");
    // _ = getPath(Checkpoint, "root.31");
    // _ = getPath(Root, "0");
    // _ = getOffset(Checkpoint, "root.20");
}
