const std = @import("std");

const Node = @import("persistent_merkle_tree").Node;
const isBasicType = @import("type_kind.zig").isBasicType;
const isFixedType = @import("type_kind.zig").isFixedType;

pub fn needsAllocatorTreeApi(comptime ST: type) bool {
    return ST.kind == .progressive_list or
        ST.kind == .progressive_bit_list or
        ST.kind == .compatible_union or
        (ST.kind == .progressive_container and !isFixedType(ST));
}

pub fn fromValue(
    comptime ST: type,
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    value: *const ST.Type,
) !Node.Id {
    if (comptime needsAllocatorTreeApi(ST)) {
        return ST.tree.fromValue(allocator, pool, value);
    } else {
        return ST.tree.fromValue(pool, value);
    }
}

pub fn supportsDeserializeFromBytes(comptime ST: type) bool {
    if (!@hasDecl(ST.tree, "deserializeFromBytes")) return false;

    switch (ST.kind) {
        .progressive_list, .progressive_bit_list, .compatible_union, .progressive_container => return false,
        .container => {
            inline for (ST.fields) |field| {
                if (!supportsDeserializeFromBytes(field.type)) return false;
            }
            return true;
        },
        .list, .vector => {
            if (comptime isBasicType(ST.Element)) return true;
            return supportsDeserializeFromBytes(ST.Element);
        },
        else => return true,
    }
}

pub fn deserializeFromBytes(
    comptime ST: type,
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    data: []const u8,
) !Node.Id {
    if (comptime needsAllocatorTreeApi(ST)) {
        return ST.tree.deserializeFromBytes(allocator, pool, data);
    } else {
        return ST.tree.deserializeFromBytes(pool, data);
    }
}
