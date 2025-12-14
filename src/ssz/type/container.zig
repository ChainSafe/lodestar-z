const std = @import("std");
const expectEqualRootsAlloc = @import("test_utils.zig").expectEqualRootsAlloc;
const expectEqualSerializedAlloc = @import("test_utils.zig").expectEqualSerializedAlloc;
const TypeKind = @import("type_kind.zig").TypeKind;

const isFixedType = @import("type_kind.zig").isFixedType;
const isBasicType = @import("type_kind.zig").isBasicType;

const merkleize = @import("hashing").merkleize;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const Depth = @import("persistent_merkle_tree").Depth;
const ContainerTreeView = @import("../tree_view/root.zig").ContainerTreeView;

pub fn FixedContainerType(comptime ST: type) type {
    const ssz_fields = switch (@typeInfo(ST)) {
        .@"struct" => |s| s.fields,
        else => @compileError("Expected a struct type."),
    };

    comptime var native_fields: [ssz_fields.len]std.builtin.Type.StructField = undefined;
    comptime var _offsets: [ssz_fields.len]usize = undefined;
    comptime var _fixed_size: usize = 0;
    inline for (ssz_fields, 0..) |field, i| {
        if (!comptime isFixedType(field.type)) {
            @compileError("FixedContainerType must only contain fixed fields");
        }

        native_fields[i] = .{
            .name = field.name,
            .type = field.type.Type,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(field.type.Type),
        };
        _offsets[i] = _fixed_size;
        _fixed_size += field.type.fixed_size;
    }

    const T = @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .backing_integer = null,
            .fields = native_fields[0..],
            // TODO: do we need to assign this value?
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });

    return struct {
        pub const kind = TypeKind.container;
        pub const Fields: type = ST;
        pub const fields: []const std.builtin.Type.StructField = ssz_fields;
        pub const Type: type = T;
        pub const TreeView: type = ContainerTreeView(@This());
        pub const fixed_size: usize = _fixed_size;
        pub const field_offsets: [fields.len]usize = _offsets;
        pub const chunk_count: usize = fields.len;
        pub const chunk_depth: Depth = maxChunksToDepth(chunk_count);

        pub const default_value: Type = blk: {
            var out: Type = undefined;
            for (fields) |field| {
                @field(out, field.name) = field.type.default_value;
            }
            break :blk out;
        };

        pub fn equals(a: *const Type, b: *const Type) bool {
            inline for (fields) |field| {
                if (!field.type.equals(&@field(a, field.name), &@field(b, field.name))) {
                    return false;
                }
            }
            return true;
        }

        /// Creates a new `FixedContainerType` and clones all underlying fields in the container.
        ///
        /// Caller owns the memory.
        pub fn clone(value: *const Type, out: *Type) !void {
            out.* = value.*;
        }

        pub fn hashTreeRoot(value: *const Type, out: *[32]u8) !void {
            var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
            inline for (fields, 0..) |field, i| {
                try field.type.hashTreeRoot(&@field(value, field.name), &chunks[i]);
            }
            try merkleize(@ptrCast(&chunks), chunk_depth, out);
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var i: usize = 0;
            inline for (fields) |field| {
                const field_value_ptr = &@field(value, field.name);
                i += field.type.serializeIntoBytes(field_value_ptr, out[i..]);
            }
            return i;
        }

        pub fn deserializeFromBytes(data: []const u8, out: *Type) !void {
            if (data.len != fixed_size) {
                return error.InvalidSize;
            }
            var i: usize = 0;
            inline for (fields) |field| {
                try field.type.deserializeFromBytes(data[i .. i + field.type.fixed_size], &@field(out, field.name));
                i += field.type.fixed_size;
            }
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }
                var i: usize = 0;
                inline for (fields) |field| {
                    try field.type.serialized.validate(data[i .. i + field.type.fixed_size]);
                    i += field.type.fixed_size;
                }
            }

            pub fn hashTreeRoot(data: []const u8, out: *[32]u8) !void {
                var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
                var i: usize = 0;
                inline for (fields, 0..) |field, field_i| {
                    try field.type.serialized.hashTreeRoot(data[i .. i + field.type.fixed_size], &chunks[field_i]);
                    i += field.type.fixed_size;
                }
                try merkleize(@ptrCast(&chunks), chunk_depth, out);
            }
        };

        pub const tree = struct {
            pub fn toValue(node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);
                inline for (fields, 0..) |field, i| {
                    const child_node = nodes[i];
                    try field.type.tree.toValue(child_node, pool, &@field(out, field.name));
                }
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;
                inline for (fields, 0..) |field, i| {
                    const field_value = &@field(value, field.name);
                    nodes[i] = try field.type.tree.fromValue(pool, field_value);
                }
                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn serializeIntoBytes(value: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                var i: usize = 0;
                inline for (fields) |field| {
                    const field_value_ptr = &@field(value, field.name);
                    i += try field.type.tree.serializeIntoBytes(field_value_ptr, pool, out[i..]);
                }
                return i;
            }

            pub fn deserializeFromBytes(data: []const u8, pool: *Node.Pool, out: *Node.Id) !void {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }
                var i: usize = 0;
                inline for (fields) |field| {
                    try field.type.tree.deserializeFromBytes(data[i .. i + field.type.fixed_size], pool, &@field(out, field.name));
                    i += field.type.fixed_size;
                }
            }
        };

        pub fn serializeIntoJson(writer: anytype, in: *const Type) !void {
            try writer.beginObject();
            inline for (fields) |field| {
                const field_value_ptr = &@field(in, field.name);
                try writer.objectField(field.name);
                try field.type.serializeIntoJson(writer, field_value_ptr);
            }
            try writer.endObject();
        }

        pub fn deserializeFromJson(source: *std.json.Scanner, out: *Type) !void {
            // start object token "{"
            switch (try source.next()) {
                .object_begin => {},
                else => return error.InvalidJson,
            }

            inline for (fields) |field| {
                const field_name = switch (try source.next()) {
                    .string => |str| str,
                    else => return error.InvalidJson,
                };
                if (!std.mem.eql(u8, field_name, field.name)) {
                    return error.InvalidJson;
                }
                try field.type.deserializeFromJson(
                    source,
                    &@field(out, field.name),
                );
            }

            // end object token "}"
            switch (try source.next()) {
                .object_end => {},
                else => return error.InvalidJson,
            }
        }

        pub fn getFieldIndex(comptime name: []const u8) usize {
            inline for (fields, 0..) |field, i| {
                if (std.mem.eql(u8, name, field.name)) {
                    return i;
                }
            } else {
                @compileError("field does not exist");
            }
        }

        pub fn getFieldType(comptime name: []const u8) type {
            inline for (fields) |field| {
                if (std.mem.eql(u8, name, field.name)) {
                    return field.type;
                }
            } else {
                @compileError("field does not exist");
            }
        }

        pub fn getFieldGindex(comptime name: []const u8) Gindex {
            const field_index = getFieldIndex(name);
            return comptime Gindex.fromDepth(chunk_depth, field_index);
        }
    };
}

pub fn VariableContainerType(comptime ST: type) type {
    const ssz_fields = switch (@typeInfo(ST)) {
        .@"struct" => |s| s.fields,
        else => @compileError("Expected a struct type."),
    };

    comptime var native_fields: [ssz_fields.len]std.builtin.Type.StructField = undefined;
    comptime var _offsets: [ssz_fields.len]usize = undefined;
    comptime var _min_size: usize = 0;
    comptime var _max_size: usize = 0;
    comptime var _fixed_end: usize = 0;
    comptime var _fixed_count: usize = 0;
    inline for (ssz_fields, 0..) |field, i| {
        _offsets[i] = _fixed_end;
        if (comptime isFixedType(field.type)) {
            _min_size += field.type.fixed_size;
            _max_size += field.type.fixed_size;
            _fixed_end += field.type.fixed_size;
            _fixed_count += 1;
        } else {
            _min_size += field.type.min_size + 4;
            _max_size += field.type.max_size + 4;
            _fixed_end += 4;
        }

        native_fields[i] = .{
            .name = field.name,
            .type = field.type.Type,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(field.type.Type),
        };
    }

    comptime {
        if (_fixed_count == ssz_fields.len) {
            @compileError("expected at least one fixed field type");
        }
    }

    const var_count = ssz_fields.len - _fixed_count;

    const T = @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .backing_integer = null,
            .fields = native_fields[0..],
            // TODO: do we need to assign this value?
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });

    return struct {
        pub const kind = TypeKind.container;
        pub const fields: []const std.builtin.Type.StructField = ssz_fields;
        pub const Fields: type = ST;
        pub const Type: type = T;
        pub const TreeView: type = ContainerTreeView(@This());
        pub const min_size: usize = _min_size;
        pub const max_size: usize = _max_size;
        pub const field_offsets: [fields.len]usize = _offsets;
        pub const fixed_end: usize = _fixed_end;
        pub const fixed_count: usize = _fixed_count;
        pub const chunk_count: usize = fields.len;
        pub const chunk_depth: u8 = maxChunksToDepth(chunk_count);

        pub const default_value: Type = blk: {
            var out: Type = undefined;
            for (fields) |field| {
                @field(out, field.name) = field.type.default_value;
            }
            break :blk out;
        };

        pub fn equals(a: *const Type, b: *const Type) bool {
            inline for (fields) |field| {
                if (!field.type.equals(&@field(a, field.name), &@field(b, field.name))) {
                    return false;
                }
            }
            return true;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            inline for (fields) |field| {
                if (!comptime isFixedType(field.type)) {
                    field.type.deinit(allocator, &@field(value, field.name));
                }
            }
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
            inline for (fields, 0..) |field, i| {
                if (comptime isFixedType(field.type)) {
                    try field.type.hashTreeRoot(&@field(value, field.name), &chunks[i]);
                } else {
                    try field.type.hashTreeRoot(allocator, &@field(value, field.name), &chunks[i]);
                }
            }
            try merkleize(@ptrCast(&chunks), chunk_depth, out);
        }

        /// Creates a new `VariableContainerType` and clones all underlying fields in the container.
        ///
        /// Caller owns the memory.
        pub fn clone(
            allocator: std.mem.Allocator,
            value: *const Type,
            out: *Type,
        ) !void {
            inline for (fields) |field| {
                if (comptime isFixedType(field.type)) {
                    try field.type.clone(&@field(value, field.name), &@field(out, field.name));
                } else {
                    @field(out, field.name) = field.type.default_value;
                    try field.type.clone(allocator, &@field(value, field.name), &@field(out, field.name));
                }
            }
        }

        pub fn serializedSize(value: *const Type) usize {
            var i: usize = 0;
            inline for (fields) |field| {
                if (comptime isFixedType(field.type)) {
                    i += field.type.fixed_size;
                } else {
                    i += 4 + field.type.serializedSize(&@field(value, field.name));
                }
            }
            return i;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var fixed_index: usize = 0;
            var variable_index: usize = fixed_end;
            inline for (fields) |field| {
                if (comptime isFixedType(field.type)) {
                    // write field value
                    fixed_index += field.type.serializeIntoBytes(&@field(value, field.name), out[fixed_index..]);
                } else {
                    // write offset
                    std.mem.writeInt(u32, out[fixed_index..][0..4], @intCast(variable_index), .little);
                    fixed_index += 4;
                    // write field value
                    variable_index += field.type.serializeIntoBytes(&@field(value, field.name), out[variable_index..]);
                }
            }
            return variable_index;
        }

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            if (data.len > max_size or data.len < min_size) {
                return error.InvalidSize;
            }

            const ranges = try readFieldRanges(data);

            inline for (fields, 0..) |field, i| {
                if (comptime isFixedType(field.type)) {
                    try field.type.deserializeFromBytes(
                        data[ranges[i][0]..ranges[i][1]],
                        &@field(out, field.name),
                    );
                } else {
                    try field.type.deserializeFromBytes(
                        allocator,
                        data[ranges[i][0]..ranges[i][1]],
                        &@field(out, field.name),
                    );
                }
            }
        }

        pub fn getFieldIndex(comptime name: []const u8) usize {
            inline for (fields, 0..) |field, i| {
                if (std.mem.eql(u8, name, field.name)) {
                    return i;
                }
            } else {
                @compileError("field does not exist");
            }
        }

        pub fn getFieldType(comptime name: []const u8) type {
            inline for (fields) |field| {
                if (std.mem.eql(u8, name, field.name)) {
                    return field.type;
                }
            } else {
                @compileError("field does not exist");
            }
        }

        pub fn getFieldGindex(comptime name: []const u8) Gindex {
            const field_index = getFieldIndex(name);
            return comptime Gindex.fromDepth(chunk_depth, field_index);
        }

        // Returns the bytes ranges of all fields, both variable and fixed size.
        // Fields may not be contiguous in the serialized bytes, so the returned ranges are [start, end].
        pub fn readFieldRanges(data: []const u8) ![fields.len][2]usize {
            var ranges: [fields.len][2]usize = undefined;
            var offsets: [var_count + 1]u32 = undefined;
            try readVariableOffsets(data, &offsets);

            var fixed_index: usize = 0;
            var variable_index: usize = 0;
            inline for (fields, 0..) |field, i| {
                if (comptime isFixedType(field.type)) {
                    ranges[i] = [2]usize{ fixed_index, fixed_index + field.type.fixed_size };
                    fixed_index += field.type.fixed_size;
                } else {
                    ranges[i] = [2]usize{ offsets[variable_index], offsets[variable_index + 1] };
                    variable_index += 1;
                    fixed_index += 4;
                }
            }

            return ranges;
        }

        fn readVariableOffsets(data: []const u8, offsets: []u32) !void {
            var variable_index: usize = 0;
            var fixed_index: usize = 0;
            inline for (fields) |field| {
                if (comptime isFixedType(field.type)) {
                    fixed_index += field.type.fixed_size;
                } else {
                    const offset = std.mem.readInt(u32, data[fixed_index..][0..4], .little);
                    if (offset > data.len) {
                        return error.offsetOutOfRange;
                    }
                    if (variable_index == 0) {
                        if (offset != fixed_end) {
                            return error.offsetOutOfRange;
                        }
                    } else {
                        if (offset < offsets[variable_index - 1]) {
                            return error.offsetNotIncreasing;
                        }
                    }

                    offsets[variable_index] = offset;
                    variable_index += 1;
                    fixed_index += 4;
                }
            }
            // set 1 more at the end of the last variable field so that each variable field can consume 2 offsets
            offsets[variable_index] = @intCast(data.len);
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len > max_size or data.len < min_size) {
                    return error.InvalidSize;
                }

                const ranges = try readFieldRanges(data);
                inline for (fields, 0..) |field, i| {
                    const start = ranges[i][0];
                    const end = ranges[i][1];
                    try field.type.serialized.validate(data[start..end]);
                }
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
                const ranges = try readFieldRanges(data);

                inline for (fields, 0..) |field, i| {
                    if (comptime isFixedType(field.type)) {
                        try field.type.serialized.hashTreeRoot(
                            data[ranges[i][0]..ranges[i][1]],
                            &chunks[i],
                        );
                    } else {
                        try field.type.serialized.hashTreeRoot(
                            allocator,
                            data[ranges[i][0]..ranges[i][1]],
                            &chunks[i],
                        );
                    }
                }

                try merkleize(@ptrCast(&chunks), chunk_depth, out);
            }
        };

        pub const tree = struct {
            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);
                inline for (fields, 0..) |field, i| {
                    const child_node = nodes[i];
                    if (comptime isFixedType(field.type)) {
                        try field.type.tree.toValue(child_node, pool, &@field(out, field.name));
                    } else {
                        try field.type.tree.toValue(allocator, child_node, pool, &@field(out, field.name));
                    }
                }
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;
                inline for (fields, 0..) |field, i| {
                    const field_value = &@field(value, field.name);
                    if (comptime isFixedType(field.type)) {
                        nodes[i] = try field.type.tree.fromValue(pool, field_value);
                    } else {
                        nodes[i] = try field.type.tree.fromValue(allocator, pool, field_value);
                    }
                }
                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }
        };

        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            try writer.beginObject();
            inline for (fields) |field| {
                const field_value_ptr = &@field(in, field.name);
                try writer.objectField(field.name);
                if (comptime isFixedType(field.type)) {
                    try field.type.serializeIntoJson(writer, field_value_ptr);
                } else {
                    try field.type.serializeIntoJson(allocator, writer, field_value_ptr);
                }
            }
            try writer.endObject();
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            // start object token "{"
            switch (try source.next()) {
                .object_begin => {},
                else => return error.InvalidJson,
            }

            inline for (fields) |field| {
                const field_name = switch (try source.next()) {
                    .string => |str| str,
                    else => return error.InvalidJson,
                };
                if (!std.mem.eql(u8, field_name, field.name)) {
                    return error.InvalidJson;
                }

                if (comptime isFixedType(field.type)) {
                    try field.type.deserializeFromJson(
                        source,
                        &@field(out, field.name),
                    );
                } else {
                    try field.type.deserializeFromJson(
                        allocator,
                        source,
                        &@field(out, field.name),
                    );
                }
            }

            // end object token "}"
            switch (try source.next()) {
                .object_end => {},
                else => return error.InvalidJson,
            }
        }
    };
}

const UintType = @import("uint.zig").UintType;
const BoolType = @import("bool.zig").BoolType;
const ByteVectorType = @import("byte_vector.zig").ByteVectorType;
const FixedListType = @import("list.zig").FixedListType;

test "ContainerType - sanity" {
    // create a fixed container type and instance and round-trip serialize
    const Checkpoint = FixedContainerType(struct {
        slot: UintType(8),
        root: ByteVectorType(32),
    });

    var c: Checkpoint.Type = undefined;
    var c_buf: [Checkpoint.fixed_size]u8 = undefined;

    _ = Checkpoint.serializeIntoBytes(&c, &c_buf);
    try Checkpoint.deserializeFromBytes(&c_buf, &c);

    // create a variable container type and instance and round-trip serialize
    const allocator = std.testing.allocator;
    const Foo = VariableContainerType(struct {
        a: FixedListType(UintType(8), 32),
        b: FixedListType(UintType(8), 32),
        c: FixedListType(UintType(8), 32),
    });
    var f: Foo.Type = undefined;
    f.a = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 10);
    f.b = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 10);
    f.c = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 10);
    defer f.a.deinit(allocator);
    defer f.b.deinit(allocator);
    defer f.c.deinit(allocator);
    f.a.expandToCapacity();
    f.b.expandToCapacity();
    f.c.expandToCapacity();

    const f_buf = try allocator.alloc(u8, Foo.serializedSize(&f));
    defer allocator.free(f_buf);
    _ = Foo.serializeIntoBytes(&f, f_buf);
    try Foo.deserializeFromBytes(allocator, f_buf, &f);
}

test "clone" {
    const allocator = std.testing.allocator;
    const Checkpoint = FixedContainerType(struct {
        slot: UintType(8),
        root: ByteVectorType(32),
    });

    var c: Checkpoint.Type = Checkpoint.default_value;

    var cloned: Checkpoint.Type = undefined;
    try Checkpoint.clone(&c, &cloned);
    try std.testing.expect(&cloned != &c);
    const Foo = VariableContainerType(struct {
        a: FixedListType(UintType(8), 32),
        b: FixedListType(UintType(8), 32),
        c: FixedListType(UintType(8), 32),
    });
    var f = Foo.default_value;
    defer Foo.deinit(allocator, &f);
    var cloned_f: Foo.Type = undefined;
    try Foo.clone(allocator, &f, &cloned_f);
    defer Foo.deinit(allocator, &cloned_f);
    try std.testing.expect(&cloned_f != &f);

    try expectEqualRootsAlloc(Foo, allocator, f, cloned_f);
    try expectEqualSerializedAlloc(Foo, allocator, f, cloned_f);
    // TODO(bing): test equals when ready
}
