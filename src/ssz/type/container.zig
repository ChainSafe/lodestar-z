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
        /// `out` is a pointer to any types that contains all fields of `Type`.
        /// Caller owns the memory.
        pub fn clone(value: *const Type, out: anytype) !void {
            const OutType = @TypeOf(out.*);
            comptime {
                const OutInfo = @typeInfo(@TypeOf(out));
                std.debug.assert(OutInfo == .pointer);
            }
            if (OutType == Type) {
                out.* = value.*;
            } else {
                inline for (fields) |field| {
                    @field(out, field.name) = @field(value, field.name);
                }
            }
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
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }

                var nodes: [chunk_count]Node.Id = undefined;
                errdefer pool.free(&nodes);
                var offset: usize = 0;

                inline for (fields, 0..) |field, i| {
                    const field_bytes = data[offset .. offset + field.type.fixed_size];
                    offset += field.type.fixed_size;

                    nodes[i] = try field.type.tree.deserializeFromBytes(pool, field_bytes);
                }

                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

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
                errdefer pool.free(&nodes);

                inline for (fields, 0..) |field, i| {
                    const field_value = &@field(value, field.name);
                    nodes[i] = try field.type.tree.fromValue(pool, field_value);
                }
                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                var offset: usize = 0;
                inline for (fields, 0..) |field, i| {
                    offset += try field.type.tree.serializeIntoBytes(nodes[i], pool, out[offset..]);
                }
                return offset;
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
        /// out is a pointer to any types that contains all fields of Type.
        /// Caller owns the memory.
        pub fn clone(
            allocator: std.mem.Allocator,
            value: *const Type,
            out: anytype,
        ) !void {
            comptime {
                const OutInfo = @typeInfo(@TypeOf(out));
                std.debug.assert(OutInfo == .pointer);
            }

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
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len > max_size or data.len < min_size) {
                    return error.InvalidSize;
                }

                const ranges = try readFieldRanges(data);
                var nodes: [chunk_count]Node.Id = undefined;
                errdefer pool.free(&nodes);

                inline for (fields, 0..) |field, i| {
                    const start = ranges[i][0];
                    const end = ranges[i][1];
                    const field_bytes = data[start..end];

                    nodes[i] = try field.type.tree.deserializeFromBytes(pool, field_bytes);
                }

                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

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

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;
                errdefer pool.free(&nodes);

                inline for (fields, 0..) |field, i| {
                    const field_value = &@field(value, field.name);
                    nodes[i] = try field.type.tree.fromValue(pool, field_value);
                }
                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                var fixed_index: usize = 0;
                var variable_index: usize = fixed_end;

                inline for (fields, 0..) |field, i| {
                    if (comptime isFixedType(field.type)) {
                        fixed_index += try field.type.tree.serializeIntoBytes(nodes[i], pool, out[fixed_index..]);
                    } else {
                        std.mem.writeInt(u32, out[fixed_index..][0..4], @intCast(variable_index), .little);
                        fixed_index += 4;
                        variable_index += try field.type.tree.serializeIntoBytes(nodes[i], pool, out[variable_index..]);
                    }
                }
                return variable_index;
            }

            pub fn serializedSize(node: Node.Id, pool: *Node.Pool) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                var total_size: usize = 0;
                inline for (fields, 0..) |field, i| {
                    if (comptime isFixedType(field.type)) {
                        total_size += field.type.fixed_size;
                    } else {
                        total_size += 4 + try field.type.tree.serializedSize(nodes[i], pool);
                    }
                }
                return total_size;
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

const TypeTestCase = @import("test_utils.zig").TypeTestCase;

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

test "clone FixedContainerType" {
    const Checkpoint = FixedContainerType(struct {
        epoch: UintType(8),
        root: ByteVectorType(32),
    });
    const CheckpointHex = FixedContainerType(struct {
        epoch: UintType(8),
        root: ByteVectorType(32),
        root_hex: ByteVectorType(64),
    });

    var c: Checkpoint.Type = Checkpoint.default_value;

    var cloned: Checkpoint.Type = undefined;
    try Checkpoint.clone(&c, &cloned);
    try std.testing.expect(&cloned != &c);
    try std.testing.expect(Checkpoint.equals(&cloned, &c));

    // clone into a larger container
    var cloned2: CheckpointHex.Type = undefined;
    cloned2.root_hex = ByteVectorType(64).default_value;
    try Checkpoint.clone(&c, &cloned2);
    try std.testing.expect(cloned2.epoch == c.epoch);
    try std.testing.expectEqualSlices(u8, &cloned2.root, &c.root);
    try std.testing.expectEqualSlices(u8, &cloned2.root_hex, &ByteVectorType(64).default_value);
}

test "clone VariableContainerType" {
    const allocator = std.testing.allocator;
    const FieldA = FixedListType(UintType(8), 32);
    const FieldB = FixedListType(UintType(8), 32);
    const Foo = VariableContainerType(struct {
        a: FieldA,
        b: FieldB,
    });
    var f = Foo.default_value;
    try f.a.append(allocator, 42);
    try f.b.append(allocator, 42);
    defer Foo.deinit(allocator, &f);
    var cloned_f: Foo.Type = undefined;
    try Foo.clone(allocator, &f, &cloned_f);
    defer Foo.deinit(allocator, &cloned_f);
    try std.testing.expect(&cloned_f != &f);

    try expectEqualRootsAlloc(Foo, allocator, f, cloned_f);
    try expectEqualSerializedAlloc(Foo, allocator, f, cloned_f);
    try std.testing.expect(Foo.equals(&cloned_f, &f));

    // clone into a larger container
    const FieldC = FixedListType(UintType(8), 32);
    const Foo2 = VariableContainerType(struct {
        a: FieldA,
        b: FieldB,
        // 1 additional field
        c: FieldC,
    });
    var cloned_f2: Foo2.Type = undefined;
    cloned_f2.c = FieldC.default_value;
    try Foo.clone(allocator, &f, &cloned_f2);
    defer Foo2.deinit(allocator, &cloned_f2);
    try std.testing.expectEqualSlices(u8, f.a.items, cloned_f2.a.items);
    try std.testing.expectEqualSlices(u8, f.b.items, cloned_f2.b.items);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/container/valid.test.ts#L9-L64
test "FixedContainerType - serializeIntoBytes (zero)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    const value: Container.Type = .{ .a = 0, .b = 0 };
    const expected_serialized = [_]u8{0} ** 16;
    const expected_root = [_]u8{ 0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09, 0x97, 0x9b, 0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8, 0xea, 0x98, 0x31, 0xa9, 0x27, 0x59, 0xfb, 0x4b };

    var serialized: [Container.fixed_size]u8 = undefined;
    const written = Container.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Container.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const node = try Container.tree.fromValue(&pool, &value);
    var tree_serialized: [Container.fixed_size]u8 = undefined;
    const tree_written = Container.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    const tree_written_val = if (@typeInfo(@TypeOf(tree_written)) == .error_union) try tree_written else tree_written;
    try std.testing.expectEqual(@as(usize, 16), tree_written_val);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "FixedContainerType - serializeIntoBytes (some value)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    const value: Container.Type = .{ .a = 123456, .b = 654321 };
    // 0x40e2010000000000f1fb090000000000
    const expected_serialized = [_]u8{ 0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_root = [_]u8{ 0x53, 0xb3, 0x8a, 0xff, 0x7b, 0xf2, 0xdd, 0x1a, 0x49, 0x90, 0x3d, 0x07, 0xa3, 0x35, 0x09, 0xb9, 0x80, 0xc6, 0xac, 0xc9, 0xf2, 0x23, 0x5a, 0x45, 0xaa, 0xc3, 0x42, 0xb0, 0xa9, 0x52, 0x8c, 0x22 };

    var serialized: [Container.fixed_size]u8 = undefined;
    const written = Container.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Container.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const node = try Container.tree.fromValue(&pool, &value);
    var tree_serialized: [Container.fixed_size]u8 = undefined;
    const tree_written = Container.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    const tree_written_val = if (@typeInfo(@TypeOf(tree_written)) == .error_union) try tree_written else tree_written;
    try std.testing.expectEqual(@as(usize, 16), tree_written_val);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "FixedContainerType - tree.deserializeFromBytes" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    const value: Container.Type = .{ .a = 123456, .b = 654321 };
    const expected_serialized = [_]u8{ 0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_root = [_]u8{ 0x53, 0xb3, 0x8a, 0xff, 0x7b, 0xf2, 0xdd, 0x1a, 0x49, 0x90, 0x3d, 0x07, 0xa3, 0x35, 0x09, 0xb9, 0x80, 0xc6, 0xac, 0xc9, 0xf2, 0x23, 0x5a, 0x45, 0xaa, 0xc3, 0x42, 0xb0, 0xa9, 0x52, 0x8c, 0x22 };

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const node = try Container.tree.deserializeFromBytes(&pool, &expected_serialized);
    try std.testing.expectEqualSlices(u8, &expected_root, node.getRoot(&pool));

    var roundtrip: [Container.fixed_size]u8 = undefined;
    const written = Container.tree.serializeIntoBytes(node, &pool, &roundtrip);
    const written_val = if (@typeInfo(@TypeOf(written)) == .error_union) try written else written;
    try std.testing.expectEqual(@as(usize, Container.fixed_size), written_val);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &roundtrip);

    // sanity: same root as fromValue
    const node2 = try Container.tree.fromValue(&pool, &value);
    try std.testing.expectEqualSlices(u8, node2.getRoot(&pool), node.getRoot(&pool));
}

test "FixedContainerType - serializeIntoBytes (uint64 + ByteVector32)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: ByteVectorType(32),
    });

    const value: Container.Type = .{ .a = 123456, .b = [_]u8{0x0a} ** 32 };
    // 0x40e20100000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
    const expected_serialized = [_]u8{ 0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0x0a} ** 32;
    const expected_root = [_]u8{ 0x97, 0xb6, 0x2a, 0xdf, 0x79, 0xc8, 0x23, 0xff, 0x07, 0xc5, 0xe7, 0xba, 0x80, 0xb9, 0x12, 0x05, 0x9f, 0x6f, 0x0f, 0x40, 0xba, 0xd5, 0xf2, 0x67, 0xd4, 0x74, 0x7b, 0x21, 0xea, 0xfb, 0x77, 0x58 };

    var serialized: [Container.fixed_size]u8 = undefined;
    const written = Container.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 40), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Container.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const node = try Container.tree.fromValue(&pool, &value);
    var tree_serialized: [Container.fixed_size]u8 = undefined;
    const tree_written = Container.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    const tree_written_val = if (@typeInfo(@TypeOf(tree_written)) == .error_union) try tree_written else tree_written;
    try std.testing.expectEqual(@as(usize, 40), tree_written_val);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "VariableContainerType - serializeIntoBytes (zero)" {
    const allocator = std.testing.allocator;
    const Container = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128),
        b: UintType(64),
    });

    var value: Container.Type = Container.default_value;
    // a = [], b = 0
    // 0x0c0000000000000000000000
    const expected_serialized = [_]u8{ 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_root = [_]u8{ 0xdc, 0x36, 0x19, 0xcb, 0xbc, 0x5e, 0xf0, 0xe0, 0xa3, 0xb3, 0x8e, 0x3c, 0xa5, 0xd3, 0x1c, 0x2b, 0x16, 0x86, 0x8e, 0xac, 0xb6, 0xe4, 0xbc, 0xf8, 0xb4, 0x51, 0x09, 0x63, 0x35, 0x43, 0x15, 0xf5 };

    const size = Container.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 12), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = Container.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 12), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try Container.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const node = try Container.tree.fromValue(&pool, &value);
    const tree_size = try Container.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 12), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    const tree_written = try Container.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqual(@as(usize, 12), tree_written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableContainerType - serializeIntoBytes (some value)" {
    const allocator = std.testing.allocator;
    const Container = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128),
        b: UintType(64),
    });

    var value: Container.Type = Container.default_value;
    // a = [123456, 654321, 123456, 654321, 123456], b = 654321
    try value.a.appendSlice(allocator, &[_]u64{ 123456, 654321, 123456, 654321, 123456 });
    value.b = 654321;
    defer value.a.deinit(allocator);

    // 0x0c000000f1fb09000000000040e2010000000000f1fb09000000000040e2010000000000f1fb09000000000040e2010000000000
    const expected_serialized = [_]u8{
        0x0c, 0x00, 0x00, 0x00, // offset to a (12)
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 654321
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a[0] = 123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // a[1] = 654321
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a[2] = 123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // a[3] = 654321
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a[4] = 123456
    };
    const expected_root = [_]u8{ 0x5f, 0xf1, 0xb9, 0x2b, 0x2f, 0xa5, 0x5e, 0xea, 0x1a, 0x14, 0xb2, 0x65, 0x47, 0x03, 0x5b, 0x2f, 0x54, 0x37, 0x81, 0x4b, 0x34, 0x36, 0x17, 0x22, 0x05, 0xfa, 0x7d, 0x6a, 0xf4, 0x09, 0x17, 0x48 };

    const size = Container.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 52), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = Container.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 52), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try Container.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();
    const node = try Container.tree.fromValue(&pool, &value);
    const tree_size = try Container.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 52), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    const tree_written = try Container.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqual(@as(usize, 52), tree_written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableContainerType - tree.deserializeFromBytes" {
    const allocator = std.testing.allocator;
    const Container = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128),
        b: UintType(64),
    });

    const serialized = [_]u8{
        0x0c, 0x00, 0x00, 0x00, // offset to a (12)
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 654321
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a[0] = 123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // a[1] = 654321
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a[2] = 123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // a[3] = 654321
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a[4] = 123456
    };
    const expected_root = [_]u8{ 0x5f, 0xf1, 0xb9, 0x2b, 0x2f, 0xa5, 0x5e, 0xea, 0x1a, 0x14, 0xb2, 0x65, 0x47, 0x03, 0x5b, 0x2f, 0x54, 0x37, 0x81, 0x4b, 0x34, 0x36, 0x17, 0x22, 0x05, 0xfa, 0x7d, 0x6a, 0xf4, 0x09, 0x17, 0x48 };

    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();

    const node = try Container.tree.deserializeFromBytes(&pool, &serialized);
    try std.testing.expectEqualSlices(u8, &expected_root, node.getRoot(&pool));

    const roundtrip_size = try Container.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, serialized.len), roundtrip_size);

    const out = try allocator.alloc(u8, roundtrip_size);
    defer allocator.free(out);
    const written = try Container.tree.serializeIntoBytes(node, &pool, out);
    try std.testing.expectEqual(@as(usize, serialized.len), written);
    try std.testing.expectEqualSlices(u8, &serialized, out);
}

test "ContainerType" {
    const test_cases = [_]TypeTestCase{
        .{
            .id = "empty",
            .serializedHex = "0x00000000000000000000000000000000",
            .json =
            \\{"a":"0","b":"0"}
            ,
            .rootHex = "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        },
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/container/valid.test.ts#L22
        .{
            .id = "some value",
            .serializedHex = "0x40e2010000000000f1fb090000000000",
            .json =
            \\{"a":"123456","b":"654321"}
            ,
            .rootHex = "0x53b38aff7bf2dd1a49903d07a33509b980c6acc9f2235a45aac342b0a9528c22",
        },
    };

    const allocator = std.testing.allocator;

    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    const TypeTest = @import("test_utils.zig").typeTest(Container);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "ContainerType with FixedListType(uint64, 128) and uint64" {
    const allocator = std.testing.allocator;

    const Container = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128),
        b: UintType(64),
    });

    const TypeTest = @import("test_utils.zig").typeTest(Container);

    const test_cases = [_]TypeTestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/container/valid.test.ts#L51
        .{
            .id = "zero",
            .serializedHex = "0x0c0000000000000000000000",
            .json =
            \\{"a":[],"b":"0"}
            ,
            .rootHex = "0xdc3619cbbc5ef0e0a3b38e3ca5d31c2b16868eacb6e4bcf8b4510963354315f5",
        },
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/container/valid.test.ts#L57
        .{
            .id = "some value",
            .serializedHex = "0x0c000000f1fb09000000000040e2010000000000f1fb09000000000040e2010000000000f1fb09000000000040e2010000000000",
            .json =
            \\{"a":["123456","654321","123456","654321","123456"],"b":"654321"}
            ,
            .rootHex = "0x5ff1b92b2fa55eea1a14b26547035b2f5437814b3436172205fa7d6af4091748",
        },
    };

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "FixedContainerType equals" {
    const Container = FixedContainerType(struct {
        slot: UintType(64),
        root: ByteVectorType(32),
        active: BoolType(),
    });

    var a: Container.Type = undefined;
    var b: Container.Type = undefined;
    var c: Container.Type = undefined;

    a.slot = 42;
    a.root = [_]u8{1} ** 32;
    a.active = true;

    b.slot = 42;
    b.root = [_]u8{1} ** 32;
    b.active = true;

    c.slot = 43; // Different slot
    c.root = [_]u8{1} ** 32;
    c.active = true;

    try std.testing.expect(Container.equals(&a, &b));
    try std.testing.expect(!Container.equals(&a, &c));
}

test "VariableContainerType equals" {
    const allocator = std.testing.allocator;
    const Container = VariableContainerType(struct {
        list1: FixedListType(UintType(8), 32),
        list2: FixedListType(UintType(8), 32),
        value: UintType(64),
    });

    var a: Container.Type = undefined;
    var b: Container.Type = undefined;
    var c: Container.Type = undefined;

    a.list1 = FixedListType(UintType(8), 32).Type.empty;
    a.list2 = FixedListType(UintType(8), 32).Type.empty;
    a.value = 100;

    b.list1 = FixedListType(UintType(8), 32).Type.empty;
    b.list2 = FixedListType(UintType(8), 32).Type.empty;
    b.value = 100;

    c.list1 = FixedListType(UintType(8), 32).Type.empty;
    c.list2 = FixedListType(UintType(8), 32).Type.empty;
    c.value = 101; // Different value

    defer a.list1.deinit(allocator);
    defer a.list2.deinit(allocator);
    defer b.list1.deinit(allocator);
    defer b.list2.deinit(allocator);
    defer c.list1.deinit(allocator);
    defer c.list2.deinit(allocator);

    try a.list1.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try a.list2.appendSlice(allocator, &[_]u8{ 4, 5, 6 });

    try b.list1.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try b.list2.appendSlice(allocator, &[_]u8{ 4, 5, 6 });

    try c.list1.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try c.list2.appendSlice(allocator, &[_]u8{ 4, 5, 6 });

    try std.testing.expect(Container.equals(&a, &b));
    try std.testing.expect(!Container.equals(&a, &c));
}
