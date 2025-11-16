const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const isFixedType = @import("type_kind.zig").isFixedType;
const isBasicType = @import("type_kind.zig").isBasicType;
const progressive = @import("progressive.zig");
const hashOne = @import("hashing").hashOne;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const Depth = @import("persistent_merkle_tree").Depth;

/// Pack active_fields bitvector into a 32-byte array (limited to 256 bits)
fn packActiveFields(comptime active_fields: []const u1) [32]u8 {
    var result = [_]u8{0} ** 32;
    for (active_fields, 0..) |bit, i| {
        if (bit == 1) {
            result[i / 8] |= @as(u8, 1) << @as(u3, @intCast(i % 8));
        }
    }
    return result;
}

/// Validates active_fields configuration at comptime
fn validateActiveFields(comptime active_fields: []const u1, comptime field_count: usize) void {
    // active_fields must not be empty
    if (active_fields.len == 0) {
        @compileError("active_fields cannot be empty");
    }

    // active_fields must not exceed 256 bits
    if (active_fields.len > 256) {
        @compileError("active_fields cannot exceed 256 entries");
    }

    // active_fields must not end in 0
    if (active_fields[active_fields.len - 1] == 0) {
        @compileError("active_fields cannot end in 0");
    }

    // count of 1s in active_fields must equal field_count
    var count: usize = 0;
    for (active_fields) |bit| {
        if (bit == 1) count += 1;
    }
    if (count != field_count) {
        @compileError("count of 1s in active_fields must equal number of fields");
    }
}

/// Returns the merkle tree index (position in active_fields) for the nth field
fn getActiveFieldIndex(comptime active_fields: []const u1, comptime n: usize) usize {
    var count: usize = 0;
    for (active_fields, 0..) |bit, i| {
        if (bit == 1) {
            if (count == n) {
                return i;
            }
            count += 1;
        }
    }
    @compileError("field index out of range");
}

/// Creates a progressive container type with only fixed-size fields.
///
/// Parameters:
///   - ST: A struct type containing only fixed-size SSZ fields
///   - active_fields: Bitvector indicating field positions in the Merkle tree
///
/// The active_fields bitvector determines where each field is placed in the Merkle tree.
/// A '1' at position i means that position is occupied; fields are assigned to positions
/// with '1' bits in order.
///
/// Example:
/// ```zig
/// const MyType = FixedProgressiveContainerType(struct {
///     field_a: UintType(8),
///     field_b: UintType(16),
/// }, &[_]u1{ 1, 0, 1 });
/// // field_a is at position 0, field_b is at position 2
/// ```
pub fn FixedProgressiveContainerType(comptime ST: type, comptime active_fields: []const u1) type {
    const ssz_fields = switch (@typeInfo(ST)) {
        .@"struct" => |s| s.fields,
        else => @compileError("Expected a struct type."),
    };

    // Validate active_fields configuration
    comptime validateActiveFields(active_fields, ssz_fields.len);

    // Validate that container has at least one field
    comptime {
        if (ssz_fields.len == 0) {
            @compileError("ProgressiveContainer with no fields is illegal");
        }
    }

    comptime var native_fields: [ssz_fields.len]std.builtin.Type.StructField = undefined;
    comptime var _offsets: [ssz_fields.len]usize = undefined;
    comptime var _fixed_size: usize = 0;
    inline for (ssz_fields, 0..) |field, i| {
        if (!comptime isFixedType(field.type)) {
            @compileError("FixedProgressiveContainerType must only contain fixed fields");
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
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });

    return struct {
        pub const kind = TypeKind.progressive_container;
        pub const Fields: type = ST;
        pub const fields: []const std.builtin.Type.StructField = ssz_fields;
        pub const Type: type = T;
        pub const fixed_size: usize = _fixed_size;
        pub const field_offsets: [fields.len]usize = _offsets;
        pub const chunk_count: usize = active_fields.len;

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

        /// Creates a new `FixedProgressiveContainerType` and clones all underlying fields in the container.
        ///
        /// Caller owns the memory.
        pub fn clone(value: *const Type, out: *Type) !void {
            out.* = value.*;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            var chunks: [chunk_count][32]u8 = undefined;
            @memset(&chunks, [_]u8{0} ** 32);

            inline for (fields, 0..) |field, i| {
                const field_idx = comptime getActiveFieldIndex(active_fields, i);
                try field.type.hashTreeRoot(&@field(value, field.name), &chunks[field_idx]);
            }

            var temp_root: [32]u8 = undefined;
            try progressive.merkleizeChunks(allocator, &chunks, &temp_root);

            const active_fields_packed = comptime packActiveFields(active_fields);
            hashOne(out, &temp_root, &active_fields_packed);
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

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                var chunks: [chunk_count][32]u8 = undefined;
                @memset(&chunks, [_]u8{0} ** 32);

                var i: usize = 0;
                inline for (fields, 0..) |field, field_i| {
                    const field_idx = comptime getActiveFieldIndex(active_fields, field_i);
                    try field.type.serialized.hashTreeRoot(data[i .. i + field.type.fixed_size], &chunks[field_idx]);
                    i += field.type.fixed_size;
                }

                var temp_root: [32]u8 = undefined;
                try progressive.merkleizeChunks(allocator, &chunks, &temp_root);

                const active_fields_packed = comptime packActiveFields(active_fields);
                hashOne(out, &temp_root, &active_fields_packed);
            }
        };

        pub const tree = struct {
            pub fn toValue(node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                var nodes: [chunk_count]Node.Id = undefined;

                // Extract the active_fields mix-in node (get left child which is the content)
                const content_node = try node.getLeft(pool);

                try progressive.getNodes(pool, content_node, &nodes);

                inline for (fields, 0..) |field, i| {
                    const field_idx = comptime getActiveFieldIndex(active_fields, i);
                    const child_node = nodes[field_idx];
                    try field.type.tree.toValue(child_node, pool, &@field(out, field.name));
                }
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;

                // Initialize all nodes to zero
                for (&nodes) |*node| {
                    node.* = @enumFromInt(0);
                }

                inline for (fields, 0..) |field, i| {
                    const field_idx = comptime getActiveFieldIndex(active_fields, i);
                    const field_value = &@field(value, field.name);
                    nodes[field_idx] = try field.type.tree.fromValue(pool, field_value);
                }

                const content_tree = try progressive.fillWithContents(allocator, pool, &nodes, false);

                // Mix in active_fields
                const active_fields_packed = comptime packActiveFields(active_fields);
                const active_fields_node = try pool.createLeaf(&active_fields_packed, false);

                return try pool.createBranch(content_tree, active_fields_node, false);
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
            const field_i = getFieldIndex(name);
            const field_idx = comptime getActiveFieldIndex(active_fields, field_i);
            return comptime progressive.chunkGindex(field_idx);
        }
    };
}

pub fn VariableProgressiveContainerType(comptime ST: type, comptime active_fields: []const u1) type {
    const ssz_fields = switch (@typeInfo(ST)) {
        .@"struct" => |s| s.fields,
        else => @compileError("Expected a struct type."),
    };

    // Validate active_fields configuration
    comptime validateActiveFields(active_fields, ssz_fields.len);

    // Validate that container has at least one field
    comptime {
        if (ssz_fields.len == 0) {
            @compileError("ProgressiveContainer with no fields is illegal");
        }
    }

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
            if (_max_size != std.math.maxInt(usize)) {
                _max_size += field.type.fixed_size;
            }
            _fixed_end += field.type.fixed_size;
            _fixed_count += 1;
        } else {
            _min_size += field.type.min_size + 4;
            // Handle unbounded types (max_size == maxInt(usize))
            if (field.type.max_size == std.math.maxInt(usize) or _max_size == std.math.maxInt(usize)) {
                _max_size = std.math.maxInt(usize);
            } else {
                _max_size += field.type.max_size + 4;
            }
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
            @compileError("expected at least one variable field type");
        }
    }

    const var_count = ssz_fields.len - _fixed_count;

    const T = @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .backing_integer = null,
            .fields = native_fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });

    return struct {
        pub const kind = TypeKind.progressive_container;
        pub const fields: []const std.builtin.Type.StructField = ssz_fields;
        pub const Fields: type = ST;
        pub const Type: type = T;
        pub const min_size: usize = _min_size;
        pub const max_size: usize = _max_size;
        pub const field_offsets: [fields.len]usize = _offsets;
        pub const fixed_end: usize = _fixed_end;
        pub const fixed_count: usize = _fixed_count;
        pub const chunk_count: usize = active_fields.len;

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
            const chunks = try allocator.alloc([32]u8, chunk_count);
            defer allocator.free(chunks);
            @memset(chunks, [_]u8{0} ** 32);

            inline for (fields, 0..) |field, i| {
                const field_idx = comptime getActiveFieldIndex(active_fields, i);
                if (comptime isFixedType(field.type)) {
                    try field.type.hashTreeRoot(&@field(value, field.name), &chunks[field_idx]);
                } else {
                    try field.type.hashTreeRoot(allocator, &@field(value, field.name), &chunks[field_idx]);
                }
            }

            var temp_root: [32]u8 = undefined;
            try progressive.merkleizeChunks(allocator, chunks, &temp_root);

            const active_fields_packed = comptime packActiveFields(active_fields);
            hashOne(out, &temp_root, &active_fields_packed);
        }

        /// Creates a new `VariableProgressiveContainerType` and clones all underlying fields in the container.
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
            const field_i = getFieldIndex(name);
            const field_idx = comptime getActiveFieldIndex(active_fields, field_i);
            return comptime progressive.chunkGindex(field_idx);
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
                const chunks = try allocator.alloc([32]u8, chunk_count);
                defer allocator.free(chunks);
                @memset(chunks, [_]u8{0} ** 32);

                const ranges = try readFieldRanges(data);

                inline for (fields, 0..) |field, i| {
                    const field_idx = comptime getActiveFieldIndex(active_fields, i);
                    if (comptime isFixedType(field.type)) {
                        try field.type.serialized.hashTreeRoot(
                            data[ranges[i][0]..ranges[i][1]],
                            &chunks[field_idx],
                        );
                    } else {
                        try field.type.serialized.hashTreeRoot(
                            allocator,
                            data[ranges[i][0]..ranges[i][1]],
                            &chunks[field_idx],
                        );
                    }
                }

                var temp_root: [32]u8 = undefined;
                try progressive.merkleizeChunks(allocator, chunks, &temp_root);

                const active_fields_packed = comptime packActiveFields(active_fields);
                hashOne(out, &temp_root, &active_fields_packed);
            }
        };

        pub const tree = struct {
            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                // Extract the active_fields mix-in node (get left child which is the content)
                const content_node = try node.getLeft(pool);

                try progressive.getNodes(pool, content_node, nodes);

                inline for (fields, 0..) |field, i| {
                    const field_idx = comptime getActiveFieldIndex(active_fields, i);
                    const child_node = nodes[field_idx];
                    if (comptime isFixedType(field.type)) {
                        try field.type.tree.toValue(child_node, pool, &@field(out, field.name));
                    } else {
                        try field.type.tree.toValue(allocator, child_node, pool, &@field(out, field.name));
                    }
                }
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                // Initialize all nodes to zero
                for (nodes) |*node| {
                    node.* = @enumFromInt(0);
                }

                inline for (fields, 0..) |field, i| {
                    const field_idx = comptime getActiveFieldIndex(active_fields, i);
                    const field_value = &@field(value, field.name);
                    if (comptime isFixedType(field.type)) {
                        nodes[field_idx] = try field.type.tree.fromValue(pool, field_value);
                    } else {
                        nodes[field_idx] = try field.type.tree.fromValue(allocator, pool, field_value);
                    }
                }

                const content_tree = try progressive.fillWithContents(allocator, pool, nodes, false);

                // Mix in active_fields
                const active_fields_packed = comptime packActiveFields(active_fields);
                const active_fields_node = try pool.createLeaf(&active_fields_packed, false);

                return try pool.createBranch(content_tree, active_fields_node, false);
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

test "ProgressiveContainerType " {
    // Square with active_fields=[1, 0, 1]
    const Square = FixedProgressiveContainerType(struct {
        side: UintType(16),
        color: UintType(8),
    }, &[_]u1{ 1, 0, 1 });

    // Circle with active_fields=[0, 1, 1]
    const Circle = FixedProgressiveContainerType(struct {
        radius: UintType(16),
        color: UintType(8),
    }, &[_]u1{ 0, 1, 1 });

    var square: Square.Type = undefined;
    square.side = 10;
    square.color = 5;

    var circle: Circle.Type = undefined;
    circle.radius = 7;
    circle.color = 5;

    // Test that both serialize correctly
    var square_buf: [Square.fixed_size]u8 = undefined;
    _ = Square.serializeIntoBytes(&square, &square_buf);

    var circle_buf: [Circle.fixed_size]u8 = undefined;
    _ = Circle.serializeIntoBytes(&circle, &circle_buf);

    // Test deserialization
    var square2: Square.Type = undefined;
    try Square.deserializeFromBytes(&square_buf, &square2);
    try std.testing.expectEqual(square.side, square2.side);
    try std.testing.expectEqual(square.color, square2.color);

    // Test hash tree root - color should be at the same gindex for both
    const allocator = std.testing.allocator;
    var square_root: [32]u8 = undefined;
    try Square.hashTreeRoot(allocator, &square, &square_root);

    var circle_root: [32]u8 = undefined;
    try Circle.hashTreeRoot(allocator, &circle, &circle_root);

    // The roots should be different since the structures are different
    try std.testing.expect(!std.mem.eql(u8, &square_root, &circle_root));
}

test "ProgressiveContainerType - variable" {
    const allocator = std.testing.allocator;
    const Foo = VariableProgressiveContainerType(struct {
        a: FixedListType(UintType(8), 32),
        b: FixedListType(UintType(8), 32),
        c: FixedListType(UintType(8), 32),
    }, &[_]u1{ 1, 1, 0, 1 });

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

    var f2: Foo.Type = Foo.default_value;
    try Foo.deserializeFromBytes(allocator, f_buf, &f2);
    defer Foo.deinit(allocator, &f2);
}
