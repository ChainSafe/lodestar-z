const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const isFixedType = @import("type_kind.zig").isFixedType;
const hashOne = @import("hashing").hashOne;
const Node = @import("persistent_merkle_tree").Node;

/// Validates that a selector is within the valid range (1-127)
fn isValidSelector(selector: u8) bool {
    return selector >= 1 and selector <= 127;
}

/// Validates and extracts selector from serialized data
fn validateAndExtractSelector(data: []const u8, comptime options: anytype) !u8 {
    if (data.len < 1) return error.InvalidSize;
    const selector = data[0];
    if (!isValidSelector(selector)) return error.InvalidSelector;

    inline for (options) |option| {
        if (option.@"0" == selector) return selector;
    }
    return error.InvalidSelector;
}

/// Creates a 32-byte padded array with the selector in the first byte
fn selectorPadded(selector: u8) [32]u8 {
    var result = [_]u8{0} ** 32;
    result[0] = selector;
    return result;
}

/// A union value containing a selector and data
fn UnionValue(comptime options: anytype) type {
    return struct {
        selector: u8,
        data: UnionDataType(options),
    };
}

/// Creates a tag enum for the union
fn UnionTagType(comptime options: anytype) type {
    const fields_count = options.len;

    comptime var enum_fields: [fields_count]std.builtin.Type.EnumField = undefined;
    inline for (options, 0..) |option, i| {
        const selector = option.@"0";
        const name = std.fmt.comptimePrint("option_{d}", .{selector});

        enum_fields[i] = .{
            .name = name,
            .value = i, // Must use index, not selector!
        };
    }

    return @Type(.{
        .@"enum" = .{
            .tag_type = std.math.IntFittingRange(0, fields_count - 1),
            .fields = &enum_fields,
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_exhaustive = true,
        },
    });
}

/// Creates a tagged union type for the data portion
fn UnionDataType(comptime options: anytype) type {
    const fields_count = options.len;

    // Build union fields from options
    comptime var union_fields: [fields_count]std.builtin.Type.UnionField = undefined;
    inline for (options, 0..) |option, i| {
        const selector = option.@"0";
        const option_type = option.@"1";

        // Create a sentinel-terminated field name
        const name = std.fmt.comptimePrint("option_{d}", .{selector});

        union_fields[i] = .{
            .name = name,
            .type = option_type.Type,
            .alignment = @alignOf(option_type.Type),
        };
    }

    return @Type(.{
        .@"union" = .{
            .layout = .auto,
            .tag_type = UnionTagType(options),
            .fields = &union_fields,
            .decls = &[_]std.builtin.Type.Declaration{},
        },
    });
}

pub fn CompatibleUnionType(comptime options: anytype) type {
    comptime {
        // Validate that we have at least one option
        if (options.len == 0) {
            @compileError("CompatibleUnion must have at least one type option");
        }

        // Validate all selectors are in valid range
        for (options) |option| {
            const selector = option.@"0";
            if (!isValidSelector(selector)) {
                @compileError("CompatibleUnion selectors must be in range 1-127");
            }
        }

        // Check for duplicate selectors
        for (options, 0..) |option1, i| {
            for (options, 0..) |option2, j| {
                if (i < j and option1.@"0" == option2.@"0") {
                    @compileError("CompatibleUnion has duplicate selector");
                }
            }
        }
    }

    const ValueType = UnionValue(options);

    // Calculate min and max sizes
    comptime var _min_size: usize = std.math.maxInt(usize);
    comptime var _max_size: usize = 0;

    inline for (options) |option| {
        const option_type = option.@"1";
        const option_min = if (@hasDecl(option_type, "min_size")) option_type.min_size else option_type.fixed_size;
        const option_max = if (@hasDecl(option_type, "max_size")) option_type.max_size else option_type.fixed_size;
        _min_size = @min(_min_size, option_min + 1);
        // Handle unbounded types (max_size == maxInt(usize))
        if (option_max == std.math.maxInt(usize)) {
            _max_size = std.math.maxInt(usize);
        } else {
            _max_size = @max(_max_size, option_max + 1);
        }
    }

    return struct {
        pub const kind = TypeKind.compatible_union;
        pub const Type: type = ValueType;
        pub const min_size: usize = _min_size;
        pub const max_size: usize = _max_size;
        pub const _union_options = options;

        // Default value uses first option with selector
        pub const default_value: Type = blk: {
            const first_selector = options[0].@"0";
            const first_type = options[0].@"1";
            const field_name = std.fmt.comptimePrint("option_{d}", .{first_selector});

            break :blk .{
                .selector = first_selector,
                .data = @unionInit(UnionDataType(options), field_name, first_type.default_value),
            };
        };

        /// Check if a selector is valid
        pub fn isValidSelectorValue(selector: u8) bool {
            inline for (options) |option| {
                if (option.@"0" == selector) {
                    return true;
                }
            }
            return false;
        }

        pub fn equals(a: *const Type, b: *const Type) bool {
            if (a.selector != b.selector) {
                return false;
            }

            // Compare data based on selector
            inline for (options) |option| {
                if (a.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});
                    return option_type.equals(&@field(a.data, field_name), &@field(b.data, field_name));
                }
            }
            return false;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            inline for (options) |option| {
                if (value.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    if (!comptime isFixedType(option_type)) {
                        const data_ptr = &@field(value.data, field_name);
                        option_type.deinit(allocator, data_ptr);
                    }
                    return;
                }
            }
        }

        pub fn clone(
            allocator: std.mem.Allocator,
            value: *const Type,
            out: *Type,
        ) !void {
            out.selector = value.selector;

            inline for (options) |option| {
                if (value.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    const value_data_ptr = &@field(value.data, field_name);
                    out.data = @unionInit(@TypeOf(out.data), field_name, option_type.default_value);
                    const out_data_ptr = &@field(out.data, field_name);
                    if (comptime isFixedType(option_type)) {
                        try option_type.clone(value_data_ptr, out_data_ptr);
                    } else {
                        try option_type.clone(allocator, value_data_ptr, out_data_ptr);
                    }
                    return;
                }
            }
            return error.InvalidSelector;
        }

        /// Hash tree root: mix_in_selector(hash_tree_root(data), selector)
        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            var data_root: [32]u8 = undefined;

            // Hash the data based on selector
            inline for (options) |option| {
                if (value.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    const data_ptr = &@field(value.data, field_name);

                    if (comptime isFixedType(option_type) and option_type.kind != .progressive_container) {
                        try option_type.hashTreeRoot(data_ptr, &data_root);
                    } else {
                        try option_type.hashTreeRoot(allocator, data_ptr, &data_root);
                    }

                    // Mix in selector: hash(data_root, selector_padded)
                    const selector_bytes = selectorPadded(value.selector);
                    hashOne(out, &data_root, &selector_bytes);
                    return;
                }
            }

            return error.InvalidSelector;
        }

        pub fn serializedSize(value: *const Type) usize {
            var size: usize = 1; // selector byte

            inline for (options) |option| {
                if (value.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    if (comptime isFixedType(option_type)) {
                        size += option_type.fixed_size;
                    } else {
                        const data_ptr = &@field(value.data, field_name);
                        size += option_type.serializedSize(data_ptr);
                    }
                    return size;
                }
            }

            return size;
        }

        /// Serialize: selector (1 byte) + serialize(data)
        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            out[0] = value.selector;

            inline for (options) |option| {
                if (value.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    // Access the union field properly using the active tag
                    const data_ref = &@field(value.data, field_name);
                    const bytes_written = option_type.serializeIntoBytes(data_ref, out[1..]);
                    return 1 + bytes_written;
                }
            }

            return 1;
        }

        /// Deserialize: read selector, then deserialize data using selected type
        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            const selector = try validateAndExtractSelector(data, options);
            out.selector = selector;

            // Deserialize data based on selector
            inline for (options) |option| {
                if (selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    out.data = @unionInit(@TypeOf(out.data), field_name, option_type.default_value);
                    const out_data_ptr = &@field(out.data, field_name);

                    if (comptime isFixedType(option_type)) {
                        try option_type.deserializeFromBytes(data[1..], out_data_ptr);
                    } else {
                        try option_type.deserializeFromBytes(allocator, data[1..], out_data_ptr);
                    }

                    return;
                }
            }

            return error.InvalidSelector;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                const selector = try validateAndExtractSelector(data, options);

                // Validate data based on selector
                inline for (options) |option| {
                    if (selector == option.@"0") {
                        const option_type = option.@"1";
                        try option_type.serialized.validate(data[1..]);
                        return;
                    }
                }
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                const selector = try validateAndExtractSelector(data, options);
                var data_root: [32]u8 = undefined;

                // Hash data based on selector
                inline for (options) |option| {
                    if (selector == option.@"0") {
                        const option_type = option.@"1";

                        if (comptime isFixedType(option_type) and option_type.kind != .progressive_container) {
                            try option_type.serialized.hashTreeRoot(data[1..], &data_root);
                        } else {
                            try option_type.serialized.hashTreeRoot(allocator, data[1..], &data_root);
                        }

                        // Mix in selector
                        const selector_bytes = selectorPadded(selector);
                        hashOne(out, &data_root, &selector_bytes);
                        return;
                    }
                }
            }
        };

        /// JSON format: {"selector": "number", "data": type_json}
        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, value: *const Type) !void {
            try writer.beginObject();

            try writer.objectField("selector");
            try writer.print("\"{d}\"", .{value.selector});

            try writer.objectField("data");

            inline for (options) |option| {
                if (value.selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    const data_ptr = &@field(value.data, field_name);

                    if (comptime isFixedType(option_type)) {
                        try option_type.serializeIntoJson(writer, data_ptr);
                    } else {
                        try option_type.serializeIntoJson(allocator, writer, data_ptr);
                    }

                    try writer.endObject();
                    return;
                }
            }

            try writer.endObject();
        }

        pub const tree = struct {
            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                // Get selector from right child (mixed in)
                const selector_node = try node.getRight(pool);
                const selector_bytes = selector_node.getRoot(pool);
                const selector = selector_bytes[0];
                if (!isValidSelector(selector) or !isValidSelectorValue(selector)) {
                    return error.InvalidSelector;
                }
                out.selector = selector;

                // Get data from left child
                const data_node = try node.getLeft(pool);

                // Deserialize data based on selector
                inline for (options) |option| {
                    if (selector == option.@"0") {
                        const option_type = option.@"1";
                        const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                        out.data = @unionInit(@TypeOf(out.data), field_name, option_type.default_value);
                        const out_data_ptr = &@field(out.data, field_name);

                        if (comptime isFixedType(option_type)) {
                            try option_type.tree.toValue(data_node, pool, out_data_ptr);
                        } else {
                            try option_type.tree.toValue(allocator, data_node, pool, out_data_ptr);
                        }
                        return;
                    }
                }

                return error.InvalidSelector;
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                var data_tree: Node.Id = undefined;

                // Create tree for data based on selector
                inline for (options) |option| {
                    if (value.selector == option.@"0") {
                        const option_type = option.@"1";
                        const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                        const data_ptr = &@field(value.data, field_name);

                        if (comptime isFixedType(option_type) and option_type.kind != .progressive_container) {
                            data_tree = try option_type.tree.fromValue(pool, data_ptr);
                        } else {
                            data_tree = try option_type.tree.fromValue(allocator, pool, data_ptr);
                        }

                        // Mix in selector: create branch with data on left, selector on right
                        const selector_bytes = selectorPadded(value.selector);
                        const selector_node = try pool.createLeaf(&selector_bytes, false);

                        return try pool.createBranch(data_tree, selector_node, false);
                    }
                }

                return error.InvalidSelector;
            }
        };

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            // Start object "{"
            switch (try source.next()) {
                .object_begin => {},
                else => return error.InvalidJson,
            }

            // Read "selector" field
            const selector_key = switch (try source.next()) {
                .string => |str| str,
                else => return error.InvalidJson,
            };

            if (!std.mem.eql(u8, selector_key, "selector")) {
                return error.InvalidJson;
            }

            const selector: u8 = switch (try source.next()) {
                .string => |str| std.fmt.parseInt(u8, str, 10) catch return error.InvalidJson,
                else => return error.InvalidJson,
            };
            if (!isValidSelector(selector) or !isValidSelectorValue(selector)) {
                return error.InvalidSelector;
            }
            out.selector = selector;

            // Read "data" field
            const data_key = switch (try source.next()) {
                .string => |str| str,
                else => return error.InvalidJson,
            };

            if (!std.mem.eql(u8, data_key, "data")) {
                return error.InvalidJson;
            }

            // Deserialize data based on selector
            inline for (options) |option| {
                if (selector == option.@"0") {
                    const option_type = option.@"1";
                    const field_name = comptime std.fmt.comptimePrint("option_{d}", .{option.@"0"});

                    out.data = @unionInit(@TypeOf(out.data), field_name, option_type.default_value);
                    const out_data_ptr = &@field(out.data, field_name);

                    if (comptime isFixedType(option_type)) {
                        try option_type.deserializeFromJson(source, out_data_ptr);
                    } else {
                        try option_type.deserializeFromJson(allocator, source, out_data_ptr);
                    }

                    // End object "}"
                    switch (try source.next()) {
                        .object_end => {},
                        else => return error.InvalidJson,
                    }
                    return;
                }
            }
        }
    };
}

const UintType = @import("uint.zig").UintType;

test "CompatibleUnion - basic square and circle" {
    const Square = @import("container.zig").FixedContainerType(struct {
        side: UintType(16),
        color: UintType(8),
    });

    const Circle = @import("container.zig").FixedContainerType(struct {
        radius: UintType(16),
        color: UintType(8),
    });

    const Shape = CompatibleUnionType(.{
        .{ 1, Square },
        .{ 2, Circle },
    });

    // Initialize the union properly with @unionInit
    var square_data = Square.default_value;
    square_data.side = 10;
    square_data.color = 5;

    var square_value: Shape.Type = .{
        .selector = 1,
        .data = @unionInit(@TypeOf(Shape.default_value.data), "option_1", square_data),
    };

    // Test serialization
    var buf: [256]u8 = undefined;
    const size = Shape.serializeIntoBytes(&square_value, &buf);

    try std.testing.expectEqual(@as(usize, 4), size); // 1 selector + 2 side + 1 color
    try std.testing.expectEqual(@as(u8, 1), buf[0]); // selector

    // Test deserialization
    var deserialized: Shape.Type = undefined;
    try Shape.deserializeFromBytes(std.testing.allocator, buf[0..size], &deserialized);

    try std.testing.expectEqual(@as(u8, 1), deserialized.selector);
    try std.testing.expectEqual(@as(u16, 10), deserialized.data.option_1.side);
    try std.testing.expectEqual(@as(u8, 5), deserialized.data.option_1.color);
}

test "CompatibleUnion - hash tree root with selector mix-in" {
    const Square = @import("container.zig").FixedContainerType(struct {
        side: UintType(16),
    });

    const Shape = CompatibleUnionType(.{
        .{ 1, Square },
    });

    // Initialize the union properly with @unionInit
    var square_data = Square.default_value;
    square_data.side = 10;

    var square_value: Shape.Type = .{
        .selector = 1,
        .data = @unionInit(@TypeOf(Shape.default_value.data), "option_1", square_data),
    };

    var root: [32]u8 = undefined;
    try Shape.hashTreeRoot(std.testing.allocator, &square_value, &root);

    // The root should not be all zeros
    var all_zero = true;
    for (root) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "CompatibleUnion - invalid selector rejected" {
    const Square = @import("container.zig").FixedContainerType(struct {
        side: UintType(16),
    });

    const Shape = CompatibleUnionType(.{
        .{ 1, Square },
    });

    // Try to deserialize with invalid selector (0)
    var buf = [_]u8{ 0, 10, 0 };
    var value: Shape.Type = undefined;

    const result = Shape.deserializeFromBytes(std.testing.allocator, &buf, &value);
    try std.testing.expectError(error.InvalidSelector, result);

    // Try to deserialize with invalid selector (128)
    buf[0] = 128;
    const result2 = Shape.deserializeFromBytes(std.testing.allocator, &buf, &value);
    try std.testing.expectError(error.InvalidSelector, result2);

    // Try to deserialize with selector not in options (2)
    buf[0] = 2;
    const result3 = Shape.deserializeFromBytes(std.testing.allocator, &buf, &value);
    try std.testing.expectError(error.InvalidSelector, result3);
}
