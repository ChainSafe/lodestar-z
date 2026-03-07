const std = @import("std");

/// Utility to create a struct type with all optional fields.
pub fn Optional(comptime T: type) type {
    const type_info = @typeInfo(T);
    if (type_info != .@"struct") {
        @compileError("Optional can only be used with struct types");
    }

    const t_fields = type_info.@"struct".fields;
    var optional_fields: [t_fields.len]std.builtin.Type.StructField = undefined;
    inline for (t_fields, 0..) |field, i| {
        const optional_type = @Type(.{ .optional = .{ .child = field.type } });
        optional_fields[i] = .{
            .name = field.name,
            .type = optional_type,
            .default_value_ptr = &@as(optional_type, null),
            .is_comptime = false,
            .alignment = field.alignment,
        };
    }

    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = &optional_fields,
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

pub fn Empty(comptime T: type) T {
    var empty: T = undefined;
    inline for (std.meta.fields(T)) |field| {
        @field(empty, field.name) = null;
    }
    return empty;
}
