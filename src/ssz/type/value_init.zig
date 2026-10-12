const std = @import("std");

/// Allocation-free, deinitializable storage for decoding or cloning. This is
/// separate from an SSZ default: compatible unions have no default value. For
/// those, select the first declared option solely to initialize the native tag
/// and empty owned fields before a decoder replaces the value.
pub fn initValue(comptime ST: type) ST.Type {
    // The value depends only on the type. Keeping the aggregate initialization
    // at comptime avoids one runtime memcpy per element of large fixed vectors.
    return comptime switch (ST.kind) {
        .compatible_union => @unionInit(
            ST.Type,
            std.fmt.comptimePrint("option_{d}", .{ST._union_options[0].@"0"}),
            initValue(ST._union_options[0].@"1"),
        ),
        .container, .progressive_container => blk: {
            var value: ST.Type = undefined;
            for (ST.fields) |field| @field(value, field.name) = initValue(field.type);
            break :blk value;
        },
        .vector => if (@typeInfo(ST.Type) == .array) @splat(initValue(ST.Element)) else ST.default_value,
        else => ST.default_value,
    };
}
