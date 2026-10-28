//! `ssz` splits these types into fixed and variable variants, so the builders pick one at comptime.

const ssz = @import("ssz");

pub fn Vector(comptime Element: type, comptime length: comptime_int) type {
    if (ssz.isFixedType(Element)) return ssz.FixedVectorType(Element, length, .{});
    return ssz.VariableVectorType(Element, length);
}

pub fn List(comptime Element: type, comptime limit: comptime_int) type {
    if (ssz.isFixedType(Element)) return ssz.FixedListType(Element, limit, .{});
    return ssz.VariableListType(Element, limit);
}

pub fn ProgressiveList(comptime Element: type) type {
    if (ssz.isFixedType(Element)) return ssz.FixedProgressiveListType(Element, .{});
    return ssz.VariableProgressiveListType(Element, .{});
}

pub fn Container(comptime Fields: type) type {
    if (allFieldsFixed(Fields)) return ssz.FixedContainerType(Fields);
    return ssz.VariableContainerType(Fields);
}

pub fn ProgressiveContainer(comptime Fields: type, comptime active_fields: []const u1) type {
    if (allFieldsFixed(Fields)) return ssz.FixedProgressiveContainerType(Fields, active_fields);
    return ssz.VariableProgressiveContainerType(Fields, active_fields);
}

fn allFieldsFixed(comptime Fields: type) bool {
    inline for (@typeInfo(Fields).@"struct".fields) |field| {
        if (!ssz.isFixedType(field.type)) return false;
    }
    return true;
}
