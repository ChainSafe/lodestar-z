const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();

pub const TypeKind = enum {
    uint,
    bool,
    vector,
    list,
    container,
};

/// Basic types are primitives
pub fn isBasicType(T: type) bool {
    return T.kind == .uint or T.kind == .bool;
}

// Fixed-size types have a known size
pub fn isFixedType(T: type) bool {
    return switch (T.kind) {
        .uint, .bool => true,
        .list => false,
        .vector => isFixedType(T.Element),
        .container => {
            inline for (T.fields) |field| {
                if (!isFixedType(field.type)) {
                    return false;
                }
            }
            return true;
        },
    };
}

/// Determines if the TreeView of this type is mutable.
/// Returns false for:
/// - Any BasicType (uint, bool)
/// - ByteVector, ByteList
/// All other composite types return TreeView wrappers that can be modified.
pub fn isViewMutable(comptime ST: type) bool {
    if (isBasicType(ST)) {
        return false;
    }

    if (ST.kind == .list or ST.kind == .vector) {
        if (@hasDecl(ST, "Element")) {
            const E = ST.Element;
            if (E.kind == .uint and E.fixed_size == 1) {
                return false;
            }
        }
    }
    return true;
}
