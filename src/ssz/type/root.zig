pub const TypeKind = @import("type_kind.zig").TypeKind;
pub const isBasicType = @import("type_kind.zig").isBasicType;
pub const isFixedType = @import("type_kind.zig").isFixedType;
pub const isProgressiveListType = @import("type_kind.zig").isProgressiveListType;
pub const isCompatibleUnionType = @import("type_kind.zig").isCompatibleUnionType;

pub const BoolType = @import("bool.zig").BoolType;
pub const UintType = @import("uint.zig").UintType;

pub const BitListType = @import("bit_list.zig").BitListType;
pub const BitList = @import("bit_list.zig").BitList;
pub const isBitListType = @import("bit_list.zig").isBitListType;

pub const BitVectorType = @import("bit_vector.zig").BitVectorType;
pub const BitVector = @import("bit_vector.zig").BitVector;
pub const isBitVectorType = @import("bit_vector.zig").isBitVectorType;

pub const ByteListType = @import("byte_list.zig").ByteListType;
pub const isByteListType = @import("byte_list.zig").isByteListType;

pub const ByteVectorType = @import("byte_vector.zig").ByteVectorType;
pub const isByteVectorType = @import("byte_vector.zig").isByteVectorType;

pub const FixedListType = @import("list.zig").FixedListType;
pub const VariableListType = @import("list.zig").VariableListType;

pub const FixedVectorType = @import("vector.zig").FixedVectorType;
pub const VariableVectorType = @import("vector.zig").VariableVectorType;

pub const FixedContainerType = @import("container.zig").FixedContainerType;
pub const VariableContainerType = @import("container.zig").VariableContainerType;

pub const getPathGindex = @import("path.zig").getPathGindex;

pub const BYTES_PER_CHUNK: usize = 32;

pub const FixedProgressiveContainerType = @import("progressive_container.zig").FixedProgressiveContainerType;
pub const VariableProgressiveContainerType = @import("progressive_container.zig").VariableProgressiveContainerType;

pub const FixedProgressiveListType = @import("progressive_list.zig").FixedProgressiveListType;
pub const VariableProgressiveListType = @import("progressive_list.zig").VariableProgressiveListType;

pub const CompatibleUnionType = @import("compatible_union.zig").CompatibleUnionType;

pub const ProgressiveBitListType = @import("progressive_bit_list.zig").ProgressiveBitListType;
pub const ProgressiveBitList = @import("progressive_bit_list.zig").ProgressiveBitList;
pub const isProgressiveBitListType = @import("progressive_bit_list.zig").isProgressiveBitListType;

pub fn ProgressiveListType(comptime ST: type) type {
    if (isFixedType(ST)) {
        return FixedProgressiveListType(ST);
    } else {
        return VariableProgressiveListType(ST);
    }
}

test {
    _ = @import("bool.zig");
    _ = @import("uint.zig");
    _ = @import("vector.zig");
    _ = @import("bit_list.zig");
    _ = @import("bit_vector.zig");
    _ = @import("byte_list.zig");
    _ = @import("byte_vector.zig");
    _ = @import("list.zig");
    _ = @import("progressive_list.zig");
    _ = @import("progressive_bit_list.zig");
    _ = @import("container.zig");
    _ = @import("progressive_container.zig");
    _ = @import("compatible_union.zig");
    _ = @import("path.zig");
}

const std = @import("std");
