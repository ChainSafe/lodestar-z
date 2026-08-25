//! A zero-allocation, eagerly validated iterator for serialized elements in
//! SSZ lists and vectors with variable-size elements.
//!
//! SSZ encodes these collections as a table of 4-byte little-endian offsets followed by the
//! element data. For example:
//!
//! ```text
//!     [offset 1] [offset 2] [data 1 ..........] [data 2 ..]
//! 0x  08000000   0e000000   010002000300        01000200
//! ```
//!
//! The first offset is 8, so the element data starts at byte 8 and the offset table is 8 bytes
//! long. Each offset occupies 4 bytes, so the table contains `8 / 4 = 2` offsets. The second offset
//! is 14, so the first element occupies bytes 8 through 13 and the second element starts at byte 14.
//!
//! # Safety 
//!
//! Initialization eagerly validates the complete offset table:
//!
//! - Returns `error.offsetOutOfRange` if a vector input is empty, the input does not contain a
//!   complete first offset, or an offset points past the end of the input.
//! - Returns `error.zeroOffset` if the first offset is zero.
//! - Returns `error.offsetNotDivisibleBy4` if the first offset is not divisible by the 4-byte offset
//!   size.
//! - Returns `error.invalidOffsetCount` if the offset count does not equal the vector length or
//!   exceeds the list limit.
//! - Returns `error.offsetNotIncreasing` if an offset is less than the previous offset.
//!
//! Equal offsets encode empty elements. For example:
//!
//! ```text
//!     [offset 1] [offset 2] [data 2 ..]
//! 0x  08000000   08000000   01000200
//! ```
//!
//! Both elements start at byte 8, so the first element is the empty slice `data[8..8]`. The second
//! element contains the remaining bytes.
//!
//! After successful validation, the iterator yields borrowed element slices without allocation or
//! per-element errors, making iteration infallible.

const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const isFixedType = @import("type_kind.zig").isFixedType;

/// Returns an iterator over serialized elements of a variable-element SSZ list or vector.
///
/// Pre-condition:
/// `ST` must describe an SSZ list or vector with a variable-size element type.
/// 
/// `init` validates the complete offset table and collection bounds,
/// which makes element iteration infallible.
///
/// Returned element slices reference the input data, so the caller must 
/// keep the data alive and unchanged while the iterator is in use.
pub fn VariableElementIterator(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector and 
            ST.kind != .list) {
            @compileError("ST must be a vector or list");
        }
        if (isFixedType(ST.Element)) {
            @compileError("ST.Element must not be a fixed type");
        }
    }

    return struct {
        data: []const u8,
        /// Total number of elements.
        element_count: usize,
        /// Number of elements already returned by `next()`.
        index: usize,
        start: usize,

        const Self = @This();

        /// Initializes an iterator and validates the complete SSZ offset table.
        ///
        /// Returns an error if the encoding has invalid offsets or violates the list or vector
        /// bounds of `ST`.
        pub fn init(data: []const u8) !Self {
            if (data.len == 0) {
                if (ST.kind == .vector) return error.offsetOutOfRange;
                return .{
                    .data = data,
                    .element_count = 0,
                    .index = 0,
                    .start = 0,
                };
            }
            if (data.len < 4) return error.offsetOutOfRange;

            const first_offset = readOffset(data, 0);
            if (first_offset == 0) return error.zeroOffset;
            if (first_offset % 4 != 0) return error.offsetNotDivisibleBy4;

            const element_count = first_offset / 4;
            if (ST.kind == .vector and element_count != ST.length) {
                return error.invalidOffsetCount;
            }
            if (ST.kind == .list and element_count > ST.limit) {
                return error.invalidOffsetCount;
            }
            if (first_offset > data.len) return error.offsetOutOfRange;

            var previous_offset = first_offset;
            for (1..element_count) |i| {
                const offset = readOffset(data, i);
                if (offset > data.len) return error.offsetOutOfRange;
                if (offset < previous_offset) return error.offsetNotIncreasing;
                previous_offset = offset;
            }

            return .{
                .data = data,
                .element_count = element_count,
                .index = 0,
                .start = first_offset,
            };
        }

        /// Returns the total element count.
        pub fn len(self: Self) usize {
            return self.element_count;
        }

        /// Returns the next serialized element, or `null` after the last element.
        pub fn next(self: *Self) ?[]const u8 {
            if (self.index == self.element_count) return null;

            const next_index = self.index + 1;
            const end = if (next_index == self.element_count)
                self.data.len
            else
                readOffset(self.data, next_index);

            std.debug.assert(end >= self.start);
            std.debug.assert(end <= self.data.len);

            const element = self.data[self.start..end];
            self.start = end;
            self.index = next_index;
            return element;
        }

        fn readOffset(data: []const u8, index: usize) usize {
            return std.mem.readInt(u32, data[index * 4 ..][0..4], .little);
        }
    };
}

/// A dummy ssz variable element used for tests.
const VariableElement = struct {
    pub const kind = TypeKind.list;
};

/// A dummy ssz variable list used for tests.
const VariableList = struct {
    pub const kind = TypeKind.list;
    pub const Element = VariableElement;
    pub const limit = 2;
};

/// A dummy ssz variable vector used for tests.
const VariableVector = struct {
    pub const kind = TypeKind.vector;
    pub const Element = VariableElement;
    pub const length = 2;
};

test "iterates validated variable elements" {
    const data = [_]u8{
        8,  0, 0, 0,
        10, 0, 0, 0,
        1,  2, 3, 4,
        5,
    };

    var elements = try VariableElementIterator(VariableList).init(&data);
    try std.testing.expectEqual(@as(usize, 2), elements.len());
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, elements.next().?);
    try std.testing.expectEqualSlices(u8, &.{ 3, 4, 5 }, elements.next().?);
    try std.testing.expectEqual(null, elements.next());
}

test "accepts empty list and empty elements" {
    var empty_list = try VariableElementIterator(VariableList).init(&.{});
    try std.testing.expectEqual(@as(usize, 0), empty_list.len());
    try std.testing.expectEqual(null, empty_list.next());

    const data = [_]u8{
        8, 0, 0, 0,
        8, 0, 0, 0,
    };
    var empty_elements = try VariableElementIterator(VariableList).init(&data);
    try std.testing.expectEqualSlices(u8, &.{}, empty_elements.next().?);
    try std.testing.expectEqualSlices(u8, &.{}, empty_elements.next().?);
    try std.testing.expectEqual(null, empty_elements.next());
}

test "rejects malformed offsets during initialization" {
    try std.testing.expectError(
        error.offsetNotIncreasing,
        VariableElementIterator(VariableList).init(&.{
            8, 0, 0, 0,
            7, 0, 0, 0,
        }),
    );
    try std.testing.expectError(
        error.offsetOutOfRange,
        VariableElementIterator(VariableList).init(&.{
            8, 0, 0, 0,
            9, 0, 0, 0,
        }),
    );
    try std.testing.expectError(
        error.offsetNotDivisibleBy4,
        VariableElementIterator(VariableList).init(&.{ 5, 0, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.invalidOffsetCount,
        VariableElementIterator(VariableVector).init(&.{ 4, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.invalidOffsetCount,
        VariableElementIterator(VariableList).init(&.{ 12, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.offsetOutOfRange,
        VariableElementIterator(VariableVector).init(&.{}),
    );
}
