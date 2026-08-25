const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const isFixedType = @import("type_kind.zig").isFixedType;

/// Iterates serialized variable-size list or vector elements after validating all offsets.
pub fn VariableElementIterator(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector and ST.kind != .list) {
            @compileError("ST must be a vector or list");
        }
        if (isFixedType(ST.Element)) {
            @compileError("ST.Element must not be a fixed type");
        }
    }

    return struct {
        data: []const u8,
        element_count: usize,
        index: usize,
        start: usize,

        const Self = @This();

        /// `data` must remain unchanged while the iterator is in use.
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

        pub fn len(self: Self) usize {
            return self.element_count;
        }

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
