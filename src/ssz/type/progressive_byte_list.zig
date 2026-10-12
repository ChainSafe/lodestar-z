const std = @import("std");
const progressive_list = @import("progressive_list.zig");
const UintType = @import("uint.zig").UintType;
const TypeKind = @import("type_kind.zig").TypeKind;

pub fn isProgressiveByteListType(comptime ST: type) bool {
    return ST.kind == .progressive_list and @hasDecl(ST, "is_progressive_byte_list") and ST.is_progressive_byte_list;
}

/// The byte-list JSON representation is hexadecimal; its SSZ encoding and roots
/// are exactly those of a progressive uint8 list with the same storage options.
pub fn ProgressiveByteListType(comptime options: progressive_list.TypeOpts) type {
    const ProgressiveListFixed = progressive_list.FixedProgressiveListType(UintType(8), options);
    return struct {
        pub const is_progressive_byte_list = true;
        pub const kind = TypeKind.progressive_list;
        pub const Element = ProgressiveListFixed.Element;
        pub const opts = ProgressiveListFixed.opts;
        pub const limit = ProgressiveListFixed.limit;
        pub const Type = ProgressiveListFixed.Type;
        pub const TreeView = @import("../tree_view/progressive_list_basic.zig").ProgressiveListBasicTreeView(@This());
        pub const min_size = ProgressiveListFixed.min_size;
        pub const max_size = ProgressiveListFixed.max_size;
        pub const default_value = ProgressiveListFixed.default_value;
        pub const default_root = ProgressiveListFixed.default_root;
        pub const equals = ProgressiveListFixed.equals;
        pub const deinit = ProgressiveListFixed.deinit;
        pub const chunkCount = ProgressiveListFixed.chunkCount;
        pub const hashTreeRoot = ProgressiveListFixed.hashTreeRoot;
        pub const serializedSize = ProgressiveListFixed.serializedSize;
        pub const serializeIntoBytes = ProgressiveListFixed.serializeIntoBytes;
        pub const deserializeFromBytes = ProgressiveListFixed.deserializeFromBytes;
        pub const serialized = ProgressiveListFixed.serialized;
        pub const tree = ProgressiveListFixed.tree;

        pub fn serializeIntoJson(_: std.mem.Allocator, writer: anytype, value: *const Type) !void {
            if (value.items.len > limit) return error.LengthOverLimit;
            try writer.print("\"0x{x}\"", .{value.items});
        }

        /// Initialize `out` with `default_value`; the caller deinitializes it after success or error.
        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            const text = switch (try source.next()) {
                .string => |value| value,
                else => return error.InvalidJson,
            };
            if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidJson;
            const digits = text[2..];
            if (digits.len % 2 != 0) return error.InvalidJson;
            const length = digits.len / 2;
            if (length > limit) return error.LengthOverLimit;

            var replacement: Type = .empty;
            errdefer replacement.deinit(allocator);
            try replacement.resize(allocator, length);
            _ = std.fmt.hexToBytes(replacement.items, digits) catch return error.InvalidJson;
            out.* = replacement;
        }
    };
}

test {
    _ = @import("progressive_byte_list_test.zig");
}
