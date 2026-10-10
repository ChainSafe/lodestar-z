const std = @import("std");
const progressive_list = @import("progressive_list.zig");
const UintType = @import("uint.zig").UintType;
const TypeKind = @import("type_kind.zig").TypeKind;

pub fn isProgressiveByteListType(comptime ST: type) bool {
    return ST.kind == .progressive_list and @hasDecl(ST, "is_progressive_byte_list") and ST.is_progressive_byte_list;
}

pub fn ProgressiveByteListType() type {
    return ProgressiveByteListTypeWithOptions(.{});
}

/// The byte-list JSON representation is hexadecimal; its SSZ encoding and roots
/// are exactly those of a progressive uint8 list with the same storage options.
pub fn ProgressiveByteListTypeWithOptions(comptime options: progressive_list.TypeOpts) type {
    const Generic = progressive_list.FixedProgressiveListTypeWithOptions(UintType(8), options);
    return struct {
        pub const is_progressive_byte_list = true;
        pub const kind = TypeKind.progressive_list;
        pub const Element = Generic.Element;
        pub const opts = Generic.opts;
        pub const limit = Generic.limit;
        pub const Type = Generic.Type;
        pub const TreeView = @import("../tree_view/progressive_list_basic.zig").ProgressiveListBasicTreeView(@This());
        pub const min_size = Generic.min_size;
        pub const max_size = Generic.max_size;
        pub const default_value = Generic.default_value;
        pub const default_root = Generic.default_root;
        pub const equals = Generic.equals;
        pub const deinit = Generic.deinit;
        pub const chunkCount = Generic.chunkCount;
        pub const hashTreeRoot = Generic.hashTreeRoot;
        pub const serializedSize = Generic.serializedSize;
        pub const serializeIntoBytes = Generic.serializeIntoBytes;
        pub const deserializeFromBytes = Generic.deserializeFromBytes;
        pub const serialized = Generic.serialized;
        pub const tree = Generic.tree;

        pub fn serializeIntoJson(_: std.mem.Allocator, writer: anytype, value: *const Type) !void {
            if (value.items.len > limit) return error.LengthOverLimit;
            try writer.print("\"0x{x}\"", .{value.items});
        }

        /// The initialized output is replaced only after the entire hex string
        /// validates and its allocation succeeds.
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
            out.deinit(allocator);
            out.* = replacement;
        }
    };
}

test {
    _ = @import("progressive_byte_list_test.zig");
}
