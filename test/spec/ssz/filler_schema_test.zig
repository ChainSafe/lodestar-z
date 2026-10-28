const std = @import("std");
const filler_schema = @import("filler_schema.zig");

test "filler schema should translate every declaration form" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\"""Docstring naming class Hidden(Container): inside."""
        \\
        \\from typing import ClassVar
        \\
        \\from ssz import (
        \\    BitList,
        \\    BitVector,
        \\    Boolean,
        \\    ByteList,
        \\    ByteVector,
        \\    CompatibleUnion,
        \\    Container,
        \\    List,
        \\    ProgressiveContainer,
        \\    ProgressiveList,
        \\    Uint16,
        \\    Vector,
        \\)
        \\from ssz_testing import SSZTestFiller
        \\
        \\
        \\class Payload(ByteList):
        \\    LIMIT = 512 * 1024
        \\
        \\
        \\class Root(ByteVector):
        \\    LENGTH = 32
        \\
        \\
        \\class Flags(BitVector):
        \\    LENGTH = 8
        \\
        \\
        \\class Votes(BitList):
        \\    LIMIT = 16
        \\
        \\
        \\class Pair(Vector[Uint16]):
        \\    """Two elements."""
        \\
        \\    LENGTH: ClassVar[int] = 2
        \\
        \\
        \\class Numbers(List[Uint16]):
        \\    LIMIT = 4
        \\    ELEMENT_TYPE = Uint16  # Restates the subscript.
        \\
        \\
        \\class NumbersAlias(Numbers):
        \\    """Same list."""
        \\
        \\
        \\class Shape(ProgressiveContainer):
        \\    ACTIVE_FIELDS = (1, *([0] * 2), 1)
        \\
        \\    side: Uint16
        \\    error: Boolean
        \\
        \\
        \\class Shapes(ProgressiveList[Shape]):
        \\    """Shapes in order."""
        \\
        \\
        \\class Either(CompatibleUnion):
        \\    OPTIONS = {
        \\        1: Numbers,
        \\        2: NumbersAlias,
        \\    }
        \\
        \\
        \\class Holder(Container):
        \\    head: Uint16
        \\    body: Shapes
        \\
        \\
        \\@decorator
        \\def test_holder(ssz_test: SSZTestFiller) -> None:
        \\    note = "\""
        \\    text = """
        \\class Fake(Container):
        \\    x: Uint16
        \\"""
        \\    ssz_test(Holder, text)
        \\
        \\
        \\LIMIT_BITS = 257
        \\
    ;
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    var diagnostic: filler_schema.Diagnostic = .{};
    try filler_schema.write(arena.allocator(), &out.writer, "sample", source, &diagnostic);
    try std.testing.expectEqualStrings(
        \\pub const sample = struct {
        \\    pub const Boolean = ssz.BoolType();
        \\    pub const Uint16 = ssz.UintType(16);
        \\    pub const Payload = ssz.ByteListType(524288);
        \\    pub const Root = ssz.ByteVectorType(32);
        \\    pub const Flags = ssz.BitVectorType(8);
        \\    pub const Votes = ssz.BitListType(16);
        \\    pub const Pair = filler.Vector(Uint16, 2);
        \\    pub const Numbers = filler.List(Uint16, 4);
        \\    pub const NumbersAlias = Numbers;
        \\    pub const Shape = filler.ProgressiveContainer(struct { side: Uint16, @"error": Boolean }, &.{ 1, 0, 0, 1 });
        \\    pub const Shapes = filler.ProgressiveList(Shape);
        \\    pub const Either = ssz.CompatibleUnionType(.{ .{ 1, Numbers }, .{ 2, NumbersAlias } });
        \\    pub const Holder = filler.Container(struct { head: Uint16, body: Shapes });
        \\};
        \\
    , out.written());
}

test "filler schema should reject declarations it cannot translate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { []const u8, anyerror, usize }{
        .{
            "from ssz import Container, Uint8\n\nclass A(Container):\n    x: Uint8\n\n" ++
                "    def size(self) -> int:\n        return 1\n",
            error.UnsupportedClassBody,
            3,
        },
        .{ "class A(List[Uint8]):\n    LIMIT = 4\n    MAX = 3\n", error.UnsupportedClassBody, 1 },
        .{ "class A(Container):\n    x: List[Uint8, 4]\n", error.UnsupportedClassBody, 1 },
        .{ "class A(Container):\n    _cache: Uint8\n", error.UnsupportedClassBody, 1 },
        .{ "class A(Container): pass\n", error.UnsupportedSyntax, 1 },
        .{ "class A(List[Uint8]):\n    \"\"\"No limit.\"\"\"\n", error.InvalidClassAttributes, 1 },
        .{ "class A(Container):\n    LIMIT = 4\n    x: Uint8\n", error.InvalidClassAttributes, 1 },
        .{
            "class A(List[Uint8]):\n    LIMIT = 4\n    ELEMENT_TYPE = Uint16\n",
            error.ElementTypeMismatch,
            1,
        },
        .{
            "class A(List[Uint8]):\n    LIMIT = 4\n\nclass B(A[Uint8]):\n    \"\"\"d\"\"\"\n",
            error.UnsupportedSubclass,
            4,
        },
        .{
            "class A(List[Uint8]):\n    LIMIT = 4\n\nclass B(A):\n\tLIMIT = 8\n",
            error.UnsupportedSubclass,
            4,
        },
        .{
            "class A(ProgressiveContainer):\n    ACTIVE_FIELDS = [1, 1]\n",
            error.UnsupportedSyntax,
            1,
        },
        .{
            "class A(ProgressiveContainer):\n    ACTIVE_FIELDS = (*([0] * 256), 1)\n",
            error.ActiveFieldsTooWide,
            1,
        },
        .{
            "class A(ProgressiveContainer):\n" ++
                "    ACTIVE_FIELDS = (*([0] * 18446744073709551615), 1)\n",
            error.ActiveFieldsTooWide,
            1,
        },
        .{ "class A(ProgressiveContainer):\n    ACTIVE_FIELDS = (1, 2)\n", error.InvalidNumber, 1 },
        .{ "class A(ByteList):\n    LIMIT = 18446744073709551615 * 2\n", error.InvalidNumber, 1 },
        .{ "class A(ByteList):\n    LIMIT = 4 + 1\n", error.UnsupportedSyntax, 1 },
        .{ "from ssz import Uint8 as Byte\n", error.UnsupportedImport, 1 },
        .{ "from ssz import *\n", error.UnsupportedImport, 1 },
        .{ "x = 1\n\n\"\"\"never closed\n", error.UnterminatedString, 3 },
        .{ "x = 'a\ny = 'b'\n", error.UnterminatedString, 1 },
        .{ "x = (1,\n", error.UnbalancedBrackets, 2 },
        .{
            "class A(Container):\n    a: Uint8\n\r\n    b: Uint8\n",
            error.UnsupportedCharacter,
            3,
        },
    };
    for (cases) |case| {
        const source, const err, const line = case;
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        var diagnostic: filler_schema.Diagnostic = .{};
        try std.testing.expectError(
            err,
            filler_schema.write(arena.allocator(), &out.writer, "sample", source, &diagnostic),
        );
        try std.testing.expectEqual(line, diagnostic.line);
    }
}
