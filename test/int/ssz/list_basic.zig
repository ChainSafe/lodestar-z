const std = @import("std");
const TestCase = @import("common.zig").TypeTestCase;
const UintType = @import("ssz").UintType;
const FixedListType = @import("ssz").FixedListType;

const testCases = [_]TestCase{
    TestCase{ .id = "empty", .serializedHex = "0x", .json = "[]", .rootHex = "0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3" },
    TestCase{ .id = "4 values", .serializedHex = "0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000", .json = 
    \\["100000","200000","300000","400000","100000","200000","300000","400000"]
    , .rootHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1" },
    TestCase{
        .id = "8 values",
        .serializedHex = "0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000",
        .json =
        \\["100000","200000","300000","400000","100000","200000","300000","400000"]
        ,
        .rootHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1",
    },
};

test "valid test for ListBasicType" {
    const allocator = std.testing.allocator;

    // uint of 8 bytes = u64
    const Uint = UintType(64);
    const List = FixedListType(Uint, 128);

    const TypeTest = @import("common.zig").typeTest(List);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "FixedListType equals" {
    const allocator = std.testing.allocator;
    const List = FixedListType(UintType(8), 32);

    var a: List.Type = List.Type.empty;
    var b: List.Type = List.Type.empty;
    var c: List.Type = List.Type.empty;

    defer a.deinit(allocator);
    defer b.deinit(allocator);
    defer c.deinit(allocator);

    try a.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try b.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try c.appendSlice(allocator, &[_]u8{ 1, 2 }); 

    try std.testing.expect(List.equals(&a, &b));
    try std.testing.expect(!List.equals(&a, &c));
}
