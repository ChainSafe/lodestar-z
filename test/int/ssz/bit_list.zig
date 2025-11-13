const std = @import("std");
const TestCase = @import("common.zig").TypeTestCase;
const BitListType = @import("ssz").BitListType;

test "BitListType" {
    const test_cases = [_]TestCase{
        TestCase{
            .id = "empty",
            .serializedHex = "0x01",
            .json =
            \\"0x01"
            ,
            .rootHex = "0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6",
        },
        TestCase{
            .id = "zero'ed 1 bytes",
            .serializedHex = "0x0010",
            .json =
            \\"0x10"
            ,
            .rootHex = "0x07eb640282e16eea87300c374c4894ad69b948de924a158d2d1843b3cf01898a",
        },
        TestCase{
            .id = "zero'ed 8 bytes",
            .serializedHex = "0x000000000000000010",
            .json =
            \\"0x000000000000000010"
            ,
            .rootHex = "0x5c597e77f879e249af95fe543cf5f4dd16b686948dc719707445a32a77ff6266",
        },
        TestCase{
            .id = "short value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bc",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bc"
            ,
            .rootHex = "0x9ab378cfbd6ec502da1f9640fd956bbef1f9fcbc10725397805c948865384e77",
        },
        TestCase{
            .id = "long value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bc",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bc"
            ,
            .rootHex = "0x4b71a7de822d00a5ff8e7e18e13712a50424cbc0e18108ab1796e591136396a0",
        },
    };

    const allocator = std.testing.allocator;
    const List = BitListType(2048);

    const TypeTest = @import("common.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "BitListType equals" {
    const allocator = std.testing.allocator;
    const BitList = BitListType(32);

    var a = try BitList.Type.fromBitLen(allocator, 8);
    var b = try BitList.Type.fromBitLen(allocator, 8);
    var c = try BitList.Type.fromBitLen(allocator, 7);

    defer a.deinit(allocator);
    defer b.deinit(allocator);
    defer c.deinit(allocator);

    try a.set(allocator, 0, true);
    try a.set(allocator, 3, true);

    try b.set(allocator, 0, true);
    try b.set(allocator, 3, true);

    try c.set(allocator, 0, true);

    try std.testing.expect(BitList.equals(&a, &b));
    try std.testing.expect(!BitList.equals(&a, &c));
}
