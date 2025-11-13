const std = @import("std");
const rootToHex = @import("hex").rootToHex;
const TestCase = @import("common.zig").TypeTestCase;
const BitVectorType = @import("ssz").BitVectorType;

test "BitVectorType of 128 bits" {
    const testCases = [_]TestCase{
        TestCase{
            .id = "empty",
            .serializedHex = "0x00000000000000000000000000000001",
            .json =
            \\"0x00000000000000000000000000000001"
            ,
            .rootHex = "0x0000000000000000000000000000000100000000000000000000000000000000",
        },
        TestCase{
            .id = "some value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bc",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bc"
            ,
            .rootHex = "0xb55b8592bcac475906631481bbc746bc00000000000000000000000000000000",
        },
    };

    const allocator = std.testing.allocator;
    const BitVector = BitVectorType(128);

    const TypeTest = @import("common.zig").typeTest(BitVector);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "BitVectorType of 512 bits" {
    const testCases = [_]TestCase{
        TestCase{
            .id = "empty",
            .serializedHex = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            .json =
            \\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
            ,
            .rootHex = "0x90f4b39548df55ad6187a1d20d731ecee78c545b94afd16f42ef7592d99cd365",
        },
        TestCase{
            .id = "some value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55bb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55b",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55bb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55b"
            ,
            .rootHex = "0xf5619a9b3c6831a68fdbd1b30b69843c778b9d36ed1ff6831339ba0f723dbea0",
        },
    };

    const allocator = std.testing.allocator;
    const BitVector = BitVectorType(512);

    const TypeTest = @import("common.zig").typeTest(BitVector);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "BitVectorType equals" {
    const BitVector = BitVectorType(16);

    var a = BitVector.Type.empty;
    var b = BitVector.Type.empty;
    var c = BitVector.Type.empty;

    try a.set(0, true);
    try a.set(5, true);
    try a.set(15, true);

    try b.set(0, true);
    try b.set(5, true);
    try b.set(15, true);

    try c.set(0, true);
    try c.set(5, true);
    try c.set(14, true);

    try std.testing.expect(BitVector.equals(&a, &b));
    try std.testing.expect(!BitVector.equals(&a, &c));
}
