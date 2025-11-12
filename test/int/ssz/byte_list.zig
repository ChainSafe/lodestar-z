const std = @import("std");
const TestCase = @import("common.zig").TypeTestCase;
const ByteListType = @import("ssz").ByteListType;

const test_cases = [_]TestCase{
    .{ .id = "empty", .serializedHex = "0x", .json = 
    \\"0x"
    , .rootHex = "0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6" },
    .{ .id = "4 bytes zero", .serializedHex = "0x00000000", .json = 
    \\"0x00000000"
    , .rootHex = "0xa39babe565305429771fc596a639d6e05b2d0304297986cdd2ef388c1936885e" },
    .{
        .id = "4 bytes some value",
        .serializedHex = "0x0cb94737",
        .json =
        \\"0x0cb94737"
        ,
        .rootHex = "0x2e14da116ecbec4c8d693656fb5b69bb0ea9e84ecdd15aba7be1c008633f2885",
    },
    .{
        .id = "32 bytes zero",
        .serializedHex = "0x0000000000000000000000000000000000000000000000000000000000000000",
        .json =
        \\"0x0000000000000000000000000000000000000000000000000000000000000000"
        ,
        .rootHex = "0xbae146b221eca758702e29b45ee7f7dc3eea17d119dd0a3094481e3f94706c96",
    },
    .{
        .id = "32 bytes some value",
        .serializedHex = "0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8",
        .json =
        \\"0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8"
        ,
        .rootHex = "0x50425dbd7a34b50b20916e965ce5c060abe6516ac71bb00a4afebe5d5c4568b8",
    },
    .{
        .id = "96 bytes zero",
        .serializedHex = "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        .json =
        \\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ,
        .rootHex = "0xcd09661f4b2109fb26decd60c004444ea5308a304203412280bd2af3ace306bf",
    },
    .{
        .id = "96 bytes some value",
        .serializedHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1",
        .json =
        \\"0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1"
        ,
        .rootHex = "0x5d3ae4b886c241ffe8dc7ae1b5f0e2fb9b682e1eac2ddea292ef02cc179e6903",
    },
};

test "ByteListType" {
    const allocator = std.testing.allocator;
    const List = ByteListType(256);

    const TypeTest = @import("common.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}
