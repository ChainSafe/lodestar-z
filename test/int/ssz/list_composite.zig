const std = @import("std");
const TestCase = @import("common.zig").TypeTestCase;
const UintType = @import("ssz").UintType;
const ByteVectorType = @import("ssz").ByteVectorType;
const FixedListType = @import("ssz").FixedListType;
const VariableListType = @import("ssz").VariableListType;
const FixedContainerType = @import("ssz").FixedContainerType;

test "ListCompositeType of Root" {
    const test_cases = [_]TestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L23
        TestCase{
            .id = "2 roots",
            .serializedHex = "0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            .json =
            \\["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]
            ,
            .rootHex = "0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8",
        },
    };

    const allocator = std.testing.allocator;
    const ByteVector = ByteVectorType(32);
    const List = FixedListType(ByteVector, 128);

    const TypeTest = @import("common.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "ListCompositeType of Container" {
    const test_cases = [_]TestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L46
        TestCase{
            .id = "2 values",
            .serializedHex = "0x0000000000000000000000000000000040e2010000000000f1fb090000000000",
            .json =
            \\[{"a":"0","b":"0"},{"a":"123456","b":"654321"}]
            ,
            .rootHex = "0x8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210",
        },
    };

    const allocator = std.testing.allocator;
    const Uint = UintType(64);
    const Container = FixedContainerType(struct {
        a: Uint,
        b: Uint,
    });
    const List = FixedListType(Container, 128);

    const TypeTest = @import("common.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "VariableListType of FixedList" {
    // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L59
    const test_cases = [_]TestCase{
        TestCase{
            .id = "empty",
            .serializedHex = "0x",
            .json =
            \\[]
            ,
            .rootHex = "0x7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5",
        },
        TestCase{
            .id = "2 full values",
            .serializedHex = "0x080000000c0000000100020003000400",
            .json =
            \\[["1","2"],["3","4"]]
            ,
            .rootHex = "0x58140d48f9c24545c1e3a50f1ebcca85fd40433c9859c0ac34342fc8e0a800b8",
        },
        TestCase{
            .id = "2 empty values",
            .serializedHex = "0x0800000008000000",
            .json =
            \\[[],[]]
            ,
            .rootHex = "0xe839a22714bda05923b611d07be93b4d707027d29fd9eef7aa864ed587e462ec",
        },
    };

    const allocator = std.testing.allocator;
    const FixedList = FixedListType(UintType(16), 2);
    const List = VariableListType(FixedList, 2);

    const TypeTest = @import("common.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}
