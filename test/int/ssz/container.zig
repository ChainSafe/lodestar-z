const std = @import("std");
const TestCase = @import("common.zig").TypeTestCase;
const UintType = @import("ssz").UintType;
const BoolType = @import("ssz").BoolType;
const ByteVectorType = @import("ssz").ByteVectorType;
const FixedContainerType = @import("ssz").FixedContainerType;
const VariableContainerType = @import("ssz").VariableContainerType;
const FixedListType = @import("ssz").FixedListType;

test "ContainerType" {
    const test_cases = [_]TestCase{
        TestCase{
            .id = "empty",
            .serializedHex = "0x00000000000000000000000000000000",
            .json =
            \\{"a":"0","b":"0"}
            ,
            .rootHex = "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        },
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/container/valid.test.ts#L22
        TestCase{
            .id = "some value",
            .serializedHex = "0x40e2010000000000f1fb090000000000",
            .json =
            \\{"a":"123456","b":"654321"}
            ,
            .rootHex = "0x53b38aff7bf2dd1a49903d07a33509b980c6acc9f2235a45aac342b0a9528c22",
        },
    };

    const allocator = std.testing.allocator;

    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    const TypeTest = @import("common.zig").typeTest(Container);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "ContainerType with FixedListType(uint64, 128) and uint64" {
    const allocator = std.testing.allocator;

    const Container = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128),
        b: UintType(64),
    });

    const TypeTest = @import("common.zig").typeTest(Container);

    const test_cases = [_]TestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/container/valid.test.ts#L51
        TestCase{
            .id = "zero",
            .serializedHex = "0x0c0000000000000000000000",
            .json =
            \\{"a":[],"b":"0"}
            ,
            .rootHex = "0xdc3619cbbc5ef0e0a3b38e3ca5d31c2b16868eacb6e4bcf8b4510963354315f5",
        },
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/container/valid.test.ts#L57
        TestCase{
            .id = "some value",
            .serializedHex = "0x0c000000f1fb09000000000040e2010000000000f1fb09000000000040e2010000000000f1fb09000000000040e2010000000000",
            .json =
            \\{"a":["123456","654321","123456","654321","123456"],"b":"654321"}
            ,
            .rootHex = "0x5ff1b92b2fa55eea1a14b26547035b2f5437814b3436172205fa7d6af4091748",
        },
    };

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "FixedContainerType equals" {
    const Container = FixedContainerType(struct {
        slot: UintType(64),
        root: ByteVectorType(32),
        active: BoolType(),
    });

    var a: Container.Type = undefined;
    var b: Container.Type = undefined;
    var c: Container.Type = undefined;

    a.slot = 42;
    a.root = [_]u8{1} ** 32;
    a.active = true;

    b.slot = 42;
    b.root = [_]u8{1} ** 32;
    b.active = true;

    c.slot = 43; // Different slot
    c.root = [_]u8{1} ** 32;
    c.active = true;

    try std.testing.expect(Container.equals(&a, &b));
    try std.testing.expect(!Container.equals(&a, &c));
}

test "VariableContainerType equals" {
    const allocator = std.testing.allocator;
    const Container = VariableContainerType(struct {
        list1: FixedListType(UintType(8), 32),
        list2: FixedListType(UintType(8), 32),
        value: UintType(64),
    });

    var a: Container.Type = undefined;
    var b: Container.Type = undefined;
    var c: Container.Type = undefined;

    a.list1 = FixedListType(UintType(8), 32).Type.empty;
    a.list2 = FixedListType(UintType(8), 32).Type.empty;
    a.value = 100;

    b.list1 = FixedListType(UintType(8), 32).Type.empty;
    b.list2 = FixedListType(UintType(8), 32).Type.empty;
    b.value = 100;

    c.list1 = FixedListType(UintType(8), 32).Type.empty;
    c.list2 = FixedListType(UintType(8), 32).Type.empty;
    c.value = 101; // Different value

    defer a.list1.deinit(allocator);
    defer a.list2.deinit(allocator);
    defer b.list1.deinit(allocator);
    defer b.list2.deinit(allocator);
    defer c.list1.deinit(allocator);
    defer c.list2.deinit(allocator);

    try a.list1.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try a.list2.appendSlice(allocator, &[_]u8{ 4, 5, 6 });

    try b.list1.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try b.list2.appendSlice(allocator, &[_]u8{ 4, 5, 6 });

    try c.list1.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try c.list2.appendSlice(allocator, &[_]u8{ 4, 5, 6 });

    try std.testing.expect(Container.equals(&a, &b));
    try std.testing.expect(!Container.equals(&a, &c));
}
