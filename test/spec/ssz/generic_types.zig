const ssz = @import("ssz");

// Each namespace mirrors a fixture suite directory and its decls match the
// `typeName` field of the fixtures in it. The same name can mean a different
// type in another suite (`SampleShapeContainer`), so types are not shared
// across suites by name. Fixtures whose type is not declared here are skipped
// by write_generic_tests.zig.
//
// Not declared: `SampleNestedShape`, `SampleShapeContainer`,
// `SampleShapeProgressiveContainer` and `SampleShapeProgressiveList` of
// test_compatible_unions. They nest a compatible union inside another type,
// which needs `default_value` on the union; CompatibleUnionType deliberately
// has none.

const base = struct {
    pub const Boolean = ssz.BoolType();
    pub const Uint8 = ssz.UintType(8);
    pub const Uint16 = ssz.UintType(16);
    pub const Uint32 = ssz.UintType(32);
    pub const Uint64 = ssz.UintType(64);
    pub const Uint128 = ssz.UintType(128);
    pub const Uint256 = ssz.UintType(256);
    pub const Bytes4 = ssz.ByteVectorType(4);
    pub const Bytes32 = ssz.ByteVectorType(32);
    pub const Bytes52 = ssz.ByteVectorType(52);
    pub const Bytes64 = ssz.ByteVectorType(64);

    pub const SampleUint16List4 = ssz.FixedListType(Uint16, 4, .{});
    pub const SampleUint64ProgressiveList = ssz.FixedProgressiveListType(Uint64);
    pub const SampleSquare = ssz.FixedProgressiveContainerType(struct {
        side: Uint16,
        color: Uint8,
    }, &[_]u1{ 1, 0, 1 });
    pub const SampleCircle = ssz.FixedProgressiveContainerType(struct {
        radius: Uint16,
        color: Uint8,
    }, &[_]u1{ 0, 1, 1 });
    pub const SampleShape = ssz.CompatibleUnionType(.{
        .{ 1, SampleSquare },
        .{ 2, SampleCircle },
        .{ 127, SampleSquare },
    });
    pub const SampleSquareProgressiveList = ssz.FixedProgressiveListType(SampleSquare);
    pub const SampleCircleProgressiveList = ssz.FixedProgressiveListType(SampleCircle);
};

pub const test_basic_types = struct {
    pub const Boolean = base.Boolean;
    pub const Uint8 = base.Uint8;
    pub const Uint16 = base.Uint16;
    pub const Uint32 = base.Uint32;
    pub const Uint64 = base.Uint64;
    pub const Uint128 = base.Uint128;
    pub const Uint256 = base.Uint256;
    pub const Bytes4 = base.Bytes4;
    pub const Bytes32 = base.Bytes32;
    pub const Bytes52 = base.Bytes52;
    pub const Bytes64 = base.Bytes64;
    pub const ByteList512KiB = ssz.ByteListType(512 * 1024);
    pub const SampleBitVector8 = ssz.BitVectorType(8);
    pub const SampleBitVector64 = ssz.BitVectorType(64);
    pub const SampleBitList16 = ssz.BitListType(16);
    pub const SampleUint16Vector3 = ssz.FixedVectorType(base.Uint16, 3, .{});
    pub const SampleUint64Vector4 = ssz.FixedVectorType(base.Uint64, 4, .{});
    pub const SampleUint32List16 = ssz.FixedListType(base.Uint32, 16, .{});
    pub const SampleBytes32List8 = ssz.FixedListType(base.Bytes32, 8, .{});
};

pub const test_compatible_unions = struct {
    pub const SampleShape = base.SampleShape;
    pub const SampleNumbers = ssz.CompatibleUnionType(.{
        .{ 1, base.SampleUint16List4 },
        .{ 2, base.SampleUint16List4 },
    });
    pub const SampleEmptyProne = ssz.CompatibleUnionType(.{
        .{ 1, base.SampleSquareProgressiveList },
        .{ 2, base.SampleCircleProgressiveList },
    });
};

pub const test_decode_failure_smoke = struct {
    pub const SmokeBitList8 = ssz.BitListType(8);
};

pub const test_merkleization_boundaries = struct {
    pub const BoundaryBitVector1 = ssz.BitVectorType(1);
    pub const BoundaryBitVector7 = ssz.BitVectorType(7);
    pub const BoundaryBitVector9 = ssz.BitVectorType(9);
    pub const BoundaryBitVector255 = ssz.BitVectorType(255);
    pub const BoundaryBitVector256 = ssz.BitVectorType(256);
    pub const BoundaryBitVector257 = ssz.BitVectorType(257);
    pub const BoundaryBitList256 = ssz.BitListType(256);
    pub const BoundaryUint64List32 = ssz.FixedListType(base.Uint64, 32, .{});
};

pub const test_progressive_containers = struct {
    pub const SampleSquare = base.SampleSquare;
    pub const SampleCircle = base.SampleCircle;
    pub const SampleOneField = ssz.FixedProgressiveContainerType(struct {
        a: base.Uint16,
    }, &[_]u1{1});
    pub const SampleLeadingGaps = ssz.FixedProgressiveContainerType(struct {
        c: base.Uint32,
    }, &[_]u1{ 0, 0, 1 });
    pub const SampleMultipleGaps = ssz.FixedProgressiveContainerType(struct {
        a: base.Uint8,
        b: base.Uint16,
        c: base.Uint32,
    }, &[_]u1{ 1, 0, 0, 1, 0, 1 });
    pub const SampleWidestLayout = ssz.FixedProgressiveContainerType(struct {
        tail: base.Uint8,
    }, &([_]u1{0} ** 255 ++ [_]u1{1}));
    pub const SampleLevelBoundary = ssz.FixedProgressiveContainerType(struct {
        first: base.Uint16,
        last: base.Uint8,
    }, &([_]u1{1} ++ [_]u1{0} ** 20 ++ [_]u1{1}));
    pub const SampleBoundedListField = ssz.VariableProgressiveContainerType(struct {
        head: base.Uint64,
        body: base.SampleUint16List4,
    }, &[_]u1{ 1, 0, 1 });
    pub const SampleProgressiveFields = ssz.VariableProgressiveContainerType(struct {
        head: base.Uint64,
        numbers: base.SampleUint64ProgressiveList,
        flags: ssz.ProgressiveBitListType(),
    }, &[_]u1{ 1, 1, 1 });
    const SampleInnerShape = ssz.FixedProgressiveContainerType(struct {
        x: base.Uint16,
        y: base.Uint8,
    }, &[_]u1{ 1, 0, 1 });
    pub const SampleOuterShape = ssz.FixedProgressiveContainerType(struct {
        head: base.Uint8,
        inner: SampleInnerShape,
    }, &[_]u1{ 1, 0, 1 });
    pub const SampleSquareProgressiveList = base.SampleSquareProgressiveList;
    pub const SampleShapeContainer = ssz.FixedContainerType(struct {
        tag: base.Uint8,
        shape: base.SampleSquare,
    });
};

pub const test_progressive_types = struct {
    pub const SampleUint64ProgressiveList = base.SampleUint64ProgressiveList;
    pub const SampleBytes32ProgressiveList = ssz.FixedProgressiveListType(base.Bytes32);
    pub const SampleNestedProgressiveList = ssz.VariableProgressiveListType(ssz.FixedProgressiveListType(base.Uint16));
    pub const ProgressiveBitList = ssz.ProgressiveBitListType();
    pub const SampleContainerWithProgressiveList = ssz.VariableContainerType(struct {
        a: base.Uint16,
        b: base.SampleUint64ProgressiveList,
        c: base.Uint8,
    });
};
