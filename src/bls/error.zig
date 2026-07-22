const c = @import("root.zig").c;

pub const BlstError = error{
    BadEncoding,
    PointNotOnCurve,
    PointNotInGroup,
    AggrTypeMismatch,
    VerifyFail,
    PkIsInfinity,
    BadScalar,
    MergeError,
    UnknownError,
};

pub fn errorFromInt(err: c_uint) BlstError!void {
    switch (err) {
        c.BLST_SUCCESS => return,
        c.BLST_BAD_ENCODING => return BlstError.BadEncoding,
        c.BLST_POINT_NOT_ON_CURVE => return BlstError.PointNotOnCurve,
        c.BLST_POINT_NOT_IN_GROUP => return BlstError.PointNotInGroup,
        c.BLST_AGGR_TYPE_MISMATCH => return BlstError.AggrTypeMismatch,
        c.BLST_VERIFY_FAIL => return BlstError.VerifyFail,
        c.BLST_PK_IS_INFINITY => return BlstError.PkIsInfinity,
        c.BLST_BAD_SCALAR => return BlstError.BadScalar,
        else => return BlstError.UnknownError,
    }
}

const std = @import("std");

test "convert BLST error codes" {
    try errorFromInt(c.BLST_SUCCESS);

    const test_cases = [_]struct {
        code: c_uint,
        expected: BlstError,
    }{
        .{ .code = c.BLST_BAD_ENCODING, .expected = BlstError.BadEncoding },
        .{ .code = c.BLST_POINT_NOT_ON_CURVE, .expected = BlstError.PointNotOnCurve },
        .{ .code = c.BLST_POINT_NOT_IN_GROUP, .expected = BlstError.PointNotInGroup },
        .{ .code = c.BLST_AGGR_TYPE_MISMATCH, .expected = BlstError.AggrTypeMismatch },
        .{ .code = c.BLST_VERIFY_FAIL, .expected = BlstError.VerifyFail },
        .{ .code = c.BLST_PK_IS_INFINITY, .expected = BlstError.PkIsInfinity },
        .{ .code = c.BLST_BAD_SCALAR, .expected = BlstError.BadScalar },
    };

    for (test_cases) |test_case| {
        try std.testing.expectError(test_case.expected, errorFromInt(test_case.code));
    }

    try std.testing.expectError(BlstError.UnknownError, errorFromInt(c.BLST_BAD_SCALAR + 1));
}
