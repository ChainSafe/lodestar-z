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
