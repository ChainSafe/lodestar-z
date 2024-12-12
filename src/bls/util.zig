const c = @cImport({
    @cInclude("blst.h");
});

pub const BLST_ERROR = error{
    BAD_ENCODING,
    POINT_NOT_ON_CURVE,
    POINT_NOT_IN_GROUP,
    AGGR_TYPE_MISMATCH,
    VERIFY_FAIL,
    PK_IS_INFINITY,
    BAD_SCALAR,
};

pub fn toBlstError(err: c_uint) ?BLST_ERROR {
    switch (err) {
        c.BLST_BAD_ENCODING => return BLST_ERROR.BAD_ENCODING,
        c.BLST_POINT_NOT_ON_CURVE => return BLST_ERROR.POINT_NOT_ON_CURVE,
        c.BLST_POINT_NOT_IN_GROUP => return BLST_ERROR.POINT_NOT_IN_GROUP,
        c.BLST_AGGR_TYPE_MISMATCH => return BLST_ERROR.AGGR_TYPE_MISMATCH,
        c.BLST_VERIFY_FAIL => return BLST_ERROR.VERIFY_FAIL,
        c.BLST_PK_IS_INFINITY => return BLST_ERROR.PK_IS_INFINITY,
        c.BLST_BAD_SCALAR => return BLST_ERROR.BAD_SCALAR,
        else => return null,
    }
}

pub fn default_blst_scalar() c.blst_scalar {
    return c.blst_scalar{
        .b = [_]u8{0} ** 32,
    };
}

pub fn default_blst_p1_affline() c.blst_p1_affine {
    return .{
        .x = default_blst_fp(),
        .y = default_blst_fp(),
    };
}

pub fn default_blst_p1() c.blst_p1 {
    return .{
        .x = default_blst_fp(),
        .y = default_blst_fp(),
        .z = default_blst_fp(),
    };
}

pub fn default_blst_fp() c.blst_fp {
    return .{
        .l = [_]u64{0} ** 6,
    };
}

pub fn default_blst_p2() c.blst_p2 {
    return .{
        .x = default_blst_fp2(),
        .y = default_blst_fp2(),
        .z = default_blst_fp2(),
    };
}

pub fn default_blst_fp2() c.blst_fp2 {
    return .{
        .fp = [_]c.blst_fp{ default_blst_fp(), default_blst_fp() },
    };
}

pub fn default_blst_p2_affine() c.blst_p2_affine {
    return .{
        .x = default_blst_fp2(),
        .y = default_blst_fp2(),
    };
}
