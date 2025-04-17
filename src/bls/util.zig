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
    FAILED_PAIRING,
    MEMORY_POOL_ERROR,
    THREAD_POOL_ERROR,
};

// BLST_ERROR max as 7
pub const BLST_FAILED_PAIRING: c_uint = 10;
pub const MEMORY_POOL_ERROR: c_uint = 11;
pub const THREAD_POOL_ERROR: c_uint = 12;

pub fn toBlstError(err: c_uint) ?BLST_ERROR {
    switch (err) {
        c.BLST_BAD_ENCODING => return BLST_ERROR.BAD_ENCODING,
        c.BLST_POINT_NOT_ON_CURVE => return BLST_ERROR.POINT_NOT_ON_CURVE,
        c.BLST_POINT_NOT_IN_GROUP => return BLST_ERROR.POINT_NOT_IN_GROUP,
        c.BLST_AGGR_TYPE_MISMATCH => return BLST_ERROR.AGGR_TYPE_MISMATCH,
        c.BLST_VERIFY_FAIL => return BLST_ERROR.VERIFY_FAIL,
        c.BLST_PK_IS_INFINITY => return BLST_ERROR.PK_IS_INFINITY,
        c.BLST_BAD_SCALAR => return BLST_ERROR.BAD_SCALAR,
        BLST_FAILED_PAIRING => return BLST_ERROR.FAILED_PAIRING,
        MEMORY_POOL_ERROR => return BLST_ERROR.MEMORY_POOL_ERROR,
        THREAD_POOL_ERROR => return BLST_ERROR.THREAD_POOL_ERROR,
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

pub fn default_blst_p1_affine() c.blst_p1_affine {
    return .{
        .x = default_blst_fp(),
        .y = default_blst_fp(),
    };
}

pub fn default_blst_p2_affline() c.blst_p2_affine {
    return .{
        .x = default_blst_fp2(),
        .y = default_blst_fp2(),
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

pub fn default_blst_fp6() c.blst_fp6 {
    return .{
        .fp2 = [_]c.blst_fp2{default_blst_fp2()} ** 3,
    };
}

pub fn default_blst_fp12() c.blst_fp12 {
    return .{
        .fp6 = [_]c.blst_fp6{default_blst_fp6()} ** 2,
    };
}

// TODO: remove this if not consumed
pub fn asU64Slice(bytes: []u8) ![]u64 {
    if ((@intFromPtr(bytes.ptr) % @alignOf(u64)) != 0) {
        return error.AlignmentError;
    }

    if (bytes.len % @sizeOf(u64) != 0) {
        return error.SizeError;
    }

    const aligned_ptr: [*]align(@alignOf(u64)) u8 = @alignCast(bytes.ptr);
    const ptr_u64: [*]u64 = @ptrCast(aligned_ptr);

    const count = bytes.len / @sizeOf(u64);

    return ptr_u64[0..count];
}

pub fn asU8Slice(u64s: []u64) []u8 {
    const aligned_ptr: [*]align(@alignOf(u8)) u64 = @alignCast(u64s.ptr);
    const ptr_u8: [*]u8 = @ptrCast(aligned_ptr);

    const count = u64s.len * @sizeOf(u64) / @sizeOf(u8);

    return ptr_u8[0..count];
}
