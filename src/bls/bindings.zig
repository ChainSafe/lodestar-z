/// See blst/bindings/rust/src/bindings.rs in blst repo for reference.
const c = @cImport({
    @cInclude("blst.h");
});

/// Bindings for blst.h
pub const byte = u8;
pub const limb_t = u64;

pub const blst_scalar = struct {
    b: [256 / 8]byte,
};

pub const blst_fr = struct {
    l: [256 / 8 / @sizeOf(limb_t)]limb_t,
};

pub const blst_fp = struct {
    l: [384 / 8 / @sizeOf(limb_t)]limb_t,
};

// /* 0 is "real" part, 1 is "imaginary" */

pub const blst_fp2 = struct {
    fp: [2]blst_fp,
};

pub const blst_fp6 = struct {
    fp2: [3]blst_fp2,
};

pub const blst_fp12 = struct {
    fp6: [2]blst_fp6,
};

pub const IncorrectLen = error{IncorrectLen};

pub fn blst_scalar_from_uint32(out: *blst_scalar, a: []const u32) IncorrectLen!void {
    if (a.len != 8) {
        return error.IncorrectLen;
    }
    c.blst_scalar_from_uint32(out, a);
}

pub fn blst_uint32_from_scalar(out: []u32, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 8) {}
    c.blst_uint32_from_scalar(out, a);
}

pub fn blst_scalar_from_uint64(out: *blst_scalar, a: []const u64) IncorrectLen!void {
    if (a.len != 4) {
        return error.IncorrectLen;
    }
    c.blst_scalar_from_uint64(out, a);
}

pub fn blst_uint64_from_scalar(out: []u64, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 4) {
        return error.IncorrectLen;
    }
    c.blst_uint64_from_scalar(out, a);
}

pub fn blst_bendian_from_scalar(out: []byte, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_bendian_from_scalar(out, a);
}

pub fn blst_scalar_from_lendian(out: *blst_scalar, a: []const byte) IncorrectLen!void {
    if (a.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_scalar_from_lendian(out, a);
}

pub fn blst_lendian_from_scalar(out: []byte, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_lendian_from_scalar(out, a);
}

pub fn blst_scalar_fr_check(a: *const blst_scalar) bool {
    return c.blst_scalar_fr_check(a);
}

pub fn blst_sk_check(a: *const blst_scalar) bool {
    return c.blst_sk_check(a);
}

pub fn blst_sk_add_n_check(out: *blst_scalar, a: *const blst_scalar, b: *const blst_scalar) bool {
    return c.blst_sk_add_n_check(out, a, b);
}

pub fn blst_sk_sub_n_check(out: *blst_scalar, a: *const blst_scalar, b: *const blst_scalar) bool {
    return c.blst_sk_sub_n_check(out, a, b);
}

pub fn blst_sk_mul_n_check(out: *blst_scalar, a: *const blst_scalar, b: *const blst_scalar) bool {
    return c.blst_sk_mul_n_check(out, a, b);
}

pub fn blst_sk_inverse(out: *blst_scalar, a: *const blst_scalar) void {
    c.blst_sk_inverse(out, a);
}

pub fn blst_scalar_from_le_bytes(out: *blst_scalar, in: *const byte, len: usize) bool {
    return c.blst_scalar_from_le_bytes(out, in, len);
}

pub fn blst_scalar_from_be_bytes(out: *blst_scalar, in: *const byte, len: usize) bool {
    return c.blst_scalar_from_be_bytes(out, in, len);
}

/// BLS12-381-specific Fr operations.
pub fn blst_fr_add(ret: *blst_fr, a: *const blst_fr, b: *const blst_fr) void {
    c.blst_fr_add(ret, a, b);
}

pub fn blst_fr_sub(ret: *blst_fr, a: *const blst_fr, b: *const blst_fr) void {
    c.blst_fr_sub(ret, a, b);
}

pub fn blst_fr_mul_by_3(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_mul_by_3(ret, a);
}

pub fn blst_fr_lshift(ret: *blst_fr, a: *const blst_fr, count: usize) void {
    c.blst_fr_lshift(ret, a, count);
}

pub fn blst_fr_rshift(ret: *blst_fr, a: *const blst_fr, count: usize) void {
    c.blst_fr_rshift(ret, a, count);
}

pub fn blst_fr_mul(ret: *blst_fr, a: *const blst_fr, b: *const blst_fr) void {
    c.blst_fr_mul(ret, a, b);
}

pub fn blst_fr_sqr(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_sqr(ret, a);
}

pub fn blst_fr_cneg(ret: *blst_fr, a: *const blst_fr, flag: bool) void {
    c.blst_fr_cneg(ret, a, flag);
}

pub fn blst_fr_eucl_inverse(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_eucl_inverse(ret, a);
}

pub fn blst_fr_inverse(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_inverse(ret, a);
}

pub fn blst_fr_from_uint64(ret: *blst_fr, a: []const u64) IncorrectLen!void {
    if (a.len != 4) {
        return error.IncorrectLen;
    }

    c.blst_fr_from_uint64(ret, a);
}

pub fn blst_uint64_from_fr(ret: []u64, a: *const blst_fr) IncorrectLen!void {
    if (ret.len != 4) {
        return error.IncorrectLen;
    }

    c.blst_uint64_from_fr(ret, a);
}

pub fn blst_fr_from_scalar(ret: *blst_fr, a: *const blst_scalar) void {
    c.blst_fr_from_scalar(ret, a);
}

pub fn blst_scalar_from_fr(ret: *blst_scalar, a: *const blst_fr) void {
    c.blst_scalar_from_fr(ret, a);
}

/// BLS12-381-specific Fp operations.
pub fn blst_fp_add(ret: *blst_fp, a: *const blst_fp, b: *const blst_fp) void {
    c.blst_fp_add(ret, a, b);
}

pub fn blst_fp_sub(ret: *blst_fp, a: *const blst_fp, b: *const blst_fp) void {
    c.blst_fp_sub(ret, a, b);
}

pub fn blst_fp_mul_by_3(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_mul_by_3(ret, a);
}

pub fn blst_fp_mul_by_8(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_mul_by_8(ret, a);
}

pub fn blst_fp_lshift(ret: *blst_fp, a: *const blst_fp, count: usize) void {
    c.blst_fp_lshift(ret, a, count);
}

pub fn blst_fp_mul(ret: *blst_fp, a: *const blst_fp, b: *const blst_fp) void {
    c.blst_fp_mul(ret, a, b);
}

pub fn blst_fp_sqr(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_sqr(ret, a);
}

pub fn blst_fp_cneg(ret: *blst_fp, a: *const blst_fp, flag: bool) void {
    c.blst_fp_cneg(ret, a, flag);
}

pub fn blst_fp_eucl_inverse(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_eucl_inverse(ret, a);
}

pub fn blst_fp_inverse(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_inverse(ret, a);
}

pub fn blst_fp_sqrt(ret: *blst_fp, a: *const blst_fp) bool {
    return c.blst_fp_sqrt(ret, a);
}

pub fn blst_fp_from_uint32(ret: *blst_fp, a: []const u32) IncorrectLen!void {
    if (a.len != 12) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_uint32(ret, a);
}

pub fn blst_uint32_from_fp(ret: []u32, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 12) {
        return error.IncorrectLen;
    }

    c.blst_uint32_from_fp(ret, a);
}

pub fn blst_fp_from_uint64(ret: *blst_fp, a: []const u64) IncorrectLen!void {
    if (a.len != 6) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_uint64(ret, a);
}

pub fn blst_uint64_from_fp(ret: []u64, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 6) {
        return error.IncorrectLen;
    }

    c.blst_uint64_from_fp(ret, a);
}

pub fn blst_fp_from_bendian(ret: *blst_fp, a: []const byte) IncorrectLen!void {
    if (a.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_bendian(ret, a);
}

pub fn blst_bendian_from_fp(ret: []byte, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_bendian_from_fp(ret, a);
}

pub fn blst_fp_from_lendian(ret: *blst_fp, a: []const byte) IncorrectLen!void {
    if (a.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_lendian(ret, a);
}

pub fn blst_lendian_from_fp(ret: []byte, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_lendian_from_fp(ret, a);
}

/// BLS12-381-specific Fp2 operations.
pub fn blst_fp2_add(ret: *blst_fp2, a: *const blst_fp2, b: *const blst_fp2) void {
    c.blst_fp2_add(ret, a, b);
}

pub fn blst_fp2_sub(ret: *blst_fp2, a: *const blst_fp2, b: *const blst_fp2) void {
    c.blst_fp2_sub(ret, a, b);
}

pub fn blst_fp2_mul_by_3(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_mul_by_3(ret, a);
}

pub fn blst_fp2_mul_by_8(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_mul_by_8(ret, a);
}

pub fn blst_fp2_lshift(ret: *blst_fp2, a: *const blst_fp2, count: usize) void {
    c.blst_fp2_lshift(ret, a, count);
}

pub fn blst_fp2_mul(ret: *blst_fp2, a: *const blst_fp2, b: *const blst_fp2) void {
    c.blst_fp2_mul(ret, a, b);
}

pub fn blst_fp2_sqr(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_sqr(ret, a);
}

pub fn blst_fp2_cneg(ret: *blst_fp2, a: *const blst_fp2, flag: bool) void {
    c.blst_fp2_cneg(ret, a, flag);
}

pub fn blst_fp2_eucl_inverse(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_eucl_inverse(ret, a);
}

pub fn blst_fp2_inverse(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_inverse(ret, a);
}

pub fn blst_fp2_sqrt(ret: *blst_fp2, a: *const blst_fp2) bool {
    return c.blst_fp2_sqrt(ret, a);
}

/// BLS12-381-specific Fp12 operations.
pub fn blst_fp12_sqr(ret: *blst_fp12, a: *const blst_fp12) void {
    c.blst_fp12_sqr(ret, a);
}

pub fn blst_fp12_cyclotomic_sqr(ret: *blst_fp12, a: *const blst_fp12) void {
    c.blst_fp12_cyclotomic_sqr(ret, a);
}

pub fn blst_fp12_mul(ret: *blst_fp12, a: *const blst_fp12, b: *const blst_fp12) void {
    c.blst_fp12_mul(ret, a, b);
}

pub fn blst_fp12_mul_by_xy00z0(ret: *blst_fp12, a: *const blst_fp12, xy00z0: *blst_fp6) void {
    c.blst_fp12_mul_by_xy00z0(ret, a, xy00z0);
}

pub fn blst_fp12_conjugate(a: *const blst_fp12) void {
    c.blst_fp12_conjugate(a);
}

pub fn blst_fp12_inverse(ret: *blst_fp12, a: *const blst_fp12) void {
    c.blst_fp12_inverse(ret, a);
}

// caveat lector! |n| has to be non-zero and not more than 3!
pub fn blst_fp12_frobenius_map(ret: *blst_fp12, a: *const blst_fp12, n: usize) void {
    c.blst_fp12_frobenius_map(ret, a, n);
}

pub fn blst_fp12_is_equal(a: *const blst_fp12, b: *const blst_fp12) bool {
    return c.blst_fp12_is_equal(a, b);
}

pub fn blst_fp12_is_one(a: *const blst_fp12) bool {
    return c.blst_fp12_is_one(a);
}

pub fn blst_fp12_in_group(a: *const blst_fp12) bool {
    return c.blst_fp12_in_group(a);
}

pub fn blst_fp12_one(ret: *blst_fp12) void {
    c.blst_fp12_one(ret);
}

/// BLS12-381-specific point operations.
const blst_p1 = struct {
    x: blst_fp,
    y: blst_fp,
    z: blst_fp,
};

const blst_p1_affine = struct {
    x: blst_fp,
    y: blst_fp,
};

pub fn blst_p1_add(out: *blst_p1, a: *const blst_p1, b: *const blst_p1) void {
    c.blst_p1_add(out, a, b);
}

pub fn blst_p1_add_or_double(out: *blst_p1, a: *const blst_p1, b: *const blst_p1) void {
    c.blst_p1_add_or_double(out, a, b);
}

pub fn blst_p1_add_affine(out: *blst_p1, a: *const blst_p1, b: *const blst_p1_affine) void {
    c.blst_p1_add_affine(out, a, b);
}

pub fn blst_p1_add_or_double_affine(out: *blst_p1, a: *const blst_p1, b: *const blst_p1_affine) void {
    c.blst_p1_add_or_double_affine(out, a, b);
}

pub fn blst_p1_double(out: *blst_p1, a: *const blst_p1) void {
    c.blst_p1_double(out, a);
}

pub fn blst_p1_mult(out: *blst_p1, a: *const blst_p1, scalar: *const byte, nbits: usize) void {
    c.blst_p1_mult(out, a, scalar, nbits);
}

pub fn blst_p1_cneg(out: *blst_p1, cbit: bool) void {
    c.blst_p1_cneg(out, cbit);
}

pub fn blst_p1_to_affine(out: *blst_p1_affine, a: *const blst_p1) void {
    c.blst_p1_to_affine(out, a);
}

pub fn blst_p1_from_affine(out: *blst_p1, a: *const blst_p1_affine) void {
    c.blst_p1_from_affine(out, a);
}

pub fn blst_p1_on_curve(a: *const blst_p1) bool {
    return c.blst_p1_on_curve(a);
}

pub fn blst_p1_in_g1(p: *const blst_p1) bool {
    return c.blst_p1_in_g1(p);
}

pub fn blst_p1_is_equal(a: *const blst_p1, b: *const blst_p1) bool {
    return c.blst_p1_is_equal(a, b);
}

pub fn blst_p1_is_inf(a: *const blst_p1) bool {
    return c.blst_p1_is_inf(a);
}

pub fn blst_p1_generator() *blst_p1 {
    return c.blst_p1_generator();
}

pub fn blst_p1_affine_on_curve(p: *const blst_p1_affine) bool {
    return c.blst_p1_affine_on_curve(p);
}

pub fn blst_p1_affine_in_g1(p: *const blst_p1_affine) bool {
    return c.blst_p1_affine_in_g1(p);
}

pub fn blst_p1_affine_is_equal(a: *const blst_p1_affine, b: *const blst_p1_affine) bool {
    return c.blst_p1_affine_is_equal(a, b);
}

pub fn blst_p1_affine_is_inf(a: *const blst_p1_affine) bool {
    return c.blst_p1_affine_is_inf(a);
}

pub fn blst_p1_affine_generator() *blst_p1_affine {
    return c.blst_p1_affine_generator();
}

const blst_p2 = struct {
    x: blst_fp2,
    y: blst_fp2,
    z: blst_fp2,
};

const blst_p2_affine = struct {
    x: blst_fp2,
    y: blst_fp2,
};

pub fn blst_p2_add(out: *blst_p2, a: *const blst_p2, b: *const blst_p2) void {
    c.blst_p2_add(out, a, b);
}

pub fn blst_p2_add_or_double(out: *blst_p2, a: *const blst_p2, b: *const blst_p2) void {
    c.blst_p2_add_or_double(out, a, b);
}

pub fn blst_p2_add_affine(out: *blst_p2, a: *const blst_p2, b: *const blst_p2_affine) void {
    c.blst_p2_add_affine(out, a, b);
}

pub fn blst_p2_add_or_double_affine(out: *blst_p2, a: *const blst_p2, b: *const blst_p2_affine) void {
    c.blst_p2_add_or_double_affine(out, a, b);
}

pub fn blst_p2_double(out: *blst_p2, a: *const blst_p2) void {
    c.blst_p2_double(out, a);
}

pub fn blst_p2_mult(out: *blst_p2, p: *const blst_p2, scalar: *const byte, nbits: usize) void {
    c.blst_p2_mult(out, p, scalar, nbits);
}

pub fn blst_p2_cneg(p: *blst_p2, cbit: bool) void {
    c.blst_p2_cneg(p, cbit);
}

pub fn blst_p2_to_affine(out: *blst_p2_affine, in: *const blst_p2) void {
    c.blst_p2_to_affine(out, in);
}

pub fn blst_p2_from_affine(out: *blst_p2, in: *const blst_p2_affine) void {
    c.blst_p2_from_affine(out, in);
}

pub fn blst_p2_on_curve(p: *const blst_p2) bool {
    return c.blst_p2_on_curve(p);
}

pub fn blst_p2_in_g2(p: *const blst_p2) bool {
    return c.blst_p2_in_g2(p);
}

pub fn blst_p2_is_equal(a: *const blst_p2, b: *const blst_p2) bool {
    return c.blst_p2_is_equal(a, b);
}

pub fn blst_p2_is_inf(a: *const blst_p2) bool {
    return c.blst_p2_is_inf(a);
}

pub fn blst_p2_generator() *blst_p2 {
    return c.blst_p2_generator();
}

pub fn blst_p2_affine_on_curve(p: *const blst_p2_affine) bool {
    return c.blst_p2_affine_on_curve(p);
}

pub fn blst_p2_affine_in_g2(p: *const blst_p2_affine) bool {
    return c.blst_p2_affine_in_g2(p);
}

pub fn blst_p2_affine_is_equal(a: *const blst_p2_affine, b: *const blst_p2_affine) bool {
    return c.blst_p2_affine_is_equal(a, b);
}

pub fn blst_p2_affine_is_inf(a: *const blst_p2_affine) bool {
    return c.blst_p2_affine_is_inf(a);
}

pub fn blst_p2_affine_generator() *blst_p2_affine {
    return c.blst_p2_affine_generator();
}

/// Multi-scalar multiplications and other multi-point operations.
pub fn blst_p1s_to_affine(dst: []blst_p1_affine, points: []const blst_p1, npoints: usize) void {
    c.blst_p1s_to_affine(dst, points, npoints);
}

pub fn blst_p1s_add(ret: *blst_p1, points: []const blst_p1_affine, npoints: usize) void {
    c.blst_p1s_add(ret, points, npoints);
}

pub fn blst_p1s_mult_wbits_precompute_sizeof(wbits: usize, npoints: usize) usize {
    return c.blst_p1s_mult_wbits_precompute_sizeof(wbits, npoints);
}

pub fn blst_p1s_mult_wbits_precompute(table: []blst_p1_affine, wbits: usize, points: []*const blst_p1_affine, npoints: usize) void {
    c.blst_p1s_mult_wbits_precompute(table, wbits, points, npoints);
}

pub fn blst_p1s_mult_wbits_scratch_sizeof(npoints: usize) usize {
    return c.blst_p1s_mult_wbits_scratch_sizeof(npoints);
}

pub fn blst_p1s_mult_wbits(ret: *blst_p1, table: []const blst_p1_affine, wbits: usize, npoints: usize, scalars: []*const byte, nbits: usize, scratch: *limb_t) void {
    c.blst_p1s_mult_wbits(ret, table, wbits, npoints, scalars, nbits, scratch);
}

pub fn blst_p1s_mult_pippenger_scratch_sizeof(npoints: usize) usize {
    return c.blst_p1s_mult_pippenger_scratch_sizeof(npoints);
}

pub fn blst_p1s_mult_pippenger(ret: *blst_p1, points: []*const blst_p1_affine, npoints: usize, scalars: []*const byte, nbits: usize, scratch: *limb_t) void {
    c.blst_p1s_mult_pippenger(ret, points, npoints, scalars, nbits, scratch);
}

pub fn blst_p1s_tile_pippenger(ret: *blst_p1, points: []*const blst_p1_affine, npoints: usize, scalars: []*const byte, nbits: usize, scratch: *limb_t, bit0: usize, window: usize) void {
    c.blst_p1s_tile_pippenger(ret, points, npoints, scalars, nbits, scratch, bit0, window);
}

pub fn blst_p2s_to_affine(dst: []blst_p2_affine, points: []*const blst_p2, npoints: usize) void {
    c.blst_p2s_to_affine(dst, points, npoints);
}

pub fn blst_p2s_add(ret: *blst_p2, points: []*const blst_p2_affine, npoints: usize) void {
    c.blst_p2s_add(ret, points, npoints);
}

pub fn blst_p2s_mult_wbits_precompute_sizeof(wbits: usize, npoints: usize) usize {
    return c.blst_p2s_mult_wbits_precompute_sizeof(wbits, npoints);
}

pub fn blst_p2s_mult_wbits_precompute(table: []blst_p2_affine, wbits: usize, points: []*const blst_p2_affine, npoints: usize) void {
    c.blst_p2s_mult_wbits_precompute(table, wbits, points, npoints);
}

pub fn blst_p2s_mult_wbits_scratch_sizeof(npoints: usize) usize {
    return c.blst_p2s_mult_wbits_scratch_sizeof(npoints);
}

pub fn blst_p2s_mult_wbits(ret: *blst_p2, table: []const blst_p2_affine, wbits: usize, npoints: usize, scalars: []*const byte, nbits: usize, scratch: *limb_t) void {
    c.blst_p2s_mult_wbits(ret, table, wbits, npoints, scalars, nbits, scratch);
}

pub fn blst_p2s_mult_pippenger_scratch_sizeof(npoints: usize) usize {
    return c.blst_p2s_mult_pippenger_scratch_sizeof(npoints);
}

pub fn blst_p2s_mult_pippenger(ret: *blst_p2, points: []*const blst_p2_affine, npoints: usize, scalars: []*const byte, nbits: usize, scratch: *limb_t) void {
    c.blst_p2s_mult_pippenger(ret, points, npoints, scalars, nbits, scratch);
}

pub fn blst_p2s_tile_pippenger(ret: *blst_p2, points: []*const blst_p2_affine, npoints: usize, scalars: []*const byte, nbits: usize, scratch: *limb_t, bit0: usize, window: usize) void {
    c.blst_p2s_tile_pippenger(ret, points, npoints, scalars, nbits, scratch, bit0, window);
}

/// Hash-to-curve operations.
pub fn blst_map_to_g1(out: *blst_p1, u: *const blst_fp, v: ?*const blst_fp) void {
    // TODO: do we need to unwrap value of v if it's not null?
    // same for below
    c.blst_map_to_g1(out, u, v);
}

pub fn blst_map_to_g2(out: *blst_p2, u: *const blst_fp2, v: ?*const blst_fp2) void {
    // TODO: do we need to unwrap value of v if it's not null?
    c.blst_map_to_g2(out, u, v);
}

pub fn blst_encode_to_g1(out: *blst_p1, msg: *const byte, msg_len: usize, dst: ?*const byte, dst_len: ?usize, aug: ?*const byte, aug_len: ?usize) void {
    c.blst_encode_to_g1(out, msg, msg_len, dst, dst_len, aug, aug_len);
}

pub fn blst_hash_to_g1(out: *blst_p1, msg: *const byte, msg_len: usize, dst: ?*const byte, dst_len: ?usize, aug: ?*const byte, aug_len: ?usize) void {
    c.blst_hash_to_g1(out, msg, msg_len, dst, dst_len, aug, aug_len);
}

pub fn blst_encode_to_g2(out: *blst_p2, msg: *const byte, msg_len: usize, dst: ?*const byte, dst_len: ?usize, aug: ?*const byte, aug_len: ?usize) void {
    c.blst_encode_to_g2(out, msg, msg_len, dst, dst_len, aug, aug_len);
}

pub fn blst_hash_to_g2(out: *blst_p2, msg: *const byte, msg_len: usize, dst: ?*const byte, dst_len: ?usize, aug: ?*const byte, aug_len: ?usize) void {
    c.blst_hash_to_g2(out, msg, msg_len, dst, dst_len, aug, aug_len);
}

/// Zcash-compatible serialization/deserialization.
pub fn blst_p1_serialize(out: []byte, a: *const blst_p1) IncorrectLen!void {
    if (out.len != 96) {
        return error.IncorrectLen;
    }
    c.blst_p1_serialize(out, a);
}

pub fn blst_p1_compress(out: []byte, a: *const blst_p1) IncorrectLen!void {
    if (out.len != 48) {
        return error.IncorrectLen;
    }
    c.blst_p1_compress(out, a);
}

pub fn blst_p1_affine_serialize(out: []byte, in: *const blst_p1_affine) IncorrectLen!void {
    if (out.len != 96) {
        return error.IncorrectLen;
    }
    c.blst_p1_affine_serialize(out, in);
}

pub fn blst_p1_affine_compress(out: []byte, in: *const blst_p1_affine) IncorrectLen!void {
    if (out.len != 48) {
        return error.IncorrectLen;
    }
    c.blst_p1_affine_compress(out, in);
}

const BLST_ERROR = enum(u8) {
    SUCCESS = 0,
    BAD_ENCODING,
    POINT_NOT_ON_CURVE,
    POINT_NOT_IN_GROUP,
    AGGR_TYPE_MISMATCH,
    VERIFY_FAIL,
    PK_IS_INFINITY,
    BAD_SCALAR,
};

pub fn blst_p1_uncompress(out: *blst_p1_affine, in: []const byte) IncorrectLen!BLST_ERROR {
    if (in.len != 48) {
        return error.IncorrectLen;
    }
    return c.blst_p1_uncompress(out, in);
}

pub fn blst_p1_deserialize(out: *blst_p1, in: []const byte) IncorrectLen!BLST_ERROR {
    if (in.len != 96) {
        return error.IncorrectLen;
    }
    return c.blst_p1_deserialize(out, in);
}

pub fn blst_p2_serialize(out: []byte, in: *const blst_p2) IncorrectLen!void {
    if (out.len != 192) {
        return error.IncorrectLen;
    }
    c.blst_p2_serialize(out, in);
}

pub fn blst_p2_compress(out: []byte, in: *const blst_p2) IncorrectLen!void {
    if (out.len != 96) {
        return error.IncorrectLen;
    }
    c.blst_p2_compress(out, in);
}

pub fn blst_p2_affine_serialize(out: []byte, in: *const blst_p2_affine) IncorrectLen!void {
    if (out.len != 192) {
        return error.IncorrectLen;
    }
    c.blst_p2_affine_serialize(out, in);
}

pub fn blst_p2_affine_compress(out: []byte, in: *const blst_p2_affine) IncorrectLen!void {
    if (out.len != 96) {
        return error.IncorrectLen;
    }
    c.blst_p2_affine_compress(out, in);
}

pub fn blst_p2_uncompress(out: *blst_p2_affine, in: []const byte) IncorrectLen!BLST_ERROR {
    if (in.len != 96) {
        return error.IncorrectLen;
    }
    return c.blst_p2_uncompress(out, in);
}

pub fn blst_p2_deserialize(out: *blst_p2_affine, in: []const byte) IncorrectLen!BLST_ERROR {
    if (in.len != 192) {
        return error.IncorrectLen;
    }
    return c.blst_p2_deserialize(out, in);
}

/// Secret-key operations.
pub fn blst_keygen(out_sk: *blst_scalar, ikm: *const byte, ikm_len: usize, info: ?*const byte, info_len: ?usize) void {
    // TODO: unwrap option types?
    c.blst_keygen(out_sk, ikm, ikm_len, info, info_len);
}

pub fn blst_sk_to_pk_in_g1(out_pk: *blst_p1, sk: *const blst_scalar) void {
    c.blst_sk_to_pk_in_g1(out_pk, sk);
}

pub fn blst_sign_pk_in_g1(out_sig: *blst_p2, hash: *const blst_p2, sk: *const blst_scalar) void {
    c.blst_sign_pk_in_g1(out_sig, hash, sk);
}

pub fn blst_sk_to_pk_in_g2(out_pk: *blst_p2, sk: *const blst_scalar) void {
    c.blst_sk_to_pk_in_g2(out_pk, sk);
}

pub fn blst_sign_pk_in_g2(out_sig: *blst_p1, hash: *const blst_p1, sk: *const blst_scalar) void {
    c.blst_sign_pk_in_g2(out_sig, hash, sk);
}

/// Pairing interface.
pub fn blst_miller_loop(ret: *blst_fp12, q: *const blst_p2_affine, p: *const blst_p1_affine) void {
    c.blst_miller_loop(ret, q, p);
}

pub fn blst_miller_loop_n(ret: *blst_fp12, qs: []*const blst_p2_affine, ps: []*const blst_p1_affine, n: usize) void {
    c.blst_miller_loop_n(ret, qs, ps, n);
}

pub fn blst_final_exp(ret: *blst_fp12, f: *const blst_fp12) void {
    c.blst_final_exp(ret, f);
}

pub fn blst_precompute_lines(qlines: []blst_fp6, q: *const blst_p2_affine) IncorrectLen!void {
    if (qlines.len != 68) {
        return error.IncorrectLen;
    }
    c.blst_precompute_lines(qlines, q);
}

pub fn blst_miller_loop_lines(ret: *blst_fp12, qlines: []const blst_fp6, p: *const blst_p1_affine) IncorrectLen!void {
    if (qlines.len != 68) {
        return error.IncorrectLen;
    }
    c.blst_miller_loop_lines(ret, qlines, p);
}

pub fn blst_fp12_finalverify(gt1: *const blst_fp12, gt2: *const blst_fp12) bool {
    return c.blst_fp12_finalverify(gt1, gt2);
}

const blst_pairing = extern struct {
    // This is intentionally left empty since it is opaque.
    // Fields are not accessible in Zig or any other language.
};

pub fn blst_pairing_sizeof() usize {
    return c.blst_pairing_sizeof();
}

pub fn blst_pairing_init(new_ctx: *blst_pairing, hash_or_encode: bool, dst: ?*const byte, dst_len: ?usize) void {
    c.blst_pairing_init(new_ctx, hash_or_encode, dst, dst_len);
}

pub fn blst_pairing_get_dst(ctx: *const blst_pairing) *const byte {
    return c.blst_pairing_get_dst(ctx);
}

pub fn blst_pairing_commit(ctx: *blst_pairing) void {
    c.blst_pairing_commit(ctx);
}

pub fn blst_pairing_aggregate_pk_in_g2(ctx: *blst_pairing, pk: *const blst_p2_affine, signature: *const blst_p1_affine, msg: *const byte, msg_len: usize, aug: *const byte, aug_len: usize) BLST_ERROR {
    return c.blst_pairing_aggregate_pk_in_g2(ctx, pk, signature, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_chk_n_aggr_pk_in_g2(ctx: *blst_pairing, pk: *const blst_p2_affine, pk_grpchk: bool, signature: *const blst_p1_affine, sig_grpchk: bool, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_chk_n_aggr_pk_in_g2(ctx, pk, pk_grpchk, signature, sig_grpchk, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_mul_n_aggregate_pk_in_g2(ctx: *blst_pairing, pk: *const blst_p2_affine, sig: *const blst_p1_affine, scalar: *const byte, nbits: usize, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_mul_n_aggregate_pk_in_g2(ctx, pk, sig, scalar, nbits, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_chk_n_mul_n_aggr_pk_in_g2(ctx: *blst_pairing, pk: *const blst_p2_affine, pk_grpchk: bool, sig: *const blst_p1_affine, sig_grpchk: bool, scalar: *const byte, nbits: usize, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_chk_n_mul_n_aggr_pk_in_g2(ctx, pk, pk_grpchk, sig, sig_grpchk, scalar, nbits, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_aggregate_pk_in_g1(ctx: *blst_pairing, pk: *const blst_p1_affine, signature: *const blst_p2_affine, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_aggregate_pk_in_g1(ctx, pk, signature, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_chk_n_aggr_pk_in_g1(ctx: *blst_pairing, pi: *const blst_p1_affine, pk_grpchk: bool, signature: *const blst_p2_affine, sig_grpchk: bool, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_chk_n_aggr_pk_in_g1(ctx, pi, pk_grpchk, signature, sig_grpchk, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_mul_n_aggregate_pk_in_g1(ctx: *blst_pairing, pk: *const blst_p1_affine, sig: *const blst_p2_affine, scalar: *const byte, nbits: usize, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_mul_n_aggregate_pk_in_g1(ctx, pk, sig, scalar, nbits, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_chk_n_mul_n_aggr_pk_in_g1(ctx: *blst_pairing, pk: *const blst_p1_affine, pk_grpchk: bool, sig: *const blst_p2_affine, sig_grpchk: bool, scalar: *const byte, nbits: usize, msg: *const byte, msg_len: usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_pairing_chk_n_mul_n_aggr_pk_in_g1(ctx, pk, pk_grpchk, sig, sig_grpchk, scalar, nbits, msg, msg_len, aug, aug_len);
}

pub fn blst_pairing_merge(ctx: *blst_pairing, ctx1: *const blst_pairing) BLST_ERROR {
    return c.blst_pairing_merge(ctx, ctx1);
}

pub fn blst_pairing_finalverify(ctx: *blst_pairing, gtsig: ?*const blst_fp12) bool {
    return c.blst_pairing_finalverify(ctx, gtsig);
}

pub fn blst_aggregate_in_g1(out: *blst_p1, in: *const blst_p1, zwire: *const byte) BLST_ERROR {
    return c.blst_aggregate_in_g1(out, in, zwire);
}

pub fn blst_aggregate_in_g2(out: *blst_p2, in: *const blst_p2, zwire: *const byte) BLST_ERROR {
    return c.blst_aggregate_in_g2(out, in, zwire);
}

pub fn blst_aggregated_in_g1(out: *blst_fp12, signature: *const blst_p1_affine) void {
    c.blst_aggregated_in_g1(out, signature);
}

pub fn blst_aggregated_in_g2(out: *blst_fp12, signature: *const blst_p2_affine) void {
    c.blst_aggregated_in_g2(out, signature);
}

/// "One-shot" CoreVerify entry points
pub fn blst_core_verify_pk_in_g1(pk: *const blst_p1_affine, signature: *const blst_p2_affine, hash_or_encode: bool, msg: *const byte, msg_len: usize, dst: ?*const byte, dst_len: ?usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_core_verify_pk_in_g1(pk, signature, hash_or_encode, msg, msg_len, dst, dst_len, aug, aug_len);
}

pub fn blst_core_verify_pk_in_g2(pk: *const blst_p2_affine, signature: *const blst_p1_affine, hash_or_encode: bool, msg: *const byte, msg_len: usize, dst: ?*const byte, dst_len: ?usize, aug: ?*const byte, aug_len: ?usize) BLST_ERROR {
    return c.blst_core_verify_pk_in_g2(pk, signature, hash_or_encode, msg, msg_len, dst, dst_len, aug, aug_len);
}

//// Bindings for blst_aux.h
/// It's commented in blst_aux.h that these apis might be promoted to blst.h or removed,
/// however since Rust use bindings for them, we'll just do the same
pub fn blst_fr_ct_bfly(x0: *blst_fr, x1: *blst_fr, twiddle: *const blst_fr) void {
    c.blst_fr_ct_bfly(x0, x1, twiddle);
}

pub fn blst_fr_gs_bfly(x0: *blst_fr, x1: *blst_fr, twiddle: *const blst_fr) void {
    c.blst_fr_gs_bfly(x0, x1, twiddle);
}

pub fn blst_fr_to(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_to(ret, a);
}

pub fn blst_fr_from(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_from(ret, a);
}

pub fn blst_fp_to(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_to(ret, a);
}

pub fn blst_fp_from(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_from(ret, a);
}

pub fn blst_fp_is_square(a: *const blst_fp) bool {
    return c.blst_fp_is_square(a);
}

pub fn blst_fp2_is_square(a: *const blst_fp2) bool {
    return c.blst_fp2_is_square(a);
}

pub fn blst_p1_from_jacobian(out: *blst_p1, in: *const blst_p1) void {
    c.blst_p1_from_jacobian(out, in);
}

pub fn blst_p2_from_jacobian(out: *blst_p2, in: *const blst_p2) void {
    c.blst_p2_from_jacobian(out, in);
}

pub fn blst_sk_to_pk2_in_g1(out: []byte, out_pk: *blst_p1_affine, sk: *const blst_scalar) IncorrectLen!void {
    if (out.len != 96) {
        return error.IncorrectLen;
    }
    c.blst_sk_to_pk2_in_g1(out, out_pk, sk);
}

pub fn blst_sign_pk2_in_g1(out: []byte, out_sig: *blst_p2_affine, hash: *const blst_p2, sk: *const blst_scalar) IncorrectLen!void {
    if (out != 192) {
        return error.IncorrectLen;
    }
    c.blst_sign_pk2_in_g1(out, out_sig, hash, sk);
}

pub fn blst_sk_to_pk2_in_g2(out: []byte, out_pk: *blst_p2_affine, sk: *const blst_scalar) IncorrectLen!void {
    if (out.len != 192) {
        return error.IncorrectLen;
    }
    c.blst_sk_to_pk2_in_g2(out, out_pk, sk);
}

pub fn blst_sign_pk2_in_g2(out: []byte, out_sig: *blst_p1_affine, hash: *const blst_p1, sk: *const blst_scalar) IncorrectLen!void {
    if (out.len != 96) {
        return error.IncorrectLen;
    }
    c.blst_sign_pk2_in_g2(out, out_sig, hash, sk);
}

const blst_uniq = extern struct {
    // This is intentionally left empty since it is opaque.
    // Fields are not accessible in Zig or any other language.
};

pub fn blst_uniq_sizeof(n_nodes: usize) usize {
    return c.blst_uniq_sizeof(n_nodes);
}

pub fn blst_uniq_init(tree: *blst_uniq) void {
    c.blst_uniq_init(tree);
}

pub fn blst_uniq_test(tree: *blst_uniq, msg: *const byte, len: usize) bool {
    return c.blst_uniq_test(tree, msg, len);
}

pub fn blst_expand_message_xmd(out: *byte, out_len: usize, msg: *const byte, msg_len: usize, dst: *const byte, dst_len: usize) void {
    c.blst_expand_message_xmd(out, out_len, msg, msg_len, dst, dst_len);
}

pub fn blst_p1_unchecked_mult(out: *blst_p1, p: *const blst_p1, scalar: *const byte, nbits: usize) void {
    c.blst_p1_unchecked_mult(out, p, scalar, nbits);
}

pub fn blst_p2_unchecked_mult(out: *blst_p2, p: *const blst_p2, scalar: *const byte, nbits: usize) void {
    c.blst_p2_unchecked_mult(out, p, scalar, nbits);
}

pub fn blst_pairing_raw_aggregate(ctx: *blst_pairing, q: *const blst_p2_affine, p: *const blst_p1_affine) void {
    c.blst_pairing_raw_aggregate(ctx, q, p);
}

pub fn blst_pairing_as_fp12(ctx: *blst_pairing) *blst_fp12 {
    return c.blst_pairing_as_fp12(ctx);
}

pub fn blst_bendian_from_fp12(out: []byte, a: *const blst_fp12) IncorrectLen!void {
    if (out.len != 48 * 12) {
        return error.IncorrectLen;
    }
    c.blst_bendian_from_fp12(out, a);
}

pub fn blst_keygen_v3(out_sk: *blst_scalar, ikm: *const byte, ikm_len: usize, info: ?*const byte, info_len: ?usize) void {
    c.blst_keygen_v3(out_sk, ikm, ikm_len, info, info_len);
}

pub fn blst_keygen_v4_5(out_sk: *blst_scalar, ikm: *const byte, ikm_len: usize, salt: *const byte, salt_len: usize, info: ?*const byte, info_len: ?usize) void {
    c.blst_keygen_v4_5(out_sk, ikm, ikm_len, salt, salt_len, info, info_len);
}

pub fn blst_keygen_v5(out_sk: *blst_scalar, ikm: *const byte, ikm_len: usize, salt: *const byte, salt_len: usize, info: ?*const byte, info_len: ?usize) void {
    c.blst_keygen_v5(out_sk, ikm, ikm_len, salt, salt_len, info, info_len);
}

pub fn blst_derive_master_eip2333(out_sk: *blst_scalar, ikm: *const byte, ikm_len: usize) void {
    c.blst_derive_master_eip2333(out_sk, ikm, ikm_len);
}

pub fn blst_derive_child_eip2333(out_sk: *blst_scalar, sk: *const blst_scalar, child_index: usize) void {
    c.blst_derive_child_eip2333(out_sk, sk, child_index);
}

pub fn blst_scalar_from_hexascii(out: *blst_scalar, sk: *const blst_scalar, child_index: usize) void {
    c.blst_scalar_from_hexascii(out, sk, child_index);
}

pub fn blst_fr_from_hexascii(ret: *blst_fr, hex: *const byte) void {
    c.blst_fr_from_hexascii(ret, hex);
}

pub fn blst_fp_from_hexascii(ret: *blst_fp, hex: *const byte) void {
    c.blst_fp_from_hexascii(ret, hex);
}

pub fn blst_p1_sizeof() usize {
    return c.blst_p1_sizeof();
}

pub fn blst_p1_affine_sizeof() usize {
    return c.blst_p1_affine_sizeof();
}

pub fn blst_p2_sizeof() usize {
    return c.blst_p2_sizeof();
}

pub fn blst_p2_affine_sizeof() usize {
    return c.blst_p2_affine_sizeof();
}

pub fn blst_fp12_sizeof() usize {
    return c.blst_fp12_sizeof();
}

pub fn blst_sha256(out: []byte, msg: *const byte, msg_len: usize) IncorrectLen!void {
    if (out.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_sha256(out, msg, msg_len);
}
