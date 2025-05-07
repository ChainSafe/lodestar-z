const std = @import("std");
const Allocator = std.mem.Allocator;
const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

const c = @cImport({
    @cInclude("blst.h");
});

pub const PairingError = error{ BufferTooSmall, DstTooSmall, OutOfMemory, InvalidPairingBufferSize, NotFound };

const PTag = enum {
    p1,
    p2,
};

const PairingPk = union(PTag) {
    p1: c.blst_p1_affine,
    p2: c.blst_p2_affine,
};

pub const Pairing = struct {
    v: [*c]u8,

    /// Rust always use a heap allocation here, but adding an allocator as param for Zig is too complex
    /// instead of that we provide a buffer that's big enough for the struct to operate on so that:
    /// - it does not have allocator in its api
    /// - can use stack allocation at consumer side
    /// - can reuse memory if it makes sense at consumer side
    pub fn new(buffer: [*c]u8, buffer_len: usize, hash_or_encode: bool, dst: [*c]const u8, dst_len: usize) PairingError!Pairing {
        if (buffer_len < c.blst_pairing_sizeof()) {
            return PairingError.BufferTooSmall;
        }

        if (dst_len == 0) {
            return PairingError.DstTooSmall;
        }

        var obj = Pairing{
            .v = buffer,
        };
        obj.init(hash_or_encode, dst, dst_len);

        return obj;
    }

    // Javascript can leverage this api to allocate a Pairing buffer on its own
    pub fn sizeOf() usize {
        return c.blst_pairing_sizeof();
    }

    fn init(self: *Pairing, hash_or_encode: bool, dst: [*c]const u8, dst_len: usize) void {
        c.blst_pairing_init(self.ctx(), hash_or_encode, dst, dst_len);
    }

    fn ctx(self: *Pairing) *c.blst_pairing {
        const ptr: *c.blst_pairing = @ptrCast(self.v);
        return ptr;
    }

    fn constCtx(self: *const Pairing) *const c.blst_pairing {
        const ptr: *const c.blst_pairing = @ptrCast(&self.v[0]);
        return ptr;
    }

    pub fn aggregateG1(self: *Pairing, pk: *const c.blst_p1_affine, pk_validate: bool, sig: ?*const c.blst_p2_affine, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, aug: ?[]const u8) BLST_ERROR!void {
        const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
        const aug_len = if (aug != null) aug.?.len else 0;
        const sig_ptr = if (sig != null) sig.? else null;

        const res = c.blst_pairing_chk_n_aggr_pk_in_g1(self.ctx(), pk, pk_validate, sig_ptr, sig_groupcheck, msg, msg_len, aug_ptr, aug_len);

        if (toBlstError(res)) |err| {
            return err;
        }
    }

    pub fn aggregateG2(self: *Pairing, pk: *const c.blst_p2_affine, pk_validate: bool, sig: ?*const c.blst_p1_affine, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, aug: ?[]const u8) BLST_ERROR!void {
        const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
        const aug_len = if (aug != null) aug.?.len else 0;
        const sig_ptr = if (sig != null) sig.? else null;

        const res = c.blst_pairing_chk_n_aggr_pk_in_g2(self.ctx(), pk, pk_validate, sig_ptr, sig_groupcheck, msg, msg_len, aug_ptr, aug_len);

        if (toBlstError(res)) |err| {
            return err;
        }
    }

    // TODO: msgs and scalar should have len > 0
    // check for other apis as well
    pub fn mulAndAggregateG1(self: *Pairing, pk: *const c.blst_p1_affine, pk_validate: bool, sig: *const c.blst_p2_affine, sig_groupcheck: bool, scalar: [*c]const u8, nbits: usize, msg: [*c]const u8, msg_len: usize, aug: ?[]const u8) BLST_ERROR!void {
        const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
        const aug_len = if (aug != null) aug.?.len else 0;

        const res = c.blst_pairing_chk_n_mul_n_aggr_pk_in_g1(self.ctx(), pk, pk_validate, sig, sig_groupcheck, scalar, nbits, msg, msg_len, aug_ptr, aug_len);

        if (toBlstError(res)) |err| {
            return err;
        }
    }

    pub fn mulAndAggregateG2(self: *Pairing, pk: *const c.blst_p2_affine, pk_validate: bool, sig: *const c.blst_p1_affine, sig_groupcheck: bool, scalar: [*c]const u8, nbits: usize, msg: [*c]const u8, msg_len: usize, aug: ?[]const u8) BLST_ERROR!void {
        const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
        const aug_len = if (aug != null) aug.?.len else 0;

        const res = c.blst_pairing_chk_n_mul_n_aggr_pk_in_g2(self.ctx(), pk, pk_validate, sig, sig_groupcheck, scalar, nbits, msg, msg_len, aug_ptr, aug_len);

        if (toBlstError(res)) |err| {
            return err;
        }
    }

    pub fn aggregatedG1(gtsig: *c.blst_fp12, sig: *const c.blst_p2_affine) void {
        c.blst_aggregated_in_g2(gtsig, sig);
    }

    pub fn aggregatedG2(gtsig: *c.blst_fp12, sig: *const c.blst_p1_affine) void {
        c.blst_aggregated_in_g1(gtsig, sig);
    }

    pub fn commit(self: *Pairing) void {
        c.blst_pairing_commit(self.ctx());
    }

    pub fn merge(self: *Pairing, ctx1: *const Pairing) BLST_ERROR!void {
        const res = c.blst_pairing_merge(self.ctx(), ctx1.constCtx());

        if (toBlstError(res)) |err| {
            return err;
        }
    }

    pub fn finalVerify(self: *const Pairing, gtsig: ?*const c.blst_fp12) bool {
        const gtsig_ptr = if (gtsig != null) gtsig.? else null;
        return c.blst_pairing_finalverify(self.constCtx(), gtsig_ptr);
    }

    pub fn rawAggregate(self: *Pairing, q: *c.blst_p2_affine, p: *c.blst_p1_affine) void {
        c.blst_pairing_raw_aggregate(self.ctx(), q, p);
    }

    pub fn asFp12(self: *Pairing) *c.blst_fp12 {
        return c.blst_pairing_as_fp12(self.ctx());
    }
};

test "init Pairing" {
    const allocator = std.testing.allocator;
    const buffer = try allocator.alloc(u8, Pairing.sizeOf());
    defer allocator.free(buffer);

    const dst = "destination";
    _ = try Pairing.new(&buffer[0], buffer.len, true, &dst[0], dst.len);
}

test "sizeOf Pairing" {
    // this works on MacOS, adding this test to understand more about the size of Pairing
    std.debug.print("Size of Pairing: {}", .{Pairing.sizeOf()});
    try std.testing.expectEqual(3192, Pairing.sizeOf());
}
