//! BLS signatures in the 'minimal-pubkey-size' setting.
//!
//! In this setting, a `Signature` is `p2_affine` point.
//! Source: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-00#section-2.1

point: c.blst_p2_affine = c.blst_p2_affine{},

const Self = @This();

pub const SERIALIZE_SIZE = 192;
pub const COMPRESS_SIZE = 96;

/// Checks that the signature is not infinity and is in the correct subgroup.
/// Validating prior to verification avoids resource-consuming verification process.
/// Passing 'false' is always cryptographically safe, but application might want
/// to guard against obviously bogus individual signatures.
///
/// Returns `BlstError` if validation fails.
pub fn validate(self: *const Self, sig_infcheck: bool) BlstError!void {
    if (sig_infcheck and c.blst_p2_affine_is_inf(&self.point)) return BlstError.PkIsInfinity;
    if (!c.blst_p2_affine_in_g2(&self.point)) return BlstError.PointNotInGroup;
}

/// Verify the `Signature` against a `PublicKey` and message.
///
/// Returns `BlstError` if verification fails.
pub fn verify(
    self: *const Self,
    sig_groupcheck: bool,
    msg: []const u8,
    dst: []const u8,
    aug: ?[]const u8,
    pk: *const PublicKey,
    pk_validate: bool,
) BlstError!void {
    if (sig_groupcheck) try self.validate(false);
    if (pk_validate) try pk.validate();

    if (msg.len == 0 or dst.len == 0) {
        return BlstError.BadEncoding;
    }

    const chk = errorFromInt(c.blst_core_verify_pk_in_g1(
        &pk.point,
        &self.point,
        true,
        msg.ptr,
        msg.len,
        dst.ptr,
        dst.len,
        if (aug) |a| a.ptr else null,
        if (aug) |a| a.len else 0,
    ));

    return chk;
}

/// Verify an `AggregateSignature` against a single message and a slice of `PublicKey`.
///
/// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
pub fn aggregateVerify(
    self: *const Self,
    sig_groupcheck: bool,
    buffer: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *const PublicKey,
    pks_validate: bool,
) BlstError!bool {
    const n_elems = pks.len;
    if (n_elems == 0 or msgs.len != n_elems) {
        return BlstError.VerifyFail;
    }
    var pairing = Pairing.init(buffer, true, dst);
    try pairing.aggregate(
        pks[0],
        pks_validate,
        self,
        sig_groupcheck,
        &msgs[0],
        null,
    );

    for (1..n_elems) |i| {
        try pairing.aggregate(
            pks[i],
            pks_validate,
            null,
            sig_groupcheck,
            &msgs[i],
            null,
        );
    }

    pairing.commit();
    var gtsig = c.blst_fp12{};
    Pairing.aggregated(&gtsig, self);

    return pairing.finalVerify(&gtsig);
}

/// Fast verify an `AggregateSignature` against a single message and a slice of `PublicKey`.
///
/// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
pub fn fastAggregateVerify(
    self: *const Self,
    sig_groupcheck: bool,
    buffer: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    msg: *const [32]u8,
    dst: []const u8,
    pks: []const *const PublicKey,
    pks_validate: bool,
) BlstError!bool {
    const agg_pk = try AggregatePublicKey.aggregate(pks, pks_validate);
    const pk = agg_pk.toPublicKey();

    return try self.aggregateVerify(
        sig_groupcheck,
        buffer,
        @ptrCast(msg),
        dst,
        &[_]*const PublicKey{&pk},
        false,
    );
}

/// Fast verify an `AggregateSignature` against a single message and pre-aggregated `PublicKey`.
///
/// Returns `BlstError` if verification fails.
pub fn fastAggregateVerifyPreAggregated(
    self: *const Self,
    sig_groupcheck: bool,
    buffer: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    msg: *const [32]u8,
    dst: []const u8,
    pk: *const PublicKey,
) BlstError!bool {
    return try self.aggregateVerify(
        sig_groupcheck,
        buffer,
        @ptrCast(msg),
        dst,
        &[_]*const PublicKey{pk},
        false,
    );
}

/// Convert an `AggregateSignature` to a regular `Signature`.
pub fn fromAggregate(agg_sig: *const AggregateSignature) Self {
    var sig = Self{};
    c.blst_p2_to_affine(&sig.point, &agg_sig.point);
    return sig;
}

/// Compress the `Signature` to bytes.
pub fn compress(self: *const Self) [COMPRESS_SIZE]u8 {
    var sig_comp = [_]u8{0} ** COMPRESS_SIZE;
    c.blst_p2_affine_compress(&sig_comp, &self.point);
    return sig_comp;
}

/// Serialize the `Signature` to bytes.
pub fn serialize(self: *const Self) [SERIALIZE_SIZE]u8 {
    var sig_out = [_]u8{0} ** SERIALIZE_SIZE;
    c.blst_p2_affine_serialize(&sig_out, &self.point);
    return sig_out;
}

/// Decompress a `Signature` from compressed bytes.
///
/// Returns `Signature` on success, `BlstError` on failure.
pub fn uncompress(sig_comp: []const u8) BlstError!Self {
    if (sig_comp.len == COMPRESS_SIZE and (sig_comp[0] & 0x80) != 0) {
        var sig = Self{};
        try errorFromInt(c.blst_p2_uncompress(&sig.point, &sig_comp[0]));
        return sig;
    }

    return BlstError.BadEncoding;
}

/// Deserialize a `Signature` from bytes.
///
/// Returns `Signature` on success, `BlstError` on failure.
pub fn deserialize(sig_in: []const u8) BlstError!Self {
    if ((sig_in.len == SERIALIZE_SIZE and (sig_in[0] & 0x80) == 0) or
        (sig_in.len == COMPRESS_SIZE and (sig_in[0] & 0x80) != 0))
    {
        var sig = Self{};
        try errorFromInt(c.blst_p2_deserialize(&sig.point, &sig_in[0]));
        return sig;
    }

    return BlstError.BadEncoding;
}

/// Check if the `Signature` is in the correct subgroup.
pub fn subgroupCheck(self: *const Self) bool {
    return c.blst_p2_affine_in_g2(&self.point);
}

/// Check if the `Signature` is the point at infinity.
pub fn isInfinity(self: *const Self) bool {
    return c.blst_p2_affine_is_inf(&self.point);
}

/// Check if two signatures are equal.
pub fn isEqual(self: *const Self, other: *const Self) bool {
    return c.blst_p2_affine_is_equal(&self.point, &other.point);
}

const std = @import("std");
const c = @cImport({
    @cInclude("blst.h");
});

const BlstError = @import("error.zig").BlstError;
const errorFromInt = @import("error.zig").errorFromInt;
const PublicKey = @import("root.zig").PublicKey;
const AggregatePublicKey = @import("AggregatePublicKey.zig");
const AggregateSignature = @import("AggregateSignature.zig");
const Pairing = @import("Pairing.zig");

const SecretKey = @import("SecretKey.zig");
const DST = @import("root.zig").DST;

test "test_sign_n_verify" {
    // sample code for consumer like on Readme
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();

    const dst = DST;
    const msg = "hello foo";
    const sig = sk.sign(msg, dst, null);

    // aug is null
    try sig.verify(
        true,
        msg,
        dst,
        null,
        &pk,
        true,
    );
}

test aggregateVerify {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const dst = DST;
    // aug is null

    const num_sigs = 10;

    var buffer: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;

    var msgs: [num_sigs][32]u8 = undefined;
    var sks: [num_sigs]SecretKey = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]@This() = undefined;

    for (0..num_sigs) |i| {
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const sig = sk.sign(&msgs[i], dst, null);

        sks[i] = sk;
        pks[i] = pk;
        sigs[i] = sig;
    }

    var sig_ptrs: [num_sigs]*const @This() = undefined;
    var pk_ptrs: [num_sigs]*const PublicKey = undefined;
    for (0..num_sigs) |i| {
        sig_ptrs[i] = &sigs[i];
        pk_ptrs[i] = &pks[i];
    }

    const agg_sig = try AggregateSignature.aggregate(&sig_ptrs, false);
    const sig = @This().fromAggregate(&agg_sig);

    try std.testing.expect(try sig.aggregateVerify(false, &buffer, &msgs, dst, &pk_ptrs, false));
}
