//! BLS public key in the 'minimal-pubkey-size' setting.
//!
//! In this setting, a `PublicKey` is `p1_affine` point.
//! Source: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-00#section-2.1

point: c.blst_p1_affine = c.blst_p1_affine{},

pub const COMPRESS_SIZE = 48;
pub const SERIALIZE_SIZE = 96;

const Self = @This();

// Core operations

/// Checks that a given `Point` is not infinity and is in the correct subgroup.
///
/// Returns a `BlstError` if verification fails.
pub fn validate(self: *const Self) BlstError!void {
    if (c.blst_p1_affine_is_inf(&self.point)) return BlstError.PkIsInfinity;
    if (!c.blst_p1_affine_in_g1(&self.point)) return BlstError.PointNotInGroup;
}

/// Validate a serialized public key.
///
/// Returns the `PublicKey` on success, `BlstError` on failure.
pub fn keyValidate(key: []const u8) BlstError!Self {
    const pk = try Self.deserialize(key);
    try pk.validate();
    return pk;
}

/// Convert an `AggregatePublicKey` to a regular `PublicKey`.
pub fn fromAggregate(agg_pk: *const AggregatePublicKey) Self {
    var pk_aff = @This(){};
    c.blst_p1_to_affine(&pk_aff.point, &agg_pk.point);
    return pk_aff;
}

/// Convert a regular `PublicKey` to a `AggregatePublicKey`.
pub fn toAggregate(self: *const Self) AggregatePublicKey {
    var agg_pk = AggregatePublicKey{};
    c.blst_p1_from_affine(&agg_pk.point, &self.point);
    return agg_pk;
}

/// Compress the `PublicKey` to bytes.
pub fn compress(self: *const Self) [COMPRESS_SIZE]u8 {
    var pk_comp = [_]u8{0} ** COMPRESS_SIZE;
    c.blst_p1_affine_compress(&pk_comp, &self.point);
    return pk_comp;
}

/// Serialize the `PublicKey` to bytes.
pub fn serialize(self: *const Self) [SERIALIZE_SIZE]u8 {
    var pk_out = [_]u8{0} ** SERIALIZE_SIZE;
    c.blst_p1_affine_serialize(&pk_out, &self.point);
    return pk_out;
}

/// Decompress a `PublicKey` from compressed bytes.
///
/// Returns the `PublicKey` on success, `BlstError` on failure.
pub fn uncompress(pk_comp: []const u8) BlstError!Self {
    if (pk_comp.len == COMPRESS_SIZE or (pk_comp[0] & 0x80) != 0) {
        var pk = Self{};
        try errorFromInt(c.blst_p1_uncompress(&pk.point, pk_comp.ptr));
        return pk;
    }
    return BlstError.BadEncoding;
}

/// Deserialize a `PublicKey` (either compressed and uncompressed) from bytes.
///
/// Returns a `PublicKey` on success, `BlstError` on failure.
pub fn deserialize(pk_in: []const u8) BlstError!Self {
    if ((pk_in.len == SERIALIZE_SIZE and (pk_in[0] & 0x80) == 0) or
        (pk_in.len == COMPRESS_SIZE and (pk_in[0] & 0x80) != 0))
    {
        var pk = Self{};
        try errorFromInt(c.blst_p1_deserialize(&pk.point, &pk_in[0]));
        return pk;
    }

    return BlstError.BadEncoding;
}

/// Check if two public keys are equal.
pub fn isEqual(self: *const Self, other: *const Self) bool {
    return c.blst_p1_affine_is_equal(&self.point, &other.point);
}

const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const errorFromInt = @import("error.zig").errorFromInt;
const AggregatePublicKey = @import("AggregatePublicKey.zig");

const c = @cImport({
    @cInclude("blst.h");
});
