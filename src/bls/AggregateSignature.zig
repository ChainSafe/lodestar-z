//! AggregateSignature definition for BLS signature scheme using BLS12-381.
const Self = @This();

/// An aggregate signature that can be used to verify multiple messages
/// against an aggregate public key.
point: c.blst_p2 = c.blst_p2{},

/// Validates that the aggregate signature is in the correct subgroup (G2).
pub fn validate(self: *const Self) BlstError!void {
    if (!c.blst_p2_in_g2(&self.point)) return BlstError.PointNotInGroup;
}

/// Converts an aggregate signature back to a regular signature.
/// Converts from projective coordinates back to affine coordinates.
pub fn toSignature(self: *const Self) Signature {
    var sig = Signature{};
    c.blst_p2_to_affine(&sig.point, &self.point);
    return sig;
}

/// Aggregates multiple signatures into a single aggregate signature.
///
/// Validates each signature before aggregation if `sigs_groupcheck` is true.
/// Errors if the `sigs` slice is empty or if any signature validation fails.
pub fn aggregate(sigs: []const Signature, sigs_groupcheck: bool) BlstError!Self {
    if (sigs.len == 0) return BlstError.AggrTypeMismatch;
    if (sigs_groupcheck) for (sigs) |sig| try sig.validate(false);

    var agg_sig = Self{};
    c.blst_p2_from_affine(&agg_sig.point, &sigs[0].point);
    for (1..sigs.len) |i| {
        c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &sigs[i].point);
    }

    return agg_sig;
}

/// Aggregates multiple signatures using multi-scalar multiplication with randomness.
///
/// Errors if scratch space is insufficient, or if any signature validation fails.
///
/// Returns the `AggregateSignature` on success.
pub fn aggregateWithRandomness(
    sigs: []*const Signature,
    randomness: []const u8,
    sigs_groupcheck: bool,
    scratch: []u64,
) BlstError!Self {
    if (sigs_groupcheck) for (sigs) |sig| try sig.validate(false);
    if (scratch.len < c.blst_p2s_mult_pippenger_scratch_sizeof(sigs.len)) {
        return BlstError.AggrTypeMismatch;
    }

    var scalars_refs: [MAX_AGGREGATE_PER_JOB]*const u8 = undefined;
    for (0..sigs.len) |i| scalars_refs[i] = &randomness[i * 32];

    var agg_sig = Self{};

    c.blst_p2s_mult_pippenger(
        &agg_sig.point,
        @ptrCast(sigs[0..sigs.len].ptr),
        sigs.len,
        scalars_refs[0..sigs.len].ptr,
        64,
        scratch.ptr,
    );
    return agg_sig;
}

test aggregateWithRandomness {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const dst = DST;
    // aug is null

    const num_sigs = MAX_AGGREGATE_PER_JOB;

    var msgs: [num_sigs][32]u8 = undefined;
    var sks: [num_sigs]SecretKey = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;

    const m = c.blst_p2s_mult_pippenger_scratch_sizeof(num_sigs) * 64;
    const allocator = std.testing.allocator;
    var scratch = try std.testing.allocator.alloc(u64, m);
    defer allocator.free(scratch);

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();
    std.Random.bytes(rand, &msgs[0]);
    for (0..num_sigs) |i| {
        const msg = msgs[0];
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const sig = sk.sign(&msg, dst, null);

        sks[i] = sk;
        pks[i] = pk;
        sigs[i] = sig;
        msgs[i] = msg;
        try sig.verify(true, &msgs[i], dst, null, &pks[i], true);
    }
    var rands: [32 * MAX_AGGREGATE_PER_JOB]u8 = [_]u8{0} ** (32 * MAX_AGGREGATE_PER_JOB);
    var sigs_refs: [MAX_AGGREGATE_PER_JOB]*const Signature = undefined;
    var pks_refs: [MAX_AGGREGATE_PER_JOB]*const PublicKey = undefined;
    std.Random.bytes(rand, &rands);

    for (0..num_sigs) |i| {
        sigs_refs[i] = &sigs[i];
        pks_refs[i] = &pks[i];
    }

    const agg_pk = try AggregatePublicKey.aggregateWithRandomness(pks_refs[0..], &rands, true, scratch[0..]);
    const pk = agg_pk.toPublicKey();
    const agg_sig = try aggregateWithRandomness(
        &sigs_refs,
        &rands,
        true,
        scratch[0..],
    );
    const sig = agg_sig.toSignature();
    try sig.verify(true, &msgs[0], dst, null, &pk, true);
}
const std = @import("std");
const c = @cImport({
    @cInclude("blst.h");
});

const BlstError = @import("error.zig").BlstError;
const blst = @import("root.zig");
const Signature = blst.Signature;
const SecretKey = @import("SecretKey.zig");
const PublicKey = @import("root.zig").PublicKey;
const AggregatePublicKey = @import("AggregatePublicKey.zig");
const DST = blst.DST;
const MAX_AGGREGATE_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;
