/// Number of random bytes used for verification.
const RAND_BYTES = 8;

/// Number of random bits used for verification.
const RAND_BITS = 8 * RAND_BYTES;

/// Verify multiple aggregate signatures efficiently using random coefficients.
///
/// Source: https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
///
/// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
pub fn verifyMultipleAggregateSignatures(
    pairing_buf: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
) BlstError!bool {
    if (n_elems == 0) {
        return BlstError.VerifyFail;
    }

    var pairing = Pairing.init(
        pairing_buf,
        true,
        dst,
    );

    for (0..n_elems) |i| {
        try pairing.mulAndAggregate(
            pks[i],
            pks_validate,
            sigs[i],
            sigs_groupcheck,
            &rands[i],
            RAND_BITS,
            &msgs[i],
        );
    }

    pairing.commit();

    return pairing.finalVerify(null);
}

const BlstError = @import("error.zig").BlstError;
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
