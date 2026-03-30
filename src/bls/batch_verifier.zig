//! Batch BLS signature verifier for block import and gossip pipelines.
//!
//! ## Design
//!
//! Block processing collects signature sets (proposer, randao, attestations,
//! voluntary exits, slashings, sync committee, BLS-to-execution changes) into
//! this verifier instead of verifying each one inline.  After all operations
//! are processed, `verifyAll()` batch-verifies everything in one shot using
//! `verifyMultipleAggregateSignatures` with random scalars (ethresear.ch fast
//! verification).
//!
//! ### Same-message optimization
//!
//! Attestations within a block often share the same signing root (same source,
//! target, head vote). When N attestations share a message, Pippenger
//! multi-scalar multiplication combines all N pubkeys+sigs with random scalars
//! into a single pairing check — O(N/log N) group operations instead of O(N).
//! This is the **key** performance optimization: typical mainnet blocks have
//! 64-128 attestations, most sharing one of ~2-4 distinct messages.
//!
//! ### Memory strategy
//!
//! All buffers are stack-allocated with comptime-known max sizes:
//! - MAX_SETS_PER_BLOCK = 256 covers the worst case (128 attestations +
//!   128 other operations like slashings, exits, etc.)
//! - Zero heap allocation on the sync path
//! - Aggregate pubkey resolution is done at verification time
//!
//! ### Thread pool integration
//!
//! When a `ThreadPool` is provided, the final `verifyMultipleAggregateSignatures`
//! call is dispatched to the pool for parallel execution.  When null, falls
//! back to single-threaded verification.

const std = @import("std");
const bls = @import("root.zig");
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const BlstError = bls.BlstError;
const Pairing = bls.Pairing;
const ThreadPool = bls.ThreadPool;
const SignatureSet = @import("signature_set.zig").SignatureSet;
const fast_verify = @import("fast_verify.zig");

/// Maximum signature sets per block. Worst case:
/// - 1 proposer + 1 randao + 128 attestations + 16 attester slashings (×2 indexed attestations each = 32)
/// - + 16 proposer slashings (×2 = 32) + 16 voluntary exits + 16 BLS changes + 1 sync committee = 227
/// Round up to 256 for safety.
pub const MAX_SETS_PER_BLOCK: usize = 256;

pub const BatchVerifier = struct {
    /// Collected signature sets, stack-allocated.
    sets: [MAX_SETS_PER_BLOCK]SignatureSet = undefined,
    /// Number of sets currently buffered.
    count: usize = 0,
    /// Optional thread pool for parallel verification.
    thread_pool: ?*ThreadPool = null,

    /// Create a batch verifier, optionally backed by a thread pool.
    pub fn init(thread_pool: ?*ThreadPool) BatchVerifier {
        return .{ .thread_pool = thread_pool };
    }

    /// Queue a signature set for later batch verification.
    /// Returns error if the buffer is full.
    pub fn addSet(self: *BatchVerifier, set: SignatureSet) error{BatchVerifierFull}!void {
        if (self.count >= MAX_SETS_PER_BLOCK) return error.BatchVerifierFull;
        self.sets[self.count] = set;
        self.count += 1;
    }

    /// Queue a single-pubkey signature set.
    pub fn addSingle(self: *BatchVerifier, pubkey: PublicKey, signing_root: [32]u8, signature: [96]u8) error{BatchVerifierFull}!void {
        try self.addSet(SignatureSet.initSingle(pubkey, signing_root, signature));
    }

    /// Queue an aggregate-pubkey signature set.
    pub fn addAggregate(self: *BatchVerifier, pubkeys: []const PublicKey, signing_root: [32]u8, signature: [96]u8) error{BatchVerifierFull}!void {
        try self.addSet(SignatureSet.initAggregate(pubkeys, signing_root, signature));
    }

    /// Reset the verifier for reuse.
    pub fn reset(self: *BatchVerifier) void {
        self.count = 0;
    }

    /// Batch-verify all collected signature sets.
    ///
    /// Returns true if ALL signatures are valid, false if any is invalid.
    /// Empty batch returns true (vacuous truth — no signatures to reject).
    ///
    /// This resolves aggregate pubkeys, decompresses signatures, generates
    /// random scalars, and calls verifyMultipleAggregateSignatures for a
    /// single multi-pairing check.
    pub fn verifyAll(self: *BatchVerifier) BlstError!bool {
        const n = self.count;
        if (n == 0) return true;

        // Resolve all pubkeys and decompress all signatures
        var resolved_pks: [MAX_SETS_PER_BLOCK]PublicKey = undefined;
        var resolved_sigs: [MAX_SETS_PER_BLOCK]Signature = undefined;
        var msgs: [MAX_SETS_PER_BLOCK][32]u8 = undefined;
        var pk_ptrs: [MAX_SETS_PER_BLOCK]*PublicKey = undefined;
        var sig_ptrs: [MAX_SETS_PER_BLOCK]*Signature = undefined;

        for (0..n) |i| {
            resolved_pks[i] = try self.sets[i].resolvePublicKey();
            resolved_sigs[i] = try self.sets[i].decompressSignature();
            msgs[i] = self.sets[i].signing_root;
            pk_ptrs[i] = &resolved_pks[i];
            sig_ptrs[i] = &resolved_sigs[i];
        }

        // Generate random scalars for fast verification
        var rands: [MAX_SETS_PER_BLOCK][32]u8 = undefined;
        fillRandomScalars(rands[0..n]);

        // Dispatch to thread pool if available, otherwise single-threaded
        if (self.thread_pool) |pool| {
            return pool.verifyMultipleAggregateSignatures(
                n,
                msgs[0..n],
                bls.DST,
                pk_ptrs[0..n],
                false, // pubkeys already validated from cache
                sig_ptrs[0..n],
                true, // signatures from wire, must group-check
                rands[0..n],
            );
        } else {
            var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
            return fast_verify.verifyMultipleAggregateSignatures(
                &pairing_buf,
                n,
                msgs[0..n],
                bls.DST,
                pk_ptrs[0..n],
                false,
                sig_ptrs[0..n],
                true,
                rands[0..n],
            );
        }
    }

    /// Returns the number of queued signature sets.
    pub fn len(self: *const BatchVerifier) usize {
        return self.count;
    }
};

/// Fill random scalars for batch verification.
/// Uses OS entropy for cryptographic security (random scalars must be
/// unpredictable to prevent rogue-key attacks on the batch).
///
/// C-bls fix: use std.crypto.random as the primary path for all platforms.
/// std.crypto.random is backed by the OS CSPRNG (getrandom on Linux,
/// SecRandomCopyBytes on macOS, etc.) and is correct on all Zig targets.
/// The previous hand-rolled platform dispatch was fragile; the ASLR-seeded
/// ChaCha fallback provided only ~40 bits of entropy — cryptographically weak.
fn fillRandomScalars(rands: [][32]u8) void {
    const bytes = std.mem.sliceAsBytes(rands);
    std.Options.debug_io.random(bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "batch verifier: empty batch returns true" {
    var bv = BatchVerifier.init(null);
    try std.testing.expect(try bv.verifyAll());
}

test "batch verifier: single valid signature" {
    const SecretKey = @import("SecretKey.zig");
    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();
    const msg = [_]u8{0xAA} ** 32;
    const sig = sk.sign(&msg, bls.DST, null);
    const sig_bytes = sig.compress();

    var bv = BatchVerifier.init(null);
    try bv.addSingle(pk, msg, sig_bytes);
    try std.testing.expect(try bv.verifyAll());
}

test "batch verifier: single invalid signature" {
    const SecretKey = @import("SecretKey.zig");
    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();
    const msg = [_]u8{0xAA} ** 32;
    const wrong_msg = [_]u8{0xBB} ** 32;
    const sig = sk.sign(&wrong_msg, bls.DST, null); // Sign wrong message
    const sig_bytes = sig.compress();

    var bv = BatchVerifier.init(null);
    try bv.addSingle(pk, msg, sig_bytes);
    try std.testing.expect(!try bv.verifyAll());
}

test "batch verifier: multiple valid signatures" {
    const SecretKey = @import("SecretKey.zig");
    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var bv = BatchVerifier.init(null);
    const num_sigs = 8;

    var pks: [num_sigs]PublicKey = undefined;
    var sig_bytes: [num_sigs][96]u8 = undefined;
    var msgs: [num_sigs][32]u8 = undefined;

    for (0..num_sigs) |i| {
        var ikm = base_ikm;
        ikm[0] = @intCast(i);
        msgs[i] = [_]u8{@intCast(i + 1)} ** 32;
        const sk = try SecretKey.keyGen(&ikm, null);
        pks[i] = sk.toPublicKey();
        const sig = sk.sign(&msgs[i], bls.DST, null);
        sig_bytes[i] = sig.compress();
        try bv.addSingle(pks[i], msgs[i], sig_bytes[i]);
    }

    try std.testing.expect(try bv.verifyAll());
}

test "batch verifier: mixed single + aggregate sets" {
    const SecretKey = @import("SecretKey.zig");
    const AggregateSignature = bls.AggregateSignature;
    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var bv = BatchVerifier.init(null);

    // Add a single signature set
    const sk0 = try SecretKey.keyGen(&base_ikm, null);
    const pk0 = sk0.toPublicKey();
    const msg0 = [_]u8{0x01} ** 32;
    const sig0 = sk0.sign(&msg0, bls.DST, null);
    try bv.addSingle(pk0, msg0, sig0.compress());

    // Add an aggregate signature set (3 signers, same message)
    const agg_msg = [_]u8{0x02} ** 32;
    var agg_pks: [3]PublicKey = undefined;
    var agg_sigs: [3]Signature = undefined;
    for (0..3) |i| {
        var ikm = base_ikm;
        ikm[0] = @intCast(i + 10);
        const sk = try SecretKey.keyGen(&ikm, null);
        agg_pks[i] = sk.toPublicKey();
        agg_sigs[i] = sk.sign(&agg_msg, bls.DST, null);
    }
    const agg_sig = try AggregateSignature.aggregate(&agg_sigs, false);
    const final_sig = agg_sig.toSignature();
    try bv.addAggregate(&agg_pks, agg_msg, final_sig.compress());

    try std.testing.expect(try bv.verifyAll());
    try std.testing.expectEqual(@as(usize, 2), bv.len());
}

test "batch verifier: same-message attestations" {
    // Simulate multiple attestations with the same signing root (same vote)
    const SecretKey = @import("SecretKey.zig");
    const AggregateSignature = bls.AggregateSignature;
    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var bv = BatchVerifier.init(null);

    // All attestations share the same signing root
    const shared_msg = [_]u8{0xFF} ** 32;

    // Create 16 "attestation" signature sets, each with 2-4 validators
    var all_pks: [64]PublicKey = undefined;
    var pk_idx: usize = 0;

    for (0..16) |att_idx| {
        const n_validators: usize = 2 + (att_idx % 3); // 2, 3, or 4 validators
        const start = pk_idx;

        var sigs_for_agg: [4]Signature = undefined;
        for (0..n_validators) |v| {
            var ikm = base_ikm;
            ikm[0] = @intCast(pk_idx & 0xFF);
            ikm[1] = @intCast((pk_idx >> 8) & 0xFF);
            const sk = try SecretKey.keyGen(&ikm, null);
            all_pks[pk_idx] = sk.toPublicKey();
            sigs_for_agg[v] = sk.sign(&shared_msg, bls.DST, null);
            pk_idx += 1;
        }

        const agg_sig = try AggregateSignature.aggregate(sigs_for_agg[0..n_validators], false);
        const final_sig = agg_sig.toSignature();
        try bv.addAggregate(all_pks[start..pk_idx], shared_msg, final_sig.compress());
    }

    try std.testing.expectEqual(@as(usize, 16), bv.len());
    try std.testing.expect(try bv.verifyAll());
}

test "batch verifier: one bad sig in batch fails all" {
    const SecretKey = @import("SecretKey.zig");
    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var bv = BatchVerifier.init(null);

    // Add 3 valid signatures
    for (0..3) |i| {
        var ikm = base_ikm;
        ikm[0] = @intCast(i);
        const msg = [_]u8{@intCast(i + 1)} ** 32;
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const sig = sk.sign(&msg, bls.DST, null);
        try bv.addSingle(pk, msg, sig.compress());
    }

    // Add 1 invalid signature (wrong message)
    {
        var ikm = base_ikm;
        ikm[0] = 99;
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const msg = [_]u8{0xDD} ** 32;
        const wrong_msg = [_]u8{0xEE} ** 32;
        const sig = sk.sign(&wrong_msg, bls.DST, null);
        try bv.addSingle(pk, msg, sig.compress());
    }

    try std.testing.expect(!try bv.verifyAll());
}

test "batch verifier: reset and reuse" {
    const SecretKey = @import("SecretKey.zig");
    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var bv = BatchVerifier.init(null);
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();
    const msg = [_]u8{0x01} ** 32;
    const sig = sk.sign(&msg, bls.DST, null);
    try bv.addSingle(pk, msg, sig.compress());

    try std.testing.expectEqual(@as(usize, 1), bv.len());
    try std.testing.expect(try bv.verifyAll());

    bv.reset();
    try std.testing.expectEqual(@as(usize, 0), bv.len());
    try std.testing.expect(try bv.verifyAll()); // Empty batch = true
}

test "batch verifier: with thread pool" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 2 });
    defer pool.deinit();

    const SecretKey = @import("SecretKey.zig");
    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var bv = BatchVerifier.init(pool);
    const num_sigs = 16;

    var pks: [num_sigs]PublicKey = undefined;
    var sig_bytes_arr: [num_sigs][96]u8 = undefined;
    var msgs: [num_sigs][32]u8 = undefined;

    for (0..num_sigs) |i| {
        var ikm = base_ikm;
        ikm[0] = @intCast(i);
        msgs[i] = [_]u8{@intCast(i + 1)} ** 32;
        const sk = try SecretKey.keyGen(&ikm, null);
        pks[i] = sk.toPublicKey();
        const sig = sk.sign(&msgs[i], bls.DST, null);
        sig_bytes_arr[i] = sig.compress();
        try bv.addSingle(pks[i], msgs[i], sig_bytes_arr[i]);
    }

    try std.testing.expect(try bv.verifyAll());
}
