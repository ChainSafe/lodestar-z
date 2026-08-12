//! Dependency-injected BLS verification by validator index.
//!
//! Composes the pubkey cache (key resolution) with the BLS thread pool
//! (batch verification) so callers hand over signature-set descriptors that
//! reference validators by index instead of materialized public keys. No
//! globals: the NAPI layer wires in the process-wide singletons; tests and
//! the future Zig-native node construct their own cache and pool.
//!
//! Error contract (mirrors Lodestar's maybeBatch semantics so gossip peer
//! scoring is unchanged):
//! - empty input, malformed/invalid signatures, invalid raw public keys,
//!   unknown validator indices, and failed verification all return `false`;
//! - malformed caller input that cannot come from the wire (wrong message
//!   length) is an error;
//! - infrastructure failures (allocation, pool shutdown, cancellation)
//!   propagate as errors and must not be scored against a peer.
//!
//! Cache lifecycle: production populates the cache (syncPubkeys/load) before
//! verification traffic starts; reset/clear is test-only under external
//! exclusion.

const std = @import("std");
const bls = @import("bls");
const PubkeyCache = @import("../cache/pubkey_cache.zig").PubkeyCache;

const ThreadPool = bls.ThreadPool;
const BatchVerifyItem = bls.BatchVerifyItem;

/// Bytes of each random coefficient that are actually used (matches
/// fast_verify's RAND_BITS = 64).
const rand_bytes = 8;

/// A signer whose key is NOT in the validator registry, so the key rides in
/// the message itself: deposit signatures (the validator does not exist
/// yet), BLS-to-execution changes (`from_bls_pubkey` was never a validator
/// key), and Gloas builder signatures (builder registry, not validator
/// registry).
pub const SingleSet = struct {
    /// 48-byte compressed public key from the message. Attacker-controlled,
    /// so it is group-checked at verification time — unlike registry keys,
    /// which were validated once at deposit processing.
    public_key: []const u8,
    /// 32-byte signing root (message hash, already domain-separated).
    message: []const u8,
    /// 96-byte compressed BLS signature.
    signature: []const u8,
};

/// One registry validator signed: block proposer signature, RANDAO reveal,
/// voluntary exit, sync-committee message, aggregator selection proof. The
/// key is resolved from the pubkey cache by validator index.
pub const IndexedSet = struct {
    /// Validator index into the registry / pubkey cache. May be
    /// attacker-influenced on gossip paths: an unknown index fails
    /// verification (`false`) rather than erroring.
    index: u64,
    /// 32-byte signing root.
    message: []const u8,
    /// 96-byte compressed BLS signature.
    signature: []const u8,
};

/// Many registry validators co-signed one message: attestations
/// (`attesting_indices`), sync aggregates, attester slashings. Verification
/// needs the sum of the signers' keys, so the aggregation happens here, from
/// the cache, rather than in the caller.
pub const AggregateSet = struct {
    /// Validator indices of every participant. Duplicates are legal and add
    /// the key once per occurrence (the signature must match). Empty fails
    /// verification (`false`).
    indices: []const u32,
    /// 32-byte signing root all participants signed.
    message: []const u8,
    /// 96-byte compressed aggregate of the participants' signatures.
    signature: []const u8,
};

/// One verifiable signature set, discriminated by where the signer's key
/// lives. Mirrors Lodestar's `ISignatureSet`: the two registry-backed
/// variants carry indices (resolved here); `single` carries the key itself.
pub const VerifySet = union(enum) {
    single: SingleSet,
    indexed: IndexedSet,
    aggregate: AggregateSet,
};

/// One signer in a same-message batch: many validators independently signed
/// the SAME 32-byte signing root (unaggregated attestations from one subnet
/// sharing identical attestation data). The shared message is passed once to
/// `verifySameMessageSets`, so each set carries only its signer and
/// signature.
pub const SameMessageSet = struct {
    /// Validator index; same unknown-index semantics as `IndexedSet.index`.
    index: u64,
    /// 96-byte compressed BLS signature over the shared message.
    signature: []const u8,
};

/// Batch-verify heterogeneous signature sets. One boolean for the whole
/// batch; callers needing attribution retry at their own request boundary.
pub fn verifyIndexedSets(
    allocator: std.mem.Allocator,
    io: std.Io,
    cache: *const PubkeyCache,
    pool: *ThreadPool,
    sets: []const VerifySet,
) !bool {
    if (sets.len == 0) return false;

    const pks = try allocator.alloc(bls.PublicKey, sets.len);
    defer allocator.free(pks);
    const sigs = try allocator.alloc(bls.Signature, sets.len);
    defer allocator.free(sigs);
    const items = try allocator.alloc(BatchVerifyItem, sets.len);
    defer allocator.free(items);

    // Positions of `indexed` sets, resolved in one batch below so the whole
    // batch takes the cache's shared lock once instead of once per set.
    const indexed_positions = try allocator.alloc(usize, sets.len);
    defer allocator.free(indexed_positions);
    const indexed_indices = try allocator.alloc(u64, sets.len);
    defer allocator.free(indexed_indices);
    var indexed_count: usize = 0;

    // Scratch for widening aggregate indices to the cache's u64 API.
    var widen: std.ArrayList(u64) = .empty;
    defer widen.deinit(allocator);

    for (sets, 0..) |set, i| {
        const message = switch (set) {
            inline else => |s| s.message,
        };
        if (message.len != 32) return error.InvalidMessageLength;

        const signature = switch (set) {
            inline else => |s| s.signature,
        };
        sigs[i] = bls.Signature.uncompress(signature) catch return false;
        sigs[i].validate(true) catch return false;

        switch (set) {
            .single => |s| {
                if (s.public_key.len != 48) return false;
                pks[i] = bls.PublicKey.uncompress(s.public_key) catch return false;
                pks[i].validate() catch return false;
            },
            .indexed => |s| {
                indexed_positions[indexed_count] = i;
                indexed_indices[indexed_count] = s.index;
                indexed_count += 1;
            },
            .aggregate => |s| {
                if (s.indices.len == 0) return false;
                widen.clearRetainingCapacity();
                try widen.ensureTotalCapacity(allocator, s.indices.len);
                for (s.indices) |index| widen.appendAssumeCapacity(index);
                pks[i] = cache.aggregate(io, widen.items) catch |err| switch (err) {
                    error.InvalidIndex, error.InvalidLength => return false,
                };
            },
        }

        items[i] = .{
            .message = message[0..32].*,
            .public_key = &pks[i],
            .signature = &sigs[i],
            .randomness = undefined,
        };
    }

    // Resolve every indexed set's key under one shared-lock acquisition.
    // getPubkeys writes contiguously; scatter into batch positions after.
    if (indexed_count > 0) {
        const contiguous = try allocator.alloc(bls.PublicKey, indexed_count);
        defer allocator.free(contiguous);
        cache.getPubkeys(io, indexed_indices[0..indexed_count], contiguous) catch |err| switch (err) {
            error.InvalidIndex => return false,
            error.InvalidLength => unreachable, // lengths match by construction
        };
        for (indexed_positions[0..indexed_count], contiguous) |position, pk| {
            pks[position] = pk;
        }
    }

    fillRandomness(io, items);

    // pks_validate=false: registry keys were group-checked at deposit and
    // `single` keys were validated above. sigs_groupcheck=false: validated
    // at deserialization above.
    return pool.verifyMultipleAggregateSignatures(io, items, bls.DST, false, false) catch |err| switch (err) {
        error.VerifyFail => false,
        else => |infra| infra,
    };
}

/// Fused same-message verification: aggregate `(pk_i, sig_i)` pairs with
/// per-set random coefficients (multi-scalar multiplication on G1 and G2),
/// then verify the single aggregate pair against `message`. One boolean for
/// the batch; on `false`, callers retry per set for ordered attribution.
pub fn verifySameMessageSets(
    allocator: std.mem.Allocator,
    io: std.Io,
    cache: *const PubkeyCache,
    pool: *ThreadPool,
    message: []const u8,
    sets: []const SameMessageSet,
) !bool {
    if (sets.len == 0) return false;
    if (message.len != 32) return error.InvalidMessageLength;

    const pks = try allocator.alloc(bls.PublicKey, sets.len);
    defer allocator.free(pks);
    const sigs = try allocator.alloc(bls.Signature, sets.len);
    defer allocator.free(sigs);
    const indices = try allocator.alloc(u64, sets.len);
    defer allocator.free(indices);

    for (sets, 0..) |set, i| {
        indices[i] = set.index;
        sigs[i] = bls.Signature.uncompress(set.signature) catch return false;
        sigs[i].validate(true) catch return false;
    }

    // One shared-lock acquisition for the whole batch.
    cache.getPubkeys(io, indices, pks) catch |err| switch (err) {
        error.InvalidIndex => return false,
        error.InvalidLength => unreachable, // lengths match by construction
    };

    // Randomized aggregation: Pippenger MSM over keys (G1) and sigs (G2)
    // with the same per-set scalars, as in fast BLS batch verification.
    const pk_ptrs = try allocator.alloc(*const bls.c.blst_p1_affine, sets.len);
    defer allocator.free(pk_ptrs);
    const sig_ptrs = try allocator.alloc(*const bls.c.blst_p2_affine, sets.len);
    defer allocator.free(sig_ptrs);
    const scalars = try allocator.alloc(u8, sets.len * rand_bytes);
    defer allocator.free(scalars);
    const scalar_ptrs = try allocator.alloc(*const u8, sets.len);
    defer allocator.free(scalar_ptrs);

    io.random(scalars);
    for (0..sets.len) |i| {
        pk_ptrs[i] = &pks[i].point;
        sig_ptrs[i] = &sigs[i].point;
        const scalar = scalars[i * rand_bytes ..][0..rand_bytes];
        ensureNonzero(io, scalar);
        scalar_ptrs[i] = &scalars[i * rand_bytes];
    }

    const scratch_size = @max(
        bls.c.blst_p1s_mult_pippenger_scratch_sizeof(sets.len),
        bls.c.blst_p2s_mult_pippenger_scratch_sizeof(sets.len),
    );
    const scratch = try allocator.alloc(u64, @divExact(scratch_size, @sizeOf(u64)));
    defer allocator.free(scratch);

    var p1: bls.c.blst_p1 = std.mem.zeroes(bls.c.blst_p1);
    bls.c.blst_p1s_mult_pippenger(&p1, @ptrCast(pk_ptrs.ptr), sets.len, @ptrCast(scalar_ptrs.ptr), rand_bytes * 8, scratch.ptr);
    var aggregate_pk: bls.PublicKey = .{};
    bls.c.blst_p1_to_affine(&aggregate_pk.point, &p1);

    var p2: bls.c.blst_p2 = std.mem.zeroes(bls.c.blst_p2);
    bls.c.blst_p2s_mult_pippenger(&p2, @ptrCast(sig_ptrs.ptr), sets.len, @ptrCast(scalar_ptrs.ptr), rand_bytes * 8, scratch.ptr);
    var aggregate_sig: bls.Signature = .{};
    bls.c.blst_p2_to_affine(&aggregate_sig.point, &p2);

    var items = [_]BatchVerifyItem{.{
        .message = message[0..32].*,
        .public_key = &aggregate_pk,
        .signature = &aggregate_sig,
        .randomness = undefined,
    }};
    fillRandomness(io, &items);

    return pool.verifyMultipleAggregateSignatures(io, &items, bls.DST, false, false) catch |err| switch (err) {
        error.VerifyFail => false,
        else => |infra| infra,
    };
}

fn fillRandomness(io: std.Io, items: []BatchVerifyItem) void {
    for (items) |*item| {
        @memset(item.randomness[rand_bytes..], 0);
        io.random(item.randomness[0..rand_bytes]);
        ensureNonzero(io, item.randomness[0..rand_bytes]);
    }
}

/// A zero coefficient would erase its set from the batch check; redraw until
/// nonzero (probability of even one redraw is ~2^-64).
fn ensureNonzero(io: std.Io, scalar: []u8) void {
    while (std.mem.allEqual(u8, scalar, 0)) {
        io.random(scalar);
    }
}
