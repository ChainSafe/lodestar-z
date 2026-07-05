//! Verifies every BLS signature across `blocks` against `pre_state0`, in one
//! batched call to `bls.ThreadPool.verifyMultipleAggregateSignatures`. Companion
//! to `verifyBlocksStateTransitionOnly(use_bls_batch_verify=true)` — the state
//! transition trusts signatures on the assumption that this function runs (in
//! parallel with STF) and rejects the batch on any invalid signature.
//!
//! Caller contract (matches TS `verifyBlocksSignatures.ts`):
//! all `blocks` MUST belong to the same epoch as `pre_state0`. `getBlockSignatureSets`
//! derives signing roots from `pre_state0`'s epoch cache (proposer shuffling,
//! sync-committee membership at Altair+), so crossing an epoch boundary — and
//! especially a sync-committee period boundary — produces wrong signing roots.

const std = @import("std");
const time = @import("time");
const st = @import("state_transition");
const bls = @import("bls");

const CachedBeaconState = st.CachedBeaconState;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;

pub const VerifyBlocksSignaturesOpts = struct {
    /// When true, every signature is trusted; the function returns immediately.
    valid_signatures: bool = false,
    /// When true, the proposer signature per block is trusted (operation
    /// signatures still verified).
    valid_proposer_signature: bool = false,
};

pub const VerifyBlocksSignaturesResult = struct {
    /// Wall-clock unix milliseconds captured at the moment verification finished.
    verify_signatures_finished_at_ms: u64,
};

pub fn verifyBlocksSignatures(
    allocator: std.mem.Allocator,
    io: std.Io,
    bls_pool: *bls.ThreadPool,
    pre_state0: *CachedBeaconState,
    blocks: []const AnySignedBeaconBlock,
    opts: VerifyBlocksSignaturesOpts,
    /// On `error.InvalidBlockSignature`, this is written with the index of the
    /// first failing block. Pass `null` if the identity of the offender is not
    /// needed.
    invalid_block_index_out: ?*u32,
) !VerifyBlocksSignaturesResult {
    std.debug.assert(blocks.len > 0);

    if (opts.valid_signatures) {
        return .{ .verify_signatures_finished_at_ms = time.nowMs(io) };
    }

    var per_block_sets = try allocator.alloc(st.BlockSignatureSets, blocks.len);
    for (per_block_sets) |*s| s.* = .empty;
    defer {
        for (per_block_sets) |*s| s.deinit(allocator);
        allocator.free(per_block_sets);
    }

    for (blocks, 0..) |signed_block, i| {
        try st.getBlockSignatureSets(
            allocator,
            pre_state0,
            signed_block,
            .{ .skip_proposer_signature = opts.valid_proposer_signature },
            &per_block_sets[i],
        );
    }

    if (try batchVerify(allocator, io, bls_pool, per_block_sets)) {
        try io.checkCancel();
        return .{ .verify_signatures_finished_at_ms = time.nowMs(io) };
    }

    const offender = try findInvalidBlockSequential(per_block_sets);
    if (invalid_block_index_out) |p| p.* = @intCast(offender);
    return error.InvalidBlockSignature;
}

/// Flattens every set across `per_block_sets` into `(pk, sig, msg)` triples,
/// aggregates multi-pubkey sets into a single pubkey, and feeds the whole batch
/// to `bls.ThreadPool.verifyMultipleAggregateSignatures`. Returns `false` when
/// the aggregate check fails; a `BlstError` propagates on structurally invalid
/// signature/pubkey bytes.
fn batchVerify(
    allocator: std.mem.Allocator,
    io: std.Io,
    bls_pool: *bls.ThreadPool,
    per_block_sets: []st.BlockSignatureSets,
) !bool {
    var total: usize = 0;
    for (per_block_sets) |sets| total += sets.single.items.len + sets.aggregated.items.len;
    if (total == 0) return true;

    const pks = try allocator.alloc(PublicKey, total);
    defer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, total);
    defer allocator.free(sigs);
    const pk_ptrs = try allocator.alloc(*PublicKey, total);
    defer allocator.free(pk_ptrs);
    const sig_ptrs = try allocator.alloc(*Signature, total);
    defer allocator.free(sig_ptrs);
    const msgs = try allocator.alloc([]const u8, total);
    defer allocator.free(msgs);
    const rands = try allocator.alloc([32]u8, total);
    defer allocator.free(rands);

    io.random(std.mem.sliceAsBytes(rands));

    var k: usize = 0;
    for (per_block_sets) |*sets| {
        for (sets.single.items) |*set| {
            pks[k] = set.pubkey;
            sigs[k] = try Signature.uncompress(&set.signature);
            pk_ptrs[k] = &pks[k];
            sig_ptrs[k] = &sigs[k];
            msgs[k] = set.signing_root[0..];
            k += 1;
        }
        for (sets.aggregated.items) |*set| {
            const agg_pk = try bls.AggregatePublicKey.aggregate(set.pubkeys, false);
            pks[k] = agg_pk.toPublicKey();
            sigs[k] = try Signature.uncompress(&set.signature);
            pk_ptrs[k] = &pks[k];
            sig_ptrs[k] = &sigs[k];
            msgs[k] = set.signing_root[0..];
            k += 1;
        }
    }
    std.debug.assert(k == total);

    return bls_pool.verifyMultipleAggregateSignatures(
        io,
        total,
        msgs,
        bls.DST,
        pk_ptrs,
        false,
        sig_ptrs,
        true,
        rands,
    );
}

/// Sequentially verifies each block's sets until one returns false. Returns the
/// offending block index. Called only after `batchVerify` reported failure, so
/// exactly one block is expected to fail.
fn findInvalidBlockSequential(per_block_sets: []st.BlockSignatureSets) !usize {
    for (per_block_sets, 0..) |sets, i| {
        for (sets.single.items) |*set| {
            if (!try st.verifySingleSignatureSet(set)) return i;
        }
        for (sets.aggregated.items) |*set| {
            if (!try st.verifyAggregatedSignatureSet(set)) return i;
        }
    }
    return error.NoInvalidBlockFound;
}

const testing = std.testing;
const types = @import("consensus_types");
const Node = @import("persistent_merkle_tree").Node;
const constants = @import("constants");

fn setupTestState(allocator: std.mem.Allocator, pool: *Node.Pool) !st.test_utils.TestCachedBeaconState {
    return try st.test_utils.TestCachedBeaconState.init(allocator, pool, 256);
}

fn initTestPool(io: std.Io) !*bls.ThreadPool {
    return try bls.ThreadPool.init(testing.allocator, io, .{ .n_workers = 2 });
}

/// Signs RANDAO reveal and the proposer signature with the interop secret key
/// of `proposer_index`. All other operation signatures are left at their (invalid)
/// defaults; the caller must clear the operation lists and set the sync-aggregate
/// signature to `G2_POINT_AT_INFINITY`.
fn signBlockInterop(
    allocator: std.mem.Allocator,
    cached_state: *const st.CachedBeaconState,
    signed_block: *types.electra.SignedBeaconBlock.Type,
    proposer_index: u64,
) !void {
    const config = cached_state.config;
    const epoch_cache = cached_state.epoch_cache;
    const block_slot = signed_block.message.slot;
    const block_epoch = st.computeEpochAtSlot(block_slot);

    // Domains must be resolved with `epoch_cache.epoch` (not `block_epoch`) to match
    // `signature_sets/proposer.zig` and `signature_sets/randao.zig`, which both use
    // the epoch cache's epoch. Signing with a different epoch would produce a
    // signing root that the aggregator can't verify.
    const domain_randao = try config.getDomain(epoch_cache.epoch, constants.DOMAIN_RANDAO, block_slot);
    var randao_signing_root: [32]u8 = undefined;
    try st.computeSigningRoot(types.primitive.Epoch, &block_epoch, domain_randao, &randao_signing_root);
    const randao_sig = try st.test_utils.interopSign(proposer_index, &randao_signing_root);
    signed_block.message.body.randao_reveal = randao_sig.compress();

    const domain_proposer = try config.getDomain(epoch_cache.epoch, constants.DOMAIN_BEACON_PROPOSER, block_slot);
    var block_signing_root: [32]u8 = undefined;
    const any_block = @import("fork_types").AnyBeaconBlock{ .full_electra = &signed_block.message };
    try st.computeBlockSigningRoot(allocator, any_block, domain_proposer, &block_signing_root);
    const proposer_sig = try st.test_utils.interopSign(proposer_index, &block_signing_root);
    signed_block.signature = proposer_sig.compress();
}

/// Constructs a minimally-populated Electra block at slot `pre_slot + slot_offset`,
/// validly signed by the correct interop proposer for that slot. `parent_root`,
/// when non-null, is used verbatim; otherwise the pre-state's latest-header root is
/// used (which is only correct for the first block in a chain).
///
/// Every operation list is left empty; sync aggregate is `G2_POINT_AT_INFINITY`.
/// Caller owns the block and must invoke `types.electra.SignedBeaconBlock.deinit`.
fn buildValidElectraBlock(
    allocator: std.mem.Allocator,
    cached_state: *st.CachedBeaconState,
    slot_offset: u64,
    parent_root: ?*const [32]u8,
    out: *types.electra.SignedBeaconBlock.Type,
) !void {
    out.* = types.electra.SignedBeaconBlock.default_value;
    const pre_slot = try cached_state.state.slot();
    const block_slot = pre_slot + slot_offset;
    out.message.slot = block_slot;

    if (parent_root) |p| {
        out.message.parent_root = p.*;
    } else {
        var latest_header_view = try cached_state.state.latestBlockHeader();
        out.message.parent_root = (try latest_header_view.hashTreeRoot()).*;
    }
    // Any unix stamp above genesis keeps `processExecutionPayload` monotonicity happy.
    out.message.body.execution_payload.timestamp = 1_737_111_896;
    out.message.body.sync_aggregate.sync_committee_signature = constants.G2_POINT_AT_INFINITY;

    const proposer_index = try cached_state.getBeaconProposer(block_slot);
    out.message.proposer_index = proposer_index;

    try signBlockInterop(allocator, cached_state, out, proposer_index);
}

/// Computes the block-message hash-tree-root of `signed_block` — the value a
/// subsequent block's `parent_root` must reference in a real chain.
fn blockMessageRoot(
    allocator: std.mem.Allocator,
    signed_block: *const types.electra.SignedBeaconBlock.Type,
    out: *[32]u8,
) !void {
    const any_block = @import("fork_types").AnyBeaconBlock{ .full_electra = @constCast(&signed_block.message) };
    try any_block.hashTreeRoot(allocator, out);
}

test "verifyBlocksSignatures - valid_signatures=true short-circuits and returns a wall-clock stamp" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var bls_pool = try initTestPool(testing.io);
    defer bls_pool.deinit(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};

    const before_ms = time.nowMs(testing.io);
    const res = try verifyBlocksSignatures(
        allocator,
        testing.io,
        bls_pool,
        test_state.cached_state,
        &blocks,
        .{ .valid_signatures = true },
        null,
    );
    try testing.expect(res.verify_signatures_finished_at_ms >= before_ms);
}

test "verifyBlocksSignatures - default opts reject bad-signature block and populate invalid_block_index" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var bls_pool = try initTestPool(testing.io);
    defer bls_pool.deinit(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    electra_block.message.body.sync_aggregate.sync_committee_signature = constants.G2_POINT_AT_INFINITY;

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};

    var offender: u32 = std.math.maxInt(u32);
    const res = verifyBlocksSignatures(
        allocator,
        testing.io,
        bls_pool,
        test_state.cached_state,
        &blocks,
        .{},
        &offender,
    );
    try testing.expectError(error.BadEncoding, res);
    // BadEncoding fires in uncompress before the batch runs, so the offender out-param stays untouched.
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), offender);
}

test "verifyBlocksSignatures - happy path: validly-signed block returns without error" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var bls_pool = try initTestPool(testing.io);
    defer bls_pool.deinit(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block: types.electra.SignedBeaconBlock.Type = undefined;
    try buildValidElectraBlock(allocator, test_state.cached_state, 1, null, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};

    const res = try verifyBlocksSignatures(
        allocator,
        testing.io,
        bls_pool,
        test_state.cached_state,
        &blocks,
        .{},
        null,
    );
    try testing.expect(res.verify_signatures_finished_at_ms > 0);
}

test "verifyBlocksSignatures - multi-block happy path: two validly-signed blocks in same epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 10 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var bls_pool = try initTestPool(testing.io);
    defer bls_pool.deinit(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var block_a: types.electra.SignedBeaconBlock.Type = undefined;
    try buildValidElectraBlock(allocator, test_state.cached_state, 1, null, &block_a);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &block_a);

    var block_a_root: [32]u8 = undefined;
    try blockMessageRoot(allocator, &block_a, &block_a_root);
    var block_b: types.electra.SignedBeaconBlock.Type = undefined;
    try buildValidElectraBlock(allocator, test_state.cached_state, 2, &block_a_root, &block_b);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &block_b);

    // Prove batch handles two distinct inputs, not a duplicate.
    try testing.expect(block_a.message.slot != block_b.message.slot);
    try testing.expect(!std.mem.eql(u8, &block_a.signature, &block_b.signature));

    const signed_a = AnySignedBeaconBlock{ .full_electra = &block_a };
    const signed_b = AnySignedBeaconBlock{ .full_electra = &block_b };
    const blocks = [_]AnySignedBeaconBlock{ signed_a, signed_b };

    const res = try verifyBlocksSignatures(
        allocator,
        testing.io,
        bls_pool,
        test_state.cached_state,
        &blocks,
        .{},
        null,
    );
    try testing.expect(res.verify_signatures_finished_at_ms > 0);
}

test "verifyBlocksSignatures - offender attribution: block[1] has a corrupted proposer signature" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 10 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var bls_pool = try initTestPool(testing.io);
    defer bls_pool.deinit(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var block_a: types.electra.SignedBeaconBlock.Type = undefined;
    try buildValidElectraBlock(allocator, test_state.cached_state, 1, null, &block_a);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &block_a);

    var block_a_root: [32]u8 = undefined;
    try blockMessageRoot(allocator, &block_a, &block_a_root);
    var block_b: types.electra.SignedBeaconBlock.Type = undefined;
    try buildValidElectraBlock(allocator, test_state.cached_state, 2, &block_a_root, &block_b);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &block_b);

    // Signing with the wrong validator key yields a well-formed BLS signature (uncompress
    // passes) that fails pairing — so batch verify fails and the sequential fallback runs.
    // A bit-flip corruption would fail at uncompress instead, never reaching the fallback.
    const config = test_state.cached_state.config;
    const epoch_cache = test_state.cached_state.epoch_cache;
    const domain_proposer = try config.getDomain(epoch_cache.epoch, constants.DOMAIN_BEACON_PROPOSER, block_b.message.slot);
    var block_signing_root: [32]u8 = undefined;
    const any_block_b = @import("fork_types").AnyBeaconBlock{ .full_electra = &block_b.message };
    try st.computeBlockSigningRoot(allocator, any_block_b, domain_proposer, &block_signing_root);
    const wrong_signer = if (block_b.message.proposer_index == 0) 1 else block_b.message.proposer_index - 1;
    const wrong_sig = try st.test_utils.interopSign(wrong_signer, &block_signing_root);
    block_b.signature = wrong_sig.compress();

    const signed_a = AnySignedBeaconBlock{ .full_electra = &block_a };
    const signed_b = AnySignedBeaconBlock{ .full_electra = &block_b };
    const blocks = [_]AnySignedBeaconBlock{ signed_a, signed_b };

    var offender: u32 = std.math.maxInt(u32);
    const res = verifyBlocksSignatures(
        allocator,
        testing.io,
        bls_pool,
        test_state.cached_state,
        &blocks,
        .{},
        &offender,
    );
    if (res) |_| {
        try testing.expect(false);
    } else |err| switch (err) {
        error.InvalidBlockSignature => try testing.expectEqual(@as(u32, 1), offender),
        else => try testing.expect(false),
    }
}

test "verifyBlocksSignatures - composition proof: STF(use_bls_batch_verify=true) + verifyBlocksSignatures accept a validly-signed block" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 10 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var bls_pool = try initTestPool(testing.io);
    defer bls_pool.deinit(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block: types.electra.SignedBeaconBlock.Type = undefined;
    try buildValidElectraBlock(allocator, test_state.cached_state, 1, null, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    {
        const dry_post = try st.stateTransition(allocator, testing.io, test_state.cached_state, signed_block, .{
            .verify_state_root = false,
            .verify_proposer = false,
            .verify_signatures = false,
            .transfer_cache = false,
            .block_external_data = .{ .execution_payload_status = .valid, .data_availability_status = .available },
        });
        defer {
            dry_post.deinit();
            allocator.destroy(dry_post);
        }
        electra_block.message.state_root = (try dry_post.state.hashTreeRoot()).*;
    }

    // Re-sign the proposer signature since state_root changed the signing root.
    try signBlockInterop(allocator, test_state.cached_state, &electra_block, electra_block.message.proposer_index);

    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    const stfn = @import("verify_blocks_state_transition_only.zig");
    var stf_res = try stfn.verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{ .use_bls_batch_verify = true, .valid_signatures = true },
    );
    defer stf_res.freeResult(allocator);

    const sig_res = try verifyBlocksSignatures(
        allocator,
        testing.io,
        bls_pool,
        test_state.cached_state,
        &blocks,
        .{},
        null,
    );

    try testing.expectEqual(@as(usize, 1), stf_res.post_states.len);
    try testing.expect(sig_res.verify_signatures_finished_at_ms > 0);
}
