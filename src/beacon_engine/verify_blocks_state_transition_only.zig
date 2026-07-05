//! Runs state transition for N linear blocks. When `use_bls_batch_verify` is
//! set, the caller is responsible for verifying signatures separately; otherwise
//! state transition verifies signatures inline for each block.

const std = @import("std");
const time = @import("time");
const st = @import("state_transition");
const be_metrics = @import("metrics.zig");

const CachedBeaconState = st.CachedBeaconState;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

pub const VerifyStateTransitionOpts = struct {
    /// When true, state transition skips signature and proposer-signature checks;
    /// the caller MUST verify signatures separately before trusting the post-states.
    use_bls_batch_verify: bool = false,
    valid_signatures: bool = false,
    valid_proposer_signature: bool = false,
    /// Unix seconds when the block was received on gossip. When set and exactly
    /// one block is verified, the single-block gossip histograms are observed.
    seen_timestamp_sec: ?u64 = null,
};

pub const VerifyBlocksStateTransitionResult = struct {
    /// Chained: `post_states[i]` is `blocks[i]` applied to `post_states[i-1]`
    /// (or to `pre_state0` when `i == 0`). Owned by the caller; use `freeResult()`.
    post_states: []*CachedBeaconState,
    /// Signed because slashings can reduce a proposer's balance.
    proposer_balance_deltas: []i64,
    /// Wall-clock unix milliseconds at the moment the loop returned. Not a
    /// duration; callers compute recv-to-validation latency as
    /// `verify_state_finished_at_ms / 1000 - opts.seen_timestamp_sec`.
    verify_state_finished_at_ms: u64,

    pub fn freeResult(self: *VerifyBlocksStateTransitionResult, allocator: std.mem.Allocator) void {
        std.debug.assert(self.post_states.len == self.proposer_balance_deltas.len);
        std.debug.assert(self.post_states.len > 0);
        for (self.post_states) |cached_state| {
            cached_state.deinit();
            allocator.destroy(cached_state);
        }
        allocator.free(self.post_states);
        allocator.free(self.proposer_balance_deltas);
    }
};

/// State-root verification is lifted out of `st.stateTransition` so its cost
/// is timed under the `.block_transition` metric source. On any block failure,
/// all previously-created post-states are freed and `pre_state0` is untouched.
pub fn verifyBlocksStateTransitionOnly(
    allocator: std.mem.Allocator,
    io: std.Io,
    pre_state0: *CachedBeaconState,
    blocks: []const AnySignedBeaconBlock,
    data_availability_statuses: []const st.DataAvailabilityStatus,
    opts: VerifyStateTransitionOpts,
) !VerifyBlocksStateTransitionResult {
    std.debug.assert(blocks.len > 0);
    std.debug.assert(blocks.len == data_availability_statuses.len);

    const post_states = try allocator.alloc(*CachedBeaconState, blocks.len);
    errdefer allocator.free(post_states);
    const deltas = try allocator.alloc(i64, blocks.len);
    errdefer allocator.free(deltas);

    var completed: usize = 0;
    errdefer for (post_states[0..completed]) |cached_state| {
        cached_state.deinit();
        allocator.destroy(cached_state);
    };

    const verify_proposer = !opts.use_bls_batch_verify and !opts.valid_signatures and !opts.valid_proposer_signature;
    const verify_signatures = !opts.use_bls_batch_verify and !opts.valid_signatures;

    const now_sec_f: f64 = @floatFromInt(time.nowSec(io));
    const recv_to_val_latency_sec: f64 = if (opts.seen_timestamp_sec) |seen|
        now_sec_f - @as(f64, @floatFromInt(seen))
    else
        0;

    for (blocks, 0..) |signed_block, i| {
        const pre = if (i == 0) pre_state0 else post_states[i - 1];
        const das = data_availability_statuses[i];

        const post = try st.stateTransition(allocator, io, pre, signed_block, .{
            .verify_state_root = false,
            .verify_proposer = verify_proposer,
            .verify_signatures = verify_signatures,
            .transfer_cache = true,
            .block_external_data = .{
                .execution_payload_status = .valid,
                .data_availability_status = das,
            },
        });
        post_states[i] = post;
        completed += 1;

        const t1 = time.start(io);
        const post_state_root = try post.state.hashTreeRoot();
        try st.metrics.state_transition.state_hash_tree_root.observe(
            .{ .source = .block_transition },
            time.durationSeconds(time.since(io, t1)),
        );

        const block_state_root = signed_block.beaconBlock().stateRoot();
        if (!std.mem.eql(u8, post_state_root, block_state_root)) {
            return error.InvalidStateRoot;
        }

        const proposer_idx = signed_block.beaconBlock().proposerIndex();
        var pre_balances_view = try pre.state.balances();
        var post_balances_view = try post.state.balances();
        const pre_bal = try pre_balances_view.get(proposer_idx);
        const post_bal = try post_balances_view.get(proposer_idx);
        deltas[i] = @as(i64, @intCast(post_bal)) - @as(i64, @intCast(pre_bal));

        try io.checkCancel();
    }

    std.debug.assert(completed == blocks.len);

    const verify_state_finished_at_ms = time.nowMs(io);

    if (blocks.len == 1 and opts.seen_timestamp_sec != null) {
        const recv_to_validation_sec = @as(f64, @floatFromInt(verify_state_finished_at_ms)) / std.time.ms_per_s - @as(f64, @floatFromInt(opts.seen_timestamp_sec.?));
        const validation_time_sec = recv_to_validation_sec - recv_to_val_latency_sec;
        be_metrics.beacon_engine.gossip_block_state_transition_recv_to_validation.observe(recv_to_validation_sec);
        be_metrics.beacon_engine.gossip_block_state_transition_validation_time.observe(validation_time_sec);
    }

    return .{
        .post_states = post_states,
        .proposer_balance_deltas = deltas,
        .verify_state_finished_at_ms = verify_state_finished_at_ms,
    };
}

const testing = std.testing;
const types = @import("consensus_types");
const Node = @import("persistent_merkle_tree").Node;

fn setupTestState(allocator: std.mem.Allocator, pool: *Node.Pool) !st.test_utils.TestCachedBeaconState {
    return try st.test_utils.TestCachedBeaconState.init(allocator, pool, 256);
}

// `generateElectraBlock` emits an all-zero proposer signature. `Signature.uncompress`
// rejects that with `BadEncoding` before the pairing check runs, so the error
// surfaces as `BadEncoding` rather than `InvalidBlockSignature`.
test "verifyBlocksStateTransitionOnly - default opts reject the generated block with BadEncoding and leave pre_state0 unchanged" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    const before_root = (try test_state.cached_state.state.hashTreeRoot()).*;
    const before_slot = try test_state.cached_state.state.slot();

    const res = verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{},
    );
    try testing.expectError(error.BadEncoding, res);

    const after_root = (try test_state.cached_state.state.hashTreeRoot()).*;
    try testing.expectEqualSlices(u8, &before_root, &after_root);
    try testing.expectEqual(before_slot, try test_state.cached_state.state.slot());
}

test "verifyBlocksStateTransitionOnly - batch-verify path surfaces InvalidStateRoot from external check" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    const before_root = (try test_state.cached_state.state.hashTreeRoot()).*;

    const res = verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{ .use_bls_batch_verify = true, .valid_signatures = true },
    );
    try testing.expectError(error.InvalidStateRoot, res);

    const after_root = (try test_state.cached_state.state.hashTreeRoot()).*;
    try testing.expectEqualSlices(u8, &before_root, &after_root);
}

test "verifyBlocksStateTransitionOnly - OOM at first allocation site returns error and leaks nothing" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const res = verifyBlocksStateTransitionOnly(
        failing.allocator(),
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{},
    );
    try testing.expectError(error.OutOfMemory, res);
}

test "verifyBlocksStateTransitionOnly - seen_timestamp_sec opt still returns InvalidStateRoot on the error path" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    const res = verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{ .use_bls_batch_verify = true, .valid_signatures = true, .seen_timestamp_sec = 1_700_000_000 },
    );
    try testing.expectError(error.InvalidStateRoot, res);
}

test "verifyBlocksStateTransitionOnly - OOM at second allocation site returns error and leaks nothing" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const res = verifyBlocksStateTransitionOnly(
        failing.allocator(),
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{},
    );
    try testing.expectError(error.OutOfMemory, res);
}

fn patchBlockStateRoot(
    allocator: std.mem.Allocator,
    io: std.Io,
    pre_state: *st.CachedBeaconState,
    signed_block: AnySignedBeaconBlock,
    block_to_patch: *types.electra.SignedBeaconBlock.Type,
) !void {
    const dry_post = try st.stateTransition(allocator, io, pre_state, signed_block, .{
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
    block_to_patch.message.state_root = (try dry_post.state.hashTreeRoot()).*;
}

test "verifyBlocksStateTransitionOnly - happy path: single block succeeds, freeResult clean, delta and wall-clock stamp populated" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    try patchBlockStateRoot(allocator, testing.io, test_state.cached_state, signed_block, &electra_block);

    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    const before_ms = time.nowMs(testing.io);

    var res = try verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{ .use_bls_batch_verify = true, .valid_signatures = true },
    );
    defer res.freeResult(allocator);

    try testing.expectEqual(@as(usize, 1), res.post_states.len);
    try testing.expectEqual(@as(usize, 1), res.proposer_balance_deltas.len);
    try testing.expect(res.verify_state_finished_at_ms >= before_ms);
    const post_slot = try res.post_states[0].state.slot();
    try testing.expectEqual(electra_block.message.slot, post_slot);
}

test "verifyBlocksStateTransitionOnly - multi-block sweep: block[0] succeeds, block[1] fails, errdefer frees post_states[0] with no leaks" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block_0 = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block_0);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block_0);

    const signed_0 = AnySignedBeaconBlock{ .full_electra = &electra_block_0 };
    try patchBlockStateRoot(allocator, testing.io, test_state.cached_state, signed_0, &electra_block_0);

    // slot=0 forces `error.outdatedSlot` inside processSlots so block[1] fails
    // after `completed == 1`, exercising the errdefer sweep on post_states[0].
    var electra_block_1 = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block_1);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block_1);
    electra_block_1.message.slot = 0;

    const signed_1 = AnySignedBeaconBlock{ .full_electra = &electra_block_1 };
    const blocks = [_]AnySignedBeaconBlock{ signed_0, signed_1 };
    const das = [_]st.DataAvailabilityStatus{ .available, .available };

    const before_root = (try test_state.cached_state.state.hashTreeRoot()).*;
    const before_slot = try test_state.cached_state.state.slot();

    const res = verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{ .use_bls_batch_verify = true, .valid_signatures = true },
    );
    try testing.expectError(error.outdatedSlot, res);

    const after_root = (try test_state.cached_state.state.hashTreeRoot()).*;
    try testing.expectEqualSlices(u8, &before_root, &after_root);
    try testing.expectEqual(before_slot, try test_state.cached_state.state.slot());
}

test "verifyBlocksStateTransitionOnly - happy path with seen_timestamp_sec enters the gossip metrics branch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 5 });
    defer pool.deinit();
    defer st.deinitReusedEpochTransitionCache(testing.io);

    try be_metrics.init(allocator, testing.io, .{});

    var test_state = try setupTestState(allocator, &pool);
    defer test_state.deinit();

    var electra_block = types.electra.SignedBeaconBlock.default_value;
    try st.test_utils.generateElectraBlock(allocator, test_state.cached_state, &electra_block);
    defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

    const signed_block = AnySignedBeaconBlock{ .full_electra = &electra_block };
    try patchBlockStateRoot(allocator, testing.io, test_state.cached_state, signed_block, &electra_block);

    const blocks = [_]AnySignedBeaconBlock{signed_block};
    const das = [_]st.DataAvailabilityStatus{.available};

    var res = try verifyBlocksStateTransitionOnly(
        allocator,
        testing.io,
        test_state.cached_state,
        &blocks,
        &das,
        .{ .use_bls_batch_verify = true, .valid_signatures = true, .seen_timestamp_sec = time.nowSec(testing.io) -| 1 },
    );
    defer res.freeResult(allocator);

    try testing.expectEqual(@as(usize, 1), res.post_states.len);
}
