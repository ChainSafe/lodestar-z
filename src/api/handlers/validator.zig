//! Validator API handlers.
//!
//! Implements the `/eth/v1/validator/*` Beacon API endpoints used by
//! validator clients to obtain duties and submit messages.
//!
//! Reference: https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const CachedBeaconState = context.CachedBeaconState;
const constants = @import("constants");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const consensus_types = @import("consensus_types");
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;

// ---------------------------------------------------------------------------
// Duty types
// ---------------------------------------------------------------------------

/// Proposer duty for a single slot in an epoch.
pub const ProposerDuty = struct {
    /// BLS public key of the proposer (48 bytes, hex-encoded in JSON).
    pubkey: [48]u8,
    /// Validator index of the proposer.
    validator_index: u64,
    /// Slot within the epoch for which this validator is the proposer.
    slot: u64,
};

/// Attester duty for a single validator in an epoch.
pub const AttesterDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    committee_index: u64,
    committee_length: u64,
    committees_at_slot: u64,
    validator_committee_index: u64,
    slot: u64,
};

/// Sync committee duty for a single validator in a sync period.
pub const SyncDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    /// Indices of the validator within the sync committee.
    validator_sync_committee_indices: []const u64,
};

const PoolSubmitProbe = struct {
    aggregate_phase0_len: usize = 0,
    aggregate_electra_len: usize = 0,
    contribution_len: usize = 0,

    fn submitAggregate(ptr: *anyopaque, aggregates: context.SubmittedAggregateAndProofs) anyerror!void {
        const self: *PoolSubmitProbe = @ptrCast(@alignCast(ptr));
        switch (aggregates) {
            .phase0 => |items| self.aggregate_phase0_len = items.len,
            .electra => |items| self.aggregate_electra_len = items.len,
        }
    }

    fn submitContribution(
        ptr: *anyopaque,
        contributions: []const consensus_types.altair.SignedContributionAndProof.Type,
    ) anyerror!void {
        const self: *PoolSubmitProbe = @ptrCast(@alignCast(ptr));
        self.contribution_len = contributions.len;
    }
};

fn attesterDependentRoot(state: *CachedBeaconState, epoch: u64) ?[32]u8 {
    const current_epoch = state.epoch_cache.epoch;
    if (epoch == current_epoch) return state.previousDecisionRoot();
    if (epoch == current_epoch + 1) return state.currentDecisionRoot();
    return null;
}

fn proposerDependentRoot(state: *CachedBeaconState, epoch: u64) ?[32]u8 {
    const current_epoch = state.epoch_cache.epoch;
    const is_post_fulu = state.state.forkSeq().gte(.fulu);

    if (epoch == current_epoch) {
        return if (is_post_fulu) state.previousDecisionRoot() else state.currentDecisionRoot();
    }
    if (epoch == current_epoch + 1) {
        return if (is_post_fulu) state.currentDecisionRoot() else null;
    }
    if (epoch + 1 == current_epoch) {
        return state.previousDecisionRoot();
    }
    return null;
}

fn nextEpochProposers(state: *CachedBeaconState, allocator: std.mem.Allocator) ![preset.SLOTS_PER_EPOCH]u64 {
    if (state.epoch_cache.proposers_next_epoch) |next| return next;

    const next_epoch = state.epoch_cache.epoch + 1;
    const active_indices = state.epoch_cache.next_shuffling.get().active_indices;

    var proposers = [_]u64{0} ** preset.SLOTS_PER_EPOCH;
    if (active_indices.len == 0) return proposers;

    var seed: [32]u8 = undefined;
    switch (state.state.forkSeq()) {
        inline else => |fork_seq| {
            // Exported through the state_transition module so API code does
            // not reach into another module's private file tree.
            try state_transition.getSeed(
                fork_seq,
                state.state.castToFork(fork_seq),
                next_epoch,
                constants.DOMAIN_BEACON_PROPOSER,
                &seed,
            );
            try state_transition.computeProposers(
                fork_seq,
                allocator,
                seed,
                next_epoch,
                active_indices,
                state.epoch_cache.effective_balance_increments.get(),
                &proposers,
            );
        },
    }

    return proposers;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /eth/v1/validator/duties/proposer/{epoch}
///
/// Returns the proposer duties for every slot in the given epoch.
///
/// Uses the EpochCache from the head CachedBeaconState to look up real
/// proposer assignments and validator pubkeys for epochs the live cache
/// actually covers.
pub fn getProposerDuties(ctx: *ApiContext, epoch: u64) !HandlerResult([]ProposerDuty) {
    const head = ctx.currentHeadTracker();
    const slots_per_epoch = preset.SLOTS_PER_EPOCH;
    const epoch_start = epoch * slots_per_epoch;
    const state = ctx.headState() orelse return error.NodeNotReady;
    const current_epoch = state.epoch_cache.epoch;
    const proposer_indices: [slots_per_epoch]u64 = blk: {
        if (epoch == current_epoch) break :blk state.epoch_cache.proposers;
        if (epoch == current_epoch + 1) {
            break :blk try nextEpochProposers(state, ctx.allocator);
        }
        if (current_epoch > 0 and epoch == current_epoch - 1) {
            const prev = state.epoch_cache.proposers_prev_epoch orelse return error.NodeNotReady;
            break :blk prev;
        }
        return error.InvalidRequest;
    };

    const duties = try ctx.allocator.alloc(ProposerDuty, slots_per_epoch);
    errdefer ctx.allocator.free(duties);

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);

    for (duties, 0..) |*duty, i| {
        const proposer_index = proposer_indices[i];
        if (proposer_index >= validators.len) return error.CorruptState;
        duty.* = .{
            .pubkey = validators[proposer_index].pubkey,
            .validator_index = proposer_index,
            .slot = epoch_start + i,
        };
    }

    return .{
        .data = duties,
        .meta = .{
            .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
            .dependent_root = proposerDependentRoot(state, epoch),
        },
    };
}

/// POST /eth/v1/validator/duties/attester/{epoch}
///
/// Returns attester duties for the requested validators in the given epoch.
///
/// Uses the EpochCache shuffling to compute committee assignments.
pub fn getAttesterDuties(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) !HandlerResult([]AttesterDuty) {
    const head = ctx.currentHeadTracker();
    const state = ctx.headState() orelse return error.NodeNotReady;
    const epoch_cache = state.epoch_cache;

    // We can serve duties for the current or next epoch.
    const shuffling = epoch_cache.getShufflingAtEpochOrNull(epoch) orelse return error.InvalidRequest;

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);

    const committees_per_slot = shuffling.committees_per_slot;
    const epoch_start = epoch * preset.SLOTS_PER_EPOCH;

    var result = std.ArrayListUnmanaged(AttesterDuty).empty;
    errdefer result.deinit(ctx.allocator);

    // For each requested validator, find which slot/committee they belong to.
    for (validator_indices) |vi| {
        // Walk all committees in the epoch to find this validator.
        for (0..preset.SLOTS_PER_EPOCH) |slot_offset| {
            const slot = epoch_start + slot_offset;
            for (0..committees_per_slot) |committee_idx| {
                const committee = try epoch_cache.getBeaconCommittee(@intCast(slot), @intCast(committee_idx));
                for (committee, 0..) |member, pos| {
                    if (member == vi) {
                        const pubkey = if (vi < validators.len) validators[vi].pubkey else [_]u8{0} ** 48;
                        try result.append(ctx.allocator, .{
                            .pubkey = pubkey,
                            .validator_index = vi,
                            .committee_index = @intCast(committee_idx),
                            .committee_length = @intCast(committee.len),
                            .committees_at_slot = @intCast(committees_per_slot),
                            .validator_committee_index = @intCast(pos),
                            .slot = slot,
                        });
                        break;
                    }
                }
            }
        }
    }

    return .{
        .data = try result.toOwnedSlice(ctx.allocator),
        .meta = .{
            .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
            .dependent_root = attesterDependentRoot(state, epoch),
        },
    };
}

/// POST /eth/v1/validator/duties/sync/{epoch}
///
/// Returns sync committee duties for the requested validators in the given epoch.
///
/// Uses the sync committee cache from the epoch cache.
pub fn getSyncDuties(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) !HandlerResult([]SyncDuty) {
    const head = ctx.currentHeadTracker();
    const state = ctx.headState() orelse return error.NodeNotReady;
    const epoch_cache = state.epoch_cache;

    // Get the indexed sync committee for this epoch.
    const sync_committee = epoch_cache.getIndexedSyncCommitteeAtEpoch(epoch) catch {
        return error.InvalidRequest;
    };
    const sync_indices = sync_committee.getValidatorIndices();

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);

    var result = std.ArrayListUnmanaged(SyncDuty).empty;
    errdefer result.deinit(ctx.allocator);

    for (validator_indices) |vi| {
        // Collect all positions where this validator appears in the sync committee.
        var positions = std.ArrayListUnmanaged(u64).empty;
        errdefer positions.deinit(ctx.allocator);

        for (sync_indices, 0..) |member, pos| {
            if (member == vi) {
                try positions.append(ctx.allocator, @intCast(pos));
            }
        }

        if (positions.items.len > 0) {
            const pubkey = if (vi < validators.len) validators[vi].pubkey else [_]u8{0} ** 48;
            try result.append(ctx.allocator, .{
                .pubkey = pubkey,
                .validator_index = vi,
                .validator_sync_committee_indices = try positions.toOwnedSlice(ctx.allocator),
            });
        } else {
            positions.deinit(ctx.allocator);
        }
    }

    return .{
        .data = try result.toOwnedSlice(ctx.allocator),
        .meta = .{
            .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
        },
    };
}

/// POST /eth/v1/validator/beacon_committee_subscriptions
pub fn prepareBeaconCommitteeSubnet(
    ctx: *ApiContext,
    subscriptions: []const types.BeaconCommitteeSubscription,
) !HandlerResult(void) {
    const cb = ctx.subnet_subscriptions orelse return error.NotImplemented;
    try cb.prepareBeaconCommitteeSubnetsFn(cb.ptr, subscriptions);
    return .{ .data = {} };
}

/// POST /eth/v1/validator/sync_committee_subscriptions
pub fn prepareSyncCommitteeSubnets(
    ctx: *ApiContext,
    subscriptions: []const types.SyncCommitteeSubscription,
) !HandlerResult(void) {
    const cb = ctx.subnet_subscriptions orelse return error.NotImplemented;
    try cb.prepareSyncCommitteeSubnetsFn(cb.ptr, subscriptions);
    return .{ .data = {} };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getProposerDuties returns NodeNotReady without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = getProposerDuties(&tc.ctx, 0);
    try std.testing.expectError(error.NodeNotReady, result);
}

test "getProposerDuties returns real duties for cached epoch" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const persistent_merkle_tree = @import("persistent_merkle_tree");
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try persistent_merkle_tree.Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const epoch = test_state.cached_state.epoch_cache.epoch;
    const result = try getProposerDuties(&tc.ctx, epoch);
    defer tc.ctx.allocator.free(result.data);

    try std.testing.expectEqual(preset.SLOTS_PER_EPOCH, result.data.len);
    for (result.data, 0..) |duty, i| {
        try std.testing.expectEqual(epoch * preset.SLOTS_PER_EPOCH + i, duty.slot);
    }
}

test "getProposerDuties returns InvalidRequest for unsupported epoch" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const persistent_merkle_tree = @import("persistent_merkle_tree");
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try persistent_merkle_tree.Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const result = getProposerDuties(&tc.ctx, test_state.cached_state.epoch_cache.epoch + 2);
    try std.testing.expectError(error.InvalidRequest, result);
}

test "getAttesterDuties returns NodeNotReady without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getAttesterDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NodeNotReady, result);
}

test "getSyncDuties returns NodeNotReady without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getSyncDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NodeNotReady, result);
}

test "getAttesterDuties returns InvalidRequest for unsupported epoch" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const persistent_merkle_tree = @import("persistent_merkle_tree");
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try persistent_merkle_tree.Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const result = getAttesterDuties(&tc.ctx, test_state.cached_state.epoch_cache.epoch + 2, &.{0});
    try std.testing.expectError(error.InvalidRequest, result);
}

test "getSyncDuties returns InvalidRequest for unsupported sync period" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const persistent_merkle_tree = @import("persistent_merkle_tree");
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try persistent_merkle_tree.Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;

    const unsupported_epoch = test_state.cached_state.epoch_cache.epoch + (2 * preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
    const result = getSyncDuties(&tc.ctx, unsupported_epoch, &.{0});
    try std.testing.expectError(error.InvalidRequest, result);
}

test "getValidatorLiveness returns NodeNotReady without current slot" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    tc.ctx.chain = null;

    const result = getValidatorLiveness(&tc.ctx, 0, &.{0});
    try std.testing.expectError(error.NodeNotReady, result);
}

test "prepareBeaconCommitteeSubnet forwards subscriptions to callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const Mock = struct {
        var called = false;
        fn prepareBeacon(ptr: *anyopaque, subscriptions: []const types.BeaconCommitteeSubscription) anyerror!void {
            _ = ptr;
            called = true;
            try std.testing.expectEqual(@as(usize, 1), subscriptions.len);
            try std.testing.expectEqual(@as(u64, 7), subscriptions[0].slot);
        }

        fn prepareSync(_: *anyopaque, _: []const types.SyncCommitteeSubscription) anyerror!void {}
    };

    var dummy: u8 = 0;
    tc.ctx.subnet_subscriptions = .{
        .ptr = &dummy,
        .prepareBeaconCommitteeSubnetsFn = &Mock.prepareBeacon,
        .prepareSyncCommitteeSubnetsFn = &Mock.prepareSync,
    };

    const result = try prepareBeaconCommitteeSubnet(&tc.ctx, &.{
        .{
            .validator_index = 1,
            .committee_index = 2,
            .committees_at_slot = 3,
            .slot = 7,
            .is_aggregator = true,
        },
    });
    _ = result;
    try std.testing.expect(Mock.called);
}

test "prepareSyncCommitteeSubnets forwards subscriptions to callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const Mock = struct {
        var called = false;
        fn prepareBeacon(_: *anyopaque, _: []const types.BeaconCommitteeSubscription) anyerror!void {}

        fn prepareSync(ptr: *anyopaque, subscriptions: []const types.SyncCommitteeSubscription) anyerror!void {
            _ = ptr;
            called = true;
            try std.testing.expectEqual(@as(usize, 1), subscriptions.len);
            try std.testing.expectEqual(@as(usize, 2), subscriptions[0].sync_committee_indices.len);
            try std.testing.expectEqual(@as(u64, 512), subscriptions[0].until_epoch);
        }
    };

    var dummy: u8 = 0;
    const indices = [_]u64{ 0, 128 };
    tc.ctx.subnet_subscriptions = .{
        .ptr = &dummy,
        .prepareBeaconCommitteeSubnetsFn = &Mock.prepareBeacon,
        .prepareSyncCommitteeSubnetsFn = &Mock.prepareSync,
    };

    const result = try prepareSyncCommitteeSubnets(&tc.ctx, &.{
        .{
            .validator_index = 1,
            .sync_committee_indices = &indices,
            .until_epoch = 512,
        },
    });
    _ = result;
    try std.testing.expect(Mock.called);
}

// ---------------------------------------------------------------------------
// Block production and validator data endpoints
// ---------------------------------------------------------------------------

/// GET /eth/v1/validator/blocks/{slot}
///
/// Produce an unsigned beacon block for the given slot. The validator
/// must sign the returned block and then submit it via
/// POST /eth/v2/beacon/blocks.
///
/// Takes: slot (path param), randao_reveal (query param, 0x-hex BLS sig),
///        fee_recipient (optional 0x-hex 20 bytes), graffiti (optional
///        query param, 0x-hex 32 bytes), builder_boost_factor (optional),
///        strict_fee_recipient_check (optional boolean), blinded_local
///        (optional boolean).
///
/// Returns a HandlerResult with the block in JSON (or SSZ if requested).
/// The .meta.version field must be set to the fork name for the block.
///
/// Without a produce_block callback wired, returns NotImplemented.
pub fn produceBlock(
    ctx: *ApiContext,
    slot: u64,
    randao_reveal: [96]u8,
    fee_recipient: ?[20]u8,
    graffiti: ?[32]u8,
    builder_selection: ?types.BuilderSelection,
    builder_boost_factor: ?u64,
    strict_fee_recipient_check: bool,
    blinded_local: bool,
) !HandlerResult(context.ProducedBlockData) {
    const cb = ctx.produce_block orelse return error.NotImplemented;
    const block_data = try cb.produceBlockFn(cb.ptr, ctx.allocator, .{
        .slot = slot,
        .randao_reveal = randao_reveal,
        .fee_recipient = fee_recipient,
        .graffiti = graffiti,
        .builder_selection = builder_selection,
        .builder_boost_factor = builder_boost_factor,
        .strict_fee_recipient_check = strict_fee_recipient_check,
        .blinded_local = blinded_local,
    });
    return .{
        .data = block_data,
        .meta = .{},
    };
}

/// GET /eth/v1/validator/attestation_data
///
/// Get attestation data for the given slot and committee index.
/// This is the unsigned data that validators need to create an attestation.
pub fn getAttestationData(
    ctx: *ApiContext,
    slot: u64,
    committee_index: u64,
) !HandlerResult(context.AttestationDataResult) {
    const cb = ctx.attestation_data orelse return error.NotImplemented;
    const result = try cb.getAttestationDataFn(cb.ptr, slot, committee_index);
    return .{ .data = result, .meta = .{} };
}

/// GET /eth/v1/validator/aggregate_attestation
///
/// Get the best aggregate attestation for the given slot and
/// attestation_data_root (from the op pool).
///
pub fn getAggregateAttestation(
    ctx: *ApiContext,
    slot: u64,
    attestation_data_root: [32]u8,
) !HandlerResult(context.AggregateAttestationResult) {
    const cb = ctx.aggregate_attestation orelse return error.NotImplemented;
    const result = try cb.getAggregateAttestationFn(cb.ptr, slot, attestation_data_root);
    return .{ .data = result, .meta = .{} };
}

/// POST /eth/v1/validator/aggregate_and_proofs
///
/// Submit signed aggregate-and-proof objects for import into the op pool
/// and broadcast to gossip.
pub fn publishAggregateAndProofs(
    ctx: *ApiContext,
    aggregates: context.SubmittedAggregateAndProofs,
) !HandlerResult(void) {
    const is_empty = switch (aggregates) {
        .phase0 => |items| items.len == 0,
        .electra => |items| items.len == 0,
    };
    if (is_empty) return .{ .data = {} };
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitAggregateAndProofFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, aggregates);
    return .{ .data = {} };
}

/// GET /eth/v1/validator/sync_committee_contribution
///
/// Get a sync committee contribution for the given slot, subcommittee_index,
/// and beacon_block_root.
///
pub fn getSyncCommitteeContribution(
    ctx: *ApiContext,
    slot: u64,
    subcommittee_index: u64,
    beacon_block_root: [32]u8,
) !HandlerResult(context.SyncCommitteeContributionResult) {
    const cb = ctx.sync_committee_contribution orelse return error.NotImplemented;
    const result = try cb.getSyncCommitteeContributionFn(cb.ptr, slot, subcommittee_index, beacon_block_root);
    return .{ .data = result, .meta = .{} };
}

/// POST /eth/v1/validator/contribution_and_proofs
///
/// Submit signed contribution-and-proof objects for import and broadcast.
pub fn publishContributionAndProofs(
    ctx: *ApiContext,
    contributions: []const consensus_types.altair.SignedContributionAndProof.Type,
) !HandlerResult(void) {
    if (contributions.len == 0) return .{ .data = {} };
    const cb = ctx.pool_submit orelse return error.NotImplemented;
    const submit_fn = cb.submitContributionAndProofFn orelse return error.NotImplemented;
    try submit_fn(cb.ptr, contributions);
    return .{ .data = {} };
}

// ---------------------------------------------------------------------------
// Tests for new endpoints
// ---------------------------------------------------------------------------

test "getAttestationData returns NotImplemented without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = getAttestationData(&tc.ctx, 100, 0);
    try std.testing.expectError(error.NotImplemented, result);
}

test "getAttestationData uses callback when wired" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getAttData(_: *anyopaque, slot: u64, committee_index: u64) anyerror!context.AttestationDataResult {
            return .{
                .slot = slot,
                .index = committee_index,
                .beacon_block_root = [_]u8{0x42} ** 32,
                .source = .{ .epoch = 5, .root = [_]u8{0x11} ** 32 },
                .target = .{ .epoch = 6, .root = [_]u8{0x22} ** 32 },
            };
        }
    };
    var dummy: u8 = 0;
    tc.ctx.attestation_data = .{
        .ptr = &dummy,
        .getAttestationDataFn = &MockCb.getAttData,
    };

    const result = try getAttestationData(&tc.ctx, 200, 3);
    try std.testing.expectEqual(@as(u64, 200), result.data.slot);
    try std.testing.expectEqual(@as(u64, 3), result.data.index);
    try std.testing.expectEqual([_]u8{0x42} ** 32, result.data.beacon_block_root);
    try std.testing.expectEqual(@as(u64, 5), result.data.source.epoch);
    try std.testing.expectEqual([_]u8{0x11} ** 32, result.data.source.root);
    try std.testing.expectEqual(@as(u64, 6), result.data.target.epoch);
    try std.testing.expectEqual([_]u8{0x22} ** 32, result.data.target.root);
}

test "produceBlock returns NotImplemented without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = produceBlock(&tc.ctx, 100, [_]u8{0} ** 96, null, null, null, null, false, false);
    try std.testing.expectError(error.NotImplemented, result);
}

test "produceBlock forwards extended params to callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        var saw_params = false;

        fn produce(
            _: *anyopaque,
            allocator: std.mem.Allocator,
            params: context.ProduceBlockParams,
        ) anyerror!context.ProducedBlockData {
            saw_params = true;
            try std.testing.expectEqual(@as(u64, 123), params.slot);
            try std.testing.expectEqual([_]u8{0xAA} ** 96, params.randao_reveal);
            try std.testing.expect(params.fee_recipient != null);
            try std.testing.expectEqual([_]u8{0xBB} ** 20, params.fee_recipient.?);
            try std.testing.expect(params.graffiti != null);
            try std.testing.expectEqual([_]u8{0xCC} ** 32, params.graffiti.?);
            try std.testing.expectEqual(types.BuilderSelection.maxprofit, params.builder_selection.?);
            try std.testing.expectEqual(@as(?u64, 150), params.builder_boost_factor);
            try std.testing.expect(params.strict_fee_recipient_check);
            try std.testing.expect(params.blinded_local);

            return .{
                .ssz_bytes = try allocator.dupe(u8, "block"),
                .fork = "electra",
                .blinded = true,
                .execution_payload_source = .engine,
                .execution_payload_value = 123,
                .consensus_block_value = 456,
            };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.produce_block = .{
        .ptr = &dummy,
        .produceBlockFn = &MockCb.produce,
    };

    const result = try produceBlock(
        &tc.ctx,
        123,
        [_]u8{0xAA} ** 96,
        [_]u8{0xBB} ** 20,
        [_]u8{0xCC} ** 32,
        .maxprofit,
        150,
        true,
        true,
    );
    defer tc.ctx.allocator.free(result.data.ssz_bytes);
    try std.testing.expect(MockCb.saw_params);
    try std.testing.expect(result.data.blinded);
    try std.testing.expectEqual(@as(u256, 123), result.data.execution_payload_value);
    try std.testing.expectEqual(@as(u256, 456), result.data.consensus_block_value);
}

test "getAggregateAttestation returns NotImplemented without callback" {
    // Callback is required on the live path.
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getAggregateAttestation(&tc.ctx, 100, [_]u8{0} ** 32);
    try std.testing.expectError(error.NotImplemented, result);
}

test "getAggregateAttestation uses callback when wired" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getAggregate(_: *anyopaque, slot: u64, attestation_data_root: [32]u8) anyerror!context.AggregateAttestationResult {
            const AggregationBits = @FieldType(context.AggregateAttestationResult, "aggregation_bits");
            var aggregation_bits = try AggregationBits.fromBitLen(std.testing.allocator, 8);
            try aggregation_bits.set(std.testing.allocator, 0, true);
            return .{
                .aggregation_bits = aggregation_bits,
                .data = .{
                    .slot = slot,
                    .index = 0,
                    .beacon_block_root = attestation_data_root,
                    .source = .{ .epoch = 1, .root = [_]u8{0x11} ** 32 },
                    .target = .{ .epoch = 2, .root = [_]u8{0x22} ** 32 },
                },
                .signature = [_]u8{0x33} ** 96,
            };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.aggregate_attestation = .{
        .ptr = &dummy,
        .getAggregateAttestationFn = &MockCb.getAggregate,
    };

    const expected_root = [_]u8{0xAB} ** 32;
    var result = try getAggregateAttestation(&tc.ctx, 100, expected_root);
    defer consensus_types.phase0.Attestation.deinit(std.testing.allocator, &result.data);

    try std.testing.expectEqual(@as(u64, 100), result.data.data.slot);
    try std.testing.expectEqual(@as(u64, 0), result.data.data.index);
    try std.testing.expectEqualSlices(u8, &expected_root, &result.data.data.beacon_block_root);
    try std.testing.expect(try result.data.aggregation_bits.get(0));
}

test "publishAggregateAndProofs with empty body returns ok" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = try publishAggregateAndProofs(&tc.ctx, .{ .phase0 = &.{} });
    _ = result;
}

test "publishAggregateAndProofs returns NotImplemented without callback when body non-empty" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = publishAggregateAndProofs(&tc.ctx, .{ .phase0 = &.{consensus_types.phase0.SignedAggregateAndProof.default_value} });
    try std.testing.expectError(error.NotImplemented, result);
}

test "publishAggregateAndProofs forwards body to pool_submit callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var probe = PoolSubmitProbe{};
    tc.ctx.pool_submit = .{
        .ptr = @ptrCast(&probe),
        .submitAggregateAndProofFn = &PoolSubmitProbe.submitAggregate,
    };

    _ = try publishAggregateAndProofs(&tc.ctx, .{ .phase0 = &.{consensus_types.phase0.SignedAggregateAndProof.default_value} });
    try std.testing.expectEqual(@as(usize, 1), probe.aggregate_phase0_len);
    try std.testing.expectEqual(@as(usize, 0), probe.aggregate_electra_len);
}

test "publishContributionAndProofs with empty body returns ok" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = try publishContributionAndProofs(&tc.ctx, &.{});
    _ = result;
}

test "publishContributionAndProofs returns NotImplemented without callback when body non-empty" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = publishContributionAndProofs(&tc.ctx, &.{consensus_types.altair.SignedContributionAndProof.default_value});
    try std.testing.expectError(error.NotImplemented, result);
}

test "publishContributionAndProofs forwards body to pool_submit callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var probe = PoolSubmitProbe{};
    tc.ctx.pool_submit = .{
        .ptr = @ptrCast(&probe),
        .submitContributionAndProofFn = &PoolSubmitProbe.submitContribution,
    };

    _ = try publishContributionAndProofs(&tc.ctx, &.{consensus_types.altair.SignedContributionAndProof.default_value});
    try std.testing.expectEqual(@as(usize, 1), probe.contribution_len);
}

test "getSyncCommitteeContribution returns NotImplemented without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getSyncCommitteeContribution(&tc.ctx, 100, 0, [_]u8{0} ** 32);
    try std.testing.expectError(error.NotImplemented, result);
}

test "getSyncCommitteeContribution uses callback when wired" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getContribution(_: *anyopaque, slot: u64, subcommittee_index: u64, beacon_block_root: [32]u8) anyerror!context.SyncCommitteeContributionResult {
            var aggregation_bits = @FieldType(context.SyncCommitteeContributionResult, "aggregation_bits").empty;
            try aggregation_bits.set(0, true);
            try aggregation_bits.set(1, true);
            return .{
                .slot = slot,
                .beacon_block_root = beacon_block_root,
                .subcommittee_index = subcommittee_index,
                .aggregation_bits = aggregation_bits,
                .signature = [_]u8{0x44} ** 96,
            };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.sync_committee_contribution = .{
        .ptr = &dummy,
        .getSyncCommitteeContributionFn = &MockCb.getContribution,
    };

    const expected_root = [_]u8{0xCD} ** 32;
    const result = try getSyncCommitteeContribution(&tc.ctx, 120, 2, expected_root);
    try std.testing.expectEqual(@as(u64, 120), result.data.slot);
    try std.testing.expectEqual(@as(u64, 2), result.data.subcommittee_index);
    try std.testing.expectEqualSlices(u8, &expected_root, &result.data.beacon_block_root);
    try std.testing.expect(try result.data.aggregation_bits.get(0));
    try std.testing.expect(try result.data.aggregation_bits.get(1));
}

// ---------------------------------------------------------------------------
// Validator liveness
// ---------------------------------------------------------------------------

/// POST /eth/v1/validator/liveness/{epoch}
///
/// Check whether validators were live (made any on-chain activity) in the epoch.
pub fn getValidatorLiveness(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) !HandlerResult([]types.ValidatorLiveness) {
    const current_slot = ctx.currentSlot() orelse return error.NodeNotReady;
    const current_epoch = current_slot / preset.SLOTS_PER_EPOCH;

    if ((current_epoch > 0 and epoch + 1 < current_epoch) or epoch > current_epoch + 1) {
        return error.InvalidRequest;
    }

    const out = try ctx.allocator.alloc(types.ValidatorLiveness, validator_indices.len);
    errdefer ctx.allocator.free(out);

    for (validator_indices, out) |validator_index, *entry| {
        entry.* = .{
            .index = validator_index,
            .epoch = epoch,
            .is_live = ctx.validatorSeenAtEpoch(validator_index, epoch),
        };
    }

    return .{ .data = out };
}

test "getValidatorLiveness returns live results from chain liveness cache" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const current_epoch = tc.chain_fixture.current_slot / preset.SLOTS_PER_EPOCH;
    try tc.chain_fixture.markValidatorSeenAtEpoch(11, current_epoch);

    const result = try getValidatorLiveness(&tc.ctx, current_epoch, &.{ 10, 11 });
    defer std.testing.allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 2), result.data.len);
    try std.testing.expectEqual(types.ValidatorLiveness{ .index = 10, .epoch = current_epoch, .is_live = false }, result.data[0]);
    try std.testing.expectEqual(types.ValidatorLiveness{ .index = 11, .epoch = current_epoch, .is_live = true }, result.data[1]);
}

test "getValidatorLiveness rejects epochs outside the supported window" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const current_epoch = tc.chain_fixture.current_slot / preset.SLOTS_PER_EPOCH;

    if (current_epoch > 1) {
        try std.testing.expectError(error.InvalidRequest, getValidatorLiveness(&tc.ctx, current_epoch - 2, &.{0}));
    }
    try std.testing.expectError(error.InvalidRequest, getValidatorLiveness(&tc.ctx, current_epoch + 2, &.{0}));
}

// ---------------------------------------------------------------------------
// Proposer preparation / registration
// ---------------------------------------------------------------------------

/// POST /eth/v1/validator/prepare_beacon_proposer
///
/// Register fee recipients for upcoming proposers (EIP-1559).
/// Stores the fee recipient mapping; actual use during block production
/// requires wiring to the block builder.
pub fn prepareBeaconProposer(
    ctx: *ApiContext,
    preparations: []const types.ProposerPreparation,
) !HandlerResult(void) {
    const cb = ctx.prepare_beacon_proposer orelse return error.NotImplemented;
    try cb.prepareBeaconProposerFn(cb.ptr, preparations);
    return .{ .data = {} };
}

/// POST /eth/v1/validator/register_validator
///
/// MEV-boost validator registration. Forward to the configured builder API.
pub fn registerValidator(
    ctx: *ApiContext,
    registrations: []const types.SignedValidatorRegistrationV1,
) !HandlerResult(void) {
    const builder_cb = ctx.builder orelse return error.BuilderNotConfigured;
    try builder_cb.registerValidators(registrations);
    return .{ .data = {} };
}

test "registerValidator returns BuilderNotConfigured without builder callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = registerValidator(&tc.ctx, &.{});
    try std.testing.expectError(error.BuilderNotConfigured, result);
}

test "registerValidator forwards typed registrations to builder callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const Mock = struct {
        var called = false;

        fn register(
            _: *anyopaque,
            registrations: []const types.SignedValidatorRegistrationV1,
        ) anyerror!void {
            called = true;
            try std.testing.expectEqual(@as(usize, 1), registrations.len);
            try std.testing.expectEqual([_]u8{0x11} ** 20, registrations[0].message.fee_recipient);
            try std.testing.expectEqual(@as(u64, 30_000_000), registrations[0].message.gas_limit);
            try std.testing.expectEqual([_]u8{0x22} ** 48, registrations[0].message.pubkey);
            try std.testing.expectEqual([_]u8{0x33} ** 96, registrations[0].signature);
        }
    };

    var dummy: u8 = 0;
    tc.ctx.builder = .{
        .ptr = &dummy,
        .registerValidatorsFn = &Mock.register,
    };

    _ = try registerValidator(&tc.ctx, &.{
        .{
            .message = .{
                .fee_recipient = [_]u8{0x11} ** 20,
                .gas_limit = 30_000_000,
                .timestamp = 1234,
                .pubkey = [_]u8{0x22} ** 48,
            },
            .signature = [_]u8{0x33} ** 96,
        },
    });

    try std.testing.expect(Mock.called);
}

test "registerValidator propagates builder errors" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const Mock = struct {
        fn register(_: *anyopaque, _: []const types.SignedValidatorRegistrationV1) anyerror!void {
            return error.BuilderUnavailable;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.builder = .{
        .ptr = &dummy,
        .registerValidatorsFn = &Mock.register,
    };

    const result = registerValidator(&tc.ctx, &.{});
    try std.testing.expectError(error.BuilderUnavailable, result);
}
