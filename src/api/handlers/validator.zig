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
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const EpochCache = state_transition.EpochCache;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;
const ResponseMeta = handler_result.ResponseMeta;

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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /eth/v1/validator/duties/proposer/{epoch}
///
/// Returns the proposer duties for every slot in the given epoch.
///
/// Uses the EpochCache from the head CachedBeaconState to look up real
/// proposer assignments and validator pubkeys. Falls back to a zeroed
/// stub if the head state is unavailable.
pub fn getProposerDuties(ctx: *ApiContext, epoch: u64) !HandlerResult([]ProposerDuty) {
    const slots_per_epoch = preset.SLOTS_PER_EPOCH;
    const epoch_start = epoch * slots_per_epoch;

    const duties = try ctx.allocator.alloc(ProposerDuty, slots_per_epoch);
    errdefer ctx.allocator.free(duties);

    // Try to get real data from the head state's epoch cache.
    const head_state: ?*CachedBeaconState = blk: {
        const cb = ctx.head_state orelse break :blk null;
        break :blk cb.getHeadStateFn(cb.ptr);
    };

    if (head_state) |state| {
        const epoch_cache = state.epoch_cache;
        // Check if this epoch cache covers the requested epoch.
        // The epoch cache has proposers for its current epoch.
        if (epoch_cache.epoch == epoch) {
            // Read proposers from the epoch cache and resolve pubkeys from the state.
            const validators = try state.state.validatorsSlice(ctx.allocator);
            defer ctx.allocator.free(validators);

            for (duties, 0..) |*duty, i| {
                const proposer_index = epoch_cache.proposers[i];
                const pubkey = if (proposer_index < validators.len) validators[proposer_index].pubkey else [_]u8{0} ** 48;
                duty.* = .{
                    .pubkey = pubkey,
                    .validator_index = proposer_index,
                    .slot = epoch_start + i,
                };
            }
            return .{
                .data = duties,
                .meta = .{
                    .execution_optimistic = false,
                    .dependent_root = ctx.head_tracker.head_root,
                },
            };
        }
    }

    // Fallback: return stub duties with zeroed pubkeys.
    for (duties, 0..) |*duty, i| {
        duty.* = .{
            .pubkey = [_]u8{0} ** 48,
            .validator_index = 0,
            .slot = epoch_start + i,
        };
    }

    return .{
        .data = duties,
        .meta = .{
            .execution_optimistic = false,
            .dependent_root = ctx.head_tracker.head_root,
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
    const cb = ctx.head_state orelse return error.NotImplemented;
    const state = cb.getHeadStateFn(cb.ptr) orelse return error.StateNotAvailable;
    const epoch_cache = state.epoch_cache;

    // We can serve duties for the current or next epoch.
    const shuffling = epoch_cache.getShufflingAtEpochOrNull(epoch) orelse return error.NotImplemented;

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
            .execution_optimistic = false,
            .dependent_root = ctx.head_tracker.head_root,
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
    const cb = ctx.head_state orelse return error.NotImplemented;
    const state = cb.getHeadStateFn(cb.ptr) orelse return error.StateNotAvailable;
    const epoch_cache = state.epoch_cache;

    // Get the indexed sync committee for this epoch.
    const sync_committee = epoch_cache.getIndexedSyncCommitteeAtEpoch(epoch) catch return error.NotImplemented;
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
            .execution_optimistic = false,
        },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getProposerDuties returns SLOTS_PER_EPOCH entries" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = try getProposerDuties(&tc.ctx, 0);
    defer tc.ctx.allocator.free(result.data);

    try std.testing.expectEqual(preset.SLOTS_PER_EPOCH, result.data.len);
}

test "getProposerDuties assigns correct slots for epoch 0" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = try getProposerDuties(&tc.ctx, 0);
    defer tc.ctx.allocator.free(result.data);

    for (result.data, 0..) |duty, i| {
        try std.testing.expectEqual(@as(u64, i), duty.slot);
    }
}

test "getProposerDuties assigns correct slots for epoch 3" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const epoch: u64 = 3;
    const result = try getProposerDuties(&tc.ctx, epoch);
    defer tc.ctx.allocator.free(result.data);

    const expected_start = epoch * preset.SLOTS_PER_EPOCH;
    try std.testing.expectEqual(expected_start, result.data[0].slot);
    try std.testing.expectEqual(expected_start + preset.SLOTS_PER_EPOCH - 1, result.data[result.data.len - 1].slot);
}

test "getAttesterDuties returns NotImplemented without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getAttesterDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NotImplemented, result);
}

test "getSyncDuties returns NotImplemented without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getSyncDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NotImplemented, result);
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
///        graffiti (optional query param, 0x-hex 32 bytes).
///
/// Returns a HandlerResult with the block in JSON (or SSZ if requested).
/// The .meta.version field must be set to the fork name for the block.
///
/// Without a produce_block callback wired, returns NotImplemented.
pub fn produceBlock(
    ctx: *ApiContext,
    slot: u64,
    randao_reveal: [96]u8,
    graffiti: ?[32]u8,
) !HandlerResult(context.ProducedBlockData) {
    const cb = ctx.produce_block orelse return error.NotImplemented;
    const block_data = try cb.produceBlockFn(cb.ptr, ctx.allocator, .{
        .slot = slot,
        .randao_reveal = randao_reveal,
        .graffiti = graffiti,
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
///
/// Without an attestation_data callback, returns a stub response.
pub fn getAttestationData(
    ctx: *ApiContext,
    slot: u64,
    committee_index: u64,
) !HandlerResult(context.AttestationDataResult) {
    if (ctx.attestation_data) |cb| {
        const result = try cb.getAttestationDataFn(cb.ptr, slot, committee_index);
        return .{ .data = result, .meta = .{} };
    }

    // Stub: return attestation data based on current head.
    // W6: target_root is the block root at the START of the target epoch,
    // not the current head root. Use justified_root as an approximation
    // when no callback is wired (justified checkpoint root is at epoch start).
    const target_epoch = slot / preset.SLOTS_PER_EPOCH;
    const target_root = if (target_epoch == ctx.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH)
        ctx.head_tracker.justified_root
    else
        ctx.head_tracker.head_root; // best effort when no state available
    return .{
        .data = .{
            .slot = slot,
            .index = committee_index,
            .beacon_block_root = ctx.head_tracker.head_root,
            .source_epoch = ctx.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
            .source_root = ctx.head_tracker.justified_root,
            .target_epoch = target_epoch,
            .target_root = target_root,
        },
        .meta = .{},
    };
}

/// GET /eth/v1/validator/aggregate_attestation
///
/// Get the best aggregate attestation for the given slot and
/// attestation_data_root (from the op pool).
///
/// Returns the raw JSON from the aggregate_attestation callback,
/// or NotImplemented if not wired.
pub fn getAggregateAttestation(
    ctx: *ApiContext,
    slot: u64,
    attestation_data_root: [32]u8,
) ![]const u8 {
    const cb = ctx.aggregate_attestation orelse return error.NotImplemented;
    return cb.getAggregateAttestationFn(cb.ptr, ctx.allocator, slot, attestation_data_root);
}

/// POST /eth/v1/validator/aggregate_and_proofs
///
/// Submit signed aggregate-and-proof objects for import into the op pool
/// and broadcast to gossip.
pub fn publishAggregateAndProofs(
    ctx: *ApiContext,
    body: []const u8,
) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitAggregateAndProofFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    // Parse to validate even without a callback.
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    _ = std.json.parseFromSlice(std.json.Value, arena.allocator(), body, .{}) catch
        return error.InvalidRequest;

    return .{ .data = {} };
}

/// GET /eth/v1/validator/sync_committee_contribution
///
/// Get a sync committee contribution for the given slot, subcommittee_index,
/// and beacon_block_root.
///
/// Returns raw JSON from the sync_committee_contribution callback,
/// or NotImplemented if not wired.
pub fn getSyncCommitteeContribution(
    ctx: *ApiContext,
    slot: u64,
    subcommittee_index: u64,
    beacon_block_root: [32]u8,
) ![]const u8 {
    const cb = ctx.sync_committee_contribution orelse return error.NotImplemented;
    return cb.getSyncCommitteeContributionFn(cb.ptr, ctx.allocator, slot, subcommittee_index, beacon_block_root);
}

/// POST /eth/v1/validator/contribution_and_proofs
///
/// Submit signed contribution-and-proof objects for import and broadcast.
pub fn publishContributionAndProofs(
    ctx: *ApiContext,
    body: []const u8,
) !HandlerResult(void) {
    if (body.len == 0) return .{ .data = {} };

    if (ctx.pool_submit) |cb| {
        if (cb.submitContributionAndProofFn) |submit_fn| {
            try submit_fn(cb.ptr, body);
            return .{ .data = {} };
        }
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    _ = std.json.parseFromSlice(std.json.Value, arena.allocator(), body, .{}) catch
        return error.InvalidRequest;

    return .{ .data = {} };
}

// ---------------------------------------------------------------------------
// Tests for new endpoints
// ---------------------------------------------------------------------------

test "getAttestationData returns stub data without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = try getAttestationData(&tc.ctx, 100, 0);
    try std.testing.expectEqual(@as(u64, 100), result.data.slot);
    try std.testing.expectEqual(@as(u64, 0), result.data.index);
    try std.testing.expectEqual(tc.ctx.head_tracker.head_root, result.data.beacon_block_root);
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
                .source_epoch = 5,
                .source_root = [_]u8{0x11} ** 32,
                .target_epoch = 6,
                .target_root = [_]u8{0x22} ** 32,
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
}

test "produceBlock returns NotImplemented without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = produceBlock(&tc.ctx, 100, [_]u8{0} ** 96, null);
    try std.testing.expectError(error.NotImplemented, result);
}

test "getAggregateAttestation returns NotImplemented without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getAggregateAttestation(&tc.ctx, 100, [_]u8{0} ** 32);
    try std.testing.expectError(error.NotImplemented, result);
}

test "publishAggregateAndProofs with empty body returns ok" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = try publishAggregateAndProofs(&tc.ctx, "");
    _ = result;
}

test "publishContributionAndProofs with empty body returns ok" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = try publishContributionAndProofs(&tc.ctx, "");
    _ = result;
}

test "getSyncCommitteeContribution returns NotImplemented without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getSyncCommitteeContribution(&tc.ctx, 100, 0, [_]u8{0} ** 32);
    try std.testing.expectError(error.NotImplemented, result);
}

// ---------------------------------------------------------------------------
// Validator liveness
// ---------------------------------------------------------------------------

/// POST /eth/v1/validator/liveness/{epoch}
///
/// Check whether validators were live (made any on-chain activity) in the epoch.
/// Stub — requires attestation inclusion tracking from the DB.
pub fn getValidatorLiveness(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) !HandlerResult([]types.ValidatorLiveness) {
    const result = try ctx.allocator.alloc(types.ValidatorLiveness, validator_indices.len);
    errdefer ctx.allocator.free(result);

    for (validator_indices, 0..) |idx, i| {
        result[i] = .{
            .index = idx,
            .epoch = epoch,
            .is_live = false, // stub: would check DB for attestation inclusion
        };
    }

    return .{
        .data = result,
        .meta = .{},
    };
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
    _: *ApiContext,
    _: []const types.ProposerPreparation,
) !HandlerResult(void) {
    // TODO: store fee_recipient per validator_index in a fee recipient cache.
    // For now, accept and ignore (return 200).
    return .{ .data = {} };
}

/// POST /eth/v1/validator/register_validator
///
/// MEV-boost validator registration. Forward to builder API if wired.
pub fn registerValidator(
    ctx: *ApiContext,
    registrations: []const types.SignedValidatorRegistrationV1,
) !HandlerResult(void) {
    if (ctx.builder) |*builder_cb| {
        // Serialize registrations to JSON and forward to the relay.
        const json = serializeRegistrationsToJson(ctx.allocator, registrations) catch |err| {
            std.log.warn("registerValidator: failed to serialize registrations: {s}", .{@errorName(err)});
            return .{ .data = {} };
        };
        defer ctx.allocator.free(json);
        builder_cb.registerValidators(json) catch |err| {
            std.log.warn("registerValidator: builder relay error: {s}", .{@errorName(err)});
        };
    }
    return .{ .data = {} };
}

fn serializeRegistrationsToJson(
    allocator: std.mem.Allocator,
    registrations: []const types.SignedValidatorRegistrationV1,
) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    var writer = buf.writer();
    try writer.writeByte('[');
    for (registrations, 0..) |r, i| {
        if (i > 0) try writer.writeByte(',');
        const fee_hex = std.fmt.bytesToHex(&r.message.fee_recipient, .lower);
        const pk_hex = std.fmt.bytesToHex(&r.message.pubkey, .lower);
        const sig_hex = std.fmt.bytesToHex(&r.signature, .lower);
        const entry = try std.fmt.allocPrint(
            allocator,
            "{{\"{s}\":{{\"{s}\":\"0x{s}\",\"{s}\":\"{d}\",\"{s}\":\"{d}\",\"{s}\":\"0x{s}\"}},\"{s}\":\"0x{s}\"}}",
            .{
                "message",
                "fee_recipient", fee_hex,
                "gas_limit", r.message.gas_limit,
                "timestamp", r.message.timestamp,
                "pubkey", pk_hex,
                "signature", sig_hex,
            },
        );
        defer allocator.free(entry);
        try writer.writeAll(entry);
    }
    try writer.writeByte(']');
    return buf.toOwnedSlice();
}
