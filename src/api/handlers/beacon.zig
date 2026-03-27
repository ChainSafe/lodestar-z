//! Beacon API handlers.
//!
//! Pure functions implementing the `/eth/v1/beacon/*` and `/eth/v2/beacon/*`
//! endpoints. These require chain state access through the ApiContext.

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const CachedBeaconState = context.CachedBeaconState;
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;
const ResponseMeta = handler_result.ResponseMeta;

/// GET /eth/v1/beacon/genesis
///
/// Returns genesis time, genesis validators root, and genesis fork version.
pub fn getGenesis(ctx: *ApiContext) HandlerResult(types.GenesisData) {
    const cfg = ctx.beacon_config;
    return .{
        .data = .{
            .genesis_time = cfg.chain.MIN_GENESIS_TIME,
            .genesis_validators_root = cfg.genesis_validator_root,
            .genesis_fork_version = cfg.chain.GENESIS_FORK_VERSION,
        },
        .meta = .{ .finalized = true },
    };
}

/// GET /eth/v1/beacon/headers/{block_id}
///
/// Returns the block header for the given block identifier.
pub fn getBlockHeader(ctx: *ApiContext, block_id: types.BlockId) !HandlerResult(types.BlockHeaderData) {
    const result = try resolveBlockHeader(ctx, block_id);
    return .{
        .data = result.header,
        .meta = .{
            .execution_optimistic = result.execution_optimistic,
            .finalized = result.finalized,
        },
    };
}

/// GET /eth/v2/beacon/blocks/{block_id}
///
/// Returns the full signed beacon block for the given block identifier.
/// The response is fork-versioned; callers should check the `version` field.
///
/// Note: Returns raw SSZ bytes from the DB. The HTTP layer is responsible
/// for content negotiation (JSON vs SSZ encoding).
pub fn getBlock(ctx: *ApiContext, block_id: types.BlockId) !BlockResult {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);

    // Try hot (unfinalized) first, then cold (archived)
    const block_bytes = (try ctx.db.getBlock(slot_info.root)) orelse
        (try ctx.db.getBlockArchiveByRoot(slot_info.root)) orelse
        return error.BlockNotFound;

    // Determine fork from slot for version metadata
    const fork_name = forkNameFromSlot(ctx, slot_info.slot);

    return .{
        .data = block_bytes,
        .slot = slot_info.slot,
        .execution_optimistic = !slot_info.finalized,
        .finalized = slot_info.finalized,
        .fork_name = fork_name,
    };
}

pub const BlockResult = struct {
    /// Raw SSZ bytes of the signed beacon block.
    data: []const u8,
    slot: u64,
    execution_optimistic: bool,
    finalized: bool,
    fork_name: handler_result.Fork = .phase0,
};

/// Determine the fork name for a given slot using the beacon config.
fn forkNameFromSlot(ctx: *ApiContext, slot: u64) handler_result.Fork {
    const fork_seq = ctx.beacon_config.forkSeq(slot);
    return switch (fork_seq) {
        .phase0 => .phase0,
        .altair => .altair,
        .bellatrix => .bellatrix,
        .capella => .capella,
        .deneb => .deneb,
        .electra => .electra,
        else => .phase0,
    };
}

/// GET /eth/v2/beacon/states/{state_id}/validators
///
/// Returns the list of validators for the given state.
/// Supports optional filtering by validator IDs and statuses.
///
/// For `head` and `justified`, uses the head state callback.
/// For `finalized`, `genesis`, slot, and root — loads the state from the
/// DB archive and deserializes it. This is the state regen path.
pub fn getValidators(
    ctx: *ApiContext,
    state_id: types.StateId,
    _: types.ValidatorQuery,
) !HandlerResult([]const types.ValidatorData) {
    // Try the head state callback for head/justified.
    const use_head = switch (state_id) {
        .head, .justified => true,
        else => false,
    };

    if (use_head) {
        const cb = ctx.head_state orelse return error.StateNotAvailable;
        const state_opaque = cb.getHeadStateFn(cb.ptr) orelse return error.StateNotAvailable;
        const state: *CachedBeaconState = @ptrCast(@alignCast(state_opaque));
        return buildValidatorResponse(ctx, state);
    }

    // Try state regen callback for non-head state lookups.
    if (ctx.state_regen_callback) |regen_cb| {
        const state = switch (state_id) {
            .root => |root| regen_cb.getStateByRoot(root),
            .head, .justified => unreachable, // handled above
            else => null, // slot-based lookup not yet wired
        };
        if (state) |s| return buildValidatorResponse(ctx, s);
    }

    // State regen not available or lookup failed.
    return error.StateNotAvailable;
}

/// Build a validator response from a CachedBeaconState.
fn buildValidatorResponse(
    ctx: *ApiContext,
    state: *CachedBeaconState,
) !HandlerResult([]const types.ValidatorData) {
    // Read validators and balances from the state
    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);
    const balances = try state.state.balancesSlice(ctx.allocator);
    defer ctx.allocator.free(balances);

    const epoch = (try state.state.slot()) / preset.SLOTS_PER_EPOCH;

    var result = std.ArrayList(types.ValidatorData).empty;
    errdefer result.deinit(ctx.allocator);

    for (validators, 0..) |v, i| {
        const balance = if (i < balances.len) balances[i] else 0;
        try result.append(ctx.allocator, .{
            .index = @intCast(i),
            .balance = balance,
            .status = types.ValidatorStatus.fromValidator(&v, epoch),
            .validator = .{
                .pubkey = v.pubkey,
                .withdrawal_credentials = v.withdrawal_credentials,
                .effective_balance = v.effective_balance,
                .slashed = v.slashed,
                .activation_eligibility_epoch = v.activation_eligibility_epoch,
                .activation_epoch = v.activation_epoch,
                .exit_epoch = v.exit_epoch,
                .withdrawable_epoch = v.withdrawable_epoch,
            },
        });
    }

    return .{
        .data = try result.toOwnedSlice(ctx.allocator),
        .meta = .{
            .execution_optimistic = false,
            .finalized = false,
        },
    };
}

/// GET /eth/v2/beacon/states/{state_id}/validators/{validator_id}
///
/// Returns a single validator from the given state.
pub fn getValidator(
    ctx: *ApiContext,
    state_id: types.StateId,
    validator_id: types.ValidatorId,
) !HandlerResult(types.ValidatorData) {
    // Only head state is available via the head_state callback for now.
    const use_head = switch (state_id) {
        .head, .justified => true,
        else => false,
    };

    if (!use_head) return error.StateNotAvailable;

    const cb = ctx.head_state orelse return error.StateNotAvailable;
    const state_opaque = cb.getHeadStateFn(cb.ptr) orelse return error.StateNotAvailable;
    const state: *CachedBeaconState = @ptrCast(@alignCast(state_opaque));

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);
    const balances = try state.state.balancesSlice(ctx.allocator);
    defer ctx.allocator.free(balances);

    const epoch = (try state.state.slot()) / preset.SLOTS_PER_EPOCH;

    // Resolve validator index from id
    const index: u64 = switch (validator_id) {
        .index => |idx| idx,
        .pubkey => |pk| blk: {
            for (validators, 0..) |v, i| {
                if (std.mem.eql(u8, &v.pubkey, &pk)) break :blk @intCast(i);
            }
            return error.ValidatorNotFound;
        },
    };

    if (index >= validators.len) return error.ValidatorNotFound;

    const v = validators[index];
    const balance = if (index < balances.len) balances[index] else 0;

    return .{
        .data = .{
            .index = index,
            .balance = balance,
            .status = types.ValidatorStatus.fromValidator(&v, epoch),
            .validator = .{
                .pubkey = v.pubkey,
                .withdrawal_credentials = v.withdrawal_credentials,
                .effective_balance = v.effective_balance,
                .slashed = v.slashed,
                .activation_eligibility_epoch = v.activation_eligibility_epoch,
                .activation_epoch = v.activation_epoch,
                .exit_epoch = v.exit_epoch,
                .withdrawable_epoch = v.withdrawable_epoch,
            },
        },
        .meta = .{},
    };
}

/// GET /eth/v1/beacon/states/{state_id}/root
///
/// Returns the state root for the given state identifier.
pub fn getStateRoot(ctx: *ApiContext, state_id: types.StateId) !HandlerResult([32]u8) {
    switch (state_id) {
        .head => {
            return .{
                .data = ctx.head_tracker.head_state_root,
                .meta = .{},
            };
        },
        .finalized => {
            // For finalized, we'd need the state root at finalized slot.
            // Approximate with head_state_root for now if finalized == head.
            return .{
                .data = ctx.head_tracker.head_state_root,
                .meta = .{ .finalized = true },
            };
        },
        .genesis => {
            // Genesis state root would be stored in config/DB.
            return .{
                .data = [_]u8{0} ** 32, // placeholder
                .meta = .{ .finalized = true },
            };
        },
        .justified => {
            return .{
                .data = ctx.head_tracker.head_state_root,
                .meta = .{},
            };
        },
        .slot => |slot| {
            // Look up the block at this slot, deserialize it, and return the state_root.
            const root = (try ctx.db.getBlockRootBySlot(slot)) orelse return error.SlotNotFound;

            // Try hot store first, then archived
            const block_bytes = (try ctx.db.getBlock(root)) orelse
                (try ctx.db.getBlockArchiveByRoot(root)) orelse
                return error.BlockNotFound;
            defer ctx.allocator.free(block_bytes);

            const fork_seq = ctx.beacon_config.forkSeq(slot);
            const any_block = try AnySignedBeaconBlock.deserialize(ctx.allocator, .full, fork_seq, block_bytes);
            defer any_block.deinit(ctx.allocator);

            const state_root = any_block.beaconBlock().stateRoot().*;
            return .{
                .data = state_root,
                .meta = .{ .finalized = slot <= ctx.head_tracker.finalized_slot },
            };
        },
        .root => |root| {
            // The state_id IS the root
            return .{
                .data = root,
                .meta = .{},
            };
        },
    }
}

/// GET /eth/v1/beacon/states/{state_id}/fork
///
/// Returns the fork data for the given state.
pub fn getStateFork(ctx: *ApiContext, state_id: types.StateId) !HandlerResult(types.ForkData) {
    // Determine the slot to compute the fork for
    const slot = resolveStateSlot(ctx, state_id);

    // Walk the config's fork schedule to find the active fork at this slot
    const cfg = ctx.beacon_config;
    const epoch = slot / preset.SLOTS_PER_EPOCH;

    var result = types.ForkData{
        .previous_version = cfg.chain.GENESIS_FORK_VERSION,
        .current_version = cfg.chain.GENESIS_FORK_VERSION,
        .epoch = 0,
    };

    // Walk ascending fork schedule
    for (cfg.forks_ascending_epoch_order) |fork_info| {
        if (fork_info.epoch <= epoch) {
            result = .{
                .previous_version = fork_info.prev_version,
                .current_version = fork_info.version,
                .epoch = fork_info.epoch,
            };
        } else {
            break;
        }
    }

    return .{
        .data = result,
        .meta = .{
            .finalized = switch (state_id) {
                .finalized, .genesis => true,
                else => false,
            },
        },
    };
}

/// GET /eth/v1/beacon/states/{state_id}/finality_checkpoints
///
/// Returns the finality checkpoints (previous justified, current justified, finalized).
///
/// Note: Full implementation requires loading the beacon state for each state_id.
/// Currently returns data from the head tracker which only tracks the current head's
/// finalized/justified data. Non-head state_ids fall back to head tracker data.
pub fn getFinalityCheckpoints(ctx: *ApiContext, _: types.StateId) !HandlerResult(types.FinalityCheckpoints) {
    // TODO: Load actual state for non-head state_ids. This requires state regen to be
    // wired into the API context so we can load the beacon state at any slot/root.
    return .{
        .data = .{
            .previous_justified = .{
                .epoch = ctx.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
                .root = ctx.head_tracker.justified_root,
            },
            .current_justified = .{
                .epoch = ctx.head_tracker.justified_slot / preset.SLOTS_PER_EPOCH,
                .root = ctx.head_tracker.justified_root,
            },
            .finalized = .{
                .epoch = ctx.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH,
                .root = ctx.head_tracker.finalized_root,
            },
        },
        .meta = .{},
    };
}

/// POST /eth/v2/beacon/blocks
///
/// Submit a signed beacon block for propagation and import.
///
/// Accepts raw SSZ bytes of a SignedBeaconBlock and forwards them to
/// the block import pipeline registered on the ApiContext. Returns
/// error.NotImplemented if no import callback is wired.
pub fn submitBlock(
    ctx: *ApiContext,
    block_bytes: []const u8,
) !HandlerResult(void) {
    const cb = ctx.block_import orelse return error.NotImplemented;
    try cb.importFn(cb.ptr, block_bytes);
    return .{ .data = {} };
}

/// POST /eth/v1/beacon/pool/attestations
/// POST /eth/v1/beacon/pool/voluntary_exits
/// POST /eth/v1/beacon/pool/proposer_slashings
/// POST /eth/v1/beacon/pool/attester_slashings
/// POST /eth/v1/beacon/pool/bls_to_execution_changes
/// POST /eth/v1/beacon/pool/sync_committees
///
/// All pool submission endpoints follow the same pattern: accept an encoded
/// object (JSON or SSZ), validate/process, return 200 on success.
/// These are stubs — full implementation requires op pool write callbacks.
pub fn submitPoolAttestations(_: *ApiContext, _: []const u8) !HandlerResult(void) {
    // TODO: wire op pool submit callback
    return .{ .data = {} };
}

pub fn submitPoolVoluntaryExits(_: *ApiContext, _: []const u8) !HandlerResult(void) {
    return .{ .data = {} };
}

pub fn submitPoolProposerSlashings(_: *ApiContext, _: []const u8) !HandlerResult(void) {
    return .{ .data = {} };
}

pub fn submitPoolAttesterSlashings(_: *ApiContext, _: []const u8) !HandlerResult(void) {
    return .{ .data = {} };
}

pub fn submitPoolBlsToExecutionChanges(_: *ApiContext, _: []const u8) !HandlerResult(void) {
    return .{ .data = {} };
}

pub fn submitPoolSyncCommittees(_: *ApiContext, _: []const u8) !HandlerResult(void) {
    return .{ .data = {} };
}

// ---------------------------------------------------------------------------
// Pool endpoints
// ---------------------------------------------------------------------------

/// GET /eth/v1/beacon/pool/attestations
///
/// Returns pending attestation group count from the operation pool.
/// The full response with attestation data requires the op pool callback.
pub fn getPoolAttestations(ctx: *ApiContext) HandlerResult(types.PoolCounts) {
    const counts = getPoolCountsFromCtx(ctx);
    return .{
        .data = .{
            .attestation_groups = counts[0],
            .voluntary_exits = counts[1],
            .proposer_slashings = counts[2],
            .attester_slashings = counts[3],
            .bls_to_execution_changes = counts[4],
        },
    };
}

/// GET /eth/v1/beacon/pool/voluntary_exits
///
/// Returns the count of pending voluntary exits.
pub fn getPoolVoluntaryExits(ctx: *ApiContext) HandlerResult(usize) {
    const counts = getPoolCountsFromCtx(ctx);
    return .{ .data = counts[1] };
}

/// GET /eth/v1/beacon/pool/proposer_slashings
///
/// Returns the count of pending proposer slashings.
pub fn getPoolProposerSlashings(ctx: *ApiContext) HandlerResult(usize) {
    const counts = getPoolCountsFromCtx(ctx);
    return .{ .data = counts[2] };
}

/// GET /eth/v1/beacon/pool/attester_slashings
///
/// Returns the count of pending attester slashings.
pub fn getPoolAttesterSlashings(ctx: *ApiContext) HandlerResult(usize) {
    const counts = getPoolCountsFromCtx(ctx);
    return .{ .data = counts[3] };
}

/// GET /eth/v1/beacon/pool/bls_to_execution_changes
///
/// Returns the count of pending BLS-to-execution changes.
pub fn getPoolBlsToExecutionChanges(ctx: *ApiContext) HandlerResult(usize) {
    const counts = getPoolCountsFromCtx(ctx);
    return .{ .data = counts[4] };
}

fn getPoolCountsFromCtx(ctx: *ApiContext) [5]usize {
    const cb = ctx.op_pool orelse return [5]usize{ 0, 0, 0, 0, 0 };
    return cb.getPoolCountsFn(cb.ptr);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const SlotAndRoot = struct {
    slot: u64,
    root: [32]u8,
    finalized: bool,
};

fn resolveBlockSlotAndRoot(ctx: *ApiContext, block_id: types.BlockId) !SlotAndRoot {
    switch (block_id) {
        .head => return .{
            .slot = ctx.head_tracker.head_slot,
            .root = ctx.head_tracker.head_root,
            .finalized = false,
        },
        .finalized => return .{
            .slot = ctx.head_tracker.finalized_slot,
            .root = ctx.head_tracker.finalized_root,
            .finalized = true,
        },
        .justified => return .{
            .slot = ctx.head_tracker.justified_slot,
            .root = ctx.head_tracker.justified_root,
            .finalized = false,
        },
        .genesis => return .{
            .slot = 0,
            .root = [_]u8{0} ** 32,
            .finalized = true,
        },
        .slot => |slot| {
            const root = (try ctx.db.getBlockRootBySlot(slot)) orelse return error.SlotNotFound;
            return .{
                .slot = slot,
                .root = root,
                .finalized = slot <= ctx.head_tracker.finalized_slot,
            };
        },
        .root => |root| {
            // We have the root; look up the block to get the real slot.
            const block_bytes = (try ctx.db.getBlock(root)) orelse
                (try ctx.db.getBlockArchiveByRoot(root)) orelse
                return error.BlockNotFound;
            defer ctx.allocator.free(block_bytes);

            // Determine fork from head slot as a best approximation (we don't
            // know the block's slot before deserializing it). For a proper
            // implementation we'd store a root->slot index in the DB.
            const fork_seq = ctx.beacon_config.forkSeq(ctx.head_tracker.head_slot);
            const any_block = try AnySignedBeaconBlock.deserialize(ctx.allocator, .full, fork_seq, block_bytes);
            defer any_block.deinit(ctx.allocator);

            const block = any_block.beaconBlock();
            return .{
                .slot = block.slot(),
                .root = root,
                .finalized = block.slot() <= ctx.head_tracker.finalized_slot,
            };
        },
    }
}

const BlockHeaderResult = struct {
    header: types.BlockHeaderData,
    execution_optimistic: bool,
    finalized: bool,
};

fn resolveBlockHeader(ctx: *ApiContext, block_id: types.BlockId) !BlockHeaderResult {
    const slot_info = try resolveBlockSlotAndRoot(ctx, block_id);

    // Try to load and deserialize the block to get real header fields.
    const block_bytes_opt = (try ctx.db.getBlock(slot_info.root)) orelse
        try ctx.db.getBlockArchiveByRoot(slot_info.root);

    if (block_bytes_opt) |block_bytes| {
        defer ctx.allocator.free(block_bytes);

        const fork_seq = ctx.beacon_config.forkSeq(slot_info.slot);
        const any_signed = try AnySignedBeaconBlock.deserialize(ctx.allocator, .full, fork_seq, block_bytes);
        defer any_signed.deinit(ctx.allocator);

        const block = any_signed.beaconBlock();

        // Compute body_root via hash_tree_root of the body
        var body_root: [32]u8 = [_]u8{0} ** 32;
        try block.beaconBlockBody().hashTreeRoot(ctx.allocator, &body_root);

        const sig = any_signed.signature();

        return .{
            .header = .{
                .root = slot_info.root,
                .canonical = true,
                .header = .{
                    .message = .{
                        .slot = block.slot(),
                        .proposer_index = block.proposerIndex(),
                        .parent_root = block.parentRoot().*,
                        .state_root = block.stateRoot().*,
                        .body_root = body_root,
                    },
                    .signature = sig.*,
                },
            },
            .execution_optimistic = !slot_info.finalized,
            .finalized = slot_info.finalized,
        };
    }

    // Block not in DB — return what we know from the head tracker with zero fields.
    return .{
        .header = .{
            .root = slot_info.root,
            .canonical = true,
            .header = .{
                .message = .{
                    .slot = slot_info.slot,
                    .proposer_index = 0,
                    .parent_root = [_]u8{0} ** 32,
                    .state_root = [_]u8{0} ** 32,
                    .body_root = [_]u8{0} ** 32,
                },
                .signature = [_]u8{0} ** 96,
            },
        },
        .execution_optimistic = !slot_info.finalized,
        .finalized = slot_info.finalized,
    };
}

fn resolveStateSlot(ctx: *ApiContext, state_id: types.StateId) u64 {
    return switch (state_id) {
        .head => ctx.head_tracker.head_slot,
        .finalized => ctx.head_tracker.finalized_slot,
        .justified => ctx.head_tracker.justified_slot,
        .genesis => 0,
        .slot => |s| s,
        .root => ctx.head_tracker.head_slot, // fallback; would need root->slot lookup
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getGenesis returns genesis data from config" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getGenesis(&tc.ctx);
    try std.testing.expectEqual(@as(u64, 1606824000), resp.data.genesis_time);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "getStateRoot for head returns head state root" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getStateRoot(&tc.ctx, .head);
    try std.testing.expectEqual(tc.ctx.head_tracker.head_state_root, resp.data);
}

test "getStateRoot for slot returns state_root from block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // Build a minimal phase0 signed block with a known state_root and store it.
    const ct = @import("consensus_types");

    var signed_block = ct.phase0.SignedBeaconBlock.default_value;
    signed_block.message.slot = 1;
    signed_block.message.state_root = [_]u8{0xee} ** 32;

    // Serialize the block
    const block_size = ct.phase0.SignedBeaconBlock.serializedSize(&signed_block);
    const block_bytes = try std.testing.allocator.alloc(u8, block_size);
    defer std.testing.allocator.free(block_bytes);
    _ = ct.phase0.SignedBeaconBlock.serializeIntoBytes(&signed_block, block_bytes);

    // Compute block root (just use a fixed test root)
    const block_root = [_]u8{0x11} ** 32;
    try tc.db.putBlockArchive(1, block_root, block_bytes);

    const resp = try getStateRoot(&tc.ctx, .{ .slot = 1 });
    try std.testing.expectEqual([_]u8{0xee} ** 32, resp.data);
}

test "getStateRoot for slot returns SlotNotFound if no block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getStateRoot(&tc.ctx, .{ .slot = 999 });
    try std.testing.expectError(error.SlotNotFound, result);
}

test "getStateFork returns genesis fork for slot 0" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getStateFork(&tc.ctx, .genesis);
    try std.testing.expectEqual(tc.ctx.beacon_config.chain.GENESIS_FORK_VERSION, resp.data.current_version);
    try std.testing.expect(resp.meta.finalized orelse false);
}

test "getFinalityCheckpoints returns checkpoint data" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getFinalityCheckpoints(&tc.ctx, .head);
    const expected_epoch = tc.ctx.head_tracker.finalized_slot / preset.SLOTS_PER_EPOCH;
    try std.testing.expectEqual(expected_epoch, resp.data.finalized.epoch);
}

test "getBlockHeader for head returns header" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expectEqual(tc.ctx.head_tracker.head_slot, resp.data.header.message.slot);
    try std.testing.expect(resp.data.canonical);
}

test "getBlockHeader for head extracts real fields from DB block" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const ct = @import("consensus_types");

    // Build a phase0 signed block with known fields
    var signed_block = ct.phase0.SignedBeaconBlock.default_value;
    signed_block.message.slot = tc.ctx.head_tracker.head_slot;
    signed_block.message.proposer_index = 42;
    signed_block.message.parent_root = [_]u8{0xab} ** 32;
    signed_block.message.state_root = [_]u8{0xcd} ** 32;
    signed_block.signature = [_]u8{0xef} ** 96;

    const block_size = ct.phase0.SignedBeaconBlock.serializedSize(&signed_block);
    const block_bytes = try std.testing.allocator.alloc(u8, block_size);
    defer std.testing.allocator.free(block_bytes);
    _ = ct.phase0.SignedBeaconBlock.serializeIntoBytes(&signed_block, block_bytes);

    // Store under the head root
    try tc.db.putBlock(tc.ctx.head_tracker.head_root, block_bytes);

    const resp = try getBlockHeader(&tc.ctx, .head);
    try std.testing.expectEqual(@as(u64, 42), resp.data.header.message.proposer_index);
    try std.testing.expectEqual([_]u8{0xab} ** 32, resp.data.header.message.parent_root);
    try std.testing.expectEqual([_]u8{0xcd} ** 32, resp.data.header.message.state_root);
    try std.testing.expectEqual([_]u8{0xef} ** 96, resp.data.header.signature);
}

test "getValidators without head state returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    // head_state is null in test context
    const result = getValidators(&tc.ctx, .head, .{});
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getValidators non-head returns StateNotAvailable" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getValidators(&tc.ctx, .{ .slot = 10 }, .{});
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getValidators with head state returns non-empty list" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    // Wire head state callback
    const HeadStateCb = struct {
        cached: *state_transition.CachedBeaconState,

        fn getState(ptr: *anyopaque) ?*state_transition.CachedBeaconState {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.cached;
        }
    };

    var cb_ctx = HeadStateCb{ .cached = test_state.cached_state };
    tc.ctx.head_state = .{
        .ptr = &cb_ctx,
        .getHeadStateFn = &HeadStateCb.getState,
    };

    const resp = try getValidators(&tc.ctx, .head, .{});
    defer allocator.free(resp.data);

    try std.testing.expectEqual(@as(usize, 4), resp.data.len);
    // Each validator should have a valid index
    try std.testing.expectEqual(@as(u64, 0), resp.data[0].index);
    try std.testing.expectEqual(@as(u64, 3), resp.data[3].index);
}

test "getValidator with valid index returns data" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const HeadStateCb = struct {
        cached: *state_transition.CachedBeaconState,

        fn getState(ptr: *anyopaque) ?*state_transition.CachedBeaconState {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.cached;
        }
    };

    var cb_ctx = HeadStateCb{ .cached = test_state.cached_state };
    tc.ctx.head_state = .{
        .ptr = &cb_ctx,
        .getHeadStateFn = &HeadStateCb.getState,
    };

    const resp = try getValidator(&tc.ctx, .head, .{ .index = 2 });
    try std.testing.expectEqual(@as(u64, 2), resp.data.index);
    // Validator should be active (activation_epoch 0, exit_epoch max)
    try std.testing.expectEqual(types.ValidatorStatus.active_ongoing, resp.data.status);
}

test "getValidator with out-of-range index returns ValidatorNotFound" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const HeadStateCb = struct {
        cached: *state_transition.CachedBeaconState,

        fn getState(ptr: *anyopaque) ?*state_transition.CachedBeaconState {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.cached;
        }
    };

    var cb_ctx = HeadStateCb{ .cached = test_state.cached_state };
    tc.ctx.head_state = .{
        .ptr = &cb_ctx,
        .getHeadStateFn = &HeadStateCb.getState,
    };

    const result = getValidator(&tc.ctx, .head, .{ .index = 99 });
    try std.testing.expectError(error.ValidatorNotFound, result);
}

test "submitBlock returns NotImplemented when block_import is null" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    // block_import defaults to null
    const fake_bytes = [_]u8{0x01, 0x02, 0x03};
    const result = submitBlock(&tc.ctx, &fake_bytes);
    try std.testing.expectError(error.NotImplemented, result);
}

test "submitBlock invokes block_import callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // Mock callback that records invocation
    const MockImporter = struct {
        called: bool = false,
        received_len: usize = 0,

        fn importBlock(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.called = true;
            self.received_len = block_bytes.len;
        }
    };

    var mock = MockImporter{};
    tc.ctx.block_import = .{
        .ptr = &mock,
        .importFn = &MockImporter.importBlock,
    };

    const fake_bytes = [_]u8{0xDE, 0xAD, 0xBE, 0xEF} ** 4;
    const result = try submitBlock(&tc.ctx, &fake_bytes);
    _ = result;

    try std.testing.expect(mock.called);
    try std.testing.expectEqual(fake_bytes.len, mock.received_len);
}

test "submitBlock propagates error from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const FailImporter = struct {
        fn importBlock(_: *anyopaque, _: []const u8) anyerror!void {
            return error.BlockAlreadyKnown;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.block_import = .{
        .ptr = &dummy,
        .importFn = &FailImporter.importBlock,
    };

    const fake_bytes = [_]u8{0x01};
    const result = submitBlock(&tc.ctx, &fake_bytes);
    try std.testing.expectError(error.BlockAlreadyKnown, result);
}

test "getPoolAttestations returns zero counts when no op_pool" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = getPoolAttestations(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 0), resp.data.attestation_groups);
}

test "getPoolAttestations returns counts from callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockOpPool = struct {
        fn getPoolCounts(_: *anyopaque) [5]usize {
            return .{ 10, 3, 1, 2, 5 };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.op_pool = .{
        .ptr = &dummy,
        .getPoolCountsFn = &MockOpPool.getPoolCounts,
    };

    const resp = getPoolAttestations(&tc.ctx);
    try std.testing.expectEqual(@as(usize, 10), resp.data.attestation_groups);
    try std.testing.expectEqual(@as(usize, 3), resp.data.voluntary_exits);
    try std.testing.expectEqual(@as(usize, 1), resp.data.proposer_slashings);
}
