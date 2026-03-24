//! Beacon API handlers.
//!
//! Pure functions implementing the `/eth/v1/beacon/*` and `/eth/v2/beacon/*`
//! endpoints. These require chain state access through the ApiContext.

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

/// GET /eth/v1/beacon/genesis
///
/// Returns genesis time, genesis validators root, and genesis fork version.
pub fn getGenesis(ctx: *ApiContext) types.ApiResponse(types.GenesisData) {
    const cfg = ctx.beacon_config;
    return .{
        .data = .{
            .genesis_time = cfg.chain.MIN_GENESIS_TIME,
            .genesis_validators_root = cfg.genesis_validator_root,
            .genesis_fork_version = cfg.chain.GENESIS_FORK_VERSION,
        },
        .finalized = true,
    };
}

/// GET /eth/v1/beacon/headers/{block_id}
///
/// Returns the block header for the given block identifier.
pub fn getBlockHeader(ctx: *ApiContext, block_id: types.BlockId) !types.ApiResponse(types.BlockHeaderData) {
    const result = try resolveBlockHeader(ctx, block_id);
    return .{
        .data = result.header,
        .execution_optimistic = result.execution_optimistic,
        .finalized = result.finalized,
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

    return .{
        .data = block_bytes,
        .slot = slot_info.slot,
        .execution_optimistic = !slot_info.finalized,
        .finalized = slot_info.finalized,
    };
}

pub const BlockResult = struct {
    /// Raw SSZ bytes of the signed beacon block.
    data: []const u8,
    slot: u64,
    execution_optimistic: bool,
    finalized: bool,
};

/// GET /eth/v2/beacon/states/{state_id}/validators
///
/// Returns the list of validators for the given state.
/// Supports optional filtering by validator IDs and statuses.
///
/// Note: Full implementation requires state regeneration. Currently returns
/// a stub until StateRegen is wired up.
pub fn getValidators(
    _: *ApiContext,
    _: types.StateId,
    _: types.ValidatorQuery,
) !types.ApiResponse([]const types.ValidatorData) {
    // TODO: Implement once state regen is available.
    // This will need to:
    // 1. Resolve StateId to a slot/root
    // 2. Regenerate or load the state (via ctx.regen.getStateAtSlot)
    // 3. Iterate validators, apply filters
    // 4. Return matching validators with balances and status
    // State regen is not yet wired to the API context — returning empty stub.
    return .{
        .data = &[_]types.ValidatorData{},
    };
}

/// GET /eth/v2/beacon/states/{state_id}/validators/{validator_id}
///
/// Returns a single validator from the given state.
pub fn getValidator(
    _: *ApiContext,
    _: types.StateId,
    _: types.ValidatorId,
) !types.ApiResponse(types.ValidatorData) {
    // TODO: Implement once state regen is available.
    // State regen is not yet wired to the API context.
    // See getValidators for the required implementation steps.
    return error.StateNotAvailable;
}

/// GET /eth/v1/beacon/states/{state_id}/root
///
/// Returns the state root for the given state identifier.
pub fn getStateRoot(ctx: *ApiContext, state_id: types.StateId) !types.ApiResponse([32]u8) {
    switch (state_id) {
        .head => {
            return .{
                .data = ctx.head_tracker.head_state_root,
            };
        },
        .finalized => {
            // For finalized, we'd need the state root at finalized slot.
            // Approximate with head_state_root for now if finalized == head.
            return .{
                .data = ctx.head_tracker.head_state_root,
                .finalized = true,
            };
        },
        .genesis => {
            // Genesis state root would be stored in config/DB.
            return .{
                .data = [_]u8{0} ** 32, // placeholder
                .finalized = true,
            };
        },
        .justified => {
            return .{
                .data = ctx.head_tracker.head_state_root,
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
                .finalized = slot <= ctx.head_tracker.finalized_slot,
            };
        },
        .root => |root| {
            // The state_id IS the root
            return .{
                .data = root,
            };
        },
    }
}

/// GET /eth/v1/beacon/states/{state_id}/fork
///
/// Returns the fork data for the given state.
pub fn getStateFork(ctx: *ApiContext, state_id: types.StateId) !types.ApiResponse(types.ForkData) {
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
        .finalized = switch (state_id) {
            .finalized, .genesis => true,
            else => false,
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
pub fn getFinalityCheckpoints(ctx: *ApiContext, _: types.StateId) !types.ApiResponse(types.FinalityCheckpoints) {
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
    };
}

/// POST /eth/v2/beacon/blocks
///
/// Submit a signed beacon block for propagation and import.
///
/// Returns whether the block was accepted. The actual block processing
/// pipeline is not yet implemented.
pub fn submitBlock(
    _: *ApiContext,
    _: []const u8, // raw block bytes
) !void {
    // TODO: Implement block import pipeline.
    // ApiContext needs a block importer callback or reference, e.g.:
    //   ctx.block_importer.importBlock(block_bytes)
    // Steps required:
    // 1. Determine fork from slot in the raw bytes
    // 2. Deserialize into AnySignedBeaconBlock
    // 3. Validate block (parent exists, correct slot, valid signature)
    // 4. Import into fork choice via BlockImporter
    // 5. Gossip to peers via P2P layer
    // Adding a block_importer field to ApiContext is the prerequisite.
    return error.NotImplemented;
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
    try std.testing.expect(resp.finalized);
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
    try std.testing.expect(resp.finalized);
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

test "getValidators returns empty stub" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const resp = try getValidators(&tc.ctx, .head, .{});
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}
