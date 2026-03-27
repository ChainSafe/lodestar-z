//! Block body production.
//!
//! Assembles a full `BeaconBlockBody` by:
//! 1. Pulling pending operations from the op pool (attestations, slashings, exits, BLS changes)
//! 2. Incorporating the execution payload from the engine API
//! 3. Building sync aggregate (empty for now — no sync committee contribution pool yet)
//! 4. Setting eth1_data, graffiti, and randao_reveal
//!
//! The `produceBlockBody` function returns a lightweight `ProducedBlockBody` of op slices
//! for use by code that only needs the operations. For full block assembly including
//! execution payload integration, use `BlockProducer`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Epoch = types.primitive.Epoch.Type;

const OpPool = @import("op_pool.zig").OpPool;

const execution_types = @import("execution").engine_api_types;
const GetPayloadResponse = @import("execution").GetPayloadResponse;
const ExecutionPayloadV3 = execution_types.ExecutionPayloadV3;

// Per-block operation limits (Phase0 / pre-Electra).
pub const MAX_ATTESTATIONS: u32 = preset.MAX_ATTESTATIONS;
pub const MAX_VOLUNTARY_EXITS: u32 = preset.MAX_VOLUNTARY_EXITS;
pub const MAX_PROPOSER_SLASHINGS: u32 = preset.MAX_PROPOSER_SLASHINGS;
pub const MAX_ATTESTER_SLASHINGS: u32 = preset.MAX_ATTESTER_SLASHINGS;
pub const MAX_BLS_TO_EXECUTION_CHANGES: u32 = preset.MAX_BLS_TO_EXECUTION_CHANGES;

/// Graffiti bytes (32 bytes). Can be set by the validator.
pub const DEFAULT_GRAFFITI: [32]u8 = blk: {
    // "lodestar-z" padded with zeros
    var g: [32]u8 = [_]u8{0} ** 32;
    const tag = "lodestar-z";
    @memcpy(g[0..tag.len], tag);
    break :blk g;
};

/// Result of block body production.
///
/// Contains slices of pending operations selected from the op pool.
/// Caller owns all returned slices and must free them with the same
/// allocator.
pub const ProducedBlockBody = struct {
    attestations: []types.phase0.Attestation.Type,
    voluntary_exits: []types.phase0.SignedVoluntaryExit.Type,
    proposer_slashings: []types.phase0.ProposerSlashing.Type,
    attester_slashings: []types.phase0.AttesterSlashing.Type,
    bls_to_execution_changes: []types.capella.SignedBLSToExecutionChange.Type,

    /// Free all owned slices.
    pub fn deinit(self: *ProducedBlockBody, allocator: Allocator) void {
        allocator.free(self.attestations);
        allocator.free(self.voluntary_exits);
        allocator.free(self.proposer_slashings);
        allocator.free(self.attester_slashings);
        allocator.free(self.bls_to_execution_changes);
    }
};

/// Full block production result including execution payload and blobs.
///
/// Wraps the assembled block body with the execution layer artifacts
/// needed for broadcasting (blobs bundle) and tracking (block value).
pub const ProducedBlock = struct {
    /// Fully assembled BeaconBlockBody (Electra fork — current target).
    block_body: types.electra.BeaconBlockBody.Type,

    /// Blobs bundle from the execution engine (commitments, proofs, blobs).
    /// Null if no blobs were produced.
    blobs_bundle: ?execution_types.BlobsBundle,

    /// Execution payload value in wei (MEV block value).
    block_value: u256,

    /// The proposer index that produced this block.
    proposer_index: ValidatorIndex,

    /// The slot this block is for.
    slot: Slot,

    /// Parent block root.
    parent_root: [32]u8,

    /// Free owned resources (mostly the execution payload data).
    pub fn deinit(self: *ProducedBlock, allocator: Allocator) void {
        // Free variable-length fields in the execution payload
        var body = &self.block_body;
        // execution_payload transactions and extra_data are owned by the engine response
        // We need to free the SSZ list backing memory
        body.attestations.deinit(allocator);
        body.voluntary_exits.deinit(allocator);
        body.proposer_slashings.deinit(allocator);
        body.attester_slashings.deinit(allocator);
        body.bls_to_execution_changes.deinit(allocator);
        body.deposits.deinit(allocator);
        body.blob_kzg_commitments.deinit(allocator);
        // execution_requests sub-lists
        body.execution_requests.deposits.deinit(allocator);
        body.execution_requests.withdrawals.deinit(allocator);
        body.execution_requests.consolidations.deinit(allocator);
        // execution_payload variable fields
        body.execution_payload.transactions.deinit(allocator);
        body.execution_payload.withdrawals.deinit(allocator);
        body.execution_payload.extra_data.deinit(allocator);
    }
};

/// Configuration for block production.
pub const BlockProductionConfig = struct {
    /// Fee recipient address for execution payload.
    fee_recipient: [20]u8 = [_]u8{0} ** 20,

    /// Custom graffiti (32 bytes). Uses DEFAULT_GRAFFITI if null.
    graffiti: ?[32]u8 = null,
};

/// Produce a block body by selecting pending operations from the pool.
///
/// The returned `ProducedBlockBody` holds slices allocated with `allocator`.
/// The caller must call `deinit` on the result when done.
///
/// NOTE: `slot` is accepted for future use (e.g. fork-aware limits).
/// The execution payload, RANDAO reveal, and graffiti are not included —
/// they come from the engine API and validator signing key, which are
/// wired separately.
pub fn produceBlockBody(
    allocator: Allocator,
    _: Slot, // slot — reserved for fork-aware logic
    op_pool: *OpPool,
) !ProducedBlockBody {
    const attestations = try op_pool.attestation_pool.getForBlock(allocator, MAX_ATTESTATIONS);
    errdefer allocator.free(attestations);

    const voluntary_exits = try op_pool.voluntary_exit_pool.getForBlock(allocator, MAX_VOLUNTARY_EXITS);
    errdefer allocator.free(voluntary_exits);

    const proposer_slashings = try op_pool.proposer_slashing_pool.getForBlock(allocator, MAX_PROPOSER_SLASHINGS);
    errdefer allocator.free(proposer_slashings);

    const attester_slashings = try op_pool.attester_slashing_pool.getForBlock(allocator, MAX_ATTESTER_SLASHINGS);
    errdefer allocator.free(attester_slashings);

    const bls_changes = try op_pool.bls_change_pool.getForBlock(allocator, MAX_BLS_TO_EXECUTION_CHANGES);

    return .{
        .attestations = attestations,
        .voluntary_exits = voluntary_exits,
        .proposer_slashings = proposer_slashings,
        .attester_slashings = attester_slashings,
        .bls_to_execution_changes = bls_changes,
    };
}

/// Assemble a full Electra BeaconBlockBody from op pool operations and
/// an execution payload response.
///
/// This is the main block assembly function. It:
/// 1. Pulls operations from the op pool (attestations, slashings, exits, BLS changes)
/// 2. Converts the Engine API execution payload to SSZ format
/// 3. Builds an empty sync aggregate (no sync contribution pool yet)
/// 4. Sets eth1_data from the head state, graffiti, and a zero RANDAO reveal
/// 5. Sets blob KZG commitments from the blobs bundle
/// 6. Sets execution requests (empty — populated from EL in future)
///
/// Returns a ProducedBlock with the full block body and metadata.
pub fn assembleBlock(
    allocator: Allocator,
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: [32]u8,
    op_pool: *OpPool,
    payload_response: ?GetPayloadResponse,
    eth1_data: types.phase0.Eth1Data.Type,
    config: BlockProductionConfig,
) !ProducedBlock {
    // 1. Pull operations from op pool
    const ops = try produceBlockBody(allocator, slot, op_pool);
    // Don't defer deinit — ownership transfers to the block body lists below

    // 2. Build execution payload (from engine response or empty)
    var exec_payload = types.electra.ExecutionPayload.default_value;
    var blobs_bundle: ?execution_types.BlobsBundle = null;
    var block_value: u256 = 0;
    var blob_commitments = std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type){};

    if (payload_response) |resp| {
        exec_payload = convertExecutionPayload(allocator, resp.execution_payload) catch |err| {
            std.log.warn("Failed to convert execution payload: {}", .{err});
            // Fall back to default empty payload
            exec_payload = types.electra.ExecutionPayload.default_value;
            return assembleBlockWithPayload(
                allocator,
                slot,
                proposer_index,
                parent_root,
                ops,
                exec_payload,
                null,
                0,
                blob_commitments,
                eth1_data,
                config,
            );
        };
        blobs_bundle = resp.blobs_bundle;
        block_value = resp.block_value;

        // Extract blob KZG commitments
        if (resp.blobs_bundle.commitments.len > 0) {
            blob_commitments = try std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).initCapacity(
                allocator,
                resp.blobs_bundle.commitments.len,
            );
            for (resp.blobs_bundle.commitments) |commitment| {
                blob_commitments.appendAssumeCapacity(commitment);
            }
        }
    }

    return assembleBlockWithPayload(
        allocator,
        slot,
        proposer_index,
        parent_root,
        ops,
        exec_payload,
        blobs_bundle,
        block_value,
        blob_commitments,
        eth1_data,
        config,
    );
}

/// Inner assembly: takes pre-converted components and builds the final block body.
fn assembleBlockWithPayload(
    allocator: Allocator,
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: [32]u8,
    ops: ProducedBlockBody,
    exec_payload: types.electra.ExecutionPayload.Type,
    blobs_bundle: ?execution_types.BlobsBundle,
    block_value: u256,
    blob_commitments: std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type),
    eth1_data: types.phase0.Eth1Data.Type,
    config: BlockProductionConfig,
) !ProducedBlock {

    // 3. Build sync aggregate (empty — no sync contribution pool yet)
    const sync_aggregate = types.electra.SyncAggregate.default_value;

    // 4. RANDAO reveal — needs validator signing key; use zeros for now
    // In production, the validator client provides the RANDAO signature
    const randao_reveal: types.primitive.BLSSignature.Type = [_]u8{0} ** 96;

    // 5. Graffiti
    const graffiti = config.graffiti orelse DEFAULT_GRAFFITI;

    // 6. Assemble the full Electra BeaconBlockBody
    const block_body = types.electra.BeaconBlockBody.Type{
        .randao_reveal = randao_reveal,
        .eth1_data = eth1_data,
        .graffiti = graffiti,
        .proposer_slashings = std.ArrayListUnmanaged(types.phase0.ProposerSlashing.Type).fromOwnedSlice(ops.proposer_slashings),
        .attester_slashings = std.ArrayListUnmanaged(types.electra.AttesterSlashing.Type).empty, // TODO: convert phase0 → electra format
        .attestations = std.ArrayListUnmanaged(types.electra.Attestation.Type).empty, // TODO: convert phase0 → electra format
        .deposits = std.ArrayListUnmanaged(types.phase0.Deposit.Type).empty, // Electra: deposits via EL
        .voluntary_exits = std.ArrayListUnmanaged(types.phase0.SignedVoluntaryExit.Type).fromOwnedSlice(ops.voluntary_exits),
        .sync_aggregate = sync_aggregate,
        .execution_payload = exec_payload,
        .bls_to_execution_changes = std.ArrayListUnmanaged(types.capella.SignedBLSToExecutionChange.Type).fromOwnedSlice(ops.bls_to_execution_changes),
        .blob_kzg_commitments = blob_commitments,
        .execution_requests = types.electra.ExecutionRequests.default_value,
    };

    // Free the phase0 op slices we didn't transfer (attester_slashings, attestations)
    // TODO: When we have electra-format pool methods, these become direct transfers
    allocator.free(ops.attester_slashings);
    allocator.free(ops.attestations);

    std.log.info(
        "Assembled block body: slot={d} proposer={d} txs={d} attestations={d} exits={d} slashings={d} bls_changes={d} blobs={d}",
        .{
            slot,
            proposer_index,
            exec_payload.transactions.items.len,
            block_body.attestations.items.len,
            block_body.voluntary_exits.items.len,
            block_body.proposer_slashings.items.len,
            block_body.bls_to_execution_changes.items.len,
            block_body.blob_kzg_commitments.items.len,
        },
    );

    return ProducedBlock{
        .block_body = block_body,
        .blobs_bundle = blobs_bundle,
        .block_value = block_value,
        .proposer_index = proposer_index,
        .slot = slot,
        .parent_root = parent_root,
    };
}

/// Convert an Engine API ExecutionPayloadV3 to the SSZ ExecutionPayload type.
///
/// The Engine API types use raw slices ([]const []const u8 for transactions,
/// []const Withdrawal for withdrawals). The SSZ types use ArrayListUnmanaged.
/// This function bridges the two representations.
fn convertExecutionPayload(
    allocator: Allocator,
    engine_payload: ExecutionPayloadV3,
) !types.electra.ExecutionPayload.Type {
    // Convert transactions: []const []const u8 → VariableList of ByteList
    var transactions = try std.ArrayListUnmanaged(
        types.bellatrix.Transactions.Element.Type,
    ).initCapacity(allocator, engine_payload.transactions.len);
    errdefer {
        for (transactions.items) |*tx| {
            tx.deinit(allocator);
        }
        transactions.deinit(allocator);
    }

    for (engine_payload.transactions) |tx_bytes| {
        var tx_data = std.ArrayListUnmanaged(u8){};
        try tx_data.appendSlice(allocator, tx_bytes);
        transactions.appendAssumeCapacity(tx_data);
    }

    // Convert withdrawals: []const engine Withdrawal → FixedList of SSZ Withdrawal
    var withdrawals = try std.ArrayListUnmanaged(
        types.capella.Withdrawal.Type,
    ).initCapacity(allocator, engine_payload.withdrawals.len);
    errdefer withdrawals.deinit(allocator);

    for (engine_payload.withdrawals) |w| {
        withdrawals.appendAssumeCapacity(.{
            .index = w.index,
            .validator_index = w.validator_index,
            .address = w.address,
            .amount = w.amount,
        });
    }

    // Convert extra_data: []const u8 → ArrayListUnmanaged(u8)
    var extra_data = std.ArrayListUnmanaged(u8){};
    if (engine_payload.extra_data.len > 0) {
        try extra_data.appendSlice(allocator, engine_payload.extra_data);
    }

    // Convert logs_bloom: [256]u8 → SSZ ByteVector (same underlying type)
    // LogsBloom = ByteVectorType(256) whose Type = [256]u8
    const logs_bloom: types.bellatrix.LogsBloom.Type = engine_payload.logs_bloom;

    return types.electra.ExecutionPayload.Type{
        .parent_hash = engine_payload.parent_hash,
        .fee_recipient = engine_payload.fee_recipient,
        .state_root = engine_payload.state_root,
        .receipts_root = engine_payload.receipts_root,
        .logs_bloom = logs_bloom,
        .prev_randao = engine_payload.prev_randao,
        .block_number = engine_payload.block_number,
        .gas_limit = engine_payload.gas_limit,
        .gas_used = engine_payload.gas_used,
        .timestamp = engine_payload.timestamp,
        .extra_data = extra_data,
        .base_fee_per_gas = engine_payload.base_fee_per_gas,
        .block_hash = engine_payload.block_hash,
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = engine_payload.blob_gas_used,
        .excess_blob_gas = engine_payload.excess_blob_gas,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const op_pool_mod = @import("op_pool.zig");

test "produceBlockBody: empty pool produces empty body" {
    const allocator = std.testing.allocator;
    var pool = OpPool.init(allocator);
    defer pool.deinit();

    var body = try produceBlockBody(allocator, 100, &pool);
    defer body.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), body.attestations.len);
    try std.testing.expectEqual(@as(usize, 0), body.voluntary_exits.len);
    try std.testing.expectEqual(@as(usize, 0), body.proposer_slashings.len);
    try std.testing.expectEqual(@as(usize, 0), body.attester_slashings.len);
    try std.testing.expectEqual(@as(usize, 0), body.bls_to_execution_changes.len);
}

test "produceBlockBody: populated pool produces non-empty body" {
    const allocator = std.testing.allocator;
    var pool = OpPool.init(allocator);
    defer pool.deinit();

    // Add some test operations.
    try pool.attestation_pool.add(op_pool_mod.makeTestAttestation(10, 0));
    try pool.voluntary_exit_pool.add(op_pool_mod.makeTestExit(1, 5));
    try pool.proposer_slashing_pool.add(op_pool_mod.makeTestProposerSlashing(7, 100));
    try pool.bls_change_pool.add(op_pool_mod.makeTestBlsChange(42));

    var body = try produceBlockBody(allocator, 100, &pool);
    defer body.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), body.attestations.len);
    try std.testing.expectEqual(@as(usize, 1), body.voluntary_exits.len);
    try std.testing.expectEqual(@as(usize, 1), body.proposer_slashings.len);
    try std.testing.expectEqual(@as(usize, 1), body.bls_to_execution_changes.len);
}

test "convertExecutionPayload: converts empty payload" {
    const payload = ExecutionPayloadV3{
        .parent_hash = [_]u8{0} ** 32,
        .fee_recipient = [_]u8{0} ** 20,
        .state_root = [_]u8{0} ** 32,
        .receipts_root = [_]u8{0} ** 32,
        .logs_bloom = [_]u8{0} ** 256,
        .prev_randao = [_]u8{0} ** 32,
        .block_number = 0,
        .gas_limit = 30000000,
        .gas_used = 0,
        .timestamp = 1000,
        .extra_data = &.{},
        .base_fee_per_gas = 1000000000,
        .block_hash = [_]u8{0} ** 32,
        .transactions = &.{},
        .withdrawals = &.{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };

    const allocator = std.testing.allocator;
    var result = try convertExecutionPayload(allocator, payload);
    defer {
        result.transactions.deinit(allocator);
        result.withdrawals.deinit(allocator);
        result.extra_data.deinit(allocator);
    }

    try std.testing.expectEqual(@as(u64, 30000000), result.gas_limit);
    try std.testing.expectEqual(@as(u64, 1000), result.timestamp);
    try std.testing.expectEqual(@as(usize, 0), result.transactions.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.withdrawals.items.len);
}

test "convertExecutionPayload: converts payload with transactions" {
    const tx1 = &[_]u8{ 0x01, 0x02, 0x03 };
    const tx2 = &[_]u8{ 0x04, 0x05 };
    const txs = &[_][]const u8{ tx1, tx2 };

    const w = execution_types.Withdrawal{
        .index = 0,
        .validator_index = 42,
        .address = [_]u8{0xAB} ** 20,
        .amount = 32000000000,
    };
    const withdrawals = &[_]execution_types.Withdrawal{w};

    const payload = ExecutionPayloadV3{
        .parent_hash = [_]u8{0x11} ** 32,
        .fee_recipient = [_]u8{0x22} ** 20,
        .state_root = [_]u8{0} ** 32,
        .receipts_root = [_]u8{0} ** 32,
        .logs_bloom = [_]u8{0} ** 256,
        .prev_randao = [_]u8{0x33} ** 32,
        .block_number = 100,
        .gas_limit = 30000000,
        .gas_used = 21000,
        .timestamp = 2000,
        .extra_data = &[_]u8{ 0xDE, 0xAD },
        .base_fee_per_gas = 1000000000,
        .block_hash = [_]u8{0x44} ** 32,
        .transactions = txs,
        .withdrawals = withdrawals,
        .blob_gas_used = 131072,
        .excess_blob_gas = 0,
    };

    const allocator = std.testing.allocator;
    var result = try convertExecutionPayload(allocator, payload);
    defer {
        for (result.transactions.items) |*tx| {
            tx.deinit(allocator);
        }
        result.transactions.deinit(allocator);
        result.withdrawals.deinit(allocator);
        result.extra_data.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), result.transactions.items.len);
    try std.testing.expectEqual(@as(usize, 3), result.transactions.items[0].items.len);
    try std.testing.expectEqual(@as(usize, 2), result.transactions.items[1].items.len);
    try std.testing.expectEqual(@as(usize, 1), result.withdrawals.items.len);
    try std.testing.expectEqual(@as(u64, 42), result.withdrawals.items[0].validator_index);
    try std.testing.expectEqual(@as(usize, 2), result.extra_data.items.len);
    try std.testing.expectEqual(@as(u64, 131072), result.blob_gas_used);
}

test "DEFAULT_GRAFFITI starts with lodestar-z" {
    try std.testing.expect(std.mem.startsWith(u8, &DEFAULT_GRAFFITI, "lodestar-z"));
    // Rest should be zeros
    try std.testing.expectEqual(@as(u8, 0), DEFAULT_GRAFFITI[10]);
}
