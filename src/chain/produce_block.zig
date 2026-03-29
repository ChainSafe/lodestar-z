//! Block body production.
//!
//! Assembles a `BeaconBlockBody` by selecting the best pending operations
//! from the `OpPool` and combining them with an execution payload, sync
//! aggregate, and other block body fields.
//!
//! The `produceBlockBody` function returns a lightweight `ProducedBlockBody`
//! of op slices for use by code that only needs the operations. For full
//! block assembly, use `assembleBlock` which builds a complete Electra
//! `BeaconBlockBody`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Epoch = types.primitive.Epoch.Type;

const OpPool = @import("op_pool.zig").OpPool;
const SyncContributionAndProofPool = @import("sync_contribution_pool.zig").SyncContributionAndProofPool;

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

/// Result of block body production (lightweight — just op pool slices).
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
        if (self.attestations.len > 0) allocator.free(self.attestations);
        if (self.voluntary_exits.len > 0) allocator.free(self.voluntary_exits);
        if (self.proposer_slashings.len > 0) allocator.free(self.proposer_slashings);
        if (self.attester_slashings.len > 0) allocator.free(self.attester_slashings);
        if (self.bls_to_execution_changes.len > 0) allocator.free(self.bls_to_execution_changes);
    }
};

/// Blobs bundle — engine-layer-agnostic representation.
///
/// Mirrors the engine API BlobsBundle but uses the same types so the chain
/// module doesn't need to import execution types.
pub const BlobsBundle = struct {
    commitments: []const [48]u8,
    proofs: []const [48]u8,
    blobs: []const [131072]u8,
};

/// Full block production result including execution payload and blobs.
pub const ProducedBlock = struct {
    /// Fully assembled BeaconBlockBody (Electra fork — current target).
    block_body: types.electra.BeaconBlockBody.Type,

    /// Blobs bundle (commitments, proofs, blobs). Null if no blobs.
    blobs_bundle: ?BlobsBundle,

    /// Execution payload value in wei (MEV block value).
    block_value: u256,

    /// The proposer index that produced this block.
    proposer_index: ValidatorIndex,

    /// The slot this block is for.
    slot: Slot,

    /// Parent block root.
    parent_root: [32]u8,

    /// Free owned resources.
    pub fn deinit(self: *ProducedBlock, allocator: Allocator) void {
        var body = &self.block_body;
        // Electra attestations own their aggregation_bits data
        for (body.attestations.items) |*att| {
            att.aggregation_bits.data.deinit(allocator);
        }
        body.attestations.deinit(allocator);
        body.voluntary_exits.deinit(allocator);
        body.proposer_slashings.deinit(allocator);
        // Electra attester slashings own their IndexedAttestation indices
        for (body.attester_slashings.items) |*sl| {
            sl.attestation_1.attesting_indices.deinit(allocator);
            sl.attestation_2.attesting_indices.deinit(allocator);
        }
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
/// Returns a lightweight `ProducedBlockBody` of op slices.
/// The caller must call `deinit` on the result when done.
pub fn produceBlockBody(
    allocator: Allocator,
    slot: Slot,
    op_pool: *OpPool,
) !ProducedBlockBody {
    // Use the aggregated pool for greedy maximum-coverage attestation selection.
    // Falls back to the legacy pool if the aggregated pool is empty.
    const attestations = if (op_pool.agg_attestation_pool.entryCount() > 0)
        try op_pool.agg_attestation_pool.getAttestationsForBlock(allocator, slot, MAX_ATTESTATIONS)
    else
        try op_pool.attestation_pool.getForBlock(allocator, MAX_ATTESTATIONS);
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


// ---------------------------------------------------------------------------
// Format conversion helpers: Phase0 → Electra
//
// The op pool stores attestations and attester slashings in Phase0 format
// (the format they arrive in from gossip). Electra blocks require a different
// layout:
//   - Attestation: aggregation_bits is over ALL committees (not one),
//     committee_bits indicates which committee(s) are represented.
//   - AttesterSlashing: uses Electra IndexedAttestation (larger max indices).
//   - IndexedAttestation: max attesting_indices = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT
//
// These helpers convert Phase0 items to Electra format for block inclusion.
// ---------------------------------------------------------------------------

/// Convert a Phase0 attestation to Electra format.
///
/// In Electra, attestations have:
///   - aggregation_bits: BitList[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]
///   - committee_bits: BitVector[MAX_COMMITTEES_PER_SLOT] — indicates which committee
///   - data.index is always 0 (committee identified by committee_bits)
///
/// For a Phase0 attestation targeting committee `index`:
///   1. Set the corresponding bit in committee_bits
///   2. Place aggregation_bits at the correct offset within the larger bitfield
///      (for single-committee conversion, just copy them directly — the bits
///       represent validators within that single committee)
pub fn phase0ToElectraAttestation(
    allocator: Allocator,
    phase0_att: types.phase0.Attestation.Type,
) !types.electra.Attestation.Type {
    const committee_index = phase0_att.data.index;

    // Committee bits type: BitVector[MAX_COMMITTEES_PER_SLOT]
    const CommitteeBits = @import("ssz").BitVectorType(preset.MAX_COMMITTEES_PER_SLOT);
    // Aggregation bits type: BitList[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]
    const AggBits = @import("ssz").BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT);

    // Build committee_bits: set bit for the committee this attestation is from
    var committee_bits = CommitteeBits.default_value;
    committee_bits.set(@intCast(committee_index), true) catch {};

    // Copy aggregation_bits — in the single-committee case, the bits directly
    // represent validators in that committee. For a full implementation with
    // aggregation across committees, we'd need to offset by committee position.
    var agg_bits: AggBits.Type = AggBits.default_value;
    if (phase0_att.aggregation_bits.data.items.len > 0) {
        var new_data = try std.ArrayListUnmanaged(u8).initCapacity(
            allocator,
            phase0_att.aggregation_bits.data.items.len,
        );
        new_data.appendSliceAssumeCapacity(phase0_att.aggregation_bits.data.items);
        agg_bits.data = new_data;
        agg_bits.bit_len = phase0_att.aggregation_bits.bit_len;
    }

    // Electra attestation data has index=0 (committee is in committee_bits)
    var electra_data = phase0_att.data;
    electra_data.index = 0;

    return types.electra.Attestation.Type{
        .aggregation_bits = agg_bits,
        .data = electra_data,
        .signature = phase0_att.signature,
        .committee_bits = committee_bits,
    };
}

/// Convert a Phase0 attester slashing to Electra format.
///
/// The only difference is the IndexedAttestation type: Electra allows
/// MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT attesting indices
/// (vs just MAX_VALIDATORS_PER_COMMITTEE in Phase0).
///
/// The actual attesting_indices data is identical — we just need to wrap
/// it in the larger-capacity Electra IndexedAttestation type.
pub fn phase0ToElectraAttesterSlashing(
    allocator: Allocator,
    phase0_slashing: types.phase0.AttesterSlashing.Type,
) !types.electra.AttesterSlashing.Type {
    return types.electra.AttesterSlashing.Type{
        .attestation_1 = try phase0ToElectraIndexedAttestation(allocator, phase0_slashing.attestation_1),
        .attestation_2 = try phase0ToElectraIndexedAttestation(allocator, phase0_slashing.attestation_2),
    };
}

/// Convert a Phase0 IndexedAttestation to Electra format.
///
/// Copies the attesting_indices into the larger-capacity Electra list.
fn phase0ToElectraIndexedAttestation(
    allocator: Allocator,
    phase0_ia: types.phase0.IndexedAttestation.Type,
) !types.electra.IndexedAttestation.Type {
    // Copy attesting_indices to the electra-sized list
    var indices = try std.ArrayListUnmanaged(types.primitive.ValidatorIndex.Type).initCapacity(
        allocator,
        phase0_ia.attesting_indices.items.len,
    );
    indices.appendSliceAssumeCapacity(phase0_ia.attesting_indices.items);

    return types.electra.IndexedAttestation.Type{
        .attesting_indices = indices,
        .data = phase0_ia.data,
        .signature = phase0_ia.signature,
    };
}

/// Assemble a full Electra BeaconBlockBody from op pool operations and
/// a pre-converted execution payload.
///
/// The execution payload must already be in SSZ format — conversion from
/// engine API types is the caller's responsibility (see beacon_node.zig).
///
/// This function:
/// 1. Pulls operations from the op pool
/// 2. Builds a SyncAggregate from the contribution pool (empty if null)
/// 3. Uses the provided execution payload, eth1_data, graffiti
/// 4. Sets blob KZG commitments and execution requests
/// 5. RANDAO reveal is zeroed (needs validator signing key)
///
/// Returns a ProducedBlock with the full block body and metadata.
pub fn assembleBlock(
    allocator: Allocator,
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: [32]u8,
    op_pool: *OpPool,
    exec_payload: types.electra.ExecutionPayload.Type,
    blobs_bundle: ?BlobsBundle,
    block_value: u256,
    blob_commitments: std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type),
    eth1_data: types.phase0.Eth1Data.Type,
    config: BlockProductionConfig,
    sync_contribution_pool: ?*SyncContributionAndProofPool,
) !ProducedBlock {
    // 1. Pull operations from op pool
    const ops = try produceBlockBody(allocator, slot, op_pool);

    // 2. Build sync aggregate from the contribution pool.
    //
    // The sync aggregate covers the *previous* slot — sync committee members
    // sign the block root of the previous slot. So we query for `slot - 1`
    // and use `parent_root` as the block root they signed over.
    //
    // Falls back to empty (all zeros) if no contributions are available,
    // which is valid but suboptimal (reduces sync committee rewards).
    const sync_aggregate = if (sync_contribution_pool) |pool|
        pool.getSyncAggregate(if (slot > 0) slot - 1 else 0, parent_root)
    else
        types.electra.SyncAggregate.default_value;

    // 3. RANDAO reveal — zeroed (needs validator signing key)
    const randao_reveal: types.primitive.BLSSignature.Type = [_]u8{0} ** 96;

    // 4. Graffiti
    const graffiti = config.graffiti orelse DEFAULT_GRAFFITI;

    // 5. Convert phase0 attestations and attester slashings to electra format
    var electra_attestations = std.ArrayListUnmanaged(types.electra.Attestation.Type).empty;
    errdefer {
        for (electra_attestations.items) |*att| {
            att.aggregation_bits.data.deinit(allocator);
        }
        electra_attestations.deinit(allocator);
    }
    for (ops.attestations) |att| {
        const electra_att = try phase0ToElectraAttestation(allocator, att);
        try electra_attestations.append(allocator, electra_att);
    }

    var electra_slashings = std.ArrayListUnmanaged(types.electra.AttesterSlashing.Type).empty;
    errdefer {
        for (electra_slashings.items) |*sl| {
            sl.attestation_1.attesting_indices.deinit(allocator);
            sl.attestation_2.attesting_indices.deinit(allocator);
        }
        electra_slashings.deinit(allocator);
    }
    for (ops.attester_slashings) |sl| {
        const electra_sl = try phase0ToElectraAttesterSlashing(allocator, sl);
        try electra_slashings.append(allocator, electra_sl);
    }

    // 6. Assemble the full Electra BeaconBlockBody
    const block_body = types.electra.BeaconBlockBody.Type{
        .randao_reveal = randao_reveal,
        .eth1_data = eth1_data,
        .graffiti = graffiti,
        .proposer_slashings = std.ArrayListUnmanaged(types.phase0.ProposerSlashing.Type).fromOwnedSlice(ops.proposer_slashings),
        .attester_slashings = electra_slashings,
        .attestations = electra_attestations,
        .deposits = std.ArrayListUnmanaged(types.phase0.Deposit.Type).empty, // Electra: deposits via EL
        .voluntary_exits = std.ArrayListUnmanaged(types.phase0.SignedVoluntaryExit.Type).fromOwnedSlice(ops.voluntary_exits),
        .sync_aggregate = sync_aggregate,
        .execution_payload = exec_payload,
        .bls_to_execution_changes = std.ArrayListUnmanaged(types.capella.SignedBLSToExecutionChange.Type).fromOwnedSlice(ops.bls_to_execution_changes),
        .blob_kzg_commitments = blob_commitments,
        .execution_requests = types.electra.ExecutionRequests.default_value,
    };

    // Free the original phase0 slices (we copied/converted them above)
    allocator.free(ops.attester_slashings);
    allocator.free(ops.attestations);

    std.log.info(
        "Assembled block body: slot={d} proposer={d} txs={d} atts={d} exits={d} slashings={d} bls_changes={d} blobs={d}",
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

test "assembleBlock: empty pool produces valid block structure" {
    const allocator = std.testing.allocator;
    var pool = OpPool.init(allocator);
    defer pool.deinit();

    var block = try assembleBlock(
        allocator,
        100, // slot
        42, // proposer
        [_]u8{0xAB} ** 32, // parent root
        &pool,
        types.electra.ExecutionPayload.default_value, // empty payload
        null, // no blobs
        0, // no block value
        std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).empty, // no commitments
        types.phase0.Eth1Data.default_value,
        .{},
        null, // no sync contribution pool
    );
    defer block.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 100), block.slot);
    try std.testing.expectEqual(@as(u64, 42), block.proposer_index);
    try std.testing.expectEqual(@as(usize, 0), block.block_body.voluntary_exits.items.len);
    try std.testing.expectEqual(@as(usize, 0), block.block_body.proposer_slashings.items.len);
    try std.testing.expect(std.mem.startsWith(u8, &block.block_body.graffiti, "lodestar-z"));
}

test "assembleBlock: custom graffiti" {
    const allocator = std.testing.allocator;
    var pool = OpPool.init(allocator);
    defer pool.deinit();

    var custom_graffiti: [32]u8 = [_]u8{0} ** 32;
    @memcpy(custom_graffiti[0..6], "custom");

    var block = try assembleBlock(
        allocator,
        200,
        7,
        [_]u8{0} ** 32,
        &pool,
        types.electra.ExecutionPayload.default_value,
        null,
        0,
        std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).empty,
        types.phase0.Eth1Data.default_value,
        .{ .graffiti = custom_graffiti },
        null, // no sync contribution pool
    );
    defer block.deinit(allocator);

    try std.testing.expect(std.mem.startsWith(u8, &block.block_body.graffiti, "custom"));
}

test "assembleBlock: with ops from pool" {
    const allocator = std.testing.allocator;
    var pool = OpPool.init(allocator);
    defer pool.deinit();

    // Add ops
    try pool.voluntary_exit_pool.add(op_pool_mod.makeTestExit(1, 5));
    try pool.proposer_slashing_pool.add(op_pool_mod.makeTestProposerSlashing(7, 100));
    try pool.bls_change_pool.add(op_pool_mod.makeTestBlsChange(42));

    var block = try assembleBlock(
        allocator,
        300,
        1,
        [_]u8{0xFF} ** 32,
        &pool,
        types.electra.ExecutionPayload.default_value,
        null,
        0,
        std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).empty,
        types.phase0.Eth1Data.default_value,
        .{},
        null, // no sync contribution pool
    );
    defer block.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), block.block_body.voluntary_exits.items.len);
    try std.testing.expectEqual(@as(usize, 1), block.block_body.proposer_slashings.items.len);
    try std.testing.expectEqual(@as(usize, 1), block.block_body.bls_to_execution_changes.items.len);
}

test "DEFAULT_GRAFFITI starts with lodestar-z" {
    try std.testing.expect(std.mem.startsWith(u8, &DEFAULT_GRAFFITI, "lodestar-z"));
    // Rest should be zeros
    try std.testing.expectEqual(@as(u8, 0), DEFAULT_GRAFFITI[10]);
}
