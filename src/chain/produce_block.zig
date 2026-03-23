//! Block body production.
//!
//! Assembles a `BeaconBlockBody` by selecting the best pending operations
//! from the `OpPool`.  Execution payload and RANDAO reveal are stubbed for
//! now — they require the engine API and validator signing key respectively.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;

const OpPool = @import("op_pool.zig").OpPool;

// Per-block operation limits (Phase0 / pre-Electra).
pub const MAX_ATTESTATIONS: u32 = preset.MAX_ATTESTATIONS;
pub const MAX_VOLUNTARY_EXITS: u32 = preset.MAX_VOLUNTARY_EXITS;
pub const MAX_PROPOSER_SLASHINGS: u32 = preset.MAX_PROPOSER_SLASHINGS;
pub const MAX_ATTESTER_SLASHINGS: u32 = preset.MAX_ATTESTER_SLASHINGS;
pub const MAX_BLS_TO_EXECUTION_CHANGES: u32 = preset.MAX_BLS_TO_EXECUTION_CHANGES;

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
