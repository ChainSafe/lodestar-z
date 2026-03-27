//! Signing root helpers for the Validator Client.
//!
//! Wraps compute_domain + compute_signing_root for each duty type.
//! Each helper produces the 32-byte signing root that goes into
//! ValidatorStore.signXxx(pubkey, signing_root, ...).
//!
//! Design:
//!   - Uses `state_transition.computeDomain` + `computeSigningRoot`.
//!   - Caller supplies fork_version and genesis_validators_root.
//!   - No allocator needed (all fixed-size types).

const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const constants = @import("constants");
const state_transition = @import("state_transition");

const computeDomain = state_transition.computeDomain;
const computeSigningRoot = state_transition.computeSigningRoot;
const computeSigningRootAlloc = state_transition.computeSigningRootAlloc;

// Domain types from constants.
const DOMAIN_BEACON_PROPOSER = constants.DOMAIN_BEACON_PROPOSER;
const DOMAIN_BEACON_ATTESTER = constants.DOMAIN_BEACON_ATTESTER;
const DOMAIN_RANDAO = constants.DOMAIN_RANDAO;
const DOMAIN_VOLUNTARY_EXIT = constants.DOMAIN_VOLUNTARY_EXIT;
const DOMAIN_AGGREGATE_AND_PROOF = constants.DOMAIN_AGGREGATE_AND_PROOF;
const DOMAIN_SYNC_COMMITTEE = constants.DOMAIN_SYNC_COMMITTEE;
const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF = constants.DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF;
const DOMAIN_CONTRIBUTION_AND_PROOF = constants.DOMAIN_CONTRIBUTION_AND_PROOF;

/// Signing context shared across all sign calls for a given state.
pub const SigningContext = struct {
    /// Active fork version for the message's epoch.
    fork_version: [4]u8,
    /// Beacon chain genesis validators root.
    genesis_validators_root: [32]u8,
};

// ---------------------------------------------------------------------------
// RANDAO reveal: sign(epoch)
// ---------------------------------------------------------------------------

/// Compute the signing root for a RANDAO reveal.
///
/// TS: getDomainForEpoch(epoch) + computeSigningRoot(epoch, domain)
pub fn randaoSigningRoot(ctx: SigningContext, epoch: u64, out: *[32]u8) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_RANDAO, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.primitive.Epoch, &epoch, &domain, out);
}

// ---------------------------------------------------------------------------
// Block: sign(BeaconBlockHeader)
// ---------------------------------------------------------------------------

/// Compute the signing root for a beacon block header.
///
/// TS: getDomainForSlot(slot) + computeSigningRoot(beaconBlockHeader, domain)
pub fn blockHeaderSigningRoot(
    ctx: SigningContext,
    header: *const consensus_types.phase0.BeaconBlockHeader.Type,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_BEACON_PROPOSER, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.phase0.BeaconBlockHeader, header, &domain, out);
}

// ---------------------------------------------------------------------------
// Attestation: sign(AttestationData)
// ---------------------------------------------------------------------------

/// Compute the signing root for attestation data.
///
/// TS: getDomainForSlot(slot) + computeSigningRoot(attestationData, domain)
pub fn attestationSigningRoot(
    ctx: SigningContext,
    attestation_data: *const consensus_types.phase0.AttestationData.Type,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_BEACON_ATTESTER, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.phase0.AttestationData, attestation_data, &domain, out);
}

// ---------------------------------------------------------------------------
// Sync committee message: sign(beacon_block_root at slot)
// ---------------------------------------------------------------------------

/// Compute the signing root for a sync committee message.
///
/// The message is the beacon block root (a `Root`, i.e., [32]u8).
/// TS: computeSigningRoot(beaconBlockRoot, domain)
pub fn syncCommitteeSigningRoot(
    ctx: SigningContext,
    beacon_block_root: *const [32]u8,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_SYNC_COMMITTEE, ctx.fork_version, ctx.genesis_validators_root, &domain);
    // SyncCommitteeMessage signs over the beacon block root as a Root type.
    try computeSigningRoot(consensus_types.primitive.Root, beacon_block_root, &domain, out);
}

// ---------------------------------------------------------------------------
// Sync committee selection proof: sign(SyncAggregatorSelectionData)
// ---------------------------------------------------------------------------

/// Compute the selection proof signing root for sync committee aggregation.
///
/// TS: computeSigningRoot(SyncAggregatorSelectionData{slot, subcommitteeIndex}, domain)
pub fn syncCommitteeSelectionProofSigningRoot(
    ctx: SigningContext,
    slot: u64,
    subcommittee_index: u64,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, ctx.fork_version, ctx.genesis_validators_root, &domain);
    const selection_data = consensus_types.altair.SyncAggregatorSelectionData.Type{
        .slot = slot,
        .subcommittee_index = subcommittee_index,
    };
    try computeSigningRoot(consensus_types.altair.SyncAggregatorSelectionData, &selection_data, &domain, out);
}

// ---------------------------------------------------------------------------
// ContributionAndProof: sign(ContributionAndProof)
// ---------------------------------------------------------------------------

/// Compute the signing root for a sync committee contribution and proof.
pub fn contributionAndProofSigningRoot(
    ctx: SigningContext,
    contribution_and_proof: *const consensus_types.altair.ContributionAndProof.Type,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_CONTRIBUTION_AND_PROOF, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.altair.ContributionAndProof, contribution_and_proof, &domain, out);
}

// ---------------------------------------------------------------------------
// AggregateAndProof (phase0): sign(AggregateAndProof)
// ---------------------------------------------------------------------------

/// Compute the signing root for a phase0/altair AggregateAndProof.
pub fn aggregateAndProofSigningRoot(
    allocator: Allocator,
    ctx: SigningContext,
    aggregate_and_proof: *const consensus_types.phase0.AggregateAndProof.Type,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_AGGREGATE_AND_PROOF, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRootAlloc(consensus_types.phase0.AggregateAndProof, allocator, aggregate_and_proof, &domain, out);
}

// ---------------------------------------------------------------------------
// VoluntaryExit: sign(VoluntaryExit)
// ---------------------------------------------------------------------------

/// Compute the signing root for a voluntary exit.
pub fn voluntaryExitSigningRoot(
    ctx: SigningContext,
    voluntary_exit: *const consensus_types.phase0.VoluntaryExit.Type,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    try computeDomain(DOMAIN_VOLUNTARY_EXIT, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.phase0.VoluntaryExit, voluntary_exit, &domain, out);
}

// ---------------------------------------------------------------------------
// Attestation selection proof: sign(slot)
// ---------------------------------------------------------------------------

/// Compute the signing root for an attestation aggregator selection proof.
///
/// The selection proof is a signature over the slot number.
/// TS: computeSigningRoot(slot, domain)
pub fn attestationSelectionProofSigningRoot(
    ctx: SigningContext,
    slot: u64,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    // DOMAIN_SELECTION_PROOF = 0x05
    const DOMAIN_SELECTION_PROOF = [4]u8{ 0x05, 0x00, 0x00, 0x00 };
    try computeDomain(DOMAIN_SELECTION_PROOF, ctx.fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.primitive.Slot, &slot, &domain, out);
}
