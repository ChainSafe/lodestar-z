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
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;

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
///
/// BUG-6 fix: SigningContext now holds the BeaconConfig reference so that
/// fork_version can be computed dynamically per epoch. Use forkVersionAtEpoch()
/// or forkVersionAtSlot() to get the correct fork version for a given message.
pub const SigningContext = struct {
    /// Beacon chain genesis validators root.
    genesis_validators_root: [32]u8,
    /// Genesis time (Unix seconds) — used to compute current epoch.
    genesis_time_unix_secs: u64,
    /// Seconds per slot — used to compute current epoch.
    seconds_per_slot: u64,
    /// Slots per epoch — used to compute current epoch.
    slots_per_epoch: u64,
    /// Fork schedule: up to 16 (epoch, fork_version) pairs, sorted by epoch ascending.
    /// Index 0 = phase0 (epoch 0). Populated from chain config at startup.
    fork_schedule_len: usize,
    fork_schedule: [16]ForkEntry,
    /// EIP-7044: Capella fork version for voluntary exit signing (always used post-Deneb).
    /// Set from chain config. Zero-value means not configured (pre-Capella chain).
    capella_fork_version: [4]u8 = [4]u8{ 0, 0, 0, 0 },
    /// EIP-7044: Deneb fork epoch. Post-Deneb, voluntary exits use CAPELLA_FORK_VERSION.
    /// std.math.maxInt(u64) means Deneb not scheduled (treat as pre-Deneb).
    deneb_fork_epoch: u64 = std.math.maxInt(u64),

    pub const ForkEntry = struct {
        epoch: u64,
        version: [4]u8,
    };

    /// Return the fork version active at the given epoch.
    pub fn forkVersionAtEpoch(self: *const SigningContext, epoch: u64) [4]u8 {
        // Walk schedule in reverse to find the latest fork active at `epoch`.
        var i: usize = self.fork_schedule_len;
        while (i > 0) {
            i -= 1;
            if (epoch >= self.fork_schedule[i].epoch) {
                return self.fork_schedule[i].version;
            }
        }
        // Fallback: phase0 version.
        if (self.fork_schedule_len > 0) return self.fork_schedule[0].version;
        return [4]u8{ 0, 0, 0, 0 };
    }

    /// Return the fork version active at the given slot.
    pub fn forkVersionAtSlot(self: *const SigningContext, slot: u64) [4]u8 {
        const epoch = slot / self.slots_per_epoch;
        return self.forkVersionAtEpoch(epoch);
    }
};

// ---------------------------------------------------------------------------
// RANDAO reveal: sign(epoch)
// ---------------------------------------------------------------------------

/// Compute the signing root for a RANDAO reveal.
///
/// TS: getDomainForEpoch(epoch) + computeSigningRoot(epoch, domain)
pub fn randaoSigningRoot(ctx: SigningContext, epoch: u64, out: *[32]u8) !void {
    var domain: [32]u8 = undefined;
    const fork_version = ctx.forkVersionAtEpoch(epoch);
    try computeDomain(DOMAIN_RANDAO, fork_version, ctx.genesis_validators_root, &domain);
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
    const fork_version = ctx.forkVersionAtSlot(header.slot);
    try computeDomain(DOMAIN_BEACON_PROPOSER, fork_version, ctx.genesis_validators_root, &domain);
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
    const fork_version = ctx.forkVersionAtSlot(attestation_data.slot);
    try computeDomain(DOMAIN_BEACON_ATTESTER, fork_version, ctx.genesis_validators_root, &domain);
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
    slot: u64,
    beacon_block_root: *const [32]u8,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    const fork_version = ctx.forkVersionAtSlot(slot);
    try computeDomain(DOMAIN_SYNC_COMMITTEE, fork_version, ctx.genesis_validators_root, &domain);
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
    const fork_version = ctx.forkVersionAtSlot(slot);
    try computeDomain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, fork_version, ctx.genesis_validators_root, &domain);
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
    const fork_version = ctx.forkVersionAtSlot(contribution_and_proof.contribution.slot);
    try computeDomain(DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, ctx.genesis_validators_root, &domain);
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
    // Use the slot from the aggregate attestation data for fork version lookup.
    const fork_version = ctx.forkVersionAtSlot(aggregate_and_proof.aggregate.data.slot);
    try computeDomain(DOMAIN_AGGREGATE_AND_PROOF, fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRootAlloc(consensus_types.phase0.AggregateAndProof, allocator, aggregate_and_proof, &domain, out);
}

// ---------------------------------------------------------------------------
// VoluntaryExit: sign(VoluntaryExit)
// ---------------------------------------------------------------------------

/// Compute the signing root for a voluntary exit.
///
/// `current_epoch` must be provided by the caller (e.g. derived from the beacon clock)
/// rather than read from wall-clock time, keeping this function pure and testable.
pub fn voluntaryExitSigningRoot(
    ctx: SigningContext,
    voluntary_exit: *const consensus_types.phase0.VoluntaryExit.Type,
    current_epoch: u64,
    out: *[32]u8,
) !void {
    var domain: [32]u8 = undefined;
    // EIP-7044: post-Deneb activation, voluntary exits MUST use CAPELLA_FORK_VERSION
    // regardless of the exit.epoch. This ensures exits signed before Deneb remain
    // valid after the upgrade, and that validators can exit at any time post-Deneb.
    // Mirror of BeaconConfig.getDomainForVoluntaryExit on the state-transition side.
    // Pre-Deneb chains (deneb_fork_epoch == maxInt) fall back to epoch-derived version.
    //
    // EIP-7044 fix: check if Deneb has been *reached*, not just *scheduled*.
    // The old check (deneb_fork_epoch != maxInt) would apply CAPELLA_FORK_VERSION even
    // before the fork activates, causing exits on pre-Deneb chains with Deneb scheduled
    // to use the wrong fork version.
    const deneb_reached = ctx.deneb_fork_epoch != std.math.maxInt(u64) and
        current_epoch >= ctx.deneb_fork_epoch;
    const fork_version = if (deneb_reached)
        ctx.capella_fork_version
    else
        ctx.forkVersionAtEpoch(voluntary_exit.epoch);
    try computeDomain(DOMAIN_VOLUNTARY_EXIT, fork_version, ctx.genesis_validators_root, &domain);
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
    // Use DOMAIN_SELECTION_PROOF from constants (removed inline duplicate; fix #9).
    const fork_version = ctx.forkVersionAtSlot(slot);
    try computeDomain(constants.DOMAIN_SELECTION_PROOF, fork_version, ctx.genesis_validators_root, &domain);
    try computeSigningRoot(consensus_types.primitive.Slot, &slot, &domain, out);
}
