//! Shared types for the Validator Client.
//!
//! Maps to TypeScript Lodestar's duty types in:
//!   packages/validator/src/services/attestationDuties.ts
//!   packages/validator/src/services/blockDuties.ts
//!   packages/validator/src/services/syncCommitteeDuties.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Duty types (mirror of BN handler types in src/api/handlers/validator.zig)
// ---------------------------------------------------------------------------

/// Proposer duty for a single slot in an epoch.
///
/// TS: BlockDutiesService internals; returned by GET /eth/v1/validator/duties/proposer/{epoch}
pub const ProposerDuty = struct {
    /// BLS public key (48 bytes).
    pubkey: [48]u8,
    /// Validator index.
    validator_index: u64,
    /// Slot within the epoch.
    slot: u64,
};

/// Attester duty for a single validator in an epoch.
///
/// TS: AttDutyAndProof / AttestationDutiesService
/// Returned by POST /eth/v1/validator/duties/attester/{epoch}
pub const AttesterDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    committee_index: u64,
    committee_length: u64,
    committees_at_slot: u64,
    /// Position of this validator within the committee.
    validator_committee_index: u64,
    slot: u64,
};

/// Attester duty with selection proof (for aggregation).
pub const AttesterDutyWithProof = struct {
    duty: AttesterDuty,
    /// BLS signature over the slot — proves the validator is allowed to aggregate.
    /// Null until computed.
    selection_proof: ?[96]u8,
};

/// Sync committee duty for a single validator in a sync period.
///
/// TS: SyncDutyAndProofs / SyncCommitteeDutiesService
/// Returned by POST /eth/v1/validator/duties/sync/{epoch}
pub const SyncCommitteeDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    /// Indices within the sync committee (a validator may appear multiple times).
    validator_sync_committee_indices: []const u64,
};

/// Sync committee duty with selection proofs for each subcommittee.
pub const SyncCommitteeDutyWithProofs = struct {
    duty: SyncCommitteeDuty,
    /// One selection proof per subcommittee index.
    selection_proofs: []const ?[96]u8,
};

// ---------------------------------------------------------------------------
// Validator status
// ---------------------------------------------------------------------------

/// Validator lifecycle status (mirrors Ethereum spec / BN API).
pub const ValidatorStatus = enum {
    pending_initialized,
    pending_queued,
    active_ongoing,
    active_exiting,
    active_slashed,
    exited_unslashed,
    exited_slashed,
    withdrawal_possible,
    withdrawal_done,
    unknown,
};

// ---------------------------------------------------------------------------
// Signing domains
// ---------------------------------------------------------------------------

/// BLS domain type bytes (4 bytes, big-endian).
pub const DomainType = [4]u8;

pub const DOMAIN_BEACON_PROPOSER: DomainType = .{ 0x00, 0x00, 0x00, 0x00 };
pub const DOMAIN_BEACON_ATTESTER: DomainType = .{ 0x01, 0x00, 0x00, 0x00 };
pub const DOMAIN_RANDAO: DomainType = .{ 0x02, 0x00, 0x00, 0x00 };
pub const DOMAIN_DEPOSIT: DomainType = .{ 0x03, 0x00, 0x00, 0x00 };
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = .{ 0x04, 0x00, 0x00, 0x00 };
pub const DOMAIN_SELECTION_PROOF: DomainType = .{ 0x05, 0x00, 0x00, 0x00 };
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = .{ 0x06, 0x00, 0x00, 0x00 };
pub const DOMAIN_SYNC_COMMITTEE: DomainType = .{ 0x07, 0x00, 0x00, 0x00 };
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = .{ 0x08, 0x00, 0x00, 0x00 };
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = .{ 0x09, 0x00, 0x00, 0x00 };

// ---------------------------------------------------------------------------
// Slashing protection
// ---------------------------------------------------------------------------

/// Tracks the highest slot/epoch signed for each validator.
/// Used to prevent equivocation (double-voting / double-proposing).
///
/// TS: ISlashingProtection / SlashingProtectionSqlite
pub const SlashingProtectionRecord = struct {
    pubkey: [48]u8,
    /// Highest block slot we have signed (proposal protection).
    last_signed_block_slot: ?u64,
    /// Highest source epoch in any signed attestation (vote protection).
    last_signed_attestation_source_epoch: ?u64,
    /// Highest target epoch in any signed attestation (vote protection).
    last_signed_attestation_target_epoch: ?u64,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the validator client.
pub const ValidatorConfig = struct {
    /// HTTP URL of the beacon node REST API (e.g. "http://localhost:5052").
    beacon_node_url: []const u8,
    /// Genesis time (Unix seconds) — needed to compute current slot.
    genesis_time: u64,
    /// Validators root (32 bytes) — used for domain computation.
    genesis_validators_root: [32]u8,
    /// Seconds per slot (default: 12).
    seconds_per_slot: u64 = 12,
    /// Slots per epoch (default: 32).
    slots_per_epoch: u64 = 32,
    /// Whether doppelganger protection is enabled.
    doppelganger_protection: bool = true,
    /// Path to slashing protection DB file (null = in-memory only).
    slashing_protection_path: ?[]const u8 = null,
    /// Path to keystores directory.
    keystores_dir: ?[]const u8 = null,
    /// Path to secrets directory.
    secrets_dir: ?[]const u8 = null,
    /// URL of Web3Signer remote signing service (null = disabled).
    /// When set, public keys are fetched from the signer at startup.
    web3signer_url: ?[]const u8 = null,
    /// Additional beacon node URLs for fallback (beyond beacon_node_url).
    ///
    /// When set, api_client will try these URLs if the primary fails.
    /// TS: --beaconNodes flag (array of BN URLs).
    beacon_node_fallback_urls: []const []const u8 = &.{},
};
