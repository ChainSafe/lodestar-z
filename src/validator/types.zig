//! Shared types for the Validator Client.
//!
//! Maps to TypeScript Lodestar's duty types in:
//!   packages/validator/src/services/attestationDuties.ts
//!   packages/validator/src/services/blockDuties.ts
//!   packages/validator/src/services/syncCommitteeDuties.ts

const std = @import("std");
const Allocator = std.mem.Allocator;
const api = @import("api");

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
    /// BLS signature over the slot for validators that are actually selected as
    /// aggregators for this committee and slot. Null for non-aggregators.
    selection_proof: ?[96]u8,
};

/// Sync committee duty for a single validator in a sync period.
///
/// TS: SyncDutyAndProofs / SyncCommitteeDutiesService
/// Returned by POST /eth/v1/validator/duties/sync/{epoch}
pub const SyncCommitteeDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    /// One representative committee index per subscribed subnet.
    ///
    /// A validator can appear multiple times in the sync committee, but the VC
    /// only needs one entry per subnet for subnet subscriptions and contribution
    /// production.
    validator_sync_committee_indices: []const u64,
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

pub fn parseValidatorStatus(text: []const u8) ValidatorStatus {
    inline for (std.meta.fields(ValidatorStatus)) |field| {
        if (std.mem.eql(u8, text, field.name)) {
            return @field(ValidatorStatus, field.name);
        }
    }
    return .unknown;
}

// ---------------------------------------------------------------------------
// Signing domains (removed — use constants module directly)
// ---------------------------------------------------------------------------
// Domain type constants were duplicated here and in signing.zig. They have been
// removed. All callers should import from the `constants` module:
//   const constants = @import("constants");
//   const DOMAIN_BEACON_PROPOSER = constants.DOMAIN_BEACON_PROPOSER;

// ---------------------------------------------------------------------------
// Slashing protection
// ---------------------------------------------------------------------------

/// Signing root value used when a record was imported/exported without an
/// explicit signing root. EIP-3076 treats signing roots as optional.
pub const UNKNOWN_SIGNING_ROOT = std.mem.zeroes([32]u8);

/// One slash-protection block record.
///
/// `signing_root == UNKNOWN_SIGNING_ROOT` means the source data omitted the
/// optional signing root, so exact same-data repeat signing cannot be proven.
pub const SlashingProtectionBlockRecord = struct {
    slot: u64,
    signing_root: [32]u8 = UNKNOWN_SIGNING_ROOT,
};

/// One slash-protection attestation record.
///
/// `signing_root == UNKNOWN_SIGNING_ROOT` means the source data omitted the
/// optional signing root, so exact same-data repeat signing cannot be proven.
pub const SlashingProtectionAttestationRecord = struct {
    source_epoch: u64,
    target_epoch: u64,
    signing_root: [32]u8 = UNKNOWN_SIGNING_ROOT,
};

/// Full slash-protection history for one validator.
///
/// This is the in-memory / interchange shape that matches Lodestar and EIP-3076
/// much more closely than the older "latest slot/latest epoch" summary.
pub const SlashingProtectionHistory = struct {
    pubkey: [48]u8,
    signed_blocks: []const SlashingProtectionBlockRecord,
    signed_attestations: []const SlashingProtectionAttestationRecord,
};

pub const ProposerConfig = struct {
    fee_recipient: ?[20]u8 = null,
    graffiti: ?[32]u8 = null,
    gas_limit: ?u64 = null,
    builder_selection: ?BuilderSelection = null,
    builder_boost_factor: ?u64 = null,
    strict_fee_recipient_check: ?bool = null,
};

pub const ProposerConfigEntry = struct {
    pubkey: [48]u8,
    config: ProposerConfig,
};

pub const EffectiveProposerConfig = struct {
    fee_recipient: [20]u8,
    graffiti: [32]u8,
    gas_limit: u64,
    builder_selection: BuilderSelection = .executiononly,
    builder_boost_factor: ?u64,
    strict_fee_recipient_check: bool,
};

pub const BroadcastValidation = api.types.BroadcastValidation;
pub const BuilderSelection = api.types.BuilderSelection;
pub const ExecutionPayloadSource = api.types.ExecutionPayloadSource;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the validator client.
pub const ValidatorConfig = struct {
    /// Concrete validator persistence directories prepared by the launcher.
    ///
    /// The validator runtime uses these resolved paths for runtime keymanager
    /// mutations. Path policy and defaults stay in the CLI/bootstrap layer.
    persistence: ?PersistencePaths = null,
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
    /// Epochs per sync committee period (default: 256 mainnet, 8 minimal).
    epochs_per_sync_committee_period: u64 = 256,
    /// Sync committee size (default: 512 mainnet, 32 minimal).
    sync_committee_size: u64 = 512,
    /// Sync committee subnet count (default: 4).
    sync_committee_subnet_count: u64 = 4,
    /// Electra fork epoch (EIP-7549). Attestation format changes at this epoch.
    /// Default: maxInt(u64) = Electra not scheduled.
    electra_fork_epoch: u64 = std.math.maxInt(u64),
    /// Gloas fork epoch. Attestation and sync due times change at/after this fork.
    gloas_fork_epoch: u64 = std.math.maxInt(u64),
    /// Attestation production deadline in milliseconds from slot start pre-Gloas.
    attestation_due_ms: u64 = 4_000,
    /// Attestation production deadline in milliseconds from slot start at/after Gloas.
    attestation_due_ms_gloas: u64 = 3_000,
    /// Aggregate production deadline in milliseconds from slot start pre-Gloas.
    aggregate_due_ms: u64 = 8_000,
    /// Aggregate production deadline in milliseconds from slot start at/after Gloas.
    aggregate_due_ms_gloas: u64 = 6_000,
    /// Sync message deadline in milliseconds from slot start pre-Gloas.
    sync_message_due_ms: u64 = 4_000,
    /// Sync message deadline in milliseconds from slot start at/after Gloas.
    sync_message_due_ms_gloas: u64 = 3_000,
    /// Sync contribution deadline in milliseconds from slot start pre-Gloas.
    sync_contribution_due_ms: u64 = 8_000,
    /// Sync contribution deadline in milliseconds from slot start at/after Gloas.
    sync_contribution_due_ms_gloas: u64 = 6_000,
    /// Whether doppelganger protection is enabled.
    doppelganger_protection: bool = true,
    /// Path to slashing protection DB file (null = in-memory only).
    slashing_protection_path: ?[]const u8 = null,
    /// URLs of configured Web3Signer remote signing services.
    ///
    /// These are the static endpoints the validator can sign against, regardless
    /// of whether the remote validator set was loaded from disk, pinned by CLI,
    /// or fetched dynamically.
    external_signer_urls: []const []const u8 = &.{},
    /// Whether the remote signer set should be refreshed dynamically.
    ///
    /// This is enabled only for `--externalSigner.fetch`. Persisted `remoteKeys/`
    /// definitions and explicit `--externalSigner.pubkeys` are static startup
    /// configuration and do not enable background refresh.
    external_signer_fetch_enabled: bool = false,
    /// Refresh interval for dynamic external signer key discovery in milliseconds.
    ///
    /// Null uses the Lodestar default: once per epoch. Ignored unless
    /// `external_signer_fetch_enabled` is true.
    external_signer_fetch_interval_ms: ?u64 = null,
    /// Additional beacon node URLs for fallback (beyond beacon_node_url).
    ///
    /// When set, api_client will try these URLs if the primary fails.
    /// TS: --beaconNodes flag (array of BN URLs).
    beacon_node_fallback_urls: []const []const u8 = &.{},
    /// Path to an EIP-3076 slashing protection interchange file to import at startup.
    ///
    /// When set, `ValidatorClient.init()` imports the interchange records into the
    /// slashing protection DB before starting. This ensures validators cannot sign
    /// anything that would conflict with their history on a previous client.
    ///
    /// TS: --importKeystores / --slashingProtection flag that feeds into
    ///     SlashingProtectionInterchange.importInterchange().
    interchange_import_path: ?[]const u8 = null,
    /// Builder relay URL for MEV-boost (null = disabled).
    /// When set, the VC will register validators and use blinded blocks.
    /// Example: "http://localhost:18550"
    builder_url: ?[]const u8 = null,
    /// Per-validator proposer config overrides loaded from persisted
    /// keymanager state at startup.
    proposer_configs: []const ProposerConfigEntry = &.{},
    /// Suggested fee recipient address (20 bytes, hex).
    /// Used when building SignedValidatorRegistration messages.
    /// Defaults to zero address — operator must override.
    suggested_fee_recipient: [20]u8 = [_]u8{0} ** 20,
    /// Default gas limit for builder registrations (default: 60_000_000).
    gas_limit: u64 = 60_000_000,
    /// Graffiti bytes (32 bytes) included in proposed blocks.
    /// Defaults to all-zeros. Operators can set a custom string (UTF-8, right-padded).
    graffiti: [32]u8 = std.mem.zeroes([32]u8),
    /// Builder boost factor: percentage advantage given to builder bids.
    /// 100 = neutral. Values above 100 boost builder bids, values below 100 dampen them.
    /// Per-spec default is 100. Set null to disable builder path.
    builder_boost_factor: ?u64 = 100,
    /// Default builder selection policy for block production.
    builder_selection: BuilderSelection = .executiononly,
    /// Whether the validator must enforce that the block returned by the beacon
    /// node uses the configured fee recipient.
    strict_fee_recipient_check: bool = false,
    /// Request local beacon-node block production in blinded form when possible.
    blinded_local: bool = false,
    /// Validation policy requested when publishing signed blocks back to the BN.
    broadcast_validation: BroadcastValidation = .gossip,
};

pub const PersistencePaths = struct {
    keystores_dir: []const u8,
    secrets_dir: []const u8,
    remote_keys_dir: []const u8,
    proposer_dir: []const u8,
};
