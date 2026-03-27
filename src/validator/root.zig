//! Validator Client module root.
//!
//! Re-exports the public API for the lodestar-z validator client.
//!
//! Usage:
//!   const validator = @import("validator");
//!   const ValidatorClient = validator.ValidatorClient;
//!   const ValidatorConfig  = validator.ValidatorConfig;

pub const types = @import("types.zig");
pub const clock = @import("clock.zig");
pub const api_client = @import("api_client.zig");
pub const validator_store = @import("validator_store.zig");
pub const block_service = @import("block_service.zig");
pub const attestation_service = @import("attestation_service.zig");
pub const sync_committee_service = @import("sync_committee_service.zig");
pub const doppelganger = @import("doppelganger.zig");
pub const validator = @import("validator.zig");

// Convenience re-exports.
pub const ValidatorClient = validator.ValidatorClient;
pub const ValidatorConfig = types.ValidatorConfig;
pub const SlotClock = clock.SlotClock;
pub const BeaconApiClient = api_client.BeaconApiClient;
pub const ValidatorStore = validator_store.ValidatorStore;
pub const BlockService = block_service.BlockService;
pub const AttestationService = attestation_service.AttestationService;
pub const SyncCommitteeService = sync_committee_service.SyncCommitteeService;
pub const DoppelgangerService = doppelganger.DoppelgangerService;
pub const ProposerDuty = types.ProposerDuty;
pub const AttesterDuty = types.AttesterDuty;
pub const SyncCommitteeDuty = types.SyncCommitteeDuty;
pub const ValidatorStatus = types.ValidatorStatus;
pub const SlashingProtectionRecord = types.SlashingProtectionRecord;
