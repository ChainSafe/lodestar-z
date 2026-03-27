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
pub const signing = @import("signing.zig");
pub const SigningContext = signing.SigningContext;
pub const chain_header_tracker = @import("chain_header_tracker.zig");
pub const prepare_beacon_proposer = @import("prepare_beacon_proposer.zig");
pub const ChainHeaderTracker = chain_header_tracker.ChainHeaderTracker;
pub const PrepareBeaconProposerService = prepare_beacon_proposer.PrepareBeaconProposerService;
pub const HeadInfo = chain_header_tracker.HeadInfo;
pub const HeadCallback = chain_header_tracker.HeadCallback;
pub const keystore = @import("keystore.zig");
pub const slashing_protection_db = @import("slashing_protection_db.zig");
pub const remote_signer = @import("remote_signer.zig");
pub const SlashingProtectionDb = slashing_protection_db.SlashingProtectionDb;
pub const RemoteSigner = remote_signer.RemoteSigner;
pub const interchange = @import("interchange.zig");
pub const Keystore = keystore.Keystore;
pub const KeystoreDecryptor = keystore.KeystoreDecryptor;
pub const loadKeystore = keystore.loadKeystore;
pub const InterchangeFormat = interchange.InterchangeFormat;
pub const SignedBlock = interchange.SignedBlock;
pub const SignedAttestation = interchange.SignedAttestation;
pub const importInterchange = interchange.importInterchange;
pub const exportInterchange = interchange.exportInterchange;

pub const key_discovery = @import("key_discovery.zig");
pub const KeyDiscovery = key_discovery.KeyDiscovery;
pub const DiscoveredKey = key_discovery.DiscoveredKey;
pub const LoadedKey = key_discovery.LoadedKey;
