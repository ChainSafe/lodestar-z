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
const config_mod = @import("config");
/// Shared SlotClock (from config) — for simple time queries.
pub const SlotClock = config_mod.SlotClock;
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
pub const ValidatorSlotTicker = clock.ValidatorSlotTicker;
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
pub const keymanager_auth = @import("keymanager_auth.zig");
pub const KeymanagerAuth = keymanager_auth.KeymanagerAuth;
pub const keystore_create = @import("keystore_create.zig");
pub const createKeystore = keystore_create.createKeystore;
pub const encryptKeystore = keystore_create.encryptKeystore;
pub const writeKeystoreToDir = keystore_create.writeKeystoreToDir;

// New: Index tracker (pubkey → validator index mapping).
pub const index_tracker = @import("index_tracker.zig");
pub const IndexTracker = index_tracker.IndexTracker;

// New: Validator liveness tracker (per-epoch duty outcome tracking).
pub const liveness = @import("liveness.zig");
pub const LivenessTracker = liveness.LivenessTracker;
pub const DutyKind = liveness.DutyKind;

// Genesis validators root verified interchange import.
pub const importInterchangeVerified = interchange.importInterchangeVerified;

// Syncing status tracker — pauses duties when BN is out of sync.
pub const syncing_tracker = @import("syncing_tracker.zig");
pub const SyncingTracker = syncing_tracker.SyncingTracker;

// Builder registration service — sends signed validator registrations to the builder relay.
pub const builder_registration = @import("builder_registration.zig");
pub const BuilderRegistrationService = builder_registration.BuilderRegistrationService;
