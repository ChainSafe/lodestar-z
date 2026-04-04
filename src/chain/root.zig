//! Chain module — block import pipeline, operation pools, validator duties,
//! seen caches, block production logic, and the Chain coordinator struct.

const std = @import("std");
const testing = std.testing;

pub const chain = @import("chain.zig");
pub const chain_types = @import("types.zig");
pub const effects = @import("effects.zig");
pub const ports = @import("ports/root.zig");
pub const runtime = @import("runtime.zig");
pub const service = @import("service.zig");
pub const query = @import("query.zig");
pub const regen = @import("regen/root.zig");
pub const state_work_service = @import("state_work_service.zig");
pub const block_import = @import("block_import.zig");
pub const op_pool = @import("op_pool.zig");
pub const seen_cache = @import("seen_cache.zig");
pub const seen_attesters = @import("seen_attesters.zig");
pub const seen_attestation_data = @import("seen_attestation_data.zig");
pub const validator_duties = @import("validator_duties.zig");
pub const produce_block = @import("produce_block.zig");
pub const gossip_validation = @import("gossip_validation.zig");

// Chain struct and types
pub const Chain = chain.Chain;
// BlockInput is now consolidated to blocks/types.BlockInput (P1-7 fix).
pub const BlockInput = blocks.BlockInput;
pub const BlockSource = blocks.BlockSource;
pub const DataAvailabilityStatus = chain_types.DataAvailabilityStatus;
pub const HeadInfo = chain_types.HeadInfo;
pub const SyncStatus = chain_types.SyncStatus;
pub const ForkchoiceUpdateState = chain_types.ForkchoiceUpdateState;
pub const ReadyBlockInput = chain_types.ReadyBlockInput;
pub const PlannedBlockImport = blocks.PlannedBlockImport;
pub const PreparedBlockImport = blocks.PreparedBlockImport;
pub const RawBlockBytes = chain_types.RawBlockBytes;
pub const PlannedBlockIngress = chain_types.PlannedBlockIngress;
pub const BlockDataRequirement = chain_types.BlockDataRequirement;
pub const BlockIngressReadiness = chain_types.BlockIngressReadiness;
pub const BlockDataFetchPlan = chain_types.BlockDataFetchPlan;
pub const BlockIngressResult = chain_types.BlockIngressResult;
pub const NotificationSink = chain_types.NotificationSink;
pub const ChainNotification = chain_types.ChainNotification;
pub const ImportOutcome = effects.ImportOutcome;
pub const SegmentImportOutcome = effects.SegmentImportOutcome;
pub const ExecutionRevalidationOutcome = effects.ExecutionRevalidationOutcome;
pub const BootstrapOutcome = effects.BootstrapOutcome;
pub const ImportEffects = effects.ImportEffects;
pub const SegmentImportEffects = effects.SegmentImportEffects;
pub const ChainSnapshot = effects.ChainSnapshot;
pub const CheckpointSnapshot = effects.CheckpointSnapshot;
pub const ArchiveStateRequest = effects.ArchiveStateRequest;
pub const ExecutionForkchoiceUpdate = effects.ExecutionForkchoiceUpdate;
pub const Runtime = runtime.Runtime;
pub const RuntimeBuilder = runtime.Builder;
pub const RuntimeOptions = runtime.RuntimeOptions;
pub const StorageBackend = runtime.StorageBackend;
pub const Service = service.Service;
pub const Query = query.Query;
pub const CPStateDatastore = regen.CPStateDatastore;
pub const MemoryCPStateDatastore = regen.MemoryCPStateDatastore;
pub const FileCPStateDatastore = regen.FileCPStateDatastore;
pub const CheckpointKey = regen.CheckpointKey;
pub const BlockStateCache = regen.BlockStateCache;
pub const CheckpointStateCache = regen.CheckpointStateCache;
pub const StateDisposer = regen.StateDisposer;
pub const SharedStateGraph = regen.SharedStateGraph;
pub const StateGraphGate = regen.StateGraphGate;
pub const StateRegen = regen.StateRegen;
pub const StateWorkService = state_work_service.StateWorkService;
pub const CompletedBlockImport = state_work_service.CompletedBlockImport;

// Existing re-exports (kept for backward compatibility)
pub const HeadTracker = block_import.HeadTracker;
// ImportResult is now consolidated to blocks/types.ImportResult (P1-8 fix).
pub const ImportResult = blocks.ImportResult;
pub const ImportError = block_import.ImportError;
pub const OpPool = op_pool.OpPool;
pub const SeenCache = seen_cache.SeenCache;
pub const SeenAttesters = seen_attesters.SeenAttesters;
pub const SeenAttestationData = seen_attestation_data.SeenAttestationData;
pub const AttestationDataCacheEntry = seen_attestation_data.AttestationDataCacheEntry;
pub const ValidatorDuties = validator_duties.ValidatorDuties;
pub const AttestationDuty = validator_duties.AttestationDuty;
pub const SyncDuty = validator_duties.SyncDuty;
pub const produceBlockBody = produce_block.produceBlockBody;
pub const GossipAction = gossip_validation.GossipAction;
pub const ChainGossipState = gossip_validation.ChainState;
pub const validateGossipBlock = gossip_validation.validateGossipBlock;
pub const validateGossipAttestation = gossip_validation.validateGossipAttestation;
pub const validateGossipAggregate = gossip_validation.validateGossipAggregate;
pub const validateGossipDataColumnSidecar = gossip_validation.validateGossipDataColumnSidecar;
pub const validateGossipBlobSidecar = gossip_validation.validateGossipBlobSidecar;
pub const validateGossipVoluntaryExit = gossip_validation.validateGossipVoluntaryExit;
pub const validateGossipProposerSlashing = gossip_validation.validateGossipProposerSlashing;
pub const validateGossipAttesterSlashing = gossip_validation.validateGossipAttesterSlashing;
pub const validateGossipBlsToExecutionChange = gossip_validation.validateGossipBlsToExecutionChange;
pub const validateGossipSyncCommitteeMessage = gossip_validation.validateGossipSyncCommitteeMessage;
pub const validateGossipSyncContributionAndProof = gossip_validation.validateGossipSyncContributionAndProof;
pub const ProducedBlockBody = produce_block.ProducedBlockBody;
pub const CommonBlockBody = produce_block.CommonBlockBody;
pub const ProposalSnapshot = produce_block.ProposalSnapshot;
pub const PreparedProposalTemplate = produce_block.PreparedProposalTemplate;
pub const ProducedBlock = produce_block.ProducedBlock;
pub const ProducedBlindedBlock = produce_block.ProducedBlindedBlock;
pub const BlockProductionConfig = produce_block.BlockProductionConfig;
pub const assembleBlock = produce_block.assembleBlock;
pub const assembleBlindedBlock = produce_block.assembleBlindedBlock;
pub const prepareProposalSnapshot = produce_block.prepareProposalSnapshot;
pub const buildProposalTemplate = produce_block.buildProposalTemplate;
pub const assembleBlockFromTemplate = produce_block.assembleBlockFromTemplate;
pub const assembleBlindedBlockFromTemplate = produce_block.assembleBlindedBlockFromTemplate;
pub const DEFAULT_GRAFFITI = produce_block.DEFAULT_GRAFFITI;

test {
    testing.refAllDecls(@This());
}
pub const sync_contribution_pool = @import("sync_contribution_pool.zig");
pub const SyncContributionAndProofPool = sync_contribution_pool.SyncContributionAndProofPool;
pub const SyncCommitteeMessagePool = sync_contribution_pool.SyncCommitteeMessagePool;

// New chain pipeline modules
pub const shuffling_cache = @import("shuffling_cache.zig");
pub const beacon_proposer_cache = @import("beacon_proposer_cache.zig");
pub const prepare_next_slot = @import("prepare_next_slot.zig");
pub const archive_store = @import("archive_store.zig");
// block_verification.zig removed — superseded by blocks/ pipeline (P1-6 fix).
pub const reprocess = @import("reprocess.zig");
pub const pending_block_ingress = @import("block_ingress.zig");
pub const payload_envelope_ingress = @import("payload_envelope_ingress.zig");

// Re-exports
pub const ShufflingCache = shuffling_cache.ShufflingCache;
pub const BeaconProposerCache = beacon_proposer_cache.BeaconProposerCache;
pub const ProposerInfo = beacon_proposer_cache.ProposerInfo;
pub const PrepareNextSlot = prepare_next_slot.PrepareNextSlot;
pub const ArchiveStore = archive_store.ArchiveStore;
pub const ReprocessQueue = reprocess.ReprocessQueue;
pub const PendingBlock = reprocess.PendingBlock;
pub const PendingReason = reprocess.PendingReason;
pub const PendingBlockIngress = pending_block_ingress.PendingBlockIngress;
pub const PendingIngressBlock = pending_block_ingress.PendingIngressBlock;
pub const PayloadEnvelopeIngress = payload_envelope_ingress.PayloadEnvelopeIngress;
pub const PendingPayloadEnvelope = payload_envelope_ingress.PendingPayloadEnvelope;
pub const PayloadEnvelopeFetchPlan = payload_envelope_ingress.PayloadEnvelopeFetchPlan;
// BlockVerification removed — use blocks/pipeline.zig instead.

// Queued state regeneration
pub const queued_regen = regen.queued_regen;
pub const QueuedStateRegen = queued_regen.QueuedStateRegen;
pub const RegenPriority = queued_regen.RegenPriority;
pub const RegenKey = queued_regen.RegenKey;
pub const RegenRequest = queued_regen.RegenRequest;
// KZG verification for blob sidecars and data columns
pub const blob_kzg_verification = @import("blob_kzg_verification.zig");
pub const BlobVerifyInput = blob_kzg_verification.BlobVerifyInput;
pub const BlobVerifyError = blob_kzg_verification.BlobVerifyError;
pub const verifyBlobSidecar = blob_kzg_verification.verifyBlobSidecar;
pub const verifyBlobSidecarBatch = blob_kzg_verification.verifyBlobSidecarBatch;
pub const verifyDataColumnSidecar = blob_kzg_verification.verifyDataColumnSidecar;

// Block import pipeline — staged verification and import
pub const blocks = @import("blocks/root.zig");
pub const BlockPipeline = blocks.pipeline;
pub const PipelineContext = blocks.PipelineContext;
// PipelineBlockInput / PipelineImportResult are now consolidated to the primary names.
// Keep aliases for backward compatibility.
pub const PipelineBlockInput = blocks.BlockInput; // = BlockInput (same type now)
pub const PipelineBlockSource = blocks.BlockSource; // = BlockSource (same type now)
pub const PipelineImportOpts = blocks.ImportBlockOpts;
pub const PipelineImportResult = blocks.ImportResult; // = ImportResult (same type now)
pub const VerifiedBlock = blocks.VerifiedBlock;
pub const ExecutionStatus = blocks.ExecutionStatus;
pub const PipelineDataAvailabilityStatus = blocks.DataAvailabilityStatus;
pub const BlockImportError = blocks.BlockImportError;
pub const BatchBlockResult = blocks.BatchBlockResult;
pub const SanityOutcome = blocks.SanityOutcome;
pub const ExecutionPort = ports.ExecutionPort;
pub const ExecutionVerifier = ports.ExecutionVerifier;
pub const NewPayloadRequest = ports.NewPayloadRequest;
pub const NewPayloadResult = ports.NewPayloadResult;
// Data availability subsystem
pub const blob_tracker = @import("blob_tracker.zig");
pub const column_tracker = @import("column_tracker.zig");
pub const column_reconstruction = @import("column_reconstruction.zig");
pub const da_sampling = @import("da_sampling.zig");
pub const data_availability = @import("data_availability.zig");

// DA re-exports
pub const BlobTracker = blob_tracker.BlobTracker;
pub const ColumnTracker = column_tracker.ColumnTracker;
pub const ColumnReconstructor = column_reconstruction.ColumnReconstructor;
pub const DataAvailabilityManager = data_availability.DataAvailabilityManager;
pub const DaStatus = data_availability.DaStatus;
pub const DaCheckResult = data_availability.DaCheckResult;
pub const DaConfig = data_availability.DaConfig;
pub const aggregated_attestation_pool = @import("aggregated_attestation_pool.zig");
pub const AggregatedAttestationPool = aggregated_attestation_pool.AggregatedAttestationPool;
pub const AttestationGroup = aggregated_attestation_pool.AttestationGroup;
// Validator monitor — per-validator on-chain performance tracking
pub const validator_monitor = @import("validator_monitor.zig");
pub const ValidatorMonitor = validator_monitor.ValidatorMonitor;
pub const MonitoredValidator = validator_monitor.MonitoredValidator;
pub const ValidatorSummary = validator_monitor.ValidatorSummary;
