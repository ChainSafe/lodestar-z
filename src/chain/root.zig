//! Chain module — block import pipeline, operation pools, validator duties,
//! seen caches, block production logic, and the Chain coordinator struct.

const std = @import("std");
const testing = std.testing;

pub const chain = @import("chain.zig");
pub const chain_types = @import("types.zig");
pub const block_import = @import("block_import.zig");
pub const op_pool = @import("op_pool.zig");
pub const seen_cache = @import("seen_cache.zig");
pub const validator_duties = @import("validator_duties.zig");
pub const produce_block = @import("produce_block.zig");
pub const gossip_validation = @import("gossip_validation.zig");

// Chain struct and types
pub const Chain = chain.Chain;
pub const BlockInput = chain_types.BlockInput;
pub const HeadInfo = chain_types.HeadInfo;
pub const SyncStatus = chain_types.SyncStatus;
pub const EventCallback = chain_types.EventCallback;
pub const SseEvent = chain_types.SseEvent;

// Existing re-exports (kept for backward compatibility)
pub const HeadTracker = block_import.HeadTracker;
pub const ImportResult = chain_types.ImportResult;
pub const ImportError = block_import.ImportError;
pub const OpPool = op_pool.OpPool;
pub const SeenCache = seen_cache.SeenCache;
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
pub const ProducedBlockBody = produce_block.ProducedBlockBody;
pub const ProducedBlock = produce_block.ProducedBlock;
pub const BlockProductionConfig = produce_block.BlockProductionConfig;
pub const assembleBlock = produce_block.assembleBlock;
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
pub const block_verification = @import("block_verification.zig");
pub const reprocess = @import("reprocess.zig");

// Re-exports
pub const ShufflingCache = shuffling_cache.ShufflingCache;
pub const BeaconProposerCache = beacon_proposer_cache.BeaconProposerCache;
pub const ProposerInfo = beacon_proposer_cache.ProposerInfo;
pub const PrepareNextSlot = prepare_next_slot.PrepareNextSlot;
pub const ArchiveStore = archive_store.ArchiveStore;
pub const ReprocessQueue = reprocess.ReprocessQueue;
pub const PendingBlock = reprocess.PendingBlock;
pub const PendingReason = reprocess.PendingReason;
pub const BlockVerification = block_verification;

// Queued state regeneration
pub const queued_regen = @import("queued_regen.zig");
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
pub const PipelineBlockInput = blocks.BlockInput;
pub const PipelineBlockSource = blocks.BlockSource;
pub const PipelineImportOpts = blocks.ImportBlockOpts;
pub const PipelineImportResult = blocks.ImportResult;
pub const VerifiedBlock = blocks.VerifiedBlock;
pub const ExecutionStatus = blocks.ExecutionStatus;
pub const PipelineDataAvailabilityStatus = blocks.DataAvailabilityStatus;
pub const BlockImportError = blocks.BlockImportError;
pub const BatchBlockResult = blocks.BatchBlockResult;
pub const SanityOutcome = blocks.SanityOutcome;
pub const ExecutionVerifier = blocks.ExecutionVerifier;
