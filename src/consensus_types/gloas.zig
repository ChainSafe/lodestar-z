const ssz = @import("ssz");
const p = @import("primitive.zig");
const c = @import("constants");
const preset = @import("preset").preset;
const phase0 = @import("phase0.zig");
const altair = @import("altair.zig");
const bellatrix = @import("bellatrix.zig");
const capella = @import("capella.zig");
const deneb = @import("deneb.zig");
const electra = @import("electra.zig");
const fulu = @import("fulu.zig");

// Gloas reuses most types from prior forks
pub const Fork = phase0.Fork;
pub const ForkData = phase0.ForkData;
pub const Checkpoint = phase0.Checkpoint;
pub const Validator = phase0.Validator;
pub const Validators = phase0.Validators;
pub const AttestationData = phase0.AttestationData;
pub const PendingAttestation = phase0.PendingAttestation;
pub const Eth1Data = phase0.Eth1Data;
pub const Eth1DataVotes = phase0.Eth1DataVotes;
pub const HistoricalBatch = phase0.HistoricalBatch;
pub const DepositMessage = phase0.DepositMessage;
pub const DepositData = phase0.DepositData;
pub const BeaconBlockHeader = phase0.BeaconBlockHeader;
pub const SigningData = phase0.SigningData;
pub const ProposerSlashing = phase0.ProposerSlashing;
pub const Deposit = phase0.Deposit;
pub const VoluntaryExit = phase0.VoluntaryExit;
pub const SignedVoluntaryExit = phase0.SignedVoluntaryExit;
pub const Eth1Block = phase0.Eth1Block;
pub const HistoricalBlockRoots = phase0.HistoricalBlockRoots;
pub const HistoricalStateRoots = phase0.HistoricalStateRoots;
pub const ProposerSlashings = phase0.ProposerSlashings;
pub const Deposits = phase0.Deposits;
pub const VoluntaryExits = phase0.VoluntaryExits;
pub const Slashings = phase0.Slashings;
pub const Balances = phase0.Balances;
pub const RandaoMixes = phase0.RandaoMixes;

pub const SyncAggregate = altair.SyncAggregate;
pub const SyncCommittee = altair.SyncCommittee;
pub const SyncCommitteeMessage = altair.SyncCommitteeMessage;
pub const SyncCommitteeContribution = altair.SyncCommitteeContribution;
pub const ContributionAndProof = altair.ContributionAndProof;
pub const SignedContributionAndProof = altair.SignedContributionAndProof;
pub const SyncAggregatorSelectionData = altair.SyncAggregatorSelectionData;

pub const PowBlock = bellatrix.PowBlock;

pub const Withdrawal = capella.Withdrawal;
pub const Withdrawals = capella.Withdrawals;
pub const BLSToExecutionChange = capella.BLSToExecutionChange;
pub const SignedBLSToExecutionChange = capella.SignedBLSToExecutionChange;
pub const SignedBLSToExecutionChanges = capella.SignedBLSToExecutionChanges;
pub const HistoricalSummary = capella.HistoricalSummary;

pub const BlobIdentifier = deneb.BlobIdentifier;
pub const BlobKzgCommitments = deneb.BlobKzgCommitments;

// Reuse Electra types
pub const PendingDeposit = electra.PendingDeposit;
pub const PendingPartialWithdrawal = electra.PendingPartialWithdrawal;
pub const PendingConsolidation = electra.PendingConsolidation;
pub const DepositRequest = electra.DepositRequest;
pub const WithdrawalRequest = electra.WithdrawalRequest;
pub const ConsolidationRequest = electra.ConsolidationRequest;
pub const ExecutionRequests = electra.ExecutionRequests;
pub const SingleAttestation = electra.SingleAttestation;
pub const Attestation = electra.Attestation;
pub const Attestations = electra.Attestations;
pub const IndexedAttestation = electra.IndexedAttestation;
pub const AttesterSlashing = electra.AttesterSlashing;
pub const AttesterSlashings = electra.AttesterSlashings;
pub const AggregateAndProof = electra.AggregateAndProof;
pub const SignedAggregateAndProof = electra.SignedAggregateAndProof;
pub const SignedBeaconBlockHeader = electra.SignedBeaconBlockHeader;

// Execution payload types remain for envelope usage
pub const ExecutionPayload = electra.ExecutionPayload;
pub const ExecutionPayloadHeader = electra.ExecutionPayloadHeader;

// Reuse Fulu DAS types
pub const RowIndex = fulu.RowIndex;
pub const ColumnIndex = fulu.ColumnIndex;
pub const CustodyIndex = fulu.CustodyIndex;
pub const Cell = fulu.Cell;
pub const MatrixEntry = fulu.MatrixEntry;
pub const ProposerLookahead = fulu.ProposerLookahead;

// Light client types
pub const LightClientHeader = electra.LightClientHeader;
pub const LightClientBootstrap = electra.LightClientBootstrap;
pub const LightClientUpdate = electra.LightClientUpdate;
pub const LightClientFinalityUpdate = electra.LightClientFinalityUpdate;
pub const LightClientOptimisticUpdate = electra.LightClientOptimisticUpdate;

// ── New Gloas types (EIP-7732: ePBS) ──

// Alias for builder indices (Uint64 like ValidatorIndex)
pub const BuilderIndex = p.Uint64;

pub const Builder = ssz.FixedContainerType(struct {
    pubkey: p.BLSPubkey,
    version: p.Uint8,
    execution_address: p.ExecutionAddress,
    balance: p.Uint64,
    deposit_epoch: p.Uint64,
    withdrawable_epoch: p.Uint64,
});

pub const BuilderPendingWithdrawal = ssz.FixedContainerType(struct {
    fee_recipient: p.ExecutionAddress,
    amount: p.Uint64,
    builder_index: BuilderIndex,
});

pub const BuilderPendingPayment = ssz.FixedContainerType(struct {
    weight: p.Uint64,
    withdrawal: BuilderPendingWithdrawal,
});

pub const PayloadAttestationData = ssz.FixedContainerType(struct {
    beacon_block_root: p.Root,
    slot: p.Slot,
    payload_present: p.Boolean,
    blob_data_available: p.Boolean,
});

pub const PayloadAttestation = ssz.FixedContainerType(struct {
    aggregation_bits: ssz.BitVectorType(preset.PTC_SIZE),
    data: PayloadAttestationData,
    signature: p.BLSSignature,
});

pub const PayloadAttestationMessage = ssz.FixedContainerType(struct {
    validator_index: p.ValidatorIndex,
    data: PayloadAttestationData,
    signature: p.BLSSignature,
});

pub const IndexedPayloadAttestation = ssz.VariableContainerType(struct {
    attesting_indices: ssz.FixedListType(p.ValidatorIndex, preset.PTC_SIZE),
    data: PayloadAttestationData,
    signature: p.BLSSignature,
});

pub const ProposerPreferences = ssz.FixedContainerType(struct {
    proposal_slot: p.Slot,
    validator_index: p.ValidatorIndex,
    fee_recipient: p.ExecutionAddress,
    gas_limit: p.Uint64,
});

pub const SignedProposerPreferences = ssz.FixedContainerType(struct {
    message: ProposerPreferences,
    signature: p.BLSSignature,
});

pub const ExecutionPayloadBid = ssz.VariableContainerType(struct {
    parent_block_hash: p.Bytes32,
    parent_block_root: p.Root,
    block_hash: p.Bytes32,
    prev_randao: p.Bytes32,
    fee_recipient: p.ExecutionAddress,
    gas_limit: p.Uint64,
    builder_index: BuilderIndex,
    slot: p.Slot,
    value: p.Uint64,
    execution_payment: p.Uint64,
    blob_kzg_commitments: ssz.FixedListType(p.KZGCommitment, preset.MAX_BLOB_COMMITMENTS_PER_BLOCK),
});

pub const SignedExecutionPayloadBid = ssz.VariableContainerType(struct {
    message: ExecutionPayloadBid,
    signature: p.BLSSignature,
});

pub const ExecutionPayloadEnvelope = ssz.VariableContainerType(struct {
    payload: ExecutionPayload,
    execution_requests: ExecutionRequests,
    builder_index: BuilderIndex,
    beacon_block_root: p.Root,
    slot: p.Slot,
    state_root: p.Root,
});

pub const SignedExecutionPayloadEnvelope = ssz.VariableContainerType(struct {
    message: ExecutionPayloadEnvelope,
    signature: p.BLSSignature,
});

// Gloas BeaconBlockBody: removes executionPayload, blobKzgCommitments, executionRequests
// Adds signedExecutionPayloadBid and payloadAttestations
pub const BeaconBlockBody = ssz.VariableContainerType(struct {
    randao_reveal: p.BLSSignature,
    eth1_data: Eth1Data,
    graffiti: p.Bytes32,
    proposer_slashings: ProposerSlashings,
    attester_slashings: AttesterSlashings,
    attestations: Attestations,
    deposits: Deposits,
    voluntary_exits: VoluntaryExits,
    sync_aggregate: SyncAggregate,
    // executionPayload removed in Gloas (EIP-7732)
    bls_to_execution_changes: SignedBLSToExecutionChanges,
    // blobKzgCommitments removed in Gloas (EIP-7732)
    // executionRequests removed in Gloas (EIP-7732)
    signed_execution_payload_bid: SignedExecutionPayloadBid,
    payload_attestations: ssz.FixedListType(PayloadAttestation, preset.MAX_PAYLOAD_ATTESTATIONS),
});

pub const BeaconBlock = ssz.VariableContainerType(struct {
    slot: p.Slot,
    proposer_index: p.ValidatorIndex,
    parent_root: p.Root,
    state_root: p.Root,
    body: BeaconBlockBody,
});

pub const SignedBeaconBlock = ssz.VariableContainerType(struct {
    message: BeaconBlock,
    signature: p.BLSSignature,
});

// DataColumnSidecar simplified in Gloas (EIP-7732)
pub const DataColumnSidecar = ssz.VariableContainerType(struct {
    index: ColumnIndex,
    column: ssz.FixedListType(Cell, preset.MAX_BLOB_COMMITMENTS_PER_BLOCK),
    kzg_proofs: ssz.FixedListType(p.KZGProof, preset.MAX_BLOB_COMMITMENTS_PER_BLOCK),
    slot: p.Slot,
    beacon_block_root: p.Root,
});

// Gloas BeaconState: replaces latestExecutionPayloadHeader with latestExecutionPayloadBid
// Adds builder registry, executionPayloadAvailability, builder payments/withdrawals, latestBlockHash
pub const BeaconState = ssz.VariableContainerType(struct {
    genesis_time: p.Uint64,
    genesis_validators_root: p.Root,
    slot: p.Slot,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: HistoricalBlockRoots,
    state_roots: HistoricalStateRoots,
    historical_roots: ssz.FixedListType(p.Root, preset.HISTORICAL_ROOTS_LIMIT),
    eth1_data: Eth1Data,
    eth1_data_votes: phase0.Eth1DataVotes,
    eth1_deposit_index: p.Uint64,
    validators: ssz.FixedListType(Validator, preset.VALIDATOR_REGISTRY_LIMIT),
    balances: ssz.FixedListType(p.Gwei, preset.VALIDATOR_REGISTRY_LIMIT),
    randao_mixes: ssz.FixedVectorType(p.Bytes32, preset.EPOCHS_PER_HISTORICAL_VECTOR),
    slashings: ssz.FixedVectorType(p.Gwei, preset.EPOCHS_PER_SLASHINGS_VECTOR),
    previous_epoch_participation: ssz.FixedListType(p.Uint8, preset.VALIDATOR_REGISTRY_LIMIT),
    current_epoch_participation: ssz.FixedListType(p.Uint8, preset.VALIDATOR_REGISTRY_LIMIT),
    justification_bits: ssz.BitVectorType(c.JUSTIFICATION_BITS_LENGTH),
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: ssz.FixedListType(p.Uint64, preset.VALIDATOR_REGISTRY_LIMIT),
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
    // latestExecutionPayloadHeader removed in Gloas (EIP-7732)
    latest_execution_payload_bid: ExecutionPayloadBid,
    next_withdrawal_index: p.WithdrawalIndex,
    next_withdrawal_validator_index: p.ValidatorIndex,
    historical_summaries: ssz.FixedListType(HistoricalSummary, preset.HISTORICAL_ROOTS_LIMIT),
    deposit_requests_start_index: p.Uint64,
    deposit_balance_to_consume: p.Gwei,
    exit_balance_to_consume: p.Gwei,
    earliest_exit_epoch: p.Epoch,
    consolidation_balance_to_consume: p.Gwei,
    earliest_consolidation_epoch: p.Epoch,
    pending_deposits: ssz.FixedListType(PendingDeposit, preset.PENDING_DEPOSITS_LIMIT),
    pending_partial_withdrawals: ssz.FixedListType(PendingPartialWithdrawal, preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT),
    pending_consolidations: ssz.FixedListType(PendingConsolidation, preset.PENDING_CONSOLIDATIONS_LIMIT),
    proposer_lookahead: ProposerLookahead,
    // New in Gloas (EIP-7732)
    builders: ssz.FixedListType(Builder, preset.BUILDER_REGISTRY_LIMIT),
    next_withdrawal_builder_index: BuilderIndex,
    execution_payload_availability: ssz.BitVectorType(preset.SLOTS_PER_HISTORICAL_ROOT),
    builder_pending_payments: ssz.FixedVectorType(BuilderPendingPayment, 2 * preset.SLOTS_PER_EPOCH),
    builder_pending_withdrawals: ssz.FixedListType(BuilderPendingWithdrawal, preset.BUILDER_PENDING_WITHDRAWALS_LIMIT),
    latest_block_hash: p.Bytes32,
    payload_expected_withdrawals: Withdrawals,
});

pub const BlobSidecar = electra.BlobSidecar;
