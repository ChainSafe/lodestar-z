const std = @import("std");
const testing = std.testing;

pub const computeSigningRoot = @import("./utils/signing_root.zig").computeSigningRoot;
pub const BeaconBlock = @import("./types/beacon_block.zig").BeaconBlock;
pub const BeaconBlockBody = @import("./types/beacon_block.zig").BeaconBlockBody;
pub const BeaconState = @import("./types/beacon_state.zig").BeaconState;
pub const CachedBeaconState = @import("./cache/state_cache.zig").CachedBeaconState;
pub const EffectiveBalanceIncrements = @import("./cache/effective_balance_increments.zig").EffectiveBalanceIncrements;

pub const EpochCacheImmutableData = @import("./cache/epoch_cache.zig").EpochCacheImmutableData;
pub const EpochCacheRc = @import("./cache/epoch_cache.zig").EpochCacheRc;
pub const EpochCache = @import("./cache/epoch_cache.zig").EpochCache;

pub const PubkeyIndexMap = @import("./utils/pubkey_index_map.zig").PubkeyIndexMap;
pub const shuffle = @import("./utils/shuffle.zig");
pub const committee_indices = @import("./utils/committee_indices.zig");
pub const Index2PubkeyCache = @import("./cache/pubkey_cache.zig").Index2PubkeyCache;
pub const syncPubkeys = @import("./cache/pubkey_cache.zig").syncPubkeys;

pub const EpochTransitionCache = @import("./cache/epoch_transition_cache.zig").EpochTransitionCache;
pub const processEpoch = @import("./epoch/process_epoch.zig").processEpoch;
pub const processJustificationAndFinalization = @import("./epoch/process_justification_and_finalization.zig").processJustificationAndFinalization;
pub const processInactivityUpdates = @import("./epoch/process_inactivity_updates.zig").processInactivityUpdates;
pub const processRegistryUpdates = @import("./epoch/process_registry_updates.zig").processRegistryUpdates;
pub const processSlashings = @import("./epoch/process_slashings.zig").processSlashings;
pub const processRewardsAndPenalties = @import("./epoch/process_rewards_and_penalties.zig").processRewardsAndPenalties;
pub const getRewardsAndPenalties = @import("./epoch/process_rewards_and_penalties.zig").getRewardsAndPenalties;
pub const processEth1DataReset = @import("./epoch/process_eth1_data_reset.zig").processEth1DataReset;
pub const processPendingDeposits = @import("./epoch/process_pending_deposits.zig").processPendingDeposits;
pub const processPendingConsolidations = @import("./epoch/process_pending_consolidations.zig").processPendingConsolidations;
pub const processEffectiveBalanceUpdates = @import("./epoch/process_effective_balance_updates.zig").processEffectiveBalanceUpdates;
pub const processSlashingsReset = @import("./epoch/process_slashings_reset.zig").processSlashingsReset;
pub const processRandaoMixesReset = @import("./epoch/process_randao_mixes_reset.zig").processRandaoMixesReset;
pub const processHistoricalSummariesUpdate = @import("./epoch/process_historical_summaries_update.zig").processHistoricalSummariesUpdate;
pub const processHistoricalRootsUpdate = @import("./epoch/process_historical_roots_update.zig").processHistoricalRootsUpdate;
pub const processParticipationRecordUpdates = @import("./epoch/process_participation_record_updates.zig").processParticipationRecordUpdates;
pub const processParticipationFlagUpdates = @import("./epoch/process_participation_flag_updates.zig").processParticipationFlagUpdates;
pub const processSyncCommitteeUpdates = @import("./epoch/process_sync_committee_updates.zig").processSyncCommitteeUpdates;
pub const getNextSyncCommitteeIndices = @import("./utils/sync_committee.zig").getNextSyncCommitteeIndices;

pub const upgradeStateToAltair = @import("./slot/upgrade_state_to_altair.zig").upgradeStateToAltair;
pub const upgradeStateToBellatrix = @import("./slot/upgrade_state_to_bellatrix.zig").upgradeStateToBellatrix;
pub const upgradeStateToCapella = @import("./slot/upgrade_state_to_capella.zig").upgradeStateToCapella;
pub const upgradeStateToDeneb = @import("./slot/upgrade_state_to_deneb.zig").upgradeStateToDeneb;
pub const upgradeStateToElectra = @import("./slot/upgrade_state_to_electra.zig").upgradeStateToElectra;
pub const upgradeStateToFulu = @import("./slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;

// Block
pub const processBlockHeader = @import("./block/process_block_header.zig").processBlockHeader;
pub const processWithdrawals = @import("./block/process_withdrawals.zig").processWithdrawals;
pub const getExpectedWithdrawals = @import("./block/process_withdrawals.zig").getExpectedWithdrawals;
pub const processExecutionPayload = @import("./block/process_execution_payload.zig").processExecutionPayload;
pub const processRandao = @import("./block/process_randao.zig").processRandao;
pub const processEth1Data = @import("./block/process_eth1_data.zig").processEth1Data;
pub const processOperations = @import("./block/process_operations.zig").processOperations;
pub const processSyncAggregate = @import("./block/process_sync_committee.zig").processSyncAggregate;
pub const processBlobKzgCommitments = @import("./block/process_blob_kzg_commitments.zig").processBlobKzgCommitments;
pub const processAttestations = @import("./block/process_attestations.zig").processAttestations;
pub const processAttesterSlashing = @import("./block/process_attester_slashing.zig").processAttesterSlashing;
pub const processDeposit = @import("./block/process_deposit.zig").processDeposit;
pub const processProposerSlashing = @import("./block/process_proposer_slashing.zig").processProposerSlashing;
pub const processVoluntaryExit = @import("./block/process_voluntary_exit.zig").processVoluntaryExit;
pub const processBlsToExecutionChange = @import("./block/process_bls_to_execution_change.zig").processBlsToExecutionChange;
pub const processDepositRequest = @import("./block/process_deposit_request.zig").processDepositRequest;
pub const processWithdrawalRequest = @import("./block/process_withdrawal_request.zig").processWithdrawalRequest;
pub const processConsolidationRequest = @import("./block/process_consolidation_request.zig").processConsolidationRequest;

// utils
pub const getBlockRootAtSlot = @import("./utils/block_root.zig").getBlockRootAtSlot;
pub const computeStartSlotAtEpoch = @import("./utils/epoch.zig").computeStartSlotAtEpoch;
pub const deinitStateTransition = @import("./state_transition.zig").deinitStateTransition;

pub const WithdrawalsResult = @import("./block/process_withdrawals.zig").WithdrawalsResult;

pub const test_utils = @import("test_utils/root.zig");

pub const bls = @import("utils/bls.zig");
const seed = @import("./utils/seed.zig");
pub const state_transition = @import("./state_transition.zig");
const EpochShuffling = @import("./utils/epoch_shuffling.zig");
pub const SignedBlock = @import("./types/block.zig").SignedBlock;
pub const Block = @import("./types/block.zig").Block;
pub const SignedBeaconBlock = @import("./types/beacon_block.zig").SignedBeaconBlock;
pub const Attestations = @import("./types/attestation.zig").Attestations;
pub const processProposerLookahead = @import("./epoch/process_proposer_lookahead.zig").processProposerLookahead;

test {
    testing.refAllDecls(@This());
    testing.refAllDecls(seed);
    testing.refAllDecls(state_transition);
    testing.refAllDecls(EpochShuffling);
}
