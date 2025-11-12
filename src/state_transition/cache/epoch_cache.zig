const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const types = @import("consensus_types");
const c = @import("constants");
const blst = @import("blst");
const Epoch = types.primitive.Epoch.Type;
const Slot = types.primitive.Slot.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const SyncPeriod = types.primitive.SyncPeriod.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const CommitteeIndex = types.primitive.CommitteeIndex.Type;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const PubkeyIndexMap = @import("../utils/pubkey_index_map.zig").PubkeyIndexMap(ValidatorIndex);
const Index2PubkeyCache = @import("./pubkey_cache.zig").Index2PubkeyCache;
const EpochShuffling = @import("../utils//epoch_shuffling.zig").EpochShuffling;
const EpochShufflingRc = @import("../utils/epoch_shuffling.zig").EpochShufflingRc;
const EffectiveBalanceIncrementsRc = @import("./effective_balance_increments.zig").EffectiveBalanceIncrementsRc;
const EffectiveBalanceIncrements = @import("./effective_balance_increments.zig").EffectiveBalanceIncrements;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const computeActivationExitEpoch = @import("../utils/epoch.zig").computeActivationExitEpoch;
const getEffectiveBalanceIncrementsWithLen = @import("./effective_balance_increments.zig").getEffectiveBalanceIncrementsWithLen;
const getTotalSlashingsByIncrement = @import("../epoch/process_slashings.zig").getTotalSlashingsByIncrement;
const computeEpochShuffling = @import("../utils/epoch_shuffling.zig").computeEpochShuffling;
const getSeed = @import("../utils/seed.zig").getSeed;
const computeProposers = @import("../utils/seed.zig").computeProposers;
const SyncCommitteeCacheRc = @import("./sync_committee_cache.zig").SyncCommitteeCacheRc;
const SyncCommitteeCacheAllForks = @import("./sync_committee_cache.zig").SyncCommitteeCacheAllForks;
const computeSyncParticipantReward = @import("../utils/sync_committee.zig").computeSyncParticipantReward;
const computeBaseRewardPerIncrement = @import("../utils/sync_committee.zig").computeBaseRewardPerIncrement;
const computeSyncPeriodAtEpoch = @import("../utils/epoch.zig").computeSyncPeriodAtEpoch;
const isAggregatorFromCommitteeLength = @import("../utils/aggregator.zig").isAggregatorFromCommitteeLength;

const sumTargetUnslashedBalanceIncrements = @import("../utils/target_unslashed_balance.zig").sumTargetUnslashedBalanceIncrements;

const isActiveValidator = @import("../utils/validator.zig").isActiveValidator;
const getChurnLimit = @import("../utils/validator.zig").getChurnLimit;
const getActivationChurnLimit = @import("../utils/validator.zig").getActivationChurnLimit;

const Attestation = @import("../types/attestation.zig").Attestation;
const IndexedAttestation = @import("../types/attestation.zig").IndexedAttestation;

const syncPubkeys = @import("./pubkey_cache.zig").syncPubkeys;

const ReferenceCount = @import("../utils/reference_count.zig").ReferenceCount;

pub const EpochCacheImmutableData = struct {
    config: *const BeaconConfig,
    pubkey_to_index: *PubkeyIndexMap,
    index_to_pubkey: *Index2PubkeyCache,
};

pub const EpochCacheOpts = struct {
    skip_sync_committee_cache: bool,
    skip_sync_pubkeys: bool,
};

const proposer_weight: f64 = @floatFromInt(c.PROPOSER_WEIGHT);
const weight_denominator: f64 = @floatFromInt(c.WEIGHT_DENOMINATOR);

pub const proposer_weight_factor: f64 = proposer_weight / (weight_denominator - proposer_weight);

/// an EpochCache is shared by multiple CachedBeaconStateAllForks instances
/// a CachedBeaconStateAllForks should increase the reference count of EpochCache when it is created
/// and decrease the reference count when it is deinitialized
pub const EpochCacheRc = ReferenceCount(*EpochCache);

pub const EpochCache = struct {
    allocator: Allocator,

    config: *const BeaconConfig,

    // this is shared across applications, EpochCache does not own this field so should not deinit()
    pubkey_to_index: *PubkeyIndexMap,

    // this is shared across applications, EpochCache does not own this field so should not deinit()
    index_to_pubkey: *Index2PubkeyCache,

    proposers: [preset.SLOTS_PER_EPOCH]ValidatorIndex,

    proposer_prev_epoch: ?[preset.SLOTS_PER_EPOCH]ValidatorIndex,

    // TODO: may not need this
    // proposers_next_epoch: not needed after EIP-7917
    // the below is not needed if we compute the next epoch shuffling eagerly
    // previous_decision_root
    // current_decision_root
    // next_decision_root

    // EpochCache does not take ownership of EpochShuffling, it is shared across EpochCache instances
    previous_shuffling: *EpochShufflingRc,

    current_shuffling: *EpochShufflingRc,

    next_shuffling: *EpochShufflingRc,

    // TODO: not needed, maybe just get from the next shuffling?
    // next_active_indices

    // EpochCache does not take ownership of EffectiveBalanceIncrements, it is shared across EpochCache instances
    effective_balance_increment: *EffectiveBalanceIncrementsRc,

    total_slashings_by_increment: u64,

    sync_participant_reward: u64,

    sync_proposer_reward: u64,

    base_reward_per_increment: u64,

    total_active_balance_increments: u64,

    churn_limit: u64,

    activation_churn_limit: u64,

    exit_queue_epoch: Epoch,

    exit_queue_churn: u64,

    current_target_unslashed_balance_increments: u64,

    previous_target_unslashed_balance_increments: u64,

    // EpochCache does not take ownership of SyncCommitteeCache, it is shared across EpochCache instances
    current_sync_committee_indexed: *SyncCommitteeCacheRc,

    next_sync_committee_indexed: *SyncCommitteeCacheRc,

    sync_period: SyncPeriod,

    epoch: Epoch,

    pub fn createFromState(allocator: Allocator, state: *const BeaconStateAllForks, immutable_data: EpochCacheImmutableData, option: ?EpochCacheOpts) !*EpochCache {
        const config = immutable_data.config;
        const pubkey_to_index = immutable_data.pubkey_to_index;
        const index_to_pubkey = immutable_data.index_to_pubkey;

        const current_epoch = computeEpochAtSlot(state.slot());
        const is_genesis = current_epoch == GENESIS_EPOCH;
        const previous_epoch = if (is_genesis) GENESIS_EPOCH else current_epoch - 1;
        const next_epoch = current_epoch + 1;

        var total_active_balance_increments: u64 = 0;
        var exit_queue_epoch = computeActivationExitEpoch(current_epoch);
        var exit_queue_churn: u64 = 0;

        const validators = state.validators().items;
        const validator_count = validators.len;

        // syncPubkeys here to ensure EpochCacheImmutableData is popualted before computing the rest of caches
        // - computeSyncCommitteeCache() needs a fully populated pubkey2index cache
        const skip_sync_pubkeys = if (option) |opt| opt.skip_sync_pubkeys else false;
        if (!skip_sync_pubkeys) {
            try syncPubkeys(validators, pubkey_to_index, index_to_pubkey);
        }

        const effective_balance_increment = try getEffectiveBalanceIncrementsWithLen(allocator, validator_count);
        const total_slashings_by_increment = getTotalSlashingsByIncrement(state);
        var previous_active_indices_array_list = std.ArrayList(ValidatorIndex).init(allocator);
        defer previous_active_indices_array_list.deinit();
        try previous_active_indices_array_list.ensureTotalCapacity(validator_count);
        var current_active_indices_array_list = std.ArrayList(ValidatorIndex).init(allocator);
        defer current_active_indices_array_list.deinit();
        try current_active_indices_array_list.ensureTotalCapacity(validator_count);
        var next_active_indices_array_list = std.ArrayList(ValidatorIndex).init(allocator);
        defer next_active_indices_array_list.deinit();
        try next_active_indices_array_list.ensureTotalCapacity(validator_count);

        for (0..validator_count) |i| {
            const validator = validators[i];

            // Note: Not usable for fork-choice balances since in-active validators are not zero'ed
            effective_balance_increment.items[i] = @intCast(@divFloor(validator.effective_balance, preset.EFFECTIVE_BALANCE_INCREMENT));

            if (isActiveValidator(&validator, previous_epoch)) {
                try previous_active_indices_array_list.append(i);
            }

            if (isActiveValidator(&validator, current_epoch)) {
                try current_active_indices_array_list.append(i);
                total_active_balance_increments += effective_balance_increment.items[i];
            }

            if (isActiveValidator(&validator, next_epoch)) {
                try next_active_indices_array_list.append(i);
            }

            const exit_epoch = validator.exit_epoch;
            if (exit_epoch != c.FAR_FUTURE_EPOCH) {
                if (exit_epoch > exit_queue_epoch) {
                    exit_queue_epoch = exit_epoch;
                    exit_queue_churn = 1;
                } else if (exit_epoch == exit_queue_epoch) {
                    exit_queue_churn += 1;
                }
            }
        }

        // Spec: `EFFECTIVE_BALANCE_INCREMENT` Gwei minimum to avoid divisions by zero
        // 1 = 1 unit of EFFECTIVE_BALANCE_INCREMENT
        if (total_active_balance_increments < 1) {
            total_active_balance_increments = 1;
        }

        // ownership of the active indices is transferred to EpochShuffling
        const previous_active_indices = try allocator.alloc(ValidatorIndex, previous_active_indices_array_list.items.len);
        std.mem.copyForwards(ValidatorIndex, previous_active_indices, previous_active_indices_array_list.items);
        const previous_shuffling: *EpochShuffling = try computeEpochShuffling(allocator, state, previous_active_indices, previous_epoch);

        // ownership of the active indices is transferred to EpochShuffling
        const current_active_indices = try allocator.alloc(ValidatorIndex, current_active_indices_array_list.items.len);
        std.mem.copyForwards(ValidatorIndex, current_active_indices, current_active_indices_array_list.items);
        const current_shuffling: *EpochShuffling = try computeEpochShuffling(allocator, state, current_active_indices, current_epoch);

        // ownership of the active indices is transferred to EpochShuffling
        const next_active_indices = try allocator.alloc(ValidatorIndex, next_active_indices_array_list.items.len);
        std.mem.copyForwards(ValidatorIndex, next_active_indices, next_active_indices_array_list.items);
        const next_shuffling: *EpochShuffling = try computeEpochShuffling(allocator, state, next_active_indices, next_epoch);

        // TODO: implement proposerLookahead in fulu
        const fork_seq = config.forkSeqAtEpoch(current_epoch);
        var current_proposer_seed: [32]u8 = undefined;
        try getSeed(state, current_epoch, c.DOMAIN_BEACON_PROPOSER, &current_proposer_seed);
        var proposers = [_]ValidatorIndex{0} ** preset.SLOTS_PER_EPOCH;
        if (current_shuffling.active_indices.len > 0) {
            try computeProposers(allocator, fork_seq, current_proposer_seed, current_epoch, current_shuffling.active_indices, effective_balance_increment, &proposers);
        }

        // Only after altair, compute the indices of the current sync committee
        const after_altair_fork = current_epoch >= config.chain.ALTAIR_FORK_EPOCH;

        // Values syncParticipantReward, syncProposerReward, baseRewardPerIncrement are only used after altair.
        // However, since they are very cheap to compute they are computed always to simplify upgradeState function.
        const sync_participant_reward = computeSyncParticipantReward(total_active_balance_increments);
        const sync_participant_reward_f64: f64 = @floatFromInt(sync_participant_reward);
        const sync_proposer_reward: u64 = @intFromFloat(std.math.floor(sync_participant_reward_f64 * proposer_weight_factor));
        const base_reward_pre_increment = computeBaseRewardPerIncrement(total_active_balance_increments);
        const skip_sync_committee_cache = if (option) |opt| opt.skip_sync_committee_cache else !after_altair_fork;
        var current_sync_committee_indexed = if (skip_sync_committee_cache) SyncCommitteeCacheAllForks.initEmpty() else try SyncCommitteeCacheAllForks.initSyncCommittee(allocator, state.currentSyncCommittee(), pubkey_to_index);
        var next_sync_committee_indexed = if (skip_sync_committee_cache) SyncCommitteeCacheAllForks.initEmpty() else try SyncCommitteeCacheAllForks.initSyncCommittee(allocator, state.nextSyncCommittee(), pubkey_to_index);

        errdefer {
            current_sync_committee_indexed.deinit();
            next_sync_committee_indexed.deinit();
        }

        // Precompute churnLimit for efficient initiateValidatorExit() during block proposing MUST be recompute everytime the
        // active validator indices set changes in size. Validators change active status only when:
        // - validator.activation_epoch is set. Only changes in process_registry_updates() if validator can be activated. If
        //   the value changes it will be set to `epoch + 1 + MAX_SEED_LOOKAHEAD`.
        // - validator.exit_epoch is set. Only changes in initiate_validator_exit() if validator exits. If the value changes,
        //   it will be set to at least `epoch + 1 + MAX_SEED_LOOKAHEAD`.
        // ```
        // is_active_validator = validator.activation_epoch <= epoch < validator.exit_epoch
        // ```
        // So the returned value of is_active_validator(epoch) is guaranteed to not change during `MAX_SEED_LOOKAHEAD` epochs.
        //
        // activeIndices size is dependent on the state epoch. The epoch is advanced after running the epoch transition, and
        // the first block of the epoch process_block() call. So churnLimit must be computed at the end of the before epoch
        // transition and the result is valid until the end of the next epoch transition
        const churn_limit = getChurnLimit(config, current_shuffling.active_indices.len);
        const activation_churn_limit = getActivationChurnLimit(config, fork_seq, current_shuffling.active_indices.len);
        if (exit_queue_churn >= churn_limit) {
            exit_queue_epoch += 1;
            exit_queue_churn = 0;
        }

        // TODO: describe issue. Compute progressive target balances
        // Compute balances from zero, note this state could be mid-epoch so target balances != 0
        var previous_target_unslashed_balance_increments: u64 = 0;
        var current_target_unslashed_balance_increments: u64 = 0;

        if (fork_seq.isPostAltair()) {
            const previous_epoch_participation = state.previousEpochParticipations().items;
            const current_epoch_participation = state.currentEpochParticipations().items;

            previous_target_unslashed_balance_increments = sumTargetUnslashedBalanceIncrements(previous_epoch_participation, previous_epoch, validators);
            current_target_unslashed_balance_increments = sumTargetUnslashedBalanceIncrements(current_epoch_participation, current_epoch, validators);
        }

        const epoch_cache_ptr = try allocator.create(EpochCache);
        errdefer allocator.destroy(epoch_cache_ptr);

        epoch_cache_ptr.* = .{
            .allocator = allocator,
            .config = config,
            .pubkey_to_index = pubkey_to_index,
            .index_to_pubkey = index_to_pubkey,
            .proposers = proposers,
            // On first epoch, set to null to prevent unnecessary work since this is only used for metrics
            .proposer_prev_epoch = null,
            .previous_shuffling = try EpochShufflingRc.init(allocator, previous_shuffling),
            .current_shuffling = try EpochShufflingRc.init(allocator, current_shuffling),
            .next_shuffling = try EpochShufflingRc.init(allocator, next_shuffling),
            .effective_balance_increment = try EffectiveBalanceIncrementsRc.init(allocator, effective_balance_increment),
            .total_slashings_by_increment = total_slashings_by_increment,
            .sync_participant_reward = sync_participant_reward,
            .sync_proposer_reward = sync_proposer_reward,
            .base_reward_per_increment = base_reward_pre_increment,
            .total_active_balance_increments = total_active_balance_increments,
            .churn_limit = churn_limit,
            .activation_churn_limit = activation_churn_limit,
            .exit_queue_epoch = exit_queue_epoch,
            .exit_queue_churn = exit_queue_churn,
            .current_target_unslashed_balance_increments = current_target_unslashed_balance_increments,
            .previous_target_unslashed_balance_increments = previous_target_unslashed_balance_increments,
            .current_sync_committee_indexed = try SyncCommitteeCacheRc.init(allocator, current_sync_committee_indexed),
            .next_sync_committee_indexed = try SyncCommitteeCacheRc.init(allocator, next_sync_committee_indexed),
            .sync_period = computeSyncPeriodAtEpoch(current_epoch),
            .epoch = current_epoch,
        };

        return epoch_cache_ptr;
    }

    pub fn deinit(self: *EpochCache) void {
        // pubkey_to_index and index_to_pubkey are shared across applications, EpochCache does not own this field so should not deinit()

        // unref the epoch shufflings
        self.previous_shuffling.release();
        self.current_shuffling.release();
        self.next_shuffling.release();

        // unref the effective balance increments
        self.effective_balance_increment.release();

        // unref the sync committee caches
        self.current_sync_committee_indexed.release();
        self.next_sync_committee_indexed.release();
        self.allocator.destroy(self);
    }

    pub fn clone(self: *const EpochCache, allocator: Allocator) !*EpochCache {
        const epoch_cache = .EpochCache{
            .allocator = self.allocator,
            .config = self.config,
            // Common append-only structures shared with all states, no need to clone
            .pubkey_to_index = self.pubkey_to_index,
            .index_to_pubkey = self.index_to_pubkey,
            // Immutable data
            .proposers = self.proposers,
            .proposer_prev_epoch = self.proposer_prev_epoch,
            // reuse the same instances, increase reference count
            .previous_shuffling = self.previous_shuffling.acquire(),
            .current_shuffling = self.current_shuffling.acquire(),
            .next_shuffling = self.next_shuffling.acquire(),
            // reuse the same instances, increase reference count, cloned only when necessary before an epoch transition
            .effective_balance_increment = self.effective_balance_increment.acquire(),
            .total_slashings_by_increment = self.total_slashings_by_increment,
            // Basic types (numbers) cloned implicitly
            .sync_participant_reward = self.sync_participant_reward,
            .sync_proposer_reward = self.sync_proposer_reward,
            .base_reward_per_increment = self.base_reward_per_increment,
            .total_active_balance_increments = self.total_active_balance_increments,
            .churn_limit = self.churn_limit,
            .activation_churn_limit = self.activation_churn_limit,
            .exit_queue_epoch = self.exit_queue_epoch,
            .exit_queue_churn = self.exit_queue_churn,
            .current_target_unslashed_balance_increments = self.current_target_unslashed_balance_increments,
            .previous_target_unslashed_balance_increments = self.previous_target_unslashed_balance_increments,
            // reuse the same instances, increase reference count
            .current_sync_committee_indexed = self.current_sync_committee_indexed.acquire(),
            .next_sync_committee_indexed = self.next_sync_committee_indexed.acquire(),
            .sync_period = self.sync_period,
            .epoch = self.epoch,
        };

        const epoch_cache_ptr = try allocator.create(EpochCache);
        errdefer allocator.destroy(epoch_cache_ptr);
        epoch_cache_ptr.* = epoch_cache;
        return epoch_cache_ptr;
    }

    /// Utility method to return EpochShuffling so that consumers don't have to deal with ".get()" call
    /// Consumers borrow value, so they must not either modify or deinit it.
    /// TODO: @spiral-ladder prefer `self.previous_shuffling.get()` pattern instead, same to below
    pub fn getPreviousShuffling(self: *const EpochCache) *const EpochShuffling {
        return self.previous_shuffling.get();
    }

    /// Utility method to return EpochShuffling so that consumers don't have to deal with ".get()" call
    /// Consumers borrow value, so they must not either modify or deinit it.
    pub fn getCurrentShuffling(self: *const EpochCache) *const EpochShuffling {
        return self.current_shuffling.get();
    }

    /// Utility method to return EpochShuffling so that consumers don't have to deal with ".get()" call
    /// Consumers borrow value, so they must not either modify or deinit it.
    pub fn getNextEpochShuffling(self: *const EpochCache) *const EpochShuffling {
        return self.next_shuffling.get();
    }

    /// Utility method to return SyncCommitteeCache so that consumers don't have to deal with ".get()" call
    pub fn getEffectiveBalanceIncrements(self: *const EpochCache) EffectiveBalanceIncrements {
        return self.effective_balance_increment.get();
    }

    pub fn afterProcessEpoch(self: *EpochCache, cached_state: *const CachedBeaconStateAllForks, epoch_transition_cache: *const EpochTransitionCache) !void {
        const state = cached_state.state;
        const upcoming_epoch = self.epoch + 1;
        const epoch_after_upcoming = upcoming_epoch + 1;

        // move current to previous
        self.previous_shuffling.release();
        // no need to release current_shuffling and next_shuffling
        self.previous_shuffling = self.current_shuffling;
        self.current_shuffling = self.next_shuffling;
        // allocate next_shuffling_active_indices here and transfer owner ship to EpochShuffling
        const next_shuffling_active_indices = try self.allocator.alloc(ValidatorIndex, epoch_transition_cache.next_shuffling_active_indices.len);
        std.mem.copyForwards(ValidatorIndex, next_shuffling_active_indices, epoch_transition_cache.next_shuffling_active_indices);
        const next_shuffling = try computeEpochShuffling(
            self.allocator,
            state,
            next_shuffling_active_indices,
            epoch_after_upcoming,
        );
        self.next_shuffling = try EpochShufflingRc.init(self.allocator, next_shuffling);

        var upcoming_proposer_seed: [32]u8 = undefined;
        try getSeed(state, upcoming_epoch, c.DOMAIN_BEACON_PROPOSER, &upcoming_proposer_seed);
        try computeProposers(self.allocator, self.config.forkSeqAtEpoch(upcoming_epoch), upcoming_proposer_seed, upcoming_epoch, self.current_shuffling.get().active_indices, self.effective_balance_increment.get(), &self.proposers);

        self.churn_limit = getChurnLimit(self.config, self.current_shuffling.get().active_indices.len);
        self.activation_churn_limit = getActivationChurnLimit(self.config, self.config.forkSeq(state.slot()), self.current_shuffling.get().active_indices.len);

        const exit_queue_epoch = computeActivationExitEpoch(upcoming_epoch);
        if (exit_queue_epoch > self.exit_queue_epoch) {
            self.exit_queue_epoch = exit_queue_epoch;
            self.exit_queue_churn = 0;
        }

        self.total_active_balance_increments = epoch_transition_cache.next_epoch_total_active_balance_by_increment;
        if (upcoming_epoch >= self.config.chain.ALTAIR_FORK_EPOCH) {
            self.sync_participant_reward = computeSyncParticipantReward(self.total_active_balance_increments);
            const sync_participant_reward_f64: f64 = @floatFromInt(self.sync_participant_reward);
            self.sync_proposer_reward = @intFromFloat(std.math.floor(sync_participant_reward_f64 * proposer_weight_factor));
            self.base_reward_per_increment = computeBaseRewardPerIncrement(self.total_active_balance_increments);
        }

        self.previous_target_unslashed_balance_increments = self.current_target_unslashed_balance_increments;
        self.current_target_unslashed_balance_increments = 0;
        self.epoch = computeEpochAtSlot(state.slot());
        self.sync_period = computeSyncPeriodAtEpoch(self.epoch);
    }

    pub fn beforeEpochTransition(self: *EpochCache) !void {
        // Clone (copy) before being mutated in processEffectiveBalanceUpdates
        var effective_balance_increment = try EffectiveBalanceIncrements.initCapacity(self.allocator, self.effective_balance_increment.get().items.len);
        try effective_balance_increment.appendSlice(self.effective_balance_increment.get().items);
        // unref the previous effective balance increment
        self.effective_balance_increment.release();
        self.effective_balance_increment = try EffectiveBalanceIncrementsRc.init(self.allocator, effective_balance_increment);
    }

    /// Consumer borrows the returned slice
    pub fn getBeaconCommittee(self: *const EpochCache, slot: Slot, index: CommitteeIndex) ![]const ValidatorIndex {
        const shuffling = self.getShufflingAtSlotOrNull(slot) orelse return error.EpochShufflingNotFound;
        const slot_committees = shuffling.committees[slot % preset.SLOTS_PER_EPOCH];
        if (index >= slot_committees.len) {
            return error.CommitteeIndexOutOfBounds;
        }
        return slot_committees[index];
    }

    pub fn getCommitteeCountPerSlot(self: *const EpochCache, epoch: Epoch) !usize {
        if (self.getShufflingAtEpochOrNull(epoch)) |s| return s.committees_per_slot;

        return error.EpochShufflingNotFound;
    }

    pub fn computeSubnetForSlot(self: *const EpochCache, slot: Slot, committee_index: CommitteeIndex) !u8 {
        const slots_since_epoch_start = slot % preset.SLOTS_PER_EPOCH;
        const committees_per_slot = try self.getCommitteeCountPerSlot(computeEpochAtSlot(slot));
        const committees_since_epoch_start = committees_per_slot * slots_since_epoch_start;
        return @intCast((committees_since_epoch_start + committee_index) % c.ATTESTATION_SUBNET_COUNT);
    }

    pub fn getBeaconProposer(self: *const EpochCache, slot: Slot) !ValidatorIndex {
        const epoch = computeEpochAtSlot(slot);
        if (epoch != self.epoch) return error.NotCurrentEpoch;

        return self.proposers[slot % preset.SLOTS_PER_EPOCH];
    }

    // TODO: getBeaconProposers - can access directly?

    // TODO: getBeaconProposersNextEpoch - may not needed post-fulu

    // TODO: do we need getBeaconCommittees? in validateAttestationElectra we do a for loop over committee_indices and call getBeaconProposer() instead

    /// consumer takes ownership of the returned indexed attestation
    /// hence it needs to deinit attesting_indices inside
    pub fn computeIndexedAttestationPhase0(self: *const EpochCache, attestation: *const types.phase0.Attestation.Type, out: *types.phase0.IndexedAttestation.Type) !void {
        var attesting_indices_ = try self.getAttestingIndicesPhase0(attestation);
        const sort_fn = struct {
            pub fn sort(_: void, a: ValidatorIndex, b: ValidatorIndex) bool {
                return a < b;
            }
        }.sort;
        const attesting_indices = attesting_indices_.moveToUnmanaged();
        std.mem.sort(ValidatorIndex, attesting_indices.items, {}, sort_fn);

        out.attesting_indices = attesting_indices;
        out.data = attestation.data;
        out.signature = attestation.signature;
        out.* = .{
            .attesting_indices = attesting_indices,
            .data = attestation.data,
            .signature = attestation.signature,
        };
    }

    /// consumer takes ownership of the returned indexed attestation
    /// hence it needs to deinit attesting_indices inside
    pub fn computeIndexedAttestationElectra(self: *const EpochCache, attestation: *const types.electra.Attestation.Type, out: *types.electra.IndexedAttestation.Type) !void {
        var attesting_indices_ = try self.getAttestingIndicesElectra(attestation);
        const sort_fn = struct {
            pub fn sort(_: void, a: ValidatorIndex, b: ValidatorIndex) bool {
                return a < b;
            }
        }.sort;
        const attesting_indices = attesting_indices_.moveToUnmanaged();
        std.mem.sort(ValidatorIndex, attesting_indices.items, {}, sort_fn);

        out.attesting_indices = attesting_indices;
        out.data = attestation.data;
        out.signature = attestation.signature;
        out.* = .{
            .attesting_indices = attesting_indices,
            .data = attestation.data,
            .signature = attestation.signature,
        };
    }

    pub fn getAttestingIndices(self: *const EpochCache, attestation: Attestation) !std.ArrayList(ValidatorIndex) {
        return switch (attestation.*) {
            .phase0 => |phase0_attestation| self.getAttestingIndicesPhase0(&phase0_attestation),
            .electra => |electra_attestation| self.getAttestingIndicesElectra(&electra_attestation),
        };
    }

    /// Consumer takes ownership of the returned array
    pub fn getAttestingIndicesPhase0(self: *const EpochCache, attestation: *const types.phase0.Attestation.Type) !std.ArrayList(ValidatorIndex) {
        const aggregation_bits = attestation.aggregation_bits;
        const data = attestation.data;
        const validator_indices = try self.getBeaconCommittee(data.slot, data.index);
        return try aggregation_bits.intersectValues(ValidatorIndex, self.allocator, validator_indices);
    }

    /// consumer takes ownership of the returned array
    pub fn getAttestingIndicesElectra(self: *const EpochCache, attestation: *const types.electra.Attestation.Type) !std.ArrayList(ValidatorIndex) {
        const aggregation_bits = attestation.aggregation_bits;
        const committee_bits = attestation.committee_bits;
        const data = attestation.data;

        // There is a naming conflict on the term `committeeIndices`
        // In Lodestar it usually means a list of validator indices of participants in a committee
        // In the spec it means a list of committee indices according to committeeBits
        // This `committeeIndices` refers to the latter
        // TODO Electra: resolve the naming conflicts
        var committee_indices_buffer: [preset.MAX_COMMITTEES_PER_SLOT]usize = undefined;
        const committee_indices_len = try committee_bits.getTrueBitIndexes(committee_indices_buffer[0..]);
        const committee_indices = committee_indices_buffer[0..committee_indices_len];

        var total_len: usize = 0;
        for (committee_indices) |committee_index| {
            const committee = try self.getBeaconCommittee(data.slot, committee_index);
            total_len += committee.len;
        }

        var committee_validators = try self.allocator.alloc(ValidatorIndex, total_len);
        defer self.allocator.free(committee_validators);

        var offset: usize = 0;
        for (committee_indices) |committee_index| {
            const committee = try self.getBeaconCommittee(data.slot, committee_index);
            std.mem.copyForwards(ValidatorIndex, committee_validators[offset..(offset + committee.len)], committee);
            offset += committee.len;
        }

        return try aggregation_bits.intersectValues(ValidatorIndex, self.allocator, committee_validators);
    }

    // TODO: getCommitteeAssignments

    // TODO: getCommitteeAssignment

    pub fn isAggregator(self: *const EpochCache, slot: Slot, index: CommitteeIndex, slot_signature: BLSSignature) !bool {
        const committee = try self.getBeaconCommittee(slot, index);
        return isAggregatorFromCommitteeLength(committee.length, slot_signature);
    }

    pub fn getPubkey(self: *const EpochCache, index: ValidatorIndex) ?types.primitive.BLSPubkey {
        return if (index < self.index_to_pubkey.items.len) self.index_to_pubkey[index] else null;
    }

    pub fn getValidatorIndex(self: *const EpochCache, pubkey: *const types.primitive.BLSPubkey.Type) ?ValidatorIndex {
        return self.pubkey_to_index.get(pubkey[0..]);
    }

    /// Sets `index` at `PublicKey` within the index to pubkey map and allocates and puts a new `PublicKey` at `index` within the set of validators.
    pub fn addPubkey(self: *EpochCache, index: ValidatorIndex, pubkey: types.primitive.BLSPubkey.Type) !void {
        std.debug.assert(index <= self.index_to_pubkey.items.len);
        try self.pubkey_to_index.set(pubkey[0..], index);
        // this is deinit() by application
        const pk = try blst.PublicKey.uncompress(&pubkey);
        if (index == self.index_to_pubkey.items.len) {
            try self.index_to_pubkey.append(pk);
            return;
        }
        self.index_to_pubkey.items[index] = pk;
    }

    // TODO: getBeaconCommittee
    pub fn getShufflingAtSlotOrNull(self: *const EpochCache, slot: Slot) ?*const EpochShuffling {
        const epoch = computeEpochAtSlot(slot);
        return self.getShufflingAtEpochOrNull(epoch);
    }

    pub fn getShufflingAtEpochOrNull(self: *const EpochCache, epoch: Epoch) ?*const EpochShuffling {
        const previous_epoch = if (self.epoch == GENESIS_EPOCH) GENESIS_EPOCH else self.epoch - 1;
        const shuffling = if (epoch == previous_epoch)
            self.getPreviousShuffling()
        else if (epoch == self.epoch) self.getCurrentShuffling() else if (epoch == self.epoch + 1)
            self.getNextEpochShuffling()
        else
            null;

        return shuffling;
    }

    /// Note: The range of slots a validator has to perform duties is off by one.
    /// The previous slot wording means that if your validator is in a sync committee for a period that runs from slot
    /// 100 to 200,then you would actually produce signatures in slot 99 - 199.
    pub fn getIndexedSyncCommittee(self: *const EpochCache, slot: Slot) !SyncCommitteeCacheAllForks {
        // See note above for the +1 offset
        return self.getIndexedSyncCommitteeAtEpoch(computeEpochAtSlot(slot + 1));
    }

    pub fn getIndexedSyncCommitteeAtEpoch(self: *const EpochCache, epoch: Epoch) !SyncCommitteeCacheAllForks {
        const sync_period = computeSyncPeriodAtEpoch(epoch);
        switch (sync_period) {
            self.sync_period => return self.current_sync_committee_indexed.get(),
            self.sync_period + 1 => return self.next_sync_committee_indexed.get(),
            else => return error.SyncCommitteeNotFound,
        }
    }

    pub fn rotateSyncCommitteeIndexed(self: *EpochCache, allocator: Allocator, next_sync_committee_indices: []const ValidatorIndex) !void {
        // unref the old instance
        self.current_sync_committee_indexed.release();
        // this is the transfer of reference count
        // should not do an release() then acquire() here as it may trigger a deinit()
        self.current_sync_committee_indexed = self.next_sync_committee_indexed;
        const next_sync_committee_indexed = try SyncCommitteeCacheAllForks.initValidatorIndices(allocator, next_sync_committee_indices);
        self.next_sync_committee_indexed = try SyncCommitteeCacheRc.init(allocator, next_sync_committee_indexed);
    }

    // TODO: review the use of this function, use the rotateSyncCommitteeIndexed() instead
    // TODO: also increase reference count
    // pub fn setSyncCommitteesIndexed(self: *EpochCache, next_sync_committee_indices: std.ArrayList(ValidatorIndex)) !void {
    //     self.next_sync_committee_indexed = try SyncCommitteeCacheAllForks.initValidatorIndices(self.allocator, next_sync_committee_indices);
    //     self.current_sync_committee_indexed = self.next_sync_committee_indexed;
    // }

    /// This is different from typescript version: only allocate new EffectiveBalanceIncrements if needed
    pub fn effectiveBalanceIncrementsSet(self: *EpochCache, allocator: Allocator, index: usize, effective_balance: u64) !void {
        var effective_balance_increments = self.effective_balance_increment.get();
        if (index >= effective_balance_increments.items.len) {
            // Clone and extend effectiveBalanceIncrements
            effective_balance_increments = try getEffectiveBalanceIncrementsWithLen(self.allocator, index + 1);
            self.effective_balance_increment.release();
            self.effective_balance_increment = try EffectiveBalanceIncrementsRc.init(allocator, effective_balance_increments);
        }
        self.effective_balance_increment.get().items[index] = @intCast(@divFloor(effective_balance, preset.EFFECTIVE_BALANCE_INCREMENT));
    }

    pub fn isPostElectra(self: *const EpochCache) bool {
        return self.epoch >= self.config.chain.ELECTRA_FORK_EPOCH;
    }
};
