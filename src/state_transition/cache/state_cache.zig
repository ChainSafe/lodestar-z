const std = @import("std");
const types = @import("consensus_types");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const EpochCacheRc = @import("./epoch_cache.zig").EpochCacheRc;
const EpochCache = @import("./epoch_cache.zig").EpochCache;
const EpochCacheImmutableData = @import("./epoch_cache.zig").EpochCacheImmutableData;
const EpochCacheOpts = @import("./epoch_cache.zig").EpochCacheOpts;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const CloneOpts = @import("ssz").BaseTreeView.CloneOpts;
const Node = @import("persistent_merkle_tree").Node;

pub const ProposerRewards = struct {
    attestations: u64 = 0,
    sync_aggregate: u64 = 0,
    slashing: u64 = 0,
};

pub const CachedBeaconState = struct {
    allocator: Allocator,
    /// only a reference to the singleton BeaconConfig
    config: *const BeaconConfig,
    /// only a reference to the shared EpochCache instance
    /// TODO: before an epoch transition, need to release() epoch_cache before using a new one
    epoch_cache_ref: *EpochCacheRc,
    /// this takes ownership of the state, it is expected to be deinitialized by this struct
    state: *AnyBeaconState,
    /// Proposer rewards accumulated during block processing
    proposer_rewards: ProposerRewards,

    cloned_count: u32 = 0,
    cloned_count_with_transfer_cache: u32 = 0,
    created_with_transfer_cache: bool = false,

    /// This class takes ownership of state after this function and has responsibility to deinit it
    pub fn createCachedBeaconState(allocator: Allocator, state: *AnyBeaconState, immutable_data: EpochCacheImmutableData, option: ?EpochCacheOpts) !*CachedBeaconState {
        const cached_state = try allocator.create(CachedBeaconState);
        errdefer allocator.destroy(cached_state);

        try cached_state.init(allocator, state, immutable_data, option);

        return cached_state;
    }

    pub fn init(self: *CachedBeaconState, allocator: Allocator, state: *AnyBeaconState, immutable_data: EpochCacheImmutableData, option: ?EpochCacheOpts) !void {
        const epoch_cache = try EpochCache.createFromState(allocator, state, immutable_data, option);
        errdefer epoch_cache.deinit();
        const epoch_cache_ref = try EpochCacheRc.init(allocator, epoch_cache);
        errdefer epoch_cache_ref.release();
        self.* = .{
            .allocator = allocator,
            .config = immutable_data.config,
            .epoch_cache_ref = epoch_cache_ref,
            .state = state,
            .proposer_rewards = .{},
        };
    }

    // TODO: do we need another getConst()?
    pub fn getEpochCache(self: *const CachedBeaconState) *EpochCache {
        return self.epoch_cache_ref.get();
    }

    /// Get the proposer rewards for the state.
    pub fn getProposerRewards(self: *const CachedBeaconState) ProposerRewards {
        return self.proposer_rewards;
    }

    pub fn clone(self: *CachedBeaconState, allocator: Allocator, opts: CloneOpts) !*CachedBeaconState {
        const cached_state = try allocator.create(CachedBeaconState);
        errdefer allocator.destroy(cached_state);
        const epoch_cache_ref = self.epoch_cache_ref.acquire();
        errdefer epoch_cache_ref.release();

        const state = try allocator.create(AnyBeaconState);
        errdefer allocator.destroy(state);
        state.* = try self.state.clone(opts);

        cached_state.* = .{
            .allocator = allocator,
            .config = self.config,
            .epoch_cache_ref = epoch_cache_ref,
            .state = state,
            .proposer_rewards = self.proposer_rewards,
            .created_with_transfer_cache = opts.transfer_cache,
        };

        self.cloned_count += 1;
        if (opts.transfer_cache) {
            self.cloned_count_with_transfer_cache += 1;
        }

        return cached_state;
    }

    pub fn deinit(self: *CachedBeaconState) void {
        // should not deinit config since we don't take ownership of it, it's singleton across applications
        self.epoch_cache_ref.release();
        self.state.deinit();
        self.allocator.destroy(self.state);
    }

    // TODO: implement loadCachedBeaconState
    // this is used when we load a state from disc, given a seed state
    // need to do this once we switch to TreeView

    // TODO: implement getCachedBeaconState
    // this is used to create a CachedBeaconState based on a tree and an exising CachedBeaconState at fork transition
    // implement this once we switch to TreeView

    /// Gets the beacon proposer index for a given slot.
    /// For the Fulu fork, this uses `proposer_lookahead` from the state.
    /// For earlier forks, this uses `EpochCache.getBeaconProposer()`.
    pub fn getBeaconProposer(self: *const CachedBeaconState, slot: types.primitive.Slot.Type) !ValidatorIndex {
        const preset_import = @import("preset").preset;
        const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;

        // For Fulu, use proposer_lookahead from state
        if (self.state.forkSeq().gte(.fulu)) {
            const current_epoch = computeEpochAtSlot(try self.state.slot());
            const slot_epoch = computeEpochAtSlot(slot);

            // proposer_lookahead covers current_epoch through current_epoch + MIN_SEED_LOOKAHEAD
            const lookahead_start_epoch = current_epoch;
            const lookahead_end_epoch = current_epoch + preset_import.MIN_SEED_LOOKAHEAD;

            if (slot_epoch < lookahead_start_epoch or slot_epoch > lookahead_end_epoch) {
                return error.SlotOutsideProposerLookahead;
            }

            var proposer_lookahead = try self.state.proposerLookahead();
            const epoch_offset = slot_epoch - lookahead_start_epoch;
            const slot_in_epoch = slot % preset_import.SLOTS_PER_EPOCH;
            const index = epoch_offset * preset_import.SLOTS_PER_EPOCH + slot_in_epoch;

            return try proposer_lookahead.get(index);
        }
        return self.getEpochCache().getBeaconProposer(slot);
    }

    /// Get the previous decision root for the state from the epoch cache.
    pub fn previousDecisionRoot(self: *CachedBeaconState) [32]u8 {
        return self.getEpochCache().previous_decision_root;
    }

    /// Get the current decision root for the state from the epoch cache.
    pub fn currentDecisionRoot(self: *CachedBeaconState) [32]u8 {
        return self.getEpochCache().current_decision_root;
    }

    /// Get the next decision root for the state from the epoch cache.
    pub fn nextDecisionRoot(self: *CachedBeaconState) [32]u8 {
        return self.getEpochCache().next_decision_root;
    }
};

test "CachedBeaconState.clone()" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();
    // test clone() api works fine with no memory leak
    const cloned_cached_state = try test_state.cached_state.clone(allocator, .{});
    defer {
        cloned_cached_state.deinit();
        allocator.destroy(cloned_cached_state);
    }
}
