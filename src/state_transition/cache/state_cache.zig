const std = @import("std");
const ct = @import("consensus_types");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const TestCachedBeaconStateAllForks = @import("../test_utils/root.zig").TestCachedBeaconStateAllForks;
const EpochCacheRc = @import("./epoch_cache.zig").EpochCacheRc;
const EpochCache = @import("./epoch_cache.zig").EpochCache;
const EpochCacheImmutableData = @import("./epoch_cache.zig").EpochCacheImmutableData;
const EpochCacheOpts = @import("./epoch_cache.zig").EpochCacheOpts;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;
const PubkeyIndexMap = @import("pubkey_cache.zig").PubkeyIndexMap(ValidatorIndex);
const Index2PubkeyCache = @import("pubkey_cache.zig").Index2PubkeyCache;

pub const CachedBeaconStateAllForks = struct {
    allocator: Allocator,
    /// only a reference to the singleton BeaconConfig
    config: *const BeaconConfig,
    /// only a reference to the shared EpochCache instance
    /// TODO: before an epoch transition, need to release() epoch_cache before using a new one
    epoch_cache_ref: *EpochCacheRc,
    /// this takes ownership of the state, it is expected to be deinitialized by this struct
    state: *BeaconStateAllForks,

    // TODO: cloned_count properties, implement this once we switch to TreeView
    // TODO: proposer_rewards, looks like this is not a great place to put in, it's a result of a block state transition instead

    /// This class takes ownership of state after this function and has responsibility to deinit it
    pub fn createCachedBeaconState(allocator: Allocator, state: *BeaconStateAllForks, immutable_data: EpochCacheImmutableData, option: ?EpochCacheOpts) !*CachedBeaconStateAllForks {
        const epoch_cache = try EpochCache.createFromState(allocator, state, immutable_data, option);
        errdefer epoch_cache.deinit();
        const epoch_cache_ref = try EpochCacheRc.init(allocator, epoch_cache);
        errdefer epoch_cache_ref.release();
        const cached_state = try allocator.create(CachedBeaconStateAllForks);
        errdefer allocator.destroy(cached_state);
        cached_state.* = .{
            .allocator = allocator,
            .config = immutable_data.config,
            .epoch_cache_ref = epoch_cache_ref,
            .state = state,
        };

        return cached_state;
    }

    // TODO: do we need another getConst()?
    pub fn getEpochCache(self: *const CachedBeaconStateAllForks) *EpochCache {
        return self.epoch_cache_ref.get();
    }

    pub fn clone(self: *CachedBeaconStateAllForks, allocator: Allocator) !*CachedBeaconStateAllForks {
        const cached_state = try allocator.create(CachedBeaconStateAllForks);
        errdefer allocator.destroy(cached_state);
        const epoch_cache_ref = self.epoch_cache_ref.acquire();
        errdefer epoch_cache_ref.release();

        cached_state.* = .{
            .allocator = allocator,
            .config = self.config,
            .epoch_cache_ref = epoch_cache_ref,
            .state = try self.state.clone(allocator),
        };
        return cached_state;
    }

    pub fn deinit(self: *CachedBeaconStateAllForks) void {
        // should not deinit config since we don't take ownership of it, it's singleton across applications
        self.epoch_cache_ref.release();
        self.state.deinit(self.allocator);
        self.allocator.destroy(self.state);
    }

    // TODO: implement loadCachedBeaconState
    // this is used when we load a state from disc, given a seed state
    // need to do this once we switch to TreeView

    // TODO: implement getCachedBeaconState
    // this is used to create a CachedBeaconStateAllForks based on a tree and an exising CachedBeaconStateAllForks at fork transition
    // implement this once we switch to TreeView
};

test "CachedBeaconStateAllForks.clone()" {
    const allocator = std.testing.allocator;
    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    defer test_state.deinit();
    // test clone() api works fine with no memory leak
    const cloned_cached_state = try test_state.cached_state.clone(allocator);
    defer {
        cloned_cached_state.deinit();
        allocator.destroy(cloned_cached_state);
    }
}
