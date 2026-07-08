const std = @import("std");
const types = @import("consensus_types");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const EpochCache = @import("./epoch_cache.zig").EpochCache;
const EpochCacheImmutableData = @import("./epoch_cache.zig").EpochCacheImmutableData;
const EpochCacheOpts = @import("./epoch_cache.zig").EpochCacheOpts;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const PubkeyIndexMap = @import("pubkey_cache.zig").PubkeyIndexMap(ValidatorIndex);
const Index2PubkeyCache = @import("pubkey_cache.zig").Index2PubkeyCache;
const CloneOpts = @import("ssz").CloneOpts;
const SlashingsCache = @import("./slashings_cache.zig").SlashingsCache;
const Node = @import("persistent_merkle_tree").Node;
const loadState = @import("../load_state.zig").loadState;
const getBlockRootAtSlotFn = @import("../utils/block_root.zig").getBlockRootAtSlot;

pub const ProposerRewards = struct {
    attestations: u64 = 0,
    sync_aggregate: u64 = 0,
    slashing: u64 = 0,
};

pub const CachedBeaconState = struct {
    allocator: Allocator,
    /// only a reference to the singleton BeaconConfig
    config: *const BeaconConfig,
    /// Owns an independent EpochCache (shallow clone). Inner Rc elements are shared.
    epoch_cache: *EpochCache,
    slashings_cache: SlashingsCache,
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
        self.* = .{
            .allocator = allocator,
            .config = immutable_data.config,
            .epoch_cache = epoch_cache,
            .slashings_cache = try SlashingsCache.initEmpty(allocator),
            .state = state,
            .proposer_rewards = .{},
        };
    }

    /// Get the proposer rewards for the state.
    pub fn getProposerRewards(self: *const CachedBeaconState) ProposerRewards {
        return self.proposer_rewards;
    }

    pub fn clone(self: *CachedBeaconState, allocator: Allocator, opts: CloneOpts) !*CachedBeaconState {
        const cached_state = try allocator.create(CachedBeaconState);
        errdefer allocator.destroy(cached_state);
        const cloned_epoch_cache = try self.epoch_cache.clone(allocator);
        errdefer cloned_epoch_cache.deinit();

        var slashings_cache = try self.slashings_cache.clone(allocator);
        errdefer slashings_cache.deinit();

        const state = try allocator.create(AnyBeaconState);
        errdefer allocator.destroy(state);
        state.* = try self.state.clone(opts);

        cached_state.* = .{
            .allocator = allocator,
            .config = self.config,
            .epoch_cache = cloned_epoch_cache,
            .slashings_cache = slashings_cache,
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

    pub const LoadOtherStateOpts = struct {
        /// Warm the validator and balance views' navigation caches so a state consumed immediately
        /// afterward doesn't pay the lazy per-access cost — both are read/written per-element during
        /// block replay (validators via epoch updates, balances via increase/decreaseBalance).
        preload_validators_and_balances: bool = false,
    };

    /// Reload `state_bytes` against this state into a new `*CachedBeaconState`, reusing this state's
    /// node pool and the SHARED pubkey maps (seed-diff: unchanged validator/inactivity subtrees are
    /// reused, not re-deserialized). `seed_validators_bytes` (pre-serialized validators) lets the diff
    /// skip re-serializing; null serializes internally. Caller owns the result.
    pub fn loadOtherState(self: *CachedBeaconState, allocator: Allocator, config: *const BeaconConfig, state_bytes: []const u8, seed_validators_bytes: ?[]const u8, opts: LoadOtherStateOpts) !*CachedBeaconState {
        // Seed-diff reload: reuse the seed's unchanged validator/inactivity-score subtrees instead of
        // a full re-deserialize, saving the ~500ms re-hash of those large lists on each disk fault-in.
        const migrate = try loadState(allocator, config, self.state, state_bytes, seed_validators_bytes);
        // `modified_validators` is owned regardless of later failures and unused here; free it first.
        allocator.free(migrate.modified_validators);

        // Own the loaded state by-value until it is moved onto the heap below; `null` once moved.
        var loaded_state: ?AnyBeaconState = migrate.state;
        errdefer if (loaded_state) |*s| s.deinit();

        // Move the loaded state onto the heap; own the slot + contents until `createCachedBeaconState`
        // takes them — `null` once transferred, then `destroyState` reclaims it.
        const any_state = try allocator.create(AnyBeaconState);
        any_state.* = loaded_state.?;
        loaded_state = null;
        var heap_state: ?*AnyBeaconState = any_state;
        errdefer if (heap_state) |s| {
            s.deinit();
            allocator.destroy(s);
        };

        const fork = any_state.forkSeq();

        const immutable = EpochCacheImmutableData{
            .config = config,
            .pubkey_to_index = self.epoch_cache.pubkey_to_index,
            .index_to_pubkey = self.epoch_cache.index_to_pubkey,
        };

        const new_cached = try createCachedBeaconState(allocator, any_state, immutable, .{
            .skip_sync_committee_cache = fork == .phase0,
            // The pubkey maps borrowed above are shared and already populated, so syncing the loaded
            // state's validators into them would just redundantly re-scan all of them.
            .skip_sync_pubkeys = true,
        });
        heap_state = null;
        errdefer {
            new_cached.deinit();
            allocator.destroy(new_cached);
        }

        if (opts.preload_validators_and_balances) {
            const validators_view = try new_cached.state.validators();
            try validators_view.prefetchAll();

            const balances_view = try new_cached.state.balances();
            try balances_view.prefetchAll();
        }

        return new_cached;
    }

    pub fn deinit(self: *CachedBeaconState) void {
        // should not deinit config since we don't take ownership of it, it's singleton across applications
        self.epoch_cache.deinit();
        self.slashings_cache.deinit();
        self.state.deinit();
        self.allocator.destroy(self.state);
    }

    pub fn isSlashed(self: *const CachedBeaconState, index: ValidatorIndex) bool {
        return self.slashings_cache.isSlashed(index);
    }

    pub fn recordValidatorSlashing(self: *CachedBeaconState, block_slot: types.primitive.Slot.Type, index: ValidatorIndex) !void {
        try self.slashings_cache.recordValidatorSlashing(block_slot, index);
    }

    pub fn updateSlashingsCacheLatestBlockSlot(self: *CachedBeaconState) !void {
        var latest_block_header = try self.state.latestBlockHeader();
        const latest_block_slot = try latest_block_header.get("slot");
        self.slashings_cache.updateLatestBlockSlot(latest_block_slot);
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
        return self.epoch_cache.getBeaconProposer(slot);
    }

    /// Get the block root at `slot` regardless of fork. The underlying `getBlockRootAtSlot` is
    /// fork-comptime, so dispatch on the runtime tag once here rather than scattering the switch
    /// across callers. Propagates SlotTooBig/SlotTooSmall.
    pub fn getBlockRootAtSlot(self: *CachedBeaconState, slot: types.primitive.Slot.Type) !*const [32]u8 {
        return switch (self.state.forkSeq()) {
            inline else => |f| getBlockRootAtSlotFn(f, self.state.castToFork(f), slot),
        };
    }

    /// Get the previous decision root for the state from the epoch cache.
    pub fn previousDecisionRoot(self: *CachedBeaconState) [32]u8 {
        return self.epoch_cache.previous_decision_root;
    }

    /// Get the current decision root for the state from the epoch cache.
    pub fn currentDecisionRoot(self: *CachedBeaconState) [32]u8 {
        return self.epoch_cache.current_decision_root;
    }

    /// Get the next decision root for the state from the epoch cache.
    pub fn nextDecisionRoot(self: *CachedBeaconState) [32]u8 {
        return self.epoch_cache.next_decision_root;
    }
};

test "CachedBeaconState.clone()" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256, .{});
    defer test_state.deinit();
    // test clone() api works fine with no memory leak
    const cloned_cached_state = try test_state.cached_state.clone(allocator, .{});
    defer {
        cloned_cached_state.deinit();
        allocator.destroy(cloned_cached_state);
    }
}

test "CachedBeaconState.clone() epoch cache isolation" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256, .{});
    defer test_state.deinit();

    const original = test_state.cached_state;
    const cloned = try original.clone(allocator, .{});
    defer {
        cloned.deinit();
        allocator.destroy(cloned);
    }

    // Capture original values
    const orig_exit_queue_churn = original.epoch_cache.exit_queue_churn;
    const orig_total_slashings = original.epoch_cache.total_slashings_by_increment;
    const orig_current_target = original.epoch_cache.current_target_unslashed_balance_increments;

    // Mutate the clone's epoch cache
    cloned.epoch_cache.exit_queue_churn += 99;
    cloned.epoch_cache.total_slashings_by_increment += 42;
    cloned.epoch_cache.current_target_unslashed_balance_increments += 7;

    // Assert the original is unaffected
    try std.testing.expectEqual(orig_exit_queue_churn, original.epoch_cache.exit_queue_churn);
    try std.testing.expectEqual(orig_total_slashings, original.epoch_cache.total_slashings_by_increment);
    try std.testing.expectEqual(orig_current_target, original.epoch_cache.current_target_unslashed_balance_increments);
}
