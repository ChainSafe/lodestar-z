const std = @import("std");
const bls = @import("bls");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const mainnet_chain_config = @import("config").mainnet.chain_config;
const minimal_chain_config = @import("config").minimal.chain_config;
const types = @import("consensus_types");
const hex = @import("hex");
const Epoch = types.primitive.Epoch.Type;
const ElectraBeaconState = types.electra.BeaconState.Type;
const BLSPubkey = types.primitive.BLSPubkey.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const preset = @import("preset").preset;
const active_preset = @import("preset").active_preset;
const BeaconConfig = @import("config").BeaconConfig;
const ChainConfig = @import("config").ChainConfig;
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("../root.zig");
const CachedBeaconState = state_transition.CachedBeaconState;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const PubkeyIndexMap = state_transition.PubkeyIndexMap;
const Index2PubkeyCache = state_transition.Index2PubkeyCache;
const EffectiveBalanceIncrements = state_transition.EffectiveBalanceIncrements;
const getNextSyncCommitteeIndices = state_transition.getNextSyncCommitteeIndices;
const syncPubkeys = state_transition.syncPubkeys;
const interopPubkeysCached = @import("./interop_pubkeys.zig").interopPubkeysCached;
const EFFECTIVE_BALANCE_INCREMENT = 32;
const EFFECTIVE_BALANCE = 32 * 1e9;
const active_chain_config = if (active_preset == .mainnet) mainnet_chain_config else minimal_chain_config;

/// The SSZ BeaconState type for `fork`.
fn beaconStateSsz(comptime fork: ForkSeq) type {
    return switch (fork) {
        .phase0 => types.phase0.BeaconState,
        .altair => types.altair.BeaconState,
        .bellatrix => types.bellatrix.BeaconState,
        .capella => types.capella.BeaconState,
        .deneb => types.deneb.BeaconState,
        .electra => types.electra.BeaconState,
        .fulu => types.fulu.BeaconState,
        .gloas => types.gloas.BeaconState,
    };
}

/// `fork`'s activation epoch in `config`.
fn forkActivationEpoch(config: ChainConfig, comptime fork: ForkSeq) Epoch {
    return switch (fork) {
        .phase0 => 0,
        .altair => config.ALTAIR_FORK_EPOCH,
        .bellatrix => config.BELLATRIX_FORK_EPOCH,
        .capella => config.CAPELLA_FORK_EPOCH,
        .deneb => config.DENEB_FORK_EPOCH,
        .electra => config.ELECTRA_FORK_EPOCH,
        .fulu => config.FULU_FORK_EPOCH,
        .gloas => config.GLOAS_FORK_EPOCH,
    };
}

/// Generate + allocate a BeaconState of `fork`; the consumer deinits and destroys it. Fork-generic
/// port of TS `generateState` — common fields for all forks, then the altair+ additions
/// (participation, inactivity scores, sync committees) under a comptime fork guard.
pub fn generateState(comptime fork: ForkSeq, allocator: Allocator, pool: *Node.Pool, chain_config: ChainConfig, validator_count: usize) !*AnyBeaconState {
    const StateSsz = beaconStateSsz(fork);

    const beacon_state = try allocator.create(AnyBeaconState);
    errdefer allocator.destroy(beacon_state);

    const fork_state = try allocator.create(StateSsz.Type);
    defer {
        StateSsz.deinit(allocator, fork_state);
        allocator.destroy(fork_state);
    }
    fork_state.* = StateSsz.default_value;
    fork_state.genesis_time = 1596546008;
    fork_state.genesis_validators_root = try hex.hexToRoot("0x8a8b3f1f1e2d3c4b5a697887766554433221100ffeeddccbbaa9988776655443");
    const activation_epoch = forkActivationEpoch(chain_config, fork);
    // set the slot to be ready for the next epoch transition
    fork_state.slot = activation_epoch * preset.SLOTS_PER_EPOCH + 2025 * preset.SLOTS_PER_EPOCH - 1;
    const current_epoch = @divFloor(fork_state.slot, preset.SLOTS_PER_EPOCH);
    var version: [4]u8 = undefined;
    _ = try hex.hexToBytes(&version, "0x00000001");
    fork_state.fork = .{
        .previous_version = version,
        .current_version = version,
        .epoch = activation_epoch,
    };
    fork_state.latest_block_header = .{
        .slot = fork_state.slot - 1,
        .proposer_index = 80882,
        .parent_root = try hex.hexToRoot("0x5b83c3078e474b86af60043eda82a34c3c2e5ebf83146b14d9d909aea4163ef2"),
        .state_root = try hex.hexToRoot("0x2761ae355e8a53c11e0e37d5e417f8984db0c53fa83f1bc65f89c6af35a196a7"),
        .body_root = try hex.hexToRoot("0x249a1962eef90e122fa2447040bfac102798b1dba9c73e5593bc5aa32eb92bfd"),
    };
    fork_state.block_roots = [_][32]u8{[_]u8{1} ** 32} ** preset.SLOTS_PER_HISTORICAL_ROOT;
    fork_state.state_roots = [_][32]u8{[_]u8{2} ** 32} ** preset.SLOTS_PER_HISTORICAL_ROOT;

    const pubkeys = try allocator.alloc(BLSPubkey, validator_count);
    defer allocator.free(pubkeys);
    try interopPubkeysCached(validator_count, pubkeys);

    for (0..validator_count) |i| {
        const validator = types.phase0.Validator.Type{
            .pubkey = pubkeys[i],
            .withdrawal_credentials = [_]u8{0} ** 32,
            .effective_balance = EFFECTIVE_BALANCE,
            .slashed = false,
            .activation_eligibility_epoch = 0,
            .activation_epoch = 0,
            .exit_epoch = 0xFFFFFFFFFFFFFFFF,
            .withdrawable_epoch = 0xFFFFFFFFFFFFFFFF,
        };
        try fork_state.validators.append(allocator, validator);
        try fork_state.balances.append(allocator, EFFECTIVE_BALANCE);
        if (comptime fork.gte(.altair)) {
            try fork_state.inactivity_scores.append(allocator, 0);
            try fork_state.previous_epoch_participation.append(allocator, 0b11111111);
            try fork_state.current_epoch_participation.append(allocator, 0b11111111);
        }
    }

    fork_state.eth1_data = .{
        .deposit_root = try hex.hexToRoot("0xcb1f89a924cfd31224823db5a41b1643f10faa7aedf231f1e28887f6ee98c047"),
        .deposit_count = pubkeys.len,
        .block_hash = try hex.hexToRoot("0x701fb2869ce16d0f1d14f6705725adb0dec6799da29006dfc6fff83960298f21"),
    };

    // no need to populate eth1_data_votes
    fork_state.eth1_deposit_index = pubkeys.len;
    // enable this will cause some tests failed
    // fork_state.randao_mixes = [_][32]u8{[_]u8{4} ** 32} ** preset.EPOCHS_PER_HISTORICAL_VECTOR;
    // no need to populate slashings
    // finality
    fork_state.justification_bits = types.phase0.JustificationBits.default_value;
    for (0..4) |i| {
        try fork_state.justification_bits.set(i, true);
    }
    fork_state.previous_justified_checkpoint = .{
        .epoch = current_epoch - 2,
        .root = try hex.hexToRoot("0x3fe60bf06a57b0956cd1f8181d26649cf8bf79e48bf82f55562e04b33d4785d4"),
    };
    fork_state.current_justified_checkpoint = .{
        .epoch = current_epoch - 1,
        .root = try hex.hexToRoot("0x3ba0913d2fb5e4cbcfb0d39eb15803157c1e769d63b8619285d8fdabbd8181c7"),
    };
    fork_state.finalized_checkpoint = .{
        .epoch = current_epoch - 3,
        .root = try hex.hexToRoot("0x122b8ff579d0c8f8a8b66326bdfec3f685007d2842f01615a0768870961ccc17"),
    };

    beacon_state.* = try AnyBeaconState.fromValue(allocator, pool, fork, fork_state);
    errdefer beacon_state.deinit();

    // Sync committees exist altair+. Same logic as processSyncCommitteeUpdates.
    if (comptime fork.gte(.altair)) {
        var active_validator_indices = try std.ArrayList(ValidatorIndex).initCapacity(allocator, validator_count);
        defer active_validator_indices.deinit(allocator);
        var effective_balance_increments = try EffectiveBalanceIncrements.initCapacity(allocator, validator_count);
        defer effective_balance_increments.deinit(allocator);
        for (0..validator_count) |i| {
            try active_validator_indices.append(allocator, @intCast(i));
            try effective_balance_increments.append(allocator, EFFECTIVE_BALANCE_INCREMENT);
        }

        var next_sync_committee_indices: [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex = undefined;
        try getNextSyncCommitteeIndices(
            fork,
            allocator,
            beacon_state.castToFork(fork),
            active_validator_indices.items,
            effective_balance_increments,
            &next_sync_committee_indices,
        );

        var next_sync_committee_pubkeys: [preset.SYNC_COMMITTEE_SIZE]BLSPubkey = undefined;
        var next_sync_committee_pubkeys_slices: [preset.SYNC_COMMITTEE_SIZE]bls.PublicKey = undefined;
        var validators = try beacon_state.validators();
        for (next_sync_committee_indices, 0..next_sync_committee_indices.len) |index, i| {
            var validator = try validators.get(@intCast(index));
            // Validator is now a StructContainerType — `get("pubkey")` returns the
            // value directly (a `[48]u8` array), not a child TreeView.
            next_sync_committee_pubkeys[i] = try validator.get("pubkey");
            next_sync_committee_pubkeys_slices[i] = try bls.PublicKey.uncompress(&next_sync_committee_pubkeys[i]);
        }

        var current_sync_committee = try beacon_state.currentSyncCommittee();
        var next_sync_committee = try beacon_state.nextSyncCommittee();
        // Rotate syncCommittee in state
        const aggregate_pubkey = (try bls.AggregatePublicKey.aggregate(&next_sync_committee_pubkeys_slices, false)).toPublicKey().compress();
        try next_sync_committee.setValue("pubkeys", &next_sync_committee_pubkeys);
        try next_sync_committee.setValue("aggregate_pubkey", &aggregate_pubkey);

        // initialize current sync committee to be the same as next sync committee
        try current_sync_committee.setValue("pubkeys", &next_sync_committee_pubkeys);
        try current_sync_committee.setValue("aggregate_pubkey", &aggregate_pubkey);
    }

    try beacon_state.commit();

    return beacon_state;
}

/// Electra-fork convenience wrapper over `generateState`.
pub fn generateElectraState(allocator: Allocator, pool: *Node.Pool, chain_config: ChainConfig, validator_count: usize) !*AnyBeaconState {
    return generateState(.electra, allocator, pool, chain_config, validator_count);
}

pub const TestCachedBeaconState = struct {
    allocator: Allocator,
    pool: *Node.Pool,
    config: *BeaconConfig,
    pubkey_index_map: *PubkeyIndexMap,
    index_pubkey_cache: *Index2PubkeyCache,
    cached_state: *CachedBeaconState,
    epoch_transition_cache: *state_transition.EpochTransitionCache,

    pub const Options = struct {
        /// The fork of the generated state. Mirrors TS `generateState(opts, getConfig(fork, ...))`.
        fork: ForkSeq = .electra,
        /// `fork`'s activation epoch; null keeps the active chain config's. 0 activates `fork` (and
        /// all priors) at genesis so low-slot persisted states resolve as `fork`.
        fork_epoch: ?Epoch = null,
    };

    pub fn init(allocator: Allocator, pool: *Node.Pool, validator_count: usize, options: Options) !TestCachedBeaconState {
        return switch (options.fork) {
            inline else => |f| initForFork(f, allocator, pool, validator_count, options.fork_epoch),
        };
    }

    fn initForFork(comptime fork: ForkSeq, allocator: Allocator, pool: *Node.Pool, validator_count: usize, fork_epoch_opt: ?Epoch) !TestCachedBeaconState {
        const fork_epoch = fork_epoch_opt orelse forkActivationEpoch(active_chain_config, fork);
        const chain_config = getConfig(active_chain_config, fork, fork_epoch);
        var state = try generateState(fork, allocator, pool, chain_config, validator_count);
        errdefer {
            state.deinit();
            allocator.destroy(state);
        }

        return initFromState(allocator, pool, state, fork, fork_epoch);
    }

    pub fn initFromState(allocator: Allocator, pool: *Node.Pool, state: *AnyBeaconState, fork: ForkSeq, fork_epoch: Epoch) !TestCachedBeaconState {
        const pubkey_index_map = try allocator.create(PubkeyIndexMap);
        pubkey_index_map.* = PubkeyIndexMap.init(allocator);
        errdefer {
            pubkey_index_map.deinit();
            allocator.destroy(pubkey_index_map);
        }
        const index_pubkey_cache = try allocator.create(Index2PubkeyCache);
        errdefer allocator.destroy(index_pubkey_cache);
        index_pubkey_cache.* = Index2PubkeyCache.empty;
        errdefer index_pubkey_cache.deinit(allocator);
        const chain_config = getConfig(active_chain_config, fork, fork_epoch);
        const config = try allocator.create(BeaconConfig);
        errdefer allocator.destroy(config);
        config.* = BeaconConfig.init(chain_config, (try state.genesisValidatorsRoot()).*);

        const validators = try state.validatorsPtrSlice(allocator);
        defer allocator.free(validators);

        try syncPubkeys(allocator, validators, pubkey_index_map, index_pubkey_cache);

        const immutable_data = state_transition.EpochCacheImmutableData{
            .config = config,
            .index_to_pubkey = index_pubkey_cache,
            .pubkey_to_index = pubkey_index_map,
        };
        // cached_state takes ownership of state and will deinit there
        const cached_state = try CachedBeaconState.createCachedBeaconState(allocator, state, immutable_data, .{
            .skip_sync_committee_cache = state.forkSeq() == .phase0,
            .skip_sync_pubkeys = false,
        });

        const epoch_transition_cache = try allocator.create(state_transition.EpochTransitionCache);
        errdefer allocator.destroy(epoch_transition_cache);
        epoch_transition_cache.* = try state_transition.EpochTransitionCache.init(
            allocator,
            std.testing.io,
            cached_state.config,
            cached_state.epoch_cache,
            cached_state.state,
        );

        return TestCachedBeaconState{
            .allocator = allocator,
            .pool = pool,
            .config = config,
            .pubkey_index_map = pubkey_index_map,
            .index_pubkey_cache = index_pubkey_cache,
            .cached_state = cached_state,
            .epoch_transition_cache = epoch_transition_cache,
        };
    }

    pub fn deinit(self: *TestCachedBeaconState) void {
        self.cached_state.deinit();
        self.allocator.destroy(self.cached_state);
        self.pubkey_index_map.deinit();
        self.allocator.destroy(self.pubkey_index_map);
        self.index_pubkey_cache.deinit(self.allocator);
        self.epoch_transition_cache.deinit(self.allocator);
        @import("../state_transition.zig").deinitReusedEpochTransitionCache(std.testing.io);
        self.allocator.destroy(self.epoch_transition_cache);
        self.allocator.destroy(self.index_pubkey_cache);
        self.allocator.destroy(self.config);
    }
};

/// get a ChainConfig for spec test, refer to https://github.com/ChainSafe/lodestar/blob/v1.35.0/packages/beacon-node/test/utils/config.ts#L9
pub fn getConfig(config: ChainConfig, fork: ForkSeq, fork_epoch: Epoch) ChainConfig {
    switch (fork) {
        .phase0 => return config,
        .altair => return config.merge(.{
            .ALTAIR_FORK_EPOCH = fork_epoch,
        }),
        .bellatrix => return config.merge(.{
            .ALTAIR_FORK_EPOCH = 0,
            .BELLATRIX_FORK_EPOCH = fork_epoch,
        }),
        .capella => return config.merge(.{
            .ALTAIR_FORK_EPOCH = 0,
            .BELLATRIX_FORK_EPOCH = 0,
            .CAPELLA_FORK_EPOCH = fork_epoch,
        }),
        .deneb => return config.merge(.{
            .ALTAIR_FORK_EPOCH = 0,
            .BELLATRIX_FORK_EPOCH = 0,
            .CAPELLA_FORK_EPOCH = 0,
            .DENEB_FORK_EPOCH = fork_epoch,
        }),
        .electra => return config.merge(.{
            .ALTAIR_FORK_EPOCH = 0,
            .BELLATRIX_FORK_EPOCH = 0,
            .CAPELLA_FORK_EPOCH = 0,
            .DENEB_FORK_EPOCH = 0,
            .ELECTRA_FORK_EPOCH = fork_epoch,
        }),
        .fulu => return config.merge(.{
            .ALTAIR_FORK_EPOCH = 0,
            .BELLATRIX_FORK_EPOCH = 0,
            .CAPELLA_FORK_EPOCH = 0,
            .DENEB_FORK_EPOCH = 0,
            .ELECTRA_FORK_EPOCH = 0,
            .FULU_FORK_EPOCH = fork_epoch,
        }),
        .gloas => return config.merge(.{
            .ALTAIR_FORK_EPOCH = 0,
            .BELLATRIX_FORK_EPOCH = 0,
            .CAPELLA_FORK_EPOCH = 0,
            .DENEB_FORK_EPOCH = 0,
            .ELECTRA_FORK_EPOCH = 0,
            .FULU_FORK_EPOCH = 0,
            .GLOAS_FORK_EPOCH = fork_epoch,
        }),
    }
}

test TestCachedBeaconState {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256, .{});
    defer test_state.deinit();
}
