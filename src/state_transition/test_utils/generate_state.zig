const std = @import("std");
const blst = @import("blst");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const mainnet_chain_config = @import("config").mainnet.chain_config;
const minimal_chain_config = @import("config").minimal.chain_config;
const types = @import("consensus_types");
const hex = @import("hex");
const Epoch = types.primitive.Epoch.Type;
const ElectraBeaconState = types.electra.BeaconState.Type;
const Validator = types.phase0.Validator.Type;
const BLSPubkey = types.primitive.BLSPubkey.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const preset = @import("preset").preset;
const active_preset = @import("preset").active_preset;
const BeaconConfig = @import("config").BeaconConfig;
const ChainConfig = @import("config").ChainConfig;
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("../root.zig");
const CachedBeaconState = state_transition.CachedBeaconState;
const BeaconState = state_transition.BeaconState;
const PubkeyIndexMap = state_transition.PubkeyIndexMap(ValidatorIndex);
const Index2PubkeyCache = state_transition.Index2PubkeyCache;
const EffectiveBalanceIncrements = state_transition.EffectiveBalanceIncrements;
const getNextSyncCommitteeIndices = state_transition.getNextSyncCommitteeIndices;
const syncPubkeys = state_transition.syncPubkeys;
const interopPubkeysCached = @import("./interop_pubkeys.zig").interopPubkeysCached;
const EFFECTIVE_BALANCE_INCREMENT = 32;
const EFFECTIVE_BALANCE = 32 * 1e9;
const active_chain_config = if (active_preset == .mainnet) mainnet_chain_config else minimal_chain_config;

/// generate, allocate BeaconState
/// consumer has responsibility to deinit it
pub fn generateElectraState(allocator: Allocator, pool: *Node.Pool, chain_config: ChainConfig, validator_count: usize) !BeaconState {
    const electra_state = try allocator.create(ElectraBeaconState);
    defer {
        types.electra.BeaconState.deinit(allocator, electra_state);
        allocator.destroy(electra_state);
    }
    electra_state.* = types.electra.BeaconState.default_value;
    electra_state.genesis_time = 1596546008;
    electra_state.genesis_validators_root = try hex.hexToRoot("0x8a8b3f1f1e2d3c4b5a697887766554433221100ffeeddccbbaa9988776655443");
    // set the slot to be ready for the next epoch transition
    electra_state.slot = chain_config.ELECTRA_FORK_EPOCH * preset.SLOTS_PER_EPOCH + 2025 * preset.SLOTS_PER_EPOCH - 1;
    const current_epoch = @divFloor(electra_state.slot, preset.SLOTS_PER_EPOCH);
    var version: [4]u8 = undefined;
    _ = try hex.hexToBytes(&version, "0x00000001");
    electra_state.fork = .{
        .previous_version = version,
        .current_version = version,
        .epoch = chain_config.ELECTRA_FORK_EPOCH,
    };
    electra_state.latest_block_header = .{
        .slot = electra_state.slot - 1,
        .proposer_index = 80882,
        .parent_root = try hex.hexToRoot("0x5b83c3078e474b86af60043eda82a34c3c2e5ebf83146b14d9d909aea4163ef2"),
        .state_root = try hex.hexToRoot("0x2761ae355e8a53c11e0e37d5e417f8984db0c53fa83f1bc65f89c6af35a196a7"),
        .body_root = try hex.hexToRoot("0x249a1962eef90e122fa2447040bfac102798b1dba9c73e5593bc5aa32eb92bfd"),
    };
    electra_state.block_roots = [_][32]u8{[_]u8{1} ** 32} ** preset.SLOTS_PER_HISTORICAL_ROOT;
    electra_state.state_roots = [_][32]u8{[_]u8{2} ** 32} ** preset.SLOTS_PER_HISTORICAL_ROOT;

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
        try electra_state.validators.append(allocator, validator);
        try electra_state.balances.append(allocator, EFFECTIVE_BALANCE);
        try electra_state.inactivity_scores.append(allocator, 0);
        try electra_state.previous_epoch_participation.append(allocator, 0b11111111);
        try electra_state.current_epoch_participation.append(allocator, 0b11111111);
    }

    electra_state.eth1_data = .{
        .deposit_root = try hex.hexToRoot("0xcb1f89a924cfd31224823db5a41b1643f10faa7aedf231f1e28887f6ee98c047"),
        .deposit_count = pubkeys.len,
        .block_hash = try hex.hexToRoot("0x701fb2869ce16d0f1d14f6705725adb0dec6799da29006dfc6fff83960298f21"),
    };

    // populate sync committee
    var active_validator_indices = try std.ArrayList(ValidatorIndex).initCapacity(allocator, validator_count);
    defer active_validator_indices.deinit();
    var effective_balance_increments = try EffectiveBalanceIncrements.initCapacity(allocator, validator_count);
    defer effective_balance_increments.deinit();
    for (0..validator_count) |i| {
        try active_validator_indices.append(@intCast(i));
        try effective_balance_increments.append(EFFECTIVE_BALANCE_INCREMENT);
    }

    // no need to populate eth1_data_votes
    electra_state.eth1_deposit_index = pubkeys.len;
    // enable this will cause some tests failed
    // electra_state.randao_mixes = [_][32]u8{[_]u8{4} ** 32} ** preset.EPOCHS_PER_HISTORICAL_VECTOR;
    // no need to populate slashings
    // finality
    electra_state.justification_bits = types.phase0.JustificationBits.default_value;
    for (0..4) |i| {
        try electra_state.justification_bits.set(i, true);
    }
    electra_state.previous_justified_checkpoint = .{
        .epoch = current_epoch - 2,
        .root = try hex.hexToRoot("0x3fe60bf06a57b0956cd1f8181d26649cf8bf79e48bf82f55562e04b33d4785d4"),
    };
    electra_state.current_justified_checkpoint = .{
        .epoch = current_epoch - 1,
        .root = try hex.hexToRoot("0x3ba0913d2fb5e4cbcfb0d39eb15803157c1e769d63b8619285d8fdabbd8181c7"),
    };
    electra_state.finalized_checkpoint = .{
        .epoch = current_epoch - 3,
        .root = try hex.hexToRoot("0x122b8ff579d0c8f8a8b66326bdfec3f685007d2842f01615a0768870961ccc17"),
    };

    // the same logic to processSyncCommitteeUpdates
    var beacon_state = try BeaconState.fromValue(allocator, pool, .electra, electra_state);
    errdefer beacon_state.deinit();

    var next_sync_committee_indices: [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex = undefined;
    try getNextSyncCommitteeIndices(allocator, &beacon_state, active_validator_indices.items, effective_balance_increments, &next_sync_committee_indices);

    var next_sync_committee_pubkeys: [preset.SYNC_COMMITTEE_SIZE]BLSPubkey = undefined;
    var next_sync_committee_pubkeys_slices: [preset.SYNC_COMMITTEE_SIZE]blst.PublicKey = undefined;
    var validators = try beacon_state.validators();
    for (next_sync_committee_indices, 0..next_sync_committee_indices.len) |index, i| {
        var validator = try validators.get(@intCast(index));
        var pubkey_view = try validator.get("pubkey");
        _ = try pubkey_view.getAllInto(next_sync_committee_pubkeys[i][0..]);
        next_sync_committee_pubkeys_slices[i] = try blst.PublicKey.uncompress(&next_sync_committee_pubkeys[i]);
    }

    var current_sync_committee = try beacon_state.currentSyncCommittee();
    var next_sync_committee = try beacon_state.nextSyncCommittee();
    // Rotate syncCommittee in state
    const aggregate_pubkey = (try blst.AggregatePublicKey.aggregate(&next_sync_committee_pubkeys_slices, false)).toPublicKey().compress();
    try next_sync_committee.setValue("pubkeys", &next_sync_committee_pubkeys);
    try next_sync_committee.setValue("aggregate_pubkey", &aggregate_pubkey);

    // initialize current sync committee to be the same as next sync committee
    try current_sync_committee.setValue("pubkeys", &next_sync_committee_pubkeys);
    try current_sync_committee.setValue("aggregate_pubkey", &aggregate_pubkey);

    try beacon_state.commit();

    return beacon_state;
}

pub const TestCachedBeaconState = struct {
    allocator: Allocator,
    config: *BeaconConfig,
    pubkey_index_map: *PubkeyIndexMap,
    index_pubkey_cache: *Index2PubkeyCache,
    cached_state: *CachedBeaconState,

    pub fn init(allocator: Allocator, pool: *Node.Pool, validator_count: usize) !TestCachedBeaconState {
        var state = try generateElectraState(allocator, pool, active_chain_config, validator_count);
        errdefer state.deinit();

        const fork_view = try state.fork();
        const fork_epoch = try fork_view.get("epoch");
        return initFromState(allocator, state, ForkSeq.electra, fork_epoch);
    }

    pub fn initFromState(allocator: Allocator, state: BeaconState, fork: ForkSeq, fork_epoch: Epoch) !TestCachedBeaconState {
        const pubkey_index_map = try PubkeyIndexMap.init(allocator);
        errdefer pubkey_index_map.deinit();
        const index_pubkey_cache = try allocator.create(Index2PubkeyCache);
        errdefer {
            index_pubkey_cache.deinit();
            allocator.destroy(index_pubkey_cache);
        }
        index_pubkey_cache.* = Index2PubkeyCache.init(allocator);
        const chain_config = getConfig(active_chain_config, fork, fork_epoch);
        const config = try allocator.create(BeaconConfig);
        errdefer allocator.destroy(config);
        config.* = BeaconConfig.init(chain_config, (try state.genesisValidatorsRoot()).*);

        const validators = try state.validatorsSlice(allocator);
        defer allocator.free(validators);

        try syncPubkeys(validators, pubkey_index_map, index_pubkey_cache);

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

        return TestCachedBeaconState{
            .allocator = allocator,
            .config = config,
            .pubkey_index_map = pubkey_index_map,
            .index_pubkey_cache = index_pubkey_cache,
            .cached_state = cached_state,
        };
    }

    pub fn deinit(self: *TestCachedBeaconState) void {
        self.cached_state.deinit();
        self.allocator.destroy(self.cached_state);
        self.pubkey_index_map.deinit();
        self.index_pubkey_cache.deinit();
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
    }
}

test TestCachedBeaconState {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();
}
