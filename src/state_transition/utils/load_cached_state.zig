const std = @import("std");
const Allocator = std.mem.Allocator;
const bls = @import("bls");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const Node = @import("persistent_merkle_tree").Node;
const ct = @import("consensus_types");
const AnyBeaconState = @import("fork_types").AnyBeaconState;

const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochCacheImmutableData = @import("../cache/epoch_cache.zig").EpochCacheImmutableData;
const EpochCacheOpts = @import("../cache/epoch_cache.zig").EpochCacheOpts;
const PubkeyIndexMap = @import("../cache/pubkey_cache.zig").PubkeyIndexMap;
const Index2PubkeyCache = @import("../cache/pubkey_cache.zig").Index2PubkeyCache;

const load_state_mod = @import("load_state.zig");
pub const loadState = load_state_mod.loadState;
pub const findModifiedItems = load_state_mod.findModifiedItems;
pub const VALIDATOR_BYTES_SIZE = load_state_mod.VALIDATOR_BYTES_SIZE;
pub const INACTIVITY_SCORE_SIZE = load_state_mod.INACTIVITY_SCORE_SIZE;

/// Load a CachedBeaconState from SSZ bytes, sharing unchanged tree nodes with a seed CachedBeaconState.
///
/// This is the key optimization that turns a ~43s cold deserialization into ~1-2s by:
/// 1. Sharing unchanged validator tree nodes with the seed state
/// 2. Reusing the seed's pubkey cache (only updating entries for modified validators)
/// 3. Sharing unchanged inactivity_scores tree nodes (altair+)
///
/// @param allocator Memory allocator
/// @param pool Persistent Merkle tree node pool
/// @param seed_cached_state The seed CachedBeaconState to share tree nodes with
/// @param fork_seq The fork of the new state
/// @param state_bytes The SSZ-serialized new state bytes
/// @param seed_validators_bytes Optional pre-serialized seed validator bytes (optimization to avoid re-serializing)
/// @return A new CachedBeaconState that shares tree nodes with the seed
pub fn loadCachedBeaconState(
    allocator: Allocator,
    pool: *Node.Pool,
    seed_cached_state: *CachedBeaconState,
    fork_seq: ForkSeq,
    state_bytes: []const u8,
    seed_validators_bytes: ?[]const u8,
) !*CachedBeaconState {
    // 1. Load the state tree, sharing unchanged nodes with seed
    const result = try loadState(
        allocator,
        pool,
        seed_cached_state.state,
        fork_seq,
        state_bytes,
        seed_validators_bytes,
    );
    const modified_validators = result.modified_validators;
    defer allocator.free(modified_validators);

    // Allocate state on heap (CachedBeaconState takes ownership)
    const state_ptr = try allocator.create(AnyBeaconState);
    errdefer {
        var s = result.state;
        s.deinit();
        allocator.destroy(state_ptr);
    }
    state_ptr.* = result.state;

    // 2. Update pubkey caches for modified validators
    const pubkey_to_index = seed_cached_state.epoch_cache.pubkey_to_index;
    const index_to_pubkey = seed_cached_state.epoch_cache.index_to_pubkey;

    // Ensure index_to_pubkey has capacity for new validators
    const new_validator_count = try state_ptr.validatorsCount();
    if (new_validator_count > index_to_pubkey.items.len) {
        try index_to_pubkey.resize(new_validator_count);
    }
    try pubkey_to_index.ensureTotalCapacity(@intCast(new_validator_count));

    // Update only modified validators' pubkeys
    var validators_view = try state_ptr.validators();
    for (modified_validators) |idx| {
        // Use getValue to extract the validator without creating a cached TreeView
        var validator: ct.phase0.Validator.Type = undefined;
        try validators_view.getValue(allocator, idx, &validator);

        const pubkey = &validator.pubkey;
        pubkey_to_index.putAssumeCapacity(pubkey.*, @intCast(idx));
        index_to_pubkey.items[idx] = try bls.PublicKey.uncompress(pubkey);
    }

    // 3. Create CachedBeaconState with skip_sync_pubkeys: true
    const immutable_data = EpochCacheImmutableData{
        .config = seed_cached_state.config,
        .pubkey_to_index = pubkey_to_index,
        .index_to_pubkey = index_to_pubkey,
    };

    const cached_state = try CachedBeaconState.createCachedBeaconState(
        allocator,
        state_ptr,
        immutable_data,
        .{ .skip_sync_pubkeys = true, .skip_sync_committee_cache = false },
    );

    return cached_state;
}
