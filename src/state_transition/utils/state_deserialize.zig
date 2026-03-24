//! state_deserialize: deserialize a beacon state from raw SSZ bytes.
//!
//! Used by the cold path in StateRegen and checkpoint sync to reconstruct a
//! CachedBeaconState from bytes stored in the BeaconDB.
//!
//! For the hot path (sharing tree nodes with a seed state) see load_cached_state.zig.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bls = @import("bls");
const BeaconConfig = @import("config").BeaconConfig;
const Node = @import("persistent_merkle_tree").Node;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const readSlotFromAnyBeaconStateBytes = @import("fork_types").readSlotFromAnyBeaconStateBytes;

const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochCacheImmutableData = @import("../cache/epoch_cache.zig").EpochCacheImmutableData;
const EpochCacheOpts = @import("../cache/epoch_cache.zig").EpochCacheOpts;
const PubkeyIndexMap = @import("../cache/pubkey_cache.zig").PubkeyIndexMap;
const Index2PubkeyCache = @import("../cache/pubkey_cache.zig").Index2PubkeyCache;
const syncPubkeys = @import("../cache/pubkey_cache.zig").syncPubkeys;

/// Deserialize raw SSZ bytes into a fully-initialized CachedBeaconState.
///
/// This is the cold-path entry point: no seed state is available, so tree
/// nodes are not shared and pubkey caches are built from scratch.
///
/// Caller must call `deinit()` then `allocator.destroy()` on the returned
/// pointer when done.
///
/// @param allocator  Memory allocator.
/// @param pool       Persistent Merkle tree node pool (shared across states).
/// @param config     Beacon chain config (not owned; must outlive the returned state).
/// @param ssz_bytes  Raw SSZ-serialized BeaconState bytes.
/// @return           A heap-allocated, fully-initialized CachedBeaconState.
pub fn deserializeState(
    allocator: Allocator,
    pool: *Node.Pool,
    config: *const BeaconConfig,
    ssz_bytes: []const u8,
) !*CachedBeaconState {
    // 1. Detect fork from the slot field embedded in the SSZ bytes.
    //    Slot is at byte offset 40 (after genesis_time: u64 and genesis_validators_root: bytes32).
    if (ssz_bytes.len < 48) return error.StateBytesTooShort;
    const slot = readSlotFromAnyBeaconStateBytes(ssz_bytes);
    const fork_seq = config.forkSeq(slot);

    // 2. Deserialize into AnyBeaconState.
    var any_state = try AnyBeaconState.deserialize(allocator, pool, fork_seq, ssz_bytes);
    errdefer any_state.deinit();

    // Move onto the heap so CachedBeaconState can take ownership.
    const state_ptr = try allocator.create(AnyBeaconState);
    errdefer allocator.destroy(state_ptr);
    state_ptr.* = any_state;

    // 3. Build pubkey caches from the deserialized validators list.
    //    syncPubkeys expects both caches to be consistent (same length) and empty
    //    at the start, so we initialise them with len=0.
    const pubkey_to_index = try allocator.create(PubkeyIndexMap);
    errdefer allocator.destroy(pubkey_to_index);
    pubkey_to_index.* = PubkeyIndexMap.init(allocator);
    errdefer pubkey_to_index.deinit();

    const index_to_pubkey = try allocator.create(Index2PubkeyCache);
    errdefer allocator.destroy(index_to_pubkey);
    index_to_pubkey.* = Index2PubkeyCache.init(allocator);
    errdefer index_to_pubkey.deinit();

    // Extract validators as a plain slice (caller owns; freed below).
    const validators = try state_ptr.validatorsSlice(allocator);
    defer allocator.free(validators);

    // BLS uncompress + map building — the expensive part on cold path.
    try syncPubkeys(validators, pubkey_to_index, index_to_pubkey);

    // 4. Assemble EpochCacheImmutableData and create CachedBeaconState.
    //    EpochCache.createFromState takes ownership of pubkey_to_index / index_to_pubkey
    //    through EpochCacheImmutableData (they are referenced, not owned by immutable_data).
    const immutable_data = EpochCacheImmutableData{
        .config = config,
        .pubkey_to_index = pubkey_to_index,
        .index_to_pubkey = index_to_pubkey,
    };

    const opts = EpochCacheOpts{
        // Phase0 has no sync committees.
        .skip_sync_committee_cache = fork_seq == .phase0,
        // We already populated the caches above via syncPubkeys.
        .skip_sync_pubkeys = true,
    };

    // createCachedBeaconState takes ownership of state_ptr.
    // On success the state's memory is managed by CachedBeaconState.deinit().
    const cached_state = try CachedBeaconState.createCachedBeaconState(
        allocator,
        state_ptr,
        immutable_data,
        opts,
    );

    return cached_state;
}
