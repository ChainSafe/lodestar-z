//! state_deserialize: deserialize a beacon state from raw SSZ bytes.
//!
//! Used by the cold path in StateRegen and checkpoint sync to reconstruct a
//! CachedBeaconState from bytes stored in the BeaconDB.
//!
//! For the hot path (sharing tree nodes with a seed state) see load_cached_state.zig.
const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const Node = @import("persistent_merkle_tree").Node;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const readSlotFromAnyBeaconStateBytes = @import("fork_types").readSlotFromAnyBeaconStateBytes;

const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochCacheImmutableData = @import("../cache/epoch_cache.zig").EpochCacheImmutableData;
const EpochCacheOpts = @import("../cache/epoch_cache.zig").EpochCacheOpts;
const SharedValidatorPubkeys = @import("../cache/shared_pubkeys.zig").SharedValidatorPubkeys;

fn createCachedStateWithPubkeys(
    allocator: Allocator,
    pool: *Node.Pool,
    config: *const BeaconConfig,
    shared_pubkeys: *SharedValidatorPubkeys,
    ssz_bytes: []const u8,
    sync_shared_pubkeys: bool,
) !*CachedBeaconState {
    // 1. Detect fork from the slot field embedded in the SSZ bytes.
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

    // 3. Ensure the application-owned validator pubkey cache is ready.
    const validators = try state_ptr.validatorsSlice(allocator);
    defer allocator.free(validators);
    if (sync_shared_pubkeys) {
        try shared_pubkeys.syncFromValidators(validators);
    } else if (validators.len > shared_pubkeys.index_to_pubkey.items.len) {
        return error.SharedPubkeyCacheTooSmall;
    }

    const immutable_data: EpochCacheImmutableData = shared_pubkeys.immutableData(config);

    const opts = EpochCacheOpts{
        .skip_sync_committee_cache = fork_seq == .phase0,
        .skip_sync_pubkeys = true,
    };

    return CachedBeaconState.createCachedBeaconState(
        allocator,
        state_ptr,
        immutable_data,
        opts,
    );
}

/// Deserialize raw SSZ bytes into a fully-initialized CachedBeaconState.
///
/// This path borrows the already-owned application pubkey cache and assumes it
/// is already large enough for the loaded state.
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
    shared_pubkeys: *SharedValidatorPubkeys,
    ssz_bytes: []const u8,
) !*CachedBeaconState {
    return createCachedStateWithPubkeys(
        allocator,
        pool,
        config,
        shared_pubkeys,
        ssz_bytes,
        false,
    );
}

/// Bootstrap a published state from external bytes and seed the application
/// pubkey cache from that state exactly once.
pub fn deserializePublishedState(
    allocator: Allocator,
    pool: *Node.Pool,
    config: *const BeaconConfig,
    shared_pubkeys: *SharedValidatorPubkeys,
    ssz_bytes: []const u8,
) !*CachedBeaconState {
    return createCachedStateWithPubkeys(
        allocator,
        pool,
        config,
        shared_pubkeys,
        ssz_bytes,
        true,
    );
}
