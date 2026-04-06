//! genesis_util: helpers for loading or generating a genesis BeaconState.
//!
//! Two entry points:
//!   - createMinimalGenesis: generate a synthetic genesis state for testing (--network minimal)
//!   - loadGenesisFromFile: deserialize a real genesis SSZ file (--checkpoint-state)

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const deserializePublishedState = state_transition.deserializePublishedState;
const SharedValidatorPubkeys = state_transition.SharedValidatorPubkeys;
const EpochCacheImmutableData = state_transition.EpochCacheImmutableData;
const generateElectraState = state_transition.test_utils.generateElectraState;
const StateTransitionMetrics = state_transition.metrics.StateTransitionMetrics;

const Node = @import("persistent_merkle_tree").Node;
const BeaconConfig = @import("config").BeaconConfig;

/// Generate a synthetic genesis state with `validator_count` validators.
///
/// Uses TestCachedBeaconState (electra, active-preset chain config) for a
/// quick in-memory genesis suitable for `--network minimal` development runs.
///
/// The returned CachedBeaconState is heap-allocated; call `.deinit()` then
/// `allocator.destroy()` when done (but in practice a running node never
/// frees its genesis state).
///
/// NOTE: the TestCachedBeaconState wrapper and its subsidiary heap objects
/// (BeaconConfig copy, pubkey caches, epoch_transition_cache) are intentionally
/// not freed — they are referenced by the returned CachedBeaconState and must
/// remain alive for the lifetime of the node.
pub fn createMinimalGenesis(
    allocator: Allocator,
    pool: *Node.Pool,
    config: *const BeaconConfig,
    shared_pubkeys: *SharedValidatorPubkeys,
    validator_count: usize,
    st_metrics: *StateTransitionMetrics,
) !*CachedBeaconState {
    const state = try generateElectraState(allocator, pool, config.chain, validator_count);
    errdefer {
        state.deinit();
        allocator.destroy(state);
    }

    const validators = try state.validatorsSlice(allocator);
    defer allocator.free(validators);
    try shared_pubkeys.syncFromValidators(validators);

    return CachedBeaconState.createCachedBeaconState(
        allocator,
        state,
        st_metrics,
        EpochCacheImmutableData{
            .config = config,
            .pubkey_to_index = &shared_pubkeys.pubkey_to_index,
            .index_to_pubkey = &shared_pubkeys.index_to_pubkey,
        },
        .{
            .skip_sync_committee_cache = state.forkSeq() == .phase0,
            .skip_sync_pubkeys = true,
        },
    );
}

/// Load and deserialize a genesis / checkpoint state from an SSZ file.
///
/// Opens the file via `io` (so it works with both real and simulated I/O),
/// reads the raw bytes, then calls `deserializeState` to build a fully-
/// initialised CachedBeaconState.
///
/// Caller owns the returned pointer: call `.deinit()` then
/// `allocator.destroy()` when done.
pub fn loadGenesisFromFile(
    allocator: Allocator,
    pool: *Node.Pool,
    config: *const BeaconConfig,
    shared_pubkeys: *SharedValidatorPubkeys,
    io: Io,
    path: []const u8,
    st_metrics: *StateTransitionMetrics,
) !*CachedBeaconState {
    // Open the file.
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    // Get file size.
    const stat = try file.stat(io);
    const size = stat.size;
    if (size == 0) return error.EmptyStateFile;

    // Allocate a buffer and read the entire file.
    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    const n = try file.readPositionalAll(io, buf, 0);
    if (n != size) return error.ShortRead;

    // Deserialize into a CachedBeaconState.
    return deserializePublishedState(allocator, pool, config, shared_pubkeys, buf, st_metrics);
}
