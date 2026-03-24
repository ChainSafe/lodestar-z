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
const deserializeState = state_transition.deserializeState;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

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
    validator_count: usize,
) !*CachedBeaconState {
    // TestCachedBeaconState.init creates a fully-initialised CachedBeaconState
    // with pubkey caches and epoch cache populated.
    var test_state = try TestCachedBeaconState.init(allocator, pool, validator_count);

    // Extract the CachedBeaconState pointer.  We intentionally do NOT call
    // test_state.deinit() so that the heap objects it owns (BeaconConfig,
    // pubkey caches) remain alive and accessible through the CachedBeaconState.
    return test_state.cached_state;
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
    io: Io,
    path: []const u8,
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
    return deserializeState(allocator, pool, config, buf);
}
