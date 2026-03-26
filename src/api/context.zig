//! API context — the shared state that route handlers need.
//!
//! Each dependency is behind a pointer so the context struct stays small
//! and copyable. Components that don't exist yet use opaque stub types
//! with placeholder interfaces; they'll be swapped for real implementations
//! once the corresponding modules land.

const std = @import("std");
const types = @import("types.zig");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const state_transition = @import("state_transition");
pub const CachedBeaconState = state_transition.CachedBeaconState;

// ---------------------------------------------------------------------------
// Stub types for components not yet implemented
// ---------------------------------------------------------------------------

/// Tracks the chain head (slot, root, state root).
pub const HeadTracker = struct {
    head_slot: u64,
    head_root: [32]u8,
    head_state_root: [32]u8,

    finalized_slot: u64,
    finalized_root: [32]u8,

    justified_slot: u64,
    justified_root: [32]u8,
};

/// Sync status tracker.
pub const SyncStatus = struct {
    head_slot: u64,
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
    el_offline: bool,
};

/// Stub for state regeneration. In the full implementation this would
/// load or replay state to a requested slot/root.
pub const StateRegen = struct {
    /// Placeholder — returns null until real state regen is implemented.
    pub fn getStateAtSlot(_: *StateRegen, _: u64) ?*anyopaque {
        return null;
    }
};

// ---------------------------------------------------------------------------
// Block import callback
// ---------------------------------------------------------------------------

/// Callback for importing a signed beacon block from the API layer.
/// The ptr field holds a type-erased pointer to the concrete importer;
/// importFn receives raw SSZ bytes of the block and returns void or an error.
pub const BlockImportCallback = struct {
    ptr: *anyopaque,
    importFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,
};

// ---------------------------------------------------------------------------
// Head state callback
// ---------------------------------------------------------------------------

/// Callback for accessing the current head CachedBeaconState.
/// Uses a type-erased pointer so BeaconNode can wire itself in
/// without exposing internal state to all API handlers directly.
pub const HeadStateCallback = struct {
    ptr: *anyopaque,
    /// Returns the current head CachedBeaconState, or null if unavailable.
    getHeadStateFn: *const fn (ptr: *anyopaque) ?*CachedBeaconState,
};

// ---------------------------------------------------------------------------
// Peer DB callback — type-erased access to the networking PeerDB
// ---------------------------------------------------------------------------

/// Info about a single peer, returned from the peer DB callback.
/// Matches the shape needed by the `/eth/v1/node/peers` response.
pub const PeerEntry = struct {
    peer_id: []const u8,
    state: types.PeerState,
    direction: types.PeerDirection,
    agent: ?[]const u8,
};

/// Aggregate peer counts by connection state.
pub const PeerCounts = struct {
    connected: u64,
    disconnected: u64,
    connecting: u64,
    disconnecting: u64,
};

/// Type-erased callback for accessing the PeerDB.
/// BeaconNode wires this so the API can query peers without importing networking.
pub const PeerDBCallback = struct {
    ptr: *anyopaque,
    /// Returns the list of connected peers. Caller owns the returned slice.
    getConnectedPeersFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]PeerEntry,
    /// Returns aggregate peer counts.
    getPeerCountsFn: *const fn (ptr: *anyopaque) PeerCounts,
};

// ---------------------------------------------------------------------------
// Operation pool callback — type-erased access to the op pools
// ---------------------------------------------------------------------------

/// Type-erased callback for querying operation pools.
pub const OpPoolCallback = struct {
    ptr: *anyopaque,
    /// Returns the number of items in each pool: [attestation_groups, voluntary_exits, proposer_slashings, attester_slashings, bls_changes].
    getPoolCountsFn: *const fn (ptr: *anyopaque) [5]usize,
};

// ---------------------------------------------------------------------------
// ApiContext
// ---------------------------------------------------------------------------

pub const ApiContext = struct {
    /// Chain head tracking.
    head_tracker: *HeadTracker,

    /// State access (for state queries).
    regen: *StateRegen,

    /// Block / state database.
    db: *BeaconDB,

    /// This node's identity on the P2P network.
    node_identity: types.NodeIdentity,

    /// Current sync status.
    sync_status: *SyncStatus,

    /// Beacon chain configuration.
    beacon_config: *const BeaconConfig,

    /// Allocator for dynamic responses.

    /// Event bus for SSE beacon chain events.
    event_bus: ?*@import("event_bus.zig").EventBus = null,
    allocator: std.mem.Allocator,

    /// Optional block import callback. Nil until wired by BeaconNode.init.
    block_import: ?BlockImportCallback = null,

    /// Optional head state callback. Nil until wired by BeaconNode.init.
    head_state: ?HeadStateCallback = null,

    /// Optional peer DB callback. Nil until wired by BeaconNode.init.
    peer_db: ?PeerDBCallback = null,

    /// Optional operation pool callback. Nil until wired by BeaconNode.init.
    op_pool: ?OpPoolCallback = null,
};
