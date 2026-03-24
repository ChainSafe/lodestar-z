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
    allocator: std.mem.Allocator,

    /// Optional block import callback. Nil until wired by BeaconNode.init.
    block_import: ?BlockImportCallback = null,
};
