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
///
/// C-api-root: BeaconNode writes to this via a raw pointer; fields must stay
/// in sync with the initialization in src/node/beacon_node.zig (initFromGenesis /
/// initFromCheckpoint). Current layout verified 2026-03-28.
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
///
/// C-api-root: These fields MUST stay in sync with `beacon_node.SyncStatus`
/// (src/node/beacon_node.zig). BeaconNode writes to this struct via a raw
/// pointer — field name or type mismatches are silent ABI breakage.
/// Verified identical as of 2026-03-28: head_slot, sync_distance, is_syncing,
/// is_optimistic, el_offline.
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

/// Callback for accessing state regeneration from the API layer.
pub const StateRegenCallback = struct {
    ptr: *anyopaque,
    getStateByRootFn: *const fn (ptr: *anyopaque, state_root: [32]u8) ?*CachedBeaconState,
    getPreStateFn: ?*const fn (ptr: *anyopaque, parent_root: [32]u8, block_slot: u64) ?*CachedBeaconState,

    pub fn getStateByRoot(self: *const StateRegenCallback, state_root: [32]u8) ?*CachedBeaconState {
        return self.getStateByRootFn(self.ptr, state_root);
    }
    pub fn getPreState(self: *const StateRegenCallback, parent_root: [32]u8, block_slot: u64) ?*CachedBeaconState {
        if (self.getPreStateFn) |f| return f(self.ptr, parent_root, block_slot);
        return null;
    }
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
// Pool submission callback
// ---------------------------------------------------------------------------

/// Type-erased callback for submitting items to operation pools.
pub const PoolSubmitCallback = struct {
    ptr: *anyopaque,
    /// Submit attestations (raw JSON bytes, array of SingleAttestation or Attestation).
    submitAttestationFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit a signed voluntary exit (raw JSON bytes).
    submitVoluntaryExitFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit a proposer slashing (raw JSON bytes).
    submitProposerSlashingFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit an attester slashing (raw JSON bytes).
    submitAttesterSlashingFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit signed BLS-to-execution changes (raw JSON bytes, array).
    submitBlsChangeFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit sync committee messages (raw JSON bytes, array).
    submitSyncCommitteeMessageFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit aggregate and proofs (raw JSON bytes, array).
    submitAggregateAndProofFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
    /// Submit contribution and proofs (raw JSON bytes, array).
    submitContributionAndProofFn: ?*const fn (ptr: *anyopaque, json_bytes: []const u8) anyerror!void = null,
};

// ---------------------------------------------------------------------------
// Produce block callback
// ---------------------------------------------------------------------------

/// Parameters for block production.
pub const ProduceBlockParams = struct {
    slot: u64,
    randao_reveal: [96]u8,
    graffiti: ?[32]u8 = null,
};

/// Result of block production (minimal, for API response).
pub const ProducedBlockData = struct {
    /// Raw SSZ bytes of the produced BeaconBlock (unsigned).
    ssz_bytes: []const u8,
    /// Fork name for the produced block (e.g. "electra").
    fork: []const u8,
};

/// Callback for producing blocks (GET /eth/v1/validator/blocks/{slot}).
pub const ProduceBlockCallback = struct {
    ptr: *anyopaque,
    /// Produce a block for the given slot. Caller owns returned ssz_bytes.
    produceBlockFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, params: ProduceBlockParams) anyerror!ProducedBlockData,
};

// ---------------------------------------------------------------------------
// Attestation data callback
// ---------------------------------------------------------------------------

/// Result of attestation data query.
pub const AttestationDataResult = struct {
    slot: u64,
    index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
    target_epoch: u64,
    target_root: [32]u8,
};

/// Callback for getting attestation data (GET /eth/v1/validator/attestation_data).
pub const AttestationDataCallback = struct {
    ptr: *anyopaque,
    getAttestationDataFn: *const fn (ptr: *anyopaque, slot: u64, committee_index: u64) anyerror!AttestationDataResult,
};

// ---------------------------------------------------------------------------
// Aggregate attestation callback
// ---------------------------------------------------------------------------

/// Callback for getting best aggregate attestation from pool.
pub const AggregateAttestationCallback = struct {
    ptr: *anyopaque,
    /// Returns raw JSON bytes of the best aggregate attestation. Caller owns.
    getAggregateAttestationFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, slot: u64, attestation_data_root: [32]u8) anyerror![]const u8,
};

// ---------------------------------------------------------------------------
// Sync committee contribution callback
// ---------------------------------------------------------------------------

/// Callback for getting sync committee contribution.
pub const SyncCommitteeContributionCallback = struct {
    ptr: *anyopaque,
    /// Returns raw JSON bytes of the contribution. Caller owns.
    getSyncCommitteeContributionFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, slot: u64, subcommittee_index: u64, beacon_block_root: [32]u8) anyerror![]const u8,
};
/// Validator key info for listing.
pub const ValidatorKeyInfo = struct {
    pubkey: [48]u8,
    derivation_path: []const u8,
    readonly: bool,
};

/// Remote signer key info.
pub const RemoteKeyInfo = struct {
    pubkey: [48]u8,
    url: []const u8,
    readonly: bool,
};

/// Result of a key delete operation.
pub const KeymanagerCallback = struct {
    ptr: *anyopaque,
    /// Validate bearer token — returns error.Unauthorized if invalid.
    validateTokenFn: *const fn (ptr: *anyopaque, auth_header: ?[]const u8) anyerror!void,
    /// List all local validator keys. Caller owns result + slice.
    listKeysFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]ValidatorKeyInfo,
    /// Import a keystore JSON string with password. Returns status string ("imported"/"duplicate"/"error").
    importKeyFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, keystore_json: []const u8, password: []const u8, slashing_protection: ?[]const u8) anyerror![]const u8,
    /// Delete a key by pubkey. Returns status ("deleted"/"not_found"/"error") + slashing protection JSON.
    deleteKeyFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror!DeleteKeyResult,
    /// List remote signer keys. Caller owns result + slice.
    listRemoteKeysFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]RemoteKeyInfo,
    /// Import a remote key. Returns status string ("imported"/"duplicate"/"error").
    importRemoteKeyFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8, url: []const u8) anyerror![]const u8,
    /// Delete a remote key. Returns status string ("deleted"/"not_found"/"error").
    deleteRemoteKeyFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror![]const u8,
};

/// Result of a key delete operation.
pub const DeleteKeyResult = struct {
    /// "deleted", "not_found", or "error"
    status: []const u8,
    /// EIP-3076 interchange JSON for the deleted key (empty if not_found).
    slashing_protection: []const u8,
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

    /// Optional pool submission callback. Nil until wired by BeaconNode.init.
    pool_submit: ?PoolSubmitCallback = null,

    /// Optional block production callback. Nil until wired by BeaconNode.init.
    produce_block: ?ProduceBlockCallback = null,

    /// Optional attestation data callback. Nil until wired by BeaconNode.init.
    attestation_data: ?AttestationDataCallback = null,

    /// Optional aggregate attestation callback. Nil until wired by BeaconNode.init.
    aggregate_attestation: ?AggregateAttestationCallback = null,

    /// Optional sync committee contribution callback. Nil until wired by BeaconNode.init.
    sync_committee_contribution: ?SyncCommitteeContributionCallback = null,
    /// Optional state regen callback.
    state_regen_callback: ?StateRegenCallback = null,
    /// Optional keymanager callback.
    keymanager: ?KeymanagerCallback = null,
    /// Optional validator monitor callback. Nil until wired by BeaconNode.init.
    validator_monitor: ?ValidatorMonitorCallback = null,
};

// ---------------------------------------------------------------------------
// Validator monitor callback
// ---------------------------------------------------------------------------

/// Type-erased callback for querying the validator monitor.
pub const ValidatorMonitorCallback = struct {
    ptr: *anyopaque,
    /// Returns JSON bytes of all monitored validators' summaries. Caller owns.
    getMonitorStatusFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]const u8,
};
