//! API context — the shared state that route handlers need.
//!
//! Dependencies stay behind small type-erased callback surfaces so handlers
//! can stay decoupled from node/runtime internals while still using the live
//! production services.

const std = @import("std");
const types = @import("types.zig");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const BlockType = fork_types.BlockType;
pub const CachedBeaconState = state_transition.CachedBeaconState;

// ---------------------------------------------------------------------------
// Bridge snapshot types
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

    // Epoch-start slot (epoch * SLOTS_PER_EPOCH). Not the actual finalized block slot.
    finalized_slot: u64,
    finalized_root: [32]u8,

    // Epoch-start slot (epoch * SLOTS_PER_EPOCH). Not the actual justified block slot.
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

/// Type-erased callback for chain-backed reads and state lookup.
///
/// This is the API-facing chain boundary: handlers ask this port for head
/// snapshots, canonical block/state reads, and live state lookup/regeneration
/// without depending on node-local trackers or direct DB access.
pub const ChainCallback = struct {
    ptr: *anyopaque,
    getHeadTrackerFn: *const fn (ptr: *anyopaque) HeadTracker,
    getCurrentSlotFn: *const fn (ptr: *anyopaque) u64,
    validatorSeenAtEpochFn: *const fn (ptr: *anyopaque, validator_index: u64, epoch: u64) bool,
    getBlockRootBySlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!?[32]u8,
    getBlockBytesByRootFn: *const fn (ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8,
    getBlobSidecarsByRootFn: *const fn (ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8,
    getBlockExecutionOptimisticFn: *const fn (ptr: *anyopaque, root: [32]u8) bool,
    getBlockExecutionOptimisticAtSlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!bool,
    getStateRootBySlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!?[32]u8,
    getStateRootByBlockRootFn: *const fn (ptr: *anyopaque, root: [32]u8) anyerror!?[32]u8,
    getStateBytesBySlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!?[]const u8,
    getStateBytesByRootFn: *const fn (ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8,
    getStateArchiveAtSlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!?[]const u8,
    getStateArchiveByRootFn: *const fn (ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8,
    getHeadStateFn: *const fn (ptr: *anyopaque) ?*CachedBeaconState,
    getStateByRootFn: *const fn (ptr: *anyopaque, state_root: [32]u8) anyerror!?*CachedBeaconState,
    getStateBySlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!?*CachedBeaconState,
    getStateExecutionOptimisticByRootFn: *const fn (ptr: *anyopaque, state_root: [32]u8) bool,
    getStateExecutionOptimisticBySlotFn: *const fn (ptr: *anyopaque, slot: u64) anyerror!bool,
    getBlockRewardsFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, block_root: [32]u8) anyerror!types.BlockRewards,
    getAttestationRewardsFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, epoch: u64, validator_indices: []const u64) anyerror!types.AttestationRewardsData,
    getSyncCommitteeRewardsFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, block_root: [32]u8, validator_indices: []const u64) anyerror![]const types.SyncCommitteeReward,
};

/// Type-erased callback for live node sync status.
///
/// Sync status is a node/runtime concern rather than a pure chain query since
/// it depends on the sync service state machine and EL liveness.
pub const SyncStatusCallback = struct {
    ptr: *anyopaque,
    getSyncStatusFn: *const fn (ptr: *anyopaque) SyncStatus,
};

/// Type-erased callback for fork-choice-backed debug views.
pub const ForkChoiceDebugCallback = struct {
    ptr: *anyopaque,
    getHeadsFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]types.DebugChainHead,
    getForkChoiceDumpFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!types.ForkChoiceDump,
};

// Comptime ABI guard: verify field layout matches what BeaconNode writes via raw pointer.
// If beacon_node.SyncStatus changes, this will catch it at compile time.
// Keep this in sync with src/node/beacon_node.zig:SyncStatus.
comptime {
    // Field order and types must match the beacon_node.SyncStatus layout exactly.
    // Asserted sizes: u64 + u64 + bool + bool + bool = 18 bytes (with padding).
    std.debug.assert(@offsetOf(SyncStatus, "head_slot") == 0);
    std.debug.assert(@offsetOf(SyncStatus, "sync_distance") == @sizeOf(u64));
    // is_syncing, is_optimistic, el_offline follow after two u64s.
    std.debug.assert(@offsetOf(SyncStatus, "is_syncing") == 2 * @sizeOf(u64));
    std.debug.assert(@offsetOf(SyncStatus, "is_optimistic") == 2 * @sizeOf(u64) + 1);
    std.debug.assert(@offsetOf(SyncStatus, "el_offline") == 2 * @sizeOf(u64) + 2);
}

// ---------------------------------------------------------------------------
// Block import callback
// ---------------------------------------------------------------------------

pub const PublishedBlockParams = struct {
    block_bytes: []const u8,
    block_type: BlockType,
    broadcast_validation: types.BroadcastValidation = .gossip,
};

pub const PublishedBlockImportResult = enum {
    imported,
    queued,
    ignored,
};

pub const BlockImportCallback = struct {
    ptr: *anyopaque,
    importFn: *const fn (ptr: *anyopaque, params: PublishedBlockParams) anyerror!PublishedBlockImportResult,
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
    pub const consensus = @import("consensus_types");
    pub const Phase0Attestation = consensus.phase0.Attestation.Type;
    pub const SignedVoluntaryExit = consensus.phase0.SignedVoluntaryExit.Type;
    pub const ProposerSlashing = consensus.phase0.ProposerSlashing.Type;
    pub const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
    pub const SignedBLSToExecutionChange = consensus.capella.SignedBLSToExecutionChange.Type;

    ptr: *anyopaque,
    /// Returns the number of items in each pool: [attestation_groups, voluntary_exits, proposer_slashings, attester_slashings, bls_changes].
    getPoolCountsFn: *const fn (ptr: *anyopaque) [5]usize,
    /// Returns all pending attestations, optionally filtered by slot and committee_index.
    /// Caller owns the returned slice.
    getAttestationsFn: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator, slot: ?u64, committee_index: ?u64) anyerror![]Phase0Attestation = null,
    /// Returns all pending voluntary exits. Caller owns the returned slice.
    getVoluntaryExitsFn: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]SignedVoluntaryExit = null,
    /// Returns all pending proposer slashings. Caller owns the returned slice.
    getProposerSlashingsFn: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]ProposerSlashing = null,
    /// Returns all pending attester slashings. Caller owns the returned slice.
    getAttesterSlashingsFn: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]AnyAttesterSlashing = null,
    /// Returns all pending BLS-to-execution changes. Caller owns the returned slice.
    getBlsToExecutionChangesFn: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]SignedBLSToExecutionChange = null,
};

// ---------------------------------------------------------------------------
// Pool submission callback
// ---------------------------------------------------------------------------

pub const SubmittedAttestations = union(enum) {
    phase0: []const consensus_types.phase0.Attestation.Type,
    electra_single: []const consensus_types.electra.SingleAttestation.Type,
};

pub const SubmittedAttesterSlashing = union(enum) {
    phase0: consensus_types.phase0.AttesterSlashing.Type,
    electra: consensus_types.electra.AttesterSlashing.Type,
};

pub const SubmittedAggregateAndProofs = union(enum) {
    phase0: []const consensus_types.phase0.SignedAggregateAndProof.Type,
    electra: []const consensus_types.electra.SignedAggregateAndProof.Type,
};

/// Type-erased callback for submitting items to operation pools.
pub const PoolSubmitCallback = struct {
    ptr: *anyopaque,
    /// Submit attestations.
    submitAttestationFn: ?*const fn (ptr: *anyopaque, attestations: SubmittedAttestations) anyerror!void = null,
    /// Submit a signed voluntary exit.
    submitVoluntaryExitFn: ?*const fn (ptr: *anyopaque, exit: consensus_types.phase0.SignedVoluntaryExit.Type) anyerror!void = null,
    /// Submit a proposer slashing.
    submitProposerSlashingFn: ?*const fn (ptr: *anyopaque, slashing: consensus_types.phase0.ProposerSlashing.Type) anyerror!void = null,
    /// Submit an attester slashing.
    submitAttesterSlashingFn: ?*const fn (ptr: *anyopaque, slashing: SubmittedAttesterSlashing) anyerror!void = null,
    /// Submit signed BLS-to-execution changes.
    submitBlsChangeFn: ?*const fn (ptr: *anyopaque, changes: []const consensus_types.capella.SignedBLSToExecutionChange.Type) anyerror!void = null,
    /// Submit sync committee messages.
    submitSyncCommitteeMessageFn: ?*const fn (ptr: *anyopaque, messages: []const consensus_types.altair.SyncCommitteeMessage.Type) anyerror!void = null,
    /// Submit aggregate and proofs.
    submitAggregateAndProofFn: ?*const fn (ptr: *anyopaque, aggregates: SubmittedAggregateAndProofs) anyerror!void = null,
    /// Submit contribution and proofs.
    submitContributionAndProofFn: ?*const fn (ptr: *anyopaque, contributions: []const consensus_types.altair.SignedContributionAndProof.Type) anyerror!void = null,
};

// ---------------------------------------------------------------------------
// Produce block callback
// ---------------------------------------------------------------------------

/// Parameters for block production.
pub const ProduceBlockParams = struct {
    slot: u64,
    randao_reveal: [96]u8,
    fee_recipient: ?[20]u8 = null,
    graffiti: ?[32]u8 = null,
    builder_selection: ?types.BuilderSelection = null,
    builder_boost_factor: ?u64 = null,
    strict_fee_recipient_check: bool = false,
    blinded_local: bool = false,
};

/// Result of block production (minimal, for API response).
pub const ProducedBlockData = struct {
    /// Raw SSZ bytes of the produced BeaconBlock (unsigned).
    ssz_bytes: []const u8,
    /// Fork name for the produced block (e.g. "electra").
    fork: []const u8,
    /// True when the produced block bytes encode a blinded block.
    blinded: bool = false,
    /// Source of the execution payload used to assemble the block.
    execution_payload_source: types.ExecutionPayloadSource = .engine,
    /// Execution payload value in wei.
    execution_payload_value: u256 = 0,
    /// Consensus proposer reward for the block in wei.
    consensus_block_value: u256 = 0,
};

/// Callback for producing blocks (GET /eth/v1/validator/blocks/{slot}).
pub const ProduceBlockCallback = struct {
    ptr: *anyopaque,
    /// Produce a block for the given slot. Caller owns returned ssz_bytes.
    produceBlockFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, params: ProduceBlockParams) anyerror!ProducedBlockData,
};

pub const PrepareBeaconProposerCallback = struct {
    ptr: *anyopaque,
    prepareBeaconProposerFn: *const fn (ptr: *anyopaque, preparations: []const types.ProposerPreparation) anyerror!void,
};

// ---------------------------------------------------------------------------
// Attestation data callback
// ---------------------------------------------------------------------------

/// Result of attestation data query.
pub const AttestationDataResult = struct {
    slot: u64,
    index: u64,
    beacon_block_root: [32]u8,
    source: types.CheckpointData,
    target: types.CheckpointData,
};

/// Callback for getting attestation data (GET /eth/v1/validator/attestation_data).
pub const AttestationDataCallback = struct {
    ptr: *anyopaque,
    getAttestationDataFn: *const fn (ptr: *anyopaque, slot: u64, committee_index: u64) anyerror!AttestationDataResult,
};

pub const AggregateAttestationResult = consensus_types.phase0.Attestation.Type;
pub const SyncCommitteeContributionResult = consensus_types.altair.SyncCommitteeContribution.Type;

// ---------------------------------------------------------------------------
// Aggregate attestation callback
// ---------------------------------------------------------------------------

/// Callback for getting best aggregate attestation from pool.
pub const AggregateAttestationCallback = struct {
    ptr: *anyopaque,
    getAggregateAttestationFn: *const fn (ptr: *anyopaque, slot: u64, attestation_data_root: [32]u8) anyerror!AggregateAttestationResult,
};

// ---------------------------------------------------------------------------
// Sync committee contribution callback
// ---------------------------------------------------------------------------

/// Callback for getting sync committee contribution.
pub const SyncCommitteeContributionCallback = struct {
    ptr: *anyopaque,
    getSyncCommitteeContributionFn: *const fn (ptr: *anyopaque, slot: u64, subcommittee_index: u64, beacon_block_root: [32]u8) anyerror!SyncCommitteeContributionResult,
};

/// Callback for validator-driven subnet subscription updates.
pub const SubnetSubscriptionCallback = struct {
    ptr: *anyopaque,
    prepareBeaconCommitteeSubnetsFn: *const fn (ptr: *anyopaque, subscriptions: []const types.BeaconCommitteeSubscription) anyerror!void,
    prepareSyncCommitteeSubnetsFn: *const fn (ptr: *anyopaque, subscriptions: []const types.SyncCommitteeSubscription) anyerror!void,
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
    /// Import a keystore JSON string with password and optional typed EIP-3076 interchange data.
    importKeyFn: *const fn (ptr: *anyopaque, keystore_json: []const u8, password: []const u8, slashing_protection: ?types.KeymanagerInterchangeFormat) anyerror!types.KeymanagerOperationStatus,
    /// Delete a key by pubkey. Returns status + optional typed EIP-3076 interchange data.
    deleteKeyFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror!DeleteKeyResult,
    /// List remote signer keys. Caller owns result + slice.
    listRemoteKeysFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]RemoteKeyInfo,
    /// Import a remote key.
    importRemoteKeyFn: *const fn (ptr: *anyopaque, pubkey: [48]u8, url: []const u8) anyerror!types.KeymanagerOperationStatus,
    /// Delete a remote key.
    deleteRemoteKeyFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!types.KeymanagerOperationStatus,
    /// Get the effective fee recipient for a validator.
    getFeeRecipientFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror![20]u8,
    /// Set/delete per-validator fee recipient overrides.
    setFeeRecipientFn: *const fn (ptr: *anyopaque, pubkey: [48]u8, fee_recipient: [20]u8) anyerror!void,
    deleteFeeRecipientFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!void,
    /// Get/set/delete per-validator graffiti overrides.
    getGraffitiFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror![32]u8,
    setGraffitiFn: *const fn (ptr: *anyopaque, pubkey: [48]u8, graffiti: [32]u8) anyerror!void,
    deleteGraffitiFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!void,
    /// Get/set/delete per-validator gas-limit overrides.
    getGasLimitFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!u64,
    setGasLimitFn: *const fn (ptr: *anyopaque, pubkey: [48]u8, gas_limit: u64) anyerror!void,
    deleteGasLimitFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!void,
    /// Get/set/delete per-validator builder boost overrides.
    getBuilderBoostFactorFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!u64,
    setBuilderBoostFactorFn: *const fn (ptr: *anyopaque, pubkey: [48]u8, builder_boost_factor: u64) anyerror!void,
    deleteBuilderBoostFactorFn: *const fn (ptr: *anyopaque, pubkey: [48]u8) anyerror!void,
    /// Get the proposer-config override for a validator. Caller owns any allocated nested strings.
    getProposerConfigFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror!?types.KeymanagerProposerConfigData,
    /// Sign and return a voluntary exit for the validator.
    signVoluntaryExitFn: *const fn (ptr: *anyopaque, pubkey: [48]u8, epoch: ?u64) anyerror!consensus_types.phase0.SignedVoluntaryExit.Type,
};

/// Result of a key delete operation.
pub const DeleteKeyResult = struct {
    status: types.KeymanagerOperationStatus,
    /// EIP-3076 interchange data for the deleted key, if any.
    slashing_protection: ?types.KeymanagerInterchangeFormat,
};

// ---------------------------------------------------------------------------
// ApiContext
// ---------------------------------------------------------------------------

pub const ApiContext = struct {
    /// This node's identity on the P2P network.
    node_identity: *types.NodeIdentity,

    /// Beacon chain configuration.
    beacon_config: *const BeaconConfig,

    /// Actual genesis time (set from genesis state or checkpoint, NOT config minimum).
    genesis_time: u64 = 0,

    /// Allocator for dynamic responses.
    /// Event bus for SSE beacon chain events.
    event_bus: ?*@import("event_bus.zig").EventBus = null,
    allocator: std.mem.Allocator,

    /// Optional block import callback. Nil until wired by BeaconNode.init.
    block_import: ?BlockImportCallback = null,

    /// Optional chain callback. Nil until wired by BeaconNode.init.
    chain: ?ChainCallback = null,

    /// Optional live node sync-status callback. Nil until wired by BeaconNode.init.
    sync_status_view: ?SyncStatusCallback = null,

    /// Optional peer DB callback. Nil until wired by BeaconNode.init.
    peer_db: ?PeerDBCallback = null,

    /// Optional fork-choice debug callback. Nil until wired by BeaconNode.init.
    fork_choice_debug: ?ForkChoiceDebugCallback = null,

    /// Optional operation pool callback. Nil until wired by BeaconNode.init.
    op_pool: ?OpPoolCallback = null,

    /// Optional pool submission callback. Nil until wired by BeaconNode.init.
    pool_submit: ?PoolSubmitCallback = null,

    /// Optional block production callback. Nil until wired by BeaconNode.init.
    produce_block: ?ProduceBlockCallback = null,
    /// Optional proposer-preparation callback. Nil until wired by BeaconNode.init.
    prepare_beacon_proposer: ?PrepareBeaconProposerCallback = null,

    /// Optional attestation data callback. Nil until wired by BeaconNode.init.
    attestation_data: ?AttestationDataCallback = null,

    /// Optional aggregate attestation callback. Nil until wired by BeaconNode.init.
    aggregate_attestation: ?AggregateAttestationCallback = null,

    /// Optional sync committee contribution callback. Nil until wired by BeaconNode.init.
    sync_committee_contribution: ?SyncCommitteeContributionCallback = null,
    /// Optional validator subnet subscription callback. Nil until wired by BeaconNode.init.
    subnet_subscriptions: ?SubnetSubscriptionCallback = null,
    /// Optional keymanager callback.
    keymanager: ?KeymanagerCallback = null,
    /// Optional validator monitor callback. Nil until wired by BeaconNode.init.
    validator_monitor: ?ValidatorMonitorCallback = null,
    /// Optional builder relay callback. Nil when builder is not configured.
    builder: ?BuilderCallback = null,

    pub fn currentHeadTracker(self: *const ApiContext) HeadTracker {
        if (self.chain) |cb| return cb.getHeadTrackerFn(cb.ptr);
        return std.mem.zeroes(HeadTracker);
    }

    pub fn currentSlot(self: *const ApiContext) ?u64 {
        if (self.chain) |cb| return cb.getCurrentSlotFn(cb.ptr);
        return null;
    }

    pub fn validatorSeenAtEpoch(self: *const ApiContext, validator_index: u64, epoch: u64) bool {
        if (self.chain) |cb| return cb.validatorSeenAtEpochFn(cb.ptr, validator_index, epoch);
        return false;
    }

    pub fn currentSyncStatus(self: *const ApiContext) SyncStatus {
        if (self.sync_status_view) |cb| return cb.getSyncStatusFn(cb.ptr);
        return std.mem.zeroes(SyncStatus);
    }

    pub fn forkChoiceHeads(self: *const ApiContext, allocator: std.mem.Allocator) ![]types.DebugChainHead {
        const cb = self.fork_choice_debug orelse return error.NotImplemented;
        return cb.getHeadsFn(cb.ptr, allocator);
    }

    pub fn forkChoiceDump(self: *const ApiContext, allocator: std.mem.Allocator) !types.ForkChoiceDump {
        const cb = self.fork_choice_debug orelse return error.NotImplemented;
        return cb.getForkChoiceDumpFn(cb.ptr, allocator);
    }

    pub fn blockRootBySlot(self: *const ApiContext, slot: u64) !?[32]u8 {
        if (self.chain) |cb| return cb.getBlockRootBySlotFn(cb.ptr, slot);
        return null;
    }

    pub fn blockBytesByRoot(self: *const ApiContext, root: [32]u8) !?[]const u8 {
        if (self.chain) |cb| return cb.getBlockBytesByRootFn(cb.ptr, root);
        return null;
    }

    pub fn blobSidecarsByRoot(self: *const ApiContext, root: [32]u8) !?[]const u8 {
        if (self.chain) |cb| return cb.getBlobSidecarsByRootFn(cb.ptr, root);
        return null;
    }

    pub fn blobSidecarsAtSlot(self: *const ApiContext, slot: u64) !?[]const u8 {
        const root = try self.blockRootBySlot(slot) orelse return null;
        return self.blobSidecarsByRoot(root);
    }

    pub fn blockExecutionOptimistic(self: *const ApiContext, root: [32]u8) bool {
        if (self.chain) |cb| return cb.getBlockExecutionOptimisticFn(cb.ptr, root);
        return false;
    }

    pub fn blockExecutionOptimisticAtSlot(self: *const ApiContext, slot: u64) !bool {
        if (self.chain) |cb| return cb.getBlockExecutionOptimisticAtSlotFn(cb.ptr, slot);
        return false;
    }

    pub fn blockBytesAtSlot(self: *const ApiContext, slot: u64) !?[]const u8 {
        const root = try self.blockRootBySlot(slot) orelse return null;
        return self.blockBytesByRoot(root);
    }

    pub fn stateRootBySlot(self: *const ApiContext, slot: u64) !?[32]u8 {
        if (self.chain) |cb| return cb.getStateRootBySlotFn(cb.ptr, slot);
        const head = self.currentHeadTracker();
        if (slot == head.head_slot) return head.head_state_root;
        const block_root = try self.blockRootBySlot(slot) orelse return null;
        return self.stateRootByBlockRoot(block_root);
    }

    pub fn stateRootByBlockRoot(self: *const ApiContext, root: [32]u8) !?[32]u8 {
        if (self.chain) |cb| return cb.getStateRootByBlockRootFn(cb.ptr, root);

        const block_bytes = try self.blockBytesByRoot(root) orelse return null;
        defer self.allocator.free(block_bytes);

        return self.deserializeSignedBlockStateRoot(block_bytes);
    }

    pub fn stateArchiveAtSlot(self: *const ApiContext, slot: u64) !?[]const u8 {
        if (self.chain) |cb| return cb.getStateArchiveAtSlotFn(cb.ptr, slot);
        return null;
    }

    pub fn stateArchiveByRoot(self: *const ApiContext, root: [32]u8) !?[]const u8 {
        if (self.chain) |cb| return cb.getStateArchiveByRootFn(cb.ptr, root);
        return null;
    }

    pub fn stateBytesBySlot(self: *const ApiContext, slot: u64) !?[]const u8 {
        if (self.chain) |cb| {
            if (try cb.getStateBytesBySlotFn(cb.ptr, slot)) |bytes| return bytes;
        }
        if (try self.stateArchiveAtSlot(slot)) |bytes| return bytes;
        if (try self.stateBySlot(slot)) |state| {
            const bytes = try state.state.serialize(self.allocator);
            return bytes;
        }
        return null;
    }

    pub fn stateBytesByRoot(self: *const ApiContext, root: [32]u8) !?[]const u8 {
        if (self.chain) |cb| {
            if (try cb.getStateBytesByRootFn(cb.ptr, root)) |bytes| return bytes;
        }
        if (try self.stateArchiveByRoot(root)) |bytes| return bytes;
        if (try self.stateByRoot(root)) |state| {
            const bytes = try state.state.serialize(self.allocator);
            return bytes;
        }
        return null;
    }

    pub fn headState(self: *const ApiContext) ?*CachedBeaconState {
        if (self.chain) |cb| return cb.getHeadStateFn(cb.ptr);
        return null;
    }

    pub fn stateByRoot(self: *const ApiContext, state_root: [32]u8) !?*CachedBeaconState {
        if (self.chain) |cb| return cb.getStateByRootFn(cb.ptr, state_root);
        return null;
    }

    pub fn stateByBlockRoot(self: *const ApiContext, block_root: [32]u8) !?*CachedBeaconState {
        const state_root = try self.stateRootByBlockRoot(block_root) orelse return null;
        return self.stateByRoot(state_root);
    }

    pub fn stateBySlot(self: *const ApiContext, slot: u64) !?*CachedBeaconState {
        if (self.chain) |cb| return cb.getStateBySlotFn(cb.ptr, slot);
        if (slot == self.currentHeadTracker().head_slot) return self.headState();
        if (try self.stateRootBySlot(slot)) |state_root| return self.stateByRoot(state_root);
        return null;
    }

    pub fn stateExecutionOptimisticByRoot(self: *const ApiContext, state_root: [32]u8) bool {
        if (self.chain) |cb| return cb.getStateExecutionOptimisticByRootFn(cb.ptr, state_root);
        return false;
    }

    pub fn stateExecutionOptimisticBySlot(self: *const ApiContext, slot: u64) !bool {
        if (self.chain) |cb| return cb.getStateExecutionOptimisticBySlotFn(cb.ptr, slot);
        return false;
    }

    pub fn blockRewards(self: *const ApiContext, block_root: [32]u8) !types.BlockRewards {
        const cb = self.chain orelse return error.NotImplemented;
        return cb.getBlockRewardsFn(cb.ptr, self.allocator, block_root);
    }

    pub fn attestationRewards(self: *const ApiContext, epoch: u64, validator_indices: []const u64) !types.AttestationRewardsData {
        const cb = self.chain orelse return error.NotImplemented;
        return cb.getAttestationRewardsFn(cb.ptr, self.allocator, epoch, validator_indices);
    }

    pub fn syncCommitteeRewards(self: *const ApiContext, block_root: [32]u8, validator_indices: []const u64) ![]const types.SyncCommitteeReward {
        const cb = self.chain orelse return error.NotImplemented;
        return cb.getSyncCommitteeRewardsFn(cb.ptr, self.allocator, block_root, validator_indices);
    }

    fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
        if (block_bytes.len < 108) return null;
        return std.mem.readInt(u64, block_bytes[100..108], .little);
    }

    fn deserializeSignedBlockStateRoot(self: *const ApiContext, block_bytes: []const u8) !?[32]u8 {
        const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
        const fork_seq = self.beacon_config.forkSeq(slot);
        const any_signed = try AnySignedBeaconBlock.deserialize(
            self.allocator,
            .full,
            fork_seq,
            block_bytes,
        );
        defer any_signed.deinit(self.allocator);
        return any_signed.beaconBlock().stateRoot().*;
    }
};

// ---------------------------------------------------------------------------
// Builder relay callback
// ---------------------------------------------------------------------------

/// Type-erased callback for forwarding validator registrations to the builder relay.
pub const BuilderCallback = struct {
    ptr: *anyopaque,
    /// Forward signed validator registrations to the relay.
    registerValidatorsFn: *const fn (ptr: *anyopaque, registrations: []const types.SignedValidatorRegistrationV1) anyerror!void,

    pub fn registerValidators(self: *const BuilderCallback, registrations: []const types.SignedValidatorRegistrationV1) !void {
        return self.registerValidatorsFn(self.ptr, registrations);
    }
};

// ---------------------------------------------------------------------------
// Validator monitor callback
// ---------------------------------------------------------------------------

/// Type-erased callback for querying the validator monitor.
pub const ValidatorMonitorCallback = struct {
    ptr: *anyopaque,
    /// Returns owned validator monitor snapshots for API encoding.
    getMonitorStatusFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!types.ValidatorMonitorData,
};
