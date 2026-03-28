//! Beacon REST API types.
//!
//! Request and response types matching the Ethereum Beacon API specification.
//! These types are transport-agnostic: they represent the logical data that
//! handlers produce and consume. Serialization to JSON or SSZ happens at
//! the response-encoding layer.
//!
//! Reference: https://ethereum.github.io/beacon-APIs/

const std = @import("std");
const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const phase0 = consensus_types.phase0;

// ---------------------------------------------------------------------------
// Common identifiers
// ---------------------------------------------------------------------------

/// Block identifier — accepts named values, slot numbers, or 0x-prefixed roots.
pub const BlockId = union(enum) {
    head,
    genesis,
    finalized,
    justified,
    slot: u64,
    root: [32]u8,

    pub fn parse(raw: []const u8) !BlockId {
        if (std.mem.eql(u8, raw, "head")) return .head;
        if (std.mem.eql(u8, raw, "genesis")) return .genesis;
        if (std.mem.eql(u8, raw, "finalized")) return .finalized;
        if (std.mem.eql(u8, raw, "justified")) return .justified;
        if (raw.len == 66 and raw[0] == '0' and raw[1] == 'x') {
            var root: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&root, raw[2..]) catch return error.InvalidBlockId;
            return .{ .root = root };
        }
        const slot = std.fmt.parseInt(u64, raw, 10) catch return error.InvalidBlockId;
        return .{ .slot = slot };
    }
};

/// State identifier — same grammar as BlockId.
pub const StateId = union(enum) {
    head,
    genesis,
    finalized,
    justified,
    slot: u64,
    root: [32]u8,

    pub fn parse(raw: []const u8) !StateId {
        if (std.mem.eql(u8, raw, "head")) return .head;
        if (std.mem.eql(u8, raw, "genesis")) return .genesis;
        if (std.mem.eql(u8, raw, "finalized")) return .finalized;
        if (std.mem.eql(u8, raw, "justified")) return .justified;
        if (raw.len == 66 and raw[0] == '0' and raw[1] == 'x') {
            var root: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&root, raw[2..]) catch return error.InvalidStateId;
            return .{ .root = root };
        }
        const slot = std.fmt.parseInt(u64, raw, 10) catch return error.InvalidStateId;
        return .{ .slot = slot };
    }
};

/// Validator identifier — accepts index or 0x-prefixed pubkey.
pub const ValidatorId = union(enum) {
    index: u64,
    pubkey: [48]u8,

    pub fn parse(raw: []const u8) !ValidatorId {
        if (raw.len == 98 and raw[0] == '0' and raw[1] == 'x') {
            var pk: [48]u8 = undefined;
            _ = std.fmt.hexToBytes(&pk, raw[2..]) catch return error.InvalidValidatorId;
            return .{ .pubkey = pk };
        }
        const idx = std.fmt.parseInt(u64, raw, 10) catch return error.InvalidValidatorId;
        return .{ .index = idx };
    }
};

/// Validator status per the Beacon API spec.
pub const ValidatorStatus = enum {
    pending_initialized,
    pending_queued,
    active_ongoing,
    active_exiting,
    active_slashed,
    exited_unslashed,
    exited_slashed,
    withdrawal_possible,
    withdrawal_done,

    pub fn fromValidator(validator: anytype, epoch: u64) ValidatorStatus {
        const v = validator.*;
        const eff_balance_exists = true;
        _ = eff_balance_exists;

        if (v.activation_epoch > epoch) {
            if (v.activation_eligibility_epoch == std.math.maxInt(u64)) {
                return .pending_initialized;
            }
            return .pending_queued;
        }
        if (v.activation_epoch <= epoch and epoch < v.exit_epoch) {
            if (v.exit_epoch == std.math.maxInt(u64)) {
                return .active_ongoing;
            }
            if (v.slashed) {
                return .active_slashed;
            }
            return .active_exiting;
        }
        if (v.exit_epoch <= epoch and epoch < v.withdrawable_epoch) {
            if (v.slashed) {
                return .exited_slashed;
            }
            return .exited_unslashed;
        }
        // withdrawable_epoch <= epoch
        if (v.effective_balance == 0) {
            return .withdrawal_done;
        }
        return .withdrawal_possible;
    }

    pub fn toString(self: ValidatorStatus) []const u8 {
        return switch (self) {
            .pending_initialized => "pending_initialized",
            .pending_queued => "pending_queued",
            .active_ongoing => "active_ongoing",
            .active_exiting => "active_exiting",
            .active_slashed => "active_slashed",
            .exited_unslashed => "exited_unslashed",
            .exited_slashed => "exited_slashed",
            .withdrawal_possible => "withdrawal_possible",
            .withdrawal_done => "withdrawal_done",
        };
    }
};

/// Query filter for the validators endpoint.
pub const ValidatorQuery = struct {
    /// Optional list of validator IDs to filter by.
    ids: ?[]const ValidatorId = null,
    /// Optional list of statuses to filter by.
    statuses: ?[]const ValidatorStatus = null,
};

/// Peer connection state.
pub const PeerState = enum {
    disconnected,
    connecting,
    connected,
    disconnecting,

    pub fn toString(self: PeerState) []const u8 {
        return switch (self) {
            .disconnected => "disconnected",
            .connecting => "connecting",
            .connected => "connected",
            .disconnecting => "disconnecting",
        };
    }
};

/// Peer connection direction.
pub const PeerDirection = enum {
    inbound,
    outbound,

    pub fn toString(self: PeerDirection) []const u8 {
        return switch (self) {
            .inbound => "inbound",
            .outbound => "outbound",
        };
    }
};

// ---------------------------------------------------------------------------
// Accepted content types (JSON vs SSZ)
// ---------------------------------------------------------------------------

pub const ContentType = enum {
    json,
    ssz,

    pub fn fromAcceptHeader(accept: ?[]const u8) ContentType {
        const header = accept orelse return .json;
        if (std.mem.indexOf(u8, header, "application/octet-stream") != null) return .ssz;
        return .json;
    }
};

// ---------------------------------------------------------------------------
// Response wrappers
// ---------------------------------------------------------------------------

/// Standard Beacon API JSON envelope: `{ "data": ..., "meta": ... }`.
pub fn ApiResponse(comptime T: type) type {
    return struct {
        data: T,
        /// Execution-optimistic flag (true when EL has not validated).
        execution_optimistic: bool = false,
        /// Whether the data comes from the finalized chain.
        finalized: bool = false,
    };
}

/// Version metadata for versioned responses (blocks, states).
pub const VersionMeta = struct {
    version: []const u8,
};

// ---------------------------------------------------------------------------
// Node endpoint types
// ---------------------------------------------------------------------------

pub const NodeIdentity = struct {
    peer_id: []const u8,
    enr: []const u8,
    p2p_addresses: []const []const u8,
    discovery_addresses: []const []const u8,
    metadata: NodeMetadata,
};

pub const NodeMetadata = struct {
    seq_number: u64,
    attnets: [8]u8,
    syncnets: [1]u8,
};

pub const NodeVersion = struct {
    version: []const u8,
};

pub const SyncingStatus = struct {
    head_slot: u64,
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
    el_offline: bool,
};

pub const HealthStatus = enum(u16) {
    ready = 200,
    syncing = 206,
    not_initialized = 503,
};

pub const PeerInfo = struct {
    peer_id: []const u8,
    enr: ?[]const u8,
    last_seen_p2p_address: []const u8,
    state: PeerState,
    direction: PeerDirection,
};

// ---------------------------------------------------------------------------
// Beacon endpoint types
// ---------------------------------------------------------------------------

pub const GenesisData = struct {
    genesis_time: u64,
    genesis_validators_root: [32]u8,
    genesis_fork_version: [4]u8,
};

pub const BlockHeaderData = struct {
    root: [32]u8,
    canonical: bool,
    header: SignedHeaderData,
};

pub const SignedHeaderData = struct {
    message: BlockHeaderMessage,
    signature: [96]u8,
};

pub const BlockHeaderMessage = struct {
    slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
    state_root: [32]u8,
    body_root: [32]u8,
};

pub const ValidatorData = struct {
    index: u64,
    balance: u64,
    status: ValidatorStatus,
    validator: ValidatorInfo,
};

pub const ValidatorInfo = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
};

pub const FinalityCheckpoints = struct {
    previous_justified: CheckpointData,
    current_justified: CheckpointData,
    finalized: CheckpointData,
};

pub const CheckpointData = struct {
    epoch: u64,
    root: [32]u8,
};

pub const ForkData = struct {
    previous_version: [4]u8,
    current_version: [4]u8,
    epoch: u64,
};

// ---------------------------------------------------------------------------
// Config endpoint types
// ---------------------------------------------------------------------------

pub const ForkScheduleEntry = struct {
    previous_version: [4]u8,
    current_version: [4]u8,
    epoch: u64,
};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

pub const ApiError = error{
    InvalidBlockId,
    InvalidStateId,
    InvalidValidatorId,
    BlockNotFound,
    StateNotFound,
    ValidatorNotFound,
    SlotNotFound,
    NotImplemented,
    InternalError,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BlockId.parse named" {
    const head = try BlockId.parse("head");
    try std.testing.expect(head == .head);

    const gen = try BlockId.parse("genesis");
    try std.testing.expect(gen == .genesis);

    const fin = try BlockId.parse("finalized");
    try std.testing.expect(fin == .finalized);

    const just = try BlockId.parse("justified");
    try std.testing.expect(just == .justified);
}

test "BlockId.parse slot" {
    const bid = try BlockId.parse("12345");
    try std.testing.expect(bid == .slot);
    try std.testing.expectEqual(@as(u64, 12345), bid.slot);
}

test "BlockId.parse root" {
    const hex = "0x" ++ "ab" ** 32;
    const bid = try BlockId.parse(hex);
    try std.testing.expect(bid == .root);
    try std.testing.expectEqual(@as(u8, 0xab), bid.root[0]);
}

test "BlockId.parse invalid" {
    try std.testing.expectError(error.InvalidBlockId, BlockId.parse("not_valid_name"));
}

test "StateId.parse named" {
    const head = try StateId.parse("head");
    try std.testing.expect(head == .head);
}

test "StateId.parse slot" {
    const sid = try StateId.parse("999");
    try std.testing.expect(sid == .slot);
    try std.testing.expectEqual(@as(u64, 999), sid.slot);
}

test "StateId.parse root" {
    const hex = "0x" ++ "cd" ** 32;
    const sid = try StateId.parse(hex);
    try std.testing.expect(sid == .root);
    try std.testing.expectEqual(@as(u8, 0xcd), sid.root[0]);
}

test "ValidatorId.parse index" {
    const vid = try ValidatorId.parse("42");
    try std.testing.expect(vid == .index);
    try std.testing.expectEqual(@as(u64, 42), vid.index);
}

test "ValidatorId.parse pubkey" {
    const hex = "0x" ++ "ef" ** 48;
    const vid = try ValidatorId.parse(hex);
    try std.testing.expect(vid == .pubkey);
    try std.testing.expectEqual(@as(u8, 0xef), vid.pubkey[0]);
}

test "ValidatorStatus.toString roundtrip" {
    const status = ValidatorStatus.active_ongoing;
    try std.testing.expectEqualStrings("active_ongoing", status.toString());
}

test "ContentType.fromAcceptHeader" {
    try std.testing.expectEqual(ContentType.json, ContentType.fromAcceptHeader(null));
    try std.testing.expectEqual(ContentType.json, ContentType.fromAcceptHeader("application/json"));
    try std.testing.expectEqual(ContentType.ssz, ContentType.fromAcceptHeader("application/octet-stream"));
}

pub const PeerCount = struct {
    disconnected: u64,
    connecting: u64,
    connected: u64,
    disconnecting: u64,
};

// ---------------------------------------------------------------------------
// Pool endpoint types
// ---------------------------------------------------------------------------

/// Aggregate counts of pending operations across all pools.
pub const PoolCounts = struct {
    attestation_groups: usize,
    voluntary_exits: usize,
    proposer_slashings: usize,
    attester_slashings: usize,
    bls_to_execution_changes: usize,
};

// ---------------------------------------------------------------------------
// Committee types
// ---------------------------------------------------------------------------

/// A single beacon committee assignment.
pub const CommitteeData = struct {
    /// Committee index within the slot.
    index: u64,
    /// Slot the committee is assigned to.
    slot: u64,
    /// Sorted list of validator indices in the committee.
    validators: []const u64,
};

// ---------------------------------------------------------------------------
// Sync committee types
// ---------------------------------------------------------------------------

/// Sync committee composition for a state.
pub const SyncCommitteeData = struct {
    /// All validator indices in the sync committee (512 entries).
    validators: []const u64,
    /// Subcommittee aggregates (4 groups of 128 validators each).
    validator_aggregates: []const []const u64,
};

// ---------------------------------------------------------------------------
// RANDAO types
// ---------------------------------------------------------------------------

/// RANDAO mix for a state/epoch.
pub const RandaoData = struct {
    randao: [32]u8,
};

// ---------------------------------------------------------------------------
// Rewards types
// ---------------------------------------------------------------------------

/// Proposer reward breakdown for a block.
pub const BlockRewards = struct {
    proposer_index: u64,
    total: u64,
    attestations: u64,
    sync_aggregate: u64,
    proposer_slashings: u64,
    attester_slashings: u64,
};

/// Ideal attestation rewards (what a perfect validator would earn).
pub const IdealAttestationReward = struct {
    effective_balance: u64,
    head: u64,
    target: u64,
    source: u64,
    inclusion_delay: u64,
    inactivity: u64,
};

/// Total attestation rewards for a single validator.
pub const TotalAttestationReward = struct {
    validator_index: u64,
    head: i64,
    target: i64,
    source: i64,
    inclusion_delay: u64,
    inactivity: i64,
};

/// Response for attestation rewards.
pub const AttestationRewardsData = struct {
    ideal_rewards: []const IdealAttestationReward,
    total_rewards: []const TotalAttestationReward,
};

/// Sync committee reward per validator.
pub const SyncCommitteeReward = struct {
    validator_index: u64,
    reward: i64,
};

// ---------------------------------------------------------------------------
// Validator liveness types
// ---------------------------------------------------------------------------

/// Liveness status for a single validator.
pub const ValidatorLiveness = struct {
    index: u64,
    epoch: u64,
    is_live: bool,
};

// ---------------------------------------------------------------------------
// Fork choice debug types
// ---------------------------------------------------------------------------

/// A single node in the fork choice tree.
pub const ForkChoiceNode = struct {
    slot: u64,
    block_root: [32]u8,
    parent_root: ?[32]u8,
    justified_epoch: u64,
    finalized_epoch: u64,
    weight: u64,
    validity: []const u8,
    execution_block_hash: [32]u8,
};

/// Full fork choice dump.
pub const ForkChoiceDump = struct {
    justified_checkpoint: CheckpointData,
    finalized_checkpoint: CheckpointData,
    fork_choice_nodes: []const ForkChoiceNode,
};

// ---------------------------------------------------------------------------
// Peer (individual lookup)
// ---------------------------------------------------------------------------

/// Extended peer info for GET /eth/v1/node/peers/{peer_id}
pub const PeerDetail = struct {
    peer_id: []const u8,
    enr: ?[]const u8,
    last_seen_p2p_address: []const u8,
    state: PeerState,
    direction: PeerDirection,
};

// ---------------------------------------------------------------------------
// Validator registration types (MEV-boost)
// ---------------------------------------------------------------------------

/// Fee recipient registration.
pub const ProposerPreparation = struct {
    validator_index: u64,
    fee_recipient: [20]u8,
};

/// Validator registration for MEV-boost.
pub const ValidatorRegistrationV1 = struct {
    fee_recipient: [20]u8,
    gas_limit: u64,
    timestamp: u64,
    pubkey: [48]u8,
};

pub const SignedValidatorRegistrationV1 = struct {
    message: ValidatorRegistrationV1,
    signature: [96]u8,
};
