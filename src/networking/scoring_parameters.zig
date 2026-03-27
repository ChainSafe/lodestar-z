//! Gossipsub v1.1 per-topic scoring parameters for Ethereum consensus.
//!
//! Defines scoring weights for each gossip topic type and peer-level thresholds.
//! These parameters control how peers are scored based on their behavior in the gossip mesh.
//!
//! Reference:
//! - https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md#peer-scoring
//! - https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#why-are-there-gossipsub-scoring-parameters-specific-to-ethereum
//! - Lighthouse scoring: https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/behaviour/gossipsub_scoring_parameters.rs

const std = @import("std");
const testing = std.testing;

// ── Topic scoring parameters ─────────────────────────────────────────────────

/// Per-topic gossipsub scoring parameters.
///
/// These are the weights and caps applied to a single gossip topic
/// when computing a peer's topic score contribution.
pub const TopicScoringParams = struct {
    /// Weight of this topic relative to other topics.
    /// Higher weight = bigger impact on the overall score.
    topic_weight: f64,

    /// Weight for time spent in the mesh for this topic (P1).
    time_in_mesh_weight: f64,
    /// Cap for the time-in-mesh counter (P1).
    time_in_mesh_cap: f64,
    /// Quantum for time-in-mesh scoring (seconds per unit).
    time_in_mesh_quantum_secs: f64,

    /// Weight for first message deliveries (P2).
    first_message_deliveries_weight: f64,
    /// Decay factor for first message deliveries counter.
    first_message_deliveries_decay: f64,
    /// Cap for first message deliveries counter (P2).
    first_message_deliveries_cap: f64,

    /// Weight for mesh message deliveries (P3).
    mesh_message_deliveries_weight: f64,
    /// Decay factor for mesh message deliveries counter.
    mesh_message_deliveries_decay: f64,
    /// Activation window for mesh message deliveries (slots).
    mesh_message_deliveries_activation: f64,
    /// Cap for mesh message deliveries counter (P3).
    mesh_message_deliveries_cap: f64,
    /// Threshold below which P3 penalty is applied.
    mesh_message_deliveries_threshold: f64,
    /// Window for counting mesh message deliveries (seconds).
    mesh_message_deliveries_window_secs: f64,

    /// Weight for mesh failure penalty (P3b).
    mesh_failure_penalty_weight: f64,
    /// Decay factor for mesh failure penalty.
    mesh_failure_penalty_decay: f64,

    /// Weight for invalid message deliveries (P4).
    invalid_message_deliveries_weight: f64,
    /// Decay factor for invalid message deliveries counter.
    invalid_message_deliveries_decay: f64,
};

// ── Peer-level thresholds ─────────────────────────────────────────────────────

/// Peer-level scoring thresholds.
///
/// These determine when a peer is throttled, pruned, or disconnected
/// based on their aggregate score.
pub const PeerScoringThresholds = struct {
    /// Score below which a peer is not allowed to publish (P5).
    /// Messages from peers below this threshold are ignored.
    gossip_threshold: f64,

    /// Score below which a peer is not allowed to receive messages from the mesh (P5).
    publish_threshold: f64,

    /// Score below which a peer is graylisted (completely ignored) (P6).
    graylist_threshold: f64,

    /// Score below which gossipsub will opportunistically prune the peer (P7).
    opportunistic_graft_threshold: f64,
};

// ── Eth2 default scoring parameters ──────────────────────────────────────────

/// Slot duration in seconds on mainnet.
const SECONDS_PER_SLOT: f64 = 12.0;

/// Slots per epoch on mainnet.
const SLOTS_PER_EPOCH: f64 = 32.0;

/// One epoch in seconds.
const SECONDS_PER_EPOCH: f64 = SECONDS_PER_SLOT * SLOTS_PER_EPOCH;

/// Decay function helper: compute decay such that after `n_slots` slots,
/// the counter retains `target_fraction` of its value.
///
/// decay = target_fraction ^ (1 / n_slots)
fn decayToTarget(n_slots: f64, target_fraction: f64) f64 {
    return std.math.pow(f64, target_fraction, 1.0 / n_slots);
}

/// Scoring parameters for the beacon_block topic.
///
/// Beacon blocks are the highest-priority topic. We expect ~1 block per slot.
pub const BEACON_BLOCK_PARAMS = TopicScoringParams{
    .topic_weight = 0.5,

    .time_in_mesh_weight = 0.03333,
    .time_in_mesh_quantum_secs = SECONDS_PER_SLOT,
    .time_in_mesh_cap = 300.0, // 300 slots ~ 1 hour

    .first_message_deliveries_weight = 1.14716,
    .first_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 20, 0.01), // 20 epoch decay
    .first_message_deliveries_cap = 23.0,

    .mesh_message_deliveries_weight = -71.4072,
    .mesh_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01), // 5 epoch decay
    .mesh_message_deliveries_activation = SLOTS_PER_EPOCH,
    .mesh_message_deliveries_cap = 69.52,
    .mesh_message_deliveries_threshold = 0.6861,
    .mesh_message_deliveries_window_secs = 2.0,

    .mesh_failure_penalty_weight = -71.4072,
    .mesh_failure_penalty_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),

    .invalid_message_deliveries_weight = -99999.0,
    .invalid_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 50, 0.01),
};

/// Scoring parameters for the beacon_aggregate_and_proof topic.
///
/// Aggregate attestations: up to 64 per slot (one per subnet).
/// We loosen the mesh delivery requirements relative to blocks.
pub const BEACON_AGGREGATE_PROOF_PARAMS = TopicScoringParams{
    .topic_weight = 0.5,

    .time_in_mesh_weight = 0.03333,
    .time_in_mesh_quantum_secs = SECONDS_PER_SLOT,
    .time_in_mesh_cap = 300.0,

    .first_message_deliveries_weight = 0.12725,
    .first_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 20, 0.01),
    .first_message_deliveries_cap = 179.0,

    .mesh_message_deliveries_weight = -0.64,
    .mesh_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),
    .mesh_message_deliveries_activation = SLOTS_PER_EPOCH * 4,
    .mesh_message_deliveries_cap = 68.0,
    .mesh_message_deliveries_threshold = 0.68,
    .mesh_message_deliveries_window_secs = 2.0,

    .mesh_failure_penalty_weight = -0.64,
    .mesh_failure_penalty_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),

    .invalid_message_deliveries_weight = -99999.0,
    .invalid_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 50, 0.01),
};

/// Scoring parameters for individual attestation subnets (beacon_attestation_N).
///
/// Per-subnet attestations. Lower weight since there are many subnets.
/// A node only subscribes to a subset of subnets at a time.
pub const ATTESTATION_SUBNET_PARAMS = TopicScoringParams{
    .topic_weight = 0.015625, // 1/64 of total

    .time_in_mesh_weight = 0.03333,
    .time_in_mesh_quantum_secs = SECONDS_PER_SLOT,
    .time_in_mesh_cap = 300.0,

    .first_message_deliveries_weight = 0.92233,
    .first_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 20, 0.01),
    .first_message_deliveries_cap = 25.0,

    .mesh_message_deliveries_weight = -0.0625,
    .mesh_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),
    .mesh_message_deliveries_activation = SLOTS_PER_EPOCH * 4,
    .mesh_message_deliveries_cap = 25.0,
    .mesh_message_deliveries_threshold = 1.0,
    .mesh_message_deliveries_window_secs = 2.0,

    .mesh_failure_penalty_weight = -0.0625,
    .mesh_failure_penalty_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),

    .invalid_message_deliveries_weight = -99999.0,
    .invalid_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 50, 0.01),
};

/// Scoring parameters for sync committee contribution topics (sync_committee_contribution_and_proof).
pub const SYNC_COMMITTEE_CONTRIBUTION_PARAMS = TopicScoringParams{
    .topic_weight = 0.5,

    .time_in_mesh_weight = 0.03333,
    .time_in_mesh_quantum_secs = SECONDS_PER_SLOT,
    .time_in_mesh_cap = 300.0,

    .first_message_deliveries_weight = 1.0,
    .first_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 20, 0.01),
    .first_message_deliveries_cap = 50.0,

    .mesh_message_deliveries_weight = -1.0,
    .mesh_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),
    .mesh_message_deliveries_activation = SLOTS_PER_EPOCH,
    .mesh_message_deliveries_cap = 50.0,
    .mesh_message_deliveries_threshold = 0.5,
    .mesh_message_deliveries_window_secs = 2.0,

    .mesh_failure_penalty_weight = -1.0,
    .mesh_failure_penalty_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),

    .invalid_message_deliveries_weight = -99999.0,
    .invalid_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 50, 0.01),
};

/// Scoring parameters for sync committee message subnets (sync_committee_N).
pub const SYNC_COMMITTEE_SUBNET_PARAMS = TopicScoringParams{
    .topic_weight = 0.125, // 1/8 of sync committee allocation (4 subnets)

    .time_in_mesh_weight = 0.03333,
    .time_in_mesh_quantum_secs = SECONDS_PER_SLOT,
    .time_in_mesh_cap = 300.0,

    .first_message_deliveries_weight = 0.5,
    .first_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 20, 0.01),
    .first_message_deliveries_cap = 50.0,

    .mesh_message_deliveries_weight = -0.5,
    .mesh_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),
    .mesh_message_deliveries_activation = SLOTS_PER_EPOCH,
    .mesh_message_deliveries_cap = 50.0,
    .mesh_message_deliveries_threshold = 0.5,
    .mesh_message_deliveries_window_secs = 2.0,

    .mesh_failure_penalty_weight = -0.5,
    .mesh_failure_penalty_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),

    .invalid_message_deliveries_weight = -99999.0,
    .invalid_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 50, 0.01),
};

/// Scoring parameters for blob sidecar topics (blob_sidecar_N).
///
/// Similar priority to blocks since blobs are required for EIP-4844 data availability.
pub const BLOB_SIDECAR_PARAMS = TopicScoringParams{
    .topic_weight = 0.5,

    .time_in_mesh_weight = 0.03333,
    .time_in_mesh_quantum_secs = SECONDS_PER_SLOT,
    .time_in_mesh_cap = 300.0,

    .first_message_deliveries_weight = 0.5,
    .first_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 20, 0.01),
    .first_message_deliveries_cap = 50.0,

    .mesh_message_deliveries_weight = -1.0,
    .mesh_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),
    .mesh_message_deliveries_activation = SLOTS_PER_EPOCH,
    .mesh_message_deliveries_cap = 50.0,
    .mesh_message_deliveries_threshold = 0.5,
    .mesh_message_deliveries_window_secs = 2.0,

    .mesh_failure_penalty_weight = -1.0,
    .mesh_failure_penalty_decay = decayToTarget(SLOTS_PER_EPOCH * 5, 0.01),

    .invalid_message_deliveries_weight = -99999.0,
    .invalid_message_deliveries_decay = decayToTarget(SLOTS_PER_EPOCH * 50, 0.01),
};

/// Default peer-level scoring thresholds for Ethereum mainnet.
///
/// These values are calibrated such that:
/// - A peer delivering ~1 invalid message is graylisted.
/// - A peer consistently delivering zero mesh messages is publish-throttled.
pub const DEFAULT_PEER_THRESHOLDS = PeerScoringThresholds{
    .gossip_threshold = -4000.0,
    .publish_threshold = -8000.0,
    .graylist_threshold = -16000.0,
    .opportunistic_graft_threshold = 5.0,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "TopicScoringParams: beacon_block weight is positive" {
    try testing.expect(BEACON_BLOCK_PARAMS.topic_weight > 0.0);
    try testing.expect(BEACON_BLOCK_PARAMS.time_in_mesh_weight > 0.0);
    try testing.expect(BEACON_BLOCK_PARAMS.first_message_deliveries_weight > 0.0);
    // Mesh delivery penalty and invalid should be negative.
    try testing.expect(BEACON_BLOCK_PARAMS.mesh_message_deliveries_weight < 0.0);
    try testing.expect(BEACON_BLOCK_PARAMS.invalid_message_deliveries_weight < 0.0);
}

test "TopicScoringParams: attestation subnet weight less than block" {
    try testing.expect(ATTESTATION_SUBNET_PARAMS.topic_weight < BEACON_BLOCK_PARAMS.topic_weight);
}

test "PeerScoringThresholds: thresholds are ordered" {
    const t = DEFAULT_PEER_THRESHOLDS;
    // gossip > publish > graylist (less negative = higher)
    try testing.expect(t.gossip_threshold > t.publish_threshold);
    try testing.expect(t.publish_threshold > t.graylist_threshold);
}

test "decayToTarget: decay after n slots equals target" {
    const n: f64 = 100.0;
    const target: f64 = 0.01;
    const decay = decayToTarget(n, target);
    const result = std.math.pow(f64, decay, n);
    // Should be approximately target.
    try testing.expect(@abs(result - target) < 0.0001);
}
