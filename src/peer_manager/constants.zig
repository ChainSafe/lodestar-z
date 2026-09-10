const std = @import("std");

// --- Score Thresholds (port of score/constants.ts) ---

/// The default score for new peers.
pub const DEFAULT_SCORE: f64 = 0;
/// The minimum reputation before a peer is disconnected.
pub const MIN_SCORE_BEFORE_DISCONNECT: f64 = -20;
/// The minimum reputation before a peer is banned.
pub const MIN_SCORE_BEFORE_BAN: f64 = -50;
/// If a peer has a lodestar score below this, all other score parts are ignored
/// and the peer is banned regardless.
pub const MIN_LODESTAR_SCORE_BEFORE_BAN: f64 = -60.0;
/// The maximum score a peer can obtain.
pub const MAX_SCORE: f64 = 100;
/// The minimum score a peer can obtain.
pub const MIN_SCORE: f64 = -100;
/// Drop score if absolute value is below this threshold.
pub const SCORE_THRESHOLD: f64 = 1;
/// The halflife of a peer's score in milliseconds (10 minutes).
pub const SCORE_HALFLIFE_MS: f64 = 10 * 60 * 1000;
/// Precomputed decay constant: -ln(2) / SCORE_HALFLIFE_MS.
pub const HALFLIFE_DECAY_MS: f64 = -@log(2.0) / SCORE_HALFLIFE_MS;
/// Milliseconds to ban a peer before their score begins to decay (30 minutes).
pub const COOL_DOWN_BEFORE_DECAY_MS: i64 = 30 * 60 * 1000;
/// Maximum entries in the scores map.
pub const MAX_SCORE_ENTRIES: u32 = 1000;
/// Returned when no cooldown is applied.
pub const NO_COOL_DOWN_APPLIED: i64 = -1;

// --- Peer Manager Intervals (port of peerManager.ts) ---

/// Ping interval for inbound peers (15 seconds).
pub const PING_INTERVAL_INBOUND_MS: i64 = 15 * 1000;
/// Ping interval for outbound peers (20 seconds).
pub const PING_INTERVAL_OUTBOUND_MS: i64 = 20 * 1000;
/// Status exchange interval (5 minutes).
pub const STATUS_INTERVAL_MS: i64 = 5 * 60 * 1000;
/// Grace period for inbound STATUS (15 seconds).
pub const STATUS_INBOUND_GRACE_PERIOD_MS: i64 = 15 * 1000;
/// A peer is considered long connection if >= 1 day.
pub const LONG_PEER_CONNECTION_MS: i64 = 24 * 60 * 60 * 1000;
/// Recommended heartbeat call interval for NAPI callers (30 seconds).
/// Not used by the Zig module itself (tick-driven).
pub const HEARTBEAT_INTERVAL_MS: i64 = 30 * 1000;
/// Recommended check-ping-status call interval for NAPI callers (10 seconds).
/// Not used by the Zig module itself (tick-driven).
pub const CHECK_PING_STATUS_INTERVAL: i64 = 10 * 1000;

// --- Prioritization Constants (port of prioritizePeers.ts) ---

/// Target number of peers per active long-lived subnet.
pub const TARGET_SUBNET_PEERS: u32 = 6;
/// Target peers per non-sampling custody group (PeerDAS).
pub const TARGET_GROUP_PEERS_PER_SUBNET: u32 = 4;
/// Minimum peers per active sync committee to avoid pruning.
pub const MIN_SYNC_COMMITTEE_PEERS: u32 = 2;
/// Score threshold below which peers are pruned when over target.
pub const LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS: f64 = -2;
/// Overshoot factor for connection attempts (low success rate ~33%).
pub const PEERS_TO_CONNECT_OVERSHOOT_FACTOR: u32 = 3;
/// Minimum ratio of outbound peers to maintain.
pub const OUTBOUND_PEERS_RATIO: f64 = 0.1;
/// Tolerance for remote peer's head slot being ahead of ours.
pub const FUTURE_SLOT_TOLERANCE: u64 = 1;
/// Fraction of peers allowed to have negative gossipsub scores without penalty.
pub const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR: f64 = 0.1;
/// Fraction of additional peers to prune during starvation.
pub const STARVATION_PRUNE_RATIO: f64 = 0.05;

test {
    // Verify the decay constant is computed correctly.
    const expected = -@log(2.0) / (10.0 * 60.0 * 1000.0);
    try std.testing.expectApproxEqAbs(expected, HALFLIFE_DECAY_MS, 1e-20);
}
