//! BeaconMetrics — comprehensive Prometheus metrics for the beacon node.
//!
//! 50+ metrics covering chain state, block processing, state transition,
//! fork choice, attestation pool, P2P, discovery, sync, API, DB,
//! execution layer, and memory/cache internals.
//!
//! All metrics are defined as comptime constants so noop mode (zero overhead)
//! is trivially achievable by calling `initNoop()`.
//!
//! Usage:
//!   // enabled:
//!   var m = BeaconMetrics.init();
//!   m.head_slot.set(42);
//!   m.blocks_imported_total.incr();
//!
//!   // disabled (noop — zero overhead):
//!   var m = BeaconMetrics.initNoop();
//!
//! Prometheus output:
//!   try metrics_lib.write(&m, writer);

const std = @import("std");
const metrics_lib = @import("metrics");

pub const Counter = metrics_lib.Counter;
pub const Gauge = metrics_lib.Gauge;
pub const Histogram = metrics_lib.Histogram;

// Bucket arrays — defined at comptime as module-level constants to be
// referenced in both struct field defaults and init().

const block_import_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const state_transition_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };
const process_block_buckets = [_]f64{ 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0 };
const process_epoch_buckets = [_]f64{ 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0 };
const fork_choice_find_head_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1 };
const reqresp_request_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.5, 1.0, 5.0 };
const api_request_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0 };
const db_read_buckets = [_]f64{ 0.0001, 0.001, 0.005, 0.01, 0.05 };
const db_write_buckets = [_]f64{ 0.0001, 0.001, 0.005, 0.01, 0.05 };
const el_request_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };
const state_regen_buckets = [_]f64{ 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };

/// All beacon node metrics in a single struct.
///
/// Field layout mirrors TypeScript Lodestar categories:
///   - Chain state (head slot, epochs, validators)
///   - Block processing (import count, latency, slot delta)
///   - State transition (stfn, process_block, process_epoch)
///   - Fork choice (reorgs, find_head latency, DAG size)
///   - Attestation pool (pool size, received count)
///   - Network / P2P (peers, gossip, req/resp)
///   - Discovery (known peers, lookups)
///   - Sync (status, distance, pending batches)
///   - API (request count, latency)
///   - DB (read/write latency, block count)
///   - Execution layer (newPayload, forkchoiceUpdated latency)
///   - Memory / internals (cache sizes, hit/miss rates)
pub const BeaconMetrics = struct {
    // ===================================================================
    // Chain
    // ===================================================================

    /// Current canonical head slot.
    head_slot: Gauge(u64),
    /// First 8 bytes of the canonical head block root cast to u64.
    /// Useful for change detection — not a real numeric value.
    head_root: Gauge(u64),
    /// Epoch of the latest finalized checkpoint.
    finalized_epoch: Gauge(u64),
    /// Epoch of the latest justified checkpoint.
    justified_epoch: Gauge(u64),
    /// Number of active validators in the current epoch.
    current_active_validators: Gauge(u64),
    /// Total reorg events detected by the fork choice.
    reorg_events_total: Counter(u64),

    // ===================================================================
    // Block processing
    // ===================================================================

    /// Total blocks successfully imported into the chain.
    blocks_imported_total: Counter(u64),
    /// Histogram of block import latency in seconds.
    block_import_seconds: Histogram(f64, &block_import_buckets),
    /// Slot delta at import time: imported_block_slot - current_head_slot.
    /// Negative means we imported an old block; large positive means we are behind.
    block_slot_delta: Gauge(i64),

    // ===================================================================
    // State transition
    // ===================================================================

    /// Full state-transition latency (processSlots + processBlock) in seconds.
    state_transition_seconds: Histogram(f64, &state_transition_buckets),
    /// processBlock latency (excluding epoch transition) in seconds.
    process_block_seconds: Histogram(f64, &process_block_buckets),
    /// processEpoch latency (epoch transition only) in seconds.
    process_epoch_seconds: Histogram(f64, &process_epoch_buckets),
    /// State regeneration latency in seconds.
    state_regen_seconds: Histogram(f64, &state_regen_buckets),

    // ===================================================================
    // Fork choice
    // ===================================================================

    /// Total times a block was re-processed by fork choice (e.g. orphan recovery).
    fork_choice_reprocessed_total: Counter(u64),
    /// Latency of fork-choice findHead in seconds.
    fork_choice_find_head_seconds: Histogram(f64, &fork_choice_find_head_buckets),
    /// Number of nodes currently in the fork-choice DAG.
    fork_choice_nodes: Gauge(u64),

    // ===================================================================
    // Attestation pool
    // ===================================================================

    /// Current number of attestations in the operation pool.
    attestation_pool_size: Gauge(u64),
    /// Total attestations received (gossip + req/resp).
    attestations_received_total: Counter(u64),

    // ===================================================================
    // Network / P2P
    // ===================================================================

    /// Number of currently connected peers.
    peers_connected: Gauge(u64),
    /// Total peer connection events.
    peer_connected_total: Counter(u64),
    /// Total peer disconnection events.
    peer_disconnected_total: Counter(u64),
    /// Total gossip messages received from the network.
    gossip_messages_received: Counter(u64),
    /// Total gossip messages that passed validation.
    gossip_messages_validated: Counter(u64),
    /// Total gossip messages that failed validation and were rejected.
    gossip_messages_rejected: Counter(u64),
    /// Total gossip messages that were ignored (e.g. duplicates).
    gossip_messages_ignored: Counter(u64),
    /// Total req/resp requests served (all methods combined).
    reqresp_requests_total: Counter(u64),
    /// Histogram of req/resp request handling latency in seconds.
    reqresp_request_seconds: Histogram(f64, &reqresp_request_buckets),

    // ===================================================================
    // Discovery
    // ===================================================================

    /// Total number of peers known to the discovery service (ENR table size).
    discovery_peers_known: Gauge(u64),
    /// Total discovery lookups performed.
    discovery_lookups_total: Counter(u64),

    // ===================================================================
    // Sync
    // ===================================================================

    /// Sync status: 0 = synced, 1 = syncing.
    sync_status: Gauge(u64),
    /// Number of slots between our head and the network head.
    sync_distance: Gauge(u64),
    /// Number of pending sync batches in-flight.
    sync_batches_pending: Gauge(u64),

    // ===================================================================
    // API
    // ===================================================================

    /// Total HTTP requests received by the Beacon REST API.
    api_requests_total: Counter(u64),
    /// Histogram of HTTP API request latency in seconds.
    api_request_seconds: Histogram(f64, &api_request_buckets),

    // ===================================================================
    // DB
    // ===================================================================

    /// Histogram of database read latency in seconds.
    db_read_seconds: Histogram(f64, &db_read_buckets),
    /// Histogram of database write latency in seconds.
    db_write_seconds: Histogram(f64, &db_write_buckets),
    /// Total blocks currently stored in the database.
    db_block_count: Gauge(u64),

    // ===================================================================
    // Execution layer
    // ===================================================================

    /// Histogram of engine_newPayload request latency in seconds.
    execution_new_payload_seconds: Histogram(f64, &el_request_buckets),
    /// Histogram of engine_forkchoiceUpdated request latency in seconds.
    execution_forkchoice_updated_seconds: Histogram(f64, &el_request_buckets),
    /// Histogram of engine_getPayload request latency in seconds.
    execution_get_payload_seconds: Histogram(f64, &el_request_buckets),
    /// Total EL payload status=VALID responses.
    execution_payload_valid_total: Counter(u64),
    /// Total EL payload status=INVALID responses.
    execution_payload_invalid_total: Counter(u64),
    /// Total EL payload status=SYNCING responses.
    execution_payload_syncing_total: Counter(u64),
    /// Total EL request errors (transport / timeout / decode).
    execution_errors_total: Counter(u64),

    // ===================================================================
    // Memory / internals / caches
    // ===================================================================

    /// Number of states currently cached in the BlockStateCache.
    state_cache_size: Gauge(u64),
    /// Total state cache hits.
    state_cache_hit_total: Counter(u64),
    /// Total state cache misses.
    state_cache_miss_total: Counter(u64),
    /// Number of checkpoint epochs currently cached in CheckpointStateCache.
    checkpoint_cache_size: Gauge(u64),
    /// Total shuffling cache hits.
    shuffling_cache_hit_total: Counter(u64),
    /// Total shuffling cache misses.
    shuffling_cache_miss_total: Counter(u64),
    /// Number of PMT pool nodes currently in use.
    pmt_pool_used_nodes: Gauge(u64),

    // -------------------------------------------------------------------
    // Initializer helpers
    // -------------------------------------------------------------------

    /// Create a fully-initialized BeaconMetrics with real metric implementations.
    ///
    /// Every metric is given a stable Prometheus name with the `beacon_` prefix
    /// (except P2P metrics which use `p2p_`).
    pub fn init() BeaconMetrics {
        const ro: metrics_lib.RegistryOpts = .{};
        return .{
            // Chain
            .head_slot = Gauge(u64).init("beacon_head_slot", .{}, ro),
            .head_root = Gauge(u64).init("beacon_head_root", .{}, ro),
            .finalized_epoch = Gauge(u64).init("beacon_finalized_epoch", .{}, ro),
            .justified_epoch = Gauge(u64).init("beacon_justified_epoch", .{}, ro),
            .current_active_validators = Gauge(u64).init("beacon_current_active_validators", .{}, ro),
            .reorg_events_total = Counter(u64).init("beacon_reorg_events_total", .{}, ro),

            // Block processing
            .blocks_imported_total = Counter(u64).init("beacon_blocks_imported_total", .{}, ro),
            .block_import_seconds = Histogram(f64, &block_import_buckets).init("beacon_block_import_seconds", .{}, ro),
            .block_slot_delta = Gauge(i64).init("beacon_block_slot_delta", .{}, ro),

            // State transition
            .state_transition_seconds = Histogram(f64, &state_transition_buckets).init("beacon_state_transition_seconds", .{}, ro),
            .process_block_seconds = Histogram(f64, &process_block_buckets).init("beacon_process_block_seconds", .{}, ro),
            .process_epoch_seconds = Histogram(f64, &process_epoch_buckets).init("beacon_process_epoch_seconds", .{}, ro),
            .state_regen_seconds = Histogram(f64, &state_regen_buckets).init("beacon_state_regen_seconds", .{}, ro),

            // Fork choice
            .fork_choice_reprocessed_total = Counter(u64).init("beacon_fork_choice_reprocessed_total", .{}, ro),
            .fork_choice_find_head_seconds = Histogram(f64, &fork_choice_find_head_buckets).init("beacon_fork_choice_find_head_seconds", .{}, ro),
            .fork_choice_nodes = Gauge(u64).init("beacon_fork_choice_nodes", .{}, ro),

            // Attestation pool
            .attestation_pool_size = Gauge(u64).init("beacon_attestation_pool_size", .{}, ro),
            .attestations_received_total = Counter(u64).init("beacon_attestations_received_total", .{}, ro),

            // Network / P2P
            .peers_connected = Gauge(u64).init("p2p_peer_count", .{}, ro),
            .peer_connected_total = Counter(u64).init("p2p_peer_connected_total", .{}, ro),
            .peer_disconnected_total = Counter(u64).init("p2p_peer_disconnected_total", .{}, ro),
            .gossip_messages_received = Counter(u64).init("beacon_gossip_messages_received_total", .{}, ro),
            .gossip_messages_validated = Counter(u64).init("beacon_gossip_messages_validated_total", .{}, ro),
            .gossip_messages_rejected = Counter(u64).init("beacon_gossip_messages_rejected_total", .{}, ro),
            .gossip_messages_ignored = Counter(u64).init("beacon_gossip_messages_ignored_total", .{}, ro),
            .reqresp_requests_total = Counter(u64).init("beacon_reqresp_requests_total", .{}, ro),
            .reqresp_request_seconds = Histogram(f64, &reqresp_request_buckets).init("beacon_reqresp_request_seconds", .{}, ro),

            // Discovery
            .discovery_peers_known = Gauge(u64).init("beacon_discovery_peers_known", .{}, ro),
            .discovery_lookups_total = Counter(u64).init("beacon_discovery_lookups_total", .{}, ro),

            // Sync
            .sync_status = Gauge(u64).init("beacon_sync_status", .{}, ro),
            .sync_distance = Gauge(u64).init("beacon_sync_distance", .{}, ro),
            .sync_batches_pending = Gauge(u64).init("beacon_sync_batches_pending", .{}, ro),

            // API
            .api_requests_total = Counter(u64).init("beacon_api_requests_total", .{}, ro),
            .api_request_seconds = Histogram(f64, &api_request_buckets).init("beacon_api_request_seconds", .{}, ro),

            // DB
            .db_read_seconds = Histogram(f64, &db_read_buckets).init("beacon_db_read_seconds", .{}, ro),
            .db_write_seconds = Histogram(f64, &db_write_buckets).init("beacon_db_write_seconds", .{}, ro),
            .db_block_count = Gauge(u64).init("beacon_db_block_count", .{}, ro),

            // Execution layer
            .execution_new_payload_seconds = Histogram(f64, &el_request_buckets).init("execution_new_payload_seconds", .{}, ro),
            .execution_forkchoice_updated_seconds = Histogram(f64, &el_request_buckets).init("execution_forkchoice_updated_seconds", .{}, ro),
            .execution_get_payload_seconds = Histogram(f64, &el_request_buckets).init("execution_get_payload_seconds", .{}, ro),
            .execution_payload_valid_total = Counter(u64).init("execution_payload_valid_total", .{}, ro),
            .execution_payload_invalid_total = Counter(u64).init("execution_payload_invalid_total", .{}, ro),
            .execution_payload_syncing_total = Counter(u64).init("execution_payload_syncing_total", .{}, ro),
            .execution_errors_total = Counter(u64).init("execution_errors_total", .{}, ro),

            // Memory / internals
            .state_cache_size = Gauge(u64).init("beacon_state_cache_size", .{}, ro),
            .state_cache_hit_total = Counter(u64).init("beacon_state_cache_hit_total", .{}, ro),
            .state_cache_miss_total = Counter(u64).init("beacon_state_cache_miss_total", .{}, ro),
            .checkpoint_cache_size = Gauge(u64).init("beacon_checkpoint_cache_size", .{}, ro),
            .shuffling_cache_hit_total = Counter(u64).init("beacon_shuffling_cache_hit_total", .{}, ro),
            .shuffling_cache_miss_total = Counter(u64).init("beacon_shuffling_cache_miss_total", .{}, ro),
            .pmt_pool_used_nodes = Gauge(u64).init("beacon_pmt_pool_used_nodes", .{}, ro),
        };
    }

    /// Create a noop BeaconMetrics instance — all metrics are zero-overhead stubs.
    ///
    /// Use this when `--metrics` is not passed on the CLI.
    pub fn initNoop() BeaconMetrics {
        return metrics_lib.initializeNoop(BeaconMetrics);
    }

    /// Write all metrics in Prometheus text exposition format to `writer`.
    pub fn write(self: *BeaconMetrics, writer: *std.Io.Writer) !void {
        try metrics_lib.write(self, writer);
    }
};

test "BeaconMetrics: init fields are accessible" {
    var m = BeaconMetrics.init();
    m.head_slot.set(42);
    m.blocks_imported_total.incr();
    m.peers_connected.set(10);
    m.reqresp_request_seconds.observe(0.05);
    m.execution_new_payload_seconds.observe(0.1);
    m.peer_connected_total.incr();
    m.state_cache_hit_total.incr();
    // Verify no panics and basic values are set.
    try std.testing.expectEqual(@as(u64, 42), m.head_slot.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.blocks_imported_total.impl.count);
    try std.testing.expectEqual(@as(u64, 10), m.peers_connected.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.peer_connected_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.state_cache_hit_total.impl.count);
}

test "BeaconMetrics: initNoop produces zero-overhead stubs" {
    // Should compile and not panic.
    var m = BeaconMetrics.initNoop();
    m.head_slot.set(999);
    m.blocks_imported_total.incr();
    m.execution_new_payload_seconds.observe(1.0);
    m.peer_connected_total.incr();
    m.state_cache_hit_total.incr();
    // Noop: the union tag is .noop so no values are stored.
    try std.testing.expect(std.meta.activeTag(m.head_slot) == .noop);
    try std.testing.expect(std.meta.activeTag(m.blocks_imported_total) == .noop);
    try std.testing.expect(std.meta.activeTag(m.execution_new_payload_seconds) == .noop);
}

test "BeaconMetrics: write produces Prometheus output" {
    var m = BeaconMetrics.init();
    m.head_slot.set(100);
    m.finalized_epoch.set(3);
    m.blocks_imported_total.incr();
    m.blocks_imported_total.incr();
    m.execution_new_payload_seconds.observe(0.5);
    m.peer_connected_total.incr();
    m.state_cache_hit_total.incr();

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_finalized_epoch") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_blocks_imported_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_new_payload_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_forkchoice_updated_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_connected_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_cache_hit_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_shuffling_cache_hit_total") != null);
}
