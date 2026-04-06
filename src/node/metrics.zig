//! Beacon metrics that are actually emitted by the live beacon-node runtime.
//!
//! The surface here is intentionally small and honest. If a metric is not wired
//! through a real runtime path, it should not be exported from this module.

const std = @import("std");
const metrics_lib = @import("metrics");
const api_mod = @import("api");
const db = @import("db");
const fork_choice = @import("fork_choice");
const networking = @import("networking");
const state_transition = @import("state_transition");

pub const Counter = metrics_lib.Counter;
pub const CounterVec = metrics_lib.CounterVec;
pub const Gauge = metrics_lib.Gauge;
pub const GaugeVec = metrics_lib.GaugeVec;
pub const Histogram = metrics_lib.Histogram;
pub const HistogramVec = metrics_lib.HistogramVec;

const ApiOperationLabels = struct {
    operation_id: []const u8,
};

const BlockImportSourceLabels = struct {
    source: []const u8,
};

const BlockImportOutcomeLabels = struct {
    source: []const u8,
    outcome: []const u8,
};

const ReqRespMethodLabels = struct {
    method: []const u8,
};

const ReqRespMethodOutcomeLabels = struct {
    method: []const u8,
    outcome: []const u8,
};

const PeerDirectionLabels = struct {
    direction: []const u8,
};

const PeerConnectionStateLabels = struct {
    state: []const u8,
};

const PeerScoreStateLabels = struct {
    state: []const u8,
};

const PeerRelevanceStatusLabels = struct {
    status: []const u8,
};

const PeerReportLabels = struct {
    source: []const u8,
    action: []const u8,
};

const PeerGoodbyeLabels = struct {
    reason: []const u8,
};

const DatabaseLabels = struct {
    database: []const u8,
};

pub const MetricsSurface = struct {
    beacon: *BeaconMetrics,
    state_transition: *state_transition.metrics.StateTransitionMetrics = state_transition.metrics.noop(),

    pub fn write(self: *MetricsSurface, writer: *std.Io.Writer) !void {
        try self.beacon.write(writer);
        if (self.state_transition.isEnabled()) {
            try writer.writeByte('\n');
            try self.state_transition.write(writer);
        }
    }
};

const block_import_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const el_request_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };
const api_request_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const api_stream_buckets = [_]f64{ 0.1, 0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 300.0 };
const req_resp_request_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };

pub const BeaconMetrics = struct {
    // Chain state.
    head_slot: Gauge(u64),
    head_root: Gauge(u64),
    finalized_epoch: Gauge(u64),
    justified_epoch: Gauge(u64),

    // Block import.
    blocks_imported_total: Counter(u64),
    block_import_seconds: Histogram(f64, &block_import_buckets),
    block_import_source_seconds: HistogramVec(f64, BlockImportSourceLabels, &block_import_buckets),
    block_import_results_total: CounterVec(u64, BlockImportOutcomeLabels),
    block_import_optimistic_total: Counter(u64),
    epoch_transitions_total: Counter(u64),
    chain_reorgs_total: Counter(u64),
    chain_reorg_depth_slots_total: Counter(u64),
    chain_reorg_last_depth: Gauge(u64),

    // Network / P2P.
    known_peers: Gauge(u64),
    peers_connected: Gauge(u64),
    connected_peer_direction_count: GaugeVec(u64, PeerDirectionLabels),
    peer_connection_state_count: GaugeVec(u64, PeerConnectionStateLabels),
    peer_score_state_count: GaugeVec(u64, PeerScoreStateLabels),
    peer_relevance_count: GaugeVec(u64, PeerRelevanceStatusLabels),
    peer_connected_total: Counter(u64),
    peer_disconnected_total: Counter(u64),
    peer_reports_total: CounterVec(u64, PeerReportLabels),
    peer_goodbye_received_total: CounterVec(u64, PeerGoodbyeLabels),
    api_active_connections: Gauge(u64),
    api_requests_total: CounterVec(u64, ApiOperationLabels),
    api_errors_total: CounterVec(u64, ApiOperationLabels),
    api_request_seconds: HistogramVec(f64, ApiOperationLabels, &api_request_buckets),
    api_stream_seconds: HistogramVec(f64, ApiOperationLabels, &api_stream_buckets),
    req_resp_inbound_limiter_peers: Gauge(u64),
    req_resp_outbound_limiter_peers: Gauge(u64),
    req_resp_inbound_requests_total: CounterVec(u64, ReqRespMethodOutcomeLabels),
    req_resp_outbound_requests_total: CounterVec(u64, ReqRespMethodOutcomeLabels),
    req_resp_inbound_request_seconds: HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets),
    req_resp_outbound_request_seconds: HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets),
    gossip_messages_received: Counter(u64),
    gossip_messages_validated: Counter(u64),
    gossip_messages_rejected: Counter(u64),
    gossip_messages_ignored: Counter(u64),

    // Discovery / sync.
    discovery_peers_known: Gauge(u64),
    sync_status: Gauge(u64),
    sync_distance: Gauge(u64),
    sync_optimistic: Gauge(u64),
    sync_el_offline: Gauge(u64),

    // Chain runtime / caches / pools.
    block_state_cache_entries: Gauge(u64),
    checkpoint_state_cache_entries: Gauge(u64),
    checkpoint_state_datastore_entries: Gauge(u64),
    state_regen_cache_hits_total: Counter(u64),
    state_regen_queue_hits_total: Counter(u64),
    state_regen_dropped_total: Counter(u64),
    state_regen_queue_length: Gauge(u64),
    forkchoice_nodes: Gauge(u64),
    forkchoice_block_roots: Gauge(u64),
    forkchoice_votes: Gauge(u64),
    forkchoice_queued_attestation_slots: Gauge(u64),
    forkchoice_queued_attestations_previous_slot: Gauge(u64),
    forkchoice_validated_attestation_data_roots: Gauge(u64),
    forkchoice_equivocating_validators: Gauge(u64),
    forkchoice_proposer_boost_active: Gauge(u64),
    archive_last_finalized_slot: Gauge(u64),
    archive_last_archived_state_epoch: Gauge(u64),
    archive_finalized_slot_lag: Gauge(u64),
    archive_runs_total: Counter(u64),
    archive_failures_total: Counter(u64),
    archive_finalized_slots_advanced_total: Counter(u64),
    archive_state_epochs_archived_total: Counter(u64),
    archive_run_milliseconds_total: Counter(u64),
    archive_last_slots_advanced: Gauge(u64),
    archive_last_batch_ops: Gauge(u64),
    archive_last_run_milliseconds: Gauge(u64),
    validator_monitor_monitored_validators: Gauge(u64),
    validator_monitor_last_processed_epoch: Gauge(u64),
    validator_monitor_epoch_lag: Gauge(u64),
    db_total_entries: Gauge(u64),
    db_entries: GaugeVec(u64, DatabaseLabels),
    db_lmdb_map_size_bytes: Gauge(u64),
    db_lmdb_data_size_bytes: Gauge(u64),
    db_lmdb_page_size_bytes: Gauge(u64),
    db_lmdb_last_page_number: Gauge(u64),
    db_lmdb_last_txnid: Gauge(u64),
    db_lmdb_readers_used: Gauge(u64),
    db_lmdb_readers_max: Gauge(u64),
    attestation_pool_groups: Gauge(u64),
    aggregate_attestation_pool_groups: Gauge(u64),
    aggregate_attestation_pool_entries: Gauge(u64),
    voluntary_exit_pool_size: Gauge(u64),
    proposer_slashing_pool_size: Gauge(u64),
    attester_slashing_pool_size: Gauge(u64),
    bls_to_execution_change_pool_size: Gauge(u64),
    sync_committee_message_pool_size: Gauge(u64),
    sync_contribution_pool_size: Gauge(u64),
    proposer_cache_entries: Gauge(u64),
    pending_block_ingress_size: Gauge(u64),
    pending_block_ingress_added_total: Counter(u64),
    pending_block_ingress_replaced_total: Counter(u64),
    pending_block_ingress_resolved_total: Counter(u64),
    pending_block_ingress_removed_total: Counter(u64),
    pending_block_ingress_pruned_total: Counter(u64),
    pending_payload_envelope_ingress_size: Gauge(u64),
    pending_payload_envelope_ingress_added_total: Counter(u64),
    pending_payload_envelope_ingress_replaced_total: Counter(u64),
    pending_payload_envelope_ingress_removed_total: Counter(u64),
    pending_payload_envelope_ingress_pruned_total: Counter(u64),
    reprocess_queue_size: Gauge(u64),
    reprocess_queued_total: Counter(u64),
    reprocess_released_total: Counter(u64),
    reprocess_dropped_total: Counter(u64),
    reprocess_pruned_total: Counter(u64),
    da_blob_tracker_entries: Gauge(u64),
    da_column_tracker_entries: Gauge(u64),
    da_pending_blocks: Gauge(u64),
    da_pending_marked_total: Counter(u64),
    da_pending_resolved_total: Counter(u64),
    da_pending_pruned_total: Counter(u64),

    // Execution layer.
    execution_new_payload_seconds: Histogram(f64, &el_request_buckets),
    execution_forkchoice_updated_seconds: Histogram(f64, &el_request_buckets),
    execution_payload_valid_total: Counter(u64),
    execution_payload_invalid_total: Counter(u64),
    execution_payload_syncing_total: Counter(u64),
    execution_errors_total: Counter(u64),
    execution_pending_forkchoice_updates: Gauge(u64),
    execution_pending_payload_verifications: Gauge(u64),
    execution_completed_forkchoice_updates: Gauge(u64),
    execution_completed_payload_verifications: Gauge(u64),
    execution_failed_payload_preparations: Gauge(u64),
    execution_cached_payload: Gauge(u64),
    execution_offline: Gauge(u64),

    pub fn init(allocator: std.mem.Allocator) !BeaconMetrics {
        const ro: metrics_lib.RegistryOpts = .{};
        return .{
            .head_slot = Gauge(u64).init("beacon_head_slot", .{}, ro),
            .head_root = Gauge(u64).init("beacon_head_root", .{}, ro),
            .finalized_epoch = Gauge(u64).init("beacon_finalized_epoch", .{}, ro),
            .justified_epoch = Gauge(u64).init("beacon_justified_epoch", .{}, ro),

            .blocks_imported_total = Counter(u64).init("beacon_blocks_imported_total", .{}, ro),
            .block_import_seconds = Histogram(f64, &block_import_buckets).init("beacon_block_import_seconds", .{}, ro),
            .block_import_source_seconds = try HistogramVec(f64, BlockImportSourceLabels, &block_import_buckets).init(
                allocator,
                "beacon_block_import_source_seconds",
                .{},
                ro,
            ),
            .block_import_results_total = try CounterVec(u64, BlockImportOutcomeLabels).init(
                allocator,
                "beacon_block_import_results_total",
                .{},
                ro,
            ),
            .block_import_optimistic_total = Counter(u64).init("beacon_block_import_optimistic_total", .{}, ro),
            .epoch_transitions_total = Counter(u64).init("beacon_epoch_transitions_total", .{}, ro),
            .chain_reorgs_total = Counter(u64).init("beacon_chain_reorgs_total", .{}, ro),
            .chain_reorg_depth_slots_total = Counter(u64).init("beacon_chain_reorg_depth_slots_total", .{}, ro),
            .chain_reorg_last_depth = Gauge(u64).init("beacon_chain_reorg_last_depth", .{}, ro),

            .known_peers = Gauge(u64).init("p2p_known_peer_count", .{}, ro),
            .peers_connected = Gauge(u64).init("p2p_peer_count", .{}, ro),
            .connected_peer_direction_count = try GaugeVec(u64, PeerDirectionLabels).init(
                allocator,
                "p2p_connected_peer_direction_count",
                .{},
                ro,
            ),
            .peer_connection_state_count = try GaugeVec(u64, PeerConnectionStateLabels).init(
                allocator,
                "p2p_peer_connection_state_count",
                .{},
                ro,
            ),
            .peer_score_state_count = try GaugeVec(u64, PeerScoreStateLabels).init(
                allocator,
                "p2p_peer_score_state_count",
                .{},
                ro,
            ),
            .peer_relevance_count = try GaugeVec(u64, PeerRelevanceStatusLabels).init(
                allocator,
                "p2p_peer_relevance_count",
                .{},
                ro,
            ),
            .peer_connected_total = Counter(u64).init("p2p_peer_connected_total", .{}, ro),
            .peer_disconnected_total = Counter(u64).init("p2p_peer_disconnected_total", .{}, ro),
            .peer_reports_total = try CounterVec(u64, PeerReportLabels).init(
                allocator,
                "p2p_peer_reports_total",
                .{},
                ro,
            ),
            .peer_goodbye_received_total = try CounterVec(u64, PeerGoodbyeLabels).init(
                allocator,
                "p2p_peer_goodbye_received_total",
                .{},
                ro,
            ),
            .api_active_connections = Gauge(u64).init("beacon_api_active_connections", .{}, ro),
            .api_requests_total = try CounterVec(u64, ApiOperationLabels).init(
                allocator,
                "beacon_api_requests_total",
                .{},
                ro,
            ),
            .api_errors_total = try CounterVec(u64, ApiOperationLabels).init(
                allocator,
                "beacon_api_errors_total",
                .{},
                ro,
            ),
            .api_request_seconds = try HistogramVec(f64, ApiOperationLabels, &api_request_buckets).init(
                allocator,
                "beacon_api_request_seconds",
                .{},
                ro,
            ),
            .api_stream_seconds = try HistogramVec(f64, ApiOperationLabels, &api_stream_buckets).init(
                allocator,
                "beacon_api_stream_seconds",
                .{},
                ro,
            ),
            .req_resp_inbound_limiter_peers = Gauge(u64).init("beacon_reqresp_inbound_limiter_peers", .{}, ro),
            .req_resp_outbound_limiter_peers = Gauge(u64).init("beacon_reqresp_outbound_limiter_peers", .{}, ro),
            .req_resp_inbound_requests_total = try CounterVec(u64, ReqRespMethodOutcomeLabels).init(
                allocator,
                "beacon_reqresp_inbound_requests_total",
                .{},
                ro,
            ),
            .req_resp_outbound_requests_total = try CounterVec(u64, ReqRespMethodOutcomeLabels).init(
                allocator,
                "beacon_reqresp_outbound_requests_total",
                .{},
                ro,
            ),
            .req_resp_inbound_request_seconds = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets).init(
                allocator,
                "beacon_reqresp_inbound_request_seconds",
                .{},
                ro,
            ),
            .req_resp_outbound_request_seconds = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets).init(
                allocator,
                "beacon_reqresp_outbound_request_seconds",
                .{},
                ro,
            ),
            .gossip_messages_received = Counter(u64).init("beacon_gossip_messages_received_total", .{}, ro),
            .gossip_messages_validated = Counter(u64).init("beacon_gossip_messages_validated_total", .{}, ro),
            .gossip_messages_rejected = Counter(u64).init("beacon_gossip_messages_rejected_total", .{}, ro),
            .gossip_messages_ignored = Counter(u64).init("beacon_gossip_messages_ignored_total", .{}, ro),

            .discovery_peers_known = Gauge(u64).init("beacon_discovery_peers_known", .{}, ro),
            .sync_status = Gauge(u64).init("beacon_sync_status", .{}, ro),
            .sync_distance = Gauge(u64).init("beacon_sync_distance", .{}, ro),
            .sync_optimistic = Gauge(u64).init("beacon_sync_optimistic", .{}, ro),
            .sync_el_offline = Gauge(u64).init("beacon_sync_el_offline", .{}, ro),

            .block_state_cache_entries = Gauge(u64).init("beacon_block_state_cache_entries", .{}, ro),
            .checkpoint_state_cache_entries = Gauge(u64).init("beacon_checkpoint_state_cache_entries", .{}, ro),
            .checkpoint_state_datastore_entries = Gauge(u64).init("beacon_checkpoint_state_datastore_entries", .{}, ro),
            .state_regen_cache_hits_total = Counter(u64).init("beacon_state_regen_cache_hits_total", .{}, ro),
            .state_regen_queue_hits_total = Counter(u64).init("beacon_state_regen_queue_hits_total", .{}, ro),
            .state_regen_dropped_total = Counter(u64).init("beacon_state_regen_dropped_total", .{}, ro),
            .state_regen_queue_length = Gauge(u64).init("beacon_state_regen_queue_length", .{}, ro),
            .forkchoice_nodes = Gauge(u64).init("beacon_forkchoice_nodes", .{}, ro),
            .forkchoice_block_roots = Gauge(u64).init("beacon_forkchoice_block_roots", .{}, ro),
            .forkchoice_votes = Gauge(u64).init("beacon_forkchoice_votes", .{}, ro),
            .forkchoice_queued_attestation_slots = Gauge(u64).init("beacon_forkchoice_queued_attestation_slots", .{}, ro),
            .forkchoice_queued_attestations_previous_slot = Gauge(u64).init("beacon_forkchoice_queued_attestations_previous_slot", .{}, ro),
            .forkchoice_validated_attestation_data_roots = Gauge(u64).init("beacon_forkchoice_validated_attestation_data_roots", .{}, ro),
            .forkchoice_equivocating_validators = Gauge(u64).init("beacon_forkchoice_equivocating_validators", .{}, ro),
            .forkchoice_proposer_boost_active = Gauge(u64).init("beacon_forkchoice_proposer_boost_active", .{}, ro),
            .archive_last_finalized_slot = Gauge(u64).init("beacon_archive_last_finalized_slot", .{}, ro),
            .archive_last_archived_state_epoch = Gauge(u64).init("beacon_archive_last_archived_state_epoch", .{}, ro),
            .archive_finalized_slot_lag = Gauge(u64).init("beacon_archive_finalized_slot_lag", .{}, ro),
            .archive_runs_total = Counter(u64).init("beacon_archive_runs_total", .{}, ro),
            .archive_failures_total = Counter(u64).init("beacon_archive_failures_total", .{}, ro),
            .archive_finalized_slots_advanced_total = Counter(u64).init("beacon_archive_finalized_slots_advanced_total", .{}, ro),
            .archive_state_epochs_archived_total = Counter(u64).init("beacon_archive_state_epochs_archived_total", .{}, ro),
            .archive_run_milliseconds_total = Counter(u64).init("beacon_archive_run_milliseconds_total", .{}, ro),
            .archive_last_slots_advanced = Gauge(u64).init("beacon_archive_last_slots_advanced", .{}, ro),
            .archive_last_batch_ops = Gauge(u64).init("beacon_archive_last_batch_ops", .{}, ro),
            .archive_last_run_milliseconds = Gauge(u64).init("beacon_archive_last_run_milliseconds", .{}, ro),
            .validator_monitor_monitored_validators = Gauge(u64).init("beacon_validator_monitor_monitored_validators", .{}, ro),
            .validator_monitor_last_processed_epoch = Gauge(u64).init("beacon_validator_monitor_last_processed_epoch", .{}, ro),
            .validator_monitor_epoch_lag = Gauge(u64).init("beacon_validator_monitor_epoch_lag", .{}, ro),
            .db_total_entries = Gauge(u64).init("beacon_db_total_entries", .{}, ro),
            .db_entries = try GaugeVec(u64, DatabaseLabels).init(
                allocator,
                "beacon_db_entries",
                .{},
                ro,
            ),
            .db_lmdb_map_size_bytes = Gauge(u64).init("beacon_db_lmdb_map_size_bytes", .{}, ro),
            .db_lmdb_data_size_bytes = Gauge(u64).init("beacon_db_lmdb_data_size_bytes", .{}, ro),
            .db_lmdb_page_size_bytes = Gauge(u64).init("beacon_db_lmdb_page_size_bytes", .{}, ro),
            .db_lmdb_last_page_number = Gauge(u64).init("beacon_db_lmdb_last_page_number", .{}, ro),
            .db_lmdb_last_txnid = Gauge(u64).init("beacon_db_lmdb_last_txnid", .{}, ro),
            .db_lmdb_readers_used = Gauge(u64).init("beacon_db_lmdb_readers_used", .{}, ro),
            .db_lmdb_readers_max = Gauge(u64).init("beacon_db_lmdb_readers_max", .{}, ro),
            .attestation_pool_groups = Gauge(u64).init("beacon_attestation_pool_groups", .{}, ro),
            .aggregate_attestation_pool_groups = Gauge(u64).init("beacon_aggregate_attestation_pool_groups", .{}, ro),
            .aggregate_attestation_pool_entries = Gauge(u64).init("beacon_aggregate_attestation_pool_entries", .{}, ro),
            .voluntary_exit_pool_size = Gauge(u64).init("beacon_voluntary_exit_pool_size", .{}, ro),
            .proposer_slashing_pool_size = Gauge(u64).init("beacon_proposer_slashing_pool_size", .{}, ro),
            .attester_slashing_pool_size = Gauge(u64).init("beacon_attester_slashing_pool_size", .{}, ro),
            .bls_to_execution_change_pool_size = Gauge(u64).init("beacon_bls_to_execution_change_pool_size", .{}, ro),
            .sync_committee_message_pool_size = Gauge(u64).init("beacon_sync_committee_message_pool_size", .{}, ro),
            .sync_contribution_pool_size = Gauge(u64).init("beacon_sync_contribution_pool_size", .{}, ro),
            .proposer_cache_entries = Gauge(u64).init("beacon_proposer_cache_entries", .{}, ro),
            .pending_block_ingress_size = Gauge(u64).init("beacon_pending_block_ingress_size", .{}, ro),
            .pending_block_ingress_added_total = Counter(u64).init("beacon_pending_block_ingress_added_total", .{}, ro),
            .pending_block_ingress_replaced_total = Counter(u64).init("beacon_pending_block_ingress_replaced_total", .{}, ro),
            .pending_block_ingress_resolved_total = Counter(u64).init("beacon_pending_block_ingress_resolved_total", .{}, ro),
            .pending_block_ingress_removed_total = Counter(u64).init("beacon_pending_block_ingress_removed_total", .{}, ro),
            .pending_block_ingress_pruned_total = Counter(u64).init("beacon_pending_block_ingress_pruned_total", .{}, ro),
            .pending_payload_envelope_ingress_size = Gauge(u64).init("beacon_pending_payload_envelope_ingress_size", .{}, ro),
            .pending_payload_envelope_ingress_added_total = Counter(u64).init("beacon_pending_payload_envelope_ingress_added_total", .{}, ro),
            .pending_payload_envelope_ingress_replaced_total = Counter(u64).init("beacon_pending_payload_envelope_ingress_replaced_total", .{}, ro),
            .pending_payload_envelope_ingress_removed_total = Counter(u64).init("beacon_pending_payload_envelope_ingress_removed_total", .{}, ro),
            .pending_payload_envelope_ingress_pruned_total = Counter(u64).init("beacon_pending_payload_envelope_ingress_pruned_total", .{}, ro),
            .reprocess_queue_size = Gauge(u64).init("beacon_reprocess_queue_size", .{}, ro),
            .reprocess_queued_total = Counter(u64).init("beacon_reprocess_queued_total", .{}, ro),
            .reprocess_released_total = Counter(u64).init("beacon_reprocess_released_total", .{}, ro),
            .reprocess_dropped_total = Counter(u64).init("beacon_reprocess_dropped_total", .{}, ro),
            .reprocess_pruned_total = Counter(u64).init("beacon_reprocess_pruned_total", .{}, ro),
            .da_blob_tracker_entries = Gauge(u64).init("beacon_da_blob_tracker_entries", .{}, ro),
            .da_column_tracker_entries = Gauge(u64).init("beacon_da_column_tracker_entries", .{}, ro),
            .da_pending_blocks = Gauge(u64).init("beacon_da_pending_blocks", .{}, ro),
            .da_pending_marked_total = Counter(u64).init("beacon_da_pending_marked_total", .{}, ro),
            .da_pending_resolved_total = Counter(u64).init("beacon_da_pending_resolved_total", .{}, ro),
            .da_pending_pruned_total = Counter(u64).init("beacon_da_pending_pruned_total", .{}, ro),

            .execution_new_payload_seconds = Histogram(f64, &el_request_buckets).init("execution_new_payload_seconds", .{}, ro),
            .execution_forkchoice_updated_seconds = Histogram(f64, &el_request_buckets).init("execution_forkchoice_updated_seconds", .{}, ro),
            .execution_payload_valid_total = Counter(u64).init("execution_payload_valid_total", .{}, ro),
            .execution_payload_invalid_total = Counter(u64).init("execution_payload_invalid_total", .{}, ro),
            .execution_payload_syncing_total = Counter(u64).init("execution_payload_syncing_total", .{}, ro),
            .execution_errors_total = Counter(u64).init("execution_errors_total", .{}, ro),
            .execution_pending_forkchoice_updates = Gauge(u64).init("execution_pending_forkchoice_updates", .{}, ro),
            .execution_pending_payload_verifications = Gauge(u64).init("execution_pending_payload_verifications", .{}, ro),
            .execution_completed_forkchoice_updates = Gauge(u64).init("execution_completed_forkchoice_updates", .{}, ro),
            .execution_completed_payload_verifications = Gauge(u64).init("execution_completed_payload_verifications", .{}, ro),
            .execution_failed_payload_preparations = Gauge(u64).init("execution_failed_payload_preparations", .{}, ro),
            .execution_cached_payload = Gauge(u64).init("execution_cached_payload", .{}, ro),
            .execution_offline = Gauge(u64).init("execution_offline", .{}, ro),
        };
    }

    pub fn initNoop() BeaconMetrics {
        return metrics_lib.initializeNoop(BeaconMetrics);
    }

    pub fn deinit(self: *BeaconMetrics) void {
        self.block_import_source_seconds.deinit();
        self.block_import_results_total.deinit();
        self.connected_peer_direction_count.deinit();
        self.peer_connection_state_count.deinit();
        self.peer_score_state_count.deinit();
        self.peer_relevance_count.deinit();
        self.peer_reports_total.deinit();
        self.peer_goodbye_received_total.deinit();
        self.db_entries.deinit();
        self.api_requests_total.deinit();
        self.api_errors_total.deinit();
        self.api_request_seconds.deinit();
        self.api_stream_seconds.deinit();
        self.req_resp_inbound_requests_total.deinit();
        self.req_resp_outbound_requests_total.deinit();
        self.req_resp_inbound_request_seconds.deinit();
        self.req_resp_outbound_request_seconds.deinit();
    }

    pub fn write(self: *BeaconMetrics, writer: *std.Io.Writer) !void {
        try metrics_lib.write(self, writer);
    }

    pub fn setApiActiveConnections(self: *BeaconMetrics, active_connections: u32) void {
        self.api_active_connections.set(active_connections);
    }

    pub fn setPeerManagerSnapshot(
        self: *BeaconMetrics,
        snapshot: networking.PeerManagerMetricsSnapshot,
    ) void {
        self.known_peers.set(snapshot.known_peers);
        self.peers_connected.set(snapshot.connected_peers);
        self.connected_peer_direction_count.set(.{ .direction = peerDirectionLabel(.inbound) }, snapshot.inbound_connected_peers) catch {};
        self.connected_peer_direction_count.set(.{ .direction = peerDirectionLabel(.outbound) }, snapshot.outbound_connected_peers) catch {};

        inline for (networking.peer_manager.metric_connection_states) |state| {
            self.peer_connection_state_count.set(
                .{ .state = connectionStateLabel(state) },
                snapshot.connectionStateCount(state),
            ) catch {};
        }

        inline for (networking.peer_manager.metric_score_states) |state| {
            self.peer_score_state_count.set(
                .{ .state = scoreStateLabel(state) },
                snapshot.scoreStateCount(state),
            ) catch {};
        }

        inline for (networking.peer_manager.metric_relevance_states) |status| {
            self.peer_relevance_count.set(
                .{ .status = relevanceStatusLabel(status) },
                snapshot.relevanceCount(status),
            ) catch {};
        }
    }

    pub fn setForkChoiceSnapshot(
        self: *BeaconMetrics,
        snapshot: fork_choice.MetricsSnapshot,
    ) void {
        self.forkchoice_nodes.set(snapshot.proto_array_nodes);
        self.forkchoice_block_roots.set(snapshot.proto_array_block_roots);
        self.forkchoice_votes.set(snapshot.votes);
        self.forkchoice_queued_attestation_slots.set(snapshot.queued_attestation_slots);
        self.forkchoice_queued_attestations_previous_slot.set(snapshot.queued_attestations_previous_slot);
        self.forkchoice_validated_attestation_data_roots.set(snapshot.validated_attestation_data_roots);
        self.forkchoice_equivocating_validators.set(snapshot.equivocating_validators);
        self.forkchoice_proposer_boost_active.set(if (snapshot.proposer_boost_active) 1 else 0);
    }

    pub fn setSyncSnapshot(
        self: *BeaconMetrics,
        sync_status: u64,
        sync_distance: u64,
        sync_optimistic: bool,
        sync_el_offline: bool,
    ) void {
        self.sync_status.set(sync_status);
        self.sync_distance.set(sync_distance);
        self.sync_optimistic.set(if (sync_optimistic) 1 else 0);
        self.sync_el_offline.set(if (sync_el_offline) 1 else 0);
    }

    pub fn setArchiveProgress(
        self: *BeaconMetrics,
        last_finalized_slot: u64,
        last_archived_state_epoch: u64,
    ) void {
        self.archive_last_finalized_slot.set(last_finalized_slot);
        self.archive_last_archived_state_epoch.set(last_archived_state_epoch);
    }

    pub fn setValidatorMonitorSnapshot(
        self: *BeaconMetrics,
        monitored_validators: u64,
        last_processed_epoch: u64,
    ) void {
        self.validator_monitor_monitored_validators.set(monitored_validators);
        self.validator_monitor_last_processed_epoch.set(last_processed_epoch);
    }

    pub fn setProgressLag(
        self: *BeaconMetrics,
        archive_finalized_slot_lag: u64,
        validator_monitor_epoch_lag: u64,
    ) void {
        self.archive_finalized_slot_lag.set(archive_finalized_slot_lag);
        self.validator_monitor_epoch_lag.set(validator_monitor_epoch_lag);
    }

    pub fn setArchiveOperationalSnapshot(
        self: *BeaconMetrics,
        last_slots_advanced: u64,
        last_batch_ops: u64,
        last_run_milliseconds: u64,
    ) void {
        self.archive_last_slots_advanced.set(last_slots_advanced);
        self.archive_last_batch_ops.set(last_batch_ops);
        self.archive_last_run_milliseconds.set(last_run_milliseconds);
    }

    pub fn incrArchiveRuns(self: *BeaconMetrics, count: u64) void {
        self.archive_runs_total.incrBy(count);
    }

    pub fn incrArchiveFailures(self: *BeaconMetrics, count: u64) void {
        self.archive_failures_total.incrBy(count);
    }

    pub fn incrArchiveFinalizedSlotsAdvanced(self: *BeaconMetrics, count: u64) void {
        self.archive_finalized_slots_advanced_total.incrBy(count);
    }

    pub fn incrArchiveStateEpochsArchived(self: *BeaconMetrics, count: u64) void {
        self.archive_state_epochs_archived_total.incrBy(count);
    }

    pub fn incrArchiveRunMilliseconds(self: *BeaconMetrics, count: u64) void {
        self.archive_run_milliseconds_total.incrBy(count);
    }

    pub fn observeImportedBlocks(
        self: *BeaconMetrics,
        source: []const u8,
        count: u64,
        elapsed_seconds: f64,
    ) void {
        if (count == 0) return;

        self.blocks_imported_total.incrBy(count);
        self.block_import_seconds.observe(elapsed_seconds);
        self.block_import_source_seconds.observe(.{ .source = source }, elapsed_seconds) catch {};
        self.block_import_results_total.incrBy(.{
            .source = source,
            .outcome = "imported",
        }, count) catch {};
    }

    pub fn incrBlockImportResult(
        self: *BeaconMetrics,
        source: []const u8,
        outcome: []const u8,
        count: u64,
    ) void {
        if (count == 0) return;
        self.block_import_results_total.incrBy(.{
            .source = source,
            .outcome = outcome,
        }, count) catch {};
    }

    pub fn incrOptimisticImports(self: *BeaconMetrics, count: u64) void {
        if (count == 0) return;
        self.block_import_optimistic_total.incrBy(count);
    }

    pub fn incrEpochTransitions(self: *BeaconMetrics, count: u64) void {
        if (count == 0) return;
        self.epoch_transitions_total.incrBy(count);
    }

    pub fn observeChainReorg(self: *BeaconMetrics, depth: u64) void {
        self.chain_reorgs_total.incr();
        self.chain_reorg_depth_slots_total.incrBy(depth);
        self.chain_reorg_last_depth.set(depth);
    }

    pub fn setDbSnapshot(
        self: *BeaconMetrics,
        snapshot: db.MetricsSnapshot,
    ) void {
        self.db_total_entries.set(snapshot.total_entries);
        self.db_lmdb_map_size_bytes.set(snapshot.lmdb_map_size_bytes);
        self.db_lmdb_data_size_bytes.set(snapshot.lmdb_data_size_bytes);
        self.db_lmdb_page_size_bytes.set(snapshot.lmdb_page_size_bytes);
        self.db_lmdb_last_page_number.set(snapshot.lmdb_last_page_number);
        self.db_lmdb_last_txnid.set(snapshot.lmdb_last_txnid);
        self.db_lmdb_readers_used.set(snapshot.lmdb_readers_used);
        self.db_lmdb_readers_max.set(snapshot.lmdb_readers_max);
        inline for (db.DatabaseId.all) |db_id| {
            self.db_entries.set(
                .{ .database = db_id.name() },
                snapshot.entryCount(db_id),
            ) catch {};
        }
    }

    pub fn incrPeerReport(
        self: *BeaconMetrics,
        source: networking.ReportSource,
        action: networking.PeerAction,
        count: u64,
    ) void {
        self.peer_reports_total.incrBy(
            .{
                .source = peerReportSourceLabel(source),
                .action = peerActionLabel(action),
            },
            count,
        ) catch return;
    }

    pub fn incrPeerGoodbyeReceived(
        self: *BeaconMetrics,
        reason: networking.PeerGoodbyeMetricReason,
        count: u64,
    ) void {
        self.peer_goodbye_received_total.incrBy(
            .{ .reason = peerGoodbyeReasonLabel(reason) },
            count,
        ) catch return;
    }

    pub fn observeApiRequest(
        self: *BeaconMetrics,
        operation_id: []const u8,
        response_time_seconds: f64,
        is_error: bool,
    ) void {
        const labels: ApiOperationLabels = .{ .operation_id = operation_id };
        self.api_requests_total.incr(labels) catch return;
        if (is_error) {
            self.api_errors_total.incr(labels) catch return;
        }
        if (std.mem.eql(u8, operation_id, "getEvents")) {
            self.api_stream_seconds.observe(labels, response_time_seconds) catch return;
            return;
        }
        self.api_request_seconds.observe(labels, response_time_seconds) catch return;
    }

    pub fn observeReqRespInbound(
        self: *BeaconMetrics,
        method: networking.Method,
        outcome: networking.ReqRespRequestOutcome,
        response_time_seconds: f64,
    ) void {
        const method_labels: ReqRespMethodLabels = .{ .method = reqRespMethodLabel(method) };
        const outcome_labels: ReqRespMethodOutcomeLabels = .{
            .method = method_labels.method,
            .outcome = reqRespOutcomeLabel(outcome),
        };
        self.req_resp_inbound_requests_total.incr(outcome_labels) catch return;
        self.req_resp_inbound_request_seconds.observe(method_labels, response_time_seconds) catch return;
    }

    pub fn observeReqRespOutbound(
        self: *BeaconMetrics,
        method: networking.Method,
        outcome: networking.ReqRespRequestOutcome,
        response_time_seconds: f64,
    ) void {
        const method_labels: ReqRespMethodLabels = .{ .method = reqRespMethodLabel(method) };
        const outcome_labels: ReqRespMethodOutcomeLabels = .{
            .method = method_labels.method,
            .outcome = reqRespOutcomeLabel(outcome),
        };
        self.req_resp_outbound_requests_total.incr(outcome_labels) catch return;
        self.req_resp_outbound_request_seconds.observe(method_labels, response_time_seconds) catch return;
    }

    pub fn setReqRespLimiterPeers(self: *BeaconMetrics, inbound_peers: usize, outbound_peers: usize) void {
        self.req_resp_inbound_limiter_peers.set(@intCast(inbound_peers));
        self.req_resp_outbound_limiter_peers.set(@intCast(outbound_peers));
    }

    pub fn apiObserver(self: *BeaconMetrics) api_mod.HttpServer.Observer {
        return .{
            .ptr = self,
            .onActiveConnectionsChangedFn = onApiActiveConnectionsChanged,
            .onRequestCompletedFn = onApiRequestCompleted,
        };
    }
};

fn onApiActiveConnectionsChanged(ptr: *anyopaque, active_connections: u32) void {
    const metrics: *BeaconMetrics = @ptrCast(@alignCast(ptr));
    metrics.setApiActiveConnections(active_connections);
}

fn onApiRequestCompleted(
    ptr: *anyopaque,
    operation_id: []const u8,
    response_time_seconds: f64,
    is_error: bool,
) void {
    const metrics: *BeaconMetrics = @ptrCast(@alignCast(ptr));
    metrics.observeApiRequest(operation_id, response_time_seconds, is_error);
}

fn peerDirectionLabel(direction: networking.ConnectionDirection) []const u8 {
    return @tagName(direction);
}

fn connectionStateLabel(state: networking.ConnectionState) []const u8 {
    return @tagName(state);
}

fn scoreStateLabel(state: networking.ScoreState) []const u8 {
    return @tagName(state);
}

fn relevanceStatusLabel(status: networking.RelevanceStatus) []const u8 {
    return @tagName(status);
}

fn peerReportSourceLabel(source: networking.ReportSource) []const u8 {
    return @tagName(source);
}

fn peerActionLabel(action: networking.PeerAction) []const u8 {
    return @tagName(action);
}

fn peerGoodbyeReasonLabel(reason: networking.PeerGoodbyeMetricReason) []const u8 {
    return @tagName(reason);
}

fn reqRespMethodLabel(method: networking.Method) []const u8 {
    return @tagName(method);
}

fn reqRespOutcomeLabel(outcome: networking.ReqRespRequestOutcome) []const u8 {
    return @tagName(outcome);
}

test "BeaconMetrics: init fields are accessible" {
    var m = try BeaconMetrics.init(std.testing.allocator);
    defer m.deinit();
    m.head_slot.set(42);
    m.observeImportedBlocks("gossip", 1, 0.05);
    m.incrBlockImportResult("gossip", "queued_unknown_parent", 2);
    m.incrOptimisticImports(1);
    m.incrEpochTransitions(1);
    m.observeChainReorg(3);
    m.setPeerManagerSnapshot(.{
        .known_peers = 12,
        .connected_peers = 10,
        .inbound_connected_peers = 4,
        .outbound_connected_peers = 6,
    });
    m.setForkChoiceSnapshot(.{
        .proto_array_nodes = 9,
        .proto_array_block_roots = 7,
        .votes = 5,
    });
    m.setSyncSnapshot(1, 128, true, false);
    m.setArchiveProgress(64, 2);
    m.setArchiveOperationalSnapshot(16, 24, 250);
    m.incrArchiveRuns(2);
    m.incrArchiveFailures(1);
    m.incrArchiveFinalizedSlotsAdvanced(64);
    m.incrArchiveStateEpochsArchived(3);
    m.incrArchiveRunMilliseconds(500);
    m.setValidatorMonitorSnapshot(4, 1);
    m.setProgressLag(32, 3);
    m.pending_block_ingress_size.set(6);
    m.pending_block_ingress_added_total.incrBy(8);
    m.pending_payload_envelope_ingress_size.set(3);
    m.reprocess_queue_size.set(5);
    m.reprocess_queued_total.incrBy(9);
    m.da_pending_blocks.set(4);
    m.da_pending_marked_total.incrBy(7);
    m.setDbSnapshot(.{
        .total_entries = 33,
        .lmdb_map_size_bytes = 4096,
        .lmdb_data_size_bytes = 2048,
        .lmdb_page_size_bytes = 4096,
        .lmdb_last_page_number = 3,
        .lmdb_last_txnid = 7,
        .lmdb_readers_used = 2,
        .lmdb_readers_max = 126,
    });
    m.incrPeerReport(.rpc, .low_tolerance, 2);
    m.incrPeerGoodbyeReceived(.too_many_peers, 1);
    m.setApiActiveConnections(2);
    m.observeApiRequest("getNodeIdentity", 0.01, false);
    m.observeReqRespInbound(.status, .success, 0.02);
    m.observeReqRespOutbound(.ping, .transport_error, 0.03);
    m.setReqRespLimiterPeers(4, 2);
    m.execution_new_payload_seconds.observe(0.1);
    m.peer_connected_total.incr();
    try std.testing.expectEqual(@as(u64, 42), m.head_slot.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.blocks_imported_total.impl.count);
    try std.testing.expectEqual(@as(usize, 1), m.block_import_source_seconds.impl.metrics.items.len);
    try std.testing.expectEqual(@as(usize, 2), m.block_import_results_total.impl.metrics.items.len);
    try std.testing.expectEqual(@as(u64, 1), m.block_import_optimistic_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.epoch_transitions_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.chain_reorgs_total.impl.count);
    try std.testing.expectEqual(@as(u64, 3), m.chain_reorg_depth_slots_total.impl.count);
    try std.testing.expectEqual(@as(u64, 3), m.chain_reorg_last_depth.impl.value);
    try std.testing.expectEqual(@as(u64, 12), m.known_peers.impl.value);
    try std.testing.expectEqual(@as(u64, 10), m.peers_connected.impl.value);
    try std.testing.expectEqual(@as(u64, 9), m.forkchoice_nodes.impl.value);
    try std.testing.expectEqual(@as(u64, 64), m.archive_last_finalized_slot.impl.value);
    try std.testing.expectEqual(@as(u64, 16), m.archive_last_slots_advanced.impl.value);
    try std.testing.expectEqual(@as(u64, 24), m.archive_last_batch_ops.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.archive_runs_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.archive_failures_total.impl.count);
    try std.testing.expectEqual(@as(u64, 64), m.archive_finalized_slots_advanced_total.impl.count);
    try std.testing.expectEqual(@as(u64, 3), m.archive_state_epochs_archived_total.impl.count);
    try std.testing.expectEqual(@as(u64, 500), m.archive_run_milliseconds_total.impl.count);
    try std.testing.expectEqual(@as(u64, 250), m.archive_last_run_milliseconds.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.sync_status.impl.value);
    try std.testing.expectEqual(@as(u64, 128), m.sync_distance.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.sync_optimistic.impl.value);
    try std.testing.expectEqual(@as(u64, 0), m.sync_el_offline.impl.value);
    try std.testing.expectEqual(@as(u64, 32), m.archive_finalized_slot_lag.impl.value);
    try std.testing.expectEqual(@as(u64, 6), m.pending_block_ingress_size.impl.value);
    try std.testing.expectEqual(@as(u64, 8), m.pending_block_ingress_added_total.impl.count);
    try std.testing.expectEqual(@as(u64, 3), m.pending_payload_envelope_ingress_size.impl.value);
    try std.testing.expectEqual(@as(u64, 5), m.reprocess_queue_size.impl.value);
    try std.testing.expectEqual(@as(u64, 9), m.reprocess_queued_total.impl.count);
    try std.testing.expectEqual(@as(u64, 4), m.da_pending_blocks.impl.value);
    try std.testing.expectEqual(@as(u64, 7), m.da_pending_marked_total.impl.count);
    try std.testing.expectEqual(@as(u64, 4), m.validator_monitor_monitored_validators.impl.value);
    try std.testing.expectEqual(@as(u64, 3), m.validator_monitor_epoch_lag.impl.value);
    try std.testing.expectEqual(@as(u64, 33), m.db_total_entries.impl.value);
    try std.testing.expectEqual(@as(u64, 4096), m.db_lmdb_map_size_bytes.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.db_lmdb_readers_used.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.api_active_connections.impl.value);
    try std.testing.expectEqual(@as(u64, 4), m.req_resp_inbound_limiter_peers.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.req_resp_outbound_limiter_peers.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.peer_connected_total.impl.count);
}

test "BeaconMetrics: initNoop produces zero-overhead stubs" {
    var m = BeaconMetrics.initNoop();
    defer m.deinit();
    m.head_slot.set(999);
    m.observeImportedBlocks("gossip", 1, 0.05);
    m.setApiActiveConnections(1);
    m.observeApiRequest("getNodeIdentity", 0.01, true);
    m.observeReqRespInbound(.status, .success, 0.02);
    m.observeReqRespOutbound(.ping, .self_rate_limited, 0.0);
    m.setReqRespLimiterPeers(1, 1);
    m.execution_new_payload_seconds.observe(1.0);
    m.peer_connected_total.incr();
    try std.testing.expect(std.meta.activeTag(m.head_slot) == .noop);
    try std.testing.expect(std.meta.activeTag(m.blocks_imported_total) == .noop);
    try std.testing.expect(std.meta.activeTag(m.block_import_source_seconds) == .noop);
    try std.testing.expect(std.meta.activeTag(m.block_import_results_total) == .noop);
    try std.testing.expect(std.meta.activeTag(m.execution_new_payload_seconds) == .noop);
}

test "BeaconMetrics: write produces live Prometheus output" {
    var m = try BeaconMetrics.init(std.testing.allocator);
    defer m.deinit();
    m.head_slot.set(100);
    m.finalized_epoch.set(3);
    m.observeImportedBlocks("gossip", 1, 0.05);
    var pm = networking.PeerManager.init(std.testing.allocator, .{});
    defer pm.deinit();
    _ = try pm.onPeerConnected("peer_a", .inbound, 1000);
    _ = try pm.onPeerConnected("peer_b", .outbound, 1000);
    _ = pm.reportPeer("peer_a", .low_tolerance, .rpc, 1100);
    pm.onPeerGoodbye("peer_b", .too_many_peers, 1200);
    const peer_snapshot = pm.metricsSnapshot();
    m.incrBlockImportResult("gossip", "queued_unknown_parent", 1);
    m.setPeerManagerSnapshot(peer_snapshot);
    m.setForkChoiceSnapshot(.{
        .proto_array_nodes = 8,
        .proto_array_block_roots = 6,
        .votes = 4,
        .queued_attestation_slots = 2,
        .queued_attestations_previous_slot = 3,
        .validated_attestation_data_roots = 5,
        .equivocating_validators = 1,
        .proposer_boost_active = true,
    });
    m.setSyncSnapshot(1, 64, true, true);
    m.setArchiveProgress(96, 3);
    m.setArchiveOperationalSnapshot(32, 40, 750);
    m.incrArchiveRuns(3);
    m.incrArchiveFailures(1);
    m.incrArchiveFinalizedSlotsAdvanced(96);
    m.incrArchiveStateEpochsArchived(2);
    m.incrArchiveRunMilliseconds(1500);
    m.setValidatorMonitorSnapshot(8, 12);
    m.setProgressLag(16, 1);
    m.pending_block_ingress_size.set(6);
    m.pending_block_ingress_added_total.incrBy(8);
    m.pending_payload_envelope_ingress_size.set(3);
    m.reprocess_queue_size.set(5);
    m.reprocess_queued_total.incrBy(9);
    m.da_pending_blocks.set(4);
    m.da_pending_marked_total.incrBy(7);
    m.setDbSnapshot(.{
        .total_entries = 11,
        .entry_counts = blk: {
            var counts = [_]u64{0} ** db.DatabaseId.count;
            counts[@intFromEnum(db.DatabaseId.block)] = 3;
            counts[@intFromEnum(db.DatabaseId.block_archive)] = 2;
            break :blk counts;
        },
        .lmdb_map_size_bytes = 1_048_576,
        .lmdb_data_size_bytes = 32_768,
        .lmdb_page_size_bytes = 4096,
        .lmdb_last_page_number = 7,
        .lmdb_last_txnid = 19,
        .lmdb_readers_used = 3,
        .lmdb_readers_max = 126,
    });
    m.incrPeerReport(.rpc, .low_tolerance, peer_snapshot.peerReportCount(.rpc, .low_tolerance));
    m.incrPeerGoodbyeReceived(.too_many_peers, peer_snapshot.goodbyeReceivedCount(.too_many_peers));
    m.setApiActiveConnections(2);
    m.observeApiRequest("getNodeIdentity", 0.01, false);
    m.observeReqRespInbound(.status, .success, 0.02);
    m.observeReqRespOutbound(.ping, .transport_error, 0.03);
    m.setReqRespLimiterPeers(4, 2);
    m.observeApiRequest("getEvents", 3.0, false);
    m.observeApiRequest("publishBlockV2", 0.02, true);
    m.observeReqRespInbound(.status, .success, 0.02);
    m.observeReqRespInbound(.beacon_blocks_by_range, .resource_unavailable, 0.04);
    m.observeReqRespOutbound(.ping, .success, 0.01);
    m.observeReqRespOutbound(.metadata, .malformed_response, 0.03);
    m.setReqRespLimiterPeers(5, 3);
    m.execution_new_payload_seconds.observe(0.5);
    m.peer_connected_total.incr();

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_finalized_epoch") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_blocks_imported_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_import_source_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_import_results_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_import_optimistic_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_epoch_transitions_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_chain_reorgs_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_chain_reorg_depth_slots_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_chain_reorg_last_depth") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_known_peer_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_connected_peer_direction_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_connection_state_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_score_state_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_relevance_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_reports_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_goodbye_received_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_active_connections") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_errors_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_stream_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_limiter_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_limiter_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "getNodeIdentity") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "getEvents") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "status") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "metadata") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "malformed_response") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "queued_unknown_parent") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "gossip") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "low_tolerance") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "too_many_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "disconnecting") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_status") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_optimistic") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_el_offline") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_state_cache_entries") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_forkchoice_nodes") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_forkchoice_votes") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_last_finalized_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_finalized_slot_lag") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_runs_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_failures_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_finalized_slots_advanced_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_state_epochs_archived_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_run_milliseconds_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_last_batch_ops") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_archive_last_run_milliseconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_pending_block_ingress_added_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_pending_payload_envelope_ingress_size") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reprocess_queue_size") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_da_pending_marked_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_validator_monitor_monitored_validators") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_validator_monitor_epoch_lag") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_db_total_entries") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_db_entries") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_db_lmdb_map_size_bytes") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_db_lmdb_readers_used") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "block_archive") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_regen_cache_hits_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_new_payload_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_forkchoice_updated_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_cached_payload") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_connected_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_cache_hit_total") == null);
}

test "MetricsSurface: skips noop state-transition metrics" {
    var beacon = BeaconMetrics.initNoop();
    defer beacon.deinit();
    var surface = MetricsSurface{ .beacon = &beacon };
    beacon.head_slot.set(12);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try surface.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_stfn_") == null);
}

test "MetricsSurface: includes enabled state-transition metrics" {
    const io = std.testing.io;
    var beacon = try BeaconMetrics.init(std.testing.allocator);
    defer beacon.deinit();
    var st_metrics = try state_transition.metrics.StateTransitionMetrics.init(std.testing.allocator, io, .{});
    defer st_metrics.deinit();
    var surface = MetricsSurface{
        .beacon = &beacon,
        .state_transition = &st_metrics,
    };

    beacon.head_slot.set(12);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try surface.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_stfn_epoch_transition_seconds") != null);
}

test "BeaconMetrics: api observer updates live metrics" {
    var metrics = try BeaconMetrics.init(std.testing.allocator);
    defer metrics.deinit();

    const observer = metrics.apiObserver();
    observer.onActiveConnectionsChangedFn.?(observer.ptr, 3);
    observer.onRequestCompletedFn.?(observer.ptr, "getNodeIdentity", 0.01, false);
    observer.onRequestCompletedFn.?(observer.ptr, "getEvents", 2.5, false);
    observer.onRequestCompletedFn.?(observer.ptr, "publishBlockV2", 0.02, true);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try metrics.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_active_connections 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_errors_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_stream_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_limiter_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_limiter_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "publishBlockV2") != null);
}
