//! Beacon-node metrics, including the live runtime surface and the
//! beacon-metrics compatibility families expected by external dashboards.
//!
//! Metrics without a corresponding runtime path are still registered here so
//! the compatibility surface is complete, but they remain zero until the
//! underlying feature exists.

const std = @import("std");
const metrics_lib = @import("metrics");
const api_mod = @import("api");
const db = @import("db");
const fork_choice = @import("fork_choice");
const networking = @import("networking");
const processor = @import("processor");
const state_transition = @import("state_transition");
const sync = @import("sync");

pub const Counter = metrics_lib.Counter;
pub const CounterVec = metrics_lib.CounterVec;
pub const Gauge = metrics_lib.Gauge;
pub const GaugeVec = metrics_lib.GaugeVec;
pub const Histogram = metrics_lib.Histogram;
pub const HistogramVec = metrics_lib.HistogramVec;

pub const ScrapeCollector = struct {
    ctx: *anyopaque,
    collectFn: *const fn (*anyopaque) void,

    pub fn init(
        ptr: anytype,
        comptime collectFn: *const fn (@TypeOf(ptr)) void,
    ) ScrapeCollector {
        const Adapter = struct {
            fn call(ctx: *anyopaque) void {
                collectFn(@ptrCast(@alignCast(ctx)));
            }
        };

        return .{
            .ctx = ptr,
            .collectFn = Adapter.call,
        };
    }

    pub fn collect(self: ScrapeCollector) void {
        self.collectFn(self.ctx);
    }
};

const ApiOperationLabels = struct {
    operation_id: []const u8,
};

const GossipTopicLabels = struct {
    topic: []const u8,
};

const GossipTopicOutcomeLabels = struct {
    topic: []const u8,
    outcome: []const u8,
};

const GossipTopicSentBytesLabels = struct {
    topic: []const u8,
    partial: []const u8,
};

const GossipsubMeshPeerCountLabels = struct {
    topic: []const u8,
    supports_partial: []const u8,
};

const ColumnIndexLabels = struct {
    column_index: u64,
};

const BlockImportSourceLabels = struct {
    source: []const u8,
};

const BlockImportOutcomeLabels = struct {
    source: []const u8,
    outcome: []const u8,
};

const BlockProductionModeLabels = struct {
    mode: []const u8,
};

const BlockProductionSourceLabels = struct {
    source: []const u8,
};

const BlockProductionSelectionLabels = struct {
    source: []const u8,
    reason: []const u8,
};

const BlockProductionStepLabels = struct {
    path: []const u8,
    step: []const u8,
};

const ReqRespMethodLabels = struct {
    method: []const u8,
};

const ReqRespMethodOutcomeLabels = struct {
    method: []const u8,
    outcome: []const u8,
};

const ReqRespMethodErrorLabels = struct {
    method: []const u8,
    error_kind: []const u8,
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

const PeerClientLabels = struct {
    client: []const u8,
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

const DbOperationLabels = struct {
    operation: []const u8,
};

const ProcessorWorkTypeLabels = struct {
    work_type: []const u8,
};

const ProcessorQueueLabels = struct {
    queue: []const u8,
};

const GossipProcessorKindLabels = struct {
    kind: []const u8,
};

const GossipBlsKindLabels = struct {
    kind: []const u8,
};

const GossipBlsPathLabels = struct {
    kind: []const u8,
    path: []const u8,
};

const GossipBlsVerificationLabels = struct {
    kind: []const u8,
    path: []const u8,
    outcome: []const u8,
};

const DiscoveryDialOutcomeLabels = struct {
    outcome: []const u8,
};

const SyncTypeLabels = struct {
    sync_type: []const u8,
};

const SyncModeLabels = struct {
    mode: []const u8,
};

const SyncRangeBatchStatusLabels = struct {
    sync_type: []const u8,
    status: []const u8,
};

const SyncRangeSegmentResultLabels = struct {
    sync_type: []const u8,
    result: []const u8,
};

const SyncRangeSegmentFailureLabels = struct {
    sync_type: []const u8,
    stage: []const u8,
    error_kind: []const u8,
};

const BootstrapSourceLabels = struct {
    source: []const u8,
};

const BootstrapPhaseLabels = struct {
    source: []const u8,
    phase: []const u8,
};

pub const MetricsSurface = struct {
    beacon: *BeaconMetrics,
    scrape_collector: ?ScrapeCollector = null,
    state_transition: *state_transition.metrics.StateTransitionMetrics = state_transition.metrics.noop(),

    pub fn setScrapeCollector(self: *MetricsSurface, collector: ScrapeCollector) void {
        self.scrape_collector = collector;
    }

    pub fn clearScrapeCollector(self: *MetricsSurface) void {
        self.scrape_collector = null;
    }

    pub fn write(self: *MetricsSurface, writer: *std.Io.Writer) !void {
        if (self.scrape_collector) |collector| {
            collector.collect();
        }
        try self.beacon.write(writer);
        if (self.state_transition.isEnabled()) {
            try writer.writeByte('\n');
            try self.state_transition.write(writer);
        }
    }
};

const block_import_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const bootstrap_phase_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0 };
const block_production_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0 };
const block_production_step_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const el_request_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };
const api_request_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const api_stream_buckets = [_]f64{ 0.1, 0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 300.0 };
const gossip_phase1_buckets = [_]f64{ 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const gossip_processor_seconds_buckets = [_]f64{ 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const gossip_bls_batch_size_buckets = [_]f64{ 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 96.0, 128.0 };
const time_to_head_seconds_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 12.0, 24.0, 48.0, 96.0 };
const req_resp_request_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };
const range_sync_segment_seconds_buckets = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0 };
const range_sync_segment_blocks_buckets = [_]f64{ 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 96.0, 128.0, 192.0, 256.0, 512.0, 1024.0 };
const req_resp_payload_bytes_buckets = [_]f64{
    64.0,
    256.0,
    1024.0,
    4096.0,
    16384.0,
    65536.0,
    262144.0,
    1048576.0,
    4194304.0,
    16777216.0,
    67108864.0,
    268435456.0,
    1073741824.0,
};
const req_resp_response_chunk_buckets = [_]f64{ 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 4096.0, 16384.0 };

pub fn rootMetricValue(root: [32]u8) i64 {
    return std.mem.readInt(i64, root[24..32], .little);
}

pub const BeaconMetrics = struct {
    // Bootstrap / startup.
    bootstrap_source: GaugeVec(u64, BootstrapSourceLabels),
    bootstrap_state_slot: Gauge(u64),
    bootstrap_state_bytes: Gauge(u64),
    bootstrap_phase_seconds: HistogramVec(f64, BootstrapPhaseLabels, &bootstrap_phase_buckets),

    // Chain state.
    head_slot: Gauge(u64),
    head_root: Gauge(i64),
    finalized_epoch: Gauge(u64),
    justified_epoch: Gauge(u64),
    current_justified_epoch: Gauge(u64),
    previous_justified_epoch: Gauge(u64),
    current_active_validators: Gauge(u64),
    processed_deposits_total: Gauge(u64),
    previous_justified_root: Gauge(i64),
    head_state_root: Gauge(i64),
    head_state_finalized_root: Gauge(i64),
    current_validators: Gauge(u64),
    previous_validators: Gauge(u64),
    current_live_validators: Gauge(u64),
    previous_live_validators: Gauge(u64),
    pending_deposits: Gauge(u64),
    pending_partial_withdrawals: Gauge(u64),
    pending_consolidations: Gauge(u64),
    pending_exits: Gauge(u64),
    previous_epoch_orphaned_blocks: Gauge(u64),
    custody_groups: Gauge(u64),
    custody_groups_backfilled: Gauge(u64),

    // Block import.
    blocks_imported_total: Counter(u64),
    block_import_seconds: Histogram(f64, &block_import_buckets),
    block_import_source_seconds: HistogramVec(f64, BlockImportSourceLabels, &block_import_buckets),
    block_import_results_total: CounterVec(u64, BlockImportOutcomeLabels),
    block_import_optimistic_total: Counter(u64),
    epoch_transitions_total: Counter(u64),
    chain_reorgs_total: Counter(u64),
    reorgs_total: Counter(u64),
    chain_reorg_depth_slots_total: Counter(u64),
    chain_reorg_last_depth: Gauge(u64),
    processor_gossip_block_imported_total: Gauge(u64),

    // Network / P2P.
    libp2p_peers: Gauge(u64),
    known_peers: Gauge(u64),
    peers_connected: Gauge(u64),
    connected_peer_direction_count: GaugeVec(u64, PeerDirectionLabels),
    peer_connection_state_count: GaugeVec(u64, PeerConnectionStateLabels),
    peer_client_count: GaugeVec(u64, PeerClientLabels),
    peer_score_state_count: GaugeVec(u64, PeerScoreStateLabels),
    known_peer_score_state_count: GaugeVec(u64, PeerScoreStateLabels),
    peer_relevance_count: GaugeVec(u64, PeerRelevanceStatusLabels),
    known_peer_relevance_count: GaugeVec(u64, PeerRelevanceStatusLabels),
    peer_connected_total: Counter(u64),
    peer_disconnected_total: Counter(u64),
    peer_reports_total: CounterVec(u64, PeerReportLabels),
    peer_goodbye_received_total: CounterVec(u64, PeerGoodbyeLabels),
    api_active_connections: Gauge(u64),
    api_requests_total: CounterVec(u64, ApiOperationLabels),
    api_errors_total: CounterVec(u64, ApiOperationLabels),
    api_request_seconds: HistogramVec(f64, ApiOperationLabels, &api_request_buckets),
    api_stream_seconds: HistogramVec(f64, ApiOperationLabels, &api_stream_buckets),
    http_api_requests_total: Gauge(u64),
    http_api_successes_total: Gauge(u64),
    req_resp_inbound_limiter_peers: Gauge(u64),
    req_resp_outbound_limiter_peers: Gauge(u64),
    req_resp_inbound_requests_total: CounterVec(u64, ReqRespMethodOutcomeLabels),
    req_resp_outbound_requests_total: CounterVec(u64, ReqRespMethodOutcomeLabels),
    req_resp_maintenance_errors_total: CounterVec(u64, ReqRespMethodErrorLabels),
    req_resp_inbound_request_seconds: HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets),
    req_resp_outbound_request_seconds: HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets),
    req_resp_inbound_request_payload_bytes_total: CounterVec(u64, ReqRespMethodLabels),
    req_resp_outbound_request_payload_bytes_total: CounterVec(u64, ReqRespMethodLabels),
    req_resp_inbound_response_payload_bytes_total: CounterVec(u64, ReqRespMethodLabels),
    req_resp_outbound_response_payload_bytes_total: CounterVec(u64, ReqRespMethodLabels),
    req_resp_inbound_response_chunks_total: CounterVec(u64, ReqRespMethodLabels),
    req_resp_outbound_response_chunks_total: CounterVec(u64, ReqRespMethodLabels),
    req_resp_inbound_response_payload_bytes: HistogramVec(f64, ReqRespMethodLabels, &req_resp_payload_bytes_buckets),
    req_resp_outbound_response_payload_bytes: HistogramVec(f64, ReqRespMethodLabels, &req_resp_payload_bytes_buckets),
    req_resp_inbound_response_chunks: HistogramVec(f64, ReqRespMethodLabels, &req_resp_response_chunk_buckets),
    req_resp_outbound_response_chunks: HistogramVec(f64, ReqRespMethodLabels, &req_resp_response_chunk_buckets),
    gossip_messages_received: Counter(u64),
    gossip_messages_validated: Counter(u64),
    gossip_messages_rejected: Counter(u64),
    gossip_messages_ignored: Counter(u64),
    attestations_received_total: Gauge(u64),
    aggregates_received_total: Gauge(u64),
    attestor_slashing_received_total: Gauge(u64),
    pubsub_validation_failure_total: Gauge(u64),
    gossip_messages_received_by_topic_total: CounterVec(u64, GossipTopicLabels),
    gossip_messages_result_total: CounterVec(u64, GossipTopicOutcomeLabels),
    gossip_phase1_seconds: HistogramVec(f64, GossipTopicOutcomeLabels, &gossip_phase1_buckets),
    gossip_processor_queue_depth: GaugeVec(u64, GossipProcessorKindLabels),
    gossip_processor_messages_total: CounterVec(u64, GossipProcessorKindLabels),
    gossip_processor_queue_seconds: HistogramVec(f64, GossipProcessorKindLabels, &gossip_processor_seconds_buckets),
    gossip_processor_handle_seconds: HistogramVec(f64, GossipProcessorKindLabels, &gossip_processor_seconds_buckets),
    gossip_bls_pending_batches: GaugeVec(u64, GossipBlsKindLabels),
    gossip_bls_pending_items: GaugeVec(u64, GossipBlsKindLabels),
    gossip_bls_verifications_total: CounterVec(u64, GossipBlsVerificationLabels),
    gossip_bls_items_total: CounterVec(u64, GossipBlsVerificationLabels),
    gossip_bls_batch_size: HistogramVec(f64, GossipBlsPathLabels, &gossip_bls_batch_size_buckets),
    gossip_bls_queue_seconds: HistogramVec(f64, GossipBlsKindLabels, &gossip_processor_seconds_buckets),
    gossip_bls_verify_seconds: HistogramVec(f64, GossipBlsPathLabels, &gossip_processor_seconds_buckets),
    gossipsub_outbound_streams: Gauge(u64),
    gossipsub_tracked_subscriptions: Gauge(u64),
    gossipsub_known_topics: Gauge(u64),
    gossipsub_mesh_topics: Gauge(u64),
    gossipsub_mesh_peers: Gauge(u64),
    gossipsub_topic_peers: Gauge(u64),
    gossipsub_mesh_peers_per_main_topic: GaugeVec(u64, GossipTopicLabels),
    gossipsub_mesh_peer_counts: GaugeVec(u64, GossipsubMeshPeerCountLabels),
    gossipsub_topic_msg_sent_bytes: CounterVec(u64, GossipTopicSentBytesLabels),
    gossipsub_tracked_topics_with_peers: Gauge(u64),
    gossipsub_tracked_topic_peers: Gauge(u64),
    gossipsub_pending_events: Gauge(u64),
    gossipsub_pending_sends: Gauge(u64),
    gossipsub_pending_send_bytes: Gauge(u64),

    // Discovery / sync.
    discovery_peers_known: Gauge(u64),
    discovery_connected_peers: Gauge(u64),
    discovery_queued_peers: Gauge(u64),
    discovery_pending_subnet_queries: Gauge(u64),
    discovery_enr_cache_size: Gauge(u64),
    discovery_enr_seq: Gauge(u64),
    discovery_pending_dials: Gauge(u64),
    discovery_lookups_total: Counter(u64),
    discovery_discovered_total: Counter(u64),
    discovery_filtered_total: Counter(u64),
    discovery_dials_total: CounterVec(u64, DiscoveryDialOutcomeLabels),
    discovery_dial_time_ns_total: CounterVec(u64, DiscoveryDialOutcomeLabels),
    sync_status: Gauge(u64),
    sync_distance: Gauge(u64),
    sync_state: Gauge(u64),
    sync_optimistic: Gauge(u64),
    sync_el_offline: Gauge(u64),
    head_lag_slots: Gauge(u64),
    head_catchup_pending_slots: Gauge(u64),
    time_to_head_last_ms: Gauge(u64),
    time_to_head_current_ms: Gauge(u64),
    time_to_head_seconds: Histogram(f64, &time_to_head_seconds_buckets),
    sync_mode: Gauge(u64),
    sync_mode_state: GaugeVec(u64, SyncModeLabels),
    sync_gossip_enabled: Gauge(u64),
    sync_peer_count: Gauge(u64),
    sync_best_peer_slot: Gauge(u64),
    sync_local_head_slot: Gauge(u64),
    sync_peer_distance: Gauge(u64),
    sync_local_finalized_epoch: Gauge(u64),
    sync_unknown_block_pending: Gauge(u64),
    sync_unknown_block_fetching: Gauge(u64),
    sync_unknown_block_parents_needed: Gauge(u64),
    sync_unknown_block_in_flight: Gauge(u64),
    sync_unknown_block_bad_roots: Gauge(u64),
    sync_unknown_block_exhausted: Gauge(u64),
    process_cpu_seconds_total: Gauge(f64),
    process_max_fds: Gauge(u64),
    range_sync_active_chains: GaugeVec(u64, SyncTypeLabels),
    range_sync_peers: GaugeVec(u64, SyncTypeLabels),
    range_sync_target_slot: GaugeVec(u64, SyncTypeLabels),
    range_sync_validated_epochs: GaugeVec(u64, SyncTypeLabels),
    range_sync_batches: GaugeVec(u64, SyncTypeLabels),
    range_sync_batch_statuses: GaugeVec(u64, SyncRangeBatchStatusLabels),
    range_sync_download_requests_total: CounterVec(u64, SyncTypeLabels),
    range_sync_download_success_total: CounterVec(u64, SyncTypeLabels),
    range_sync_download_error_total: CounterVec(u64, SyncTypeLabels),
    range_sync_download_deferred_total: CounterVec(u64, SyncTypeLabels),
    range_sync_download_time_ns_total: CounterVec(u64, SyncTypeLabels),
    range_sync_processing_success_total: CounterVec(u64, SyncTypeLabels),
    range_sync_processing_error_total: CounterVec(u64, SyncTypeLabels),
    range_sync_processing_time_ns_total: CounterVec(u64, SyncTypeLabels),
    range_sync_processed_blocks_total: CounterVec(u64, SyncTypeLabels),
    range_sync_pending_segments: GaugeVec(u64, SyncTypeLabels),
    range_sync_inflight_segments: GaugeVec(u64, SyncTypeLabels),
    range_sync_pending_blocks: GaugeVec(u64, SyncTypeLabels),
    range_sync_pending_remaining_blocks: GaugeVec(u64, SyncTypeLabels),
    range_sync_segment_results_total: CounterVec(u64, SyncRangeSegmentResultLabels),
    range_sync_segment_failures_total: CounterVec(u64, SyncRangeSegmentFailureLabels),
    range_sync_segment_queue_busy_total: CounterVec(u64, SyncTypeLabels),
    range_sync_segment_seconds: HistogramVec(f64, SyncRangeSegmentResultLabels, &range_sync_segment_seconds_buckets),
    range_sync_segment_blocks: HistogramVec(f64, SyncTypeLabels, &range_sync_segment_blocks_buckets),

    // Chain runtime / caches / pools.
    block_state_cache_entries: Gauge(u64),
    checkpoint_state_cache_entries: Gauge(u64),
    checkpoint_state_datastore_entries: Gauge(u64),
    state_regen_cache_hits_total: Counter(u64),
    store_beacon_block_cache_hit_total: Gauge(u64),
    state_data_cache_misses_total: Gauge(u64),
    state_regen_queue_hits_total: Counter(u64),
    state_regen_dropped_total: Counter(u64),
    state_regen_queue_length: Gauge(u64),
    state_work_pending_jobs: Gauge(u64),
    state_work_completed_jobs: Gauge(u64),
    state_work_active_jobs: Gauge(u64),
    state_work_submitted_total: Counter(u64),
    state_work_rejected_total: Counter(u64),
    state_work_success_total: Counter(u64),
    state_work_failure_total: Counter(u64),
    state_work_execution_time_ns_total: Counter(u64),
    state_work_last_execution_time_ns: Gauge(u64),
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
    db_operation_total: CounterVec(u64, DbOperationLabels),
    db_operation_time_ns_total: CounterVec(u64, DbOperationLabels),
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
    data_column_sidecar_processing_requests_total: Counter(u64),
    data_column_sidecar_processing_successes_total: Counter(u64),
    data_column_sidecar_gossip_verification_seconds: Histogram(f64, &gossip_phase1_buckets),
    data_availability_reconstructed_columns_total: Counter(u64),
    data_availability_reconstruction_time_seconds: Histogram(f64, &gossip_processor_seconds_buckets),
    data_column_sidecar_computation_seconds: Histogram(f64, &gossip_processor_seconds_buckets),
    data_column_sidecar_inclusion_proof_verification_seconds: Histogram(f64, &gossip_processor_seconds_buckets),
    kzg_verification_data_column_batch_seconds: Histogram(f64, &gossip_processor_seconds_buckets),
    partial_message_useful_cells_total: CounterVec(u64, ColumnIndexLabels),
    partial_message_cells_received_total: CounterVec(u64, ColumnIndexLabels),
    useful_full_columns_received_total: CounterVec(u64, ColumnIndexLabels),
    partial_message_column_completions_total: CounterVec(u64, ColumnIndexLabels),
    engine_get_blobs_v2_requests_total: Counter(u64),
    engine_get_blobs_v2_responses_total: Counter(u64),
    engine_get_blobs_v2_request_duration_seconds: Histogram(f64, &el_request_buckets),
    engine_get_blobs_v3_requests_total: Counter(u64),
    engine_get_blobs_v3_complete_responses_total: Counter(u64),
    engine_get_blobs_v3_partial_responses_total: Counter(u64),
    engine_get_blobs_v3_request_duration_seconds: Histogram(f64, &el_request_buckets),
    attestor_slashing_created_total: Gauge(u64),
    da_pending_marked_total: Counter(u64),
    da_pending_resolved_total: Counter(u64),
    da_pending_pruned_total: Counter(u64),
    processor_loop_iterations_total: Counter(u64),
    processor_items_received_total: Counter(u64),
    processor_items_dispatched_total: Counter(u64),
    processor_items_dropped_full_total: Counter(u64),
    processor_items_dropped_sync_total: Counter(u64),
    processor_queue_depth: GaugeVec(u64, ProcessorQueueLabels),
    processor_items_processed_total: CounterVec(u64, ProcessorWorkTypeLabels),
    processor_processing_time_ns_total: CounterVec(u64, ProcessorWorkTypeLabels),

    // Block production.
    block_production_requests_total: CounterVec(u64, BlockProductionModeLabels),
    block_production_success_total: CounterVec(u64, BlockProductionSourceLabels),
    block_production_seconds: HistogramVec(f64, BlockProductionSourceLabels, &block_production_buckets),
    block_production_selection_results_total: CounterVec(u64, BlockProductionSelectionLabels),
    block_production_step_seconds: HistogramVec(f64, BlockProductionStepLabels, &block_production_step_buckets),

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
            .bootstrap_source = try GaugeVec(u64, BootstrapSourceLabels).init(
                allocator,
                "beacon_bootstrap_source",
                .{ .help = "One-hot gauge for the active bootstrap source." },
                ro,
            ),
            .bootstrap_state_slot = Gauge(u64).init(
                "beacon_bootstrap_state_slot",
                .{ .help = "Slot of the bootstrap state loaded into the beacon node." },
                ro,
            ),
            .bootstrap_state_bytes = Gauge(u64).init(
                "beacon_bootstrap_state_bytes",
                .{ .help = "Size in bytes of the bootstrap state loaded into the beacon node." },
                ro,
            ),
            .bootstrap_phase_seconds = try HistogramVec(f64, BootstrapPhaseLabels, &bootstrap_phase_buckets).init(
                allocator,
                "beacon_bootstrap_phase_seconds",
                .{ .help = "Distribution of bootstrap phase durations in seconds by source and phase." },
                ro,
            ),
            .head_slot = Gauge(u64).init("beacon_head_slot", .{ .help = "Current head slot." }, ro),
            .head_root = Gauge(i64).init(
                "beacon_head_root",
                .{ .help = "Low 64 bits of the head block root for Prometheus compatibility." },
                ro,
            ),
            .finalized_epoch = Gauge(u64).init("beacon_finalized_epoch", .{ .help = "Current finalized epoch." }, ro),
            .justified_epoch = Gauge(u64).init("beacon_justified_epoch", .{ .help = "Current justified epoch." }, ro),
            .current_justified_epoch = Gauge(u64).init(
                "beacon_current_justified_epoch",
                .{ .help = "Current justified checkpoint epoch from the head state." },
                ro,
            ),
            .previous_justified_epoch = Gauge(u64).init(
                "beacon_previous_justified_epoch",
                .{ .help = "Previous justified checkpoint epoch from the head state." },
                ro,
            ),
            .current_active_validators = Gauge(u64).init(
                "beacon_current_active_validators",
                .{ .help = "Current number of active validators in the head state." },
                ro,
            ),
            .processed_deposits_total = Gauge(u64).init(
                "beacon_processed_deposits_total",
                .{ .help = "Current processed deposit count from the head state." },
                ro,
            ),
            .previous_justified_root = Gauge(i64).init(
                "beacon_previous_justified_root",
                .{ .help = "Low 64 bits of the previous justified checkpoint root for Prometheus compatibility." },
                ro,
            ),
            .head_state_root = Gauge(i64).init(
                "beacon_head_state_root",
                .{ .help = "Low 64 bits of the current head state root for Prometheus compatibility." },
                ro,
            ),
            .head_state_finalized_root = Gauge(i64).init(
                "beacon_head_state_finalized_root",
                .{ .help = "Low 64 bits of the finalized checkpoint root from the head state for Prometheus compatibility." },
                ro,
            ),
            .current_validators = Gauge(u64).init(
                "beacon_current_validators",
                .{ .help = "Current number of validators in the head state." },
                ro,
            ),
            .previous_validators = Gauge(u64).init(
                "beacon_previous_validators",
                .{ .help = "Compatibility gauge currently mirroring the validator count in the head state." },
                ro,
            ),
            .current_live_validators = Gauge(u64).init(
                "beacon_current_live_validators",
                .{ .help = "Current number of live validators in the current epoch." },
                ro,
            ),
            .previous_live_validators = Gauge(u64).init(
                "beacon_previous_live_validators",
                .{ .help = "Current number of live validators recorded for the previous epoch." },
                ro,
            ),
            .pending_deposits = Gauge(u64).init(
                "beacon_pending_deposits",
                .{ .help = "Current number of pending deposits in the head state." },
                ro,
            ),
            .pending_partial_withdrawals = Gauge(u64).init(
                "beacon_pending_partial_withdrawals",
                .{ .help = "Current number of pending partial withdrawals in the head state." },
                ro,
            ),
            .pending_consolidations = Gauge(u64).init(
                "beacon_pending_consolidations",
                .{ .help = "Current number of pending consolidations in the head state." },
                ro,
            ),
            .pending_exits = Gauge(u64).init(
                "beacon_pending_exits",
                .{ .help = "Current number of pending validator exits in the head state." },
                ro,
            ),
            .previous_epoch_orphaned_blocks = Gauge(u64).init(
                "beacon_previous_epoch_orphaned_blocks",
                .{ .help = "Number of orphaned blocks observed in the previous epoch." },
                ro,
            ),
            .custody_groups = Gauge(u64).init(
                "beacon_custody_groups",
                .{ .help = "Current number of custody groups assigned to this node." },
                ro,
            ),
            .custody_groups_backfilled = Gauge(u64).init(
                "beacon_custody_groups_backfilled",
                .{ .help = "Current number of assigned custody groups that have been backfilled." },
                ro,
            ),

            .blocks_imported_total = Counter(u64).init(
                "beacon_blocks_imported_total",
                .{ .help = "Total blocks imported by the beacon node." },
                ro,
            ),
            .block_import_seconds = Histogram(f64, &block_import_buckets).init(
                "beacon_block_import_seconds",
                .{ .help = "Distribution of block import durations in seconds." },
                ro,
            ),
            .block_import_source_seconds = try HistogramVec(f64, BlockImportSourceLabels, &block_import_buckets).init(
                allocator,
                "beacon_block_import_source_seconds",
                .{ .help = "Distribution of block import durations in seconds by source." },
                ro,
            ),
            .block_import_results_total = try CounterVec(u64, BlockImportOutcomeLabels).init(
                allocator,
                "beacon_block_import_results_total",
                .{ .help = "Total block import results by source and outcome." },
                ro,
            ),
            .block_import_optimistic_total = Counter(u64).init(
                "beacon_block_import_optimistic_total",
                .{ .help = "Total blocks imported optimistically before full execution validation." },
                ro,
            ),
            .epoch_transitions_total = Counter(u64).init(
                "beacon_epoch_transitions_total",
                .{ .help = "Total epoch transitions executed during block processing." },
                ro,
            ),
            .chain_reorgs_total = Counter(u64).init(
                "beacon_chain_reorgs_total",
                .{ .help = "Total chain reorg events." },
                ro,
            ),
            .reorgs_total = Counter(u64).init(
                "beacon_reorgs_total",
                .{ .help = "Compatibility counter mirroring total chain reorg events." },
                ro,
            ),
            .chain_reorg_depth_slots_total = Counter(u64).init(
                "beacon_chain_reorg_depth_slots_total",
                .{ .help = "Cumulative chain reorg depth in slots." },
                ro,
            ),
            .chain_reorg_last_depth = Gauge(u64).init(
                "beacon_chain_reorg_last_depth",
                .{ .help = "Depth in slots of the most recent chain reorg." },
                ro,
            ),
            .processor_gossip_block_imported_total = Gauge(u64).init(
                "beacon_processor_gossip_block_imported_total",
                .{ .help = "Compatibility gauge tracking total gossip blocks imported by the processor." },
                ro,
            ),

            .libp2p_peers = Gauge(u64).init("libp2p_peers", .{ .help = "Current number of connected libp2p peers." }, ro),
            .known_peers = Gauge(u64).init(
                "p2p_known_peer_count",
                .{ .help = "Current number of peers tracked in the peer database." },
                ro,
            ),
            .peers_connected = Gauge(u64).init(
                "p2p_peer_count",
                .{ .help = "Compatibility gauge for the current number of connected peers." },
                ro,
            ),
            .connected_peer_direction_count = try GaugeVec(u64, PeerDirectionLabels).init(
                allocator,
                "p2p_connected_peer_direction_count",
                .{ .help = "Current number of connected peers by connection direction." },
                ro,
            ),
            .peer_connection_state_count = try GaugeVec(u64, PeerConnectionStateLabels).init(
                allocator,
                "p2p_peer_connection_state_count",
                .{ .help = "Current number of peers by connection state." },
                ro,
            ),
            .peer_client_count = try GaugeVec(u64, PeerClientLabels).init(
                allocator,
                "p2p_peer_client_count",
                .{ .help = "Current number of connected peers by identified client implementation." },
                ro,
            ),
            .peer_score_state_count = try GaugeVec(u64, PeerScoreStateLabels).init(
                allocator,
                "p2p_peer_score_state_count",
                .{ .help = "Current number of connected peers by score state." },
                ro,
            ),
            .known_peer_score_state_count = try GaugeVec(u64, PeerScoreStateLabels).init(
                allocator,
                "p2p_known_peer_score_state_count",
                .{ .help = "Current number of peer-database entries by score state." },
                ro,
            ),
            .peer_relevance_count = try GaugeVec(u64, PeerRelevanceStatusLabels).init(
                allocator,
                "p2p_peer_relevance_count",
                .{ .help = "Current number of connected peers by relevance status." },
                ro,
            ),
            .known_peer_relevance_count = try GaugeVec(u64, PeerRelevanceStatusLabels).init(
                allocator,
                "p2p_known_peer_relevance_count",
                .{ .help = "Current number of peer-database entries by relevance status." },
                ro,
            ),
            .peer_connected_total = Counter(u64).init(
                "p2p_peer_connected_total",
                .{ .help = "Total successful peer connections." },
                ro,
            ),
            .peer_disconnected_total = Counter(u64).init(
                "p2p_peer_disconnected_total",
                .{ .help = "Total peer disconnections." },
                ro,
            ),
            .peer_reports_total = try CounterVec(u64, PeerReportLabels).init(
                allocator,
                "p2p_peer_reports_total",
                .{ .help = "Total peer penalty reports by source and action." },
                ro,
            ),
            .peer_goodbye_received_total = try CounterVec(u64, PeerGoodbyeLabels).init(
                allocator,
                "p2p_peer_goodbye_received_total",
                .{ .help = "Total Goodbye messages received by reason." },
                ro,
            ),
            .api_active_connections = Gauge(u64).init(
                "beacon_api_active_connections",
                .{ .help = "Current number of active beacon HTTP API connections." },
                ro,
            ),
            .api_requests_total = try CounterVec(u64, ApiOperationLabels).init(
                allocator,
                "beacon_api_requests_total",
                .{ .help = "Total completed beacon HTTP API requests by operation." },
                ro,
            ),
            .api_errors_total = try CounterVec(u64, ApiOperationLabels).init(
                allocator,
                "beacon_api_errors_total",
                .{ .help = "Total failed beacon HTTP API requests by operation." },
                ro,
            ),
            .api_request_seconds = try HistogramVec(f64, ApiOperationLabels, &api_request_buckets).init(
                allocator,
                "beacon_api_request_seconds",
                .{ .help = "Distribution of beacon HTTP API request durations in seconds by operation." },
                ro,
            ),
            .api_stream_seconds = try HistogramVec(f64, ApiOperationLabels, &api_stream_buckets).init(
                allocator,
                "beacon_api_stream_seconds",
                .{ .help = "Distribution of beacon HTTP API stream durations in seconds by operation." },
                ro,
            ),
            .http_api_requests_total = Gauge(u64).init(
                "beacon_http_api_requests_total",
                .{ .help = "Compatibility gauge tracking total completed beacon HTTP API requests." },
                ro,
            ),
            .http_api_successes_total = Gauge(u64).init(
                "beacon_http_api_successes_total",
                .{ .help = "Compatibility gauge tracking total successful beacon HTTP API requests." },
                ro,
            ),
            .req_resp_inbound_limiter_peers = Gauge(u64).init(
                "beacon_reqresp_inbound_limiter_peers",
                .{ .help = "Current number of peers tracked by the inbound req/resp limiter." },
                ro,
            ),
            .req_resp_outbound_limiter_peers = Gauge(u64).init(
                "beacon_reqresp_outbound_limiter_peers",
                .{ .help = "Current number of peers tracked by the outbound req/resp limiter." },
                ro,
            ),
            .req_resp_inbound_requests_total = try CounterVec(u64, ReqRespMethodOutcomeLabels).init(
                allocator,
                "beacon_reqresp_inbound_requests_total",
                .{ .help = "Total inbound req/resp requests by method and outcome." },
                ro,
            ),
            .req_resp_outbound_requests_total = try CounterVec(u64, ReqRespMethodOutcomeLabels).init(
                allocator,
                "beacon_reqresp_outbound_requests_total",
                .{ .help = "Total outbound req/resp requests by method and outcome." },
                ro,
            ),
            .req_resp_maintenance_errors_total = try CounterVec(u64, ReqRespMethodErrorLabels).init(
                allocator,
                "beacon_reqresp_maintenance_errors_total",
                .{ .help = "Total req/resp maintenance errors by method and error kind." },
                ro,
            ),
            .req_resp_inbound_request_seconds = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets).init(
                allocator,
                "beacon_reqresp_inbound_request_seconds",
                .{ .help = "Distribution of inbound req/resp request durations in seconds by method." },
                ro,
            ),
            .req_resp_outbound_request_seconds = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_request_buckets).init(
                allocator,
                "beacon_reqresp_outbound_request_seconds",
                .{ .help = "Distribution of outbound req/resp request durations in seconds by method." },
                ro,
            ),
            .req_resp_inbound_request_payload_bytes_total = try CounterVec(u64, ReqRespMethodLabels).init(
                allocator,
                "beacon_reqresp_inbound_request_payload_bytes_total",
                .{ .help = "Total inbound req/resp request payload bytes by method." },
                ro,
            ),
            .req_resp_outbound_request_payload_bytes_total = try CounterVec(u64, ReqRespMethodLabels).init(
                allocator,
                "beacon_reqresp_outbound_request_payload_bytes_total",
                .{ .help = "Total outbound req/resp request payload bytes by method." },
                ro,
            ),
            .req_resp_inbound_response_payload_bytes_total = try CounterVec(u64, ReqRespMethodLabels).init(
                allocator,
                "beacon_reqresp_inbound_response_payload_bytes_total",
                .{ .help = "Total inbound req/resp response payload bytes by method." },
                ro,
            ),
            .req_resp_outbound_response_payload_bytes_total = try CounterVec(u64, ReqRespMethodLabels).init(
                allocator,
                "beacon_reqresp_outbound_response_payload_bytes_total",
                .{ .help = "Total outbound req/resp response payload bytes by method." },
                ro,
            ),
            .req_resp_inbound_response_chunks_total = try CounterVec(u64, ReqRespMethodLabels).init(
                allocator,
                "beacon_reqresp_inbound_response_chunks_total",
                .{ .help = "Total inbound req/resp response chunks by method." },
                ro,
            ),
            .req_resp_outbound_response_chunks_total = try CounterVec(u64, ReqRespMethodLabels).init(
                allocator,
                "beacon_reqresp_outbound_response_chunks_total",
                .{ .help = "Total outbound req/resp response chunks by method." },
                ro,
            ),
            .req_resp_inbound_response_payload_bytes = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_payload_bytes_buckets).init(
                allocator,
                "beacon_reqresp_inbound_response_payload_bytes",
                .{ .help = "Distribution of inbound req/resp response payload sizes in bytes by method." },
                ro,
            ),
            .req_resp_outbound_response_payload_bytes = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_payload_bytes_buckets).init(
                allocator,
                "beacon_reqresp_outbound_response_payload_bytes",
                .{ .help = "Distribution of outbound req/resp response payload sizes in bytes by method." },
                ro,
            ),
            .req_resp_inbound_response_chunks = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_response_chunk_buckets).init(
                allocator,
                "beacon_reqresp_inbound_response_chunks",
                .{ .help = "Distribution of inbound req/resp response chunk counts by method." },
                ro,
            ),
            .req_resp_outbound_response_chunks = try HistogramVec(f64, ReqRespMethodLabels, &req_resp_response_chunk_buckets).init(
                allocator,
                "beacon_reqresp_outbound_response_chunks",
                .{ .help = "Distribution of outbound req/resp response chunk counts by method." },
                ro,
            ),
            .gossip_messages_received = Counter(u64).init(
                "beacon_gossip_messages_received_total",
                .{ .help = "Total gossip messages received." },
                ro,
            ),
            .gossip_messages_validated = Counter(u64).init(
                "beacon_gossip_messages_validated_total",
                .{ .help = "Total gossip messages accepted by validation." },
                ro,
            ),
            .gossip_messages_rejected = Counter(u64).init(
                "beacon_gossip_messages_rejected_total",
                .{ .help = "Total gossip messages rejected by validation." },
                ro,
            ),
            .gossip_messages_ignored = Counter(u64).init(
                "beacon_gossip_messages_ignored_total",
                .{ .help = "Total gossip messages ignored without validation failure." },
                ro,
            ),
            .attestations_received_total = Gauge(u64).init(
                "beacon_attestations_received_total",
                .{ .help = "Compatibility gauge tracking total attestation gossip messages received." },
                ro,
            ),
            .aggregates_received_total = Gauge(u64).init(
                "beacon_aggregates_received_total",
                .{ .help = "Compatibility gauge tracking total aggregate gossip messages received." },
                ro,
            ),
            .attestor_slashing_received_total = Gauge(u64).init(
                "beacon_attestor_slashing_received_total",
                .{ .help = "Compatibility gauge tracking total attester slashing gossip messages received." },
                ro,
            ),
            .pubsub_validation_failure_total = Gauge(u64).init(
                "libp2p_pubsub_validation_failure_total",
                .{ .help = "Compatibility gauge tracking total libp2p pubsub validation failures." },
                ro,
            ),
            .gossip_messages_received_by_topic_total = try CounterVec(u64, GossipTopicLabels).init(
                allocator,
                "beacon_gossip_messages_received_by_topic_total",
                .{ .help = "Total gossip messages received by topic." },
                ro,
            ),
            .gossip_messages_result_total = try CounterVec(u64, GossipTopicOutcomeLabels).init(
                allocator,
                "beacon_gossip_messages_result_total",
                .{ .help = "Total gossip validation results by topic and outcome." },
                ro,
            ),
            .gossip_phase1_seconds = try HistogramVec(f64, GossipTopicOutcomeLabels, &gossip_phase1_buckets).init(
                allocator,
                "beacon_gossip_phase1_seconds",
                .{ .help = "Distribution of phase-1 gossip validation durations in seconds by topic and outcome." },
                ro,
            ),
            .gossip_processor_queue_depth = try GaugeVec(u64, GossipProcessorKindLabels).init(
                allocator,
                "beacon_gossip_processor_queue_depth",
                .{ .help = "Current number of queued gossip processor items by kind." },
                ro,
            ),
            .gossip_processor_messages_total = try CounterVec(u64, GossipProcessorKindLabels).init(
                allocator,
                "beacon_gossip_processor_messages_total",
                .{ .help = "Total gossip processor items enqueued by kind." },
                ro,
            ),
            .gossip_processor_queue_seconds = try HistogramVec(f64, GossipProcessorKindLabels, &gossip_processor_seconds_buckets).init(
                allocator,
                "beacon_gossip_processor_queue_seconds",
                .{ .help = "Distribution of gossip processor queue wait times in seconds by kind." },
                ro,
            ),
            .gossip_processor_handle_seconds = try HistogramVec(f64, GossipProcessorKindLabels, &gossip_processor_seconds_buckets).init(
                allocator,
                "beacon_gossip_processor_handle_seconds",
                .{ .help = "Distribution of gossip processor handling times in seconds by kind." },
                ro,
            ),
            .gossip_bls_pending_batches = try GaugeVec(u64, GossipBlsKindLabels).init(
                allocator,
                "beacon_gossip_bls_pending_batches",
                .{ .help = "Current number of pending gossip BLS verification batches by kind." },
                ro,
            ),
            .gossip_bls_pending_items = try GaugeVec(u64, GossipBlsKindLabels).init(
                allocator,
                "beacon_gossip_bls_pending_items",
                .{ .help = "Current number of pending gossip BLS verification items by kind." },
                ro,
            ),
            .gossip_bls_verifications_total = try CounterVec(u64, GossipBlsVerificationLabels).init(
                allocator,
                "beacon_gossip_bls_verifications_total",
                .{ .help = "Total gossip BLS verification batches by kind, path, and outcome." },
                ro,
            ),
            .gossip_bls_items_total = try CounterVec(u64, GossipBlsVerificationLabels).init(
                allocator,
                "beacon_gossip_bls_items_total",
                .{ .help = "Total gossip items covered by BLS verification batches by kind, path, and outcome." },
                ro,
            ),
            .gossip_bls_batch_size = try HistogramVec(f64, GossipBlsPathLabels, &gossip_bls_batch_size_buckets).init(
                allocator,
                "beacon_gossip_bls_batch_size",
                .{ .help = "Distribution of gossip BLS batch sizes by kind and verification path." },
                ro,
            ),
            .gossip_bls_queue_seconds = try HistogramVec(f64, GossipBlsKindLabels, &gossip_processor_seconds_buckets).init(
                allocator,
                "beacon_gossip_bls_queue_seconds",
                .{ .help = "Distribution of gossip BLS verification queue wait times in seconds by kind." },
                ro,
            ),
            .gossip_bls_verify_seconds = try HistogramVec(f64, GossipBlsPathLabels, &gossip_processor_seconds_buckets).init(
                allocator,
                "beacon_gossip_bls_verify_seconds",
                .{ .help = "Distribution of gossip BLS verification times in seconds by kind and path." },
                ro,
            ),
            .gossipsub_outbound_streams = Gauge(u64).init(
                "beacon_gossipsub_outbound_streams",
                .{ .help = "Current number of outbound gossipsub streams." },
                ro,
            ),
            .gossipsub_tracked_subscriptions = Gauge(u64).init(
                "beacon_gossipsub_tracked_subscriptions",
                .{ .help = "Current number of tracked gossipsub subscriptions." },
                ro,
            ),
            .gossipsub_known_topics = Gauge(u64).init(
                "beacon_gossipsub_known_topics",
                .{ .help = "Current number of known gossipsub topics." },
                ro,
            ),
            .gossipsub_mesh_topics = Gauge(u64).init(
                "beacon_gossipsub_mesh_topics",
                .{ .help = "Current number of gossipsub topics with an active mesh." },
                ro,
            ),
            .gossipsub_mesh_peers = Gauge(u64).init(
                "beacon_gossipsub_mesh_peers",
                .{ .help = "Current number of unique peers across all gossipsub meshes." },
                ro,
            ),
            .gossipsub_topic_peers = Gauge(u64).init(
                "beacon_gossipsub_topic_peers",
                .{ .help = "Current number of unique peers across all gossipsub topic peer sets." },
                ro,
            ),
            .gossipsub_mesh_peers_per_main_topic = try GaugeVec(u64, GossipTopicLabels).init(
                allocator,
                "gossipsub_mesh_peers_per_main_topic",
                .{ .help = "Current number of unique mesh peers for each main gossip topic." },
                ro,
            ),
            .gossipsub_mesh_peer_counts = try GaugeVec(u64, GossipsubMeshPeerCountLabels).init(
                allocator,
                "gossipsub_mesh_peer_counts",
                .{ .help = "Current number of unique mesh peers by topic and partial-support bucket." },
                ro,
            ),
            .gossipsub_topic_msg_sent_bytes = try CounterVec(u64, GossipTopicSentBytesLabels).init(
                allocator,
                "gossipsub_topic_msg_sent_bytes",
                .{ .help = "Total gossipsub message bytes sent by topic and partial flag." },
                ro,
            ),
            .gossipsub_tracked_topics_with_peers = Gauge(u64).init(
                "beacon_gossipsub_tracked_topics_with_peers",
                .{ .help = "Current number of tracked gossipsub topics that have at least one peer." },
                ro,
            ),
            .gossipsub_tracked_topic_peers = Gauge(u64).init(
                "beacon_gossipsub_tracked_topic_peers",
                .{ .help = "Current number of unique peers across tracked gossipsub topics." },
                ro,
            ),
            .gossipsub_pending_events = Gauge(u64).init(
                "beacon_gossipsub_pending_events",
                .{ .help = "Current number of pending gossipsub events." },
                ro,
            ),
            .gossipsub_pending_sends = Gauge(u64).init(
                "beacon_gossipsub_pending_sends",
                .{ .help = "Current number of pending gossipsub sends." },
                ro,
            ),
            .gossipsub_pending_send_bytes = Gauge(u64).init(
                "beacon_gossipsub_pending_send_bytes",
                .{ .help = "Current number of pending gossipsub send bytes." },
                ro,
            ),

            .discovery_peers_known = Gauge(u64).init(
                "beacon_discovery_peers_known",
                .{ .help = "Current number of peers known to discovery." },
                ro,
            ),
            .discovery_connected_peers = Gauge(u64).init(
                "beacon_discovery_connected_peers",
                .{ .help = "Current number of discovery-known peers that are connected." },
                ro,
            ),
            .discovery_queued_peers = Gauge(u64).init(
                "beacon_discovery_queued_peers",
                .{ .help = "Current number of peers queued by discovery for dialing or scoring." },
                ro,
            ),
            .discovery_pending_subnet_queries = Gauge(u64).init(
                "beacon_discovery_pending_subnet_queries",
                .{ .help = "Current number of pending discovery subnet queries." },
                ro,
            ),
            .discovery_enr_cache_size = Gauge(u64).init(
                "beacon_discovery_enr_cache_size",
                .{ .help = "Current size of the discovery ENR cache." },
                ro,
            ),
            .discovery_enr_seq = Gauge(u64).init(
                "beacon_discovery_enr_seq",
                .{ .help = "Current local discovery ENR sequence number." },
                ro,
            ),
            .discovery_pending_dials = Gauge(u64).init(
                "beacon_discovery_pending_dials",
                .{ .help = "Current number of pending discovery dial attempts." },
                ro,
            ),
            .discovery_lookups_total = Counter(u64).init(
                "beacon_discovery_lookups_total",
                .{ .help = "Total discovery lookups started." },
                ro,
            ),
            .discovery_discovered_total = Counter(u64).init(
                "beacon_discovery_discovered_total",
                .{ .help = "Total peers discovered before filtering." },
                ro,
            ),
            .discovery_filtered_total = Counter(u64).init(
                "beacon_discovery_filtered_total",
                .{ .help = "Total discovered peers filtered out before dialing." },
                ro,
            ),
            .discovery_dials_total = try CounterVec(u64, DiscoveryDialOutcomeLabels).init(
                allocator,
                "beacon_discovery_dials_total",
                .{ .help = "Total discovery dial attempts by outcome." },
                ro,
            ),
            .discovery_dial_time_ns_total = try CounterVec(u64, DiscoveryDialOutcomeLabels).init(
                allocator,
                "beacon_discovery_dial_time_ns_total",
                .{ .help = "Cumulative discovery dial time in nanoseconds by outcome." },
                ro,
            ),
            .sync_status = Gauge(u64).init(
                "beacon_sync_status",
                .{ .help = "Compatibility gauge indicating whether the node is syncing: syncing=1, synced=0." },
                ro,
            ),
            .sync_distance = Gauge(u64).init(
                "beacon_sync_distance",
                .{ .help = "Current sync distance in slots." },
                ro,
            ),
            .sync_state = Gauge(u64).init(
                "beacon_sync_state",
                .{ .help = "Compatibility sync state gauge: searching=0, synced=1, syncing=2." },
                ro,
            ),
            .sync_optimistic = Gauge(u64).init(
                "beacon_sync_optimistic",
                .{ .help = "Compatibility gauge indicating whether the node is currently optimistic." },
                ro,
            ),
            .sync_el_offline = Gauge(u64).init(
                "beacon_sync_el_offline",
                .{ .help = "Compatibility gauge indicating whether the execution layer is offline." },
                ro,
            ),
            .head_lag_slots = Gauge(u64).init(
                "beacon_head_lag_slots",
                .{ .help = "Current head lag in slots." },
                ro,
            ),
            .head_catchup_pending_slots = Gauge(u64).init(
                "beacon_head_catchup_pending_slots",
                .{ .help = "Current number of catch-up slots still pending before the head is current." },
                ro,
            ),
            .time_to_head_last_ms = Gauge(u64).init(
                "beacon_time_to_head_last_ms",
                .{ .help = "Last measured time to head in milliseconds." },
                ro,
            ),
            .time_to_head_current_ms = Gauge(u64).init(
                "beacon_time_to_head_current_ms",
                .{ .help = "Current rolling time-to-head estimate in milliseconds." },
                ro,
            ),
            .time_to_head_seconds = Histogram(f64, &time_to_head_seconds_buckets).init(
                "beacon_time_to_head_seconds",
                .{ .help = "Distribution of time-to-head observations in seconds." },
                ro,
            ),
            .sync_mode = Gauge(u64).init(
                "beacon_sync_mode",
                .{ .help = "Current sync mode as an enum: idle=0, checkpoint_sync=1, range_sync=2, synced=3." },
                ro,
            ),
            .sync_mode_state = try GaugeVec(u64, SyncModeLabels).init(
                allocator,
                "beacon_sync_mode_state",
                .{ .help = "One-hot gauge for the current sync mode by label." },
                ro,
            ),
            .sync_gossip_enabled = Gauge(u64).init(
                "beacon_sync_gossip_enabled",
                .{ .help = "Compatibility gauge indicating whether gossip processing is enabled." },
                ro,
            ),
            .sync_peer_count = Gauge(u64).init(
                "beacon_sync_peer_count",
                .{ .help = "Current number of peers participating in sync." },
                ro,
            ),
            .sync_best_peer_slot = Gauge(u64).init(
                "beacon_sync_best_peer_slot",
                .{ .help = "Current best peer slot used for sync status." },
                ro,
            ),
            .sync_local_head_slot = Gauge(u64).init(
                "beacon_sync_local_head_slot",
                .{ .help = "Current local head slot used for sync status." },
                ro,
            ),
            .sync_peer_distance = Gauge(u64).init(
                "beacon_sync_peer_distance",
                .{ .help = "Current slot distance between the best sync peer and the local head." },
                ro,
            ),
            .sync_local_finalized_epoch = Gauge(u64).init(
                "beacon_sync_local_finalized_epoch",
                .{ .help = "Current local finalized epoch used for sync status." },
                ro,
            ),
            .sync_unknown_block_pending = Gauge(u64).init(
                "beacon_sync_unknown_block_pending",
                .{ .help = "Current number of pending unknown-block sync entries." },
                ro,
            ),
            .sync_unknown_block_fetching = Gauge(u64).init(
                "beacon_sync_unknown_block_fetching",
                .{ .help = "Current number of unknown-block sync entries waiting on fetches." },
                ro,
            ),
            .sync_unknown_block_parents_needed = Gauge(u64).init(
                "beacon_sync_unknown_block_parents_needed",
                .{ .help = "Current number of unknown-block sync entries that still need parent blocks." },
                ro,
            ),
            .sync_unknown_block_in_flight = Gauge(u64).init(
                "beacon_sync_unknown_block_in_flight",
                .{ .help = "Current number of in-flight unknown-block sync requests." },
                ro,
            ),
            .sync_unknown_block_bad_roots = Gauge(u64).init(
                "beacon_sync_unknown_block_bad_roots",
                .{ .help = "Current number of unknown-block roots marked bad." },
                ro,
            ),
            .sync_unknown_block_exhausted = Gauge(u64).init(
                "beacon_sync_unknown_block_exhausted",
                .{ .help = "Current number of unknown-block entries that exhausted parent fetch attempts." },
                ro,
            ),
            .process_cpu_seconds_total = Gauge(f64).init(
                "process_cpu_seconds_total",
                .{ .help = "Total CPU time consumed by the process in seconds." },
                ro,
            ),
            .process_max_fds = Gauge(u64).init(
                "process_max_fds",
                .{ .help = "Maximum number of file descriptors available to the process." },
                ro,
            ),
            .range_sync_active_chains = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_active_chains",
                .{ .help = "Current number of active range-sync chains by sync type." },
                ro,
            ),
            .range_sync_peers = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_peers",
                .{ .help = "Current number of range-sync peers by sync type." },
                ro,
            ),
            .range_sync_target_slot = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_target_slot",
                .{ .help = "Current range-sync target slot by sync type." },
                ro,
            ),
            .range_sync_validated_epochs = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_validated_epochs",
                .{ .help = "Current number of validated range-sync epochs by sync type." },
                ro,
            ),
            .range_sync_batches = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_batches",
                .{ .help = "Current number of tracked range-sync batches by sync type." },
                ro,
            ),
            .range_sync_batch_statuses = try GaugeVec(u64, SyncRangeBatchStatusLabels).init(
                allocator,
                "beacon_range_sync_batch_statuses",
                .{ .help = "Current number of range-sync batches by sync type and batch status." },
                ro,
            ),
            .range_sync_download_requests_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_download_requests_total",
                .{ .help = "Total range-sync download requests by sync type." },
                ro,
            ),
            .range_sync_download_success_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_download_success_total",
                .{ .help = "Total successful range-sync downloads by sync type." },
                ro,
            ),
            .range_sync_download_error_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_download_error_total",
                .{ .help = "Total failed range-sync downloads by sync type." },
                ro,
            ),
            .range_sync_download_deferred_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_download_deferred_total",
                .{ .help = "Total deferred range-sync downloads by sync type." },
                ro,
            ),
            .range_sync_download_time_ns_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_download_time_ns_total",
                .{ .help = "Cumulative range-sync download time in nanoseconds by sync type." },
                ro,
            ),
            .range_sync_processing_success_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_processing_success_total",
                .{ .help = "Total successful range-sync processing passes by sync type." },
                ro,
            ),
            .range_sync_processing_error_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_processing_error_total",
                .{ .help = "Total failed range-sync processing passes by sync type." },
                ro,
            ),
            .range_sync_processing_time_ns_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_processing_time_ns_total",
                .{ .help = "Cumulative range-sync processing time in nanoseconds by sync type." },
                ro,
            ),
            .range_sync_processed_blocks_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_processed_blocks_total",
                .{ .help = "Total blocks processed by range sync by sync type." },
                ro,
            ),
            .range_sync_pending_segments = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_pending_segments",
                .{ .help = "Current number of pending range-sync segments by sync type." },
                ro,
            ),
            .range_sync_inflight_segments = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_inflight_segments",
                .{ .help = "Current number of in-flight range-sync segments by sync type." },
                ro,
            ),
            .range_sync_pending_blocks = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_pending_blocks",
                .{ .help = "Current number of pending blocks held by range sync by sync type." },
                ro,
            ),
            .range_sync_pending_remaining_blocks = try GaugeVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_pending_remaining_blocks",
                .{ .help = "Current number of pending range-sync blocks still remaining to process by sync type." },
                ro,
            ),
            .range_sync_segment_results_total = try CounterVec(u64, SyncRangeSegmentResultLabels).init(
                allocator,
                "beacon_range_sync_segment_results_total",
                .{ .help = "Total range-sync segment results by sync type and result." },
                ro,
            ),
            .range_sync_segment_failures_total = try CounterVec(u64, SyncRangeSegmentFailureLabels).init(
                allocator,
                "beacon_range_sync_segment_failures_total",
                .{ .help = "Total range-sync segment failures by sync type, stage, and error kind." },
                ro,
            ),
            .range_sync_segment_queue_busy_total = try CounterVec(u64, SyncTypeLabels).init(
                allocator,
                "beacon_range_sync_segment_queue_busy_total",
                .{ .help = "Total times range-sync segment work was deferred because the processing queue was busy, by sync type." },
                ro,
            ),
            .range_sync_segment_seconds = try HistogramVec(f64, SyncRangeSegmentResultLabels, &range_sync_segment_seconds_buckets).init(
                allocator,
                "beacon_range_sync_segment_seconds",
                .{ .help = "Distribution of range-sync segment durations in seconds by sync type and result." },
                ro,
            ),
            .range_sync_segment_blocks = try HistogramVec(f64, SyncTypeLabels, &range_sync_segment_blocks_buckets).init(
                allocator,
                "beacon_range_sync_segment_blocks",
                .{ .help = "Distribution of blocks attempted per range-sync segment by sync type." },
                ro,
            ),

            .block_state_cache_entries = Gauge(u64).init(
                "beacon_block_state_cache_entries",
                .{ .help = "Current number of in-memory block-state cache entries." },
                ro,
            ),
            .checkpoint_state_cache_entries = Gauge(u64).init(
                "beacon_checkpoint_state_cache_entries",
                .{ .help = "Current number of in-memory checkpoint-state cache entries." },
                ro,
            ),
            .checkpoint_state_datastore_entries = Gauge(u64).init(
                "beacon_checkpoint_state_datastore_entries",
                .{ .help = "Current number of persisted checkpoint-state datastore entries." },
                ro,
            ),
            .state_regen_cache_hits_total = Counter(u64).init(
                "beacon_state_regen_cache_hits_total",
                .{ .help = "Total state regeneration requests served from the fast-path cache." },
                ro,
            ),
            .store_beacon_block_cache_hit_total = Gauge(u64).init(
                "store_beacon_block_cache_hit_total",
                .{ .help = "Compatibility gauge tracking total beacon block cache hits." },
                ro,
            ),
            .state_data_cache_misses_total = Gauge(u64).init(
                "beacon_state_data_cache_misses_total",
                .{ .help = "Compatibility gauge tracking total state data cache misses." },
                ro,
            ),
            .state_regen_queue_hits_total = Counter(u64).init(
                "beacon_state_regen_queue_hits_total",
                .{ .help = "Total state regeneration requests deduplicated against queued work." },
                ro,
            ),
            .state_regen_dropped_total = Counter(u64).init(
                "beacon_state_regen_dropped_total",
                .{ .help = "Total state regeneration requests dropped under pressure." },
                ro,
            ),
            .state_regen_queue_length = Gauge(u64).init(
                "beacon_state_regen_queue_length",
                .{ .help = "Current queued state regeneration backlog." },
                ro,
            ),
            .state_work_pending_jobs = Gauge(u64).init(
                "beacon_state_work_pending_jobs",
                .{ .help = "Current number of pending state work jobs." },
                ro,
            ),
            .state_work_completed_jobs = Gauge(u64).init(
                "beacon_state_work_completed_jobs",
                .{ .help = "Current number of retained completed state work jobs." },
                ro,
            ),
            .state_work_active_jobs = Gauge(u64).init(
                "beacon_state_work_active_jobs",
                .{ .help = "Current number of active state work jobs." },
                ro,
            ),
            .state_work_submitted_total = Counter(u64).init(
                "beacon_state_work_submitted_total",
                .{ .help = "Total state work jobs submitted." },
                ro,
            ),
            .state_work_rejected_total = Counter(u64).init(
                "beacon_state_work_rejected_total",
                .{ .help = "Total state work jobs rejected before execution." },
                ro,
            ),
            .state_work_success_total = Counter(u64).init(
                "beacon_state_work_success_total",
                .{ .help = "Total state work jobs completed successfully." },
                ro,
            ),
            .state_work_failure_total = Counter(u64).init(
                "beacon_state_work_failure_total",
                .{ .help = "Total state work jobs that failed during execution." },
                ro,
            ),
            .state_work_execution_time_ns_total = Counter(u64).init(
                "beacon_state_work_execution_time_ns_total",
                .{ .help = "Cumulative state work execution time in nanoseconds." },
                ro,
            ),
            .state_work_last_execution_time_ns = Gauge(u64).init(
                "beacon_state_work_last_execution_time_ns",
                .{ .help = "Execution time in nanoseconds of the most recently completed state work job." },
                ro,
            ),
            .forkchoice_nodes = Gauge(u64).init(
                "beacon_forkchoice_nodes",
                .{ .help = "Current number of nodes in the fork-choice DAG." },
                ro,
            ),
            .forkchoice_block_roots = Gauge(u64).init(
                "beacon_forkchoice_block_roots",
                .{ .help = "Current number of block roots tracked by fork choice." },
                ro,
            ),
            .forkchoice_votes = Gauge(u64).init(
                "beacon_forkchoice_votes",
                .{ .help = "Current number of votes tracked by fork choice." },
                ro,
            ),
            .forkchoice_queued_attestation_slots = Gauge(u64).init(
                "beacon_forkchoice_queued_attestation_slots",
                .{ .help = "Current number of slots with queued fork-choice attestations." },
                ro,
            ),
            .forkchoice_queued_attestations_previous_slot = Gauge(u64).init(
                "beacon_forkchoice_queued_attestations_previous_slot",
                .{ .help = "Current number of queued fork-choice attestations carried over from the previous slot." },
                ro,
            ),
            .forkchoice_validated_attestation_data_roots = Gauge(u64).init(
                "beacon_forkchoice_validated_attestation_data_roots",
                .{ .help = "Current number of validated attestation data roots cached by fork choice." },
                ro,
            ),
            .forkchoice_equivocating_validators = Gauge(u64).init(
                "beacon_forkchoice_equivocating_validators",
                .{ .help = "Current number of validators marked equivocating by fork choice." },
                ro,
            ),
            .forkchoice_proposer_boost_active = Gauge(u64).init(
                "beacon_forkchoice_proposer_boost_active",
                .{ .help = "Gauge indicating whether proposer boost is currently active: active=1, inactive=0." },
                ro,
            ),
            .archive_last_finalized_slot = Gauge(u64).init(
                "beacon_archive_last_finalized_slot",
                .{ .help = "Most recent finalized slot processed by the archive store." },
                ro,
            ),
            .archive_last_archived_state_epoch = Gauge(u64).init(
                "beacon_archive_last_archived_state_epoch",
                .{ .help = "Most recent state epoch archived by the archive store." },
                ro,
            ),
            .archive_finalized_slot_lag = Gauge(u64).init(
                "beacon_archive_finalized_slot_lag",
                .{ .help = "Current number of finalized slots still waiting on archival." },
                ro,
            ),
            .archive_runs_total = Counter(u64).init(
                "beacon_archive_runs_total",
                .{ .help = "Total archive catch-up runs." },
                ro,
            ),
            .archive_failures_total = Counter(u64).init(
                "beacon_archive_failures_total",
                .{ .help = "Total archive catch-up run failures." },
                ro,
            ),
            .archive_finalized_slots_advanced_total = Counter(u64).init(
                "beacon_archive_finalized_slots_advanced_total",
                .{ .help = "Cumulative finalized slots advanced by archival." },
                ro,
            ),
            .archive_state_epochs_archived_total = Counter(u64).init(
                "beacon_archive_state_epochs_archived_total",
                .{ .help = "Cumulative state epochs archived." },
                ro,
            ),
            .archive_run_milliseconds_total = Counter(u64).init(
                "beacon_archive_run_milliseconds_total",
                .{ .help = "Cumulative archive catch-up runtime in milliseconds." },
                ro,
            ),
            .archive_last_slots_advanced = Gauge(u64).init(
                "beacon_archive_last_slots_advanced",
                .{ .help = "Finalized slots advanced by the most recent archive run." },
                ro,
            ),
            .archive_last_batch_ops = Gauge(u64).init(
                "beacon_archive_last_batch_ops",
                .{ .help = "Batch operations executed by the most recent archive run." },
                ro,
            ),
            .archive_last_run_milliseconds = Gauge(u64).init(
                "beacon_archive_last_run_milliseconds",
                .{ .help = "Runtime in milliseconds of the most recent archive run." },
                ro,
            ),
            .validator_monitor_monitored_validators = Gauge(u64).init(
                "beacon_validator_monitor_monitored_validators",
                .{ .help = "Current number of validators monitored by the validator monitor." },
                ro,
            ),
            .validator_monitor_last_processed_epoch = Gauge(u64).init(
                "beacon_validator_monitor_last_processed_epoch",
                .{ .help = "Most recent epoch processed by the validator monitor." },
                ro,
            ),
            .validator_monitor_epoch_lag = Gauge(u64).init(
                "beacon_validator_monitor_epoch_lag",
                .{ .help = "Current validator monitor lag in epochs." },
                ro,
            ),
            .db_total_entries = Gauge(u64).init(
                "beacon_db_total_entries",
                .{ .help = "Current total number of database entries across all named databases." },
                ro,
            ),
            .db_entries = try GaugeVec(u64, DatabaseLabels).init(
                allocator,
                "beacon_db_entries",
                .{ .help = "Current number of database entries by named database." },
                ro,
            ),
            .db_lmdb_map_size_bytes = Gauge(u64).init(
                "beacon_db_lmdb_map_size_bytes",
                .{ .help = "Current LMDB map size in bytes." },
                ro,
            ),
            .db_lmdb_data_size_bytes = Gauge(u64).init(
                "beacon_db_lmdb_data_size_bytes",
                .{ .help = "Current LMDB data size in bytes." },
                ro,
            ),
            .db_lmdb_page_size_bytes = Gauge(u64).init(
                "beacon_db_lmdb_page_size_bytes",
                .{ .help = "Current LMDB page size in bytes." },
                ro,
            ),
            .db_lmdb_last_page_number = Gauge(u64).init(
                "beacon_db_lmdb_last_page_number",
                .{ .help = "Current LMDB last page number." },
                ro,
            ),
            .db_lmdb_last_txnid = Gauge(u64).init(
                "beacon_db_lmdb_last_txnid",
                .{ .help = "Current LMDB last transaction ID." },
                ro,
            ),
            .db_lmdb_readers_used = Gauge(u64).init(
                "beacon_db_lmdb_readers_used",
                .{ .help = "Current number of LMDB reader slots in use." },
                ro,
            ),
            .db_lmdb_readers_max = Gauge(u64).init(
                "beacon_db_lmdb_readers_max",
                .{ .help = "Maximum number of LMDB reader slots available." },
                ro,
            ),
            .db_operation_total = try CounterVec(u64, DbOperationLabels).init(
                allocator,
                "beacon_db_operation_total",
                .{ .help = "Total database operations by operation type." },
                ro,
            ),
            .db_operation_time_ns_total = try CounterVec(u64, DbOperationLabels).init(
                allocator,
                "beacon_db_operation_time_ns_total",
                .{ .help = "Cumulative database operation time in nanoseconds by operation type." },
                ro,
            ),
            .attestation_pool_groups = Gauge(u64).init(
                "beacon_attestation_pool_groups",
                .{ .help = "Current number of attestation pool groups." },
                ro,
            ),
            .aggregate_attestation_pool_groups = Gauge(u64).init(
                "beacon_aggregate_attestation_pool_groups",
                .{ .help = "Current number of aggregate attestation pool groups." },
                ro,
            ),
            .aggregate_attestation_pool_entries = Gauge(u64).init(
                "beacon_aggregate_attestation_pool_entries",
                .{ .help = "Current number of aggregate attestation pool entries." },
                ro,
            ),
            .voluntary_exit_pool_size = Gauge(u64).init(
                "beacon_voluntary_exit_pool_size",
                .{ .help = "Current number of voluntary exits in the pool." },
                ro,
            ),
            .proposer_slashing_pool_size = Gauge(u64).init(
                "beacon_proposer_slashing_pool_size",
                .{ .help = "Current number of proposer slashings in the pool." },
                ro,
            ),
            .attester_slashing_pool_size = Gauge(u64).init(
                "beacon_attester_slashing_pool_size",
                .{ .help = "Current number of attester slashings in the pool." },
                ro,
            ),
            .bls_to_execution_change_pool_size = Gauge(u64).init(
                "beacon_bls_to_execution_change_pool_size",
                .{ .help = "Current number of BLS-to-execution changes in the pool." },
                ro,
            ),
            .sync_committee_message_pool_size = Gauge(u64).init(
                "beacon_sync_committee_message_pool_size",
                .{ .help = "Current number of sync committee messages in the pool." },
                ro,
            ),
            .sync_contribution_pool_size = Gauge(u64).init(
                "beacon_sync_contribution_pool_size",
                .{ .help = "Current number of sync committee contributions in the pool." },
                ro,
            ),
            .proposer_cache_entries = Gauge(u64).init(
                "beacon_proposer_cache_entries",
                .{ .help = "Current number of proposer-preparation cache entries." },
                ro,
            ),
            .pending_block_ingress_size = Gauge(u64).init(
                "beacon_pending_block_ingress_size",
                .{ .help = "Current number of pending beacon blocks awaiting attachments." },
                ro,
            ),
            .pending_block_ingress_added_total = Counter(u64).init(
                "beacon_pending_block_ingress_added_total",
                .{ .help = "Total pending beacon block ingress entries added." },
                ro,
            ),
            .pending_block_ingress_replaced_total = Counter(u64).init(
                "beacon_pending_block_ingress_replaced_total",
                .{ .help = "Total pending beacon block ingress entries replaced." },
                ro,
            ),
            .pending_block_ingress_resolved_total = Counter(u64).init(
                "beacon_pending_block_ingress_resolved_total",
                .{ .help = "Total pending beacon block ingress entries resolved." },
                ro,
            ),
            .pending_block_ingress_removed_total = Counter(u64).init(
                "beacon_pending_block_ingress_removed_total",
                .{ .help = "Total pending beacon block ingress entries removed." },
                ro,
            ),
            .pending_block_ingress_pruned_total = Counter(u64).init(
                "beacon_pending_block_ingress_pruned_total",
                .{ .help = "Total pending beacon block ingress entries pruned." },
                ro,
            ),
            .pending_payload_envelope_ingress_size = Gauge(u64).init(
                "beacon_pending_payload_envelope_ingress_size",
                .{ .help = "Current number of pending separated payload envelopes." },
                ro,
            ),
            .pending_payload_envelope_ingress_added_total = Counter(u64).init(
                "beacon_pending_payload_envelope_ingress_added_total",
                .{ .help = "Total pending payload-envelope ingress entries added." },
                ro,
            ),
            .pending_payload_envelope_ingress_replaced_total = Counter(u64).init(
                "beacon_pending_payload_envelope_ingress_replaced_total",
                .{ .help = "Total pending payload-envelope ingress entries replaced." },
                ro,
            ),
            .pending_payload_envelope_ingress_removed_total = Counter(u64).init(
                "beacon_pending_payload_envelope_ingress_removed_total",
                .{ .help = "Total pending payload-envelope ingress entries removed." },
                ro,
            ),
            .pending_payload_envelope_ingress_pruned_total = Counter(u64).init(
                "beacon_pending_payload_envelope_ingress_pruned_total",
                .{ .help = "Total pending payload-envelope ingress entries pruned." },
                ro,
            ),
            .reprocess_queue_size = Gauge(u64).init(
                "beacon_reprocess_queue_size",
                .{ .help = "Current number of queued blocks awaiting parent-driven reprocessing." },
                ro,
            ),
            .reprocess_queued_total = Counter(u64).init(
                "beacon_reprocess_queued_total",
                .{ .help = "Total blocks queued for parent-driven reprocessing." },
                ro,
            ),
            .reprocess_released_total = Counter(u64).init(
                "beacon_reprocess_released_total",
                .{ .help = "Total queued blocks released for reprocessing." },
                ro,
            ),
            .reprocess_dropped_total = Counter(u64).init(
                "beacon_reprocess_dropped_total",
                .{ .help = "Total queued blocks dropped from reprocessing." },
                ro,
            ),
            .reprocess_pruned_total = Counter(u64).init(
                "beacon_reprocess_pruned_total",
                .{ .help = "Total queued blocks pruned from reprocessing." },
                ro,
            ),
            .da_blob_tracker_entries = Gauge(u64).init(
                "beacon_da_blob_tracker_entries",
                .{ .help = "Current number of tracked blob-availability entries." },
                ro,
            ),
            .da_column_tracker_entries = Gauge(u64).init(
                "beacon_da_column_tracker_entries",
                .{ .help = "Current number of tracked custody-column entries." },
                ro,
            ),
            .da_pending_blocks = Gauge(u64).init(
                "beacon_da_pending_blocks",
                .{ .help = "Current number of blocks still waiting on data availability completion." },
                ro,
            ),
            .data_column_sidecar_processing_requests_total = Counter(u64).init(
                "beacon_data_column_sidecar_processing_requests_total",
                .{ .help = "Total data-column sidecar gossip processing requests." },
                ro,
            ),
            .data_column_sidecar_processing_successes_total = Counter(u64).init(
                "beacon_data_column_sidecar_processing_successes_total",
                .{ .help = "Total accepted data-column sidecar gossip messages." },
                ro,
            ),
            .data_column_sidecar_gossip_verification_seconds = Histogram(f64, &gossip_phase1_buckets).init(
                "beacon_data_column_sidecar_gossip_verification_seconds",
                .{ .help = "Distribution of data-column sidecar gossip verification durations in seconds." },
                ro,
            ),
            .data_availability_reconstructed_columns_total = Counter(u64).init(
                "beacon_data_availability_reconstructed_columns_total",
                .{ .help = "Total data-availability columns reconstructed locally." },
                ro,
            ),
            .data_availability_reconstruction_time_seconds = Histogram(f64, &gossip_processor_seconds_buckets).init(
                "beacon_data_availability_reconstruction_time_seconds",
                .{ .help = "Distribution of data-availability reconstruction durations in seconds." },
                ro,
            ),
            .data_column_sidecar_computation_seconds = Histogram(f64, &gossip_processor_seconds_buckets).init(
                "beacon_data_column_sidecar_computation_seconds",
                .{ .help = "Distribution of data-column sidecar computation durations in seconds." },
                ro,
            ),
            .data_column_sidecar_inclusion_proof_verification_seconds = Histogram(f64, &gossip_processor_seconds_buckets).init(
                "beacon_data_column_sidecar_inclusion_proof_verification_seconds",
                .{ .help = "Distribution of data-column sidecar inclusion proof verification durations in seconds." },
                ro,
            ),
            .kzg_verification_data_column_batch_seconds = Histogram(f64, &gossip_processor_seconds_buckets).init(
                "beacon_kzg_verification_data_column_batch_seconds",
                .{ .help = "Distribution of KZG data-column batch verification durations in seconds." },
                ro,
            ),
            .partial_message_useful_cells_total = try CounterVec(u64, ColumnIndexLabels).init(
                allocator,
                "beacon_partial_message_useful_cells_total",
                .{ .help = "Total useful cells extracted from partial data-column messages by column index." },
                ro,
            ),
            .partial_message_cells_received_total = try CounterVec(u64, ColumnIndexLabels).init(
                allocator,
                "beacon_partial_message_cells_received_total",
                .{ .help = "Total cells received from partial data-column messages by column index." },
                ro,
            ),
            .useful_full_columns_received_total = try CounterVec(u64, ColumnIndexLabels).init(
                allocator,
                "beacon_useful_full_columns_received_total",
                .{ .help = "Total useful full data columns received by column index." },
                ro,
            ),
            .partial_message_column_completions_total = try CounterVec(u64, ColumnIndexLabels).init(
                allocator,
                "beacon_partial_message_column_completions_total",
                .{ .help = "Total partial-message driven column completions by column index." },
                ro,
            ),
            .engine_get_blobs_v2_requests_total = Counter(u64).init(
                "beacon_engine_getBlobsV2_requests_total",
                .{ .help = "Total engine_getBlobsV2 requests sent to the execution layer." },
                ro,
            ),
            .engine_get_blobs_v2_responses_total = Counter(u64).init(
                "beacon_engine_getBlobsV2_responses_total",
                .{ .help = "Total engine_getBlobsV2 responses received from the execution layer." },
                ro,
            ),
            .engine_get_blobs_v2_request_duration_seconds = Histogram(f64, &el_request_buckets).init(
                "beacon_engine_getBlobsV2_request_duration_seconds",
                .{ .help = "Distribution of engine_getBlobsV2 request durations in seconds." },
                ro,
            ),
            .engine_get_blobs_v3_requests_total = Counter(u64).init(
                "beacon_engine_getBlobsV3_requests_total",
                .{ .help = "Total engine_getBlobsV3 requests sent to the execution layer." },
                ro,
            ),
            .engine_get_blobs_v3_complete_responses_total = Counter(u64).init(
                "beacon_engine_getBlobsV3_complete_responses_total",
                .{ .help = "Total complete engine_getBlobsV3 responses received from the execution layer." },
                ro,
            ),
            .engine_get_blobs_v3_partial_responses_total = Counter(u64).init(
                "beacon_engine_getBlobsV3_partial_responses_total",
                .{ .help = "Total partial engine_getBlobsV3 responses received from the execution layer." },
                ro,
            ),
            .engine_get_blobs_v3_request_duration_seconds = Histogram(f64, &el_request_buckets).init(
                "beacon_engine_getBlobsV3_request_duration_seconds",
                .{ .help = "Distribution of engine_getBlobsV3 request durations in seconds." },
                ro,
            ),
            .attestor_slashing_created_total = Gauge(u64).init(
                "beacon_attestor_slashing_created_total",
                .{ .help = "Compatibility gauge tracking total attester slashings created." },
                ro,
            ),
            .da_pending_marked_total = Counter(u64).init(
                "beacon_da_pending_marked_total",
                .{ .help = "Total blocks marked pending for data availability completion." },
                ro,
            ),
            .da_pending_resolved_total = Counter(u64).init(
                "beacon_da_pending_resolved_total",
                .{ .help = "Total pending data-availability blocks resolved." },
                ro,
            ),
            .da_pending_pruned_total = Counter(u64).init(
                "beacon_da_pending_pruned_total",
                .{ .help = "Total pending data-availability blocks pruned." },
                ro,
            ),
            .processor_loop_iterations_total = Counter(u64).init(
                "beacon_processor_loop_iterations_total",
                .{ .help = "Total processor loop iterations." },
                ro,
            ),
            .processor_items_received_total = Counter(u64).init(
                "beacon_processor_items_received_total",
                .{ .help = "Total items received by the processor." },
                ro,
            ),
            .processor_items_dispatched_total = Counter(u64).init(
                "beacon_processor_items_dispatched_total",
                .{ .help = "Total items dispatched from the processor to workers." },
                ro,
            ),
            .processor_items_dropped_full_total = Counter(u64).init(
                "beacon_processor_items_dropped_full_total",
                .{ .help = "Total processor items dropped because the queue was full." },
                ro,
            ),
            .processor_items_dropped_sync_total = Counter(u64).init(
                "beacon_processor_items_dropped_sync_total",
                .{ .help = "Total processor items dropped because sync conditions were not met." },
                ro,
            ),
            .processor_queue_depth = try GaugeVec(u64, ProcessorQueueLabels).init(
                allocator,
                "beacon_processor_queue_depth",
                .{ .help = "Current processor queue depth by queue." },
                ro,
            ),
            .processor_items_processed_total = try CounterVec(u64, ProcessorWorkTypeLabels).init(
                allocator,
                "beacon_processor_items_processed_total",
                .{ .help = "Total processor items processed by work type." },
                ro,
            ),
            .processor_processing_time_ns_total = try CounterVec(u64, ProcessorWorkTypeLabels).init(
                allocator,
                "beacon_processor_processing_time_ns_total",
                .{ .help = "Cumulative processor handling time in nanoseconds by work type." },
                ro,
            ),

            .block_production_requests_total = try CounterVec(u64, BlockProductionModeLabels).init(
                allocator,
                "beacon_block_production_requests_total",
                .{ .help = "Total block production requests by production mode." },
                ro,
            ),
            .block_production_success_total = try CounterVec(u64, BlockProductionSourceLabels).init(
                allocator,
                "beacon_block_production_success_total",
                .{ .help = "Total successful block production attempts by winning source." },
                ro,
            ),
            .block_production_seconds = try HistogramVec(f64, BlockProductionSourceLabels, &block_production_buckets).init(
                allocator,
                "beacon_block_production_seconds",
                .{ .help = "Distribution of block production durations in seconds by winning source." },
                ro,
            ),
            .block_production_selection_results_total = try CounterVec(u64, BlockProductionSelectionLabels).init(
                allocator,
                "beacon_block_production_selection_results_total",
                .{ .help = "Total block production source-selection results by source and reason." },
                ro,
            ),
            .block_production_step_seconds = try HistogramVec(f64, BlockProductionStepLabels, &block_production_step_buckets).init(
                allocator,
                "beacon_block_production_step_seconds",
                .{ .help = "Distribution of block production step durations in seconds by path and step." },
                ro,
            ),

            .execution_new_payload_seconds = Histogram(f64, &el_request_buckets).init(
                "execution_new_payload_seconds",
                .{ .help = "Distribution of engine_newPayload request durations in seconds." },
                ro,
            ),
            .execution_forkchoice_updated_seconds = Histogram(f64, &el_request_buckets).init(
                "execution_forkchoice_updated_seconds",
                .{ .help = "Distribution of engine_forkchoiceUpdated request durations in seconds." },
                ro,
            ),
            .execution_payload_valid_total = Counter(u64).init(
                "execution_payload_valid_total",
                .{ .help = "Total VALID payload status responses from the execution layer." },
                ro,
            ),
            .execution_payload_invalid_total = Counter(u64).init(
                "execution_payload_invalid_total",
                .{ .help = "Total INVALID payload status responses from the execution layer." },
                ro,
            ),
            .execution_payload_syncing_total = Counter(u64).init(
                "execution_payload_syncing_total",
                .{ .help = "Total SYNCING or ACCEPTED payload status responses from the execution layer." },
                ro,
            ),
            .execution_errors_total = Counter(u64).init(
                "execution_errors_total",
                .{ .help = "Total execution transport or request errors." },
                ro,
            ),
            .execution_pending_forkchoice_updates = Gauge(u64).init(
                "execution_pending_forkchoice_updates",
                .{ .help = "Current number of queued forkchoice updates waiting on the execution worker." },
                ro,
            ),
            .execution_pending_payload_verifications = Gauge(u64).init(
                "execution_pending_payload_verifications",
                .{ .help = "Current number of queued payload verifications waiting on the execution worker." },
                ro,
            ),
            .execution_completed_forkchoice_updates = Gauge(u64).init(
                "execution_completed_forkchoice_updates",
                .{ .help = "Current number of completed forkchoice updates awaiting node consumption." },
                ro,
            ),
            .execution_completed_payload_verifications = Gauge(u64).init(
                "execution_completed_payload_verifications",
                .{ .help = "Current number of completed payload verifications awaiting node consumption." },
                ro,
            ),
            .execution_failed_payload_preparations = Gauge(u64).init(
                "execution_failed_payload_preparations",
                .{ .help = "Current number of failed payload-preparation tickets awaiting node consumption." },
                ro,
            ),
            .execution_cached_payload = Gauge(u64).init(
                "execution_cached_payload",
                .{ .help = "Gauge indicating whether a cached payload ID is currently live: yes=1, no=0." },
                ro,
            ),
            .execution_offline = Gauge(u64).init(
                "execution_offline",
                .{ .help = "Gauge indicating whether the execution layer is currently considered offline: yes=1, no=0." },
                ro,
            ),
        };
    }

    pub fn initNoop() BeaconMetrics {
        return metrics_lib.initializeNoop(BeaconMetrics);
    }

    pub fn deinit(self: *BeaconMetrics) void {
        self.bootstrap_source.deinit();
        self.bootstrap_phase_seconds.deinit();
        self.block_import_source_seconds.deinit();
        self.block_import_results_total.deinit();
        self.connected_peer_direction_count.deinit();
        self.peer_connection_state_count.deinit();
        self.peer_client_count.deinit();
        self.peer_score_state_count.deinit();
        self.known_peer_score_state_count.deinit();
        self.peer_relevance_count.deinit();
        self.known_peer_relevance_count.deinit();
        self.peer_reports_total.deinit();
        self.peer_goodbye_received_total.deinit();
        self.db_entries.deinit();
        self.db_operation_total.deinit();
        self.db_operation_time_ns_total.deinit();
        self.api_requests_total.deinit();
        self.api_errors_total.deinit();
        self.api_request_seconds.deinit();
        self.api_stream_seconds.deinit();
        self.req_resp_inbound_requests_total.deinit();
        self.req_resp_outbound_requests_total.deinit();
        self.req_resp_maintenance_errors_total.deinit();
        self.req_resp_inbound_request_seconds.deinit();
        self.req_resp_outbound_request_seconds.deinit();
        self.req_resp_inbound_request_payload_bytes_total.deinit();
        self.req_resp_outbound_request_payload_bytes_total.deinit();
        self.req_resp_inbound_response_payload_bytes_total.deinit();
        self.req_resp_outbound_response_payload_bytes_total.deinit();
        self.req_resp_inbound_response_chunks_total.deinit();
        self.req_resp_outbound_response_chunks_total.deinit();
        self.req_resp_inbound_response_payload_bytes.deinit();
        self.req_resp_outbound_response_payload_bytes.deinit();
        self.req_resp_inbound_response_chunks.deinit();
        self.req_resp_outbound_response_chunks.deinit();
        self.gossip_messages_received_by_topic_total.deinit();
        self.gossip_messages_result_total.deinit();
        self.gossip_phase1_seconds.deinit();
        self.gossip_processor_queue_depth.deinit();
        self.gossip_processor_messages_total.deinit();
        self.gossip_processor_queue_seconds.deinit();
        self.gossip_processor_handle_seconds.deinit();
        self.gossip_bls_pending_batches.deinit();
        self.gossip_bls_pending_items.deinit();
        self.gossip_bls_verifications_total.deinit();
        self.gossip_bls_items_total.deinit();
        self.gossip_bls_batch_size.deinit();
        self.gossip_bls_queue_seconds.deinit();
        self.gossip_bls_verify_seconds.deinit();
        self.gossipsub_mesh_peers_per_main_topic.deinit();
        self.gossipsub_mesh_peer_counts.deinit();
        self.gossipsub_topic_msg_sent_bytes.deinit();
        self.discovery_dials_total.deinit();
        self.discovery_dial_time_ns_total.deinit();
        self.sync_mode_state.deinit();
        self.range_sync_active_chains.deinit();
        self.range_sync_peers.deinit();
        self.range_sync_target_slot.deinit();
        self.range_sync_validated_epochs.deinit();
        self.range_sync_batches.deinit();
        self.range_sync_batch_statuses.deinit();
        self.range_sync_download_requests_total.deinit();
        self.range_sync_download_success_total.deinit();
        self.range_sync_download_error_total.deinit();
        self.range_sync_download_deferred_total.deinit();
        self.range_sync_download_time_ns_total.deinit();
        self.range_sync_processing_success_total.deinit();
        self.range_sync_processing_error_total.deinit();
        self.range_sync_processing_time_ns_total.deinit();
        self.range_sync_processed_blocks_total.deinit();
        self.range_sync_pending_segments.deinit();
        self.range_sync_inflight_segments.deinit();
        self.range_sync_pending_blocks.deinit();
        self.range_sync_pending_remaining_blocks.deinit();
        self.range_sync_segment_results_total.deinit();
        self.range_sync_segment_failures_total.deinit();
        self.range_sync_segment_queue_busy_total.deinit();
        self.range_sync_segment_seconds.deinit();
        self.range_sync_segment_blocks.deinit();
        self.processor_queue_depth.deinit();
        self.processor_items_processed_total.deinit();
        self.processor_processing_time_ns_total.deinit();
        self.partial_message_useful_cells_total.deinit();
        self.partial_message_cells_received_total.deinit();
        self.useful_full_columns_received_total.deinit();
        self.partial_message_column_completions_total.deinit();
        self.block_production_requests_total.deinit();
        self.block_production_success_total.deinit();
        self.block_production_seconds.deinit();
        self.block_production_selection_results_total.deinit();
        self.block_production_step_seconds.deinit();
    }

    pub fn write(self: *BeaconMetrics, writer: *std.Io.Writer) !void {
        try metrics_lib.write(self, writer);
    }

    pub const BootstrapSource = enum {
        checkpoint_sync_url,
        checkpoint_file,
        db_resume,
        minimal_genesis,
    };

    pub const BootstrapPhase = enum {
        fetch,
        load,
        cache_seed,
        deserialize,
        generate,
        finish,
        total,
    };

    pub const RangeSyncSegmentResult = enum {
        complete,
        complete_with_skips,
        partial,
        failed,
        skipped,
    };

    pub const RangeSyncSegmentStage = enum {
        prepare,
        plan,
        queue,
        commit,
        execution_verify,
    };

    pub fn setBootstrapSource(self: *BeaconMetrics, source: BootstrapSource) void {
        inline for (std.meta.fields(BootstrapSource)) |field| {
            const field_source = @field(BootstrapSource, field.name);
            self.bootstrap_source.set(
                .{ .source = field.name },
                if (field_source == source) 1 else 0,
            ) catch {};
        }
    }

    pub fn setBootstrapState(self: *BeaconMetrics, state_slot: u64, state_bytes: usize) void {
        self.bootstrap_state_slot.set(state_slot);
        self.bootstrap_state_bytes.set(@intCast(state_bytes));
    }

    pub fn observeBootstrapPhase(
        self: *BeaconMetrics,
        source: BootstrapSource,
        phase: BootstrapPhase,
        elapsed_seconds: f64,
    ) void {
        self.bootstrap_phase_seconds.observe(.{
            .source = bootstrapSourceLabel(source),
            .phase = bootstrapPhaseLabel(phase),
        }, elapsed_seconds) catch {};
    }

    pub fn setApiActiveConnections(self: *BeaconMetrics, active_connections: u32) void {
        self.api_active_connections.set(active_connections);
    }

    pub fn setPeerManagerSnapshot(
        self: *BeaconMetrics,
        snapshot: networking.PeerManagerMetricsSnapshot,
    ) void {
        self.libp2p_peers.set(snapshot.connected_peers);
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

        inline for (networking.peer_manager.metric_client_kinds) |kind| {
            self.peer_client_count.set(
                .{ .client = clientKindLabel(kind) },
                snapshot.clientKindCount(kind),
            ) catch {};
        }

        inline for (networking.peer_manager.metric_score_states) |state| {
            self.peer_score_state_count.set(
                .{ .state = scoreStateLabel(state) },
                snapshot.scoreStateCount(state),
            ) catch {};
            self.known_peer_score_state_count.set(
                .{ .state = scoreStateLabel(state) },
                snapshot.knownScoreStateCount(state),
            ) catch {};
        }

        inline for (networking.peer_manager.metric_relevance_states) |status| {
            self.peer_relevance_count.set(
                .{ .status = relevanceStatusLabel(status) },
                snapshot.relevanceCount(status),
            ) catch {};
            self.known_peer_relevance_count.set(
                .{ .status = relevanceStatusLabel(status) },
                snapshot.knownRelevanceCount(status),
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

    pub fn setGossipsubSnapshot(
        self: *BeaconMetrics,
        snapshot: networking.P2pGossipsubMetricsSnapshot,
    ) void {
        self.gossipsub_outbound_streams.set(snapshot.outbound_streams);
        self.gossipsub_tracked_subscriptions.set(snapshot.tracked_subscriptions);
        self.gossipsub_known_topics.set(snapshot.known_topics);
        self.gossipsub_mesh_topics.set(snapshot.mesh_topics);
        self.gossipsub_mesh_peers.set(snapshot.mesh_peers);
        self.gossipsub_topic_peers.set(snapshot.topic_peers);
        self.gossipsub_tracked_topics_with_peers.set(snapshot.tracked_topics_with_peers);
        self.gossipsub_tracked_topic_peers.set(snapshot.tracked_topic_peers);
        self.gossipsub_pending_events.set(snapshot.pending_events);
        self.gossipsub_pending_sends.set(snapshot.pending_sends);
        self.gossipsub_pending_send_bytes.set(snapshot.pending_send_bytes);

        inline for (std.meta.fields(networking.GossipTopicType)) |field| {
            const topic = @field(networking.GossipTopicType, field.name);
            const mesh_count = snapshot.mesh_peers_by_topic[@intFromEnum(topic)];
            const topic_label = topic.topicName();
            self.gossipsub_mesh_peers_per_main_topic.set(.{ .topic = topic_label }, mesh_count) catch {};
            self.gossipsub_mesh_peer_counts.set(.{
                .topic = topic_label,
                .supports_partial = "false",
            }, mesh_count) catch {};
            self.gossipsub_mesh_peer_counts.set(.{
                .topic = topic_label,
                .supports_partial = "true",
            }, 0) catch {};
        }
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

    pub fn setSyncState(self: *BeaconMetrics, sync_state: u64) void {
        self.sync_state.set(sync_state);
    }

    pub fn setSyncModeState(self: *BeaconMetrics, mode: sync.SyncMode) void {
        inline for (std.meta.fields(sync.SyncMode)) |field| {
            const field_mode = @field(sync.SyncMode, field.name);
            self.sync_mode_state.set(
                .{ .mode = field.name },
                if (field_mode == mode) 1 else 0,
            ) catch {};
        }
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
        if (std.mem.eql(u8, source, "gossip")) {
            self.processor_gossip_block_imported_total.incrBy(count);
        }
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
        self.reorgs_total.incr();
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
        self.http_api_requests_total.incr();
        if (is_error) {
            self.api_errors_total.incr(labels) catch return;
        } else {
            self.http_api_successes_total.incr();
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
        request_payload_bytes: u64,
        response_payload_bytes: u64,
        response_chunks: u64,
    ) void {
        const method_labels: ReqRespMethodLabels = .{ .method = reqRespMethodLabel(method) };
        const outcome_labels: ReqRespMethodOutcomeLabels = .{
            .method = method_labels.method,
            .outcome = reqRespOutcomeLabel(outcome),
        };
        self.req_resp_inbound_requests_total.incr(outcome_labels) catch return;
        self.req_resp_inbound_request_payload_bytes_total.incrBy(method_labels, request_payload_bytes) catch return;
        self.req_resp_inbound_response_payload_bytes_total.incrBy(method_labels, response_payload_bytes) catch return;
        self.req_resp_inbound_response_chunks_total.incrBy(method_labels, response_chunks) catch return;
        self.req_resp_inbound_request_seconds.observe(method_labels, response_time_seconds) catch return;
        self.req_resp_inbound_response_payload_bytes.observe(method_labels, @floatFromInt(response_payload_bytes)) catch return;
        self.req_resp_inbound_response_chunks.observe(method_labels, @floatFromInt(response_chunks)) catch return;
    }

    pub fn observeReqRespOutbound(
        self: *BeaconMetrics,
        method: networking.Method,
        outcome: networking.ReqRespRequestOutcome,
        response_time_seconds: f64,
        request_payload_bytes: u64,
        response_payload_bytes: u64,
        response_chunks: u64,
    ) void {
        const method_labels: ReqRespMethodLabels = .{ .method = reqRespMethodLabel(method) };
        const outcome_labels: ReqRespMethodOutcomeLabels = .{
            .method = method_labels.method,
            .outcome = reqRespOutcomeLabel(outcome),
        };
        self.req_resp_outbound_requests_total.incr(outcome_labels) catch return;
        self.req_resp_outbound_request_payload_bytes_total.incrBy(method_labels, request_payload_bytes) catch return;
        self.req_resp_outbound_response_payload_bytes_total.incrBy(method_labels, response_payload_bytes) catch return;
        self.req_resp_outbound_response_chunks_total.incrBy(method_labels, response_chunks) catch return;
        self.req_resp_outbound_request_seconds.observe(method_labels, response_time_seconds) catch return;
        self.req_resp_outbound_response_payload_bytes.observe(method_labels, @floatFromInt(response_payload_bytes)) catch return;
        self.req_resp_outbound_response_chunks.observe(method_labels, @floatFromInt(response_chunks)) catch return;
    }

    pub fn incrReqRespMaintenanceError(
        self: *BeaconMetrics,
        method: networking.Method,
        error_label: []const u8,
    ) void {
        self.req_resp_maintenance_errors_total.incr(.{
            .method = reqRespMethodLabel(method),
            .error_kind = error_label,
        }) catch {};
    }

    pub fn incrGossipReceived(self: *BeaconMetrics, topic: networking.GossipTopicType) void {
        self.gossip_messages_received.incr();
        self.gossip_messages_received_by_topic_total.incr(.{ .topic = topic.topicName() }) catch {};
        switch (topic) {
            .beacon_attestation => self.attestations_received_total.incr(),
            .beacon_aggregate_and_proof => self.aggregates_received_total.incr(),
            .attester_slashing => self.attestor_slashing_received_total.incr(),
            .data_column_sidecar => self.data_column_sidecar_processing_requests_total.incr(),
            else => {},
        }
    }

    pub const GossipMessageOutcome = enum {
        accepted,
        ignored,
        rejected,
    };

    pub const GossipProcessorKind = enum {
        block,
        attestation,
        aggregate,
        sync_message,
        sync_contribution,
        blob_sidecar,
        data_column_sidecar,
        voluntary_exit,
        proposer_slashing,
        attester_slashing,
        bls_to_execution_change,
        execution_payload,
        payload_attestation,
        execution_payload_bid,
        proposer_preferences,
        pool_object,
    };

    pub const GossipBlsKind = enum {
        attestation,
        aggregate,
        sync_message,
    };

    pub const GossipBlsPath = enum {
        single,
        batch_sync,
        batch_async,
    };

    pub const GossipBlsOutcome = enum {
        success,
        fallback,
        failure,
    };

    pub fn observeGossipResult(
        self: *BeaconMetrics,
        topic: networking.GossipTopicType,
        outcome: GossipMessageOutcome,
    ) void {
        switch (outcome) {
            .accepted => self.gossip_messages_validated.incr(),
            .ignored => self.gossip_messages_ignored.incr(),
            .rejected => {
                self.gossip_messages_rejected.incr();
                self.pubsub_validation_failure_total.incr();
            },
        }
        self.gossip_messages_result_total.incr(.{
            .topic = topic.topicName(),
            .outcome = @tagName(outcome),
        }) catch {};
        if (topic == .data_column_sidecar and outcome == .accepted) {
            self.data_column_sidecar_processing_successes_total.incr();
        }
    }

    pub fn observeGossipPhase1(
        self: *BeaconMetrics,
        topic: networking.GossipTopicType,
        outcome: GossipMessageOutcome,
        elapsed_seconds: f64,
    ) void {
        self.gossip_phase1_seconds.observe(.{
            .topic = topic.topicName(),
            .outcome = @tagName(outcome),
        }, elapsed_seconds) catch {};
        if (topic == .data_column_sidecar) {
            self.data_column_sidecar_gossip_verification_seconds.observe(elapsed_seconds);
        }
    }

    pub fn observeGossipsubTopicSentBytes(
        self: *BeaconMetrics,
        topic: networking.GossipTopicType,
        partial: bool,
        bytes: u64,
    ) void {
        self.gossipsub_topic_msg_sent_bytes.incrBy(.{
            .topic = topic.topicName(),
            .partial = if (partial) "true" else "false",
        }, bytes) catch {};
    }

    pub fn observeDataColumnKzgVerification(
        self: *BeaconMetrics,
        elapsed_seconds: f64,
    ) void {
        self.kzg_verification_data_column_batch_seconds.observe(elapsed_seconds);
    }

    pub fn setGossipProcessorQueueDepth(
        self: *BeaconMetrics,
        kind: GossipProcessorKind,
        depth: u64,
    ) void {
        self.gossip_processor_queue_depth.set(.{
            .kind = @tagName(kind),
        }, depth) catch {};
    }

    pub fn observeGossipProcessor(
        self: *BeaconMetrics,
        kind: GossipProcessorKind,
        message_count: u64,
        queue_seconds: f64,
        handle_seconds: f64,
    ) void {
        const labels: GossipProcessorKindLabels = .{ .kind = @tagName(kind) };
        self.gossip_processor_messages_total.incrBy(labels, message_count) catch {};
        var observed: u64 = 0;
        while (observed < message_count) : (observed += 1) {
            self.gossip_processor_queue_seconds.observe(labels, queue_seconds) catch {};
            self.gossip_processor_handle_seconds.observe(labels, handle_seconds) catch {};
        }
    }

    pub fn setGossipBlsPendingSnapshot(
        self: *BeaconMetrics,
        kind: GossipBlsKind,
        pending_batches: u64,
        pending_items: u64,
    ) void {
        const labels: GossipBlsKindLabels = .{ .kind = @tagName(kind) };
        self.gossip_bls_pending_batches.set(labels, pending_batches) catch {};
        self.gossip_bls_pending_items.set(labels, pending_items) catch {};
    }

    pub fn observeGossipBlsVerification(
        self: *BeaconMetrics,
        kind: GossipBlsKind,
        path: GossipBlsPath,
        outcome: GossipBlsOutcome,
        item_count: u64,
        queue_seconds: ?f64,
        verify_seconds: f64,
    ) void {
        const verification_labels: GossipBlsVerificationLabels = .{
            .kind = @tagName(kind),
            .path = @tagName(path),
            .outcome = @tagName(outcome),
        };
        const path_labels: GossipBlsPathLabels = .{
            .kind = verification_labels.kind,
            .path = verification_labels.path,
        };
        self.gossip_bls_verifications_total.incr(verification_labels) catch {};
        self.gossip_bls_items_total.incrBy(verification_labels, item_count) catch {};
        if (path != .single) {
            self.gossip_bls_batch_size.observe(path_labels, @floatFromInt(item_count)) catch {};
        }
        if (queue_seconds) |elapsed_seconds| {
            self.gossip_bls_queue_seconds.observe(.{ .kind = verification_labels.kind }, elapsed_seconds) catch {};
        }
        self.gossip_bls_verify_seconds.observe(path_labels, verify_seconds) catch {};
    }

    pub fn setHeadCatchupSnapshot(
        self: *BeaconMetrics,
        head_lag_slots: u64,
        pending_slots: u64,
        current_ms: u64,
    ) void {
        self.head_lag_slots.set(head_lag_slots);
        self.head_catchup_pending_slots.set(pending_slots);
        self.time_to_head_current_ms.set(current_ms);
    }

    pub fn observeTimeToHead(self: *BeaconMetrics, elapsed_seconds: f64, elapsed_ms: u64) void {
        self.time_to_head_last_ms.set(elapsed_ms);
        self.time_to_head_seconds.observe(elapsed_seconds);
    }

    pub const BlockProductionSource = enum {
        engine,
        builder,
    };

    pub const BlockProductionStepPath = enum {
        shared,
        engine,
        builder,
        race,
    };

    pub const BlockProductionStep = enum {
        prepare_context,
        ensure_payload,
        build_template,
        fetch_payload,
        fetch_sources,
        fetch_bid,
        assemble,
    };

    pub const BlockProductionSelectionReason = enum {
        builder_disabled,
        builder_unavailable,
        builder_circuit_breaker,
        boost_zero,
        builder_no_bid,
        builder_error,
        builder_pending,
        builder_value_not_competitive,
        builder_header_gas_limit_rejected,
        builder_censorship_override,
        engine_disabled,
        engine_error,
        engine_pending,
        builder_value_higher,
    };

    pub fn incrBlockProductionRequest(
        self: *BeaconMetrics,
        selection: api_mod.types.BuilderSelection,
    ) void {
        self.block_production_requests_total.incr(.{
            .mode = selection.queryValue(),
        }) catch {};
    }

    pub fn observeBlockProductionSuccess(
        self: *BeaconMetrics,
        source: BlockProductionSource,
        elapsed_seconds: f64,
    ) void {
        const labels: BlockProductionSourceLabels = .{ .source = @tagName(source) };
        self.block_production_success_total.incr(labels) catch {};
        self.block_production_seconds.observe(labels, elapsed_seconds) catch {};
    }

    pub fn incrBlockProductionSelection(
        self: *BeaconMetrics,
        source: BlockProductionSource,
        reason: BlockProductionSelectionReason,
    ) void {
        self.block_production_selection_results_total.incr(.{
            .source = @tagName(source),
            .reason = @tagName(reason),
        }) catch {};
    }

    pub fn observeBlockProductionStep(
        self: *BeaconMetrics,
        path: BlockProductionStepPath,
        step: BlockProductionStep,
        elapsed_seconds: f64,
    ) void {
        self.block_production_step_seconds.observe(.{
            .path = @tagName(path),
            .step = @tagName(step),
        }, elapsed_seconds) catch {};
    }

    pub fn setReqRespLimiterPeers(self: *BeaconMetrics, inbound_peers: usize, outbound_peers: usize) void {
        self.req_resp_inbound_limiter_peers.set(@intCast(inbound_peers));
        self.req_resp_outbound_limiter_peers.set(@intCast(outbound_peers));
    }

    pub fn setUnknownBlockSnapshot(
        self: *BeaconMetrics,
        snapshot: sync.unknown_block.MetricsSnapshot,
    ) void {
        self.sync_unknown_block_pending.set(snapshot.pending_blocks);
        self.sync_unknown_block_fetching.set(snapshot.fetching_blocks);
        self.sync_unknown_block_parents_needed.set(snapshot.pending_parents);
        self.sync_unknown_block_in_flight.set(snapshot.in_flight_requests);
        self.sync_unknown_block_bad_roots.set(snapshot.bad_roots);
        self.sync_unknown_block_exhausted.set(snapshot.exhausted_blocks);
    }

    pub fn setRangeSyncPendingSnapshot(
        self: *BeaconMetrics,
        sync_type: sync.RangeSyncType,
        pending_segments: u64,
        inflight_segments: u64,
        pending_blocks: u64,
        pending_remaining_blocks: u64,
    ) void {
        const labels: SyncTypeLabels = .{ .sync_type = @tagName(sync_type) };
        self.range_sync_pending_segments.set(labels, pending_segments) catch {};
        self.range_sync_inflight_segments.set(labels, inflight_segments) catch {};
        self.range_sync_pending_blocks.set(labels, pending_blocks) catch {};
        self.range_sync_pending_remaining_blocks.set(labels, pending_remaining_blocks) catch {};
    }

    pub fn observeRangeSyncSegment(
        self: *BeaconMetrics,
        sync_type: sync.RangeSyncType,
        result: RangeSyncSegmentResult,
        block_count: u64,
        elapsed_seconds: f64,
    ) void {
        const labels: SyncRangeSegmentResultLabels = .{
            .sync_type = @tagName(sync_type),
            .result = @tagName(result),
        };
        self.range_sync_segment_results_total.incr(labels) catch {};
        self.range_sync_segment_seconds.observe(labels, elapsed_seconds) catch {};
        self.range_sync_segment_blocks.observe(.{ .sync_type = labels.sync_type }, @floatFromInt(block_count)) catch {};
    }

    pub fn incrRangeSyncSegmentFailure(
        self: *BeaconMetrics,
        sync_type: sync.RangeSyncType,
        stage: RangeSyncSegmentStage,
        error_label: []const u8,
    ) void {
        self.range_sync_segment_failures_total.incr(.{
            .sync_type = @tagName(sync_type),
            .stage = @tagName(stage),
            .error_kind = error_label,
        }) catch {};
    }

    pub fn incrRangeSyncSegmentQueueBusy(
        self: *BeaconMetrics,
        sync_type: sync.RangeSyncType,
    ) void {
        self.range_sync_segment_queue_busy_total.incr(.{
            .sync_type = @tagName(sync_type),
        }) catch {};
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

fn clientKindLabel(kind: networking.ClientKind) []const u8 {
    return switch (kind) {
        .lodestar_z => "lodestar-z",
        else => @tagName(kind),
    };
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

fn bootstrapSourceLabel(source: BeaconMetrics.BootstrapSource) []const u8 {
    return @tagName(source);
}

fn bootstrapPhaseLabel(phase: BeaconMetrics.BootstrapPhase) []const u8 {
    return @tagName(phase);
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
    m.setSyncModeState(.range_sync);
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
    m.observeReqRespInbound(.status, .success, 0.02, 84, 84, 1);
    m.observeReqRespOutbound(.ping, .transport_error, 0.03, 8, 0, 0);
    m.incrReqRespMaintenanceError(.beacon_blocks_by_root, "no_block_returned");
    m.setReqRespLimiterPeers(4, 2);
    m.setUnknownBlockSnapshot(.{
        .pending_blocks = 3,
        .fetching_blocks = 1,
        .pending_parents = 2,
        .in_flight_requests = 1,
        .bad_roots = 4,
        .exhausted_blocks = 1,
    });
    m.setRangeSyncPendingSnapshot(.head, 2, 1, 64, 40);
    m.observeRangeSyncSegment(.head, .partial, 32, 1.25);
    m.incrRangeSyncSegmentFailure(.head, .plan, "parent_unknown");
    m.incrRangeSyncSegmentQueueBusy(.head);
    m.incrBlockProductionRequest(.maxprofit);
    m.observeBlockProductionSuccess(.engine, 0.2);
    m.incrBlockProductionSelection(.engine, .builder_no_bid);
    m.observeBlockProductionStep(.race, .fetch_sources, 0.03);
    m.incrGossipReceived(.beacon_block);
    m.observeGossipResult(.beacon_block, .accepted);
    m.state_work_pending_jobs.set(2);
    m.state_work_completed_jobs.set(1);
    m.state_work_active_jobs.set(3);
    m.state_work_submitted_total.incrBy(4);
    m.state_work_rejected_total.incrBy(1);
    m.state_work_success_total.incrBy(3);
    m.state_work_failure_total.incrBy(1);
    m.state_work_execution_time_ns_total.incrBy(200);
    m.state_work_last_execution_time_ns.set(50);
    m.execution_new_payload_seconds.observe(0.1);
    m.peer_connected_total.incr();
    try std.testing.expectEqual(@as(u64, 42), m.head_slot.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.blocks_imported_total.impl.count);
    try std.testing.expectEqual(@as(usize, 1), m.block_import_source_seconds.impl.values.count());
    try std.testing.expectEqual(@as(usize, 2), m.block_import_results_total.impl.values.count());
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
    try std.testing.expectEqual(@as(usize, 4), m.sync_mode_state.impl.values.count());
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
    try std.testing.expectEqual(@as(usize, networking.peer_manager.metric_client_kinds.len), m.peer_client_count.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_maintenance_errors_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_inbound_request_payload_bytes_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_outbound_request_payload_bytes_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_inbound_response_payload_bytes_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_outbound_response_payload_bytes_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_inbound_response_chunks_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.req_resp_outbound_response_chunks_total.impl.values.count());
    try std.testing.expectEqual(@as(u64, 3), m.sync_unknown_block_pending.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.sync_unknown_block_fetching.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.sync_unknown_block_parents_needed.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.sync_unknown_block_in_flight.impl.value);
    try std.testing.expectEqual(@as(u64, 4), m.sync_unknown_block_bad_roots.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.sync_unknown_block_exhausted.impl.value);
    try std.testing.expectEqual(@as(usize, 1), m.range_sync_pending_segments.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.range_sync_segment_results_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.range_sync_segment_failures_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.range_sync_segment_queue_busy_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.block_production_requests_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.block_production_success_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.block_production_selection_results_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.block_production_step_seconds.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.gossip_messages_received_by_topic_total.impl.values.count());
    try std.testing.expectEqual(@as(usize, 1), m.gossip_messages_result_total.impl.values.count());
    try std.testing.expectEqual(@as(u64, 2), m.state_work_pending_jobs.impl.value);
    try std.testing.expectEqual(@as(u64, 4), m.state_work_submitted_total.impl.count);
    try std.testing.expectEqual(@as(u64, 50), m.state_work_last_execution_time_ns.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.peer_connected_total.impl.count);
}

test "BeaconMetrics: initNoop produces zero-overhead stubs" {
    var m = BeaconMetrics.initNoop();
    defer m.deinit();
    m.head_slot.set(999);
    m.observeImportedBlocks("gossip", 1, 0.05);
    m.setApiActiveConnections(1);
    m.observeApiRequest("getNodeIdentity", 0.01, true);
    m.observeReqRespInbound(.status, .success, 0.02, 84, 84, 1);
    m.observeReqRespOutbound(.ping, .self_rate_limited, 0.0, 8, 0, 0);
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
    _ = try pm.onPeerConnected("peer_c", .outbound, 1000);
    try pm.updateAgentVersion("peer_a", "Lighthouse/v4.5.0");
    try pm.updateAgentVersion("peer_b", "lodestar-z/0.0.1");
    _ = pm.reportPeer("peer_a", .low_tolerance, .rpc, 1100);
    pm.onPeerGoodbye("peer_c", .too_many_peers, 1200);
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
    m.observeReqRespInbound(.status, .success, 0.02, 84, 84, 1);
    m.observeReqRespOutbound(.ping, .transport_error, 0.03, 8, 0, 0);
    m.incrReqRespMaintenanceError(.beacon_blocks_by_root, "decode_error");
    m.setReqRespLimiterPeers(4, 2);
    m.observeApiRequest("getEvents", 3.0, false);
    m.observeApiRequest("publishBlockV2", 0.02, true);
    m.observeReqRespInbound(.status, .success, 0.02, 84, 84, 1);
    m.observeReqRespInbound(.beacon_blocks_by_range, .resource_unavailable, 0.04, 24, 0, 0);
    m.observeReqRespOutbound(.ping, .success, 0.01, 8, 8, 1);
    m.observeReqRespOutbound(.metadata, .malformed_response, 0.03, 0, 0, 0);
    m.setReqRespLimiterPeers(5, 3);
    m.incrBlockProductionRequest(.maxprofit);
    m.observeBlockProductionSuccess(.builder, 0.4);
    m.incrBlockProductionSelection(.builder, .builder_value_higher);
    m.observeBlockProductionStep(.shared, .prepare_context, 0.01);
    m.observeBlockProductionStep(.builder, .assemble, 0.02);
    m.incrGossipReceived(.beacon_block);
    m.observeGossipResult(.beacon_block, .accepted);
    m.observeGossipResult(.beacon_attestation, .rejected);
    m.setSyncModeState(.synced);
    m.setUnknownBlockSnapshot(.{
        .pending_blocks = 2,
        .fetching_blocks = 1,
        .pending_parents = 2,
        .in_flight_requests = 1,
        .bad_roots = 3,
        .exhausted_blocks = 1,
    });
    m.setRangeSyncPendingSnapshot(.head, 1, 1, 32, 20);
    m.observeRangeSyncSegment(.head, .partial, 32, 1.5);
    m.incrRangeSyncSegmentFailure(.head, .plan, "parent_unknown");
    m.incrRangeSyncSegmentQueueBusy(.head);
    m.state_work_pending_jobs.set(2);
    m.state_work_completed_jobs.set(1);
    m.state_work_active_jobs.set(1);
    m.state_work_submitted_total.incrBy(4);
    m.state_work_rejected_total.incrBy(1);
    m.state_work_success_total.incrBy(3);
    m.state_work_failure_total.incrBy(1);
    m.state_work_execution_time_ns_total.incrBy(200);
    m.state_work_last_execution_time_ns.set(50);
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
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_client_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_score_state_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_known_peer_score_state_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_relevance_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_known_peer_relevance_count") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_maintenance_errors_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_request_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_request_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_request_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_response_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_response_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_response_chunks_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_response_chunks_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_response_payload_bytes") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_response_payload_bytes") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_response_chunks") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_response_chunks") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_production_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_production_success_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_production_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_production_selection_results_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_production_step_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_gossip_messages_received_by_topic_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_gossip_messages_result_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_work_pending_jobs") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_work_submitted_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_work_last_execution_time_ns") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "getNodeIdentity") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "getEvents") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "status") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "metadata") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "malformed_response") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "maxprofit") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "builder_value_higher") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "prepare_context") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "queued_unknown_parent") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "gossip") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "accepted") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "mode=\"synced\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "decode_error") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "low_tolerance") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "too_many_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "disconnecting") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "client=\"lighthouse\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "client=\"lodestar-z\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_status") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_mode_state") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_optimistic") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_el_offline") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_unknown_block_fetching") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_sync_unknown_block_bad_roots") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_range_sync_pending_segments") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_range_sync_segment_results_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_range_sync_segment_failures_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_range_sync_segment_queue_busy_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_range_sync_segment_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_range_sync_segment_blocks") != null);
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
    var beacon = try BeaconMetrics.init(std.testing.allocator);
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

test "MetricsSurface: runs scrape collector before write" {
    var beacon = try BeaconMetrics.init(std.testing.allocator);
    defer beacon.deinit();

    const CollectorState = struct {
        beacon: *BeaconMetrics,

        fn collect(self: *@This()) void {
            self.beacon.head_slot.set(77);
        }
    };

    var collector_state = CollectorState{ .beacon = &beacon };
    var surface = MetricsSurface{ .beacon = &beacon };
    surface.setScrapeCollector(ScrapeCollector.init(&collector_state, CollectorState.collect));

    beacon.head_slot.set(12);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try surface.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot 77") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_request_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_request_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_response_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_response_payload_bytes_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_inbound_response_chunks_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_reqresp_outbound_response_chunks_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "publishBlockV2") != null);
}
