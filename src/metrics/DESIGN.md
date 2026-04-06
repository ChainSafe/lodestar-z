# Metrics Framework Design

## Overview

lodestar-z uses a Prometheus-compatible metrics framework for operational
monitoring, performance debugging, and operator visibility.

## Architecture

```
┌──────────────────┐     ┌──────────────────┐
│  BeaconMetrics   │     │ ValidatorMetrics │
│  node subsystem  │     │ validator client │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         │                 ┌──────┴────────────────────┐
         │                 │ explicit launcher/runtime │
         │                 │ ownership of metrics      │
         │                 └────────────┬──────────────┘
         │                              │
┌────────┴──────────────────────────────┴──────────────┐
│                subsystem instrumentation             │
│ node/*, validator/*, chain/*, execution/*, sync/*   │
│ state_transition/metrics.zig carried by cached state│
└──────────────┬───────────────────────────────────────┘
               │
      ┌────────┴─────────┐
      │ shared metrics   │
      │ HTTP server/runtime │
      │ GET /metrics     │
      └──────────────────┘
               │
          Prometheus
```

## Metric Types

All types from the `metrics` library dependency (lock-free, noop-capable):

| Type | Usage | Operations |
|------|-------|------------|
| `Counter(T)` | Monotonically increasing values | `incr()`, `incrBy(n)` |
| `Gauge(T)` | Values that go up and down | `set(v)`, `incr()`, `incrBy(v)` |
| `Histogram(T, buckets)` | Latency distributions | `observe(v)` |
| `*Vec` variants | Labeled metrics | Same + labels struct |

### Noop Mode (Zero Overhead)

Every metric is a `union(enum) { noop, impl }`. When metrics are disabled, the
launcher/runtime owns noop metric values and passes them through the same APIs
as live metrics. Hot subsystems do not have a separate initialization path.

```zig
// Enabled:
var m = BeaconMetrics.init();

// Disabled (zero overhead):
var m = BeaconMetrics.initNoop();
```

## Metric Categories

### Beacon Node (live today)

#### Chain state
- `beacon_head_slot` — current canonical head slot
- `beacon_head_root` — first 8 bytes of the canonical head root, for change detection
- `beacon_finalized_epoch` — finalized epoch
- `beacon_justified_epoch` — justified epoch

#### Block import
- `beacon_blocks_imported_total` — successfully imported blocks
- `beacon_block_import_seconds` — successful block-import operation latency histogram
- `beacon_block_import_source_seconds` — successful block-import operation latency by source
- `beacon_block_import_results_total` — terminal block-import outcomes by source and outcome
- `beacon_block_import_optimistic_total` — imported blocks accepted optimistically because EL validation is still syncing
- `beacon_epoch_transitions_total` — imported blocks that crossed an epoch boundary
- `beacon_chain_reorgs_total` / `beacon_chain_reorg_depth_slots_total` / `beacon_chain_reorg_last_depth` — reorg frequency and slot-depth impact

#### Network / P2P
- `p2p_known_peer_count` — known peers tracked in the peer DB
- `p2p_peer_count` — connected peers
- `p2p_connected_peer_direction_count` — connected peers by direction (`inbound`/`outbound`)
- `p2p_peer_connection_state_count` — known peers by connection state
- `p2p_peer_score_state_count` — known peers by peer-score state
- `p2p_peer_relevance_count` — known peers by relevance status
- `p2p_peer_connected_total` — peer connection events
- `p2p_peer_disconnected_total` — peer disconnection events
- `p2p_peer_reports_total` — peer penalty reports by source and action
- `p2p_peer_goodbye_received_total` — remote Goodbye messages by reason
- `beacon_api_active_connections` — open beacon API HTTP connections
- `beacon_api_requests_total` — completed beacon API requests by operation ID
- `beacon_api_errors_total` — failed beacon API requests by operation ID
- `beacon_api_request_seconds` — non-streaming beacon API request latency by operation ID
- `beacon_api_stream_seconds` — beacon API stream lifetime by operation ID (`getEvents` today)
- `beacon_reqresp_inbound_limiter_peers` — peers currently tracked by the inbound req/resp limiter
- `beacon_reqresp_outbound_limiter_peers` — peers currently tracked by the outbound self-rate limiter
- `beacon_reqresp_inbound_requests_total` — completed inbound req/resp requests by method and outcome
- `beacon_reqresp_outbound_requests_total` — completed outbound req/resp requests by method and outcome
- `beacon_reqresp_inbound_request_seconds` — inbound req/resp latency by method
- `beacon_reqresp_outbound_request_seconds` — outbound req/resp latency by method
- `beacon_gossip_messages_received_total` — all inbound gossip messages
- `beacon_gossip_messages_validated_total` — accepted gossip messages
- `beacon_gossip_messages_rejected_total` — rejected gossip messages
- `beacon_gossip_messages_ignored_total` — ignored gossip messages

#### Discovery / sync
- `beacon_discovery_peers_known` — known discovery peers
- `beacon_sync_status` — 0=synced, 1=syncing
- `beacon_sync_distance` — slots behind the network head
- `beacon_sync_optimistic` — 1 when the head is optimistic, else 0
- `beacon_sync_el_offline` — 1 when the execution layer is currently unavailable, else 0

#### Chain runtime / caches / pools
- `beacon_block_state_cache_entries` — in-memory block-state cache entries
- `beacon_checkpoint_state_cache_entries` — in-memory checkpoint-state cache entries
- `beacon_checkpoint_state_datastore_entries` — persisted checkpoint-state datastore entries
- `beacon_state_regen_cache_hits_total` — queued state-regen fast-path cache hits
- `beacon_state_regen_queue_hits_total` — queued state-regen slow-path requests
- `beacon_state_regen_dropped_total` — queued state-regen requests dropped under pressure
- `beacon_state_regen_queue_length` — current queued state-regen backlog
- `beacon_forkchoice_nodes` / `beacon_forkchoice_block_roots` / `beacon_forkchoice_votes` — live fork-choice DAG and vote set size
- `beacon_forkchoice_queued_attestation_slots` / `beacon_forkchoice_queued_attestations_previous_slot` — queued fork-choice attestation backlog
- `beacon_forkchoice_validated_attestation_data_roots` / `beacon_forkchoice_equivocating_validators` / `beacon_forkchoice_proposer_boost_active` — fork-choice validation and proposer-boost state
- `beacon_archive_last_finalized_slot` / `beacon_archive_last_archived_state_epoch` — live archive-store progress
- `beacon_archive_finalized_slot_lag` — finalized slots still waiting on archival
- `beacon_archive_runs_total` / `beacon_archive_failures_total` — archive catch-up success/failure counters
- `beacon_archive_finalized_slots_advanced_total` / `beacon_archive_state_epochs_archived_total` — cumulative archival throughput
- `beacon_archive_run_milliseconds_total` — cumulative archive catch-up runtime
- `beacon_archive_last_slots_advanced` / `beacon_archive_last_batch_ops` / `beacon_archive_last_run_milliseconds` — last archive run size, batch-write footprint, and duration
- `beacon_validator_monitor_monitored_validators` / `beacon_validator_monitor_last_processed_epoch` — validator-monitor runtime coverage and last processed epoch
- `beacon_validator_monitor_epoch_lag` — epochs the validator-monitor is behind the live head
- `beacon_db_total_entries` / `beacon_db_entries{database=...}` — live storage footprint by named DB
- `beacon_db_lmdb_map_size_bytes`, `beacon_db_lmdb_data_size_bytes`, `beacon_db_lmdb_page_size_bytes`, `beacon_db_lmdb_last_page_number`, `beacon_db_lmdb_last_txnid`, `beacon_db_lmdb_readers_used`, `beacon_db_lmdb_readers_max` — LMDB capacity and reader pressure
- `beacon_attestation_pool_groups` — attestation pool groups
- `beacon_aggregate_attestation_pool_groups` — aggregated attestation groups
- `beacon_aggregate_attestation_pool_entries` — aggregated attestation entries
- `beacon_voluntary_exit_pool_size` — voluntary-exit pool size
- `beacon_proposer_slashing_pool_size` — proposer-slashing pool size
- `beacon_attester_slashing_pool_size` — attester-slashing pool size
- `beacon_bls_to_execution_change_pool_size` — BLS-to-execution-change pool size
- `beacon_sync_committee_message_pool_size` — sync-committee message pool size
- `beacon_sync_contribution_pool_size` — sync-contribution pool size
- `beacon_proposer_cache_entries` — proposer-preparation cache entries
- `beacon_pending_block_ingress_size` — pending beacon blocks awaiting attachments
- `beacon_pending_block_ingress_added_total` / `replaced_total` / `resolved_total` / `removed_total` / `pruned_total` — lifecycle counters for pending beacon-block ingress
- `beacon_pending_payload_envelope_ingress_size` — pending separated payload envelopes
- `beacon_pending_payload_envelope_ingress_added_total` / `replaced_total` / `removed_total` / `pruned_total` — lifecycle counters for pending payload-envelope ingress
- `beacon_reprocess_queue_size` — queued blocks awaiting parent-driven reprocessing
- `beacon_reprocess_queued_total` / `released_total` / `dropped_total` / `pruned_total` — reprocess-queue lifecycle counters
- `beacon_da_blob_tracker_entries` — tracked blob-availability entries
- `beacon_da_column_tracker_entries` — tracked custody-column entries
- `beacon_da_pending_blocks` — blocks still waiting on DA completion
- `beacon_da_pending_marked_total` / `resolved_total` / `pruned_total` — pending-DA lifecycle counters

#### Execution layer
- `execution_new_payload_seconds` — `engine_newPayload*` latency
- `execution_forkchoice_updated_seconds` — `engine_forkchoiceUpdated*` latency
- `execution_payload_valid_total` — VALID payload-status responses
- `execution_payload_invalid_total` — INVALID payload-status responses
- `execution_payload_syncing_total` — SYNCING/ACCEPTED payload-status responses
- `execution_errors_total` — execution transport / request errors
- `execution_pending_forkchoice_updates` — queued forkchoice updates waiting on the EL worker
- `execution_pending_payload_verifications` — queued payload verifications waiting on the EL worker
- `execution_completed_forkchoice_updates` — completed forkchoice updates awaiting node consumption
- `execution_completed_payload_verifications` — completed payload verifications awaiting node consumption
- `execution_failed_payload_preparations` — failed payload-preparation tickets waiting on consumers
- `execution_cached_payload` — 1 when a cached payload ID is live, else 0
- `execution_offline` — 1 when the EL runtime currently considers the engine offline, else 0

### State Transition (live today)
- `lodestar_stfn_epoch_transition_seconds` — epoch transition latency
- `lodestar_stfn_epoch_transition_step_seconds` — per-step epoch transition latency
- `lodestar_stfn_process_block_seconds` — `processBlock` latency
- `lodestar_stfn_hash_tree_root_seconds` — post-state hash-tree-root latency

### Validator (live today)
- `validator_attestation_published_total` — attestations published
- `validator_attestation_missed_total` — attestations missed
- `validator_attestation_delay_seconds` — attestation timing
- `validator_block_proposed_total` — blocks proposed
- `validator_block_missed_total` — blocks missed
- `validator_block_delay_seconds` — block proposal timing
- `validator_sync_committee_message_total` — sync messages
- `validator_sync_committee_contribution_total` — sync contributions
- `validator_total_count` — total managed validators
- `validator_active_count` — active managed validators
- `validator_keymanager_requests_total` — keymanager request count by operation
- `validator_keymanager_errors_total` — keymanager request failures by operation
- `validator_keymanager_response_seconds` — keymanager response latency by operation
- `validator_keymanager_active_connections` — keymanager open HTTP connections
- `lodestar_monitoring_collect_data_seconds` — remote-monitoring payload collection latency
- `lodestar_monitoring_send_data_seconds` — remote-monitoring upload latency by status

### Not Yet Wired
These are good future metrics, but they should not be exported until they are real runtime instrumentation:
- DB read/write latency and object counts
- fork-choice DAG/reprocess timings
- deeper peer-scoring internals such as score distributions over time, mesh/router internals, and limiter token usage histograms

## Instrumentation Points

| Subsystem | File | What's Measured |
|-----------|------|-----------------|
| Chain import | `node/beacon_node.zig` | block import success/skip/failure counters by source, import latency, plus head/finalized/justified updates |
| Execution | `node/beacon_node.zig`, `node/execution_port.zig` | newPayload/forkchoiceUpdated latency and payload status counters |
| Gossip | `node/gossip_handler.zig` | gossip received/validated/rejected/ignored counters |
| Beacon API | `api/http_server.zig`, `node/beacon_node.zig`, `node/metrics.zig` | active HTTP connections plus request/error/latency metrics by operation ID |
| Peer/discovery/sync | `node/p2p_runtime.zig`, `node/reqresp_callbacks.zig`, `networking/eth2_protocols.zig`, `networking/peer_manager.zig` | peer counts/events, peer-state distributions, peer reports, Goodbye counters, discovery peer count, sync status/distance, req/resp request outcomes, limiter peer gauges |
| Chain runtime | `chain/runtime.zig`, `node/p2p_runtime.zig`, `fork_choice/fork_choice.zig`, `chain/archive_store.zig`, `chain/validator_monitor.zig`, `chain/block_ingress.zig`, `chain/payload_envelope_ingress.zig`, `chain/reprocess.zig`, `chain/data_availability.zig`, `db/*` | cache sizes, fork-choice DAG/vote state, archive progress, validator-monitor coverage, queued state-regen counters, pool sizes, ingress/reprocess/DA lifecycle counters, named-DB entry counts |
| Execution runtime | `node/execution_runtime.zig`, `node/p2p_runtime.zig` | EL queue depth, cached payload presence, offline state |
| STF | `state_transition/metrics.zig` | runtime-owned STFN timing carried through cached states and regen/runtime paths |
| Metrics HTTP | `metrics/server.zig`, `metrics/runtime.zig` | shared `/metrics` listener/runtime for beacon and validator |

## Prometheus Text Format

The `/metrics` endpoint renders standard Prometheus text exposition format:

```
# HELP beacon_head_slot Current head slot
# TYPE beacon_head_slot gauge
beacon_head_slot 12345

# HELP beacon_block_import_seconds Histogram of block import latency
# TYPE beacon_block_import_seconds histogram
beacon_block_import_seconds_bucket{le="0.01"} 0
beacon_block_import_seconds_bucket{le="0.05"} 3
...
beacon_block_import_seconds_bucket{le="+Inf"} 10
beacon_block_import_seconds_sum 1.234
beacon_block_import_seconds_count 10
```

## Adding New Metrics

1. Add the field to the owning subsystem metrics struct (`BeaconMetrics`, `ValidatorMetrics`, or `StateTransitionMetrics`)
2. Wire real runtime instrumentation before documenting or exporting the metric
3. Add the constructor / registry setup for the metric in that subsystem
4. Thread the live or noop metrics object through the same runtime path so disabled mode stays structurally identical

## Future Work

- More labeled metrics (per-topic gossip, per-route DB/execution, richer peer-scoring and limiter detail)
- Process metrics (RSS, open FDs, goroutine-equivalent fiber count)
- Ethereum Beacon Metrics spec compliance (when standardized)
- Grafana dashboard templates
