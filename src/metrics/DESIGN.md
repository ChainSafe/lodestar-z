# Metrics Framework Design

## Overview

lodestar-z uses a Prometheus-compatible metrics framework for operational
monitoring, performance debugging, and operator visibility.

## Architecture

```
┌──────────────────┐     ┌──────────────────┐
│  BeaconMetrics    │     │ ValidatorMetrics  │
│  (50+ metrics)    │     │  (10+ metrics)    │
└────────┬─────────┘     └────────┬──────────┘
         │                        │
         │ ?*BeaconMetrics        │ ?*ValidatorMetrics
         │ (optional pointer)     │ (optional pointer)
         │                        │
    ┌────┴────────────────────────┴───┐
    │        Subsystem Instrumentation │
    │  beacon_node.zig (chain, peers) │
    │  gossip_handler.zig (gossip)    │
    │  block_importer (EL timing)     │
    │  state_transition/metrics.zig   │
    └──────────────┬──────────────────┘
                   │
         ┌─────────┴──────────┐
         │   MetricsServer    │
         │   GET /metrics     │
         │   :9090            │
         └────────────────────┘
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

Every metric is a `union(enum) { noop, impl }`. When `--metrics` is not
passed, `initNoop()` sets all fields to `.noop`, making every `incr()`,
`set()`, `observe()` a no-op branch that the compiler can optimize away.

```zig
// Enabled:
var m = BeaconMetrics.init();

// Disabled (zero overhead):
var m = BeaconMetrics.initNoop();
```

## Metric Categories

### Chain State ("Is my node healthy?")
- `beacon_head_slot` — current head slot
- `beacon_finalized_epoch` — finalized epoch
- `beacon_justified_epoch` — justified epoch
- `beacon_current_active_validators` — active validator count
- `beacon_reorg_events_total` — fork choice reorgs

### Block Processing ("How fast are blocks imported?")
- `beacon_blocks_imported_total` — total imported blocks
- `beacon_block_import_seconds` — block import latency histogram
- `beacon_block_slot_delta` — freshness of imported blocks

### State Transition ("Where is STFN time spent?")
- `beacon_state_transition_seconds` — full STF latency
- `beacon_process_block_seconds` — processBlock latency
- `beacon_process_epoch_seconds` — epoch transition latency
- `beacon_state_regen_seconds` — state regeneration latency
- `lodestar_stfn_*` — detailed per-step epoch transition (from state_transition/metrics.zig)

### Fork Choice
- `beacon_fork_choice_find_head_seconds` — findHead latency
- `beacon_fork_choice_nodes` — DAG size
- `beacon_fork_choice_reprocessed_total` — reprocessed blocks

### Network / P2P ("What's happening on the network?")
- `p2p_peer_count` — connected peers
- `p2p_peer_connected_total` — peer connection events
- `p2p_peer_disconnected_total` — peer disconnection events
- `beacon_gossip_messages_received_total` — all gossip messages
- `beacon_gossip_messages_validated_total` — accepted
- `beacon_gossip_messages_rejected_total` — rejected
- `beacon_gossip_messages_ignored_total` — ignored (dupes, stale)
- `beacon_reqresp_requests_total` — req/resp count
- `beacon_reqresp_request_seconds` — req/resp latency

### Sync ("Is the node synced?")
- `beacon_sync_status` — 0=synced, 1=syncing
- `beacon_sync_distance` — slots behind network head
- `beacon_sync_batches_pending` — in-flight sync batches

### API ("How is the REST API performing?")
- `beacon_api_requests_total` — request count
- `beacon_api_request_seconds` — request latency

### Database
- `beacon_db_read_seconds` — read latency
- `beacon_db_write_seconds` — write latency
- `beacon_db_block_count` — stored blocks

### Execution Layer ("What's the EL doing?")
- `execution_new_payload_seconds` — newPayload latency
- `execution_forkchoice_updated_seconds` — forkchoiceUpdated latency
- `execution_get_payload_seconds` — getPayload latency
- `execution_payload_valid_total` — VALID status count
- `execution_payload_invalid_total` — INVALID status count
- `execution_payload_syncing_total` — SYNCING status count
- `execution_errors_total` — transport/timeout errors

### Caches ("What's the cache performance?")
- `beacon_state_cache_size` — cached states
- `beacon_state_cache_hit_total` — state cache hits
- `beacon_state_cache_miss_total` — state cache misses
- `beacon_shuffling_cache_hit_total` — shuffling cache hits
- `beacon_shuffling_cache_miss_total` — shuffling cache misses
- `beacon_checkpoint_cache_size` — checkpoint cache entries
- `beacon_pmt_pool_used_nodes` — PMT pool usage

### Validator ("Is my validator performing?")
- `validator_attestation_published_total` — attestations published
- `validator_attestation_missed_total` — attestations missed
- `validator_attestation_delay_seconds` — attestation timing
- `validator_block_proposed_total` — blocks proposed
- `validator_block_missed_total` — blocks missed
- `validator_block_delay_seconds` — block proposal timing
- `validator_sync_committee_message_total` — sync messages
- `validator_sync_committee_contribution_total` — sync contributions
- `validator_active_count` — managed validators
- `validator_total_balance_gwei` — total balance

## Instrumentation Points

| Subsystem | File | What's Measured |
|-----------|------|-----------------|
| Chain | `beacon_node.zig` | Block import time, head/finalized/justified updates |
| Gossip | `gossip_handler.zig` | Message received/validated/rejected/ignored counts |
| EL | `beacon_node.zig` | newPayload + forkchoiceUpdated latency, status |
| STF | `state_transition/metrics.zig` | Epoch/block/commit latency, per-step breakdown |
| Peers | `beacon_node.zig` | Peer count updated each tick |
| Sync | `beacon_node.zig` | Sync status + distance updated each tick |

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

1. Add the field to `BeaconMetrics` or `ValidatorMetrics` in `src/node/metrics.zig`
2. Add the `.init()` call in `init()` with the Prometheus name
3. Use `if (self.metrics) |m| m.your_metric.incr();` at the instrumentation point
4. The noop path is automatic — `initializeNoop` handles it

## Future Work

- Labeled metrics (per-topic gossip, per-endpoint API, per-method req/resp)
- Process metrics (RSS, open FDs, goroutine-equivalent fiber count)
- Ethereum Beacon Metrics spec compliance (when standardized)
- Grafana dashboard templates
