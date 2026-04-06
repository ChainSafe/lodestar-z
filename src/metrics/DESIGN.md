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
- `beacon_block_import_seconds` — block import latency histogram

#### Network / P2P
- `p2p_peer_count` — connected peers
- `p2p_peer_connected_total` — peer connection events
- `p2p_peer_disconnected_total` — peer disconnection events
- `beacon_gossip_messages_received_total` — all inbound gossip messages
- `beacon_gossip_messages_validated_total` — accepted gossip messages
- `beacon_gossip_messages_rejected_total` — rejected gossip messages
- `beacon_gossip_messages_ignored_total` — ignored gossip messages

#### Discovery / sync
- `beacon_discovery_peers_known` — known discovery peers
- `beacon_sync_status` — 0=synced, 1=syncing
- `beacon_sync_distance` — slots behind the network head

#### Execution layer
- `execution_new_payload_seconds` — `engine_newPayload*` latency
- `execution_forkchoice_updated_seconds` — `engine_forkchoiceUpdated*` latency
- `execution_payload_valid_total` — VALID payload-status responses
- `execution_payload_invalid_total` — INVALID payload-status responses
- `execution_payload_syncing_total` — SYNCING/ACCEPTED payload-status responses
- `execution_errors_total` — execution transport / request errors

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
- beacon REST API request counters / latency
- DB read/write latency and object counts
- fork-choice DAG/reprocess timings
- attestation/op-pool sizes
- req/resp service latency and request totals
- cache-size / cache-hit families outside the validator runtime

## Instrumentation Points

| Subsystem | File | What's Measured |
|-----------|------|-----------------|
| Chain import | `node/beacon_node.zig` | block import count/latency plus head/finalized/justified updates |
| Execution | `node/beacon_node.zig`, `node/execution_port.zig` | newPayload/forkchoiceUpdated latency and payload status counters |
| Gossip | `node/gossip_handler.zig` | gossip received/validated/rejected/ignored counters |
| Peer/discovery/sync | `node/p2p_runtime.zig`, `node/reqresp_callbacks.zig` | peer counts/events, discovery peer count, sync status/distance |
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

- Labeled metrics (per-topic gossip, per-endpoint API, per-method req/resp)
- Process metrics (RSS, open FDs, goroutine-equivalent fiber count)
- Ethereum Beacon Metrics spec compliance (when standardized)
- Grafana dashboard templates
