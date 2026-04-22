# Post-connect peer churn deep dive

Date: 2026-04-21
Host: nogroup-rs2000-0
Live service: beacon.service
Context: after discv5 ingress saturation was fixed, the node still falls behind because healthy peers are not retained.

## Question

Why do more peers not stay connected, especially when comparable Lodestar-TS deployments can maintain well over 100 QUIC peers?

## High-confidence findings

### 1. This is not primarily a gossipsub-retry gap

Lodestar-TS does not appear to rely on explicit beacon-node-level gossipsub stream retries.

What Lodestar-TS does do differently:
- `identify({runOnConnectionOpen: false})` in `packages/beacon-node/src/network/libp2p/index.ts`
- outbound connect path triggers `requestPing()` and `requestStatus()` first in `packages/beacon-node/src/network/peers/peerManager.ts`
- identify is delayed until after status proves the peer is usable in `peerManager.ts`

Current Zig connect sequence in `src/node/p2p_runtime.zig` is different:
- on first transport connect, call `openGossipsubStreamAsync()`
- then `requestIdentifyAsync()`
- then schedule `status_only`

That sequencing divergence may hurt fragile peers, but it does not by itself explain the full retention gap.

### 2. The node does dial peers; the conversion/retention rate is poor

Live sample around `2026-04-21T16:18:12Z`:
- `libp2p_peers 1`
- `p2p_peer_connection_state_count{state="connected"} 1`
- `lodestar_peers_requested_total_to_connect 54`
- `lodestar_discovery_peers_to_connect 54`
- `beacon_discovery_pending_dials 4`
- `beacon_discovery_dials_total{outcome="success"} 353`
- `beacon_discovery_dials_total{outcome="failure"} 494`
- `lodestar_discovery_dial_error_total_count{reason="HandshakeFailed"} 494`
- `lodestar_discovery_not_dial_reason_total_count{reason="transport_incompatible"} 3225`

Interpretation:
- discovery is active
- many transport dials have succeeded historically
- far too few peers remain connected and useful
- the dominant problem is not absence of dial attempts; it is poor conversion from discovered candidate -> durable useful peer

### 3. Replenishment is currently conservative

In `src/node/p2p_runtime.zig`:
- `const max_discovery_dials_per_tick: u32 = 4;`
- `discoveryDialBudget()` caps concurrent discovery dials at 4, further bounded by `pm.config.max_peers - occupied_peers`

With many QUIC handshakes taking ~20s and failing, this severely limits replenishment throughput under churn.

### 4. Goodbye cooldowns further shrink the candidate pool

In `src/networking/peer_manager.zig`:
- `onPeerGoodbye()` applies reconnection cooldowns

In `src/networking/peer_scoring.zig`:
- `too_many_peers -> 5 minutes`
- `fault_error -> 60 minutes`
- `client_shutdown -> 60 minutes`

Live counters showed:
- `p2p_peer_goodbye_received_total{reason="too_many_peers"} 12`
- `p2p_peer_goodbye_received_total{reason="banned"} 1`
- `p2p_peer_goodbye_received_total{reason="fault_error"} 1`

Interpretation:
- when remote peers prune us with `too_many_peers`, we cool those peers down for 5 minutes
- under a small discovery dial budget, this makes refill slower exactly when churn is high

### 5. Status-path transport closures are a major churn signal

Live counter:
- `beacon_reqresp_maintenance_errors_total{method="status",error_kind="transport_closed"} 220`

Current Zig policy in `src/node/p2p_runtime.zig`:
- `statusReqRespPolicy(.status_only/.restatus).disconnect_peer_on_failure = false`
- transport-closed status failures do not immediately force local disconnect

Interpretation:
- many peers are dying before or around status maintenance
- this is not the root cause by itself, but it is a strong marker of fragile post-connect peers

### 6. The peer bleed-down is real and fast

Observed live progression:
- around `16:03:27Z`:
  - `head_slot 2881166`
  - `sync_distance 1`
  - `libp2p_peers 6`
  - `beacon_gossipsub_outbound_streams 6`
  - `beacon_gossipsub_mesh_peers 6`
  - `beacon_gossipsub_topic_peers 6`
- around `16:18:12Z`:
  - `libp2p_peers 1`
  - `connected peers 1`
  - `beacon_gossipsub_outbound_streams 1`
  - `beacon_gossipsub_mesh_peers 1`
  - `beacon_gossipsub_topic_peers 1`
  - `sync_distance 23`

Interpretation:
- after recovery, the node can briefly reach a healthy-enough gossip peer set
- it then bleeds useful peers back down faster than it refills them
- that peer-retention failure explains why gossip block imports dry up and the node falls behind again

## Important nuance on the 100+ peer comparison

Current Zig defaults are not aiming for 100+ peers:
- `src/node/options.zig`: `target_peers = 50`
- `src/networking/peer_manager.zig:maxPeersForTarget()` gives only 10% headroom
- so with target 50, max peers is 55

So it is not apples-to-apples to compare current Zig default configuration with a Lodestar-TS node intentionally configured for 100+ peers.

However, that is not the explanation for the current failure on nogroup, because the node is collapsing to `1-6` connected peers — far below even its own target.

## Current root-cause hypothesis

The strongest current explanation is a combination of:

1. poor candidate quality / interoperability
- many discovered peers are QUIC-incompatible (`transport_incompatible`)
- many QUIC-capable peers still fail handshake (`HandshakeFailed`)

2. poor retention after transport connect
- many peers disappear before or around status maintenance (`status transport_closed`)
- remote peers frequently prune us with `too_many_peers`

3. slow replenishment under churn
- discovery dial concurrency is capped at 4
- remote-goodbye cooldowns temporarily remove recently-tried peers from circulation

4. connect sequencing divergence may worsen marginal-peer survival
- Zig opens gossipsub + identify before status proves usefulness
- Lodestar-TS effectively does ping/status first, then identify

## Most likely next fix directions

### A. Instrument the conversion funnel explicitly

Add metrics/logging for:
- discovery dial started
- transport connected
- status success
- ping success
- metadata success
- identify success
- gossipsub topic peer present
- disconnect / goodbye reason after connect

This would expose exactly where transport-connected peers are being lost.

### B. Revisit connect sequencing for outbound peers

For parity with Lodestar-TS behavior:
- avoid eager identify before status success
- reconsider eager gossipsub open before status proves the peer is useful

### C. Revisit refill aggressiveness

The current `max_discovery_dials_per_tick = 4` is likely too conservative under heavy QUIC churn.
Potential direction:
- dynamic dial budget based on peer deficit and recent handshake-failure rate
- keep bounded, but allow much higher concurrency when connected peers are far below target

### D. Revisit goodbye cooldown policy for remote `too_many_peers`

A 5-minute cooldown after remote `too_many_peers` may be too pessimistic when the candidate pool is already constrained.

## Bottom line

The strange behavior is not that discovery stopped dialing.

The node is dialing, but:
- too many candidates are unusable
- too many successful connects do not remain durable/useful
- and the refill loop is too weak to outrun churn

That is the current best explanation for why the node can briefly recover, then lose gossip-capable peers and fall behind again.
