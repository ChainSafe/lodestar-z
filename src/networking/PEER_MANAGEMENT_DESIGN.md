# Peer Management Design — lodestar-z

Coherent end-to-end design for peer lifecycle, relevance, prioritization,
scoring, and subnet awareness. Informed by deep study of Lodestar (TS) and
Lighthouse (Rust).

---

## 1. Connection Lifecycle

```
Discovery (discv5 / bootnodes / static peers)
  → Dial candidate
    → Handshake (Noise / TLS 1.3 via QUIC)
      → Status exchange (fork_digest, finalized checkpoint, head)
        → Relevance check (assertPeerRelevance)
          ├─ Accept → add to PeerDB, start scoring, request Metadata
          └─ Reject → send Goodbye(IRRELEVANT_NETWORK), disconnect, cooldown
```

### Key invariants
- **Accept first, prune later.** We always accept connections (unless banned or
  at hard max), then periodically prune excess. This follows Lodestar TS.
- **Status before relevance.** A peer is not considered "active" until a
  successful Status exchange proves chain compatibility.
- **Direction tracking.** Every connection records inbound vs outbound. The
  heartbeat maintains a minimum outbound ratio (~10%) to resist eclipse attacks.

---

## 2. Peer Relevance

Determines whether a peer is on the same chain as us. Checked after every
Status exchange (initial handshake + periodic re-status every 5 minutes).

### Checks (ordered by cost)

1. **Fork digest mismatch** — Different fork_digest → different network entirely.
   Immediate disconnect with `Goodbye(IRRELEVANT_NETWORK)`.

2. **Incompatible finalized checkpoint** — If the remote's `finalized_epoch ≤
   our_finalized_epoch` AND both finalized roots are non-zero AND the roots
   differ at the same epoch → diverged chain. Disconnect.

3. **Clock skew / head too far** — If `remote.head_slot > current_slot +
   FUTURE_SLOT_TOLERANCE` → either different genesis time or broken clock.
   Disconnect.

4. **Post-Fulu: missing earliestAvailableSlot** — Fulu peers must advertise
   this field. If absent → irrelevant.

### What we DON'T check (and why)
- **Head too far behind** — Lodestar TS explicitly does NOT penalize peers
  behind us. Those peers are trying to sync, and disconnecting them hurts
  network stability. Lighthouse agrees: "It's dangerous to downscore peers
  that are far behind."
- **Fork compatibility beyond digest** — The ENR fork check at discovery
  level is sufficient. Checking protocol support would require extra round
  trips.

### Implementation: `peer_relevance.zig`

```zig
pub const IrrelevantPeerCode = enum {
    incompatible_forks,
    different_finalized,
    different_clocks,
};

pub fn assertPeerRelevance(
    remote: StatusMessage.Type,
    local: CachedStatus,
    current_slot: u64,
) ?IrrelevantPeerCode;
```

Returns `null` if the peer is relevant, otherwise the reason code. The caller
sends `Goodbye(IRRELEVANT_NETWORK)` and disconnects.

---

## 3. Peer Prioritization

Given N connected peers and a target count, decide who to keep, who to
disconnect, and what subnets need more peers. Runs every heartbeat (30s).

### Algorithm (from Lodestar TS `prioritizePeers`)

**Phase A: Subnet needs assessment**
1. Count peers per attestation subnet, sync subnet, and custody group
2. For each subnet with fewer than `TARGET_SUBNET_PEERS` (6), emit a discovery
   query

**Phase B: Pruning when above target** (in order)
1. **Low-score first** — Peers with score < -2.0 are most prunable
2. **No long-lived subnets** — Peers not subscribed to any attestation or sync
   committee subnet provide less value
3. **Too-grouped subnets** — Among subnets with > TARGET_SUBNET_PEERS, remove
   the peer whose removal least affects overall coverage
4. **Find better peers** — If still above target, prune remaining worst peers

**Protections (never prune):**
- Trusted/direct peers
- Peers with active validator duties (subnet coverage for active subnets)
- Peers that would drop us below minimum sync committee peers (2)
- Outbound peers needed to maintain outbound ratio (10%)

### Implementation: `peer_prioritization.zig`

```zig
pub const PrioritizationResult = struct {
    peers_to_disconnect: BoundedArray(PeerEntry, MAX_PRUNE_PER_HEARTBEAT),
    peers_to_discover: u32,
    subnets_needing_peers: BoundedArray(SubnetQuery, 128),
};

pub fn prioritizePeers(
    allocator: Allocator,
    peers: []const ConnectedPeerView,
    active_attnets: []const SubnetId,
    active_syncnets: []const SubnetId,
    config: PrioritizationConfig,
) PrioritizationResult;
```

---

## 4. Score → Action Pipeline

```
Protocol Event
  ├─ Gossip validation: accept / reject(reason) / ignore
  ├─ Req/resp outcome: success / timeout / error / invalid
  └─ Application event: useful sync response, irrelevant peer, etc.

  → PeerAction mapping
    ├─ fatal      → -100 (instant ban)
    ├─ low_tolerance  → -10  (~5 occurrences → ban)
    ├─ mid_tolerance  → -5   (~10 occurrences → ban)
    └─ high_tolerance → -1   (~50 occurrences → ban)

  → Score components (in PeerScore)
    ├─ lodestar_score: our own assessment (actions + decay)
    └─ gossipsub_score: from libp2p gossipsub router

  → Combined score = lodestar_score + weighted(gossipsub_score)

  → State thresholds
    ├─ score > -20   → healthy (no action)
    ├─ -50 < score ≤ -20 → disconnected (send Goodbye)
    └─ score ≤ -50   → banned (disconnect + ban for 30min+)
```

### Score decay
- Exponential decay with 10-minute halflife
- On transition to banned: freeze score for 30 minutes before allowing decay
- Reconnection cooldown: freeze score on Goodbye receipt (duration varies by
  reason code)

### Event sources

| Source | Events | Actions |
|--------|--------|---------|
| `gossip_handler` | reject(invalid_block) | fatal |
| `gossip_handler` | reject(invalid_signature) | low_tolerance |
| `gossip_handler` | reject(wrong_subnet) | mid_tolerance |
| `gossip_handler` | reject(invalid_slot) | high_tolerance |
| `req_resp_handler` | timeout(ping/status) | low_tolerance |
| `req_resp_handler` | timeout(blocks_by_range) | mid_tolerance |
| `req_resp_handler` | invalid_response | low_tolerance |
| `req_resp_handler` | unsupported(ping) | fatal |
| `sync_service` | useful response | (no penalty) |
| `peer_manager` | irrelevant network | fatal + ban |

### Existing modules
- `peer_scoring.zig` — PeerScoreService (event→action mapping, per-peer stats)
- `peer_info.zig` — PeerScore (score storage, decay, state computation)
- `scoring_parameters.zig` — Gossipsub topic scoring weights

These are already well-implemented. The new code wires them into the
peer_manager heartbeat and connection lifecycle.

---

## 5. Subnet-Aware Peer Selection

### Per-peer tracking (in PeerInfo)
- `attnets: BitSet(64)` — attestation subnets from ENR/Metadata
- `syncnets: BitSet(4)` — sync committee subnets
- `last_status: ?StatusMessage.Type` — from last Status exchange

### When we need a peer for a specific subnet
1. Check `PeerDB.getPeersOnSubnet(subnet_id)` for connected peers covering it
2. If insufficient, emit a `SubnetQuery` from prioritization so discovery
   targets ENRs with the right `attnets` bitfield
3. SubnetService tracks validator duties → expiring subnet subscriptions

### Integration flow
```
SubnetService.onSlot(slot)
  → getActiveAttestationSubnets() → heartbeat reads these
  → prioritizePeers() uses them to:
     1. Protect peers covering active subnets from pruning
     2. Emit SubnetQuery for subnets with < TARGET_SUBNET_PEERS
  → discovery_service dials new peers with matching ENR attnets
```

---

## 6. PeerDB Enhancements

The existing PeerDB already tracks most needed fields. New additions for
the lifecycle wiring:

| Field | Type | Purpose |
|-------|------|---------|
| `last_status` | `?StatusMessage.Type` | Chain compatibility re-checks |
| `relevance` | `enum { unknown, relevant, irrelevant }` | Track relevance status |

These are added to `PeerInfo` and updated via `PeerDB.updateSyncInfo()` and
the new relevance check flow.

---

## 7. Full Peer Manager Heartbeat

Every 30 seconds:

```
1. Decay all scores
2. Unban expired bans
3. Collect peers with score → disconnect/ban state
4. Run assertPeerRelevance on peers needing re-status (not every heartbeat)
5. Run prioritizePeers:
   a. Classify subnet coverage
   b. Identify excess peers to disconnect
   c. Identify subnets needing discovery
6. Disconnect excess/bad peers (send Goodbye first)
7. Request discovery for missing peers/subnets
8. Prune stale disconnected entries from DB
9. Log summary metrics
```

### Periodic status/ping (separate from heartbeat)
- Ping outbound peers every 20s, inbound every 15s
- Re-status all peers every 5 minutes
- On status response: re-run assertPeerRelevance

---

## 8. Module Dependency Graph

```
                    ┌─────────────────┐
                    │   peer_manager   │  orchestrator
                    └────────┬────────┘
                             │
        ┌────────────┬───────┼───────────┬────────────┐
        │            │       │           │            │
  ┌─────▼─────┐ ┌───▼───┐ ┌─▼──────┐ ┌──▼────┐ ┌────▼──────┐
  │  peer_db   │ │scoring│ │relevance│ │priorit│ │subnet_svc │
  │  (storage) │ │service│ │(check) │ │(prune)│ │(duties)   │
  └─────┬──────┘ └───┬───┘ └────────┘ └───────┘ └───────────┘
        │            │
  ┌─────▼─────┐ ┌───▼───────────┐
  │ peer_info  │ │scoring_params │
  │ (per-peer) │ │(gossipsub)    │
  └────────────┘ └───────────────┘
```

---

## Design Decisions

1. **No peer_relevance checks for "head too far behind"** — Matches both
   Lodestar TS and Lighthouse. Penalizing behind peers hurts network health.

2. **Accept-then-prune** — Simpler than reject-at-connection. The heartbeat
   handles excess within 30 seconds.

3. **Prioritization uses real subnet queries** — SubnetService feeds active
   validator duties into prioritization, protecting subnet-covering peers.

4. **Score frozen on ban** — 30-minute freeze prevents rapid oscillation.
   Reconnection cooldowns vary by Goodbye reason (5min for too_many_peers,
   4h for irrelevant_network).

5. **PeerDB owns all state** — PeerManager is a thin orchestrator. This makes
   testing straightforward: inject PeerDB state, run heartbeat, assert actions.
