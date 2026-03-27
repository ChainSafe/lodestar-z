# Peer Scoring Design — lodestar-z

Analysis of Lodestar (TS), Lighthouse (Rust), and Prysm (Go) peer scoring systems,
with design decisions for lodestar-z.

## Architecture Overview

All three clients converge on the same fundamental design:

### Two-Component Scoring Model

Every client separates scoring into two independent tracks:

1. **Application-level score** ("lodestar score" / "lighthouse score")
   - Controlled by the node's own logic
   - Penalized via `PeerAction` events from gossip, req/resp, sync
   - Exponential decay with configurable half-life
   - Clamped to `[MIN_SCORE, MAX_SCORE]` = `[-100, 100]`

2. **Gossipsub router score**
   - Computed by the libp2p gossipsub implementation
   - Based on mesh behavior: message delivery, invalid messages, time in mesh
   - Per-topic weights (defined in `scoring_parameters.zig`)
   - Weighted conservatively when combined with application score

**Combined score formula** (from Lodestar TS & Lighthouse):
```
if lodestar_score <= MIN_LODESTAR_SCORE_BEFORE_BAN:
    score = lodestar_score  // ignore gossipsub entirely
elif gossipsub_score >= 0:
    score = lodestar_score + gossipsub_score * POSITIVE_WEIGHT
elif !ignore_negative_gossipsub:
    score = lodestar_score + gossipsub_score * NEGATIVE_WEIGHT
else:
    score = lodestar_score  // ignoring negative gossipsub for recovery
```

The negative weight is calibrated so gossipsub alone never triggers disconnect:
```
NEGATIVE_WEIGHT = (MIN_SCORE_BEFORE_DISCONNECT + 1) / GOSSIPSUB_GREYLIST_THRESHOLD
```

### Score Thresholds

| Threshold | Value | Action |
|-----------|-------|--------|
| Healthy | > -20 | Normal operation |
| Disconnect | ≤ -20 | Disconnect, allow reconnection |
| Ban | ≤ -50 | Ban, freeze score for cooldown period |
| Min score | -100 | Absolute minimum (clamp) |
| Max score | 100 | Absolute maximum (clamp) |

### PeerAction Penalties

All three clients use the same 4-tier penalty system:

| Action | Delta | Approx bans after | Use case |
|--------|-------|-------------------|----------|
| Fatal | -100 (set to MIN) | 1 | Invalid blocks, wrong network, consensus violation |
| LowTolerance | -10 | ~5 | Invalid response SSZ, wrong fork, dial failure |
| MidTolerance | -5 | ~10 | Server errors, response timeouts (range/root requests) |
| HighTolerance | -1 | ~50 | Unknown error status, minor protocol issues |

### Score Decay

- **Half-life**: 10 minutes (600 seconds) — identical across all clients
- **Decay formula**: `score *= e^(-ln(2)/halflife * elapsed)`
- **Ban cooldown**: When score drops below ban threshold, `last_updated` is set
  into the future by `BANNED_BEFORE_DECAY` duration, freezing decay
  - Lodestar TS: 30 minutes
  - Lighthouse: 12 hours
  - lodestar-z: 30 minutes (following Lodestar TS)

### Reconnection Cool-Down (Lodestar TS)

On receiving Goodbye with a reason code, apply cool-down periods:
- `TOO_MANY_PEERS` / `INBOUND_DISCONNECT`: 5 minutes
- `ERROR` / `CLIENT_SHUTDOWN`: 60 minutes
- `IRRELEVANT_NETWORK`: 240 minutes
- `BANNED` / `SCORE_TOO_LOW`: no extra cool-down (let scoring handle it)

### Gossipsub Score Ignoring

Both Lodestar and Lighthouse allow ignoring negative gossipsub scores for a
subset of peers. This prevents a mass-disconnect cascade when many peers
simultaneously develop negative gossipsub scores (e.g., during network partitions).

The top N peers with the best negative gossipsub scores have their negative
scores ignored, allowing recovery without disconnection.

## Rate Limiting

### Lighthouse Approach (GCRA)

Lighthouse uses the Generic Cell Rate Algorithm (GCRA), which is equivalent to
a leaky bucket but tracks only a single timestamp per (peer, protocol) pair.

Key parameters per protocol:
- `replenish_all_every`: Duration to fully replenish the bucket
- `max_tokens`: Maximum burst size

The GCRA tracks a Theoretical Arrival Time (TAT). A request is allowed if
`now >= TAT - tau + additional_time`, where:
- `tau` = `replenish_all_every` (time to fill bucket)
- `additional_time` = `t * tokens_requested` (t = tau / max_tokens)

On allow: `TAT = max(now, TAT) + additional_time`

Advantages over simple token bucket:
- Single u64 per (peer, protocol) instead of (tokens: f64, last_refill: i128)
- No floating point
- Returns `TooSoon(Duration)` — exact backpressure information

### Lodestar-z Design

Our current token bucket implementation is functionally correct but can be enhanced:

1. **Add global rate limit**: A single bucket across all peers to prevent aggregate overload
2. **Backpressure mode**: Return `RateLimitedErr.TooSoon(delay_ns)` instead of just bool
3. **Response-based token consumption**: Range requests consume tokens proportional to
   `max_responses` (following Lighthouse), not just 1 token per request
4. **Score penalty on rate limit**: Apply `PeerAction.high_tolerance` when a peer
   hits rate limits repeatedly

## Integration Points

### Gossip Validation → Scoring

Map `ValidationResult` to score actions:
- `accept` → positive score (reward valid message delivery)
- `reject` → penalty based on rejection reason:
  - Invalid signature → `PeerAction.low_tolerance`
  - Wrong subnet → `PeerAction.mid_tolerance`
  - Invalid slot (too old/future) → `PeerAction.high_tolerance`
  - Invalid block (fails STF) → `PeerAction.fatal`
- `ignore` → no penalty (duplicates are normal mesh behavior)

### Req/Resp → Scoring (from Lodestar TS `reqresp/score.ts`)

Outgoing request errors:
- `INVALID_REQUEST` / `INVALID_RESPONSE_SSZ` / `SSZ_OVER_MAX_SIZE` → `LowTolerance`
- `SERVER_ERROR` → `MidTolerance`
- `UNKNOWN_ERROR_STATUS` → `HighTolerance`
- `DIAL_TIMEOUT` / `DIAL_ERROR` → `LowTolerance` (Fatal if Ping protocol selection fails)
- `RESP_TIMEOUT`:
  - Ping/Status/Metadata → `LowTolerance`
  - BlocksByRange/BlocksByRoot → `MidTolerance`
  - Others → no penalty

### Peer Manager Integration

The peer manager heartbeat (every 30s) should:
1. Decay all scores
2. Unban expired bans
3. Collect peers to disconnect (score below threshold)
4. Prune excess peers (prefer low-scoring, inbound, non-unique-subnet peers)
5. Request discovery if below target peer count
6. Prune stale disconnected peer entries

This is already implemented in `peer_manager.zig`.

## Implementation Status

### Already Implemented
- [x] `PeerAction` enum with score deltas (peer_info.zig)
- [x] `PeerScore` with lodestar_score + gossipsub_score composition (peer_info.zig)
- [x] Exponential decay with half-life (peer_info.zig)
- [x] Ban cooldown freeze (peer_info.zig)
- [x] Score state thresholds: healthy/disconnected/banned (peer_info.zig)
- [x] Per-peer per-protocol token bucket rate limiter (rate_limiter.zig)
- [x] Gossipsub topic scoring parameters (scoring_parameters.zig)
- [x] PeerDB with ban management, subnet coverage (peer_db.zig)
- [x] PeerManager with heartbeat, pruning, discovery (peer_manager.zig)
- [x] Basic PeerScorer for gossip validation outcomes (peer_scoring.zig)

### This PR Adds
- [x] Multi-component scoring with req/resp tracking (peer_scoring.zig rewrite)
- [x] Req/resp scoring integration (map errors to PeerActions)
- [x] Gossip reject reason → PeerAction mapping
- [x] Global rate limit across all peers
- [x] Backpressure mode (return delay instead of just reject)
- [x] Response-count-based token consumption
- [x] Score penalty on repeated rate limiting
- [x] Reconnection cool-down on Goodbye reasons
- [x] Comprehensive tests
