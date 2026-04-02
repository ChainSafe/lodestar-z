# Zig Peer Manager — Implementation Design Spec

> Target repo: `github.com/ChainSafe/lodestar-z`
> TS source of truth: `github.com/ChainSafe/lodestar/tree/unstable/packages/beacon-node/src/network/peers`
> Date: 2026-04-02

## Overview

This spec defines the implementation design for the Zig peer manager module in lodestar-z. The peer manager is a stateful logic engine with no internal threads that manages peer lifecycle, scoring, prioritization, and connection decisions for the Ethereum consensus client.

All algorithm/logic code is a **line-by-line translation** from the Lodestar TypeScript implementation. The TS reference files are archived in `docs/superpowers/reference/lodestar-ts-peer-manager.md`.

## Agreed Constraints

1. **Peer ID storage**: `StringHashMap` with allocator-owned string keys (`[]const u8`). Natural for the NAPI boundary where peer IDs arrive as JS strings.
2. **Time injection**: All components accept a `clock_fn: *const fn () i64` parameter. Production passes `std.time.milliTimestamp`; tests pass a controllable fake. Documented in code with rationale.
3. **TS fidelity**: All logic/algorithm code is translated line-by-line from the TS source. No reinterpretation of algorithms.
4. **Build order**: Bottom-up — types → store → scorer → prioritize → relevance → manager → NAPI bindings.
5. **Single spec**: Covers all three delivery phases in one document.

---

## File Layout

```
src/peer_manager/
  root.zig              # Module entry point, re-exports public API
  types.zig             # All shared types (PeerData, Action, Config, enums)
  constants.zig         # Score thresholds, intervals, ratios
  store.zig             # Layer 1: PeerStore
  scorer.zig            # Layer 2: PeerScorer
  prioritize.zig        # prioritizePeers algorithm
  relevance.zig         # assertPeerRelevance validation
  manager.zig           # Layer 3: PeerManager (logic engine)
bindings/napi/
  peer_manager.zig      # NAPI binding layer
bindings/test/
  peer_manager.test.ts  # TypeScript integration tests
```

Estimated total: ~2,550 lines across 10 files.

---

## 1. Constants (`constants.zig`)

Direct port of `score/constants.ts` plus peer manager constants from `peerManager.ts`.

### Score Thresholds

| Constant | Value | TS Source |
|----------|-------|-----------|
| `DEFAULT_SCORE` | 0 | `score/constants.ts` |
| `MIN_SCORE_BEFORE_DISCONNECT` | -20 | `score/constants.ts` |
| `MIN_SCORE_BEFORE_BAN` | -50 | `score/constants.ts` |
| `MIN_LODESTAR_SCORE_BEFORE_BAN` | -60 | `score/constants.ts` |
| `MAX_SCORE` | 100 | `score/constants.ts` |
| `MIN_SCORE` | -100 | `score/constants.ts` |
| `SCORE_THRESHOLD` | 1 | `score/constants.ts` |
| `SCORE_HALFLIFE_MS` | 600,000 (10 min) | `score/constants.ts` |
| `HALFLIFE_DECAY_MS` | `-ln(2) / SCORE_HALFLIFE_MS` | `score/constants.ts` |
| `COOL_DOWN_BEFORE_DECAY_MS` | 1,800,000 (30 min) | `score/constants.ts` |
| `MAX_SCORE_ENTRIES` | 1,000 | `score/constants.ts` |
| `NO_COOL_DOWN_APPLIED` | -1 | `score/constants.ts` |

### Peer Manager Intervals

| Constant | Value | TS Source |
|----------|-------|-----------|
| `PING_INTERVAL_INBOUND_MS` | 15,000 | `peerManager.ts:84` |
| `PING_INTERVAL_OUTBOUND_MS` | 20,000 | `peerManager.ts:85` |
| `STATUS_INTERVAL_MS` | 300,000 (5 min) | `peerManager.ts:87` |
| `STATUS_INBOUND_GRACE_PERIOD_MS` | 15,000 | `peerManager.ts:89` |
| `LONG_PEER_CONNECTION_MS` | 86,400,000 (24 hr) | `peerManager.ts:93` |

### Prioritization Constants

| Constant | Value | TS Source |
|----------|-------|-----------|
| `TARGET_SUBNET_PEERS` | 6 | `prioritizePeers.ts:43` |
| `TARGET_GROUP_PEERS_PER_SUBNET` | 4 | `prioritizePeers.ts:49` |
| `MIN_SYNC_COMMITTEE_PEERS` | 2 | `prioritizePeers.ts:56` |
| `LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS` | -2 | `prioritizePeers.ts:62` |
| `PEERS_TO_CONNECT_OVERSHOOT_FACTOR` | 3 | `prioritizePeers.ts:69` |
| `OUTBOUND_PEERS_RATIO` | 0.1 | `prioritizePeers.ts:74` |
| `FUTURE_SLOT_TOLERANCE` | 1 | `assertPeerRelevance.ts:5` |
| `ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR` | 0.1 | `peerManager.ts:113` |
| `STARVATION_PRUNE_RATIO` | 0.05 | `peerManager.ts:108` |

---

## 2. Types (`types.zig`)

All shared types used across layers.

### Core Types

```zig
pub const PeerIdStr = []const u8;

pub const Direction = enum { inbound, outbound };
pub const RelevantPeerStatus = enum { unknown, relevant, irrelevant };
pub const ScoreState = enum { healthy, disconnected, banned };
pub const Encoding = enum { ssz, ssz_snappy };

pub const ForkName = enum {
    phase0, altair, bellatrix, capella, deneb, electra, fulu, gloas, heze,

    pub fn isPostFulu(self: ForkName) bool {
        return @intFromEnum(self) >= @intFromEnum(ForkName.fulu);
    }
};
```

### Client Kind

Port of `client.ts`. Enum + parser function:

```zig
pub const ClientKind = enum {
    lighthouse, nimbus, teku, prysm, lodestar, grandine, unknown,
};

/// Port of getKnownClientFromAgentVersion(). Returns null for unknown agents.
pub fn getKnownClientFromAgentVersion(agent_version: []const u8) ?ClientKind { ... }
```

### Peer Action and Goodbye Codes

```zig
pub const PeerAction = enum {
    fatal,
    low_tolerance,
    mid_tolerance,
    high_tolerance,

    pub fn scoreDelta(self: PeerAction) f64 {
        return switch (self) {
            .fatal => -(MAX_SCORE - MIN_SCORE),  // -200
            .low_tolerance => -10,
            .mid_tolerance => -5,
            .high_tolerance => -1,
        };
    }
};

pub const GoodbyeReasonCode = enum(u64) {
    client_shutdown = 1,
    irrelevant_network = 2,
    @"error" = 3,
    too_many_peers = 129,
    score_too_low = 250,
    banned = 251,
    inbound_disconnect = 252,
    _,
};
```

### Ethereum Protocol Types

```zig
pub const Status = struct {
    fork_digest: [4]u8,
    finalized_root: [32]u8,
    finalized_epoch: u64,
    head_root: [32]u8,
    head_slot: u64,
    earliest_available_slot: ?u64,  // Post-fulu only
};

pub const Metadata = struct {
    seq_number: u64,
    attnets: [8]u8,            // 64-bit bitvector
    syncnets: [1]u8,           // 4-bit bitvector (padded to byte)
    custody_group_count: u64,
    custody_groups: ?[]u32,    // Allocator-owned, computed
    sampling_groups: ?[]u32,   // Allocator-owned, computed
};
```

### Peer Data

```zig
pub const PeerData = struct {
    peer_id: PeerIdStr,                // Borrowed reference to HashMap key
    direction: Direction,
    status: ?Status,
    metadata: ?Metadata,
    relevant_status: RelevantPeerStatus,
    connected_unix_ts_ms: i64,
    last_received_msg_unix_ts_ms: i64,
    last_status_unix_ts_ms: i64,
    agent_version: ?[]const u8,        // Allocator-owned
    agent_client: ?ClientKind,
    node_id: ?[32]u8,
    encoding_preference: ?Encoding,
};
```

### Score Data (separate map in scorer)

```zig
pub const PeerScoreData = struct {
    lodestar_score: f64,
    gossip_score: f64,
    ignore_negative_gossip_score: bool,
    score: f64,
    last_update_ms: i64,
};
```

### Action Type (tagged union)

```zig
pub const Action = union(enum) {
    send_ping: PeerIdStr,
    send_status: PeerIdStr,
    send_goodbye: struct { peer_id: PeerIdStr, reason: GoodbyeReasonCode },
    request_metadata: PeerIdStr,
    disconnect_peer: PeerIdStr,
    request_discovery: DiscoveryRequest,
    tag_peer_relevant: PeerIdStr,
    emit_peer_connected: struct { peer_id: PeerIdStr, direction: Direction },
    emit_peer_disconnected: PeerIdStr,
};

pub const DiscoveryRequest = struct {
    peers_to_connect: u32,
    attnet_queries: []SubnetQuery,
    syncnet_queries: []SubnetQuery,
    custody_group_queries: []CustodyGroupQuery,
};

pub const SubnetQuery = struct {
    subnet: u32,
    to_slot: u64,
    max_peers_to_discover: u32,
};

pub const CustodyGroupQuery = struct {
    group: u32,
    max_peers_to_discover: u32,
};

pub const RequestedSubnet = struct {
    subnet: u32,
    to_slot: u64,
};
```

### Prioritization Types

```zig
pub const ExcessPeerDisconnectReason = enum {
    low_score,
    no_long_lived_subnet,
    too_grouped_subnet,
    find_better_peers,
};

pub const PeerDisconnect = struct {
    peer_id: PeerIdStr,
    reason: ExcessPeerDisconnectReason,
};

pub const GossipScoreUpdate = struct {
    peer_id: []const u8,
    new_score: f64,
};
```

### Relevance Result

```zig
pub const IrrelevantPeerResult = union(enum) {
    incompatible_forks: struct { ours: [4]u8, theirs: [4]u8 },
    different_clocks: struct { slot_diff: i64 },
    different_finalized: struct { expected_root: [32]u8, remote_root: [32]u8 },
    no_earliest_available_slot: void,
};
```

### Config

```zig
pub const Config = struct {
    target_peers: u32 = 200,
    max_peers: u32 = 210,
    target_group_peers: u32 = 6,
    ping_interval_inbound_ms: i64 = 15_000,
    ping_interval_outbound_ms: i64 = 20_000,
    status_interval_ms: i64 = 300_000,
    status_inbound_grace_period_ms: i64 = 15_000,
    gossipsub_negative_score_weight: f64,
    gossipsub_positive_score_weight: f64,
    disable_peer_scoring: bool = false,
    initial_fork_name: ForkName,
    number_of_custody_groups: u32 = 128,
    custody_requirement: u64 = 4,
    samples_per_slot: u64 = 8,
    slots_per_epoch: u64 = 32,
};
```

### Bitvector Helpers

```zig
/// Extract set bit indices from a 64-bit attestation subnet bitvector.
/// Returns stack-allocated bounded array — no heap allocation.
pub fn getAttnetsActiveBits(attnets: [8]u8) std.BoundedArray(u8, 64) { ... }

/// Extract set bit indices from a 4-bit sync subnet bitvector.
pub fn getSyncnetsActiveBits(syncnets: [1]u8) std.BoundedArray(u8, 8) { ... }
```

---

## 3. PeerStore (`store.zig`)

Pure data layer. Owns a `StringHashMap(PeerData)`. No timers, no scoring, no side effects.

### API

```zig
pub const PeerStore = struct {
    allocator: Allocator,
    peers: std.StringHashMap(PeerData),

    pub fn init(allocator: Allocator) PeerStore;
    pub fn deinit(self: *PeerStore) void;

    // Lifecycle
    pub fn addPeer(self: *PeerStore, peer_id: []const u8, direction: Direction, now_ms: i64) !void;
    pub fn removePeer(self: *PeerStore, peer_id: []const u8) void;
    pub fn contains(self: *const PeerStore, peer_id: []const u8) bool;

    // Accessors
    pub fn getPeerData(self: *const PeerStore, peer_id: []const u8) ?*PeerData;
    pub fn getConnectedPeerCount(self: *const PeerStore) u32;

    // Mutators
    pub fn updateStatus(self: *PeerStore, peer_id: []const u8, status: Status) void;
    pub fn updateMetadata(self: *PeerStore, peer_id: []const u8, metadata: Metadata) void;
    pub fn setAgentVersion(self: *PeerStore, peer_id: []const u8, version: []const u8) !void;
    pub fn setEncodingPreference(self: *PeerStore, peer_id: []const u8, encoding: Encoding) void;
    pub fn updateLastReceivedMsg(self: *PeerStore, peer_id: []const u8, now_ms: i64) void;
    pub fn updateLastStatus(self: *PeerStore, peer_id: []const u8, now_ms: i64) void;

    // Iteration
    pub fn iterPeers(self: *const PeerStore) std.StringHashMap(PeerData).Iterator;
};
```

### Memory Ownership

- **Key strings**: Duplicated via `allocator.dupe(u8, peer_id)` on `addPeer`. Freed on `removePeer` and `deinit`.
- **`agent_version`**: Allocator-owned. `setAgentVersion` frees previous value before allocating new.
- **`metadata.custody_groups` / `sampling_groups`**: Allocator-owned slices. Freed on metadata update and peer removal.
- **`deinit`**: Iterates all peers, frees all owned strings/slices, then `peers.deinit()`.

### Behavior

- `addPeer` returns `error.PeerAlreadyExists` if peer is already in the map. Caller (manager) decides whether to update or ignore.
- `removePeer` is a no-op for unknown peers.
- All mutators (`updateStatus`, etc.) are no-ops for unknown peers (look up, return if null).
- `iterPeers()` returns the raw HashMap iterator. Pointers are invalidated by mutations.

### Tests

- Add/remove peers, verify count
- `addPeer` duplicate returns `error.PeerAlreadyExists`
- Remove nonexistent peer is no-op
- Set/get all fields round-trip correctly
- `setAgentVersion` frees previous value, verified by `std.testing.allocator` leak detection
- `updateMetadata` frees previous custody_groups/sampling_groups slices
- Iterator yields all connected peers
- `deinit` frees everything cleanly

---

## 4. PeerScorer (`scorer.zig`)

Line-by-line port of `score/score.ts` (RealScore), `score/store.ts` (PeerRpcScoreStore), and `score/utils.ts`. Owns a separate `StringHashMap(PeerScoreData)` that persists scores across peer disconnections.

### API

```zig
pub const PeerScorer = struct {
    allocator: Allocator,
    scores: std.StringHashMap(PeerScoreData),
    config: Config,
    /// Injectable clock for deterministic testing. Returns current
    /// time in milliseconds since the Unix epoch. Production callers
    /// should pass `std.time.milliTimestamp`; tests pass a fake that
    /// returns a controllable value.
    clock_fn: *const fn () i64,

    pub fn init(allocator: Allocator, config: Config, clock_fn: *const fn () i64) PeerScorer;
    pub fn deinit(self: *PeerScorer) void;

    // Score mutations
    pub fn reportPeer(self: *PeerScorer, peer_id: []const u8, action: PeerAction) void;
    pub fn updateGossipScores(self: *PeerScorer, scores: []const GossipScoreUpdate) void;
    pub fn applyReconnectionCoolDown(self: *PeerScorer, peer_id: []const u8, reason: GoodbyeReasonCode) i64;

    // Periodic update
    pub fn decayScores(self: *PeerScorer) void;

    // Queries
    pub fn getScore(self: *const PeerScorer, peer_id: []const u8) f64;
    pub fn getScoreState(self: *const PeerScorer, peer_id: []const u8) ScoreState;
    pub fn isCoolingDown(self: *const PeerScorer, peer_id: []const u8) bool;
};
```

### Score Computation (port of `score.ts:recomputeScore`)

```
score = lodestar_score
if score <= MIN_LODESTAR_SCORE_BEFORE_BAN:
    return  // Ignore gossip, peer is banned on lodestar score alone
if gossip_score >= 0:
    score += gossip_score * config.gossipsub_positive_score_weight
else if !ignore_negative_gossip_score:
    score += gossip_score * config.gossipsub_negative_score_weight
```

### reportPeer (port of `store.ts:applyAction`)

1. `getOrCreateScore(peer_id)` — creates entry with defaults if absent, duping the key string
2. `lodestar_score += action.scoreDelta()`
3. Clamp to `[MIN_SCORE, MAX_SCORE]`
4. `recomputeScore()`
5. If score transitions from non-banned to banned: `last_update_ms = now + COOL_DOWN_BEFORE_DECAY_MS`

### decayScores (port of `store.ts:update`)

1. Cap total entries at `MAX_SCORE_ENTRIES` (prune lowest-absolute-score disconnected entries)
2. For each entry:
   - If `last_update_ms` is in the past (not cooling down):
     - `elapsed = now - last_update_ms`
     - `lodestar_score *= exp(HALFLIFE_DECAY_MS * elapsed)`
     - `last_update_ms = now`
     - `recomputeScore()`
   - If `|lodestar_score| < SCORE_THRESHOLD`: prune entry, free key string
3. Prune after decay, not before — matches TS behavior

### updateGossipScores (port of `score/utils.ts:updateGossipsubScores`)

1. Sort input by gossip score descending
2. Compute `to_ignore_count = floor(ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR * config.target_peers)`
3. For each peer in sorted order:
   - If score < 0 and score > negative threshold and `to_ignore_count > 0`: set `ignore = true`, decrement
   - Call `updateGossipsubScore(peer_id, score, ignore)` which sets fields only if not cooling down

### applyReconnectionCoolDown (port of `score.ts:218-239`)

Maps goodbye reason to cooldown:

| Reason | Cooldown |
|--------|----------|
| `banned`, `score_too_low` | No cooldown (return `NO_COOL_DOWN_APPLIED`) |
| `inbound_disconnect`, `too_many_peers` | 5 minutes |
| `error`, `client_shutdown` | 60 minutes |
| `irrelevant_network` | 4 hours |

Sets `last_update_ms = now + cooldown_minutes * 60 * 1000`.

### isCoolingDown (port of `score.ts:197-199`)

Returns `clock_fn() < last_update_ms`.

### scoreToState (port of `score/utils.ts:scoreToState`)

```
if score <= MIN_SCORE_BEFORE_BAN: return .banned
if score <= MIN_SCORE_BEFORE_DISCONNECT: return .disconnected
return .healthy
```

### disable_peer_scoring mode

When `config.disable_peer_scoring` is true (port of `MaxScore` class):
- `getScore` always returns `MAX_SCORE`
- `getScoreState` always returns `.healthy`
- `isCoolingDown` always returns `false`
- All mutation functions are no-ops

### Memory Ownership

- Key strings in the scores map are duplicated via `allocator.dupe()` on first insert
- Freed on prune and `deinit`

### Tests

- `reportPeer` with each `PeerAction` level, verify score delta and clamping
- Score decay: set score, advance fake clock, call `decayScores`, verify exponential decay
- Ban transition: report `fatal`, verify `ScoreState.banned` and cooldown
- Cooldown: `isCoolingDown` true during cooldown, false after
- Gossipsub blending: positive adds, negative weighted, top 10% ignored
- `recomputeScore`: `MIN_LODESTAR_SCORE_BEFORE_BAN` bypasses gossip
- Pruning: >1000 entries, verify pruned
- `disable_peer_scoring`: all queries return MAX_SCORE

---

## 5. assertPeerRelevance (`relevance.zig`)

Pure function. Line-by-line port of `utils/assertPeerRelevance.ts`.

### API

```zig
/// Returns null if peer is relevant, or the reason it's irrelevant.
pub fn assertPeerRelevance(
    fork_name: ForkName,
    remote: Status,
    local: Status,
    current_slot: u64,
) ?IrrelevantPeerResult;
```

### Logic (4 checks in order, matching TS)

1. **Fork digest mismatch**: `local.fork_digest != remote.fork_digest` → `incompatible_forks`
2. **Clock divergence**: `remote.head_slot - max(current_slot, 0) > FUTURE_SLOT_TOLERANCE` → `different_clocks`
3. **Finalized root mismatch**: `remote.finalized_epoch <= local.finalized_epoch` and both roots non-zero and same epoch but different roots → `different_finalized`
4. **Post-fulu missing field**: `fork_name.isPostFulu()` and `remote.earliest_available_slot == null` → `no_earliest_available_slot`

### Helper

```zig
fn isZeroRoot(root: [32]u8) bool {
    return std.mem.eql(u8, &root, &([_]u8{0} ** 32));
}
```

### Tests

- Each of the 4 irrelevant reasons triggers correctly
- Happy path: relevant peer returns null
- Edge cases: zero roots, post-fulu vs pre-fulu, exact slot tolerance boundary

---

## 6. prioritizePeers (`prioritize.zig`)

Largest file. Line-by-line port of `utils/prioritizePeers.ts` (~627 lines TS).

### Public API

```zig
pub const PrioritizePeersInput = struct {
    peer_id: PeerIdStr,
    direction: ?Direction,
    status: ?Status,
    attnets: ?[8]u8,
    syncnets: ?[1]u8,
    sampling_groups: ?[]const u32,
    score: f64,
};

pub const PrioritizePeersOpts = struct {
    target_peers: u32,
    max_peers: u32,
    target_group_peers: u32,
    local_status: Status,
    starved: bool,
    starvation_prune_ratio: f64,
    starvation_threshold_slots: u64,
    outbound_peers_ratio: f64 = OUTBOUND_PEERS_RATIO,
    target_subnet_peers: u32 = TARGET_SUBNET_PEERS,
    number_of_custody_groups: u32,
};

pub const PrioritizePeersResult = struct {
    peers_to_connect: u32,
    peers_to_disconnect: std.ArrayList(PeerDisconnect),
    attnet_queries: std.ArrayList(SubnetQuery),
    syncnet_queries: std.ArrayList(SubnetQuery),
    custody_group_queries: std.AutoHashMap(u32, u32),

    pub fn deinit(self: *PrioritizePeersResult) void;
};

pub fn prioritizePeers(
    allocator: Allocator,
    connected_peers: []const PrioritizePeersInput,
    active_attnets: []const RequestedSubnet,
    active_syncnets: []const RequestedSubnet,
    our_sampling_groups: ?[]const u32,
    opts: PrioritizePeersOpts,
) !PrioritizePeersResult;
```

### Internal Functions (matching TS structure)

**`computeStatusScore`** (port of TS `computeStatusScore`):
- Returns `FAR_AHEAD` if `theirs.finalized_epoch > ours.finalized_epoch` or `theirs.head_slot > ours.head_slot + starvation_threshold_slots`
- Otherwise `CLOSE_TO_US`

**`requestSubnetPeers`** (port of TS `requestSubnetPeers`):
- Counts peers per attestation subnet, generates `attnet_queries` for under-covered subnets
- Counts peers per sync subnet, generates `syncnet_queries`
- Post-fulu: counts peers per custody group, generates `custody_group_queries`
- Tracks `duties_by_peer` — how many active subnet duties each peer serves

**`pruneExcessPeers`** (port of TS `pruneExcessPeers`):
4-phase pruning in order:
1. Peers with no long-lived subnet subscriptions
2. Peers with score < `LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS`
3. Peers on over-populated subnets (too-grouped)
4. Remaining peers to reach target (find-better-peers)

Filtering before pruning:
- Peers with duties are not eligible
- Peers far ahead when starved are not eligible
- Outbound peers up to `OUTBOUND_PEERS_RATIO` are protected (highest score first)

**`sortPeersToPrune`** (port of TS `sortPeersToPrune`):
- Shuffle first to break ties (PRNG seeded for deterministic tests)
- Sort ascending by: duties → status score → long-lived subnet count → peer score

**`findMaxPeersSubnet`**: Find subnet with most peers exceeding `TARGET_SUBNET_PEERS`.

**`findPeerToRemove`**: Within a too-grouped subnet, find a peer whose removal won't drop any active subnet below target or any sync committee below `MIN_SYNC_COMMITTEE_PEERS`.

### Allocator Usage

- Takes an allocator for all temporary working structures
- Returned `PrioritizePeersResult` owns its ArrayLists and HashMap — caller calls `deinit()`
- Internal PeerInfo array, subnet maps, etc. are allocated and freed within the function

### Randomness

`sortPeersToPrune` needs shuffle. Uses `std.Random.DefaultPrng` with a seed. For deterministic tests, seed is controlled via a parameter or fixed value.

### Tests

- Below target peers → `peers_to_connect > 0` with overshoot factor
- Above target peers → disconnect list populated
- Subnet coverage queries generated for under-covered subnets
- Pruning priority order: no-subnet → low-score → too-grouped → find-better
- Outbound ratio protection
- Starvation mode prunes extra 5%
- Custody group queries (post-fulu)
- `sortPeersToPrune` ordering verification

---

## 7. PeerManager (`manager.zig`)

Orchestration layer. Composes PeerStore + PeerScorer. Implements the tick-driven model from the design document.

### API

```zig
pub const PeerManager = struct {
    allocator: Allocator,
    store: PeerStore,
    scorer: PeerScorer,
    config: Config,
    clock_fn: *const fn () i64,

    // Mutable state
    current_fork_name: ForkName,
    last_heartbeat_slot: u64,
    active_attnets: std.ArrayList(RequestedSubnet),
    active_syncnets: std.ArrayList(RequestedSubnet),
    our_sampling_groups: ?[]u32,

    // Reusable action buffer
    actions: std.ArrayList(Action),

    pub fn init(allocator: Allocator, config: Config, clock_fn: *const fn () i64) !PeerManager;
    pub fn deinit(self: *PeerManager) void;

    // Tick functions (return actions)
    pub fn heartbeat(self: *PeerManager, current_slot: u64, local_status: Status) ![]const Action;
    pub fn checkPingAndStatus(self: *PeerManager) ![]const Action;

    // Event handlers
    pub fn onConnectionOpen(self: *PeerManager, peer_id: []const u8, direction: Direction) ![]const Action;
    pub fn onConnectionClose(self: *PeerManager, peer_id: []const u8) ![]const Action;
    pub fn onStatusReceived(self: *PeerManager, peer_id: []const u8, remote_status: Status, local_status: Status) ![]const Action;
    pub fn onMetadataReceived(self: *PeerManager, peer_id: []const u8, metadata: Metadata) void;
    pub fn onMessageReceived(self: *PeerManager, peer_id: []const u8) void;
    pub fn onGoodbye(self: *PeerManager, peer_id: []const u8, reason: GoodbyeReasonCode) ![]const Action;
    pub fn onPing(self: *PeerManager, peer_id: []const u8, seq_number: u64) ![]const Action;

    // Score mutations
    pub fn reportPeer(self: *PeerManager, peer_id: []const u8, action: PeerAction) void;
    pub fn updateGossipScores(self: *PeerManager, scores: []const GossipScoreUpdate) void;

    // Configuration updates
    pub fn setSubnetRequirements(self: *PeerManager, attnets: []const RequestedSubnet, syncnets: []const RequestedSubnet) !void;
    pub fn setForkName(self: *PeerManager, fork_name: ForkName) void;
    pub fn setSamplingGroups(self: *PeerManager, groups: []const u32) !void;

    // Queries
    pub fn getPeerData(self: *const PeerManager, peer_id: []const u8) ?*const PeerData;
    pub fn getConnectedPeerCount(self: *const PeerManager) u32;
    pub fn getEncodingPreference(self: *const PeerManager, peer_id: []const u8) ?Encoding;
    pub fn getPeerKind(self: *const PeerManager, peer_id: []const u8) ?ClientKind;
    pub fn getAgentVersion(self: *const PeerManager, peer_id: []const u8) ?[]const u8;
    pub fn getPeerScore(self: *const PeerManager, peer_id: []const u8) f64;
};
```

### Action Buffer Pattern

The manager reuses a single `std.ArrayList(Action)` across calls. Each function clears it, appends actions, returns a slice. The caller must consume the slice before the next call. This is safe — all calls are synchronous on the same thread. Avoids per-call allocation.

### heartbeat (port of `peerManager.ts:heartbeat`)

1. `scorer.decayScores()`
2. For each connected peer: if `scorer.getScoreState(peer_id) == .banned` → append `send_goodbye(banned)` + `disconnect_peer`; if `.disconnected` → append `send_goodbye(score_too_low)` + `disconnect_peer`
3. Detect starvation: `current_slot == last_heartbeat_slot` persisting for >2 epochs
4. Build `PrioritizePeersInput` array from store + scorer state
5. Call `prioritizePeers()`
6. Convert result: disconnects → `send_goodbye(too_many_peers)` + `disconnect_peer`; peers_to_connect > 0 → `request_discovery`
7. Update `last_heartbeat_slot = current_slot`

### checkPingAndStatus (port of `peerManager.ts:pingAndStatusTimeouts`)

For each connected peer, using `clock_fn()`:
- Inbound + `now - last_received_msg > ping_interval_inbound_ms` → `send_ping`
- Outbound + `now - last_received_msg > ping_interval_outbound_ms` → `send_ping`
- `now - last_status > status_interval_ms` → `send_status`
- Inbound + `last_status == 0` (never received) + `now - connected > status_inbound_grace_period_ms` → `disconnect_peer`

### onConnectionOpen (port of `onLibp2pPeerConnect`)

1. If `store.contains(peer_id)`: return empty (idempotent)
2. `store.addPeer(peer_id, direction, clock_fn())`
3. Append `emit_peer_connected`

### onConnectionClose (port of `onLibp2pPeerDisconnect`)

1. Look up peer data. If not found, return empty.
2. `store.removePeer(peer_id)`
3. Append `emit_peer_disconnected`

### onStatusReceived (port of `onStatus`)

1. `store.updateStatus(peer_id, remote_status)`
2. `store.updateLastStatus(peer_id, clock_fn())`
3. `assertPeerRelevance(current_fork_name, remote_status, local_status, last_heartbeat_slot)`
4. If irrelevant: set `relevant_status = .irrelevant`, append `send_goodbye(irrelevant_network)` + `disconnect_peer`
5. If relevant and `relevant_status != .relevant`: set `.relevant`, append `tag_peer_relevant`

### onPing (port of `onPing`)

1. Look up peer metadata seq_number
2. If remote `seq_number > stored` or no stored metadata → append `request_metadata`

### onGoodbye (port of `onGoodbye`)

1. `scorer.applyReconnectionCoolDown(peer_id, reason)`
2. Append `disconnect_peer`

### Tests

- heartbeat: banned peers get goodbye+disconnect, starvation detection, prioritize results forwarded
- checkPingAndStatus: advance clock past each threshold, verify correct actions per direction
- onConnectionOpen: new peer added, emits event. Duplicate is no-op.
- onConnectionClose: peer removed, emits event
- onStatusReceived: relevant peer tagged, irrelevant gets goodbye
- onPing: higher seq_number triggers metadata request
- Full lifecycle: connect → status → ping → heartbeat → disconnect

---

## 8. NAPI Bindings (`bindings/napi/peer_manager.zig`)

Follows existing lodestar-z binding conventions.

### State Pattern

```zig
pub const State = struct {
    manager: ?PeerManager = null,

    pub fn init(self: *State, config: Config) !void {
        self.manager = try PeerManager.init(allocator, config, std.time.milliTimestamp);
    }

    pub fn deinit(self: *State) void {
        if (self.manager) |*m| {
            m.deinit();
            self.manager = null;
        }
    }
};

pub var state: State = .{};
```

### Binding Functions

All follow the callback signature `fn(napi.Env, napi.CallbackInfo(N)) !napi.Value`.

**Lifecycle:**
- `PeerManager_init(env, cb(1))` — deserializes Config from JS object, calls `state.init(config)`
- `PeerManager_close(env, cb(0))` — calls `state.deinit()`

**Tick functions (return Action[]):**
- `PeerManager_heartbeat(env, cb(2))` — args: `current_slot: u64`, `local_status: object`
- `PeerManager_checkPingAndStatus(env, cb(0))`

**Event handlers:**
- `PeerManager_onConnectionOpen(env, cb(2))` — args: `peerId: string`, `direction: string`
- `PeerManager_onConnectionClose(env, cb(1))` — args: `peerId: string`
- `PeerManager_onStatusReceived(env, cb(3))` — args: `peerId: string`, `remoteStatus: object`, `localStatus: object`
- `PeerManager_onMetadataReceived(env, cb(2))` — args: `peerId: string`, `metadata: object`
- `PeerManager_onMessageReceived(env, cb(1))` — args: `peerId: string`
- `PeerManager_onGoodbye(env, cb(2))` — args: `peerId: string`, `reason: number`
- `PeerManager_onPing(env, cb(2))` — args: `peerId: string`, `seqNumber: number`
- `PeerManager_reportPeer(env, cb(2))` — args: `peerId: string`, `action: string`
- `PeerManager_updateGossipScores(env, cb(1))` — args: `scores: {peerId, score}[]`
- `PeerManager_setSubnetRequirements(env, cb(2))` — args: `attnets: object[]`, `syncnets: object[]`
- `PeerManager_setForkName(env, cb(1))` — args: `forkName: string`

**Queries:**
- `PeerManager_getPeerData(env, cb(1))` — returns PeerData object or null
- `PeerManager_getConnectedPeers(env, cb(0))` — returns string[]
- `PeerManager_getConnectedPeerCount(env, cb(0))` — returns u32
- `PeerManager_getEncodingPreference(env, cb(1))` — returns string or null
- `PeerManager_getPeerKind(env, cb(1))` — returns string or null
- `PeerManager_getAgentVersion(env, cb(1))` — returns string or null
- `PeerManager_getPeerScore(env, cb(1))` — returns f64

### Config Deserialization

Uses `inline for (std.meta.fields(Config))` pattern from existing `bindings/napi/config.zig` to read each field from JS object by name with type dispatch.

### Action Serialization

Converts `[]const Action` to JS array:

```javascript
// Example output
[
  { type: "send_ping", peerId: "16Uiu2..." },
  { type: "send_goodbye", peerId: "16Uiu2...", reason: 3 },
  { type: "request_discovery", count: 15, attnetQueries: [...], syncnetQueries: [...] },
  { type: "emit_peer_connected", peerId: "16Uiu2...", direction: "outbound" },
]
```

### Status/Metadata Deserialization

- `forkDigest`: Uint8Array (4 bytes) → `[4]u8`
- `finalizedRoot`, `headRoot`: Uint8Array (32 bytes) → `[32]u8`
- Numeric fields: `getValueInt64()` or `getValueUint32()`
- `attnets`: Uint8Array (8 bytes) → `[8]u8`
- `syncnets`: Uint8Array (1 byte) → `[1]u8`

### Multi-env Support

Follows existing `env_refcount` pattern from `bindings/napi/root.zig`. First env initializes, last env tears down.

### Registration

Added to existing `bindings/napi/root.zig`:

```zig
try peer_manager.register(env, exports);
```

### Tests (`bindings/test/peer_manager.test.ts`)

- Init with config object, verify no throw
- `onConnectionOpen` → `getConnectedPeerCount()` increases
- `heartbeat` returns Action array with correct shapes
- `getPeerData` returns correct object after mutations
- Round-trip: connect → status → heartbeat → verify actions
- `reportPeer` → `getPeerScore` reflects penalty
- `close` → subsequent calls throw

---

## Build Integration

### Changes to `build.zig`

1. Register module:
```zig
const module_peer_manager = b.createModule(.{
    .root_source_file = b.path("src/peer_manager/root.zig"),
    .target = target,
    .optimize = optimize,
});
b.modules.put(b.dupe("peer_manager"), module_peer_manager) catch @panic("OOM");
```

2. Add test step:
```zig
const test_peer_manager = b.step("test:peer_manager", "Run peer_manager tests");
const test_exe = b.addTest(.{ .root_module = module_peer_manager });
test_peer_manager.dependOn(&b.addRunArtifact(test_exe).step);
```

3. Wire as dependency of bindings library.

### `src/peer_manager/root.zig`

Re-exports public API:

```zig
pub const PeerManager = @import("manager.zig").PeerManager;
pub const PeerStore = @import("store.zig").PeerStore;
pub const PeerScorer = @import("scorer.zig").PeerScorer;
pub const prioritizePeers = @import("prioritize.zig").prioritizePeers;
pub const assertPeerRelevance = @import("relevance.zig").assertPeerRelevance;

// Re-export types
const types_ = @import("types.zig");
pub const PeerData = types_.PeerData;
pub const Action = types_.Action;
pub const Config = types_.Config;
pub const Direction = types_.Direction;
pub const Status = types_.Status;
pub const Metadata = types_.Metadata;
pub const ForkName = types_.ForkName;
// ... etc

test {
    @import("std").testing.refAllDecls(@This());
}
```

---

## Implementation Order

| Step | File(s) | Dependencies | Deliverable |
|------|---------|-------------|-------------|
| 1 | `constants.zig`, `types.zig` | None | All types compile |
| 2 | `store.zig` | types, constants | PeerStore with tests |
| 3 | `scorer.zig` | types, constants | PeerScorer with tests |
| 4 | `relevance.zig` | types, constants | assertPeerRelevance with tests |
| 5 | `prioritize.zig` | types, constants | prioritizePeers with tests |
| 6 | `manager.zig` | store, scorer, relevance, prioritize | PeerManager with tests |
| 7 | `root.zig`, `build.zig` | all above | Module compiles, `zig build test:peer_manager` passes |
| 8 | `bindings/napi/peer_manager.zig` | all above | NAPI bindings compile |
| 9 | `bindings/test/peer_manager.test.ts` | bindings | `pnpm test` passes |

---

## Success Criteria

1. Peer scoring produces identical results to the TS implementation for the same inputs
2. Heartbeat action output matches TS behavior for the same peer state
3. All Zig unit tests and TypeScript integration tests pass
4. Zig module compiles and tests independently without any JS dependency
5. NAPI bindings load correctly in Node.js
6. `std.testing.allocator` detects no memory leaks in any test
7. No function exceeds 70 lines (TigerStyle)
