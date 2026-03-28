# Networking Subsystem Review

**Date:** 2026-03-28  
**Branch:** `feat/beacon-node`  
**Scope:** All 29 files in `src/networking/` (~12,800 lines)  
**Reviewer:** lodekeeper-z

---

## Executive Summary

The networking subsystem is a substantial piece of work — 12.8k lines covering req/resp wire protocol, gossip validation, peer management, discovery, PeerDAS custody, and rate limiting. The architecture is generally sound, with clean separation of concerns and extensive test coverage.

However, there are **compile-blocking bugs**, **API signature mismatches** that will prevent integration, **two parallel systems** for peer scoring/management that need consolidation, and significant **completeness gaps** vs TS Lodestar that will matter for mainnet.

**Verdict:** Good foundation. Needs targeted fixes before it can actually run.

---

## 1. Correctness

### 🔴 Critical: Duplicate switch prongs in `protocol.zig`

`Method.hasMultipleResponses()` lists `data_column_sidecars_by_root` and `data_column_sidecars_by_range` **twice** in the `true` arm:

```zig
.data_column_sidecars_by_root,
.data_column_sidecars_by_range,
.light_client_updates_by_range,
.data_column_sidecars_by_root,   // ← DUPLICATE
.data_column_sidecars_by_range,  // ← DUPLICATE
=> true,
```

Zig does not allow duplicate switch prongs. This is a **compile error** that blocks the entire networking module from building. Also `light_client_updates_by_range` is listed in the `true` arm here but in the `false` arm for `hasContextBytes` — verify intent.

### 🔴 Critical: API signature mismatch in gossip publish path

`P2pService.publishGossip()` calls:
```zig
self.gossip_adapter.publish(topic, data)
```
But `EthGossipAdapter.publish()` has signature:
```zig
pub fn publish(self, topic_type: GossipTopicType, subnet_id: ?u8, ssz_bytes: []const u8) !void
```
These are **incompatible**. The service passes `([]const u8, []const u8)` but the adapter expects `(GossipTopicType, ?u8, []const u8)`. This will fail to compile or silently misroute.

### 🟡 MetadataProtocol version mismatch

`eth2_protocols.zig` defines:
```zig
pub const MetadataProtocol = makeProtocolHandler(
    .metadata,
    "/eth2/beacon_chain/req/metadata/1/ssz_snappy",  // v1
);
```
But `req_resp_handler.zig` returns `MetadataV2` (which includes `syncnets`), and `p2p_service.zig` Identify handler advertises `/eth2/beacon_chain/req/metadata/2/ssz_snappy`.

On mainnet post-Altair, peers will negotiate v2. Responding with v2 bytes on a v1 protocol ID will confuse other clients. Fix: change to `/metadata/2/ssz_snappy`.

### 🟡 `handleBeaconBlocksByRoot` fork digest hack

```zig
const slot = std.mem.readInt(u64, root[0..8], .little);
chunks[i].context_bytes = context.getForkDigest(context.ptr, slot),
```

The first 8 bytes of a block root are not a slot. This will return **wrong fork digests** for multi-fork responses. The comment says "placeholder" — true, but this will cause real interop failures when talking to other clients. The handler needs to either (a) extract the slot from the block SSZ, or (b) have `getBlockByRoot` return (ssz_bytes, slot) pairs.

Same issue in `handleBlobSidecarsByRoot` and `handleDataColumnSidecarsByRoot`.

### 🟡 `gossip_decoding.zig` blob_sidecar hardcoded offsets

```zig
const min_size = 131288 + 32; // need through parent_root
const slot = std.mem.readInt(u64, ssz_bytes[131272..131280], .little);
```

Hardcoded byte offsets into the BlobSidecar SSZ. If the blob size changes (already different between Deneb and Electra for FIELD_ELEMENTS_PER_BLOB changes), or if the container layout shifts, this silently reads garbage. Use proper SSZ deserialization or at minimum compute offsets from constants.

### 🟢 Wire encoding is correct

`varint.zig`, `req_resp_encoding.zig` correctly implement LEB128 + Snappy framing per spec. The `calcSnappyFrameSize` approach for multi-chunk response parsing is a good solution. Test coverage is thorough.

### 🟢 Gossip validation logic is correct

`gossip_validation.zig` correctly implements the spec's ACCEPT/REJECT/IGNORE semantics for beacon_block, aggregate_and_proof, voluntary_exit, proposer_slashing, attester_slashing, and attestation topics. Dedup key generation with domain separators is well done.

### 🟢 Custody column computation is correct

`custody.zig` implements `get_custody_columns` per the fulu spec using SHA256(node_id || subnet_index) sorting. Determinism tests pass. The `isCustodied` binary search on sorted output is correct.

---

## 2. Completeness

### Missing vs TS Lodestar

| TS Lodestar Component | lodestar-z Status | Impact |
|---|---|---|
| `gossipHandlers.ts` — per-topic handler dispatch + processing | ❌ Missing | No actual gossip message processing pipeline |
| `gossipQueues/` — prioritized work queues per topic | ❌ Missing | Messages can't be rate-paced or prioritized |
| `gossipValidatorFn.ts` — feeds ACCEPT/REJECT back to gossipsub | ❌ Missing | Gossipsub mesh doesn't benefit from validation |
| `aggregatorTracker.ts` — track aggregator duties | ❌ Missing | Duplicate aggregate detection incomplete |
| `attnetsService.ts` / `syncnetsService.ts` — long-lived vs short-lived rotation | ⚠️ Partial | `subnet_service.zig` handles short-lived; no random long-lived rotation |
| `network.ts` — event-driven network coordinator | ❌ Missing | No event system connecting gossip/reqresp to beacon node |
| `networkCoreWorker.ts` — worker thread isolation | N/A | Different architecture (Zig async vs JS workers) |
| `metadata.ts` — metadata seq bump + probing | ❌ Missing | Peers won't learn about our subnet changes |
| `forks.ts` — fork-aware gossip topic management | ❌ Missing | No re-subscribe on fork transitions |
| `ReqRespBeaconNode.ts` — outbound request API + timeout | ⚠️ Partial | `handleOutbound` exists but doesn't parse responses |
| `score.ts` + `constants.ts` — RealScore + PeerRpcScoreStore | ✅ Implemented | `peer_scoring.zig` + `peer_info.zig` cover this |
| `peerManager.ts` — heartbeat, status checks | ✅ Implemented | `peer_manager.zig` covers core logic |
| `discover.ts` — discv5 + subnet-targeted queries | ⚠️ Partial | Discovery service exists but subnet queries are stubs |
| `prioritizePeers.ts` — subnet-aware pruning | ✅ Implemented | `peer_prioritization.zig` faithfully ports the algorithm |
| `assertPeerRelevance.ts` — chain compatibility check | ✅ Implemented | `peer_relevance.zig` matches TS behavior |
| `rateLimit.ts` — per-peer req/resp rate limiting | ✅ Implemented | `rate_limiter.zig` goes beyond TS with global limits |
| `scoringParameters.ts` — gossipsub topic scores | ✅ Defined | `scoring_parameters.zig` has params but they're not wired |
| `statusCache.ts` — thread-safe status cache | ✅ Implemented | `status_cache.zig` with spin mutex |
| `dataColumnSidecarsByRange/Root` handlers | ✅ Implemented | Full PeerDAS req/resp support |
| Light client protocols | ⚠️ Stubs | Returns `ServerError("not yet implemented")` |

### Key missing behaviors

1. **No gossip → beacon node pipeline.** Messages get decoded and validated but there's no queue/callback to actually process them (import blocks, aggregate attestations, etc.).

2. **No outbound request API.** `handleOutbound` writes a request and reads a response but just logs the byte count. There's no way for sync or the beacon node to make a typed request (e.g., "get blocks 100-200 from peer X") and receive parsed responses.

3. **No gossipsub validation feedback loop.** `handleMessage` returns a `ValidationResult` but this is never fed back to the gossipsub router. Without this, the gossipsub mesh can't penalize peers who send invalid messages, which is critical for spam resistance.

4. **No fork transition gossip management.** When the chain forks (e.g., Deneb → Electra), gossip topic strings change (different fork digest). TS Lodestar unsubscribes old topics and subscribes new ones. Currently there's no mechanism for this.

5. **No metadata probing cycle.** TS Lodestar periodically pings peers for metadata updates to learn about subnet subscription changes. Without this, the node can't discover which subnets peers are on after initial connection.

---

## 3. Coherence

### 🔴 Two parallel peer management systems

There are **two independent systems** that track peers:

1. **`ConnectionManager`** (connection_manager.zig) — uses `PeerScorer` with numeric u64 IDs, tracks `PeerConnection` structs, does its own pruning.
2. **`PeerManager`** (peer_manager.zig) — uses `PeerDB` with string peer IDs, tracks `PeerInfo` structs, has its own heartbeat/pruning.

These don't interact. The `ConnectionManager` is legacy (predates the peer_manager rewrite) and should be removed. Currently both are exported from `root.zig`, which means a consumer could use either — or both, with conflicting state.

### 🔴 Two parallel scoring systems

1. **`PeerScorer`** (peer_scoring.zig, bottom) — numeric IDs, simple accept/reject/ignore weights, used by `ConnectionManager` and `EthGossipAdapter`.
2. **`PeerScoreService`** + **`PeerScore`** (peer_scoring.zig top + peer_info.zig) — string IDs, rich reject reasons, req/resp integration, gossipsub score combination, decay with halflife.

The `EthGossipAdapter` holds an optional `*PeerScorer` (the legacy one). The `PeerManager` uses the new system. These need to be unified — the new system is clearly superior.

### 🟡 Gossip flow is coherent but disconnected

The data flow is clean:
```
gossipsub event → EthGossipAdapter.handleMessage → snappy decompress →
  gossip_decoding.decodeGossipMessage → typed union →
  gossip_validation.validate* → ValidationResult
```

But this pipeline ends at `ValidationResult`. There's no:
- Callback to enqueue the decoded message for processing
- Feedback to gossipsub (reportMessageValidationResult)
- Score update for the originating peer (only a placeholder PeerScorer)

### 🟡 Req/resp inbound flow is coherent

```
stream read → EthReqRespAdapter.handleStream → parse protocol ID →
  decodeRequest (varint + snappy) → handleRequest (business logic) →
  ResponseChunk[] → encodeResponseChunk → write to stream
```

This works. The abstraction between encoding, handling, and transport is clean.

### 🟡 Req/resp outbound flow is incomplete

```
P2pService.newStream → Eth2Protocol.handleOutbound → encodeRequest →
  write to stream → read response → log byte count → done
```

The response bytes are read but never decoded or returned. There's no way for the caller to get typed response data back.

### 🟢 Discovery → PeerDB → PeerManager → Connection flow

The intended flow is clear:
```
DiscoveryService.discoverPeers → DiscoveredPeer queue →
  (caller drains) → PeerManager.onDialing → PeerDB.dialingPeer →
  (P2P layer dials) → PeerManager.onPeerConnected → PeerDB.peerConnected
```

This is well-designed. The PeerManager doesn't hold P2P handles — it returns `HeartbeatActions` for the caller to execute. Good separation.

---

## 4. Taste

### 🟢 Excellent test coverage

Nearly every module has thorough unit tests. The mock contexts are well-designed (e.g., `MockContext` in req_resp_handler, test helpers in gossip_validation). Roundtrip tests for wire encoding are particularly good. This is production-quality testing discipline.

### 🟢 Clean module boundaries

The separation between:
- Wire encoding (`req_resp_encoding.zig`) vs business logic (`req_resp_handler.zig`)
- Topic parsing (`gossip_topics.zig`) vs decoding (`gossip_decoding.zig`) vs validation (`gossip_validation.zig`)
- Peer data (`peer_info.zig`, `peer_db.zig`) vs peer policy (`peer_manager.zig`, `peer_prioritization.zig`)

...is well-executed. Each file has a clear, single responsibility.

### 🟢 Good doc comments

Almost every public function has a doc comment explaining what it does, its preconditions, and what the caller owns. The spec references (URLs to consensus-specs) are helpful.

### 🟡 Memory ownership could be clearer

Several functions return allocated slices where the caller must free (e.g., `getConnectedPeers`, `getPeersOnSubnet`, `getBestPeers`, `getExpiredBans`). This is idiomatic Zig, but an ArenaAllocator pattern for request processing would reduce the chance of leaks. Consider using `std.heap.ArenaAllocator` for per-request/per-heartbeat allocations.

### 🟡 PassthroughValidator self-referential pattern is fragile

```zig
pub fn init(allocator: Allocator) PassthroughValidator {
    return .{
        .seen_blocks = SeenSet.init(allocator),
        // ... ctx = undefined
    };
}
pub fn fixupPointers(self: *PassthroughValidator) void {
    self.ctx.seen_block_roots = &self.seen_blocks;  // points into self!
}
```

If the struct is moved between `init` and `fixupPointers` (e.g., assigned, returned by value, appended to a list), the pointers dangle. The comment warns about this, but it's a classic Zig foot-gun. Consider allocating SeenSets on the heap, or using `@ptrFromInt`/index-based references.

Same pattern in `NodeGossipContext`.

### 🟡 `connection_manager.zig` is dead weight

472 lines of code that duplicates `peer_manager.zig` functionality with an older, simpler model. It uses `PeerScorer` (numeric IDs) while the rest of the system uses string IDs. This creates confusion about which system to use. Should be removed or clearly marked as deprecated.

### 🟢 StatusCache spin mutex is appropriate

For a small struct that's read/written infrequently (once per slot), a spin mutex is fine. The copy-on-read pattern (returning a `CachedStatus` value, not a pointer) is correct.

### 🟡 Linux-specific time in `p2p_service.zig`

```zig
_ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
```

This won't compile on macOS or Windows. Use `std.time.nanoTimestamp()` or `std.time.milliTimestamp()` instead.

---

## 5. Integration

### 🔴 eth-p2p-z protocol handler interface assumptions

The `makeProtocolHandler` factory in `eth2_protocols.zig` generates handlers with:
- `pub fn handleInbound(self, io, stream, ctx) !void`
- `pub fn handleOutbound(self, io, stream, ctx) !void`

These assume `stream` has `.read(io, buf)` and `.write(io, data)` methods, and that `ctx` optionally has `ssz_payload`. Without seeing the actual eth-p2p-z `Switch` type constraints, I can't verify these match. If the Switch uses different method names or signatures, this will fail at comptime.

The `Io` type is `std.Io` which is Zig 0.14+ async I/O. Confirm eth-p2p-z also uses `std.Io`.

### 🟡 GossipsubService API assumptions

`EthGossipAdapter` calls:
- `gossipsub.subscribe(topic_str)` — passing an owned `[]const u8`
- `gossipsub.publish(topic_str, compressed)` — but this is called indirectly
- `gossipsub.drainEvents()` — returns `[]GossipsubEvent`

Verify these match the actual `zig-libp2p` gossipsub `Service` API. In particular, `drainEvents()` returning an allocator-owned slice with a `.message` variant containing `.topic` and `.data` fields.

### 🟡 Discv5 integration is surface-level

`DiscoveryService` wraps the discv5 `Protocol` but only does routing table lookups. Real discv5 peer discovery requires:
- Sending FINDNODE requests to known nodes
- Processing WHOAREYOU challenges
- TALKREQ/TALKRESP for application-specific queries

The current implementation seeds the routing table from bootnodes and does `findClosest` — this only finds peers already in the table. For actual peer discovery on a live network, you need the full FINDNODE recursion. The discv5 library likely handles this, but it's not clear the integration triggers it.

### 🟢 Comptime protocol composition is elegant

```zig
pub const Eth2Switch = swarm_mod.Switch(.{
    .transports = &.{QuicTransport},
    .protocols = &.{StatusProtocol, GoodbyeProtocol, ...},
});
```

The comptime Switch composition with 14 req/resp protocols + gossipsub + identify is clean. The `makeProtocolHandler` factory avoids repetitive code. The test verifying all IDs are unique is a good safety net.

---

## Prioritized Action Items

### Must Fix (blocks compilation or correctness)

1. **Fix duplicate switch prongs** in `protocol.zig` `hasMultipleResponses()`
2. **Fix publish signature mismatch** between `P2pService.publishGossip` and `EthGossipAdapter.publish`
3. **Fix MetadataProtocol version** — change to v2 (`/metadata/2/ssz_snappy`)
4. **Fix Linux-specific time** in `p2p_service.zig` heartbeat loop

### Should Fix (interop / correctness on mainnet)

5. **Fix fork digest computation** in `handleBeaconBlocksByRoot` / `handleBlobSidecarsByRoot` / `handleDataColumnSidecarsByRoot` — extract real slot from SSZ or return (bytes, slot) from context
6. **Remove hardcoded blob sidecar offsets** in `gossip_decoding.zig` — use proper SSZ deserialization or derived constants
7. **Consolidate peer management** — remove `ConnectionManager` or clearly deprecate it
8. **Consolidate scoring** — remove legacy `PeerScorer`, wire `PeerScoreService` into `EthGossipAdapter`

### Should Build (completeness for sync/gossip to work)

9. **Outbound request API** — `handleOutbound` must decode response and return typed data to caller
10. **Gossip validation feedback** — feed `ValidationResult` back to gossipsub router (`reportMessageValidationResult`)
11. **Gossip → beacon node pipeline** — callback or channel from validated gossip messages to the processing layer
12. **Fork transition gossip management** — re-subscribe topics on fork digest change
13. **Metadata probing cycle** — periodic Ping + Metadata requests to connected peers
14. **Discovery: real FINDNODE** — ensure discv5 integration triggers recursive lookup, not just table scan

### Nice to Have

15. Use `ArenaAllocator` for per-request allocations in heartbeat/handleRequest paths
16. Add gossipsub scoring parameter wiring (params defined in `scoring_parameters.zig` but not applied)
17. Implement subnet-targeted discovery queries (currently stubs)
18. Implement light client req/resp handlers
19. Add metrics (request latency, gossip processing time, peer churn rate)

---

## Architecture Assessment

The networking subsystem follows a **layered architecture** that maps well to the consensus spec:

```
┌─────────────────────────────────────────────────┐
│  BeaconNode (consumer)                          │
├─────────────────────────────────────────────────┤
│  P2pService          │  PeerManager             │
│  ├─ Eth2Switch       │  ├─ PeerDB               │
│  ├─ EthGossipAdapter │  ├─ PeerPrioritization   │
│  └─ GossipsubService │  ├─ PeerRelevance        │
├──────────────────────│  └─ PeerScoreService      │
│  14x Eth2Protocol    ├──────────────────────────┤
│  ├─ ReqRespAdapter   │  SubnetService            │
│  ├─ ReqRespHandler   │  ColumnSubnetService      │
│  └─ ReqRespEncoding  │  StatusCache              │
├──────────────────────│  RateLimiter              │
│  GossipDecoding      │  DiscoveryService         │
│  GossipValidation    ├──────────────────────────┤
│  GossipTopics        │  ConnectionManager (legacy)│
└─────────────────────────────────────────────────┘
```

The layering is clean. The main risk is that the **glue layer** connecting these components doesn't exist yet — the BeaconNode would need to:
1. Wire gossip events to processing queues
2. Wire req/resp responses to sync
3. Wire peer manager heartbeat to P2pService disconnect/dial
4. Wire discovery results to P2pService dial
5. Wire chain head updates to StatusCache + gossip topic management

This is normal for the current development stage — the pieces are here, the wiring is next.

---

*This review covers correctness, completeness, coherence, taste, and integration across all 29 files (12,807 lines) in `src/networking/`. Generated 2026-03-28.*
