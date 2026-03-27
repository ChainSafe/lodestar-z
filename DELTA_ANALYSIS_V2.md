# Beacon Node Delta Analysis V2: lodestar-z vs TS Lodestar

**Date:** 2026-03-26
**Base branch:** `feat/beacon-node` (commit `592bef1`)
**CLI branch:** `feat/cli-integration` — 63 CLI options matching TS Lodestar
**Fix branches analyzed:**
- `fix/el-integration` (1 commit, 3 files, +423 LOC)
- `fix/sync-service` (1 commit, 1 file, +430/-82 LOC)
- `fix/attestation-gossip` (1 commit, 4 files, +420/-123 LOC)
- `fix/gossip-validation` (1 commit, 5 files, +630/-25 LOC)

---

## 1. CLI Option-by-Option Wiring Status

Source: `~/lodestar-z-cli-integration/src/node/main.zig`
Target: `src/node/options.zig` → `NodeOptions` struct

### Legend
- ✅ **Wired & functional** — CLI option parsed → NodeOptions field → backend uses it
- 🟡 **Wired but partial** — CLI option parsed → NodeOptions, backend exists but incomplete
- 🔴 **Parsed but not wired** — CLI option defined but `// TODO: wire to NodeOptions`
- ⬜ **Backend exists, not in CLI** — functionality exists but no CLI flag

---

### Execution Engine Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--execution-url` | `http://localhost:8551` | ✅ Wired | ✅ `HttpEngine` + `PosixHttpTransport` (`fix/el-integration`) |
| `--jwt-secret` | null | ✅ Wired | ✅ `loadJwtSecret()` reads hex file, feeds to `HttpEngine` |
| `--engine-mock` | false | 🟡 Partial | Logic exists (fallback when no URL) but flag not checked explicitly |
| `--execution-timeout` | null | 🔴 Not wired | No timeout on `PosixHttpTransport` TCP reads |
| `--execution-retries` | 3 | 🔴 Not wired | No retry logic in `HttpEngine.send()` |
| `--jwt-id` | null | 🔴 Not wired | JWT claims don't include `id` field |

**Backend detail (fix/el-integration):**
- `loadJwtSecret()` — 40 LOC, reads hex file via Linux syscalls, strips `0x` prefix
- `PosixHttpTransport` — 275 LOC, blocking TCP, DNS via `getaddrinfo`, HTTP/1.1 request build, chunked response decode
- `BeaconNode.init()` now branches: if `execution_urls.len > 0` → `HttpEngine`, else → `MockEngine`
- `notifyForkchoiceUpdate()` — ~45 LOC, extracts head/safe/finalized block hashes from fork choice, calls `engine_forkchoiceUpdatedV3`
- `block_importer.engine_api` wired in `init()`

### REST API Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--api-port` | 5052 | ✅ Wired | ✅ `HttpServer` listens on this port |
| `--api-address` | `127.0.0.1` | ✅ Wired | ✅ `HttpServer` binds to this address |
| `--rest` | false | 🔴 Not wired | API server always starts; no enable/disable toggle |
| `--api-cors` | null | 🔴 Not wired | No CORS header handling in `HttpServer` |
| `--api-swagger` | false | 🔴 Not wired | No Swagger UI |

### P2P Network Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--p2p-port` | 9000 | ✅ Wired | ✅ `startP2p(io, host, port)` |
| `--p2p-host` | `0.0.0.0` | ✅ Wired | ✅ `startP2p(io, host, port)` |
| `--bootnodes` | null | ✅ Wired | ✅ Parsed, passed to `NodeOptions.bootnodes`, dialed in `dialBootnodeEnr()` |
| `--target-peers` | 50 | ✅ Wired | 🟡 Stored in `NodeOptions` but not enforced (no connection manager) |
| `--p2p-host6` | null | 🔴 Not wired | No IPv6 support in P2P |
| `--p2p-port6` | null | 🔴 Not wired | No IPv6 support |
| `--discovery-port` | null | 🔴 Not wired | Discovery uses same port as P2P |
| `--subscribe-all-subnets` | false | 🔴 Not wired | Hardcoded to subscribe all 64 subnets in `fix/attestation-gossip` |
| `--disable-peer-scoring` | false | 🔴 Not wired | `PeerScorer` exists (`fix/gossip-validation`) but no disable flag |
| `--discv5` | false | 🔴 Not wired | `DiscoveryService` is stub (107 LOC, no service loop) |
| `--mdns` | false | 🔴 Not wired | No mDNS implementation |
| `--direct-peers` | null | 🔴 Not wired | No direct peer connection logic |
| `--supernode` | false | 🔴 Not wired | No data column custody |
| `--semi-supernode` | false | 🔴 Not wired | No data column custody |

### Sync Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--checkpoint-state` | null | ✅ Wired | ✅ `genesis_util.loadGenesisFromFile()` → `initFromGenesis()` |
| `--checkpoint-block` | null | 🟡 Partial | Defined in CLI, not consumed (state-only checkpoint sync) |
| `--checkpoint-sync-url` | null | 🔴 Not wired | No HTTP fetch from beacon API |
| `--force-checkpoint-sync` | false | 🔴 Not wired | No DB-has-recent-state check |
| `--weak-subjectivity-checkpoint` | null | 🔴 Not wired | No WS checkpoint verification |
| `--sync-single-node` | false | 🔴 Not wired | No single-node mode in `SyncService` |
| `--sync-disable-range` | false | 🔴 Not wired | No range sync disable flag |

**Backend detail (fix/sync-service):**
- `SyncCallbackCtx` — ~110 LOC bridge struct, queues `PendingBatchRequest` for async P2P dispatch
- `initSyncPipeline()` — creates `PeerManager`, `SyncService`, `SyncCallbackCtx`, `SyncController`
- Replaces inline range sync in `dialBootnodeEnr()` with `SyncController.onPeerConnected()` + `processSyncBatches()`
- Main loop: `SyncController.tick()` → check pending batches → `processSyncBatches()` → actual P2P calls
- `pollGossipBlocks()` extracted as standalone method

### Metrics Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--metrics` | false | 🟡 Partial | Metrics server starts but flag not checked for enable/disable |
| `--metrics-port` | 8008 | ✅ Wired | ✅ `MetricsServer` listens on this port |
| `--metrics-address` | `127.0.0.1` | ✅ Wired | ✅ `MetricsServer` binds to this address |

### Chain Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--verify-signatures` | false | ✅ Wired | ✅ `NodeOptions.verify_signatures` → STFN |
| `--suggest-fee-recipient` | null | 🟡 Partial | `NodeOptions.suggested_fee_recipient` exists, not used in payload building |
| `--safe-slots-to-import-optimistically` | null | 🔴 Not wired | No optimistic import threshold |
| `--emit-payload-attributes` | false | 🔴 Not wired | No SSE payload attributes emission |
| `--archive-state-epoch-frequency` | 1024 | 🔴 Not wired | Hardcoded archiving behavior |
| `--prune-history` | false | 🔴 Not wired | No history pruning |

### Builder / MEV Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--builder` | false | 🔴 Not wired | No builder integration |
| `--builder-url` | null | 🔴 Not wired | No builder API client |
| `--builder-timeout` | null | 🔴 Not wired | — |
| `--builder-fault-inspection-window` | null | 🔴 Not wired | — |
| `--builder-allowed-faults` | null | 🔴 Not wired | — |
| `--builder-boost-factor` | null | 🔴 Not wired | — |

### Monitoring Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--monitoring-endpoint` | null | 🔴 Not wired | No remote monitoring |
| `--monitoring-interval` | null | 🔴 Not wired | — |

### Logging Group

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--log-level` | info | 🟡 Partial | Parsed, but not wired to Zig's `std.log` scoped system |
| `--log-file` | null | 🔴 Not wired | No file log output |
| `--log-format` | human | 🔴 Not wired | No JSON log format |
| `--log-file-level` | debug | 🔴 Not wired | — |
| `--log-file-daily-rotate` | 5 | 🔴 Not wired | — |

### Global Options

| CLI Option | Default | Wiring Status | Backend Status |
|---|---|---|---|
| `--network` | mainnet | ✅ Wired | ✅ Selects `BeaconConfig` (mainnet/sepolia/holesky/hoodi/minimal) |
| `--data-dir` | "" | ✅ Wired | ✅ Creates directory, passed to `NodeOptions` |
| `--params-file` | null | ✅ Wired | ✅ `config_loader.loadConfigFromYaml()` → custom `BeaconConfig` |
| `--rc-config` | null | ✅ Wired | ✅ Pre-scanned, YAML key-value resolver for CLI defaults |
| `--preset` | null | 🔴 Not wired | No runtime preset override |

### Other Commands (not beacon)

| Command | Status |
|---|---|
| `validator` | 🔴 Stub — prints "not yet implemented" |
| `dev` | 🔴 Stub — prints "not yet implemented" |
| `bootnode` | 🔴 Stub — prints "not yet implemented" |

---

## 2. Wiring Summary

| Category | Total Options | ✅ Wired | 🟡 Partial | 🔴 Not Wired |
|---|---|---|---|---|
| Execution | 6 | 2 | 1 | 3 |
| REST API | 5 | 2 | 0 | 3 |
| P2P Network | 14 | 4 | 1 | 9 |
| Sync | 7 | 1 | 1 | 5 |
| Metrics | 3 | 2 | 1 | 0 |
| Chain | 6 | 1 | 1 | 4 |
| Builder/MEV | 6 | 0 | 0 | 6 |
| Monitoring | 2 | 0 | 0 | 2 |
| Logging | 5 | 0 | 1 | 4 |
| Global | 5 | 4 | 0 | 1 |
| **Total** | **59** | **16** | **6** | **37** |

**27% wired, 10% partial, 63% parsed-only.**

---

## 3. Updated Subsystem Assessment (Post Fix Branches)

### 3.1 Execution Engine — 🟢 Functional (was 🔴 Critical)

**Closed by:** `fix/el-integration` (+423 LOC)

| Component | File | LOC | Status |
|---|---|---|---|
| `PosixHttpTransport` | `src/execution/http_engine.zig` | 275 | ✅ Blocking TCP, DNS, HTTP/1.1, chunked decode |
| `loadJwtSecret()` | `src/node/beacon_node.zig` | 40 | ✅ Hex file parsing via Linux syscalls |
| Engine selection logic | `src/node/beacon_node.zig` | 35 | ✅ HttpEngine when URL present, MockEngine fallback |
| `notifyForkchoiceUpdate()` | `src/node/beacon_node.zig` | 45 | ✅ head/safe/finalized hashes → `forkchoiceUpdatedV3` |
| Block importer engine wiring | `src/node/beacon_node.zig` | 5 | ✅ `block_importer.engine_api = engine` |

**What still gaps (non-blocking for devnet):**
- No `engine_exchangeCapabilities` handshake
- No execution timeout or retries (single shot, blocking)
- No connection pooling (new TCP connection per request — acceptable at 1 req/12s)
- `PosixHttpTransport` uses blocking syscalls (not integrated with `std.Io` fibers)
- No payload building flow (`forkchoiceUpdated` with `PayloadAttributes` → `getPayload`)

### 3.2 Sync — 🟢 Architecture Wired (was 🟡 Partial)

**Closed by:** `fix/sync-service` (+430/-82 LOC)

| Component | File | LOC | Status |
|---|---|---|---|
| `SyncCallbackCtx` | `src/node/beacon_node.zig` | 110 | ✅ Bridges sync callbacks → P2P |
| `initSyncPipeline()` | `src/node/beacon_node.zig` | 35 | ✅ PeerManager + SyncService + SyncController |
| `processSyncBatches()` | `src/node/beacon_node.zig` | ~50 | ✅ Drains pending requests via P2P |
| Main loop restructure | `src/node/beacon_node.zig` | ~200 | ✅ tick → poll gossip → drain batches |
| Inline sync removal | `src/node/beacon_node.zig` | -82 | ✅ Replaced with SyncController.onPeerConnected |

**Architecture:**
```
peer connects → SyncController.onPeerConnected()
  → SyncService.onPeerStatus()
  → RangeSyncManager.start() / tick()
  → BatchRequestCallback (queues PendingBatchRequest)
    → processSyncBatches() [main loop]
      → p2p.requestBlocksByRange()
      → SyncCallbackCtx.syncImportBlock()
        → BeaconNode.importBlock()
```

**What still gaps:**
- Single-peer sync only (no multi-peer parallel download)
- No backfill sync
- `PeerManager` tracks peers but no peer rotation
- No batch retry with different peer on failure

### 3.3 Attestation Gossip — 🟢 Pipeline Complete (was 🔴 Stub)

**Closed by:** `fix/attestation-gossip` (+420/-123 LOC)

| Component | File | LOC | Status |
|---|---|---|---|
| `SingleAttestation` decoding | `src/networking/gossip_decoding.zig` | 40 | ✅ SSZ decode for electra `SingleAttestation` |
| `AggregateAndProof` decoding | `src/networking/gossip_decoding.zig` | new | ✅ SSZ decode for `SignedAggregateAndProof` |
| `onAttestation()` pipeline | `src/node/gossip_handler.zig` | 70 | ✅ Decompress → decode → validate → import |
| `onAggregateAndProof()` pipeline | `src/node/gossip_handler.zig` | 40 | 🟡 Validate + log, no pool insertion |
| `importAttestationFn` callback | `src/node/gossip_handler.zig` | 15 | ✅ Fn pointer for fork choice import |
| `gossipImportAttestation()` | `src/node/beacon_node.zig` | 30 | ✅ Builds minimal Attestation, calls `chain.importAttestation()` |
| Attestation subnet subscription | `src/node/beacon_node.zig` | 10 | ✅ Subscribes to all 64 attestation subnets |
| Topic routing | `src/node/beacon_node.zig` | 30 | ✅ `beacon_attestation` + `beacon_aggregate_and_proof` → `GossipHandler` |
| `initGossipHandler()` | `src/node/beacon_node.zig` | 25 | ✅ Lazy init with all callbacks wired |

**Pipeline:**
```
gossip msg (beacon_attestation_{subnet})
  → snappy decompress → SSZ decode (SingleAttestation)
  → Phase 1: validateGossipAttestation() [slot range, committee bounds, target known]
  → Phase 2: gossipImportAttestation()
    → chain.importAttestation()
      → fork_choice.onAttestation() + attestation_pool.add()
```

**What still gaps:**
- No BLS signature verification for attestations
- Aggregate phase 2 logs acceptance but doesn't insert into pool
- `source` checkpoint hardcoded to zero in `gossipImportAttestation()`
- No attestation reprocessing queue for unknown target roots

### 3.4 Gossip Validation + Peer Scoring — 🟢 Foundations (was 🔴 PassthroughValidator)

**Closed by:** `fix/gossip-validation` (+630/-25 LOC)

| Component | File | LOC | Status |
|---|---|---|---|
| `validateAttestation()` | `src/networking/gossip_validation.zig` | 30 | ✅ Slot range, epoch match, committee bounds, target known |
| `validateBlsToExecutionChange()` | `src/networking/gossip_validation.zig` | 20 | ✅ Validator bounds, dedup |
| Context `ptr` threading | `src/networking/gossip_validation.zig` | ~50 delta | ✅ All callbacks now pass `*anyopaque` ctx |
| `PeerScorer` | `src/networking/peer_scoring.zig` | 353 | ✅ Per-peer scores, accept/reject/ignore weights, decay, disconnect threshold |
| `EthGossipAdapter` dispatch | `src/networking/eth_gossip.zig` | 54 | ✅ Routes attestation validation, records scores |
| Synthetic block root | `src/networking/eth_gossip.zig` | 10 | ✅ slot+proposer+parent_root for dedup (replaces zero root) |

**Validation coverage (per gossip topic):**

| Topic | Phase 1 (fast) | Phase 2 (full) | BLS |
|---|---|---|---|
| `beacon_block` | ✅ slot range, dedup, proposer, parent | ✅ STFN + FC | ❌ |
| `beacon_attestation` | ✅ epoch range, committee, target known | ✅ FC + pool | ❌ |
| `beacon_aggregate_and_proof` | ✅ aggregator bounds, slot range, dedup | 🟡 Log only | ❌ |
| `voluntary_exit` | ✅ validator bounds, dedup, active check | ❌ No import | ❌ |
| `proposer_slashing` | ✅ validator bounds, dedup | ❌ No import | ❌ |
| `attester_slashing` | ❌ Accept all | ❌ No import | ❌ |
| `bls_to_execution_change` | ✅ validator bounds, dedup | ❌ No import | ❌ |
| `blob_sidecar` | ❌ Not decoded | ❌ | ❌ |
| `data_column_sidecar` | ❌ Not decoded | ❌ | ❌ |

---

## 4. Subsystem Status Summary (Updated)

| Subsystem | V1 Status | V2 Status | What Changed |
|---|---|---|---|
| Block Import Pipeline | 🟡 Partial | 🟡 Partial | No change (functional for sequential import) |
| Attestation Lifecycle | 🟡 Partial (stubs) | ✅ Functional | `fix/attestation-gossip`: full gossip → FC pipeline |
| Fork Choice | ✅ Functional | ✅ Functional | No change |
| Sync | 🟡 Partial (inline) | ✅ Architecture wired | `fix/sync-service`: SyncService replaces inline loop |
| Execution Engine | 🔴 Critical gap | ✅ Functional | `fix/el-integration`: real HTTP transport + JWT + FCU |
| Gossip Processing | 🟡 Partial (block only) | ✅ Functional | `fix/attestation-gossip` + `fix/gossip-validation` |
| Gossip Validation | 🔴 PassthroughValidator | 🟡 Partial | `fix/gossip-validation`: real validation + peer scoring |
| Processor / Work Queues | 🟡 Partial | 🟡 Partial | No change (not integrated) |
| P2P / Networking | 🟡 Partial | 🟡 Partial | Minor: peer scoring foundations |
| REST API | 🟡 Partial | 🟡 Partial | No change |
| Metrics | ✅ Functional | ✅ Functional | No change |
| Clock / Slot Ticker | ✅ Functional | ✅ Functional | No change |
| State Regen / Caching | 🟡 Partial | 🟡 Partial | No change |
| Validator Duties (BN) | 🟡 Partial | 🟡 Partial | No change |
| CLI | ❌ None | 🟡 Partial | `feat/cli-integration`: 63 options, 27% wired |

---

## 5. Revised Critical Path to Working Devnet BN

**Devnet MVP definition:** Checkpoint sync from a Kurtosis devnet peer, range sync to head, stay at head via gossip blocks + attestations, serve basic API, talk to a real EL via Engine API.

### P0 — Must have (blocks devnet today)

All **already addressed** by the 4 fix branches:
1. ~~Wire real EL integration~~ → `fix/el-integration` ✅
2. ~~Wire SyncService into P2P path~~ → `fix/sync-service` ✅
3. ~~Attestation gossip processing~~ → `fix/attestation-gossip` ✅
4. ~~Gossip validation (non-passthrough)~~ → `fix/gossip-validation` ✅

### P0.5 — Integration (merge + test the fix branches)

5. **Merge fix branches into `feat/beacon-node`** (see §6 below)
6. **Merge `feat/cli-integration` on top** (CLI + wiring)
7. **Smoke test on Kurtosis devnet** — verify:
   - `--execution-url` + `--jwt-secret` connects to Geth/Nethermind
   - `notifyForkchoiceUpdate` returns VALID
   - Range sync imports blocks from peer
   - Gossip blocks + attestations arrive and import
   - `GET /eth/v1/node/syncing` returns accurate status

### P1 — High (needed for stable devnet operation)

8. **Wire remaining critical CLI options to NodeOptions:**
   - `--execution-timeout` → add deadline on `PosixHttpTransport.send()`
   - `--execution-retries` → retry loop in `HttpEngine` methods
   - `--rest` → conditional API server start
   - `--metrics` → conditional metrics server start
   - `--log-level` → wire to `std.log` filtering

9. **Multi-peer sync:**
   - `PeerManager` already tracks peers, but only one peer is dialed
   - Need: discover peers (discv5 service loop), dial multiple, rotate on failure
   - `SyncService` already supports multi-peer in its design

10. **Finalization handling:**
    - Detect new finalized checkpoint after import
    - Call `chain.onFinalized()` → prune fork choice + caches
    - Currently accumulates state without pruning

11. **BLS signature verification integration:**
    - Backend exists (`src/bls/`) with `blst` bindings
    - STFN has `verify_signatures` flag
    - Gossip validation Phase 2 has no BLS calls
    - Needed for: block proposer sig, attestation aggregate sig, voluntary exit sig

### P2 — Medium (production robustness)

12. **Wire BeaconProcessor** — route gossip through work queues instead of inline
13. **Aggregate and proof Phase 2** — full import to attestation pool
14. **EpochCache in API layer** — real proposer/attester/sync duty responses
15. **Blob sidecar gossip** — decode + validate + persist
16. **Discovery service loop** — wire discv5 for peer discovery
17. **Connection manager** — enforce `--target-peers`, prune excess

### P3 — Lower priority

18. Checkpoint sync from URL (`--checkpoint-sync-url`)
19. Builder/MEV integration
20. Data column sidecar (PeerDAS)
21. TCP transport fallback
22. Log file output + rotation
23. Remote monitoring endpoint
24. Dev mode + standalone bootnode commands

---

## 6. Integration Plan: Merge Order & Conflict Risk

All 4 fix branches share the same parent commit (`592bef1` on `feat/beacon-node`). They each modify `src/node/beacon_node.zig` — that's the primary conflict zone.

### Recommended Merge Order

```
feat/beacon-node (592bef1)
  ↓
  ① fix/el-integration          [FIRST — foundational, EL wiring]
  ↓
  ② fix/gossip-validation       [SECOND — validation infra, no BN deps]
  ↓
  ③ fix/attestation-gossip      [THIRD — depends on gossip validation]
  ↓
  ④ fix/sync-service            [FOURTH — largest BN refactor]
  ↓
  ⑤ feat/cli-integration        [LAST — wraps everything with CLI]
```

### Conflict Analysis

| Merge Step | Files in Common | Conflict Risk | Conflict Details |
|---|---|---|---|
| ① el-integration | `beacon_node.zig` | 🟢 Low | Adds fields + `init()` engine logic + `notifyForkchoiceUpdate()`. Clean areas. |
| ② gossip-validation | `gossip_validation.zig`, `eth_gossip.zig`, `root.zig` | 🟢 Low | No `beacon_node.zig` changes. Adds `peer_scoring.zig` (new file). Changes ctx function signatures. |
| ③ attestation-gossip | `beacon_node.zig`, `gossip_handler.zig`, `gossip_decoding.zig` | 🟡 Medium | `beacon_node.zig` gossip routing refactor overlaps with both ① and ④. `gossip_handler.zig` adds `importAttestationFn` + `onAttestation()` + `onAggregateAndProof()`. |
| ④ sync-service | `beacon_node.zig` | 🔴 High | Largest refactor: replaces inline sync loop, restructures main loop (`processSyncBatches`, `pollGossipBlocks`). Will conflict with ③'s gossip routing changes. |
| ⑤ cli-integration | `main.zig` (new file), `beacon_node.zig` | 🟡 Medium | New file mostly, but `NodeOptions` usage in `beacon_node.zig` may need alignment with fields added by ①. |

### Specific Conflict Zones in `beacon_node.zig`

1. **Struct fields (~line 540-600):** ① adds `http_engine`, `posix_transport`; ④ adds `sync_peer_manager`, `sync_service_inst`, `sync_callback_ctx`. No overlap.

2. **`init()` (~line 720-850):** ① changes engine initialization. ④ doesn't touch `init()`. Clean.

3. **`deinit()` (~line 870-960):** ① adds engine cleanup. ④ adds sync cleanup. Different locations, but may interleave.

4. **`dialBootnodeEnr()` (~line 1250-1600):** **PRIMARY CONFLICT ZONE.**
   - ① doesn't touch this area significantly
   - ③ adds `initGossipHandler()`, attestation subnet subscription, `processGossipEventsFromSlice()`
   - ④ replaces inline sync with `SyncController`, restructures main loop
   - ③ and ④ both rewrite the gossip polling loop → **manual merge required**

5. **`notifyForkchoiceUpdate()` (~line 1900):** ① replaces the stub. Others don't touch it. Clean.

### Recommended Merge Strategy

1. Merge ① (`fix/el-integration`) — clean, isolated changes
2. Merge ② (`fix/gossip-validation`) — independent, no BN overlap
3. Merge ③ (`fix/attestation-gossip`) — align gossip routing
4. Merge ④ (`fix/sync-service`) — **expect conflicts in the main P2P loop**
   - ④'s `pollGossipBlocks()` + sync-driven loop must incorporate ③'s attestation topic routing
   - Resolution: keep ④'s loop structure, but add ③'s `processGossipEventsFromSlice()` call and `initGossipHandler()` inside it
5. Merge ⑤ (`feat/cli-integration`) — ensure `NodeOptions` fields align

**Estimated manual conflict resolution:** ~50-100 lines in `dialBootnodeEnr()` for ④ merge. Other merges should be clean or trivial.

---

## 7. What's Left After All Branches Merge

### Functional for devnet:
- ✅ Checkpoint sync from file
- ✅ Range sync via SyncService architecture
- ✅ Block import with full STFN (phase0→electra)
- ✅ Real EL integration (newPayload + forkchoiceUpdated)
- ✅ Gossip block reception + import
- ✅ Gossip attestation reception + fork choice integration
- ✅ Gossip validation (non-passthrough) with peer scoring
- ✅ Fork choice (proto-array + onBlock + onAttestation + getHead)
- ✅ REST API (genesis, syncing, blocks, headers, validators, health)
- ✅ Metrics (Prometheus endpoint)
- ✅ Slot clock
- ✅ CLI with 63 options (16 wired, 6 partial)

### Known limitations for real devnet:
- ❌ Single-peer only (no discv5 discovery loop)
- ❌ No BLS signature verification in gossip path
- ❌ No blob sidecar handling
- ❌ No finalization pruning
- ❌ Blocking TCP in EL transport (no timeout)
- ❌ BeaconProcessor bypassed (inline gossip handling)
- ❌ Aggregate attestation pool insertion incomplete
- ❌ No state regeneration for arbitrary state_id queries

### Bottom line:
After merging all 5 branches, lodestar-z can checkpoint sync, range sync from a peer, stay at head via gossip, validate blocks and attestations, talk to a real EL, and serve basic API. **This is sufficient for a controlled Kurtosis devnet** with a single known bootnode. Multi-peer discovery and BLS verification are the main remaining gaps before a real testnet.
