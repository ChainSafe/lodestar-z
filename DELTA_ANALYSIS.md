# Beacon Node Delta Analysis: lodestar-z vs TS Lodestar

**Date:** 2026-03-26
**Branch:** `feat/beacon-node` (commit `592bef1`)
**Total BN-related LOC:** ~15,700 (node + chain + fork_choice + execution + sync + processor + api + networking)
**Total codebase LOC:** ~80,600

---

## 1. Block Import Pipeline

**Status:** 🟡 Partial (functional for sequential import, missing batch/parallel)

### What exists:
- **`src/node/beacon_node.zig`** (2,675 LOC) — `BlockImporter` struct with full `importBlock()`:
  - Stage 1: `verifySanity()` — slot bounds, parent known, not finalized, not duplicate
  - Stage 2: `runStateTransition()` — `processSlots` + `processBlock` via STFN (all forks phase0→electra)
  - Stage 2b: `verifyExecutionPayload()` — calls `engine_newPayloadV3` via EngineApi vtable
  - Stage 3: Cache post-state, persist block to DB, checkpoint caching at epoch boundaries
  - Stage 4: Head tracking + fork choice `onBlock()` with full `ProtoBlock` metadata
  - State root verification (log mismatch/match)
  - Metrics updates (block_import_seconds, head_slot, finalized_epoch)
  - API context updates
  - State archiving at epoch boundaries
- **`src/chain/chain.zig`** (604 LOC) — `Chain` struct with identical `importBlock()` pipeline + SSE event emission
- **`src/chain/block_import.zig`** (212 LOC) — `HeadTracker`, `ImportResult`, `ImportError`, `verifySanity()`

### What's missing vs TS Lodestar:
- **No batch block processing** — TS has `verifyBlocksInEpoch()` batching multiple blocks per epoch for BLS batch verify
- **No pre-merge fork handling** — hardcoded to electra block type (fulu treated as electra)
- **No data availability sampling (DAS)** — `data_availability_status` hardcoded to `.available`
- **No proposer boost integration** in import path (fork choice has `setProposerBoost` but import doesn't call it)
- **No reorg detection** — TS emits `chain_reorg` events and tracks old/new head
- **Duplicate importBlock code** — exists in both `BlockImporter` (beacon_node.zig) and `Chain` (chain.zig)

**Priority for BN MVP:** ✅ **Already functional** — blocks import end-to-end with STFN + FC

---

## 2. Attestation Lifecycle

**Status:** 🟡 Partial (pool + gossip validation exist, integration path stubbed)

### What exists:
- **`src/chain/op_pool.zig`** (648 LOC) — `AttestationPool` with:
  - `add()` — groups by `AttestationData` hash
  - `getForBlock()` — selects best attestations up to `MAX_ATTESTATIONS`, sorted by group size
  - `prune()` — slot-based cleanup
- **`src/chain/gossip_validation.zig`** (405 LOC) — Phase 1 fast checks:
  - `validateGossipBlock()` — slot range, dedup, proposer check, parent known
  - `validateGossipAttestation()` — epoch range, target epoch match, committee bounds, target root known
  - `validateGossipAggregate()` — aggregator bounds, epoch range, non-empty bits, dedup
- **`src/chain/chain.zig`** — `importAttestation()` function that calls `fc.onAttestation()` + pool add
- **`src/chain/seen_cache.zig`** (256 LOC) — dedup for blocks, aggregators, exits, slashings, BLS changes

### What's missing:
- **No gossip attestation decoding** — `onAttestation()` in GossipHandler is a no-op stub: `// TODO: implement once gossip_decoding supports beacon_attestation`
- **No BLS signature verification** for attestations (neither individual nor batch)
- **No committee subnet routing** — attestation subnets not subscribed/routed
- **No aggregate and proof processing** — gossip path is stub
- **No attestation reprocessing queue** — when target root unknown, TS queues for retry
- **No SingleAttestation (Electra) handling** in gossip path

**Priority for BN MVP:** 🟡 **Medium** — needed for staying at head via gossip (fork choice weight), but range sync works without it

---

## 3. Fork Choice

**Status:** ✅ Functional

### What exists:
- **`src/fork_choice/fork_choice.zig`** (815 LOC) — `ForkChoice` struct:
  - `init()`, `deinit()`, `onBlock()`, `onAttestation()`, `getHead()`
  - `setProposerBoost()`, `clearProposerBoost()`, `onAttesterSlashing()`
  - `updateTime()`, `updateJustifiedCheckpoint()`, `updateFinalizedCheckpoint()`
  - `prune()`, `hasBlock()`, `getBlock()`, `isDescendant()`
  - `onExecutionPayload()`, `notifyPtcMessages()` (ePBS/Gloas)
- **`src/fork_choice/proto_array.zig`** (4,567 LOC) — full proto-array DAG:
  - `onBlock()`, `applyScoreChanges()`, `findHead()`
  - Execution payload status tracking (valid/syncing/invalid)
  - Data availability status
  - ePBS/Gloas payload timeliness, variant indices
  - `isFinalizedRootOrDescendant()`
- **`src/fork_choice/compute_deltas.zig`** (319 LOC) — delta computation with equivocation support
- **`src/fork_choice/vote_tracker.zig`** (162 LOC) — per-validator vote tracking
- **`src/fork_choice/store.zig`** (367 LOC) — fork choice store types

### What's missing vs TS Lodestar:
- **No unrealized justification** (checkpoints are just epoch+root, not tracked separately from realized)
  - Actually: `unrealized_justified_epoch/root` fields ARE present in ProtoBlock, populated in import path
- **No `applyFinalityUpdate()`** — TS has a separate finality re-evaluation after reorgs
- **No safe_slot computation** — needed for EL forkchoiceUpdated safe_block_hash

**Priority for BN MVP:** ✅ **Already functional** — full proto-array with onBlock + onAttestation + getHead

---

## 4. Sync

**Status:** 🟡 Partial (range sync functional in-band, sync service exists)

### What exists:
- **`src/sync/sync_service.zig`** (294 LOC) — `SyncService`:
  - State machine: idle → range_sync → synced
  - `onPeerStatus()`, `onPeerDisconnect()`, `tick()`, `isSynced()`, `getSyncStatus()`
  - Evaluates sync mode based on peer head vs local head
- **`src/sync/range_sync.zig`** (803 LOC) — `RangeSyncManager`:
  - Batch-based range sync with configurable batch size (64 slots)
  - `start()`, `tick()`, `onBatchResponse()`, `onBatchError()`
  - Pending batch tracking, retry logic
  - `BlockImporterCallback` + `BatchRequestCallback` vtables
- **`src/sync/peer_manager.zig`** (237 LOC) — `PeerManager`:
  - Status tracking, `getBestPeers()`, `getHighestPeerSlot()`
- **`src/sync/unknown_block_sync.zig`** (305 LOC) — `UnknownBlockSync`:
  - Pending block queue (keyed by parent_root)
  - `addPendingBlock()`, `onParentImported()` (returns children to retry)
  - Max attempts, max pending blocks, bad root tracking
- **`src/sync/checkpoint_sync.zig`** (194 LOC) — `CheckpointSync`:
  - `syncFromCheckpoint()` — validate + persist state + block
  - SHA-256 root verification
- **`src/node/sync_controller.zig`** (321 LOC) — `SyncController`:
  - Glue between P2P and sync pipeline
  - `onPeerConnected()`, `onPeerDisconnected()`, `tick()`, `onBlocksReceived()`
- **`src/node/beacon_node.zig`** — inline range sync in `dialBootnodeEnr()`:
  - Status exchange → range sync loop (requestBlocksByRange, 64 blocks/batch)
  - Gossip block polling loop with orphan detection + pending child processing

### What's missing vs TS Lodestar:
- **No finalized chain sync** — TS downloads finalized chain optimistically, then verifies
- **No backfill sync** — TS syncs backwards from checkpoint to genesis for historical data
- **No column-based sync** (PeerDAS) — fulu data columns
- **No rate limiting / peer scoring** — peers can flood us
- **Inline sync loop** in `dialBootnodeEnr` is a single-peer blocking loop (not the SyncService)
  - The SyncService + RangeSyncManager architecture exists but isn't used in the actual P2P path yet
- **No multi-peer parallel download** — only one peer at a time

**Priority for BN MVP:** ✅ **Functional for MVP** — single-peer range sync works, but needs SyncService integration for robustness

---

## 5. Execution Engine

**Status:** 🟡 Partial (vtable + mock + HTTP engine exist, forkchoiceUpdated stubbed)

### What exists:
- **`src/execution/engine_api.zig`** (97 LOC) — `EngineApi` vtable interface:
  - `newPayload()`, `forkchoiceUpdated()`, `getPayload()`
- **`src/execution/engine_api_types.zig`** (156 LOC) — complete Engine API types:
  - `ExecutionPayloadV3`, `PayloadStatusV1`, `ForkchoiceStateV1`
  - `PayloadAttributesV3`, `ForkchoiceUpdatedResponse`, `GetPayloadResponse`
  - `BlobsBundle`, `Withdrawal`
- **`src/execution/mock_engine.zig`** (329 LOC) — `MockEngine`:
  - Configurable newPayload responses (per-hash overrides)
  - forkchoiceUpdated tracking, payload building simulation
  - getPayload with stored payloads
- **`src/execution/http_engine.zig`** (1,085 LOC) — `HttpEngine`:
  - Full JWT HS256 authentication
  - JSON-RPC 2.0 encoding/decoding
  - Pluggable HTTP transport (real + mock for testing)
  - `newPayloadV3`, `forkchoiceUpdatedV3`, `getPayloadV3` JSON serialization
- **`src/execution/json_rpc.zig`** (219 LOC) — JSON-RPC request/response encoding

### What's missing:
- **`notifyForkchoiceUpdate()` is a stub** in BeaconNode — the import pipeline calls it but it's a no-op: `// TODO: Re-enable when execution module is wired.`
- **No real HTTP transport** — HttpEngine has the `Transport` trait but no production HTTP client plugged in
- **No JWT secret file loading** — `NodeOptions` has `jwt_secret_path` field but it's never read
- **No engine_exchangeCapabilities** — needed for capability negotiation
- **No payload building flow** — `forkchoiceUpdated` with `PayloadAttributes` → `getPayload` not wired
- **MockEngine is default** — `BeaconNode.init()` always creates MockEngine regardless of `execution_urls`

**Priority for BN MVP:** 🔴 **High** — need real EL integration. Currently runs with mock engine (all payloads → valid).

---

## 6. Gossip Validation & Processing

**Status:** 🟡 Partial (block gossip works, attestation/other topics stubbed)

### What exists:
- **`src/node/gossip_handler.zig`** (358 LOC) — `GossipHandler`:
  - Two-phase model (Phase 1 fast validation → Phase 2 full import)
  - `onBeaconBlock()` — decompress + decode + validate + import
  - `onAttestation()` — no-op stub
  - `onGossipMessage()` — routes by topic type (only beacon_block implemented)
- **`src/networking/gossip_decoding.zig`** (309 LOC):
  - `decompressGossipPayload()` — snappy frame decompression
  - `decodeGossipMessage()` — SSZ decode for `beacon_block` topic
- **`src/networking/gossip_validation.zig`** (818 LOC):
  - `NodeGossipContext` wrapping BeaconNode for real gossip validation
- **`src/node/gossip_callbacks.zig`** (141 LOC):
  - Real `getProposerIndex()`, `isKnownBlockRoot()`, `isValidatorActive()`, `getValidatorCount()`
- **`src/networking/gossip_topics.zig`** (325 LOC) — topic string generation per fork digest
- **Inline gossip processing** in `beacon_node.zig` `dialBootnodeEnr()`:
  - Polls gossipsub events, decompresses, deserializes, imports blocks
  - Orphan block queuing + pending child processing

### What's missing:
- **No attestation gossip processing** — the biggest gap for staying at head
- **No aggregate_and_proof processing**
- **No voluntary_exit, proposer_slashing, attester_slashing, bls_to_execution_change** gossip
- **No blob_sidecar gossip** — blobs from gossip not processed
- **No data_column_sidecar gossip** (PeerDAS)
- **No subnet subscription management** — not subscribing to attestation subnets
- **No gossip scoring / peer penalization** for REJECT

**Priority for BN MVP:** 🟡 **Medium-High** — block gossip works; attestation gossip needed for fork choice accuracy at head

---

## 7. Processor / Work Queues

**Status:** 🟡 Partial (architecture exists, not wired in)

### What exists:
- **`src/processor/work_item.zig`** (454 LOC) — `WorkItem` tagged union with 20+ types:
  - `gossip_block`, `gossip_blob`, `gossip_column`, `gossip_attestation_batch`
  - `gossip_aggregate_batch`, `gossip_voluntary_exit`, `gossip_proposer_slashing`
  - `gossip_attester_slashing`, `gossip_bls_change`, `api_block`
  - `slot_clock_tick`, `unknown_block_parent`, `fc_update_head`
  - `fc_process_attestations`, `fc_maybe_set_optimistic`, `reprocess_attestation`
  - `finalized_block_import`, `checkpoint_state_archive`
- **`src/processor/work_queues.zig`** (812 LOC) — `WorkQueues`:
  - 20+ per-type priority queues with configurable max size
  - Priority-based pop (`popHighestPriority`)
  - Sync-state-aware skip logic
- **`src/processor/processor.zig`** (384 LOC) — `BeaconProcessor`:
  - `create()`, `processItem()`, `run()` (main loop), `submit()`
  - Metrics collection per work type
  - Handler dispatch via function pointer
- **`src/processor/queues.zig`** (410 LOC) — generic `FifoQueue` and `LifoQueue`

### What's missing:
- **Not integrated** — BeaconNode's gossip processing bypasses the processor entirely (direct import in gossip poll loop)
- **No handler implementations** — the `HandlerFn` is a function pointer but no actual handlers are wired
- **No worker pool** — single-threaded inline dispatch (comment: "Worker pool integration comes later")
- **No channel/submit integration** with P2P layer

**Priority for BN MVP:** 🟢 **Low** — direct import works for MVP, processor needed for production throughput

---

## 8. P2P / Networking

**Status:** 🟡 Partial (QUIC transport + gossipsub + req/resp work, limited discovery)

### What exists:
- **`src/networking/p2p_service.zig`** (379 LOC) — `P2pService`:
  - QUIC transport via eth-p2p-z (lsquic)
  - `init()`, `start()`, `dial()`, `dialProtocol()`, `publishGossip()`
  - `subscribeSubnet()`, `startHeartbeat()`
  - Ed25519 host key generation
  - GossipSub integration with configurable mesh params (D=8, D_lo=6, D_hi=12)
- **`src/networking/req_resp_handler.zig`** (870 LOC) — `handleRequest()`:
  - Status, Ping, Metadata, Goodbye
  - BeaconBlocksByRoot, BeaconBlocksByRange
  - BlobSidecarsByRoot, BlobSidecarsByRange
  - Response chunk encoding with context bytes
- **`src/networking/req_resp_encoding.zig`** (489 LOC):
  - Wire encoding: varint length prefix + snappy compression
  - `encodeRequest()`, `decodeResponseChunk()`
- **`src/networking/messages.zig`** (137 LOC) — SSZ message types (Status, Metadata, Ping, etc.)
- **`src/networking/eth2_protocols.zig`** (326 LOC) — protocol ID strings
- **`src/networking/gossip_topics.zig`** (325 LOC) — topic string generation per fork
- **`src/discv5/`** (3,217 LOC) — discv5 implementation:
  - ENR encode/decode, RLP, kbucket, session crypto
  - Protocol messages (FINDNODE, NODES, PING, PONG)
  - secp256k1 via BoringSSL

### What's missing:
- **No discv5 service loop** — discv5 library exists but `DiscoveryService` (107 LOC) has stubs only
- **No peer management** at P2P level — no connect/disconnect lifecycle, no scoring
- **No TCP transport** — QUIC only (fine for modern clients, but TCP fallback is spec-required)
- **No noise protocol** — QUIC TLS handles encryption, but TCP would need noise
- **No ENR management** — node doesn't publish its own ENR
- **No gossipsub message validation callback** — uses `PassthroughValidator` (accepts everything)
- **No attestation subnet subscription** — only global topics subscribed
- **Single-peer sync** — dialBootnodeEnr connects to exactly one bootnode
- **No peer rotation / connection management** — no max peers, no pruning

**Priority for BN MVP:** 🟡 **Medium** — QUIC + single bootnode works for devnet, needs multi-peer for real networks

---

## 9. REST API

**Status:** 🟡 Partial (core endpoints implemented, many stubs)

### What exists:
- **`src/api/http_server.zig`** (657 LOC) — `HttpServer`:
  - Full HTTP/1.1 request parsing and response writing
  - Path-based routing with parameter extraction
  - JSON response serialization
  - SSZ response support (content negotiation)
- **`src/api/routes.zig`** (365 LOC) — 22 route definitions covering:
  - Node: identity, version, syncing, health, peers, peer_count
  - Beacon: genesis, blocks, headers, validators, state_root, fork, finality_checkpoints, publishBlock
  - Validator: proposer duties, attester duties, sync duties
  - Debug: states, heads
  - Events: SSE stream
  - Config: spec, fork_schedule
- **`src/api/handlers/`** — handler implementations:
  - `beacon.zig` (763 LOC): getGenesis, getBlock, getBlockHeader, getValidators, getStateRoot, getStateFork, getFinalityCheckpoints, submitBlock
  - `node.zig` (153 LOC): getNodeVersion, getSyncing, getHealth, getNodeIdentity
  - `config.zig` (117 LOC): getSpec (partial), getForkSchedule
  - `validator.zig` (166 LOC): getProposerDuties (stub), getAttesterDuties (stub), getSyncDuties (stub)
  - `debug.zig` (81 LOC): getDebugState, getDebugHeads (stubs)
  - `events.zig` (141 LOC): SSE event stream
- **`src/api/event_bus.zig`** (179 LOC) — SSE event bus with subscriber management
- **`src/api/context.zig`** (111 LOC) — `ApiContext` with head tracker, sync status, DB access
- **`src/api/types.zig`** (432 LOC) — API response types

### What's missing vs TS Lodestar:
- **Validator duty handlers return stubs** — no EpochCache access for proposer/attester/sync duties
- **No pool endpoints** — `/eth/v1/beacon/pool/attestations`, `/beacon/pool/voluntary_exits`, etc.
- **No lightclient endpoints** — `/eth/v1/beacon/light_client/*`
- **No rewards endpoints** — `/eth/v1/beacon/rewards/*`
- **No committee endpoints** — `/eth/v1/beacon/states/{state_id}/committees`
- **No builder/MEV endpoints**
- **State regeneration not wired** — can only serve head state, not arbitrary `state_id`
- **No CORS** — needed for browser-based tools

**Priority for BN MVP:** 🟡 **Medium** — genesis, syncing, blocks, head work. Validator duties need EpochCache wiring.

---

## 10. Metrics

**Status:** ✅ Functional

### What exists:
- **`src/node/metrics.zig`** (309 LOC) — `BeaconMetrics`:
  - 40+ metrics: chain state, block processing, STFN, fork choice, attestation pool
  - P2P, discovery, sync, API, DB, memory/internals
  - `init()` for real metrics, `initNoop()` for zero-overhead stubs
  - Prometheus text exposition format output
- **`src/node/metrics_server.zig`** (120 LOC) — `MetricsServer`:
  - HTTP server on configurable port
  - `GET /metrics` → Prometheus text format

### What's missing:
- **Not fully wired** — only `blocks_imported_total`, `block_import_seconds`, `head_slot`, `finalized_epoch`, `justified_epoch`, `head_root` are updated in the import path
- **No P2P metrics collection** — `peers_connected`, `gossip_*`, `reqresp_*` defined but never set
- **No DB metrics** — `db_read_seconds`, `db_write_seconds` never observed
- **No state transition timing** — `state_transition_seconds`, `process_block_seconds`, `process_epoch_seconds` not instrumented

**Priority for BN MVP:** ✅ **Already functional** — Prometheus endpoint works, more instrumentation is incremental

---

## 11. Clock / Slot Ticker

**Status:** ✅ Functional

### What exists:
- **`src/node/clock.zig`** (123 LOC) — `SlotClock`:
  - `currentSlot()`, `currentEpoch()`, `slotFraction()`, `slotStartNs()`
  - `isAttestationTime()`, `isAggregationTime()`, `isProposalTime()`
  - Uses `std.Io` abstraction (works in both real and sim modes)
- **`src/node/main.zig`** — `slotClockLoop()`:
  - Logs slot/head/finalized each slot
  - Drives `sync_controller.tick()`
  - Sleeps until next slot boundary

### What's missing:
- **No slot-triggered duties** — clock tick doesn't trigger attestation/proposal work
- **No proposer boost timing** — should clear boost at start of new slot
- **No late block detection** — TS monitors block arrival within slot for gossip scoring

**Priority for BN MVP:** ✅ **Already functional**

---

## 12. State Regen / Caching

**Status:** 🟡 Partial (hot path works, cold path exists)

### What exists:
- **`src/state_transition/`** (13,472 LOC) — complete state transition:
  - `processSlots()`, `processBlock()` for all forks (phase0 → electra/fulu)
  - `EpochCache` with proposer indices, committee shuffling
  - `BlockStateCache` — LRU cache keyed by state root
  - `CheckpointStateCache` — epoch-boundary states with datastore backend
  - `StateRegen` — `onNewBlock()`, `onCheckpoint()`, can regenerate from DB
  - `MemoryCPStateDatastore` — in-memory checkpoint state persistence
- **`src/db/`** (2,309 LOC) — `BeaconDB` with:
  - `putBlock()` / `getBlock()` — hot block storage
  - `putStateArchive()` / `getStateArchive()` — cold state storage
  - `putBlobSidecars()` / `getBlobSidecars()`
  - `putBlockArchive()` / `getBlockArchiveByRoot()`
  - Memory and LMDB backends

### What's missing:
- **No cold-to-hot replay** — `StateRegen` can't yet reconstruct arbitrary historical states by replaying blocks from DB
- **No state pruning strategy** — `block_state_cache.pruneBeforeEpoch()` exists in `Chain.onFinalized()` but finalization pruning not triggered from import path
- **No hot→cold migration** — states in hot cache aren't automatically persisted to cold on eviction

**Priority for BN MVP:** ✅ **Functional for MVP** — hot path caching works, cold path archiving at epoch boundaries works

---

## 13. Validator Duties (BN side)

**Status:** 🟡 Partial (types + structure exist, API stubs)

### What exists:
- **`src/chain/validator_duties.zig`** (142 LOC) — `ValidatorDuties`:
  - `getProposer()` — delegates to EpochCache
  - `getAttestationDuty()` — scans committees for validator
  - `getSyncCommitteeDuties()` — looks up sync committee positions
- **`src/api/handlers/validator.zig`** (166 LOC):
  - Route definitions for proposer/attester/sync duties
  - Handler functions exist but return stubs (no EpochCache access in ApiContext)

### What's missing:
- **EpochCache not accessible from API layer** — duty handlers can't compute real duties
- **No `produceBlock` API endpoint** — BN-side block production (RANDAO, execution payload, graffiti) not integrated
- **No `produceAttestationData` endpoint** — VC needs this to create attestations
- **No `submitAttestation` / `submitAggregateAndProofs` endpoints**
- **No `prepareBeaconProposer` / `registerValidator`** endpoints

**Priority for BN MVP:** 🟢 **Low** — MVP is sync + gossip, validator client integration is next phase

---

## Summary Table

| Subsystem | Status | LOC | Priority |
|---|---|---|---|
| Block Import Pipeline | 🟡 Partial | ~3,500 | ✅ Done for MVP |
| Attestation Lifecycle | 🟡 Partial | ~1,300 | 🟡 Medium |
| Fork Choice | ✅ Functional | ~6,200 | ✅ Done |
| Sync | 🟡 Partial | ~2,150 | ✅ Works (single-peer) |
| Execution Engine | 🟡 Partial | ~1,900 | 🔴 High |
| Gossip Processing | 🟡 Partial | ~1,600 | 🟡 Medium-High |
| Processor / Work Queues | 🟡 Partial | ~2,060 | 🟢 Low |
| P2P / Networking | 🟡 Partial | ~5,200 | 🟡 Medium |
| REST API | 🟡 Partial | ~3,350 | 🟡 Medium |
| Metrics | ✅ Functional | ~430 | ✅ Done |
| Clock / Slot Ticker | ✅ Functional | ~570 | ✅ Done |
| State Regen / Caching | 🟡 Partial | ~15,800 | ✅ Works for MVP |
| Validator Duties (BN) | 🟡 Partial | ~310 | 🟢 Low |

---

## Prioritized TODO for BN MVP

**MVP Definition:** Sync from genesis (or checkpoint) via a single bootnode, stay at head via gossip blocks, serve basic API endpoints.

### P0 — Critical (blocks MVP today)

1. **Wire real EL integration**
   - Load JWT secret from `--jwt-secret` CLI flag
   - Instantiate `HttpEngine` when `--execution-url` is provided (instead of always MockEngine)
   - Implement `notifyForkchoiceUpdate()` — currently a no-op stub
   - Need a real HTTP client transport for `HttpEngine` (currently only has `MockTransport`)
   - Files: `beacon_node.zig` init, `http_engine.zig` transport

2. **Wire SyncService into P2P path**
   - Replace inline range sync in `dialBootnodeEnr()` with SyncController + SyncService
   - Connect `BatchRequestCallback` to actual P2P `requestBlocksByRange()`
   - Connect `BlockImporterCallback` to `BeaconNode.importBlock()`
   - Multi-peer support: track multiple peers, pick best for batch requests

### P1 — High (needed for staying at head reliably)

3. **Attestation gossip processing**
   - Implement `gossip_decoding` for `beacon_attestation` / `SingleAttestation`
   - Wire `GossipHandler.onAttestation()` to decode → validate → `chain.importAttestation()`
   - Subscribe to attestation subnets in gossipsub
   - This gives fork choice accurate head computation

4. **Gossipsub message validation**
   - Replace `PassthroughValidator` with real gossip validation callbacks
   - Return ACCEPT/REJECT/IGNORE per message type
   - Peer scoring for REJECT

5. **Discovery service loop**
   - Wire discv5 into P2P service for peer discovery
   - Find and dial new peers automatically
   - ENR publishing

### P2 — Medium (production readiness)

6. **Wire EpochCache into API**
   - Expose EpochCache from head state through ApiContext
   - Implement real proposer/attester/sync duty handlers
   - Implement `produceBlock` / `produceAttestationData` endpoints

7. **Deduplicate block import code**
   - `Chain.importBlock()` and `BlockImporter.importBlock()` are nearly identical
   - Choose one path and remove the other

8. **Wire BeaconProcessor**
   - Route gossip messages through WorkQueues → Processor → handlers
   - Priority-based scheduling instead of inline import

9. **Finalization handling**
   - Detect new finalized checkpoint in import path
   - Call `chain.onFinalized()` to prune caches + fork choice
   - Trigger state archiving

10. **Multi-peer connections**
    - Connection manager with max peers
    - Dial discovered peers, handle disconnects
    - Per-peer reputation / scoring

### P3 — Lower (nice-to-have for devnet)

11. Add backfill sync for historical data
12. Implement pool API endpoints (`/beacon/pool/*`)
13. Wire full metrics instrumentation
14. Add CORS to REST API
15. Implement data availability checks (blob verification)
16. TCP transport fallback
