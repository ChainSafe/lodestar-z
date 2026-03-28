# Deep Functional Delta Analysis v3: lodestar-z vs Lodestar (TypeScript)

*Generated: 2026-03-28 post-speedrun-wiring — Branch: feat/beacon-node (lodestar-z-reqresp-wire)*
*Compared against: Lodestar main (depth=1 clone at ~/lodestar-ts)*
*Previous: v1 (2026-03-27 initial), v2 (2026-03-27 post-speedrun)*

---

## Methodology

Same as v2: read actual Zig code, read actual TS code, report **behavioral** gaps.

**Codebase at analysis time: 406 Zig files / 119,331 LOC** (was 403 / 116,259 in v2, 341 / 93K pre-speedrun).

---

## What Changed Since v2

The speedrun's final wave (~37 sub-agent runs) closed the most critical gaps v2 identified. Here's what actually landed, verified by reading the code:

### Confirmed Fixes (verified in code)

| v2 Gap | Status | Evidence |
|--------|--------|----------|
| **No attestation weights in fork choice** | ✅ FIXED | `import_block.zig:170-210` — iterates phase0 and electra attestations, calls `fc.onAttestation()` per validator index |
| **No forkchoiceUpdated to EL** | ✅ FIXED | `beacon_node.zig:2963-3035` — `notifyForkchoiceUpdate()` sends FCU with head/safe/finalized hashes, caches payload_id. Called after every import at line 1670 |
| **No attester slashing in fork choice** | ✅ FIXED | `import_block.zig:212-235` — sorted-set intersection of slashing indices, calls `fc.onAttesterSlashing()` |
| **Fork-hardcoded electra import** | ✅ FIXED | `chain.zig:183-226` — `importBlock()` now takes `AnySignedBeaconBlock`, delegates to `processBlockPipeline()`. Legacy path eliminated |
| **No head recomputation after import** | ✅ FIXED | `import_block.zig:240-280` — `getHead()` called with effective balance increments, old/new head compared |
| **No reorg detection/events** | ✅ FIXED | `import_block.zig:290-350` — `detectAndEmitReorg()` walks proto_array for common ancestor, emits `chain_reorg` SSE event with depth |
| **No surround vote protection** | ✅ FIXED | `slashing_protection_db.zig:76-104` — `checkSurroundVote()` with sorted history scan, returns `surrounding`/`surrounded`/`none`. Wired into `checkAndInsertAttestation()` at line 226 |
| **Only 4 gossip validators** | ✅ FIXED (11 now) | `gossip_validation.zig` — 11 validators: block, attestation, aggregate, data_column_sidecar, blob_sidecar, voluntary_exit, proposer_slashing, attester_slashing, bls_to_execution_change, sync_committee_message, sync_contribution_and_proof |
| **No aggregated attestation pool** | ✅ FIXED | `aggregated_attestation_pool.zig` (795 LOC) — groups by data root, pre-aggregation, greedy coverage selection for block packing |
| **No safe blocks** | ✅ FIXED | `fork_choice.zig:518-540` — `getSafeBlockRoot()` and `getSafeExecutionBlockHash()` with tests |
| **No proposer-boost reorg** | ✅ FIXED | `fork_choice.zig:558+` — `shouldOverrideForkChoiceUpdate()` checks head timeliness, weight, committee percentage threshold. Has 3 tests |
| **No getDependentRoot** | ✅ FIXED | `import_block.zig:370-420` — `getDependentRoot()` and `getDutyDependentRoots()` compute previous/current duty roots via proto_array ancestor walk |
| **No validator index tracker** | ✅ FIXED | `index_tracker.zig` (268 LOC) — resolves pubkey→index via BN API, epoch refresh for new activations |
| **No validator liveness** | ✅ FIXED | `liveness.zig` (281 LOC) — rolling 10-epoch window per validator, attestation/sync committee hit rates, consecutive miss warnings |
| **No validator reorg handling** | ✅ FIXED | `attestation_service.zig:87-125` — tracks dependent roots via chain header tracker, re-fetches duties on reorg |
| **Missing pool/attestations API** | ✅ FIXED | `handlers/beacon.zig:submitPoolAttestations` — accepts JSON attestation array, adds to op pool |
| **Missing attestation_data API** | ✅ FIXED | `handlers/validator.zig:getAttestationData` |
| **Missing aggregate_attestation API** | ✅ FIXED | `handlers/validator.zig:getAggregateAttestation` |
| **Missing produce block API** | ✅ FIXED | `handlers/validator.zig:produceBlock` |

### New Capabilities (not in v2)

| Capability | Files | LOC |
|-----------|-------|-----|
| Keymanager API (EIP-3042) | `handlers/keymanager.zig` | 736 |
| Gossip handler (full node-level dispatch) | `gossip_handler.zig` | 973 |
| Validator metrics | `validator_metrics.zig` | 137 |
| 51 Prometheus metrics | `metrics.zig` | 382 |
| INVALID execution status propagation (tests) | `proto_array.zig` | tested |
| Block missed slot tracking | `block_service.zig:256` | — |
| Period transitions in sync committee | `sync_committee_service.zig` | — |

---

## 1. Chain Pipeline

**Status**: 🟢 72% (CHANGED from v2: was 42%, now 72%)
**Files**: Zig 33 / 10,757 LOC | TS 149 / 24,069 LOC
**What works end-to-end**:

- Full block import pipeline via `processBlockPipeline`: verify_sanity → pre-state → DA check → state_transition → verify_execution → import
- Fork-polymorphic: accepts `AnySignedBeaconBlock` across all forks (phase0→fulu)
- Block → fork choice with justified/finalized checkpoints from post-state
- **In-block attestation weights imported to fork choice** (phase0 and electra)
- **Attester slashing import** — equivocating validators excluded from fork choice
- **Head recomputation after import** with effective balance increments
- **Reorg detection and SSE events** with depth computation via common ancestor
- **forkchoiceUpdated notification to EL** with head/safe/finalized block hashes
- INVALID execution status propagation through proto_array
- Queued state regen with priority queuing (block_import > fork_choice > api > background)
- Prepare next slot: pre-computes state at 2/3 slot mark
- Reprocess queue: parent_root keyed, 3 pending reasons
- Op pools: Attestation (simple + aggregated), VoluntaryExit, ProposerSlashing, AttesterSlashing, BlsChange, SyncContribution, SyncCommitteeMessage
- **Aggregated attestation pool** with greedy coverage-maximizing block packing
- Block production: `produceBlockBody` + `assembleBlock` with electra attestation conversion
- Data availability manager: blob tracker, column tracker, column reconstruction, KZG verification
- Seen caches: blocks, aggregators, exits, slashings, BLS changes, data columns
- Gossip validation: 11 validators (was 4)
- Full gossip handler at node level dispatching to chain (973 LOC, 11 message types)
- SSE events: block, head, finalized_checkpoint, chain_reorg

**Remaining gaps** (ordered by severity):

1. 🟡 **[Important] No validator monitor** — TS `validatorMonitor.ts` (1,375 LOC) tracks per-validator attestation performance, block proposals, sync committee participation. Zig has per-module metrics but no dedicated validator monitor wired into chain events. *Impact: No observability into individual validator performance from the BN side.*

2. 🟡 **[Important] Block input async data waiting** — TS `blockInput.ts` (1,005 LOC) handles blocks arriving before their blobs with timeout-based data availability waiting. Zig's `BlockInput` in the pipeline is simpler — no async blob waiting. *Impact: During gossip sync, blocks may be rejected if blobs arrive slightly late.*

3. 🟡 **[Important] No light client server** — TS `chain/lightClient/` (3 files) produces light client updates from the beacon node. Missing entirely. *Impact: No light client support.*

4. 🟢 **[Nice-to-have] Missing ePBS pipeline** — TS has `payloadEnvelopeProcessor.ts`, `importExecutionPayload.ts`. Zig proto_array has Gloas support but chain pipeline doesn't process payload envelopes yet.

5. 🟢 **[Nice-to-have] No archive store background jobs** — TS has 13 files for background archival. Zig has basic `archive_store.zig` but no background workers.

---

## 2. Fork Choice

**Status**: ✅ 88% (CHANGED from v2: was 65%, now 88%)
**Files**: Zig 6 / 6,638 LOC | TS 11 / 4,817 LOC
**What works end-to-end**:

- Proto-array DAG: onBlock, findHead, applyScoreChanges, prune
- **Attestation weight computation** via computeDeltas (SoA vote tracking)
- **Equivocation handling** via onAttesterSlashing
- **Safe block computation**: `getSafeBlockRoot()` and `getSafeExecutionBlockHash()` with tests
- **Proposer-boost reorg**: `shouldOverrideForkChoiceUpdate()` with timeliness/weight checks
- **getDependentRoot**: previous/current duty dependent roots for head events
- **getCommonAncestor**: reorg depth detection via proto_array ancestor walk
- Execution status: VALID/INVALID/SYNCING propagation through DAG
- **INVALID chain invalidation**: `propagateInvalidExecutionStatusByIndex` walks ancestors
- Checkpoint management: justified, finalized, best_justified, unrealized justified/finalized
- Proposer boost: setProposerBoost/clearProposerBoost with score injection
- Pruning: maybePrune below finalized root
- **Gloas ePBS support**: dual-node architecture (PENDING/FULL), `onExecutionPayload`, `notifyPtcMessages`

**Remaining gaps**:

1. 🟡 **[Important] No structured error types** — TS has `ForkChoiceErrorCode` with 17 detailed variants. Zig uses bare `error.InvalidBlock`. *Impact: Callers can't distinguish failure modes programmatically.*

2. 🟡 **[Important] Fork choice metrics** — TS has `metrics.ts` tracking node count, reorgs, head changes. Zig has some metrics in `BeaconMetrics` (fork_choice_find_head_seconds, fork_choice_nodes, reorg_events_total) but not as comprehensive.

3. 🟢 **[Nice-to-have] Interface abstraction** — TS has `IForkChoice` interface for testing. Zig uses concrete types. Not needed due to Zig's comptime generics.

**Assessment**: Fork choice is functionally near-complete. The Zig implementation is more LOC than TS (6,638 vs 4,817) because it includes the full Gloas ePBS dual-node architecture — which is **ahead** of most clients.

---

## 3. Networking / P2P

**Status**: 🟠 55% (CHANGED from v2: was 50%, now 55%)
**Files**: Zig 27 / 11,692 LOC | TS 89 / 13,998 LOC
**What works end-to-end**:

- P2P service: QUIC transport via zig-libp2p, init/start/stop/dial
- Gossip: topic construction per-fork, Snappy decompression, SSZ decode, 11 validation functions
- Req/resp: Status, Goodbye, Ping, Metadata, BeaconBlocksByRange, BeaconBlocksByRoot, **BlobSidecarsByRange, BlobSidecarsByRoot, DataColumnsByRange, DataColumnsByRoot** (protocol handlers defined)
- Discovery: full discv5 (13 files), ENR management, bootnode seeding, subnet queries
- Peer management: connected/dialing/banned, heartbeat
- **Scoring parameters**: gossipsub v1.1 with correct Ethereum-specific topic weights (310 LOC)
- **Rate limiter**: per-peer request quota tracking (655 LOC)
- **Subnet service**: attestation subnet subscription (327 LOC)
- **Column subnet service**: PeerDAS custody subnet management (465 LOC)
- Status cache: cached chain status for req/resp
- Peer DB: persistent state

**Remaining gaps**:

1. 🔴 **[Critical] QUIC-only transport** — Most consensus clients support TCP+Noise+Mplex. While spec allows QUIC and some clients support it (Lighthouse, Prysm), not all peers will be reachable. *Impact: May not connect to all peers. Risk mitigated if devnet peers are QUIC-capable.*

2. 🟡 **[Important] Multi-component peer scoring incomplete** — TS has 5 files in `peers/score/` with per-component scoring (gossip, reqresp, liveness). Zig's `peer_scoring.zig` is simpler. *Impact: Less nuanced peer selection/disconnection.*

3. 🟡 **[Important] No peer prioritization** — TS `prioritizePeers.ts` selects peers by subnet coverage/scores/diversity. Missing in Zig. *Impact: Suboptimal peer selection, especially for subnet coverage.*

4. 🟡 **[Important] No peer relevance assertion** — TS checks peer's chain status before syncing. Missing. *Impact: Could sync from irrelevant peers.*

5. 🟡 **[Important] Network processor incomplete** — Zig has `processor/` (2,090 LOC) with typed work queues, but the full prioritized dispatch pipeline (TS has 1,907 LOC in `network/processor/`) may not be fully wired for all message types.

6. 🟢 **[Nice-to-have] No gossip metrics** — Per-topic message counts, validation times, propagation delay.

**Transport risk assessment**: QUIC is spec'd and increasingly supported. For a **controlled devnet** where all participants use QUIC-capable clients (Lighthouse, Prysm), TCP may not be needed. For mainnet, TCP fallback is essential.

---

## 4. State Transition

**Status**: ✅ 85% (UNCHANGED from v2: was 85%)
**Files**: Zig 111 / 13,611 LOC | TS 140 / 14,451 LOC
**What works end-to-end**:

- All 22 block processing functions phase0→fulu
- All 20 epoch processing functions across all forks
- 6 fork upgrade functions (phase0→altair→bellatrix→capella→deneb→electra→fulu)
- Full cache system (10+ cache types)
- All 6 signature sets, batch BLS verification
- 22 utility files, full spec test framework
- **Spec tests passing for phase0→fulu presets**

**Remaining gaps**: Same as v2 — Gloas fork (ePBS state transition), reward cache, light client helpers.

---

## 5. Validator Client

**Status**: 🟡 72% (CHANGED from v2: was 55%, now 72%)
**Files**: Zig 22 / 7,354 LOC | TS 57 / 7,063 LOC
**What works end-to-end**:

- Validator orchestrator with service lifecycle management
- Attestation service with duty tracking, production, aggregation, **reorg handling**
- Block service with proposal duties, production, **missed slot tracking**
- Sync committee service with **period transitions**
- **Index tracker** — pubkey→validator_index resolution with epoch refresh
- **Liveness tracker** — 10-epoch rolling window, consecutive miss warnings
- **Surround vote protection** — full sorted-history check with surrounding/surrounded detection
- API client for BN REST endpoints
- Chain header tracker with SSE subscription
- Validator store: in-memory key/state management
- Doppelganger detection
- EIP-2335 keystore: decrypt (scrypt/pbkdf2) + create
- Key discovery: filesystem-based
- Slashing protection DB: append-only file format
- EIP-3076 interchange: import/export
- BLS signing with domain separation
- Fee recipient registration
- **Keymanager auth**: bearer token authentication
- **Validator metrics**: attestation/block/sync committee duty tracking

**Remaining gaps**:

1. 🟡 **[Important] No syncing status tracker** — TS pauses signing during BN sync. Missing. *Impact: VC could produce duties with stale data during sync.*

2. 🟡 **[Important] Remote signer stub only** — Web3Signer types defined, no HTTP implementation. *Impact: Can't use external signers in production.*

3. 🟡 **[Important] No external signer sync** — TS periodically syncs available keys from Web3Signer. Missing.

4. 🟢 **[Nice-to-have] Genesis fetching** — Explicit genesis time/validators_root fetch from BN API. May be handled implicitly.

**Assessment**: The Zig VC at 7,354 LOC now exceeds TS's 7,063 LOC. The critical safety gap (surround votes) is closed. Index tracking, liveness, reorg handling, and missed slot detection are all implemented. This is **production-viable** for local keystores (not Web3Signer).

---

## 6. Execution Engine

**Status**: 🟡 70% (CHANGED from v2: was 65%, now 70%)
**Files**: Zig 8 / 5,333 LOC | TS 16 / 3,147 LOC
**What works end-to-end**:

- Full EngineApi vtable: newPayloadV1-V4, forkchoiceUpdatedV1-V3, getPayloadV1-V4, getBlobsV1, exchangeCapabilities
- HTTP JSON-RPC client with pluggable transport
- JWT authentication (HS256, per-request, 60s expiry)
- All payload types (V1-V4), PayloadAttributes V1-V3
- Payload ID cache
- Mock engine for testing
- Engine state machine (online/offline/syncing/auth_failed)
- Retry with exponential backoff
- **KZG library**: Full c-kzg integration — blob/cell operations, PeerDAS reconstruct/verify
- Builder API stub (types + vtable defined, methods return NotImplemented)

**Remaining gaps**:

1. 🟡 **[Important] Builder/MEV-boost stub only** — Types defined but no HTTP implementation. *Impact: No MEV-boost support, validators miss MEV revenue.*

2. 🟡 **[Important] Engine error classification** — TS categorizes EL errors (sync/auth/connection). Zig returns generic errors.

3. 🟢 **[Nice-to-have] Engine metrics** — Request latency/status/errors tracked via BeaconMetrics struct but not as granular as TS.

---

## 7. Beacon API

**Status**: 🟡 65% (CHANGED from v2: was 50%, now 65%)
**Files**: Zig 20 / 7,158 LOC | TS 71 / 9,281 LOC
**What works end-to-end**:

- HTTP server with content negotiation (JSON + SSZ binary)
- SSE event streaming (block, head, finalized_checkpoint, chain_reorg)
- **40 routes implemented** (was ~33):
  - Node: identity, version, syncing, health, peers, peer_count
  - Beacon: genesis, headers, blocks, validators, state root/fork/finality
  - **Pool GET**: attestations, voluntary_exits, proposer_slashings, attester_slashings, bls_to_execution_changes
  - **Pool POST**: attestations, voluntary_exits, proposer_slashings, attester_slashings, bls_to_execution_changes, sync_committees
  - **Validator**: proposer/attester/sync duties, **produce block**, **attestation_data**, **aggregate_attestation**, **aggregate_and_proofs**, sync_committee_contribution, contribution_and_proofs
  - Config: spec, fork_schedule
  - Debug: states, heads
  - Events: SSE
  - **Keymanager**: list/import/delete keystores, list/import/delete remote keys (7 endpoints)

**Remaining gaps**:

1. 🟡 **[Important] GET /eth/v1/beacon/states/{id}/committees** — Needed for some VC implementations. *Impact: Some external VCs may require this.*

2. 🟡 **[Important] GET /eth/v1/beacon/states/{id}/sync_committees** — Similar to above.

3. 🟡 **[Important] GET /eth/v1/beacon/states/{id}/randao** — Some VCs use this for block production.

4. 🟡 **[Important] GET /eth/v1/beacon/blob_sidecars/{block_id}** — Blob retrieval for Deneb.

5. 🟡 **[Important] POST /eth/v1/validator/prepare_beacon_proposer** — Fee recipient registration via API.

6. 🟢 **[Nice-to-have] Rewards API** — `/eth/v1/beacon/rewards/*` (4+ endpoints).
7. 🟢 **[Nice-to-have] Light client API** — All `/eth/v1/light_client/*` endpoints.
8. 🟢 **[Nice-to-have] Builder API** — All `/eth/v1/builder/*` endpoints.
9. 🟢 **[Nice-to-have] Proof API** — `/eth/v1/beacon/proof/*` endpoints.

**Assessment**: The critical VC flow (duties → attestation_data → aggregate → produce_block → submit) is now complete. Missing endpoints are either nice-to-have or needed by specific VC implementations.

---

## 8. Sync

**Status**: 🟡 60% (UNCHANGED from v2: was 60%)
**Files**: Zig 11 / 3,874 LOC | TS 24 / 6,083 LOC
**What works end-to-end**:

- Sync service: onPeerStatus, onPeerDisconnect, tick, isSynced
- Range sync: addPeer/removePeer/tick, finalized chain + head chains
- Sync chains: state machine (awaiting_peers → syncing → head → idle)
- Batch management: request/response tracking, retry
- Checkpoint sync: full (state + blocks from trusted API)
- Unknown block sync: pending blocks with parent tracking
- Backwards chain walking

**Remaining gaps**: Same as v2 — backfill sync (TS: 4 files), peer balancer, download utilities, sync metrics.

---

## 9. Database

**Status**: 🟡 60% (UNCHANGED from v2: was 60%)
**Files**: Zig 10 / 2,384 LOC | TS 36 / 5,027 LOC
**What works end-to-end**: KV store abstraction, LMDB backend (named databases), in-memory backend, BeaconDB with 30+ operations.

**Remaining gaps**: Same as v2 — secondary indexes, hot/cold split, backfilled ranges, schema migrations.

---

## 10. Monitoring / Metrics

**Status**: 🟡 45% (CHANGED from v2: was 20%, now 45%)
**Files**: Zig metrics ~839 LOC | TS ~2,000 LOC
**What works end-to-end**:

- **51 Prometheus metrics** covering: head slot/root, finalized/justified epochs, active validators, reorgs, block import timing, state transition timing, fork choice timing, attestation pool, peers, gossip messages, reqresp, discovery, sync, API, DB, execution engine
- HTTP `/metrics` endpoint serving Prometheus text format
- STF metrics with timing histograms
- Validator metrics: attestation/block/sync duty tracking
- Noop metrics variant for zero-overhead when disabled

**Remaining gaps**:

1. 🟡 Missing per-topic gossip metrics (validation time, propagation delay)
2. 🟡 Missing detailed per-protocol reqresp metrics
3. 🟢 Missing remote metrics push
4. 🟢 Missing health check details beyond HTTP status

**Assessment**: 51 metrics is a solid foundation — covers the most important observability categories. TS has ~150+ individual metrics, so roughly 1/3 of the way there, but the critical operational metrics exist.

---

## 11. SSZ / BLS / Types / Config

**Status**: ✅ 85-95% (UNCHANGED from v2)

These subsystems were already mature:
- **SSZ**: 31 files, 14,173 LOC. Full type system, tree views, SIMD-accelerated SHA256, spec tests passing.
- **BLS**: 12 files, 2,138 LOC. Full blst.zig bindings, thread pool batch verification.
- **Types**: 20 files, 4,562 LOC. phase0→fulu consensus types.
- **Config**: 11 files, 1,468 LOC. YAML loader, 6 networks, compile-time presets.

---

## 12. Testing Infrastructure

**Status**: ✅ 80% (UNCHANGED from v2)
**Files**: 23 / 6,827 LOC

SimBeaconNode, SimNetwork, SimCluster, block/attestation generators, invariant checkers, fork choice simulation, integration tests. Missing: E2E against real EL, Kurtosis cross-client tests, fuzzing.

---

## 13. Light Client

**Status**: ❌ 0% (UNCHANGED)

TS: 44 files / 3,333 LOC. Zig: 0 files.

---

## 14. Slasher / Builder / PeerDAS

- **Slasher**: ❌ 0% — TS `flare` package: 9 files / 464 LOC. Not blocking.
- **Builder/MEV-boost**: 🔴 10% — Zig has types+vtable stub. TS has 363 LOC HTTP implementation.
- **PeerDAS**: 🟡 50% — Zig has KZG library, column tracker, column reconstruction, column subnet service, DA manager. Missing: custody subnet management integration, actual column sampling protocol.

---

## Summary

### 1. What changed since v2

**Gaps closed (13 critical/important fixes):**
- Attestation weights → fork choice ✅
- forkchoiceUpdated to EL ✅ (with INVALID propagation)
- Attester slashing → fork choice ✅
- Fork-polymorphic block import (legacy path → pipeline) ✅
- Head recomputation + reorg detection with SSE events ✅
- Surround vote protection ✅
- 11 gossip validators (was 4) ✅
- Aggregated attestation pool with greedy packing ✅
- Safe blocks + proposer-boost reorg logic ✅
- getDependentRoot + duty dependent roots ✅
- Validator: index tracker, liveness, reorg handling, missed slots, period transitions ✅
- API: pool/attestations, attestation_data, aggregate_attestation, produce_block ✅
- Keymanager API (EIP-3042) ✅

**New infrastructure:**
- 51 Prometheus metrics (was ~10)
- Full gossip handler (973 LOC, 11 message types)
- Validator metrics (137 LOC)
- CONCURRENCY.md architecture doc (526 LOC)

### 2. What actually works if we ran the binary today

**Would work end-to-end:**
- ✅ CLI parsing → data directory setup → logging with rotation
- ✅ Checkpoint sync from trusted API
- ✅ State transition for all forks (phase0→fulu, spec-tested)
- ✅ Block import through full pipeline: sanity → STFN → verify → import → FC → head → reorg detection
- ✅ In-block attestation weights applied to fork choice
- ✅ forkchoiceUpdated sent to EL with head/safe/finalized hashes
- ✅ INVALID execution status propagated through fork choice tree
- ✅ P2P: QUIC connections, discv5 discovery, gossip (11 validators), req/resp (10 protocols)
- ✅ REST API: 40 endpoints including full validator duty cycle
- ✅ Metrics: 51 Prometheus metrics on `/metrics`
- ✅ Validator client: keystores, duties, attestations, blocks, sync committee, surround vote protection

**Would partially work:**
- 🟠 EL integration: forkchoiceUpdated works but may need integration testing for edge cases
- 🟠 Blob sync: protocols defined but full DA verification pipeline untested end-to-end
- 🟠 Block production: works but no MEV-boost, builder API stub-only

**Would NOT work:**
- ❌ TCP-only peers: QUIC transport only
- ❌ Light client: no server, no consumer
- ❌ Web3Signer: stub only
- ❌ MEV-boost: stub only

### 3. Top 10 remaining gaps blocking devnet

| # | Gap | Subsystem | Effort | Severity |
|---|-----|-----------|--------|----------|
| 1 | **QUIC-only transport** — TCP fallback for non-QUIC peers | Network | 2 weeks or QUIC-capable devnet (0 days) | 🔴 If devnet needs TCP |
| 2 | **Blob sidecar DA verification** — end-to-end pipeline test | Chain/DA | 3-5 days | 🟡 For Deneb fork |
| 3 | **committees/sync_committees/randao API endpoints** | API | 3 days | 🟡 If external VC needs them |
| 4 | **blob_sidecars/{block_id} API endpoint** | API | 2 days | 🟡 For Deneb |
| 5 | **prepare_beacon_proposer API** | API | 1 day | 🟡 Fee recipient |
| 6 | **Network processor full pipeline** | Network | 1 week | 🟡 Message prioritization |
| 7 | **Peer relevance assertion** | Network | 2 days | 🟡 |
| 8 | **Multi-component peer scoring** | Network | 1 week | 🟡 |
| 9 | **Backfill sync** | Sync | 1 week | 🟢 Not for initial devnet |
| 10 | **Block input async DA waiting** | Chain | 3 days | 🟡 Blocks before blobs |

**Key insight vs v2**: The v2 top 10 was dominated by fork choice + chain pipeline gaps (forkchoiceUpdated, attestation weights, safe blocks, fork-aware import). **ALL of those are now closed.** The remaining gaps are mostly in networking (transport/scoring) and API completeness — not in the core consensus logic.

### 4. Top 10 remaining gaps blocking production

| # | Gap | Subsystem | Effort |
|---|-----|-----------|--------|
| 1 | **TCP transport** | Network | 2-3 weeks |
| 2 | **Builder/MEV-boost** | Execution | 2-3 weeks |
| 3 | **Validator monitor** | Chain | 2 weeks |
| 4 | **Complete peer scoring** | Network | 1-2 weeks |
| 5 | **Web3Signer implementation** | Validator | 2 weeks |
| 6 | **Backfill sync** | Sync | 2 weeks |
| 7 | **Light client server** | Chain | 3 weeks |
| 8 | **Structured error types** | All | 2 weeks |
| 9 | **Remaining API endpoints** (rewards, proof, light client) | API | 3 weeks |
| 10 | **Comprehensive metrics** (100+ remaining) | Monitoring | 2-3 weeks |

### 5. Revised devnet timeline

**v2 said 4-6 weeks. Revised estimate: 2-4 weeks.**

Rationale:
- The core consensus pipeline (block import → fork choice → EL notification) is now complete. v2's #1-#7 devnet blockers are all fixed.
- For a **controlled devnet** with QUIC-capable clients (Lighthouse + Prysm both support QUIC), TCP transport isn't needed. This removes the single biggest unknown.
- The API surface covers the full validator duty cycle. Missing endpoints (committees, randao, blob_sidecars) are 1-2 days each.
- The main work is integration testing and hardening, not greenfield implementation.

**Critical path:**
- Week 1: Blob DA pipeline integration test + missing API endpoints (committees, randao, blob_sidecars, prepare_beacon_proposer)
- Week 2: Kurtosis devnet with Zig BN + QUIC-capable CL/EL peers. Fix issues that emerge.
- Week 3-4: Hardening — peer scoring, network processor, edge cases from devnet testing.

**Risk factors:**
- zig-libp2p QUIC stability under real network conditions (untested at scale)
- EL integration edge cases (JWT rotation, reconnection, timeout handling)
- Gossip message propagation timing under real network latency

### 6. File/LOC counts

**lodestar-z (feat/beacon-node, 2026-03-28):**

| Module | Files | LOC |
|--------|-------|-----|
| ssz | 31 | 14,173 |
| state_transition | 111 | 13,611 |
| networking | 27 | 11,692 |
| chain | 33 | 10,757 |
| node | 16 | 9,712 |
| validator | 22 | 7,354 |
| api | 20 | 7,158 |
| testing | 23 | 6,827 |
| fork_choice | 6 | 6,638 |
| execution | 8 | 5,333 |
| sync | 11 | 3,874 |
| discv5 | 13 | 3,379 |
| persistent_merkle_tree | 9 | 3,196 |
| fork_types | 11 | 2,957 |
| db | 10 | 2,384 |
| bls | 12 | 2,138 |
| processor | 5 | 2,090 |
| consensus_types | 9 | 1,605 |
| config | 11 | 1,468 |
| log | 2 | 1,165 |
| kzg | 2 | 319 |
| hashing | 5 | 245 |
| preset | 2 | 208 |
| constants | 1 | 117 |
| **TOTAL** | **406** | **119,331** |

**Growth during speedrun:**
- Pre-speedrun: 341 files / ~93K LOC
- v2 (mid-speedrun): 403 files / 116,259 LOC (+62 files / +23K LOC)
- v3 (post-speedrun): 406 files / 119,331 LOC (+3 files / +3K LOC from v2)

**lodestar TypeScript (selected packages):**

| Package | Files | LOC |
|---------|-------|-----|
| beacon-node | ~412 | ~62,113 |
| state-transition | 140 | 14,451 |
| api | 71 | 9,281 |
| validator | 57 | 7,063 |
| fork-choice | 11 | 4,817 |
| sync (within bn) | 24 | 6,083 |
| light-client | 44 | 3,333 |
| types | 38 | 3,985 |
| config | 24 | 1,979 |
| params | 10 | 1,191 |
| logger | 12 | 744 |
| db | 9 | 1,027 |
| **TOTAL (selected)** | **~852** | **~116,067** |

**LOC parity**: Zig 119K vs TS 116K — Zig now slightly exceeds TS in raw LOC for the compared packages. However, TS's LOC is concentrated in the beacon-node package (62K) which covers chain pipeline + networking + execution — the areas where Zig is still catching up in behavioral completeness.

---

## Overall Assessment

The speedrun's wiring phase was remarkably effective. v2 identified 13 critical/important behavioral gaps in the core consensus pipeline; **all 13 are now closed with real implementations** (not stubs). The codebase moved from "pieces exist but aren't connected" to "core pipeline works end-to-end."

The character of remaining work has shifted fundamentally:
- **v2**: "Core consensus logic is broken" (no attestation weights, no EL notification, no reorg detection)
- **v3**: "Edge cases and production hardening" (TCP transport, MEV-boost, peer scoring, metrics)

For a **controlled devnet** with cooperative participants, the binary is approaching viability. The 2-4 week estimate assumes integration testing surfaces manageable issues, not fundamental architectural problems.

---

*Analysis completed: 2026-03-28 ~01:45 UTC*
*Branch analyzed: feat/beacon-node (lodestar-z-reqresp-wire)*
*Compared against: Lodestar main (depth=1 clone at ~/lodestar-ts)*
*Methodology: Line-by-line code reading of Zig and TS implementations*
