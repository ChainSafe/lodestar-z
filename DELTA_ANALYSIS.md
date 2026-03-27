# Structural Delta Analysis: lodestar-z vs Lodestar (TypeScript)

*Generated: 2026-03-27 — Branch: feat/beacon-node (lodestar-z-reqresp-wire)*

---

## What Changed Since the Gist

The [prior gist](https://gist.github.com/lodekeeper-z/75de0d483e7395e663c34aa58d5207e9) was written earlier today. Multiple branches were merged into `feat/beacon-node` since then:

### Merges completed today (newest first):

| Branch | What it added |
|--------|---------------|
| `feat/logging-v2` | File transport (size-based + daily rotation), structured logging |
| `feat/data-dir-layout` | `DataDir` struct, network-aware path resolution, JWT secret auto-generate |
| `feat/validator-client-v4` | **Full validator client** — attestation, block, sync committee services, API client, EIP-2335 keystore, slashing protection, remote signer stub |
| `feat/validator-client-v2` | Earlier VC wiring |
| `feat/fix-compile-errors` | Compile fix pass |
| `feat/db-redesign` | LMDB named databases instead of bucket prefixes |
| `feat/api-framework-analysis` | API framework expansion |
| `feat/execution-gaps` | Execution engine improvements |
| `feat/chain-pipeline-gaps` | Chain pipeline additions |

### Gaps CLOSED since gist:

1. ✅ **Validator Client** — gist said ❌ Not Started. Now 17 files / 5,199 LOC covering all major VC services
2. ✅ **Logging** — gist said minimal. Now structured framework with per-module levels, file transport, rotation
3. ✅ **DataDir layout** — data directory management with network-aware defaults
4. ✅ **Processor module** — new `src/processor/` with work queues and typed work items
5. ✅ **EIP-2335 keystore decryption** — keystore.zig
6. ✅ **Slashing protection DB** — slashing_protection_db.zig

### Gaps STILL OPEN (unchanged from gist):

- Light client (0%)
- Slasher / flare
- Builder API / MEV-boost
- Keymanager API (EIP-3042)
- PeerDAS column reconstruction
- KZG library integration
- Gloas fork support

---

## Summary Table

| # | Subsystem | TS Files | TS LOC | Zig Files | Zig LOC | Status | Complete % | Devnet Blocker |
|---|-----------|----------|--------|-----------|---------|--------|-----------|----------------|
| 1 | State Transition | 140 | 14,451 | 111 | 13,611 | 🟡 Substantial | ~80% | No |
| 2 | SSZ | ~35 | ~8,000 | 31 | 14,173 | ✅ Full | ~95% | No |
| 3 | BLS | ~10 | ~2,000 | 12 | 2,130 | ✅ Full | ~95% | No |
| 4 | Fork Choice | 11 | 4,817 | 6 | 6,286 | 🟠 Partial | ~55% | Yes |
| 5 | Validator Client | 57 | 7,063 | 17 | 5,199 | 🟠 Partial | ~55% | External VC |
| 6 | Networking / P2P | 89 | ~18,000 | 25 | 10,156 | 🟠 Partial | ~45% | Yes |
| 7 | Beacon API | 71 | 9,281 | 18 | 4,956 | 🟠 Partial | ~40% | Yes |
| 8 | DB (beacon-node) | 27 | ~4,000 | 10 | 2,384 | 🟠 Partial | ~50% | No |
| 9 | Sync | 24 | ~3,500 | 11 | 3,874 | 🟠 Partial | ~55% | No |
| 10 | Chain Pipeline | 149 | ~25,000 | 16 | 5,268 | 🔴 Minimal | ~22% | Partial |
| 11 | Execution Engine | 16 | ~3,000 | 7 | 3,995 | 🟠 Partial | ~55% | Partial |
| 12 | Light Client | 27 | 1,920 | 0 | 0 | ❌ None | 0% | No |
| 13 | Types | 38 | 3,985 | 20 | 4,562 | 🟡 Substantial | ~85% | No |
| 14 | Config/Params | 34 | 3,170 | 14 | 1,793 | 🟡 Substantial | ~80% | No |
| 15 | Logger | 12 | 744 | 2 | 1,165 | 🟡 Substantial | ~70% | No |
| 16 | DB (package/kv) | 9 | 1,027 | 10 | 2,384 | 🟡 Substantial | ~75% | No |
| 17 | Monitoring | 18 | ~2,000 | 3 | ~500 | 🔴 Minimal | ~20% | No |
| 18 | Processor | ~10 | ~2,000 | 5 | 2,090 | 🟠 Partial | ~50% | No |
| 19 | Testing Infra | ~20 | ~3,000 | 23 | 6,825 | 🟡 Substantial | ~80% | No |
| 20 | Data Availability | ~15 | ~3,000 | partial | ~500 | 🔴 Minimal | ~20% | For Fulu |
| 21 | CLI | ~30 | ~5,000 | 2 | ~400 | 🔴 Minimal | ~15% | No |
| 22 | Slasher | ~40 | ~6,000 | 0 | 0 | ❌ None | 0% | No |
| 23 | Key Management | ~10 | ~1,500 | 0* | 0 | 🔴 Minimal | ~15%* | For VC |

*Key management: `keystore.zig` added today covers EIP-2335 decryption; keymanager API (EIP-3042) still missing

---

## Per-Subsystem Detail

### 1. State Transition (`packages/state-transition/src/` → `src/state_transition/`)

**Status: 🟡 Substantial (80%)**

**What's implemented (111 files, 13,611 LOC):**
- Block processing: all 22 functions phase0→fulu (process_block_header through process_consolidation_request)
- Epoch processing: all 20 functions across all forks
- Slot processing + 6 fork upgrade functions (phase0→fulu)
- Cache: epoch_cache, epoch_transition_cache, pubkey_cache, root_cache, effective_balance_increments, slashings_cache, state_cache, sync_committee_cache, block_state_cache, checkpoint_state_cache, state_regen, datastore
- Signature sets: all 6 (proposer, randao, indexed_attestation, proposer_slashings, bls_to_execution_change, voluntary_exits)
- Utils: 22 files (shuffle, seed, domain, signing_root, epoch_shuffling, committee_indices, validator status, balance, attestation, sync_committee, etc.)
- Test utils: generate_block, generate_state, interop_pubkeys
- Full spec test framework with downloads, generates, and runs consensus-spec test vectors

**What's missing:**

| Gap | TS File | Priority | Effort |
|-----|---------|----------|--------|
| Gloas fork upgrade | `upgradeStateToGloas.ts` | Nice-to-have | 1 week |
| `processPayloadAttestation` | `processPayloadAttestation.ts` | Nice-to-have (Gloas) | 3 days |
| `processExecutionPayloadBid/Envelope` | ePBS processing | Nice-to-have | 3 days |
| `processBuilderPendingPayments` | ePBS epoch op | Nice-to-have | 2 days |
| Reward cache | `rewardCache.ts` | Production | 3 days |
| Light client helpers | `lightClient/proofs.ts` | Production | 1 week |
| `processExecutionPayloadEnvelope` | ePBS | Nice-to-have | 2 days |

**Priority:** Low — core phase0→fulu is complete and spec-tested  
**Effort:** 1-2 weeks for Gloas; light client helpers 1 week

---

### 2. SSZ (`@chainsafe/ssz` → `src/ssz/`)

**Status: ✅ Full (95%)**

**What's implemented (31 files, 14,173 LOC):**
- Full type system: container, uint, bool, bit_list, bit_vector, vector, list, byte_list, byte_vector
- Tree views for all types
- SIMD-accelerated SHA256 via hashtree-z
- Persistent merkle tree (Node, View, gindex, proof)
- Full SSZ generic + SSZ static spec tests

**What's missing:**

| Gap | Notes | Priority | Effort |
|-----|-------|----------|--------|
| `StableContainer`/`Profile` (EIP-7495) | PR #99 in progress | Future spec | 2-3 weeks |
| Multiproof batching | Single proof works; batch not yet | Production | 1 week |

**Devnet blocker:** No  
**Effort:** Progressive types: 2-3 weeks (PR in progress)

---

### 3. BLS (`@chainsafe/bls` → `src/bls/`)

**Status: ✅ Full (95%)**

**What's implemented (12 files, 2,130 LOC):**
- PublicKey, SecretKey, Signature, AggregatePublicKey, AggregateSignature, Pairing
- ThreadPool for multi-threaded batch verification
- fast_verify for aggregate verification
- Wraps blst C library via blst.zig

**What's missing:**

| Gap | Notes | Priority | Effort |
|-----|-------|----------|--------|
| Queue-based MT dispatch | PR #248 | Optimization | Days |
| Fuzz testing | PR #249 | Quality | Days |
| BLS batch ops higher-level | PR #219 | Optimization | Days |

**Devnet blocker:** No

---

### 4. Fork Choice (`packages/fork-choice/` → `src/fork_choice/`)

**Status: 🟠 Partial (55%)**

**What's implemented (6 files, 6,286 LOC):**
- `fork_choice.zig` — onBlock, onAttestation, getHead, setProposerBoost, clearProposerBoost, onAttesterSlashing, updateTime, updateJustifiedCheckpoint, updateFinalizedCheckpoint, updateUnrealizedCheckpoints, prune, validateLatestHash, hasBlock, getBlock, isDescendant, getCanonicalBlockByRoot, onExecutionPayload, notifyPtcMessages
- `proto_array.zig` — full proto-array: onBlock, findHead, applyScoreChanges, prune, execution status, data availability, ePBS status started
- `compute_deltas.zig` — vote weight computation
- `store.zig` — checkpoint tracking
- `vote_tracker.zig` — per-validator vote tracking

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Safe blocks logic | `safeBlocks.ts` | Critical for devnet | 2 days |
| Structured error types | `errors.ts` | Production | 2 days |
| Fork choice metrics | `metrics.ts` | Production | 1 week |
| Fork choice store persistence | `archiveStore/` | Production | 1 week |
| Interface abstraction | `interface.ts` | Nice-to-have | 2 days |

**Priority:** Critical — fork choice is core to devnet  
**Effort:** 2-3 weeks to harden + missing pieces  
**PR:** #246 (WIP) on main branch  
**Devnet blocker:** Yes — core logic present but needs testing

---

### 5. Validator Client (`packages/validator/src/` → `src/validator/`)

**Status: 🟠 Partial (55%)** *(NEW — was ❌ None in gist)*

**What's implemented (17 files, 5,199 LOC) — added today:**
- `validator.zig` — top-level validator orchestrator
- `api_client.zig` — HTTP API client for BN REST endpoints
- `attestation_service.zig` — attestation duties, creation, aggregation
- `block_service.zig` — block proposal duties, production
- `sync_committee_service.zig` — sync committee participation + aggregation
- `chain_header_tracker.zig` — SSE subscription for chain head tracking
- `validator_store.zig` — in-memory key/state management
- `doppelganger.zig` — duplicate validator detection
- `remote_signer.zig` — Web3Signer HTTP client stub
- `keystore.zig` — **EIP-2335 keystore decryption** (new today)
- `slashing_protection_db.zig` — SQLite-backed slashing protection
- `interchange.zig` — EIP-3076 interchange format
- `signing.zig` — BLS signing with domain separation
- `prepare_beacon_proposer.zig` — fee recipient registration
- `clock.zig` — slot/epoch timing
- `types.zig` — VC type definitions

**What's missing vs TS:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Slashing protection surround vote detection | `minMaxSurround/` | Critical for safety | 1 week |
| External signer sync | `externalSignerSync.ts` | Production | 3 days |
| Genesis fetching | `genesis.ts` | Critical | 2 days |
| Validator indices tracking | `services/indices.ts` | Critical | 2 days |
| Syncing status tracker | `syncingStatusTracker.ts` | Important | 2 days |
| Full interchange formats (v5) | `interchange/formats/v5.ts` | Production | 3 days |
| Validator metrics | `metrics.ts` | Production | 1 week |
| VC DB repos | `repositories/` | Production | 3 days |
| Liveness tracking | Part of duties | Nice-to-have | 3 days |
| Committee selection aggregation | `beacon_committee_selections` | Devnet (MEV) | 1 week |
| Sync committee selections | `sync_committee_selections` | Devnet (MEV) | 1 week |
| Full Web3Signer impl | `remoteSignerSync.ts` | Production | 1 week |

**Priority:** Critical — needed to run validators  
**Effort:** 3-4 weeks for production-ready VC  
**Devnet blocker:** Can use external TS VC with Zig BN for initial devnet

---

### 6. Networking / P2P (`packages/beacon-node/src/network/` → `src/networking/`)

**Status: 🟠 Partial (45%)**

**TS files:** 89 | **Zig files:** 25 | **Zig LOC:** 10,156

**What's implemented:**
- P2P service core: init, start, stop, dial, publishGossip, subscribeSubnet (via `zig-libp2p` — **QUIC transport**)
- Gossip: topic construction, Snappy decompression, SSZ decode, validation, metadata
- Req/Resp: stream handling, Snappy framing + SSZ encode, dispatch, protocol IDs, Status/Goodbye/Ping/Metadata messages, varint encoding
- Peer management: connected/dialing/banned peers, heartbeat, scoring
- Peer DB: state persistence
- Scoring: reputation scoring
- Discovery: full discv5 implementation (13 files), ENR management, bootnode seeding, subnet queries
- Connection management
- ETH2 protocol constants

**What's missing vs TS:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| TCP transport | `libp2p/` | **Critical** — QUIC may not be universal | 2 weeks |
| Gossipsub detailed scoring params | `scoringParameters.ts` | Critical | 1 week |
| Gossipsub metrics | `gossip/metrics.ts` | Production | 1 week |
| Req/resp rate limiting | `reqresp/rateLimit.ts` | Production | 1 week |
| Req/resp peer scoring | `reqresp/score.ts` | Production | 1 week |
| Attestation subnet service | `peers/subnets/attnetsService.ts` | Critical | 1 week |
| Sync subnet service | `peers/subnets/syncnetsService.ts` | Critical | 1 week |
| Multi-component peer scoring | `peers/score/` (5 files) | Critical | 1 week |
| Peer datastore persistence | `peers/datastore.ts` | Production | 3 days |
| Network processor (async pipeline) | `processor/` | Critical | 2 weeks |
| Light client req/resp handlers | `handlers/lightClient*.ts` (5 handlers) | Production | 1 week |
| Data column req/resp | `handlers/dataColumnSidecarsByRange/Root.ts` | Fulu | 1 week |
| Execution payload envelope req/resp | `handlers/executionPayloadEnvelope*.ts` | ePBS | 1 week |
| Protocol version negotiation | `forks.ts` | Critical | 3 days |
| Network events | `events.ts` | Critical | 3 days |
| Req/resp handlers (beacon blocks) | Both implemented (range + root) | ✅ Done | — |
| Blob sidecar req/resp handlers | `handlers/blobSidecarsByRange/Root.ts` | Critical (Deneb) | 1 week |

**Transport note:** lodestar-z uses QUIC (via `zig-libp2p`); TS Lodestar uses TCP+Noise+Mplex. TCP transport must be added for cross-client compatibility.

**Priority:** Critical — essential for devnet  
**Effort:** 4-6 weeks for production networking  
**Devnet blocker:** Yes — basic gossip/reqresp works in integration tests but TCP + full pipeline needed

---

### 7. Beacon API (`packages/api/` + `packages/beacon-node/src/api/` → `src/api/`)

**Status: 🟠 Partial (40%)**

**TS files:** 71 | **Zig files:** 18 | **Zig LOC:** 4,956

**What's implemented:**
- HTTP server with content negotiation (JSON + SSZ binary)
- Route table with path parameter extraction
- Event bus (SSE streaming)
- Handlers: beacon (genesis, headers, blocks, states, pool counts), config (spec, fork_schedule), debug (states, heads), events (SSE), node (identity, version, syncing, health, peers, peer_count), validator (proposer/attester/sync duties)

**Routes implemented (33 total):**
- GET /eth/v1/beacon/genesis ✅
- GET /eth/v1/beacon/headers/{block_id} ✅
- GET /eth/v2/beacon/blocks/{block_id} ✅
- GET /eth/v2/beacon/states/{state_id}/validators ✅
- GET /eth/v2/beacon/states/{state_id}/validators/{validator_id} ✅
- GET /eth/v1/beacon/states/{state_id}/root ✅
- GET /eth/v1/beacon/states/{state_id}/fork ✅
- GET /eth/v1/beacon/states/{state_id}/finality_checkpoints ✅
- POST /eth/v2/beacon/blocks ✅
- Pool count endpoints (5×) ✅
- Validator duty endpoints (3×) ✅
- Config endpoints (2×) ✅
- Debug endpoints (2×) ✅
- SSE events (4 event types) ✅
- Node endpoints (6×) ✅

**What's missing (critical for devnet with VC):**

| Gap | Priority | Effort |
|-----|----------|--------|
| POST /eth/v1/beacon/pool/attestations | Critical | 2 days |
| POST /eth/v1/beacon/pool/voluntary_exits | Critical | 1 day |
| POST /eth/v1/beacon/pool/proposer_slashings | Critical | 1 day |
| POST /eth/v1/beacon/pool/attester_slashings | Critical | 1 day |
| POST /eth/v1/beacon/pool/bls_to_execution_changes | Critical | 1 day |
| GET /eth/v1/beacon/states/{id}/committees | Critical | 2 days |
| GET /eth/v1/beacon/states/{id}/sync_committees | Critical | 2 days |
| GET /eth/v1/beacon/states/{id}/randao | Critical | 1 day |
| GET+POST /eth/v1/validator/blocks (produce block) | Critical | 3 days |
| GET /eth/v1/validator/attestation_data | Critical | 2 days |
| GET /eth/v1/validator/aggregate_attestation | Critical | 2 days |
| POST /eth/v1/validator/aggregate_and_proofs | Critical | 2 days |
| POST /eth/v1/validator/sync_committee_contributions | Critical | 2 days |
| POST /eth/v1/validator/contribution_and_proofs | Critical | 2 days |
| POST /eth/v1/validator/prepare_beacon_proposer | Important | 1 day |
| POST /eth/v1/validator/register_validator | MEV-boost | 2 days |
| GET /eth/v1/beacon/blob_sidecars/{id} | Critical (Deneb) | 2 days |
| All lightclient API endpoints | Production | 2 weeks |
| All proof API endpoints | Production | 1 week |
| All keymanager API endpoints | Production | 2 weeks |
| All builder API endpoints | MEV | 2 weeks |
| Rewards API (4+ endpoints) | Production | 1 week |
| Lodestar custom endpoints | Production | 1 week |

**Priority:** High — VC API subset needed for devnet  
**Effort:** Minimal devnet subset: 2-3 weeks; Full parity: 6-8 weeks  
**Devnet blocker:** Yes — pool submission + attestation data + produce block endpoints missing

---

### 8. Database (`packages/db/` + `packages/beacon-node/src/db/` → `src/db/`)

**Status: 🟠 Partial (50%)**

**TS files:** 36 (combined) | **Zig files:** 10 | **Zig LOC:** 2,384

**What's implemented:**
- KV store abstraction interface
- LMDB-backed persistent storage (via raw LMDB bindings) — **redesigned today** using named databases instead of bucket prefixes
- In-memory KV store for testing
- Beacon DB with 30+ functions: blocks, block archive, state archive, blob sidecars, data columns, fork choice, validator index, chain info, op pool items
- Bucket system (30+ bucket prefixes)
- Tests for all backends

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Backfilled ranges tracking | `backfilledRanges.ts` | Production | 2 days |
| Block archive secondary index | `blockArchiveIndex.ts` | Production | 2 days |
| State archive secondary index | `stateArchiveIndex.ts` | Production | 2 days |
| Light client DB repos | `lightclientBestUpdate.ts` × 3 | Production | 3 days |
| Execution payload envelope storage | `executionPayloadEnvelope.ts` | ePBS | 2 days |
| DB schema migrations | Level DB controller pattern | Production | 1 week |
| Hot/cold DB formal split | Implicit in TS | Production | 1 week |

**Priority:** Medium — current coverage sufficient for devnet  
**Effort:** 2-3 weeks for production parity  
**Devnet blocker:** No

---

### 9. Sync (`packages/beacon-node/src/sync/` → `src/sync/`)

**Status: 🟠 Partial (55%)**

**TS files:** 24 | **Zig files:** 11 | **Zig LOC:** 3,874

**What's implemented:**
- `sync_service.zig` — top-level coordinator (onPeerStatus, onPeerDisconnect, tick, isSynced)
- `range_sync.zig` — range-based sync (addPeer, removePeer, tick, onBatchResponse, onBatchError)
- `sync_chain.zig` — chain-specific sync state machine
- `batch.zig` — batch request/response tracking
- `checkpoint_sync.zig` — full checkpoint sync (state + blocks from trusted API)
- `unknown_block.zig` — unknown parent block sync (addPendingBlock, tick, onParentFetched, markBad)
- `unknown_chain/` — backwards chain walking

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Backfill sync | `backfill/backfill.ts` (4 files) | Production | 2 weeks |
| Range sync peer balancer | `range/utils/peerBalancer.ts` | Production | 3 days |
| Sync metrics | Various | Production | 1 week |
| Download retries robustness | More robust in TS | Production | 1 week |

**Priority:** Medium — checkpoint + range sync covers devnet  
**Effort:** 2-3 weeks for full parity  
**Devnet blocker:** No

---

### 10. Chain Pipeline (`packages/beacon-node/src/chain/` → `src/chain/`)

**Status: 🔴 Minimal (22%)**

**TS files:** 149 | **Zig files:** 16 | **Zig LOC:** 5,268

This is the largest gap. TS has a sophisticated multi-phase async pipeline.

**What's implemented:**
- `chain.zig` — importBlock, importAttestation, onSlot, onFinalized, getHead, produceBlock, archiveState, importBlobSidecar, advanceSlot
- `block_import.zig` — HeadTracker, basic block sanity verification
- `gossip_validation.zig` — validateGossipBlock, validateGossipAttestation, validateGossipAggregate, validateGossipDataColumnSidecar
- `produce_block.zig` — produceBlockBody, assembleBlock (phase0→electra attestation conversion)
- `op_pool.zig` — Attestation, VoluntaryExit, ProposerSlashing, AttesterSlashing, BlsChange pools
- `seen_cache.zig` — blocks, aggregators, exits, slashings, BLS changes, data columns
- `sync_contribution_pool.zig` — SyncContributionAndProofPool, SyncCommitteeMessagePool
- `validator_duties.zig` — getProposer, getAttestationDuty, getSyncCommitteeDuties
- `archive_store.zig`, `beacon_proposer_cache.zig`, `shuffling_cache.zig` — caches

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Full block verification pipeline | `blocks/verifyBlock*.ts` (8 files) | **Critical** | 3 weeks |
| Queued state regen | `regen/queued.ts`, `regen/regen.ts` | **Critical** | 2 weeks |
| Persistent checkpoints cache | `stateCache/persistentCheckpointsCache.ts` | **Critical** | 1 week |
| FIFO block state cache | `stateCache/fifoBlockStateCache.ts` | **Critical** | 1 week |
| Data availability verification | `blocks/verifyBlocksDataAvailability.ts` | **Critical** | 1 week |
| Execution payload verification | `blocks/verifyBlocksExecutionPayloads.ts` | **Critical** | 1 week |
| BLS batch verification integration | `bls/multithread/` | **Critical** | 1 week |
| Block input processing | `blocks/blockInput/` | Critical | 1 week |
| Archive store background jobs | `archiveStore/` (13 files) | Production | 2 weeks |
| Light client server | `lightClient/` | Production | 3 weeks |
| Aggregated attestation pool full | `opPools/aggregatedAttestationPool.ts` | Critical | 1 week |
| Prepare next slot | `prepareNextSlot.ts` | Important | 3 days |
| Reprocess queue | `reprocess.ts` | Important | 3 days |
| Structured error types | `errors/` (15 files) | Production | 1 week |
| Validator monitor | `validatorMonitor.ts` | Production | 1 week |
| Column reconstruction tracker | `ColumnReconstructionTracker.ts` | Fulu | 1 week |
| GetBlobs tracker | `GetBlobsTracker.ts` | Deneb | 1 week |
| ePBS payload pools | `opPools/payloadAttestationPool.ts`, etc. | Gloas | 2 weeks |

**Priority:** High — this is the biggest single gap  
**Effort:** 6-8 weeks for production-ready pipeline  
**Devnet blocker:** Partial — basic import works; full verification pipeline is needed for correctness

---

### 11. Execution Engine (`packages/beacon-node/src/execution/` → `src/execution/`)

**Status: 🟠 Partial (55%)**

**TS files:** 16 | **Zig files:** 7 | **Zig LOC:** 3,995

**What's implemented:**
- `engine_api.zig` — EngineAPI interface
- `http_engine.zig` — HTTP JSON-RPC client for EL
- `json_rpc.zig` — JSON-RPC types
- `engine_api_types.zig` — all payload types (phase0→electra)
- `mock_engine.zig` — mock for testing
- `payload_id_cache.zig` — payload ID caching

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Builder/MEV-boost integration | `builder/` (5 files) | Production | 2 weeks |
| JWT expiry rotation | `engine/jwt.ts` | Important | 2 days |
| engineGetPayloadV3/V4 full impl | Part of engine | Critical | 3 days |
| Execution engine metrics | Implicit | Production | 1 week |
| Payload type validation | `engine/utils.ts` | Important | 3 days |

**Priority:** High — EL integration essential for devnet  
**Effort:** 1-2 weeks for devnet; 3-4 weeks for production  
**Devnet blocker:** Partial — HTTP engine works; V3 tested; JWT and MEV-boost missing

---

### 12. Light Client (`packages/light-client/` → N/A)

**Status: ❌ None (0%)**

**TS files:** 27 | **TS LOC:** 1,920 | **Zig files:** 0

TS Lodestar has:
- Full light client consumer (validateUpdate, store, transport)
- Light client server (update production from beacon node)
- Prover (EIP-1193 verified request infrastructure)
- State transition light client helpers (processLightClientUpdate, etc.)
- Req/resp handlers: bootstrap, finalityUpdate, optimisticUpdate, updatesByRange

**Priority:** Medium — not needed for devnet, important for production  
**Effort:** Light client consumer: 3-4 weeks; Server: 2 weeks; Prover: 4-6 weeks  
**Devnet blocker:** No

---

### 13. Types (`packages/types/src/` → `src/consensus_types/` + `src/fork_types/`)

**Status: 🟡 Substantial (85%)**

**TS files:** 38 | **TS LOC:** 3,985 | **Zig files:** 20 | **Zig LOC:** 4,562

**What's implemented:**
- `consensus_types/`: phase0, altair, bellatrix, capella, deneb, electra, fulu types
- `fork_types/`: AnyBeaconBlock, AnyBeaconState, AnyExecutionPayload, block_type, fork_types
- Primitive types

**What's missing:**
- Gloas types (ePBS) — `isValidIndexedPayloadAttestation`, `PayloadAttestation`, etc.
- Heze types (future fork)
- Some TypeScript-specific utility types (mapping types, etc.) have no Zig equivalent needed

**Priority:** Low  
**Effort:** Gloas types: 1 week when needed

---

### 14. Config/Params (`packages/params/` + `packages/config/` → `src/config/` + `src/preset/` + `src/constants/`)

**Status: 🟡 Substantial (80%)**

**TS files:** 34 | **TS LOC:** 3,170 | **Zig files:** 14 | **Zig LOC:** 1,793

**What's implemented:**
- `BeaconConfig.zig`, `ChainConfig.zig`
- Config loader (YAML-based)
- Fork sequence
- Networks: mainnet, minimal, sepolia, gnosis, chiado, hoodi
- Presets: mainnet, minimal (compile-time)
- All spec constants

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Gnosis preset | `presets/gnosis.ts` | Production | 2 days |
| Dynamic preset loading | `setPreset.ts` | Nice-to-have | 2 days |
| Ephemery network | `chainConfig/networks/ephemery.ts` | Nice-to-have | 1 day |
| Genesis config loading | `genesisConfig/` | Important | 3 days |

**Priority:** Low  
**Effort:** 1 week

---

### 15. Logger (`packages/logger/` → `src/log/`)

**Status: 🟡 Substantial (70%)** *(Upgraded from minimal in gist — major work added today)*

**TS files:** 12 | **TS LOC:** 744 | **Zig files:** 2 | **Zig LOC:** 1,165

**What's implemented (added today):**
- Structured logging framework with per-module log levels (5 levels: debug/info/warn/error/critical)
- Module enum (26 modules: chain, network, sync, db, api, validator, etc.)
- Console transport with color output
- **File transport** with size-based rotation + daily rotation
- `std.log` integration via `stdLogFn`
- GlobalLogger with thread-safe initialization

**What's missing:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| JSON structured output | `utils/json.ts` | Production | 3 days |
| Log level env var configuration | `env.ts` | Important | 2 days |
| Remote log shipping | Part of monitoring | Nice-to-have | 1 week |

**Priority:** Low — functional logging exists  
**Effort:** 1 week for full parity

---

### 16. DB Package (`packages/db/` → `src/db/`)

**Status: 🟡 Substantial (75%)**

The KV abstraction + LMDB backend exceeds the TS leveldb-based abstraction in some ways (LMDB is faster for reads). The repository pattern is the main gap — Zig uses flat functions instead of class-based repos.

---

### 17. Monitoring/Metrics

**Status: 🔴 Minimal (20%)**

**What's implemented:**
- `metrics.zig` — BeaconMetrics struct, basic slot/epoch/head metrics
- `metrics_server.zig` — HTTP `/metrics` endpoint (Prometheus format)
- STF metrics stub

**What's missing:**
- Per-module metrics (100+ missing metric definitions across chain, network, sync, db, validator)
- Network gossip/reqresp/peer metrics
- Chain block import / fork choice / state cache metrics
- DB read/write metrics
- Health check endpoint (monitoring package)
- Remote metrics push (monitoring/service.ts)

**Priority:** Medium  
**Effort:** 3-4 weeks for comprehensive metrics

---

### 18. Processor (Network Message Processor)

**Status: 🟠 Partial (50%)** *(New module — not in gist)*

**What's implemented (5 files, 2,090 LOC):**
- `processor.zig` — main processor
- `queues.zig` — typed work queues
- `work_item.zig` — work item types
- `work_queues.zig` — queue management

**What's missing vs TS `network/processor/`:**

| Gap | TS Source | Priority | Effort |
|-----|-----------|----------|--------|
| Gossip validator function | `gossipValidatorFn.ts` | Critical | 1 week |
| Aggregator tracker | `aggregatorTracker.ts` | Critical | 3 days |
| Extract slot/root functions | `extractSlotRootFns.ts` | Critical | 2 days |
| Indexed gossip queues | `gossipQueues/indexed.ts` | Critical | 1 week |

**Priority:** High  
**Effort:** 2-3 weeks

---

### 19. Testing Infrastructure

**Status: 🟡 Substantial (80%)**

**What's implemented (23 files, 6,825 LOC):**
- `sim_beacon_node.zig` — simulated beacon node
- `sim_network.zig` — simulated network layer
- `sim_cluster.zig` — multi-node cluster simulation
- `sim_test.zig`, `sim_fault_injection_test.zig`, `sim_network_partition_test.zig` — sim test suites
- `sim_forkchoice_test.zig` — fork choice simulation
- `block_import.zig`, `block_import_test.zig` — block import testing
- `node_integration_test.zig` — full node integration
- `attestation_generator.zig`, `block_generator.zig` — test data generators
- `cluster_invariant_checker.zig`, `invariant_checker.zig`, `dst_audit.zig` — invariant checking
- `head_tracker.zig`, `sim_clock.zig`, `sim_io.zig`, `sim_storage.zig`, `sim_node_harness.zig`, `sim_test_harness.zig`

**What's missing:**
- E2E tests against real EL clients
- Cross-client interop tests (Kurtosis-based)
- Fuzzing infrastructure

**Priority:** Medium  
**Effort:** Kurtosis integration: 2 weeks (separate `kurtosis-devnet` skill)

---

### 20. Data Availability (PeerDAS/Blobs/Columns)

**Status: 🔴 Minimal (20%)**

**What's implemented:**
- `process_blob_kzg_commitments.zig` — KZG commitment verification in block processing
- DB: putBlobSidecars, getBlobSidecars, putDataColumnSidecars, getDataColumnSidecars, individual column ops
- `gossip_validation.zig` — validateGossipDataColumnSidecar
- `seen_cache.zig` — data column tracking
- Chain: importBlobSidecar

**What's missing:**

| Gap | Priority | Effort |
|-----|----------|--------|
| KZG library (c-kzg or native) | **Critical** for Deneb/Fulu | 2 weeks |
| Blob/column reqresp handlers | **Critical** for Deneb | 1 week |
| Column reconstruction (PeerDAS) | **Critical** for Fulu | 2 weeks |
| Custody subnet management | **Critical** for Fulu | 1 week |
| DA verification in block pipeline | **Critical** for Deneb | 1 week |
| Data column sampling | Fulu | 2 weeks |

**Priority:** High for Fulu devnet; Medium for Deneb-only  
**Effort:** Full PeerDAS: 6-8 weeks; Deneb blobs: 2-3 weeks

---

### 21. CLI

**Status: 🔴 Minimal (15%)**

Zig has basic flags via `src/node/options.zig`. Missing subcommand architecture, config file, preset selection via CLI, key management commands, and migration system.

**Priority:** Low for devnet (flags sufficient); High for production  
**Effort:** 3-4 weeks for usable production CLI

---

### 22. Slasher

**Status: ❌ None (0%)**

**Priority:** Low — standalone component  
**Effort:** 4-6 weeks  
**Devnet blocker:** No

---

### 23. Key Management

**Status: 🔴 Minimal (15%)** *(upgraded — EIP-2335 keystore added today)*

**What's implemented:**
- `keystore.zig` — EIP-2335 keystore decryption (added today in validator client)

**What's missing:**
- Keymanager API (EIP-3042) endpoints
- Keystore import/export CLI
- Remote signer management API
- EIP-3076 full interchange implementation (partial in validator's interchange.zig)

**Priority:** Critical for running validators  
**Effort:** 3-4 weeks  
**Devnet blocker:** Only if running validators; external TS VC handles this

---

## Updated File/LOC Counts

### lodestar-z (feat/beacon-node branch)

| Module | Files | LOC |
|--------|-------|-----|
| state_transition | 111 | 13,611 |
| ssz | 31 | 14,173 |
| networking | 25 | 10,156 |
| node | 15 | 9,195 |
| testing | 23 | 6,825 |
| fork_choice | 6 | 6,286 |
| chain | 16 | 5,268 |
| validator | 17 | 5,199 |
| api | 18 | 4,956 |
| execution | 7 | 3,995 |
| sync | 11 | 3,874 |
| persistent_merkle_tree | 9 | 3,196 |
| discv5 | 13 | 3,379 |
| fork_types | 11 | 2,957 |
| bls | 12 | 2,130 |
| processor | 5 | 2,090 |
| db | 10 | 2,384 |
| log | 2 | 1,165 |
| consensus_types | 9 | 1,605 |
| config | 11 | 1,468 |
| hashing | 5 | 245 |
| preset | 2 | 208 |
| constants | 1 | 117 |
| **TOTAL** | **376** | **~105,413** |

### lodestar TypeScript (relevant packages only)

| Package | Files | LOC |
|---------|-------|-----|
| beacon-node | 412 | 62,113 |
| state-transition | 140 | 14,451 |
| fork-choice | 11 | 4,817 |
| validator | 57 | 7,063 |
| api | 71 | 9,281 |
| types | 38 | 3,985 |
| config | 24 | 1,979 |
| params | 10 | 1,191 |
| light-client | 27 | 1,920 |
| logger | 12 | 744 |
| db | 9 | 1,027 |
| **TOTAL (selected)** | **~811** | **~108,571** |

**Key insight:** lodestar-z is at 376 Zig files / 105k LOC vs TS's 811 files / 108k LOC for the selected packages. Zig achieves near-parity in LOC with fewer files because Zig is more expressive at the systems level (no runtime framework overhead, more compact types). However, ~70% of TS's beacon-node complexity (62k LOC) is in the chain pipeline and networking which are 22% and 45% implemented respectively.

---

## Critical Path to Devnet

### Minimum Viable Devnet (Deneb fork, external TS VC, Kurtosis)

Ordered by dependency and criticality:

**Week 1-2: Block pipeline hardening**
1. Chain: Queued state regen (`regen/`) — blocks can't be processed safely without it
2. Chain: Full block verification pipeline (sanity → signatures → DA → STF → execution → import)
3. Fork choice: Safe blocks logic + structured errors

**Week 2-3: Network + API**
4. Networking: TCP transport support (critical for cross-client interop)
5. Networking: Protocol version negotiation (`forks.ts` equivalent)
6. API: Pool submission endpoints (5× POST)
7. API: Block production endpoint (GET /eth/v1/validator/blocks)
8. API: Attestation data + aggregate endpoints

**Week 3-4: DA + Execution**
9. Data availability: KZG library integration (c-kzg)
10. Data availability: Blob sidecar req/resp handlers
11. DA verification in block pipeline
12. Execution: engineGetPayloadV3 full path validation

**Week 4-6: Hardening**
13. Networking: Gossipsub scoring parameters
14. Networking: Attestation + sync subnet service
15. Networking: Network processor pipeline
16. Fork choice: Persistence (store to DB)
17. Sync: Download robustness

**Estimated time to minimal devnet: 6-8 weeks** (parallelizable, 2-3 agents)

---

## Critical Path to Production

After devnet passes:

**Phase 2 (production hardening, 8-12 weeks):**
- Full validator client (slashing protection surround, interchange, indices, syncing tracker) — 3-4 weeks
- Complete API surface (all validator duty endpoints, rewards, committees) — 3-4 weeks
- Full networking (TCP, multi-component scoring, rate limiting, persistence) — 3-4 weeks
- Monitoring: comprehensive metrics across all modules — 3-4 weeks
- CLI: subcommand architecture, config file, key management — 3-4 weeks

**Phase 3 (Fulu/PeerDAS, 6-10 weeks):**
- Full PeerDAS column reconstruction, custody management, data column sampling
- Fulu fork support in state transition (Gloas types, ePBS)
- Data column req/resp, data column gossip validation

**Phase 4 (ecosystem completeness, 6-10 weeks):**
- Light client consumer + server
- Keymanager API (EIP-3042)
- Builder API / MEV-boost
- Slasher
- Web3Signer full implementation
- E2E / cross-client testing via Kurtosis

**Total estimated time to production (all phases): 6-9 months** (assuming 2-3 full-time engineers)

---

## NAPI Bindings (Unique Zig Advantage)

lodestar-z has extensive NAPI bindings providing incremental value to TS Lodestar:
- `bindings/napi/` — state_transition, shuffle, pubkeys, blst, config, pool, metrics, BeaconStateView
- These allow accelerating TS Lodestar with Zig implementations before standalone BN is ready
- **Unique strength not reflected in the above gap analysis**

---

*Analysis completed: 2026-03-27*  
*Branch analyzed: feat/beacon-node (lodestar-z-reqresp-wire)*  
*Compared against: https://github.com/ChainSafe/lodestar (main, depth=1 clone)*
