# Deep Functional Delta Analysis v2: lodestar-z vs Lodestar (TypeScript)

*Generated: 2026-03-27 post-speedrun — Branch: feat/beacon-node (lodestar-z-reqresp-wire)*
*Compared against: Lodestar main (depth=1 clone at ~/lodestar-ts)*

---

## Methodology

This is NOT a file-count comparison. For each subsystem:
1. Read the actual Zig implementation — what does it DO?
2. Read the actual TS implementation — what does IT do?
3. Identify *behavioral* gaps — not "file X is missing" but "behavior Y is not implemented"

Codebase size at analysis time: **403 Zig files / 116,259 LOC** vs **~811 TS files / ~108,571 LOC** (selected packages).

---

## 1. Chain Pipeline

**Status**: 🟠 42% functional
**TS LOC**: ~24,069 (chain/) | **Zig LOC**: 9,454 (chain/)

### What works end-to-end
- **Full block import pipeline** exists in two forms:
  - Legacy monolithic `chain.importBlock()` — works for electra blocks specifically, hardcoded to `SignedBeaconBlock.Type`
  - New staged pipeline (`blocks/pipeline.zig`) — 6-stage design: sanity → pre-state → DA → STF → execution → import. Properly abstracted via `BlockInput` / `AnySignedBeaconBlock`
- **State transition integration**: processSlots → processBlock with batch BLS verification works. State root is verified against the block's state_root field after STFN
- **Fork choice integration**: Blocks are wired into the proto-array DAG with justified/finalized checkpoints extracted from post-state
- **Block persistence**: Blocks serialized and stored in BeaconDB before fork choice (correct ordering)
- **Epoch boundary caching**: Checkpoint states cached via StateRegen/QueuedStateRegen at epoch transitions
- **Head tracking**: HeadTracker updated on every imported block
- **SSE events**: block/head/finalized_checkpoint events emitted
- **Queued state regen**: Full implementation with priority queuing (block_import > fork_choice > api > background), deduplication by RegenKey, fast-path cache lookup, slow-path regen — mirrors TS QueuedStateRegenerator
- **Prepare next slot**: Pre-computes state for slot N+1 at 2/3 slot mark to reduce block processing latency
- **Reprocess queue**: Blocks arriving before their parent are queued by parent_root and re-triggered on import (PendingReason: unknown_parent, data_availability_pending, early_block)
- **Op pools**: Attestation, VoluntaryExit, ProposerSlashing, AttesterSlashing, BlsChange, SyncContribution, SyncCommitteeMessage pools all exist with add/get/prune
- **Gossip validation (Phase 1)**: validateGossipBlock, validateGossipAttestation, validateGossipAggregate, validateGossipDataColumnSidecar — lightweight timing/bounds/duplicate checks
- **Seen caches**: Blocks, aggregators, exits, slashings, BLS changes, data columns tracked
- **Block production**: produceBlockBody + assembleBlock with phase0→electra attestation conversion
- **Data availability manager**: Unified DA layer coordinating BlobTracker, ColumnTracker, KZG verification, column reconstruction

### Functional gaps (ordered by severity)

1. 🔴 **[Critical] No fork-aware block import** — `chain.importBlock()` is hardcoded to `electra.SignedBeaconBlock.Type`. The new pipeline uses `AnySignedBeaconBlock` but the legacy path (which is what the beacon node actually calls) only handles electra. Pre-electra blocks would fail. *Impact: devnet with non-electra genesis would break.*

2. 🔴 **[Critical] No attestation import into fork choice during block import** — TS `importBlock.ts` iterates over every attestation in a block and calls `forkChoice.onAttestation()` for each indexed attestation. The Zig `import_block.zig` does NOT do this. Fork choice weights from in-block attestations are lost. *Impact: Fork choice would be severely degraded — head selection relies on attestation weights.*

3. 🔴 **[Critical] No attester slashing import during block import** — TS imports attester slashings from blocks into fork choice via `forkChoice.onAttesterSlashing()`. Missing in Zig. *Impact: Equivocating validators' weight not removed from fork choice.*

4. 🔴 **[Critical] No forkchoiceUpdated notification to EL after import** — TS calls `executionEngine.notifyForkchoiceUpdate()` after head/finality changes. Missing in Zig. *Impact: EL won't track the canonical head, can't produce payloads.*

5. 🟡 **[Important] No head recomputation after block import** — TS calls `this.recomputeForkChoiceHead()` after importing attestations/slashings. Zig pipeline reads the current FC head but doesn't recompute. The head is only updated when `getHead()` is explicitly called with new balances. *Impact: Head state won't update until next explicit head recomputation.*

6. 🟡 **[Important] No chain reorg detection/events** — TS detects when newHead != oldHead and emits `chainReorg` events with depth calculation via `getCommonAncestorDepth()`. Missing in Zig. *Impact: No reorg metrics, no reorg event stream.*

7. 🟡 **[Important] Missing gossip validation for 8+ message types** — Zig has 4 validators (block, attestation, aggregate, data_column). TS has 14+ (adds: blob_sidecar, voluntary_exit, proposer_slashing, attester_slashing, bls_to_execution_change, sync_committee, sync_committee_contribution, light_client_finality_update, light_client_optimistic_update, payload_attestation_message, execution_payload_bid, execution_payload_envelope). *Impact: Unvalidated messages could poison the op pool or propagate invalid data.*

8. 🟡 **[Important] No validator monitor** — TS's `validatorMonitor.ts` (1,375 LOC) tracks attestation performance, block proposals, sync committee participation. Missing in Zig. *Impact: No observability into validator performance.*

9. 🟡 **[Important] Block input abstraction incomplete** — TS has a sophisticated `blockInput/blockInput.ts` (1,005 LOC) that handles PreData blocks, waits for data availability with timeout, tracks blob/column sources. Zig's `BlockInput` in the pipeline is a simpler struct without the async data waiting. *Impact: Can't handle blocks arriving before their blobs on gossip.*

10. 🟡 **[Important] No aggregated attestation pool** — TS's `aggregatedAttestationPool.ts` (889 LOC) is the sophisticated structure that tracks aggregation coverage per committee and packs optimal attestations into blocks. Zig's `op_pool.attestation_pool` is a simple list. *Impact: Blocks produced would have suboptimal attestation packing, lower rewards.*

11. 🟢 **[Nice-to-have] No light client server** — TS `chain/lightClient/` produces light client updates from beacon node. Missing entirely. *Impact: No light client support.*

12. 🟢 **[Nice-to-have] No shuffling cache integration** — TS caches shufflings at epoch boundaries and uses them for indexed attestation computation. Zig's `shuffling_cache.zig` exists but isn't wired into block import.

### Code quality observations
- The pipeline design (`blocks/pipeline.zig`) is architecturally cleaner than the TS monolith — 6 explicit stages with clear data flow
- Two import paths exist (legacy `chain.importBlock` and new `processBlockPipeline`) which will cause confusion — needs consolidation
- `chain.zig` at 715 LOC is manageable vs TS's `chain.ts` at 1,620 LOC — but TS does more work per import

---

## 2. Fork Choice

**Status**: 🟡 65% functional
**TS LOC**: 4,817 (fork-choice/) | **Zig LOC**: 6,286 (fork_choice/)

### What works end-to-end
- **Proto-array DAG**: Full implementation — onBlock, findHead, applyScoreChanges, prune, execution status tracking. 4,567 LOC in `proto_array.zig` alone (vs 1,836 in TS) — Zig version includes Gloas ePBS dual-node support
- **Weight computation**: `computeDeltas()` correctly computes vote weight changes from old→new balances with equivocating indices removal
- **Vote tracking**: Per-validator SoA (Structure of Arrays) vote tracking with target epoch monotonicity
- **Proposer boost**: setProposerBoost/clearProposerBoost with score injection
- **Equivocation handling**: onAttesterSlashing marks validators; their weight excluded from delta computation
- **Checkpoint management**: justified, finalized, best_justified, unrealized_justified, unrealized_finalized all tracked
- **Execution validation**: validateLatestHash propagates EL validity responses through the DAG
- **Head computation**: getHead orchestrates computeDeltas → applyScoreChanges → findHead pipeline
- **Pruning**: maybePrune removes nodes below finalized root
- **Ancestry queries**: isDescendant, getCanonicalBlockByRoot, iterateAncestors
- **Gloas ePBS**: onExecutionPayload creates FULL variant nodes, notifyPtcMessages for PTC votes — this is AHEAD of where many clients are

### Functional gaps (ordered by severity)

1. 🟡 **[Important] No safe blocks computation** — TS has `safeBlocks.ts` with `getSafeBeaconBlockRoot()` and `getSafeExecutionBlockHash()` per spec. Missing in Zig. Simple 2-function file but critical for EL fork choice updates. *Impact: Can't compute safe block hash for forkchoiceUpdated calls.*

2. 🟡 **[Important] No shouldOverrideForkChoiceUpdate** — TS has proposer-boost reorg logic that suppresses FCU when the current head is a weak block that the local proposer could reorg. Missing in Zig. *Impact: Lost MEV opportunity from proposer-boost reorgs, but not blocking for devnet.*

3. 🟡 **[Important] No getDependentRoot** — TS computes dependent roots for duty epochs (previous/current). Used for head events and validator duty recalculation. Missing in Zig.

4. 🟡 **[Important] No structured error types** — TS has `ForkChoiceErrorCode` enum with 17 error variants carrying detailed context. Zig uses bare `error.InvalidBlock` / `error.InvalidAttestation`. *Impact: Callers can't distinguish between different failure modes.*

5. 🟢 **[Nice-to-have] No fork choice metrics** — TS has `metrics.ts` tracking node count, reorgs, head changes. Missing.

6. 🟢 **[Nice-to-have] No getCommonAncestorDepth** — Used for reorg depth detection. Missing but not blocking.

### Code quality observations
- Proto-array is exceptionally thorough — more LOC than TS because it includes the full Gloas ePBS dual-node architecture
- The SoA vote tracking (separate arrays for current_indices, next_indices, current_slots, next_slots) is cache-friendly — good design
- Missing the `IForkChoice` interface abstraction, but Zig's comptime generics make this less necessary

---

## 3. Networking / P2P

**Status**: 🟠 50% functional
**TS LOC**: ~13,998 (network/) | **Zig LOC**: 11,692 (networking/)

### What works end-to-end
- **P2P service core**: Full `P2pService` with init/start/stop/dial, built on `zig-libp2p` with **QUIC transport**
- **Gossip**: Topic construction per-fork, Snappy decompression, SSZ decode, 4 validation functions, metadata
- **Req/resp**: Full stream handling with Snappy framing, SSZ encode/decode, protocol dispatch. Supports: Status, Goodbye, Ping, Metadata, BeaconBlocksByRange, BeaconBlocksByRoot
- **Peer management**: Connected/dialing/banned peer tracking, heartbeat, scoring
- **Peer DB**: Persistent peer state
- **Scoring**: Reputation scoring with gossipsub v1.1 parameters (TopicScoringParams, PeerScoringParams fully defined with correct Ethereum-specific weights)
- **Discovery**: Full discv5 implementation (13 files), ENR management, bootnode seeding, subnet queries
- **Connection manager**: Max peer limits, connection lifecycle
- **Rate limiter**: Per-peer request rate limiting with quota tracking (655 LOC)
- **Subnet service**: Attestation subnet subscription management
- **Column subnet service**: PeerDAS column custody subnet management (465 LOC)
- **Status cache**: Cached chain status for req/resp exchanges
- **Varint encoding**: Used for req/resp length-prefix framing

### Functional gaps (ordered by severity)

1. 🔴 **[Critical] QUIC-only transport** — lodestar-z uses QUIC exclusively. Most consensus clients currently use TCP+Noise+Mplex. While QUIC is the future (and spec'd), some clients may not support it yet. *Impact: May not connect to all peers on devnet. Cross-client interop risk.*

2. 🔴 **[Critical] Missing req/resp protocols** — Only Status/Goodbye/Ping/Metadata/BeaconBlocksByRange/BeaconBlocksByRoot are implemented. Missing: BlobSidecarsByRange, BlobSidecarsByRoot (critical for Deneb), DataColumnSidecarsByRange, DataColumnSidecarsByRoot (critical for Fulu), LightClientBootstrap/Update/FinalityUpdate/OptimisticUpdate. *Impact: Can't sync blobs, can't serve blob requests.*

3. 🔴 **[Critical] No gossip handlers for the network processor** — TS has `gossipHandlers.ts` (1,074 LOC) that routes each gossip message type to the chain for validation and import. Zig's `gossip_handler.zig` (962 LOC) exists in the node module but the chain-level integration (decode → validate → import → FC) may not be complete for all message types.

4. 🟡 **[Important] No network processor pipeline** — TS has `network/processor/` (520 LOC index + gossip handlers + queues) that prioritizes, batches, and dispatches gossip messages to the chain. Zig's `processor/` module (2,090 LOC) exists with typed work queues but the full dispatch loop connecting gossip → validation → chain may not be wired.

5. 🟡 **[Important] Multi-component peer scoring incomplete** — TS has 5 files in `peers/score/` (score.ts, store.ts, constants.ts, interface.ts, utils.ts) with detailed per-component scoring (gossip, reqresp, liveness). Zig's `peer_scoring.zig` is simpler — may not cover all scoring events.

6. 🟡 **[Important] No peer prioritization** — TS's `prioritizePeers.ts` intelligently selects which peers to connect/disconnect based on subnet coverage, scores, and diversity. Missing in Zig.

7. 🟡 **[Important] No peer relevance assertion** — TS's `assertPeerRelevance.ts` checks if a peer's status is compatible before syncing. Missing in Zig.

8. 🟡 **[Important] No protocol version negotiation** — TS's `forks.ts` determines which req/resp protocol versions to use based on fork epoch. Needed for cross-fork handshakes.

9. 🟢 **[Nice-to-have] No gossip metrics** — TS tracks message counts, validation times, propagation delay per topic.

### Code quality observations
- The scoring_parameters.zig is well-structured with correct Ethereum-specific gossipsub v1.1 parameters
- Rate limiter is a good addition that TS added relatively late
- Column subnet service shows PeerDAS awareness — forward-looking
- zig-libp2p dependency is a strength (native QUIC) but also a risk (less battle-tested than js-libp2p)

---

## 4. State Transition

**Status**: ✅ 85% functional
**TS LOC**: 14,451 (state-transition/) | **Zig LOC**: 13,611 (state_transition/)

### What works end-to-end
- **All 22 block processing functions** phase0→fulu: process_block_header, process_randao, process_eth1_data, process_operations (attestations, deposits, voluntary_exits, proposer_slashings, attester_slashings, bls_to_execution_changes, sync_aggregate, execution_payload, withdrawals, deposit_requests, withdrawal_requests, consolidation_requests)
- **All 20 epoch processing functions** across all forks: process_justification_and_finalization, process_inactivity_updates, process_rewards_and_penalties, process_registry_updates, process_slashings, process_eth1_data_reset, process_effective_balance_updates, process_slashings_reset, process_randao_mixes_reset, process_historical_roots_update, process_participation_flag_updates, process_sync_committee_updates, process_pending_deposits, process_pending_consolidations
- **6 fork upgrade functions**: phase0→altair→bellatrix→capella→deneb→electra→fulu
- **Full cache system**: epoch_cache, epoch_transition_cache, pubkey_cache, root_cache, effective_balance_increments, slashings_cache, state_cache, sync_committee_cache, block_state_cache, checkpoint_state_cache, state_regen, datastore
- **All 6 signature sets**: proposer, randao, indexed_attestation, proposer_slashings, bls_to_execution_change, voluntary_exits
- **22 utility files**: shuffle, seed, domain, signing_root, epoch_shuffling, committee_indices, etc.
- **Full spec test framework**: Downloads, generates, and runs consensus-spec test vectors
- **Spec test passing for phase0→fulu presets** (minimal at minimum)

### Functional gaps (ordered by severity)

1. 🟡 **[Important] No Gloas fork support** — upgradeStateToGloas, processPayloadAttestation, processExecutionPayloadBid/Envelope, processBuilderPendingPayments all missing. *Impact: Can't run Gloas devnets.*

2. 🟡 **[Important] No reward cache** — TS's `rewardCache.ts` caches reward computations for the rewards API. Missing. *Impact: Rewards API endpoint would be slow.*

3. 🟡 **[Important] No light client helpers** — State transition light client proof generation missing.

4. 🟢 **[Nice-to-have] Heze fork not started** — Future fork, not blocking anything.

### Code quality observations
- Near parity with TS in both LOC and functionality — spec-tested means high confidence
- The comptime fork dispatch (`inline else => |f|`) is elegant and ensures all forks share verified code paths
- Cache management is comprehensive — matches TS's cache hierarchy

---

## 5. Sync

**Status**: 🟡 60% functional
**TS LOC**: ~6,083 (sync/) | **Zig LOC**: 3,874 (sync/)

### What works end-to-end
- **Sync service**: Top-level coordinator (onPeerStatus, onPeerDisconnect, tick, isSynced)
- **Range sync**: addPeer/removePeer/tick/onBatchResponse/onBatchError, finalized chain + head chains, peer grouping by status
- **Sync chains**: Full state machine per chain target — awaiting_peers → syncing → head → idle
- **Batch management**: Request/response tracking per batch, retry on error
- **Checkpoint sync**: Full implementation — downloads state + blocks from trusted API, initializes chain
- **Unknown block sync**: addPendingBlock/tick/onParentFetched/markBad for blocks with unknown parents
- **Backwards chain walking**: `unknown_chain/` — follows parent chain backwards when a gossip block arrives before its ancestors

### Functional gaps (ordered by severity)

1. 🟡 **[Important] No backfill sync** — TS has `backfill/` (4 files) for downloading historical blocks after checkpoint sync. Missing in Zig. *Impact: After checkpoint sync, historical blocks unavailable for API queries. Not blocking for devnet.*

2. 🟡 **[Important] No peer balancer** — TS's `peerBalancer.ts` distributes batch requests across peers for fairness and throughput. Missing.

3. 🟡 **[Important] No download utilities** — TS has `downloadByRange.ts` and `downloadByRoot.ts` with retry logic, timeout handling, response validation. Zig sync relies on callback vtables (RangeSyncCallbacks) which abstract this but the actual download implementation quality is unclear.

4. 🟢 **[Nice-to-have] No sync metrics** — TS tracks batch download times, chain status, peer counts.

5. 🟢 **[Nice-to-have] No pending blocks tree** — TS's `pendingBlocksTree.ts` organizes unknown blocks into a tree structure for efficient parent chain traversal.

### Code quality observations
- Callback vtable pattern (RangeSyncCallbacks, SyncChainCallbacks) is clean for testability
- Unknown chain sync with backwards walking is a sophisticated feature — good to see it implemented
- Checkpoint sync being complete is excellent for devnet bootstrapping

---

## 6. Execution Engine

**Status**: 🟡 65% functional
**TS LOC**: ~3,000 (execution/) | **Zig LOC**: 5,333 (execution/)

### What works end-to-end
- **Full EngineApi vtable interface**: Covers newPayloadV1-V4, forkchoiceUpdatedV1-V3, getPayloadV1-V4, getBlobsV1, exchangeCapabilities
- **HTTP JSON-RPC client**: With pluggable transport (MockTransport for tests, real HTTP for production)
- **JWT authentication**: HS256 token generation per-request using std.crypto — correct IAT claim, 60-second expiry
- **All payload types**: ExecutionPayloadV1 through V4, PayloadAttributes V1-V3, ForkchoiceState, GetPayloadResponse variants
- **Payload ID cache**: Caches payload IDs from forkchoiceUpdated for subsequent getPayload calls
- **Mock engine**: Full mock implementation for testing — accepts all payloads, returns deterministic responses
- **Engine state machine**: online/offline/syncing/auth_failed states with transitions
- **Retry configuration**: Configurable retries with exponential backoff
- **Builder API stub**: MEV-boost interface defined (types, vtable) but not implemented — all methods return NotImplemented
- **KZG library**: Full c-kzg integration via Zig bindings — blobToCommitment, computeBlobProof, verifyBlobProof, verifyBlobProofBatch, computeCellsAndProofs, recoverCellsAndProofs, verifyCellProofBatch

### Functional gaps (ordered by severity)

1. 🟡 **[Important] No actual HTTP transport wired** — The HttpEngine uses a pluggable transport interface. MockTransport is complete. A real HTTP transport using std.http.Client or zig-libp2p's HTTP exists but the wiring from BeaconNode → real EL connection may not be tested end-to-end. *Impact: JWT works in isolation; full EL roundtrip needs integration testing.*

2. 🟡 **[Important] Builder/MEV-boost integration is stub-only** — Types defined, vtable defined, but all methods return NotImplemented. *Impact: No MEV-boost support. Validators miss MEV revenue.*

3. 🟡 **[Important] No engine error classification** — TS classifies EL errors into categories (sync, auth, connection, timeout) for different handling. Zig returns generic errors.

4. 🟢 **[Nice-to-have] No engine metrics** — Request latency, status transitions, error counts not tracked.

### Code quality observations
- HTTP engine at 2,812 LOC is thorough — includes JSON serialization for all payload types
- The vtable pattern for EngineApi is idiomatic Zig and allows clean testing
- KZG integration being complete (including PeerDAS cell operations) is ahead of schedule — this was expected to be a gap

---

## 7. Beacon API

**Status**: 🟠 50% functional
**TS LOC**: 9,281 (api/) | **Zig LOC**: 7,152 (api/)

### What works end-to-end
- **HTTP server**: Full request routing with path parameter extraction, content negotiation (JSON + SSZ binary)
- **SSE event streaming**: Server-sent events with 4 event types
- **~33 routes implemented** including:
  - GET: genesis, headers, blocks, validators, state root/fork/finality, node identity/version/syncing/health/peers/peer_count, config spec/fork_schedule, debug states/heads
  - POST: blocks, pool submissions (voluntary_exits, proposer_slashings, bls_to_execution_changes, sync_committees), validator duties (proposer, sync), blocks/{slot} (produce), aggregate_and_proofs, sync_committee_contribution, contribution_and_proofs
- **Content negotiation**: Accept header parsing for JSON vs SSZ responses
- **Error responses**: Structured error JSON with status codes

### Functional gaps (ordered by severity)

1. 🔴 **[Critical] POST /eth/v1/beacon/pool/attestations missing** — TS accepts attestations via API for inclusion in blocks. This is the primary path for standalone validators. *Impact: External VC can't submit attestations via API.*

2. 🔴 **[Critical] GET /eth/v1/validator/attestation_data missing** — Validators need this to create attestations. *Impact: VC attestation flow broken.*

3. 🔴 **[Critical] GET /eth/v1/validator/aggregate_attestation missing** — Validators need this for aggregation duties.

4. 🟡 **[Important] GET /eth/v1/beacon/states/{id}/committees missing** — Needed for attestation validation and VC duty computation.

5. 🟡 **[Important] GET /eth/v1/beacon/states/{id}/sync_committees missing** — Needed for sync committee participation.

6. 🟡 **[Important] GET /eth/v1/beacon/states/{id}/randao missing** — Needed by some VCs for block production.

7. 🟡 **[Important] POST /eth/v1/validator/duties/attester/{epoch} missing** — The attester duties POST endpoint. (Note: the existing `/eth/v1/validator/duties/proposer/{epoch}` is GET, attester is POST with validator indices in body.)

8. 🟡 **[Important] GET /eth/v1/beacon/blob_sidecars/{block_id} missing** — Needed for Deneb blob retrieval.

9. 🟡 **[Important] POST /eth/v1/validator/prepare_beacon_proposer missing** — Fee recipient registration for validators.

10. 🟢 **[Nice-to-have] No rewards API** — `/eth/v1/beacon/rewards/*` endpoints (4+).
11. 🟢 **[Nice-to-have] No keymanager API** — All `/eth/v1/keystores/*` endpoints.
12. 🟢 **[Nice-to-have] No builder API** — All `/eth/v1/builder/*` endpoints.
13. 🟢 **[Nice-to-have] No light client API** — All `/eth/v1/light_client/*` endpoints.

### Code quality observations
- Route matching with path params is well-implemented — `matchRoute` handles `{param}` extraction cleanly
- 33 routes is a solid foundation — covers the core beacon API spec surface
- SSZ content negotiation is present from the start — many TS implementations added this late
- Handler implementations are generally thin wrappers that delegate to chain/state — correct architecture

---

## 8. Validator Client

**Status**: 🟠 55% functional
**TS LOC**: 7,063 (validator/) | **Zig LOC**: 6,144 (validator/)

### What works end-to-end
- **Validator orchestrator**: Top-level `validator.zig` managing service lifecycle
- **Attestation service**: Duty tracking per epoch, attestation production, aggregation flow
- **Block service**: Proposal duty tracking, block production/submission
- **Sync committee service**: Sync committee participation + aggregation
- **API client**: HTTP client for BN REST endpoints — GET/POST with JSON
- **Chain header tracker**: SSE subscription for chain head tracking
- **Validator store**: In-memory key/state management
- **Doppelganger detection**: Duplicate validator detection before signing
- **Remote signer stub**: Web3Signer HTTP client interface defined
- **EIP-2335 keystore**: Full keystore decryption (scrypt/pbkdf2 KDF, AES-128-CTR cipher)
- **Keystore creation**: Key generation and keystore file creation
- **Key discovery**: Filesystem-based key discovery from data directory
- **Slashing protection DB**: Append-only file format — tracks last signed block slot and attestation source/target per pubkey
- **EIP-3076 interchange**: Import/export of slashing protection data
- **BLS signing**: Domain-separated signing for all message types
- **Fee recipient registration**: prepare_beacon_proposer flow
- **Clock**: Slot/epoch timing with configurable seconds_per_slot
- **Keymanager auth**: Bearer token authentication for keymanager API

### Functional gaps (ordered by severity)

1. 🔴 **[Critical] No surround vote detection in slashing protection** — The slashing DB tracks `last_source_epoch` and `last_target_epoch` per validator, but doesn't implement the full surround vote check (source < existing_source AND target > existing_target, or vice versa). TS has `minMaxSurround/` (5 files) implementing the full min-max surround algorithm. *Impact: Could sign slashable attestations in edge cases.*

2. 🟡 **[Important] No validator indices tracking** — TS's `services/indices.ts` tracks which local validators are active on the beacon chain and their validator indices. Missing service. *Impact: VC must discover indices through other means.*

3. 🟡 **[Important] No syncing status tracker** — TS's `syncingStatusTracker.ts` monitors BN sync status and pauses signing during sync. Missing. *Impact: VC could produce duties with stale data during sync.*

4. 🟡 **[Important] No genesis fetching** — TS's `genesis.ts` fetches genesis time/validators_root from BN API on startup. Missing explicit flow. *Impact: Must be configured manually or assumed available.*

5. 🟡 **[Important] No external signer sync** — TS's `externalSignerSync.ts` periodically syncs available keys from Web3Signer. Missing.

6. 🟡 **[Important] Remote signer is stub only** — Types defined but no actual HTTP implementation. *Impact: Can't use Web3Signer in production.*

7. 🟢 **[Nice-to-have] No validator metrics** — TS tracks duty performance, signing latency, missed duties.

8. 🟢 **[Nice-to-have] No committee selection aggregation** — For MEV-boost validator selection.

### Code quality observations
- Slashing protection uses append-only file (simple, crash-safe) vs TS's LevelDB — good tradeoff for reliability
- EIP-2335 keystore implementation is complete and handles both scrypt and pbkdf2 KDFs
- The surround vote gap is the most critical safety issue in the entire codebase — must be fixed before any production validator use

---

## 9. Database

**Status**: 🟡 60% functional
**TS LOC**: ~5,027 (db/ + beacon-node/db/) | **Zig LOC**: 2,384 (db/)

### What works end-to-end
- **KV store abstraction**: Interface trait with get/put/delete/batch operations
- **LMDB backend**: Named databases (not bucket prefixes) — faster reads than LevelDB
- **In-memory backend**: For testing
- **BeaconDB**: 30+ functions covering blocks, block archive, state archive, blob sidecars, data columns, fork choice, validator index, chain info, op pool items
- **Individual column operations**: Per-index get/put for data columns (PeerDAS)

### Functional gaps (ordered by severity)

1. 🟡 **[Important] No secondary indexes** — TS has block archive index (slot → root) and state archive index. Missing. *Impact: Can't efficiently query blocks by slot range.*

2. 🟡 **[Important] No hot/cold DB split** — TS implicitly separates recent (hot) from archived (cold) data. Zig uses flat DB.

3. 🟡 **[Important] No backfilled ranges tracking** — Can't track which historical ranges have been backfilled.

4. 🟢 **[Nice-to-have] No schema migrations** — No version tracking or migration system.

5. 🟢 **[Nice-to-have] No light client DB repos** — bestUpdate, finalityUpdate, optimisticUpdate storage.

### Code quality observations
- LMDB choice is performance-positive — single-writer, multi-reader with mmap'd reads
- Named databases instead of bucket prefixes is cleaner than the TS LevelDB approach
- Low LOC but functionally covers the devnet needs

---

## 10. Monitoring / Metrics

**Status**: 🔴 20% functional
**TS LOC**: ~2,000 (metrics/) | **Zig LOC**: ~500 (metrics + metrics_server)

### What works end-to-end
- **BeaconMetrics struct**: Basic slot/epoch/head metrics
- **HTTP metrics server**: `/metrics` endpoint serving Prometheus text format
- **STF metrics stub**: Framework exists for state transition timing

### Functional gaps (ordered by severity)

1. 🟡 **[Important] 100+ missing metric definitions** — Network, chain, fork choice, sync, db, validator metrics all absent.
2. 🟡 **[Important] No health check endpoint** — `/eth/v1/node/health` returns HTTP status but no detailed health.
3. 🟢 **[Nice-to-have] No remote metrics push**.

---

## 11. Testing Infrastructure

**Status**: ✅ 80% functional
**TS LOC**: ~3,000 (testing/) | **Zig LOC**: 6,825 (testing/)

### What works end-to-end
- **SimBeaconNode**: Full simulated beacon node for multi-node testing
- **SimNetwork**: Simulated P2P network with configurable latency/partition
- **SimCluster**: Multi-node cluster with fault injection and invariant checking
- **Block/attestation generators**: Deterministic test data generation
- **Invariant checker**: Validates chain properties hold during simulation
- **Fork choice simulation**: Tests fork choice behavior under various conditions
- **Integration tests**: Full node startup → block import → verification

### Functional gaps
1. 🟡 No E2E tests against real EL clients (Geth, Reth, etc.)
2. 🟡 No cross-client interop tests (Kurtosis)
3. 🟢 No fuzzing infrastructure

---

## Summary

### 1. What actually works today

If you ran the binary right now with `zig build` and pointed it at an EL + checkpoint sync source:

**Would work:**
- ✅ CLI parsing, data directory setup, logging with rotation
- ✅ Checkpoint sync (download state + blocks from trusted API)
- ✅ State transition for all forks phase0→fulu (spec-tested)
- ✅ Block import: receive block → STFN → verify state root → persist → fork choice
- ✅ Batch BLS signature verification during block processing
- ✅ P2P: QUIC connections, discv5 discovery, gossip subscription, req/resp Status/Ping/Metadata/BeaconBlocksByRange/Root
- ✅ REST API: ~33 endpoints, SSE events, SSZ content negotiation
- ✅ Metrics: basic Prometheus endpoint

**Would partially work:**
- 🟠 Head tracking — blocks imported into fork choice DAG but in-block attestation weights not applied
- 🟠 Block production — body assembled from op pool but attestation packing is naive
- 🟠 Validator client — can load keystores, compute duties, sign messages, but surround vote protection incomplete

**Would NOT work:**
- ❌ EL forkchoiceUpdated calls — head never communicated to execution client
- ❌ Connecting to TCP-only peers — QUIC-only transport
- ❌ Syncing blobs — no blob sidecar req/resp handlers
- ❌ External VC attestation submission — POST /pool/attestations missing
- ❌ Attestation data endpoint for VCs — not implemented

### 2. Top 10 functional gaps blocking devnet

| # | Gap | Subsystem | Effort |
|---|-----|-----------|--------|
| 1 | **forkchoiceUpdated to EL** after import | Chain | 2 days |
| 2 | **Attestation weight import** into fork choice from blocks | Chain | 3 days |
| 3 | **POST /pool/attestations** + **GET attestation_data** API | API | 3 days |
| 4 | **Blob sidecar req/resp** handlers (BlobsByRange, BlobsByRoot) | Network | 5 days |
| 5 | **TCP transport** fallback for cross-client connectivity | Network | 2 weeks |
| 6 | **Safe block hash computation** for forkchoiceUpdated | Fork Choice | 1 day |
| 7 | **Fork-aware block import** (not hardcoded to electra) | Chain | 3 days |
| 8 | **Gossip validation** for blob_sidecar, voluntary_exit, proposer_slashing | Chain | 5 days |
| 9 | **Network processor** full gossip→chain dispatch pipeline | Network | 1 week |
| 10 | **Attester slashing import** into fork choice during block import | Chain | 1 day |

### 3. Top 10 functional gaps blocking production

| # | Gap | Subsystem | Effort |
|---|-----|-----------|--------|
| 1 | **Surround vote protection** in slashing DB | Validator | 1 week |
| 2 | **Aggregated attestation pool** with optimal packing | Chain | 2 weeks |
| 3 | **Complete gossip validation** (14+ message types) | Chain | 2 weeks |
| 4 | **Multi-component peer scoring** | Network | 1 week |
| 5 | **Builder/MEV-boost integration** | Execution | 3 weeks |
| 6 | **Backfill sync** | Sync | 2 weeks |
| 7 | **Validator monitor** | Chain | 2 weeks |
| 8 | **Comprehensive metrics** (100+ missing definitions) | Monitoring | 3 weeks |
| 9 | **Structured error types** across all modules | All | 2 weeks |
| 10 | **Keymanager API** (EIP-3042) | Validator | 2 weeks |

### 4. Estimated effort to devnet

**Previous estimate: 6-8 weeks.** **Revised estimate: 4-6 weeks.**

Rationale for the reduction:
- Chain pipeline is further along than v1 analysis suggested — queued regen, reprocess queue, prepare_next_slot, DA manager all exist
- KZG library is fully integrated (was expected to be a 2-week gap)
- Blob/column tracking infrastructure exists (trackers, reconstruction)
- The top 10 devnet blockers are mostly wiring/integration work, not greenfield implementation
- Many gaps are 1-3 day fixes (forkchoiceUpdated, safe blocks, attestation weight import)

**Critical path (parallelizable with 2-3 agents):**
- Week 1-2: Devnet blocker fixes (#1-#3, #6-#7, #10 from above = ~2 weeks of work)
- Week 2-3: Blob req/resp + gossip validation expansion (#4, #8 = ~10 days)
- Week 3-4: Network processor pipeline + TCP transport investigation (#5, #9 = ~2 weeks)
- Week 4-6: Integration testing, bug fixing, Kurtosis devnet runs

**Key risk**: TCP transport is the single largest unknown. If zig-libp2p supports TCP+Noise+Mplex, it's a configuration change. If not, it's a 2-week implementation project. QUIC-only may work if all devnet participants support it.

### 5. What surprised me

**Better than expected:**
- 🎉 **KZG is fully integrated** — c-kzg bindings with all EIP-4844 and EIP-7594 operations. This was listed as a critical gap in v1.
- 🎉 **Queued state regen exists and is sophisticated** — Priority-based, deduplicated, fast-path cache hits. This was listed as a critical gap.
- 🎉 **Prepare next slot is implemented** — A production optimization that many clients add late.
- 🎉 **Reprocess queue for out-of-order blocks** — Complete with parent_root keying and 3 pending reasons.
- 🎉 **Data availability manager** — Unified DA layer with blob tracking, column tracking, column reconstruction — forward-looking architecture.
- 🎉 **Proto-array includes Gloas ePBS support** — Dual-node architecture for ePBS is already in proto_array.zig. This is ahead of most clients.
- 🎉 **Column subnet service** — PeerDAS-aware subnet management already present.
- 🎉 **Gossipsub scoring parameters** — Full v1.1 scoring with correct Ethereum-specific topic weights.

**Worse than expected:**
- 😬 **No in-block attestation import to fork choice** — This is a fundamental gap. Fork choice without attestation weights is barely functional. Surprised this was missed given how central it is.
- 😬 **No forkchoiceUpdated to EL** — Blocks are imported but the EL never learns which chain is canonical. Critical for block production.
- 😬 **Legacy + new pipeline coexistence** — Two parallel block import paths create maintenance burden and confusion about which is used.
- 😬 **Surround vote protection gap** — The slashing DB tracks last-signed epochs but doesn't implement the min-max surround algorithm. This is a validator safety issue.
- 😬 **Hardcoded electra in importBlock** — The legacy import path only handles electra blocks. Multi-fork support requires using the new pipeline.

---

*Analysis completed: 2026-03-27 23:XX UTC*
*Branch analyzed: feat/beacon-node (lodestar-z-reqresp-wire)*
*Compared against: https://github.com/ChainSafe/lodestar (main, depth=1 clone)*
*Methodology: Line-by-line code reading of both Zig and TS implementations*
