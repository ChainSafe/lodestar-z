# Beacon Node Delta Analysis: lodestar-z vs lodestar-ts

_Generated 2026-03-26. Based on reqresp-wire worktree (lodestar-z) vs TS Lodestar beacon-node package._

## Summary

lodestar-z has **76K LOC across 24 subsystems** in the reqresp-wire branch. The core STFN is complete. The gaps are in **orchestration** — the glue that makes a beacon node robust in production: state management, block pipeline, gossip validation, peer management, and sync state machines.

---

## Subsystem Comparison

### 1. State Transition (STFN)
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| Block processing (all forks) | ✅ phase0→fulu | ✅ phase0→fulu | ✅ Done |
| Epoch processing (all forks) | ✅ | ✅ | ✅ Done |
| Slot processing + fork upgrades | ✅ | ✅ | ✅ Done |
| Signature verification | ✅ batch BLS | ✅ batch BLS | ✅ Done |
| State serialization/deserialization | ✅ | ✅ | ✅ Done |

**Delta: None for core STFN. This is solid.**

---

### 2. Block Import Pipeline
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| `importBlock()` orchestration | 1200+ LOC, handles reorgs, metrics, emitters, archive | `block_import.zig` in testing/ (236 LOC) | 🔴 Skeletal |
| Sanity checks (pre-STFN) | `verifyBlocksSanityChecks.ts` — slot range, proposer, parent known | Inline in beacon_node.zig | 🟡 Partial |
| Signature batch verification | `verifyBlocksSignatures.ts` — collect all sig sets, batch verify | Per-block in STFN | 🟡 Missing batching across blocks |
| Data availability (blobs/columns) | `verifyBlocksDataAvailability.ts` — DA checks, reconstruction | ❌ | 🔴 Missing |
| Execution payload verification | `verifyBlocksExecutionPayloads.ts` — newPayload to EL | `process_execution_payload.zig` exists, `engine_api.zig` exists | 🟡 Partial (no async pipeline) |
| Block queue / reprocessing | `reprocess.ts` — queue blocks when parent unknown | ❌ | 🔴 Missing |
| Post-import: fork choice update | TS runs `onBlock()` + `onAttestation()` after import | Basic fork choice wired | 🟡 Partial |
| Post-import: head update + reorg detection | TS detects reorgs, emits events, updates metrics | ❌ | 🔴 Missing |
| Post-import: archive/persist | `writeBlockInputToDb.ts` | `beacon_db.zig` exists but not wired to import | 🟡 Exists, unwired |
| Payload envelope pipeline (Gloas) | `importExecutionPayload.ts`, dual post-state | ❌ | 🔴 Missing (future fork) |

**Delta: The block import pipeline is the biggest gap. TS has a multi-stage verification pipeline (sanity → signatures → STFN → DA → execution → fork choice → persist). lodestar-z calls STFN directly.**

**Fix path:** Build `importBlock()` as an orchestrator calling existing pieces in sequence. ~1500 LOC estimated.

---

### 3. Fork Choice
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| ProtoArray | ✅ | ✅ (6286 LOC) | ✅ Done |
| computeDeltas | ✅ | ✅ | ✅ Done |
| onBlock / onAttestation | ✅ | ✅ | ✅ Done |
| getHead | ✅ | ✅ | ✅ Done |
| Prune on finalization | ✅ | ✅ | ✅ Done |
| Equivocation tracking | ✅ | ✅ | ✅ Done |
| Unrealized justification | ✅ | 🔄 | 🟡 Partial |
| Execution status (VALID/INVALID/SYNCING) | ✅ | ✅ PayloadStatus enum | 🟡 Needs wiring to EL |
| Proposer boost | ✅ | ? | ❓ Need to verify |
| Checkpoint state management | TS: `persistentCheckpointsCache.ts` (complex) | `checkpoint_state_cache.zig` (exists) | 🟡 Exists, completeness unknown |

**Delta: Core ProtoArray is solid. Missing: wiring to EL for execution status updates, and integration with the block import pipeline. Proposer boost needs verification.**

---

### 4. State Management / Regen
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| State regen (replay from checkpoint) | `regen/regen.ts` + `queued.ts` — queued state regeneration | `state_regen.zig` (exists) | 🟡 Exists, completeness unknown |
| Block state cache (recent states) | `fifoBlockStateCache.ts` — FIFO eviction | `block_state_cache.zig` (exists) | 🟡 Exists |
| Checkpoint state cache | `persistentCheckpointsCache.ts` — persists to disk | `checkpoint_state_cache.zig` (exists) | 🟡 Exists |
| State archive (finalized) | `archiveStore/` — stores finalized states periodically | `datastore.zig` (exists) | 🟡 Exists |
| Shuffling cache | `shufflingCache.ts` — epoch shuffling LRU | `epoch_cache.zig` handles shuffling | 🟡 Different approach |
| Balances cache | `balancesCache.ts` | `effective_balance_increments.zig` | 🟡 Exists |

**Delta: lodestar-z has cache modules but their integration/completeness vs TS is unclear. Need a targeted audit of each cache to verify they handle the same scenarios (epoch boundaries, reorgs, finalization pruning).**

---

### 5. Networking / P2P
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| libp2p transport | js-libp2p (TCP + noise + mplex/yamux) | QUIC via lsquic (eth-p2p-z) | ✅ Different but working |
| discv5 | `@chainsafe/discv5` | `discv5/` (3217 LOC) | 🟡 Exists |
| Req/resp protocol handlers | 8+ handlers (Status, Goodbye, Ping, Metadata, BeaconBlocksByRange, BeaconBlocksByRoot, BlobSidecarsByRange, BlobSidecarsByRoot) | `req_resp_handler.zig` (870 LOC) | 🟡 Partial — Status/BlocksByRange work |
| Gossipsub | js-libp2p-gossipsub (full mesh) | `eth_gossip.zig` + `gossip_*` files | 🟡 Subscription works, mesh formation incomplete |
| Peer manager | `peerManager.ts` — target peer count, scoring, pruning, discovery-driven | `peer_manager.zig` (237 LOC) | 🔴 Skeletal |
| Peer scoring | `score/` — gossip score, RPC score, decay | ❌ | 🔴 Missing |
| Rate limiting | `rateLimit.ts` | ❌ | 🔴 Missing |
| Metadata (SeqNumber, attnets, syncnets) | ✅ | Partial | 🟡 |
| Subnet management | `subnets/` — attestation subnet subscriptions, sync committee subnets | ❌ | 🔴 Missing |

**Delta: Transport layer works (QUIC). Protocol negotiation works. But peer lifecycle management (scoring, rotation, subnet subscriptions) is missing. This is ~5K LOC in TS.**

**Fix path:** Peer scoring can be deferred initially (accept all peers). Subnet management needed for attestation gossip. Rate limiting needed before mainnet.**

---

### 6. Gossip Validation
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| Block validation | `validation/block.ts` — proposer check, parent known, slot range | `gossip_validation.zig` (818 LOC) | 🟡 Exists, completeness? |
| Attestation validation | `validation/attestation.ts` — complex, subnet checks | Partial in gossip_validation.zig | 🟡 Partial |
| Aggregate validation | `validation/aggregateAndProof.ts` | ? | ❓ |
| Blob sidecar validation | `validation/blobSidecar.ts` | ❌ | 🔴 Missing |
| Data column validation | `validation/dataColumnSidecar.ts` | ❌ | 🔴 Missing |
| Sync committee validation | `validation/syncCommittee.ts` | ❌ | 🔴 Missing |
| Seen caches (dedup) | `seenCache/` — SeenBlockProposers, SeenAttesters, SeenAggregators, etc. | `seen_cache.zig` (256 LOC) | 🟡 Partial |
| Proposer slashing validation | `validation/proposerSlashing.ts` | ❌ | 🔴 Missing |
| Attester slashing validation | `validation/attesterSlashing.ts` | ❌ | 🔴 Missing |
| Voluntary exit validation | `validation/voluntaryExit.ts` | ❌ | 🔴 Missing |
| BLS-to-exec validation | `validation/blsToExecutionChange.ts` | ❌ | 🔴 Missing |

**Delta: Gossip validation exists for blocks and partially for attestations. Most other gossip message types have no validation. This is critical for mainnet (accepting invalid gossip = DoS vector).**

**Fix path:** For devnet testing, block + attestation validation is sufficient. Full gossip validation is ~3K LOC spread across many types.**

---

### 7. Sync
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| Range sync state machine | `sync/range/` — batch management, chain tracking | `range_sync.zig` (803 LOC) | 🟡 Basic loop works |
| Checkpoint sync | TS: fetch finalized state from trusted source | `checkpoint_sync.zig` (194 LOC) | 🟡 Exists |
| Unknown block sync | `unknownBlock.ts` — fetch parent chain | ❌ | 🔴 Missing |
| Backfill sync | `sync/backfill/` — fill historical blocks | ❌ | 🔴 Missing |
| Sync service orchestration | `sync/sync.ts` — coordinates range + unknown + backfill | `sync_service.zig` (294 LOC) | 🟡 Skeletal |
| Multi-peer sync | TS tracks sync status per peer, picks best | Single-peer | 🔴 Single peer only |

**Delta: Single-peer range sync works. Missing: multi-peer coordination, unknown block handling (critical for staying at head), backfill.**

**Fix path:** Unknown block sync is the highest priority — it's how the node stays at head after initial sync. Range sync multi-peer is a performance optimization.**

---

### 8. Execution Layer Integration
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| Engine API types | ✅ | `engine_api_types.zig` | ✅ Done |
| JSON-RPC client | ✅ | `json_rpc.zig` | 🟡 Exists |
| newPayload | ✅ | `engine_api.zig` | 🟡 Exists |
| forkchoiceUpdated | ✅ | ? | ❓ Need to verify |
| getPayload (block production) | ✅ | ? | ❓ |
| Mock engine (testing) | ✅ | `mock_engine.zig` | ✅ Done |
| Optimistic sync (accept blocks before EL validates) | ✅ | ❌ | 🔴 Missing |
| Merge transition handling | ✅ | ❌ | 🔴 Missing (historical, not needed for new networks) |

**Delta: Engine API scaffolding exists. Needs verification of completeness and wiring to block import pipeline.**

---

### 9. Beacon API
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| HTTP server | ✅ Fastify | `http_server.zig` (Zig HTTP) | ✅ Done |
| /eth/v1/beacon/* | ✅ full | `handlers/beacon.zig` (763 LOC) | 🟡 Partial |
| /eth/v1/config/* | ✅ | `handlers/config.zig` (117 LOC) | 🟡 Partial |
| /eth/v1/debug/* | ✅ | `handlers/debug.zig` (81 LOC) | 🟡 Skeletal |
| /eth/v1/node/* | ✅ | `handlers/node.zig` (153 LOC) | 🟡 Partial |
| /eth/v1/validator/* | ✅ | `handlers/validator.zig` (166 LOC) | 🟡 Partial |
| /eth/v1/events (SSE) | ✅ | `handlers/events.zig` (141 LOC) | 🟡 Exists |

**Delta: API scaffolding exists for all major namespaces. Completeness of individual endpoints needs auditing. Not blocking for devnet testing.**

---

### 10. Block Production
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| produceBlock | `chain/produceBlock/` — full block assembly | `produce_block.zig` (122 LOC) | 🔴 Skeletal |
| Op pools (attestations, slashings, exits) | `chain/opPools/` — aggregation, dedup, expiry | `op_pool.zig` (648 LOC) | 🟡 Exists |
| Validator duties | TS: proposer duties, committee assignments | `validator_duties.zig` (142 LOC) | 🟡 Skeletal |
| Prepare next slot (pre-compute state) | `prepareNextSlot.ts` | ❌ | 🔴 Missing |

**Delta: Block production is not needed for a syncing-only node. Priority is low until validator support.**

---

### 11. Metrics / Monitoring
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| Prometheus metrics | 2658 LOC, comprehensive | `metrics.zig` + `metrics_server.zig` | 🟡 Exists |
| Monitoring service | `monitoring/` — health checks, liveness | ❌ | 🔴 Missing |
| Validator monitor | `validatorMonitor.ts` | ❌ | 🔴 Missing (validator feature) |

---

### 12. Testing Infrastructure
| Area | TS Lodestar | lodestar-z | Status |
|------|------------|------------|--------|
| Simulation framework | Various test utils | `testing/sim_*.zig` (4878 LOC) | ✅ Impressive |
| Block import tests | ✅ | `block_import_test.zig` | ✅ |
| Spec tests | ✅ | ✅ (separate build targets) | ✅ |
| Network integration tests | Various | `node_integration_test.zig` | 🟡 Exists |
| Fault injection | ❌ | `sim_fault_injection_test.zig` | ✅ Ahead of TS! |
| Fork choice sim | ❌ | `sim_forkchoice_test.zig` | ✅ Ahead of TS! |
| Network partition sim | ❌ | `sim_network_partition_test.zig` | ✅ Ahead of TS! |

**Delta: lodestar-z's simulation framework is actually AHEAD of TS Lodestar. This is a major strength.**

---

## Priority Stack (for a node that can sync and stay at head)

### P0 — Required for basic sync
1. **Block import pipeline** — orchestrate sanity → STFN → fork choice → persist (~1500 LOC)
2. **Config propagation** — SECONDS_PER_SLOT and other overrides must reach CachedBeaconState
3. **Unknown block sync** — handle gossip blocks with unknown parent (~500 LOC)
4. **Gossip mesh formation** — GRAFT/PRUNE/heartbeat so peers keep us (~already partial)

### P1 — Required for reliable sync
5. **Multi-peer range sync** — track per-peer status, parallel batch requests
6. **State regen audit** — verify checkpoint cache + regen handles epoch boundaries + reorgs
7. **Gossip block validation** — full validation per spec (not just decode)
8. **Attestation gossip validation** — needed to participate in fork choice
9. **EL wiring** — forkchoiceUpdated after new head, newPayload during import

### P2 — Required for mainnet
10. **Peer scoring** — protect against malicious peers
11. **Rate limiting** — protect against DoS
12. **Subnet management** — attestation + sync committee subnets
13. **Full gossip validation** — all message types
14. **Data availability** — blob/column verification
15. **Backfill sync** — historical block archive

### P3 — Validator support
16. **Block production** — full produceBlock
17. **Validator duties API** — proposer/attester duties endpoints
18. **Validator monitor** — performance tracking

---

## LOC Estimates

| Priority | Items | Estimated LOC | Notes |
|----------|-------|---------------|-------|
| P0 | Block import + config + unknown block + gossip mesh | ~3000 | Gets us to "syncs and stays at head" |
| P1 | Multi-peer + regen audit + validation + EL wiring | ~5000 | Reliable devnet participation |
| P2 | Scoring + rate limit + subnets + DA | ~7000 | Mainnet-grade |
| P3 | Block production + validator | ~3000 | Full node |

---

## Key Strengths (lodestar-z advantages over TS)
- Simulation test framework (fault injection, fork choice sim, network partition sim)
- QUIC transport (TS uses TCP — QUIC is better for multiplexed streams)
- 6286 LOC fork choice implementation (comprehensive)
- Complete STFN across all forks
- LMDB database backend (TS uses LevelDB-compatible)
