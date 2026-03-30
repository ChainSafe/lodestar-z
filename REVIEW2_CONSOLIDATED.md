# feat/beacon-node — Pass 2 Consolidated Review

**Date:** 2026-03-28
**Reviewers:** 7 parallel opus agents (5 subsystem + data-flow + memory)

---

## 🔴 CRITICAL — Must fix before devnet

### Gossip Deserialization (DATA FLOW)
1. **Gossip blocks always decoded as phase0** — `gossip_decoding.zig` hardcodes `phase0.SignedBeaconBlock`. On any post-phase0 network, deserialization fails. Node can't receive blocks.
2. **Aggregates also decoded as phase0 only** — Electra changes attestation layout inside aggregates.

### Gossip Validation (CHAIN)
3. **makeGossipState callbacks are all stubs** — `isKnownBlockRoot` → false, `getProposerIndex` → null, `getValidatorCount` → 0. Every gossip message IGNORED/REJECTED.

### Validator Client (VALIDATOR)
4. **Block proposals always fail** — `computeBodyRoot()` returns NotImplemented. body_root=zeros, wrong signing root, BN rejects, slot consumed in slashing protection.
5. **Attestation aggregation_bits always "0x01"** — Empty bitlist, committee position ignored, BN rejects every attestation.
6. **Sync committee selection_proofs broken** — Const slice mutation (won't compile), proofs never reset between slots.
7. **Sync committee contribution aggregation_bits hardcoded "0x00"** — Computed bits discarded.

### Networking (NET-SYNC)
8. **Wrong slot extraction from SignedBeaconBlock SSZ** — Reads bytes 0..8 (offset+signature) instead of actual slot at offset 100+. Fork digest wrong.
9. **Hardcoded PRNG seed 0xcafebabe** — All discv5 nonces deterministic. Session hijacking possible.

### Execution (EXEC-DB)
10. **builder.zig parseSignedBuilderBid use-after-free** — extra_data points into freed JSON arena.
11. **getPayloadForFork drops Electra execution requests** — promoteToV3 loses deposit/withdrawal/consolidation requests.

### API (API-NODE)
12. **DELETE method not dispatched** — handleHttpRequest only maps GET/POST. Keymanager DELETE endpoints unreachable.

### Memory (MEMORY)
13. **block_to_state + slot_roots never pruned** — Unbounded growth, OOM after weeks/months.
14. **SeenCache sub-maps never pruned** — seen_exits, seen_bls_changes grow monotonically.

---

## 🟡 IMPORTANT

### Chain + Fork Choice
- processAttestationQueue double-counts on OOM (use-after-free of deinit'd maps)
- onSingleVote uses epoch-start slot instead of attestation slot
- Duplicate verifySanity implementations
- Duplicate attester slashing processing

### Networking
- Handshake id-signature never verified (`_ = id_sig;`)
- Sync chain target never decreases when peers leave
- FINDNODE returns empty (DHT freeloader)
- unknown_block_sync callbacks never wired
- Attester slashing + BLS change gossip validation always accepts
- SeenSet eviction is O(n) per insert

### API + Node
- deinit() use-after-free (accesses api_context after destroy)
- reqRespGetStatus uses old slot-based finalized_root (C2 fix missed this)
- prev_randao hardcoded to zeros in payload prep
- DELETE body not read for keymanager endpoints
- getAttesterDuties/getSyncDuties unwired
- CORS preflight leaks to keymanager paths

### Execution
- encodeExecutionPayloadHeader missing Deneb+ fields
- base_fee_per_gas uses DATA encoding instead of QUANTITY
- blob_kzg_commitments never parsed from relay
- Duplicate hex utilities between builder.zig and http_engine.zig

### Validator
- EIP-7044 check tests if Deneb is scheduled, not if chain has reached Deneb
- Malicious BN can burn attestation capability (no bounds check on target_epoch)
- Clock skips first epoch callbacks on mid-epoch startup
- Interchange import not wired to startup
- Remote signer keys fetched but never registered
- Liveness tracker never receives duty outcomes
- SSE/ChainHeaderTracker never started

### Memory
- Fork choice queued_attestations unbounded during delays (218MB worst case)
- SyncContributionPool no slot limit on outer map
- whoareyou_rate in discv5 never pruned

---

## Priority Fix Order

**Tier 1 — Node fundamentally non-functional without these:**
1. Fork-aware gossip deserialization (blocks + aggregates + attestations)
2. Wire makeGossipState callbacks to real chain state
3. Fix discv5 PRNG seed (security)
4. Prune block_to_state + slot_roots in onFinalized

**Tier 2 — Validator client non-functional:**
5. Fix computeBodyRoot for block proposals
6. Fix attestation aggregation_bits encoding
7. Fix sync committee proofs + contribution bits

**Tier 3 — Correctness:**
8. Fix SSZ slot extraction in req_resp_handler
9. Wire DELETE method dispatch + body reading
10. Fix builder use-after-free + Electra request dropping
11. Fix prev_randao in payload preparation
12. Verify discv5 id-signature in handleHandshake
