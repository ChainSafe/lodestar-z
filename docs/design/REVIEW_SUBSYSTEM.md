# Subsystem Review: Fork Choice + BLS + KZG + Testing

**Date:** 2026-03-28
**Reviewer:** lodekeeper-z
**Branch:** feat/beacon-node (post-PR #246 adoption)
**Scope:** fork_choice/, bls/, kzg/, testing/, log/

---

## Executive Summary

The fork choice subsystem is the strongest module in this review — a faithful port of Lodestar TS's proto-array with proper Gloas (ePBS) variant support, extensive tests, and clean separation of concerns. The BLS subsystem has correct cryptographic primitives but a critical plumbing gap: gossip batching is completely unwired. KZG is a thin, correct wrapper. The testing/DST framework is impressively complete for the project's maturity, with genuine multi-node simulation, fault injection, and fuzzing — though it doesn't yet exercise fork choice integration. The logging module is solid.

**Verdict:** Fork choice is production-ready pending integration testing. BLS core is correct but the gossip pipeline is the project's single biggest performance bottleneck. Testing framework deserves investment — it's the right architecture.

---

## 1. Fork Choice (8,220 LOC across 6 files)

### 1.1 Correctness — ✅ Strong

**Spec alignment (post-PR #246 adoption):**

- `on_block` (fork_choice.zig `onBlock`/`onBlockInner`): Follows spec with comptime fork dispatch. Validates parent, finalized descendant, extracts checkpoints, computes target root, constructs ProtoBlock, inserts into proto-array. The comptime specialization via `inline else` is elegant — dead-code eliminates fork-irrelevant branches.

- `on_attestation` (fork_choice.zig `onAttestation`): Proper validation cascade matching spec's `validate_on_attestation`. Caches validated attestation data roots. Correctly separates past-slot (immediate apply) from current-slot (queued) attestations.

- `on_tick` (fork_choice.zig `onTick`): Advances slot, resets proposer boost on new slot, pulls up unrealized checkpoints at epoch boundary. Matches spec.

- `on_attester_slashing` (fork_choice.zig `onAttesterSlashing`): Two-pointer sorted intersection — correct and O(n+m).

- `get_head` / `filter_block_tree` (proto_array.zig `findHead`/`nodeIsViableForHead`): Viability check correctly uses unrealized justified for past-epoch blocks, realized justified for current-epoch blocks. The `justified_epoch + 2 >= current_epoch` leniency window matches spec.

- `computeDeltas` (compute_deltas.zig): Correctly handles vote movement, balance changes, equivocating validators. The sorted pointer-advancement for equivocating indices is O(n) — good.

- `prune` (proto_array.zig `maybePrune` + fork_choice.zig `prune`): Correctly adjusts all indices (nodes, indices map, vote tracker) after pruning. The vote index adjustment in ForkChoice.prune handles both current and next indices.

**Gloas (ePBS) support:**

The multi-variant node scheme (PENDING/EMPTY/FULL per block root) is correctly implemented:
- `onBlockGloas` creates PENDING + EMPTY with correct parent linkage (inter-block to parent's EMPTY/FULL, intra-block EMPTY→PENDING)
- `onExecutionPayload` adds FULL variant as sibling of EMPTY under PENDING
- `getParentPayloadStatus` resolves which parent variant a child extends by matching `execution_payload_block_hash`
- PTC votes tracked via `StaticBitSet(PTC_SIZE)`, threshold check at >50%
- `shouldExtendPayload` implements the 4-condition spec check
- `effectiveWeight` zeroes EMPTY/FULL variants from slot n-1 (correct per spec)
- `getPayloadStatusTiebreaker` demotes FULL when `shouldExtendPayload` is false

This is a complete, non-trivial Gloas implementation. The test coverage for variant linkage and weight propagation is thorough (15+ dedicated tests).

**Issues found:**

1. **`isProposingOnTime` hardcoded cutoff (minor):** Uses `const proposer_reorg_cutoff: u64 = 2000` instead of reading from `BeaconConfig.getProposerReorgCutoffMs`. The TODO is noted in code. Not a correctness bug (2s is a reasonable default), but will need updating before mainnet.

2. **`processAttestationQueue` slot ordering assumption:** Uses `orderedRemove` assuming `QueuedAttestationMap` (AutoArrayHashMap) maintains insertion order. `AutoArrayHashMap` in Zig is order-preserving for iteration (swapRemove reorders, orderedRemove preserves). The code correctly uses `orderedRemove` — but if attestations arrive out of slot order, the loop's `break` on `att_slot >= current_slot` could miss earlier-slot entries that were inserted later. In practice, the time-advance logic (`updateTime` calls `processAttestationQueue` once per slot advance) means slots are processed monotonically, so this is safe. But worth a comment.

3. **`onTick` inconsistency check:** `if (time > previous_slot + 1) return error.InconsistentOnTick` — this is correct because `updateTime` calls `onTick` in a loop incrementing by 1. But `updateTime` itself allows jumping multiple slots. The loop-then-error pattern is safe but could confuse readers.

### 1.2 Completeness — ✅ Near-complete

**Present:** on_block, on_attestation, on_attester_slashing, on_tick, get_head, get_ancestor, prune, proposer_boost, proposer_boost_reorg (shouldOverrideFCU, getProposerHead, predictProposerHead), Gloas on_execution_payload, PTC messages, safe block root, safe execution block hash, all ancestor/descendant traversals.

**Missing or stubbed:**
- `get_proposer_head` result not currently used by beacon_node.zig (only `updateAndGetHead` with `get_canonical_head` is called — proposer reorging is initialized but not triggered from the slot pipeline)
- No `on_tick_per_slot` tracking (the spec's time is UNIX seconds; here it's slot-based — this is a documented approximation, not a bug)
- No spec test vectors for fork choice (fork_choice_test_format) — relying on unit tests only

### 1.3 Coherence — ✅ Good

**Integration with beacon_node.zig:**

The beacon_node.zig correctly:
- Imports fork_choice types through the root.zig barrel
- Creates ForkChoice via `initFromAnchor` during genesis/checkpoint init
- Calls `onBlockFromProto` (the test-helper free function) in BlockImporter — this is a **concern**: `onBlockFromProto` is documented as "test/bench only, not part of production API." It bypasses the full `onBlock` path (no state extraction, no checkpoint updates, no Gloas support). This means:
  - Justified/finalized checkpoints are NOT updated from block state
  - Unrealized checkpoints are NOT computed
  - BlockExtraMeta is constructed externally, not from the actual block/state
  - Gloas blocks would not work through this path

  This is the biggest coherence gap. The real `ForkChoice.onBlock` takes `AnyBeaconBlock + CachedBeaconState` and does full checkpoint extraction. `onBlockFromProto` takes a pre-built `ProtoBlock` and skips all of that.

  **Verdict:** This works for V1 sim testing (which constructs ProtoBlocks with correct fields) but MUST be replaced with the real `onBlock` path before mainnet integration. The real path requires passing `CachedBeaconState` to fork choice, which requires the state cache and regen system.

- `chain.fork_choice` field is nullable (`?*ForkChoice`) — gracefully handles pre-initialization

**The shim layer:**
- `onSingleVote` and `onEquivocation` provide compatibility shims for the chain pipeline which processes attestations/slashings one-at-a-time rather than through `onAttestation`/`onAttesterSlashing`. These work correctly.

### 1.4 Taste — ✅ Good, with notes

**Strengths:**
- Clean file decomposition: proto_array (DAG), fork_choice (orchestration), compute_deltas (weight math), vote_tracker (SoA votes), store (checkpoint state)
- Comptime fork specialization in `onBlockInner` is idiomatic Zig
- SoA vote tracker is a smart optimization — 16 entries per cache line vs 4 with AoS
- Extensive inline documentation with spec links
- The test suite is table-driven where appropriate (getDependentRoot, nodeIsViableForHead, CommonAncestor)
- ProtoNode/ProtoBlock conversion via `inline for (std.meta.fields(...))` — clean and maintainable

**Concerns:**
- 8,220 LOC across 2 main files is large. proto_array.zig at 4,861 LOC could be split: types/constants, DAG operations, Gloas operations, execution status, pruning, tests. fork_choice.zig at 3,359 LOC could split: attestation handling, block handling, checkpoint management, proposer reorg, tests. But this is cosmetic — the code is navigable with good section comments.
- The `root.zig` barrel exports ~40 names. A bit noisy but functional.
- `irrecoverable_error` field stores errors but there's no periodic check or recovery path. If `validateLatestHash` fails, the error sits there silently. The node should probably log and halt.

---

## 2. BLS (13 files, ~1,200 LOC core + ThreadPool)

### 2.1 Correctness — ✅ Core is correct

The existing review (REVIEW.md) from 2026-03-27 is comprehensive and accurate. Verifying against current code:

- **BatchVerifier:** Random-scalar batch verification correctly implemented. Stack-allocated sets (MAX_SETS_PER_BLOCK=256), proper pubkey resolution, signature decompression, random scalar generation. Thread pool dispatch when available, single-threaded fallback otherwise.

- **ThreadPool:** Work-stealing via atomic counter with monotonic ordering (sufficient for counter-only use). Pairing merge correctly finds first worker with work, accumulates, and finalizes. The dispatch_mutex serializes concurrent requests — correct but limits throughput to one batch at a time.

- **SignatureSet:** Clean abstraction over single/aggregate pubkey sets. `resolvePublicKey` handles all cases correctly.

### 2.2 Completeness — 🔴 Critical gap

**The REVIEW.md findings are confirmed and still present:**

1. **🔴 Gossip BLS verification is one-at-a-time.** Every gossip message (attestation, aggregate, sync committee, etc.) calls `verifySingleSignatureSet` inline. On mainnet with ~6400 attestations/slot, this is ~6400 individual BLS pairings instead of ~1 batched multi-pairing. **10-50x performance gap vs TS Lodestar.**

2. **🔴 Gossip handler bypasses processor queue.** `GossipHandler` does decode → validate → verify BLS → import all inline. The `BeaconProcessor` with priority queues exists but is dead code in the gossip path. No backpressure, no priority ordering, no sync-aware dropping.

3. **🟡 ThreadPool not used for block import.** `BatchVerifier.init(null)` everywhere — block import is single-threaded for BLS. The ThreadPool exists, is tested, but never instantiated.

4. **🟡 `fillRandomScalars` is Linux-only.** Hardcoded `std.os.linux.getrandom`. Won't compile on macOS. Should use `std.crypto.random.bytes()`.

5. **🟡 Double/triple Snappy decompression in gossip handlers.** Confirmed in current code.

### 2.3 Coherence — 🟡 Wiring gap

The pieces exist but aren't connected:
- `BatchVerifier` ✅ → used in block import path
- `ThreadPool` ✅ → exists, tested, never instantiated in production
- `WorkQueues` ✅ → designed with priority/batching, never fed by gossip
- `GossipHandler` ✅ → validates correctly but does BLS inline

### 2.4 Taste — ✅ Good

- Stack-allocated batch verifier (zero heap alloc on sync path)
- Clean SignatureSet abstraction
- Well-documented ThreadPool with proper atomic semantics
- DST constant properly defined

---

## 3. KZG (2 files, ~250 LOC)

### 3.1 Correctness — ✅

Thin idiomatic Zig wrapper over c-kzg-4844 bindings. All functions delegate directly to the C library with proper error mapping. No logic to get wrong.

### 3.2 Completeness — ✅

Covers both EIP-4844 (blob proofs) and EIP-7594 (PeerDAS cells):
- `blobToCommitment`, `computeBlobProof`, `verifyBlobProof`, `verifyBlobProofBatch`
- `computeCellsAndProofs`, `recoverCellsAndProofs`, `verifyCellProofBatch`

Constants match spec (BYTES_PER_BLOB=131072, CELLS_PER_EXT_BLOB=128, etc.)

### 3.3 Coherence — ✅

Clean `Kzg` struct with `initFromFile`/`initFromBytes`/`deinit` lifecycle. Designed to be created once at startup and shared. Error set is minimal and appropriate.

### 3.4 Taste — ✅

This is what a wrapper should look like. Minimal code, proper types, good documentation, no unnecessary abstraction.

**One note:** No integration tests (require trusted setup file). The unit tests only check constants and type sizes. Real verification tests would need a test fixture — acceptable for now but needed before production.

---

## 4. Testing / DST Framework (8,588 LOC across 30 files)

### 4.1 Correctness — ✅ Within its scope

The DST framework is correctly implemented:
- **SimIo:** Deterministic I/O abstraction wrapping PRNG, monotonic clock, realtime clock. Same seed = identical execution, verified by replay test.
- **SimNetwork:** Priority-queue based message delivery with configurable latency, packet loss, reordering, duplication, and partitions. Deterministic tie-breaking via sequence numbers.
- **SimStorage:** Simple key-value store with deterministic failure injection.
- **SlotClock:** Slot/epoch computation from simulated time.
- **SimBeaconNode:** Single-node simulation with real state transition, block generation, and invariant checking.
- **SimCluster:** Multi-node simulation with shared genesis state, network gossip, and cross-node invariant checking.
- **SimController:** Higher-level orchestration with SimValidator integration and scenario support.
- **SimValidator:** Duty-aware validator producing blocks and attestations with proper committee assignments.
- **SimFuzzer:** Random event injection with weighted step selection and invariant checking after each step.
- **Scenario:** Scriptable step sequences with built-in patterns (happy_path, missed_proposals, network_partition).

### 4.2 Completeness — 🟡 Good foundation, key gaps

**What's tested:**
- Single-node slot progression with real STFN
- Multi-node state agreement (identical blocks → identical state roots)
- Network partitions and healing
- Block import through SimNodeHarness → BlockImporter → STFN
- Fork choice integration via `sim_forkchoice_test.zig`
- Fault injection (missed proposals, node crashes, message delays)
- Fuzzer-driven random exploration
- DST determinism audit

**What's NOT tested:**
1. **Fork choice under competing forks.** The sim_forkchoice_test exists but the cluster currently produces single-chain blocks (one proposer per slot, all nodes receive same block). No test creates two competing blocks at the same slot and verifies fork choice resolves correctly.

2. **Attestation impact on fork choice.** SimValidator produces attestations but they're tracked, not processed through the fork choice's `onAttestation` path. The weight impact of attestations on head selection isn't verified in the sim framework.

3. **Checkpoint finalization under adversarial conditions.** The invariant checker tracks finalized epochs but no test verifies that finality progresses correctly under 1/3 offline validators or competing chains.

4. **Gloas variant resolution.** No sim test exercises the PENDING→EMPTY→FULL lifecycle.

5. **Proposer reorg scenarios.** `shouldOverrideForkChoiceUpdate` is thoroughly unit-tested but not exercised in the sim framework.

### 4.3 Coherence — ✅ Good

The framework properly layers:
```
SimIo (deterministic I/O)
  └─ SimClock, SimNetwork, SimStorage (infrastructure)
      └─ SimNodeHarness (wraps BeaconNode)
          └─ SimCluster (multi-node)
              └─ SimController (+ SimValidator orchestration)
                  └─ SimFuzzer (random exploration)
                      └─ Scenario (scripted test cases)
```

Each layer depends only on the ones below it. SimNodeHarness wraps the real `BeaconNode` — not a mock — ensuring the sim tests exercise actual production code paths.

### 4.4 Taste — ✅ Very good

The DST framework is the right architecture. Following TigerBeetle's testing philosophy (deterministic simulation testing) for a consensus client is exactly right. Highlights:

- Deterministic replay guarantee (tested explicitly)
- Real STFN, not mocks
- Configurable fault injection at every layer
- Priority-queue network simulation with sequence-number tie-breaking
- Scriptable scenarios for regression tests
- Fuzzer for exploration
- Invariant checking at every step

The framework is well-positioned for expansion. The immediate next step should be wiring fork choice attestation processing into the sim loop.

---

## 5. Logging (2 files, ~1,130 LOC)

### 5.1 Correctness — ✅

- Level filtering via single integer comparison
- Per-module configurable levels
- Human-readable and JSON output formats
- Thread-safe via `std.Io` interface
- `std.log` integration via custom `logFn`

### 5.2 Completeness — ✅

Covers all needs: err/warn/info/verbose/debug/trace levels, 13 subsystem modules (chain, sync, network, api, execution, db, validator, bls, node, backfill, rest, metrics, default), human and JSON formats, file rotation config.

### 5.3 Taste — ✅

Clean, zero-overhead-when-disabled design. Comptime format strings. Proper.

---

## 6. Cross-Subsystem Issues

### 6.1 Fork Choice ↔ BeaconNode integration gap

**The most important finding:** `beacon_node.zig` calls `onBlockFromProto` (test-only helper) instead of `ForkChoice.onBlock` (production API). This means:
- No checkpoint extraction from state
- No unrealized checkpoint computation
- No Gloas block handling
- Justified/finalized balances never updated from block processing

This must be replaced before the fork choice can be considered integrated. The `onBlock` API requires `CachedBeaconState`, which requires the state cache — a known TODO.

### 6.2 BLS ↔ Gossip pipeline gap

Already covered in BLS section. The gossip → batch verify → thread pool pipeline doesn't exist yet. This is the single biggest performance blocker.

### 6.3 Testing ↔ Fork Choice coverage gap

The sim framework exercises block import through STFN but fork choice attestation processing is not wired. Attestations are produced by SimValidator but their impact on head selection isn't tested in the multi-node sim.

### 6.4 KZG ↔ Data availability

KZG functions exist but data availability checking in block import (`data_availability_status: .available` is hardcoded in sim) is not exercised.

---

## 7. Priority Action Items

### P0 — Blocks mainnet integration

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| 1 | Replace `onBlockFromProto` with `ForkChoice.onBlock` in BlockImporter | beacon_node.zig:367 | Fork choice checkpoint tracking broken |
| 2 | Wire gossip BLS batching pipeline | bls/, gossip_handler, processor | 10-50x gossip throughput |
| 3 | Wire ThreadPool to block import BatchVerifier | beacon_node.zig | 2-4x block import speedup |

### P1 — Important correctness/coverage

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| 4 | Fix `fillRandomScalars` Linux-only | bls/batch_verifier.zig | Non-Linux builds broken |
| 5 | Add competing-fork sim test | testing/sim_forkchoice_test.zig | Fork choice untested under adversarial conditions |
| 6 | Wire attestation processing in sim | testing/sim_controller.zig | Attestation → fork choice weight untested |
| 7 | `isProposingOnTime` hardcoded cutoff | fork_choice.zig | Should read from config |

### P2 — Cleanup

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| 8 | Proto_array.zig could be split (~4.8K LOC) | fork_choice/ | Navigability |
| 9 | `irrecoverable_error` needs logging/halt | fork_choice.zig | Silent failure |
| 10 | Eliminate double Snappy decompression | gossip_handler | ~2x wasted CPU |
| 11 | KZG integration tests with test fixture | kzg/ | No real verification tested |

---

## 8. Summary by Subsystem

| Subsystem | Correctness | Completeness | Coherence | Taste | Overall |
|-----------|-------------|--------------|-----------|-------|---------|
| Fork Choice | ✅ Strong | ✅ Near-complete | 🟡 `onBlockFromProto` shim | ✅ Good | **A-** |
| BLS | ✅ Core correct | 🔴 Gossip batching missing | 🟡 Pieces exist, unwired | ✅ Good | **C+** |
| KZG | ✅ Correct | ✅ Complete | ✅ Clean | ✅ Good | **A** |
| Testing/DST | ✅ Within scope | 🟡 Key gaps | ✅ Good layers | ✅ Very good | **B+** |
| Logging | ✅ Correct | ✅ Complete | ✅ Clean | ✅ Good | **A** |

**Bottom line:** The fork choice implementation is spec-faithful and well-tested — the best module in this review. The BLS core is correct but the gossip pipeline is the project's #1 performance risk. The testing framework has the right architecture and deserves investment in fork-choice-aware scenarios. The integration between fork choice and beacon_node via `onBlockFromProto` is a known shortcut that must be resolved.
