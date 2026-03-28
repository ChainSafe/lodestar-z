# Chain Pipeline Subsystem Review

**Date**: 2026-03-28
**Reviewer**: lodekeeper-z (automated)
**Branch**: feat/beacon-node
**Scope**: 35 files, ~12,350 LOC across `src/chain/` and `src/chain/blocks/`

---

## Executive Summary

| Dimension           | Score (1-10) | Notes |
|---------------------|:---:|-------|
| **Correctness**     | 6   | Pipeline stages are well-structured, but block root computation is wrong, pre-state lookup has a conceptual mismatch, and the dual-system (legacy + pipeline) creates subtle divergence risks. |
| **Completeness**    | 5   | Core import path works. Missing: light client, forkchoiceUpdated EL notification, eth1 deposit tracking, balances cache, state serialization to DB, proper regen slow path, event emitter. |
| **Coherence**       | 6   | Good separation of concerns in blocks/. But two parallel verification systems (block_verification.zig AND blocks/), two parallel type systems (chain types.zig AND blocks/types.zig), and legacy block_import.zig all coexist without clear deprecation. |
| **Taste**           | 7   | Idiomatic Zig overall. Good error types, good test coverage for unit-level modules. Some memory ownership concerns in the attestation pool. |
| **Integration**     | 5   | Modules built by different agents have type mismatches at boundaries, duplicate logic, and inconsistent naming. The pipeline orchestrator connects things correctly but relies on runtime assumptions that aren't enforced by types. |

**Overall**: 5.8/10 — a solid foundation that needs integration tightening before it can process real blocks end-to-end.

---

## 1. Critical Bugs

### BUG-1: Block root computed AFTER state transition uses wrong state_root (execute_state_transition.zig:151-162)

The block root is computed using the *post-state root* as the `state_root` field of the header:
```zig
const block_header = consensus_types.phase0.BeaconBlockHeader.Type{
    .state_root = state_root, // Uses computed post-state root
    ...
};
```
This is **incorrect during sanity checks**. The `verifySanity` stage (verify_sanity.zig:83) computes block_root via `block.hashTreeRoot()` which uses the block's *declared* state_root (possibly all zeros for a fresh block). But `executeStateTransition` recomputes it with the *actual* state_root. This means:
- The block_root in `SanityResult` (from stage 1) differs from the block_root in `StfResult` (from stage 4).
- Fork choice receives the stage-4 root (correct), but the "already known" check in stage 1 uses the stage-1 root (wrong for blocks with placeholder state_roots).

In practice this won't cause failures for well-formed blocks (where declared state_root matches computed), but it's a correctness landmine for test blocks with zeroed state_roots.

**Fix**: Either compute block_root once consistently (use the block's declared hash everywhere), or document that `block_root` in `SanityResult` and `StfResult` may differ and that the STF root is canonical.

### BUG-2: Pre-state lookup mismatch in pipeline.zig:getPreState (pipeline.zig:210-227)

```zig
fn getPreState(ctx: PipelineContext, parent_root: [32]u8, block_slot: Slot) ?*CachedBeaconState {
    if (ctx.queued_regen) |qr| {
        if (qr.getPreState(parent_root, ...) catch null) |state| {
            return state;
        }
    }
    const state_root = ctx.block_to_state.get(parent_root) orelse return null;
    return ctx.block_state_cache.get(state_root);
}
```

`QueuedStateRegen.getPreState` uses `block_cache.get(parent_root)` — it treats `parent_root` as a **state root** (because `BlockStateCache` is keyed by state root). But the pipeline passes a **block root**. This will always miss the cache and fall through.

The fallback path (`block_to_state.get(parent_root)`) correctly translates block_root → state_root, then looks up the state. So the pipeline *works*, but the queued_regen fast path is dead code. This is a latent performance bug — every block import pays the cost of a failed queued_regen lookup.

**Fix**: `QueuedStateRegen.getPreState` should accept a block root and do the block_root → state_root translation internally, or the pipeline should pass a state_root.

### BUG-3: HeadTracker.onBlock always advances head (block_import.zig:79)

```zig
pub fn onBlock(self: *HeadTracker, block_root: [32]u8, slot: u64, state_root: [32]u8) !void {
    if (slot >= self.head_slot) {
        self.head_root = block_root;
        self.head_slot = slot;
    }
}
```

This naively uses slot comparison to update head. During a fork, a block at the same slot on a different branch would **replace the head** even if fork choice selects the other branch. The import pipeline (import_block.zig) does run `updateAndGetHead` for proper fork choice, but HeadTracker is also used by `chain.zig.getStatus()` and other code paths that don't go through the pipeline.

**Fix**: HeadTracker.onBlock should NOT update head. Head should only be set by fork choice `updateAndGetHead` results. HeadTracker should be a passive tracker, not an authoritative head selector.

### BUG-4: SSE head event emitted twice on new block (import_block.zig:371-385 and 406-413)

When a new block changes the head (common case), `detectAndEmitReorg` emits a head event (line ~406) AND the post-import code also emits a head event (line ~383). The caller receives two `head` SSE events for the same block.

**Fix**: The post-import head event (lines 378-385) should be conditional on "head did NOT change" (i.e., the block extended the canonical chain without reorg). When head changes, `detectAndEmitReorg` already handles the event.

### BUG-5: `advanceSlot` updates head_slot without fork choice (chain.zig:~370)

`Chain.advanceSlot` directly sets `head_tracker.head_slot = target_slot` without involving fork choice. This desynchronizes fork choice time from the head tracker. If `onSlot` is called afterward, fork choice may reject blocks as "future" that are actually at the current slot.

**Fix**: `advanceSlot` should also call `fork_choice.updateTime(target_slot)` or be documented as test-only.

---

## 2. Completeness Gaps (vs TS Lodestar)

### GAP-1: No forkchoiceUpdated call after block import ⚠️ HIGH
TS Lodestar calls `notifyForkchoiceUpdate` after every block import to tell the EL the new head/finalized/safe roots. This drives EL block building and is **required for block production**. The Zig pipeline skips this entirely (`skip_execution: true` hardcoded in `chain.zig:importBlock`). The comment says "handled by BeaconNode after importBlock returns" but there's no code that does this.

### GAP-2: No light client subsystem
TS Lodestar has `chain/lightClient/` (30KB) that produces light client updates and optimistic updates on every block import. Not present.

### GAP-3: No eth1 deposit tracking
TS Lodestar's opPools has deposit tracking from the EL. The Zig `produce_block.zig` sets `deposits: empty` with comment "Electra: deposits via EL" but there's no mechanism to fetch them.

### GAP-4: No proper state serialization to DB on import
`import_block.zig` caches the post-state in memory (BlockStateCache) but never serializes it to disk. Only `chain.zig.archiveState()` does disk writes, and it's called externally. If the node restarts, all non-finalized states are lost.

### GAP-5: No balances cache
TS Lodestar has `balancesCache.ts` for efficient fork choice weight computation. Not present.

### GAP-6: No block input DB persistence
TS Lodestar has `writeBlockInputToDb.ts` which persists blob sidecars and data columns alongside the block. The Zig pipeline persists the block but not its associated data.

### GAP-7: Missing gossip validation: signature verification
Gossip validation (`gossip_validation.zig`) does Phase 1 (structural) checks only. Phase 2 (BLS signature verification before ACCEPT) is noted as "deferred to Phase 2 work items" but there's no mechanism to queue and execute Phase 2.

### GAP-8: No `ReprocessController` integration
`reprocess.zig` implements the queue, but nothing connects it to the block import pipeline. When `ParentUnknown` is returned by the pipeline, the caller should queue the block for reprocessing, but this wiring doesn't exist.

### GAP-9: Missing `emitter.ts` equivalent
TS Lodestar has a typed event emitter (`chain/emitter.ts`) for chain events (head, block, attestation, finalized). The Zig code has `EventCallback` but it's a single vtable pointer — no event filtering, no multiple subscribers.

### GAP-10: No `initState.ts` equivalent
TS Lodestar has `initState.ts` for initializing chain state from genesis, weak subjectivity checkpoint, or checkpoint sync. Not present.

---

## 3. Coherence Issues

### COH-1: Two parallel verification systems
`block_verification.zig` (the older module) and `blocks/*.zig` (the newer pipeline) both implement the same stages. They have:
- Different type names: `VerifyError` vs `BlockImportError`, `SanityResult` (both files), `DataAvailabilityStatus` (both files), `ExecutionStatus` (both files)
- Different stage signatures
- Both are exported from `root.zig`

This will confuse any consumer. One should be removed or clearly deprecated.

### COH-2: Two BlockInput types
`chain/types.zig` defines `BlockInput` and `chain/blocks/types.zig` also defines `BlockInput`. They have overlapping but different fields (the chain-level one has a `Source` enum, the pipeline one has `BlockSource` with additional variants like `regen`). Both are exported from `root.zig` under different names, but this is fragile.

### COH-3: Two ImportResult types
`chain/types.zig` defines `ImportResult` (with `execution_optimistic` defaulting to `false`) and `blocks/types.zig` defines `ImportResult` (with `execution_optimistic` as a required field). `chain.zig.importBlock` manually maps between them (lines 154-160). This is unnecessary duplication.

### COH-4: `block_import.zig` is legacy but still used
`block_import.zig` contains `HeadTracker`, `ImportError`, and its own `verifySanity`. The pipeline in `blocks/` has its own `verifySanity` with more features. But `chain.zig` imports `HeadTracker` from the legacy module, while using the pipeline's `processBlock`. This creates a dependency tangle.

### COH-5: PipelineContext vs ImportContext redundancy
`pipeline.zig.PipelineContext` and `import_block.zig.ImportContext` have nearly identical fields. `PipelineContext.toImportContext()` just copies fields. This adds boilerplate and makes it easy to forget adding a new field to both.

---

## 4. Taste Improvements

### TASTE-1: Prune buffer overflow silently drops entries
Multiple modules (SeenCache, OpPool, DataAvailabilityManager) use fixed-size stack buffers for pruning:
```zig
var to_remove: [256][32]u8 = undefined;
```
If there are >256 entries to prune, the excess is silently skipped. This won't cause correctness issues (they'll be pruned next time) but could cause memory growth under adversarial conditions. Use an ArrayList instead.

### TASTE-2: Attestation pool clones aggregation_bits but not deeply
`AttestationPool.add` clones `aggregation_bits.data` but the attestation data, signature, etc. are copied by value. If the source attestation is later mutated by the caller, the pool's copy is fine (value semantics). But the `getForBlock` function returns references into the pool's storage without cloning — if the pool is pruned while the caller holds the slice, it's use-after-free.

### TASTE-3: Error handling in `onSlot` swallows failures
```zig
pub fn onSlot(self: *Chain, slot: u64) void {
    if (self.fork_choice) |fc| {
        fc.updateTime(self.allocator, slot) catch {};
    }
```
Fork choice time update failure is silently swallowed. This could mask serious issues.

### TASTE-4: `@import("ssz")` inside produce_block.zig
`phase0ToElectraAttestation` imports SSZ types inline:
```zig
const CommitteeBits = @import("ssz").BitVectorType(preset.MAX_COMMITTEES_PER_SLOT);
```
This should use the types from `consensus_types` instead of reaching into the SSZ layer directly. It's a layering violation.

### TASTE-5: Inconsistent `deinit` patterns
Some modules have `pub fn deinit(self: *Self) void` and some have `pub fn deinit(_: *Self) void` (when there's nothing to clean up). The latter should probably just not have a `deinit` at all, rather than having a no-op one.

### TASTE-6: `var` used where `const` would suffice
Several places use `var` for iterators or accumulators that are never reassigned. Zig 0.14+ emits warnings for this. Should be `const` where possible.

---

## 5. Integration Bugs (Cross-Agent Boundaries)

### INT-1: `blocks/import_block.zig` uses `fork_choice_mod.onBlockFromProto` but this function may not exist
Line 176: `fork_choice_mod.onBlockFromProto(fc, ctx.allocator, fc_block, block_slot)` — need to verify this function exists in the fork_choice module with this exact signature. The error handling suggests familiarity with the error set, so it was likely written to match, but the `extra_meta: .{ .pre_merge = {} }` field and `timeliness: true` field on ProtoBlock may not match the actual ProtoBlock definition.

### INT-2: `chain.zig` vs `blocks/pipeline.zig` ownership of PipelineContext
`Chain.getPipelineContext` creates a `PipelineContext` that contains pointers to chain internals. The pipeline then passes these pointers through all stages. If the chain state is modified concurrently (e.g., by `onSlot` or another import), the pointers may become dangling or point to mutated state. This is safe in a single-threaded model but fragile.

### INT-3: `SyncContributionAndProofPool` referenced but not connected to pipeline
`produce_block.zig.assembleBlock` accepts `?*SyncContributionAndProofPool` but `chain.zig` doesn't hold a reference to this pool. The sync contribution pool is defined in `sync_contribution_pool.zig` and exported from `root.zig`, but the `OpPool` struct doesn't include it, and `Chain` doesn't store it. Block production will always get an empty sync aggregate.

### INT-4: `QueuedStateRegen.getPreState` signature expects state root, pipeline passes block root
(Same as BUG-2). This is an integration boundary mismatch between the regen module (which thinks in state roots) and the pipeline (which thinks in block roots).

### INT-5: `gossip_validation.zig` ChainState interface vs actual Chain
`ChainState` requires function pointers (`getProposerIndex`, `isKnownBlockRoot`, `getValidatorCount`). These must be wired by BeaconProcessor, which constructs a `ChainState` snapshot from the actual chain. This wiring doesn't exist yet — there's no `chain.toGossipState()` method.

---

## 6. Prioritized Action Items

### P0 — Must fix before any integration testing
1. **Fix HeadTracker head update logic** (BUG-3) — head should only be set by fork choice
2. **Fix double SSE head event** (BUG-4) — simple conditional
3. **Wire reprocess queue** (GAP-8) — needed for gossip block handling
4. **Remove or deprecate block_verification.zig** (COH-1) — it's superseded by blocks/

### P1 — Must fix before devnet
5. **Implement forkchoiceUpdated EL notification** (GAP-1) — required for EL integration
6. **Fix pre-state lookup in pipeline** (BUG-2) — performance, but also correctness for queued_regen users
7. **Connect SyncContributionPool to Chain** (INT-3) — needed for valid block production
8. **Wire gossip validation to actual chain state** (INT-5) — needed for P2P
9. **Persist blob/column sidecars to DB** (GAP-6) — needed for DA

### P2 — Should fix before mainnet
10. **Consolidate dual type systems** (COH-2, COH-3) — reduce confusion
11. **Merge PipelineContext and ImportContext** (COH-5) — reduce boilerplate
12. **Implement eth1 deposit tracking** (GAP-3) — required for valid blocks
13. **Implement state serialization to DB** (GAP-4) — restart resilience
14. **Add Phase 2 gossip validation** (GAP-7) — BLS sig verification
15. **Fix prune buffer overflow** (TASTE-1) — robustness
16. **Light client subsystem** (GAP-2) — needed for light client serving
17. **Chain event emitter** (GAP-9) — proper pub/sub for chain events

### P3 — Nice to have
18. Fix SSZ layering violation in produce_block.zig (TASTE-4)
19. Balances cache (GAP-5) — performance optimization
20. initState module (GAP-10) — proper chain initialization

---

## Appendix: File-by-File Notes

| File | LOC | Notes |
|------|-----|-------|
| chain.zig | 510 | Central coordinator, clean API. `advanceSlot` is test-only but not marked as such. |
| blocks/pipeline.zig | 284 | Good orchestrator. `getPreState` has the root mismatch bug. |
| blocks/types.zig | 334 | Well-designed type vocabulary. `DataAvailabilityStatus` has 5 variants vs chain/types.zig's 3. |
| blocks/import_block.zig | 510 | The heaviest stage. Reorg detection is solid. Double head event emission. |
| blocks/execute_state_transition.zig | 221 | Block root recomputation is clever but creates the dual-root issue. |
| blocks/verify_sanity.zig | 148 | Clean. Uses fork choice + block_to_state fallback correctly. |
| blocks/verify_signatures.zig | 176 | Mostly policy code. Actual BLS wiring is correct (defers to state_transition). |
| blocks/verify_data_availability.zig | 137 | Thin wrapper. Correct. |
| blocks/verify_execution.zig | 165 | Vtable pattern is good. Batch function has off-by-one potential. |
| gossip_validation.zig | 923 | Excellent test coverage (30+ tests). Phase 1 only — Phase 2 deferred. |
| op_pool.zig | 657 | Good basic pools. Attestation pool getForBlock doesn't clone — dangling reference risk. |
| aggregated_attestation_pool.zig | 795 | Sophisticated greedy selection. Well-tested. Mirrors TS well. |
| produce_block.zig | 528 | Complete block assembly. SSZ layering violation. Phase0→Electra conversion is correct. |
| seen_cache.zig | 336 | Clean. Fixed prune buffers could overflow silently. |
| queued_regen.zig | 694 | Priority queuing works. getPreState has the root type mismatch. Good tests. |
| reprocess.zig | 296 | Good queue implementation. Not wired to anything. |
| data_availability.zig | 439 | Well-structured DA coordinator. Tests pass. |
| blob_tracker.zig | 279 | Clean bitset tracking. MAX_BLOBS_PER_BLOCK=6 hardcoded vs spec (should use preset). |
| column_tracker.zig | 299 | Clean. Good custody tracking. |
| column_reconstruction.zig | 153 | Thin KZG wrapper. Correct interface. |
| da_sampling.zig | 222 | Deterministic sampling implementation. Correct Fisher-Yates. |
| block_input.zig | 818 | Async data waiting layer using std.Io.Event. Excellent test coverage. |
| validator_monitor.zig | 752 | Full monitor with effectiveness scoring. Well-tested. |
| shuffling_cache.zig | 162 | LRU cache. Doesn't own EpochShuffling — ownership documented. |
| beacon_proposer_cache.zig | 180 | Simple cache. SLOTS_PER_EPOCH hardcoded as 32 in archive_store.zig. |
| prepare_next_slot.zig | 177 | Pre-computation optimization. Correct epoch boundary handling. |
| archive_store.zig | 229 | Block archival. `SLOTS_PER_EPOCH` hardcoded as 32 (line 139) — should use preset. |
| block_verification.zig | 327 | **LEGACY** — superseded by blocks/. Should be removed. |
| block_import.zig | 212 | **LEGACY** — HeadTracker still needed, verifySanity is dead code. |
| validator_duties.zig | 142 | Thin wrapper over EpochCache. Correct. |
| sync_contribution_pool.zig | 663 | Not connected to Chain or OpPool. Orphaned. |
| blob_kzg_verification.zig | 183 | Clean KZG verification wrapper. |
| types.zig | 164 | Chain-level types. Overlaps with blocks/types.zig. |
| root.zig | 136 | Module root. Exports both old and new systems without deprecation markers. |
