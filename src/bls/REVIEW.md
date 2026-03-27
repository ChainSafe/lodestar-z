# BLS Batch Verification & Gossip Pipeline — Deep Review

**Date:** 2026-03-27
**Reviewer:** lodekeeper-z
**Branch:** review/bls-gossip-quality
**Scope:** BLS batch verifier, ThreadPool, gossip handler, gossip validation, processor queues

---

## 1. Architecture Assessment

### How the pipeline actually works end-to-end

```
Gossip Message
  │
  ├─ gossip_handler.onBeaconBlock / onAttestation / onAggregate / ...
  │    ├─ Phase 1a: decodeGossipMessage() → snappy decompress + SSZ decode (extract fields)
  │    ├─ Phase 1b: chain/gossip_validation.validateGossip*() → slot bounds, dedup, proposer checks
  │    ├─ Phase 1c: verify*SignatureFn() → BLS verify **ONE AT A TIME** ← 🔴 CRITICAL ISSUE
  │    └─ Phase 2: import*Fn() → direct call (no queue) ← 🟡 ISSUE
  │
  ├─ BLOCK IMPORT PATH (separate):
  │    ├─ chain.zig importBlock()
  │    │    ├─ processBlock() with BatchVerifier → collects sig sets
  │    │    └─ batch.verifyAll() → single multi-pairing check ← ✅ CORRECT
  │    └─ BatchVerifier.init(null) → no ThreadPool ← 🟡 ISSUE
  │
  └─ PROCESSOR (exists but not wired to gossip):
       ├─ WorkQueues with priority ordering (blocks > aggregates > attestations) ← ✅ GOOD DESIGN
       ├─ formAttestationBatch() / formAggregateBatch() ← ✅ BATCH SUPPORT EXISTS
       └─ But nothing pushes gossip messages into these queues ← 🔴 CRITICAL
```

### Key Findings

| Component | Status | Notes |
|-----------|--------|-------|
| BatchVerifier core | ✅ Correct | Random-scalar scheme properly implemented |
| ThreadPool | ✅ Correct | Work-stealing, proper pairing merge |
| Block import batch verify | ✅ Works | Collects sets → verifyAll() |
| Gossip BLS verification | 🔴 **One-at-a-time** | Each message verified individually |
| Gossip → Processor queue | 🔴 **Not wired** | Direct function calls, queues unused |
| ThreadPool for gossip | 🔴 **Not used** | BatchVerifier.init(null) everywhere |
| Double decompression | 🟡 Waste | Many handlers decompress 2-3x |
| SignatureSet memory | 🟢 Sound | Stack-allocated, no leaks |

---

## 2. Critical Issues

### 🔴 CRITICAL-1: Gossip BLS verification is one-at-a-time (10-50x performance miss)

**The biggest issue in the codebase.**

Every gossip message type verifies its BLS signature inline, one at a time:

```zig
// beacon_node.zig line ~3727 (attestation)
fn gossipVerifyAttestationSignature(...) bool {
    ...
    return state_transition.signature_sets.verifySingleSignatureSet(&sig_set) catch false;
}

// beacon_node.zig line ~3793 (aggregate — verifies 3 signatures sequentially!)
fn gossipVerifyAggregateSignature(...) bool {
    // selection_proof → verifySingleSignatureSet
    // aggregator sig → verifySingleSignatureSet
    // aggregate attestation → verifyAggregatedSignatureSet
    // ALL SEQUENTIAL, NO BATCHING
}
```

On mainnet with ~6400 attestations per slot:
- **Current:** 6400 × individual BLS verify = ~6400 pairings
- **TS Lodestar:** Collects N attestations → batch verify with random scalars = ~1 multi-pairing (amortized ~N/logN pairings)
- **Performance gap:** ~10-50x depending on batch sizes

TS Lodestar's approach (from `multithread/index.ts`):
1. Gossip messages marked `batchable: true` accumulate in a buffer
2. Buffer flushes when either:
   - `MAX_BUFFERED_SIGS` (32) signatures collected, OR
   - `MAX_BUFFER_WAIT_MS` (100ms) timeout fires
3. Buffered sets sent to a worker thread for `verifyMultipleAggregateSignatures`
4. If batch fails, retry individual sets to find the bad one

**lodestar-z has NONE of this.** The processor's `formAttestationBatch()` exists but is never reached because gossip messages never enter the processor queues.

### 🔴 CRITICAL-2: Gossip messages bypass the processor queue entirely

The `GossipHandler` does everything inline:
```zig
// gossip_handler.zig: onAttestation
pub fn onAttestation(self: *GossipHandler, ...) !void {
    // Phase 1: decode + validate
    // Phase 1c: BLS verify (inline, one-at-a-time)
    // Phase 2: import (inline, direct call)
    if (self.importAttestationFn) |importFn| {
        importFn(self.node, ...);  // Direct call, no queue!
    }
}
```

The `BeaconProcessor` with its priority queues (`WorkQueues`) exists with proper priority ordering (blocks > aggregates > attestations), batch formation logic, and sync-aware dropping — but **nothing feeds work items into it**. It's dead code in the gossip path.

This means:
1. No priority ordering: attestation processing can delay block processing
2. No backpressure: under load, attestations flood the system
3. No sync-aware dropping: attestations aren't dropped during initial sync
4. No batching: batch formation in `WorkQueues` is never triggered

### 🟡 ISSUE-3: ThreadPool not used for block import

In both `chain.zig` and `beacon_node.zig`, batch verification uses:
```zig
var batch = BatchVerifier.init(null);  // null = no thread pool!
```

The `ThreadPool` is fully implemented and tested, but never instantiated or passed to `BatchVerifier`. Block import runs single-threaded for BLS verification. On mainnet with 128+ attestations per block, multi-threaded verify would be 2-4x faster.

### 🟡 ISSUE-4: Double/triple Snappy decompression in gossip handler

Most handlers decompress the message twice or three times:

```zig
// onBeaconBlock: decompress TWICE
const decoded = decodeGossipMessage(..., message_data);  // decompress #1
const ssz_bytes = snappy.decompressGossipPayload(..., message_data);  // decompress #2

// onSyncCommitteeMessage: decompress THREE TIMES
const decoded = decodeGossipMessage(..., message_data);  // decompress #1
const sc_ssz = gossip_decoding.decompressGossipPayload(..., message_data);  // decompress #2 (for BLS)
const sc_ssz = gossip_decoding.decompressGossipPayload(..., message_data);  // decompress #3 (for import)
```

Each decompression allocates a fresh buffer and does full Snappy decompression. On mainnet with ~6400 attestations/slot, this is ~12,800+ unnecessary decompressions per slot.

### 🟡 ISSUE-5: `fillRandomScalars` is Linux-only and has weak fallback

```zig
fn fillRandomScalars(rands: [][32]u8) void {
    const rc = std.os.linux.getrandom(bytes.ptr + filled, bytes.len - filled, 0);
    const signed_rc: isize = @bitCast(rc);
    if (signed_rc < 0) {
        // Fallback: CSPRNG seeded from stack + timestamp
        var seed: [32]u8 = [_]u8{0} ** 32;
        var stack_var: u8 = 0;
        const addr: u64 = @truncate(@intFromPtr(&stack_var));
        @memcpy(seed[0..8], std.mem.asBytes(&addr));
        var prng = std.Random.ChaCha.init(seed);
```

Problems:
1. **Linux-only:** Hardcoded `std.os.linux.getrandom` won't compile on macOS/Windows
2. **Weak fallback:** On getrandom failure, seed is only 8 bytes of stack address — trivially predictable. An attacker who can predict the random scalars can craft signatures that pass batch verification but fail individual verification (rogue key attack on the batch).
3. **Should use `std.crypto.random`** which handles all platforms and has proper entropy

### 🟢 MINOR-6: `RAND_BYTES` inconsistency

- `batch_verifier.zig`: `RAND_BYTES = 8` (defined but unused — scalars are [32]u8)
- `fast_verify.zig`: `RAND_BITS = 64` (= 8 bytes, correct)
- `ThreadPool.zig`: `RAND_BITS = 64` (consistent with fast_verify)

The `batch_verifier.zig` fills 32-byte random scalars but `fast_verify` only uses `RAND_BITS = 64` (8 bytes). The extra 24 bytes per scalar are wasted entropy. Not a correctness issue (extra random bytes are ignored by blst's `mulAndAggregate`), but wasteful.

---

## 3. Correctness Analysis

### BatchVerifier: ✅ Correct

The random-scalar batch verification scheme is correctly implemented:
1. Signature sets collected via `addSet/addSingle/addAggregate`
2. Pubkeys resolved (aggregated for multi-signer sets) via `resolvePublicKey`
3. Signatures decompressed from compressed bytes
4. Random scalars generated (modulo the entropy issue above)
5. `verifyMultipleAggregateSignatures` called with proper DST

The `verifyMultipleAggregateSignatures` in `fast_verify.zig` correctly:
- Initializes a Pairing context with DST
- For each set: `mulAndAggregate(pk, sig, rand, msg)` — multiplies the pairing contribution by the random scalar
- Commits and does final verification

**No correctness bug possible here** — even with the weak fallback PRNG, an attacker would need to predict scalars *before* they're generated, and the scalars are generated at verification time.

### ThreadPool: ✅ Correct (with minor notes)

- Work-stealing via atomic counter: correct. `fetchAdd(.monotonic)` is sufficient for a counter (no ordering needed between counter increments).
- `err_flag` uses `.acquire/.release`: correct. Ensures error is visible to all threads.
- `dispatch_mutex` with `tryLock` + `spinLoopHint`: correct but could use `lock()` instead since the spinloop is equivalent. The tryLock+spin pattern is fine for the expected low-contention case.
- `mergeAndVerify` correctly finds the first worker that did work, accumulates pairings, and does final verify.
- The `has_work` tracking correctly handles the case where a worker gets no items (empty batch).

**One subtle issue:** The `dispatch_mutex` is a `std.atomic.Mutex` which is a futex-based mutex. Using `tryLock` in a spinloop will burn CPU. This is fine if contention is rare (only one thread calls `verifyMultipleAggregateSignatures` at a time), but could be an issue if gossip batching sends concurrent verification requests. Should use `pool.dispatch_mutex.lock()` instead of the tryLock spinloop.

### SignatureSet: ✅ Correct

- Single sets store the pubkey by value — correct, avoids dangling pointer
- Aggregate sets store a slice reference — lifetime is documented and correct (callers keep pubkeys alive through the batch verify call)
- `resolvePublicKey` correctly handles single (return value), 1-element aggregate (return first), and N-element aggregate (call `AggregatePublicKey.aggregate`)

### Gossip Validation: ✅ Correct

Phase 1 checks are properly ordered and match the consensus spec:
- Blocks: future slot, finalized, dedup, proposer bounds, expected proposer, parent known
- Attestations: epoch window, target epoch match, committee bounds, target known
- Aggregates: aggregator bounds, epoch window, target epoch, non-empty bits, dedup

### Block Import Path: ✅ Correct

The `processBlock` → `BatchVerifier` → `verifyAll` path correctly:
1. Collects signature sets via `verifySingleSignatureSetOrDefer` / `verifyAggregatedSignatureSetOrDefer`
2. Sets are queued in the batch verifier instead of verified inline
3. After `processBlock` completes, `batch.verifyAll()` does a single multi-pairing check
4. If any signature is invalid, the entire block is rejected

---

## 4. Comparison with TS Lodestar

### Architecture Comparison

| Aspect | TS Lodestar | lodestar-z | Gap |
|--------|------------|------------|-----|
| Gossip BLS batching | ✅ `BlsMultiThreadWorkerPool` with buffering | ❌ One-at-a-time | **Critical** |
| Buffer strategy | Collect up to 32 sigs or 100ms timeout | None | **Critical** |
| Worker pool | ✅ N workers (CPU count - 1) | ✅ ThreadPool exists, unused | **Critical** |
| Priority | ✅ `priority: true` fast-paths blocks | ✅ WorkQueues has priorities, unused | **Major** |
| Batch on fail retry | ✅ Re-verify individually on batch fail | ❌ N/A (no batching) | **Critical** |
| `sameMessage` optimization | ✅ `aggregateWithRandomness` for same-msg attestations | ✅ BatchVerifier supports same-message (via shared signing_root) | Parity potential |
| Block import batch | ✅ Batched | ✅ Batched | Parity |
| Multi-thread block verify | ✅ Worker threads | ❌ `BatchVerifier.init(null)` | **Major** |

### What TS Lodestar Does That We Don't

1. **Gossip BLS batching** (`BlsMultiThreadWorkerPool`):
   - Gossip messages call `verifySignatureSets(sets, {batchable: true})`
   - Sets accumulate in `bufferedJobs` with a 100ms timeout
   - When 32 sigs collected OR timeout fires → batch dispatched to worker
   - Worker calls `verifyMultipleAggregateSignatures` (same random-scalar scheme we have)
   - If batch fails → retry each individually to find the bad sig

2. **Priority fast-path**:
   - Block signature verification uses `{priority: true}` → pushed to front of job queue
   - Attestations use `{batchable: true}` → buffered and batched
   - This ensures blocks are verified ASAP while attestations are batched for throughput

3. **Main-thread fallback**:
   - Some signatures verified on main thread (`verifyOnMainThread: true`)
   - Used for time-critical operations where worker latency is unacceptable

### What We Have That TS Lodestar Doesn't

1. **Stack-allocated batch verifier** — zero heap allocation for block import
2. **Zig-native ThreadPool** with work-stealing — no IPC overhead like TS workers
3. **Processor queue infrastructure** — well-designed priority queues ready to use

### Conclusion: Foundation is Solid, Wiring is Missing

The building blocks are all there:
- `BatchVerifier` ✅ correctly implements batch verification
- `ThreadPool` ✅ correctly parallelizes verification
- `WorkQueues` ✅ correctly prioritizes and batches work items
- `GossipHandler` ✅ correctly validates messages

But they're not connected:
- `GossipHandler` → should push to `BeaconProcessor` → which batches → which dispatches to `ThreadPool`
- Instead: `GossipHandler` → inline BLS verify → inline import

---

## 5. Action Items (Prioritized)

### P0 — Critical (blocks mainnet viability)

1. **[CRITICAL] Implement gossip BLS batching**
   - Create a `BlsVerifierPool` that collects signature sets from gossip
   - Buffer sets with max-count (32) and max-wait (100ms) triggers
   - On flush: batch verify with random scalars via ThreadPool
   - On batch fail: retry individually to identify bad signature
   - Wire into gossip_handler: replace inline `verify*SignatureFn` calls with pool submission

2. **[CRITICAL] Wire gossip handler to processor queues**
   - GossipHandler Phase 1 → ACCEPT → push WorkItem to BeaconProcessor
   - BeaconProcessor pops by priority → handler dispatches BLS verify + import
   - This enables priority ordering, backpressure, and sync-aware dropping

### P1 — Important (significant performance impact)

3. **[IMPORTANT] Wire ThreadPool to block import BatchVerifier**
   - Create ThreadPool at BeaconNode startup
   - Pass to `BatchVerifier.init(pool)` in chain.zig and beacon_node.zig
   - Estimated 2-4x speedup for block import on multi-core machines

4. **[IMPORTANT] Fix `fillRandomScalars` portability and security**
   - Replace `std.os.linux.getrandom` with `std.crypto.random.bytes()`
   - Remove the weak ChaCha fallback (std.crypto.random handles all platforms)
   - This is a one-line fix

5. **[IMPORTANT] Eliminate double/triple decompression**
   - Decompress once, pass SSZ bytes to all phases
   - Saves ~2x decompression work per gossip message

### P2 — Nice to have

6. **[MINOR] Fix `RAND_BYTES` inconsistency**
   - Remove unused `RAND_BYTES` constant from batch_verifier.zig
   - Only fill 8 bytes of randomness per scalar (matching RAND_BITS = 64)

7. **[MINOR] Use `lock()` instead of `tryLock` spinloop in ThreadPool**
   - `dispatch_mutex.lock()` is cleaner and doesn't burn CPU

8. **[MINOR] Add block signature bisection on batch failure**
   - When `batch.verifyAll()` fails, bisect to find the bad signature
   - TS Lodestar retries individually; bisection is O(log N) vs O(N)

---

## 6. Detailed Fix Sketches

### Fix CRITICAL-1 + CRITICAL-2: Gossip BLS Batching Pool

The core architectural change needed. Create `src/bls/gossip_bls_pool.zig`:

```zig
/// GossipBlsPool — collects gossip signature sets, batch-verifies them.
///
/// Architecture:
///   gossip_handler → pool.submit(sig_sets, callback) → buffer
///   buffer flush (count or timeout) → ThreadPool.verifyMultipleAggregateSignatures
///   result → callback(true/false) → gossip_handler continues import or reject
///
/// This is the Zig equivalent of TS Lodestar's BlsMultiThreadWorkerPool.
pub const GossipBlsPool = struct {
    thread_pool: *ThreadPool,
    // Buffer of pending signature sets
    pending_sets: BoundedArray(PendingSet, MAX_BUFFERED),
    // Timer for flush timeout
    flush_deadline_ns: ?i128,

    const MAX_BUFFERED = 32;
    const MAX_WAIT_NS = 100 * std.time.ns_per_ms; // 100ms

    const PendingSet = struct {
        sig_set: SignatureSet,
        callback: *const fn (valid: bool) void,
    };

    pub fn submit(self: *GossipBlsPool, set: SignatureSet, callback: ...) void {
        self.pending_sets.append(.{ .sig_set = set, .callback = callback });
        if (self.pending_sets.len >= MAX_BUFFERED) {
            self.flush();
        } else if (self.flush_deadline_ns == null) {
            self.flush_deadline_ns = now() + MAX_WAIT_NS;
        }
    }

    pub fn flush(self: *GossipBlsPool) void {
        // Batch verify all pending sets
        // On failure: retry individually
    }
};
```

### Fix ISSUE-5: Portable Random Scalars

```zig
fn fillRandomScalars(rands: [][32]u8) void {
    const bytes = std.mem.sliceAsBytes(rands);
    std.crypto.random.bytes(bytes);
}
```

### Fix ISSUE-4: Single Decompression

```zig
pub fn onAttestation(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
    // Decompress ONCE
    const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
        return GossipHandlerError.DecodeFailed;
    defer self.allocator.free(ssz_bytes);

    // Decode from already-decompressed bytes
    const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_attestation, ssz_bytes) catch
        return GossipHandlerError.DecodeFailed;
    const att = decoded.beacon_attestation;

    // Phase 1b: Fast validation (uses decoded fields, no bytes needed)
    // ...

    // Phase 1c: BLS verification (reuse ssz_bytes, no re-decompression)
    if (self.verifyAttestationSignatureFn) |verifyFn| {
        if (!verifyFn(self.node, ssz_bytes)) {
            return GossipHandlerError.ValidationRejected;
        }
    }

    // Phase 2: Import (reuse ssz_bytes)
    // ...
}
```

---

## 7. Test Coverage Assessment

| Component | Tests | Coverage | Notes |
|-----------|-------|----------|-------|
| BatchVerifier | 8 tests | ✅ Good | Empty, single, multi, aggregate, same-message, invalid, reset, thread pool |
| ThreadPool | 2 tests | 🟡 Adequate | Multi-threaded verify + aggregate verify |
| gossip_validation (chain) | 14 tests | ✅ Good | Block, attestation, aggregate, data column |
| gossip_handler | 8 tests | ✅ Good | Block import, dedup, future/finalized, attestation, aggregate |
| processor | 4 tests | 🟡 Adequate | Priority, drain, metrics, sync state |
| work_queues | 2 tests | 🟡 Adequate | Priority, sync-aware |

Missing test coverage:
- ThreadPool edge cases: 0 elements, 1 element, N > workers, shutdown during work
- BatchVerifier overflow (MAX_SETS_PER_BLOCK exceeded)
- Gossip BLS verification integration (currently mocked with null callbacks)
- Processor batch formation from queue

---

## 8. Summary

**The foundation is excellent.** The BLS batch verifier is correctly implemented, the ThreadPool works properly, and the processor queue design is solid. The codebase shows thoughtful engineering with good documentation, comprehensive tests, and proper memory management.

**The critical gap is plumbing.** The pieces exist but aren't connected for the gossip hot path. Gossip BLS verification happens one-at-a-time, bypassing both the batch verifier and the thread pool. This is the single biggest performance issue and would make mainnet operation infeasible at current validator counts.

**Priority for fixes:**
1. Fix `fillRandomScalars` portability (5-minute fix, unblocks non-Linux)
2. Eliminate double decompression (moderate refactor)
3. Wire ThreadPool to block import (small change, 2-4x block import speedup)
4. Implement gossip BLS batching pool (large feature, 10-50x gossip throughput)
5. Wire gossip handler to processor queues (large refactor, enables backpressure)

Items 4 and 5 are the architectural centerpiece and should be designed together, but items 1-3 are quick wins that can land immediately.
