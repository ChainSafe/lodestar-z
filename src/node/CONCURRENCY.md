# Concurrency Model Analysis: lodestar-z vs TS Lodestar vs Lighthouse

*Deep analysis of threading, I/O, and work distribution — March 2026*

---

## 1. Current Model: lodestar-z

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        Main Thread (std.Io)                       │
│                                                                  │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────────┐  │
│  │ HTTP API │  │ P2P/QUIC │  │ Slot Clock │  │ Sync Service  │  │
│  │ (fiber)  │  │ (fiber)  │  │  (fiber)   │  │  (inline)     │  │
│  └────┬─────┘  └────┬─────┘  └─────┬──────┘  └──────┬────────┘  │
│       │              │              │                │            │
│       │      ┌───────▼───────┐      │                │            │
│       │      │ GossipHandler │      │                │            │
│       │      │  (inline)     │      │                │            │
│       │      └───────┬───────┘      │                │            │
│       │              │              │                │            │
│       └──────────────▼──────────────▼────────────────▘            │
│                      │                                            │
│              ┌───────▼──────────┐                                 │
│              │  BeaconNode      │                                 │
│              │  .importBlock()  │  ← ALL block processing here   │
│              │  .importAttest() │  ← ALL attestation processing  │
│              │  .verifyExec()   │  ← ALL EL calls here           │
│              └───────┬──────────┘                                 │
│                      │                                            │
│              ┌───────▼──────────┐                                 │
│              │  State Transition│  ← CPU-bound, BLOCKS main loop │
│              │  (synchronous)   │                                 │
│              └──────────────────┘                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    BLS ThreadPool (separate threads)              │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Worker 0 │ │ Worker 1 │ │ Worker 2 │ │ Worker N │  N ≤ 16   │
│  │ (main)   │ │ (thread) │ │ (thread) │ │ (thread) │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│                                                                  │
│  Used for: batch BLS verify (block import), aggregate verify     │
│  NOT used for: gossip attestation BLS, gossip block proposer BLS │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    BeaconProcessor (DEFINED but NOT WIRED)        │
│                                                                  │
│  WorkQueues: ~35 priority queues, FIFO+LIFO, batch formation     │
│  ❌ Not instantiated by BeaconNode                               │
│  ❌ No work items flow through it                                │
│  ❌ Gossip → import is all inline on the main fiber              │
└──────────────────────────────────────────────────────────────────┘
```

### Subsystem-by-Subsystem Breakdown

#### 1.1 Entry Point (`main.zig`)

- **Thread:** Main thread only.
- **I/O:** `std.Io` (cooperative evented I/O; io_uring on Linux in 0.16).
- **Concurrency:** Three fibers via `Io.Group.async`:
  1. `runApiServer` — HTTP accept loop
  2. `runP2p` — P2P service (QUIC + gossipsub + sync loop)
  3. `runSlotClock` — slot timing loop
- **Key insight:** All three fibers share a single OS thread via cooperative scheduling. A CPU-bound operation in any fiber blocks the other two.

#### 1.2 BeaconNode (`beacon_node.zig`)

- **Thread:** Main fiber.
- **Communication:** Direct function calls — no channels, no queues.
- **Locks/Mutexes:** None within BeaconNode itself.
- **I/O:** `std.Io` stored in `self.io`, passed to Engine API and P2P.
- **Critical path:** `importBlock()` is fully synchronous on the calling fiber:
  1. `verifySanity()` — cheap
  2. `runStateTransition()` — **CPU-bound, 10ms–500ms+ for epoch transitions**
  3. `verifyExecutionPayload()` — **network I/O to EL, 50ms–200ms**
  4. `regen.onNewBlock()` — state cache update
  5. `fork_choice.onBlock()` — fork choice update
  6. `notifyForkchoiceUpdate()` — **network I/O to EL**

#### 1.3 Gossip Handler (`gossip_handler.zig`)

- **Thread:** Main fiber (called from `processGossipEventsFromSlice`).
- **Processing model:** Fully inline — decompress → validate → BLS verify → import, all synchronous.
- **No queueing:** Despite `BeaconProcessor` and `WorkQueues` being implemented, they are never instantiated. Gossip messages are processed one-at-a-time on the main loop.
- **BLS verification:** Calls individual `verifySingleSignatureSet()` per message — **not batched** for gossip. Only block import uses `BatchVerifier`.

#### 1.4 Processor (`processor.zig` + `work_queues.zig`)

- **Status: IMPLEMENTED but UNWIRED.**
- `BeaconProcessor` has a complete priority queue system (~35 queues), batch formation for attestations/aggregates, sync-aware dropping, and metrics.
- `WorkQueues.popHighestPriority()` implements Lighthouse-style strict priority ordering.
- **Gap:** No code instantiates `BeaconProcessor` or pushes `WorkItem`s into it. All gossip processing bypasses it entirely.

#### 1.5 BLS ThreadPool (`ThreadPool.zig`)

- **Threads:** Up to 16 workers (configurable). Worker 0 = calling thread.
- **Communication:** `std.Io.Event` for signaling, `std.atomic.Value` for shutdown flag, `std.atomic.Mutex` for dispatch serialization.
- **Work items:** `verifyMultipleAggregateSignatures` and `aggregateVerify` — pairing-based batch BLS.
- **Usage:** Used by `BlockImporter.runStateTransition()` (via `BatchVerifier`) for block-level batch signature verification.
- **NOT used for:** Individual gossip BLS checks (attestations, aggregates, exits). These use `verifySingleSignatureSet()` on the main thread.

#### 1.6 Chain (`chain.zig`)

- **Thread:** Main fiber.
- **Block import:** Synchronous STFN pipeline. No async, no work offloading.
- **Epoch transitions:** Run inline during `processSlots()` — **this is the #1 latency problem**. On mainnet, epoch transitions take 200ms–800ms, during which the entire event loop is blocked.

#### 1.7 Queued State Regen (`queued_regen.zig`)

- **Thread:** Main fiber.
- **Design:** Has a priority queue for regen requests with dedup, but `processNext()` is synchronous. "The queue is processed inline via processNext(). When the beacon node moves to multi-threaded (std.Io fibers), the queue will be drained by a dedicated worker."
- **Current state:** Fast path only (cache hit or synchronous regen). No background processing.

#### 1.8 Sync Service (`sync_service.zig`)

- **Thread:** Main fiber. `tick()` called from the P2P maintenance loop.
- **Communication:** `SyncCallbackCtx` bridges sync state machine → P2P transport via a fixed-size array of `PendingBatchRequest[32]` (effectively a bounded channel).
- **Block fetching:** `fetchRawBlocksByRange` does blocking stream I/O on the main fiber.
- **Processing:** `onBatchResponse` → `importBlock` — synchronous on the calling fiber.

#### 1.9 P2P Service (`p2p_service.zig`)

- **Thread:** Main fiber via `std.Io` cooperative scheduling.
- **Transport:** QUIC via lsquic (C library), integrated through `std.Io`.
- **Gossipsub:** Events polled via `gossipsub.drainEvents()` in the 6-second maintenance loop.
- **No dedicated network thread:** All network I/O is multiplexed on the same fiber as block processing.

#### 1.10 HTTP API Server (`http_server.zig`)

- **Thread:** Runs as a fiber in the Io.Group alongside P2P and slot clock.
- **Model:** `std.http.Server` with blocking accept loop per-connection.
- **Problem:** Handler calls (e.g., `getHeadState`, `importBlock`) execute synchronously on the API fiber. During a block import or epoch transition, the API is unresponsive.

#### 1.11 Engine API (`http_engine.zig`)

- **Thread:** Main fiber.
- **Transport:** Pluggable `Transport` interface. Production uses `IoHttpTransport` (std.http.Client over std.Io).
- **I/O model:** Cooperative via `std.Io` — HTTP requests yield to the event loop while waiting for the EL response.
- **JWT auth:** Per-request JWT generation (cheap, no I/O).

#### 1.12 Validator Client (`validator.zig`)

- **Thread:** Separate process (connects to BN via HTTP API).
- **Services:** Block, attestation, sync committee services — each driven by slot clock callbacks.
- **I/O:** `std.Io` for HTTP calls to the beacon node.

---

## 2. TS Lodestar Concurrency Model

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Node.js Event Loop (single thread)             │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  Fastify     │  │ js-libp2p    │  │  Chain (gossip→import) │  │
│  │  HTTP API    │  │ (TCP+noise)  │  │  sequential on EL      │  │
│  └──────────────┘  └──────────────┘  └───────────┬────────────┘  │
│                                                  │               │
│                                          ┌───────▼──────────┐    │
│                                          │ GossipHandlers   │    │
│                                          │ → validate       │    │
│                                          │ → BLS to workers │    │
│                                          │ → import inline  │    │
│                                          └──────────────────┘    │
│                                                                  │
│  ❗ Epoch transitions BLOCK the event loop for 200-800ms         │
│  ❗ processSlots runs synchronously on the main thread           │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│               BLS Worker Pool (worker_threads)                    │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Worker 1 │ │ Worker 2 │ │ Worker 3 │ │ Worker N │  N=cores-1│
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│                                                                  │
│  - Receives serialized signature sets via postMessage            │
│  - Batch BLS verification (maybeBatch: up to 128 sets/job)      │
│  - Results returned via Promise (resolved on event loop)         │
│  - Buffered for 100ms (MAX_BUFFER_WAIT_MS) to increase batch %  │
│                                                                  │
│  Used for: ALL BLS verification (gossip + block import)          │
└──────────────────────────────────────────────────────────────────┘
```

### Key Properties

| Dimension | TS Lodestar |
|-----------|-------------|
| **Main thread** | Node.js event loop — single-threaded |
| **BLS offloading** | `BlsMultiThreadWorkerPool` — `worker_threads` (cores-1 workers) |
| **BLS batching** | Yes: 100ms buffer + 32-sig threshold. Gossip sigs batched. |
| **Epoch transitions** | **BLOCKS event loop** — known 200-800ms stall on mainnet |
| **Block import** | Sequential on event loop after BLS returns from workers |
| **Gossip validation** | Phase 1 (cheap) inline → BLS to worker pool → Phase 2 inline |
| **Network I/O** | Node.js async (libuv) — non-blocking |
| **HTTP API** | Fastify — async, shares event loop |
| **Engine API** | async HTTP (fetch/undici) |
| **Gossip priority** | No priority queues — FIFO processing |

### Strengths
- All BLS verification is offloaded to workers (even gossip attestations).
- 100ms batching window significantly reduces BLS verification time (2x improvement).
- Network I/O never blocks the event loop.

### Weaknesses
- **Epoch transitions block the event loop** — the biggest known perf issue.
- No priority queues — blocks and attestations compete for event loop time.
- Single-threaded state transition — no parallelism for STFN.
- Worker→main thread serialization overhead for BLS results.

---

## 3. Lighthouse Concurrency Model

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Tokio Runtime (multi-threaded)                    │
│                  Default: num_cpus threads                        │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              BeaconProcessor                              │    │
│  │  ┌─────────────────────────────────────────────┐          │    │
│  │  │ Priority-weighted work queue                 │          │    │
│  │  │ ~40 work types, strict priority ordering     │          │    │
│  │  │ Channel-based: network → processor           │          │    │
│  │  │ mpsc::channel with backpressure              │          │    │
│  │  └─────────────┬───────────────────────────────┘          │    │
│  │                │                                          │    │
│  │  ┌─────────────▼───────────────────────────────┐          │    │
│  │  │ Work execution (Tokio tasks + spawn_blocking)│          │    │
│  │  │ - Lightweight: inline on Tokio thread        │          │    │
│  │  │ - CPU-heavy: spawn_blocking (thread pool)    │          │    │
│  │  │ - BLS-heavy: spawn_blocking_with_rayon       │          │    │
│  │  └─────────────────────────────────────────────┘          │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Axum HTTP API│  │ libp2p       │  │ Slot clock (timer)   │   │
│  │ (async)      │  │ (Tokio async)│  │ (Tokio interval)     │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    Rayon Thread Pool (dedicated)                   │
│                                                                  │
│  Two pools: HighPriority + LowPriority                           │
│  Used for: signature verification, parallel epoch processing      │
│  spawn_blocking_with_rayon_async for CPU-bound work              │
└──────────────────────────────────────────────────────────────────┘
```

### Key Properties

| Dimension | Lighthouse |
|-----------|------------|
| **Runtime** | Tokio multi-threaded (num_cpus threads) |
| **Work scheduling** | `BeaconProcessor` — priority-weighted channel + work types |
| **BLS offloading** | Rayon thread pool (separate from Tokio) via `spawn_blocking_with_rayon_async` |
| **BLS batching** | Yes — via `verify_signature_sets` with parallel Rayon workers |
| **Epoch transitions** | `spawn_blocking` — does NOT block the async runtime |
| **Block import** | Async pipeline: parallel sig verify → sequential STFN → async FC update |
| **Network I/O** | Tokio async (non-blocking) |
| **HTTP API** | Axum (Tokio async) — fully non-blocking |
| **Engine API** | async HTTP via Reqwest (Tokio) |
| **Gossip priority** | ~40 work types with strict priority ordering |

### Strengths
- **Nothing blocks the network I/O.** CPU work is always on `spawn_blocking` or Rayon.
- Priority queues ensure blocks and sync messages are processed before attestations.
- Epoch transitions don't stall the network or API.
- Two Rayon pools (high/low priority) prevent background work from starving critical-path BLS.
- Full async pipeline for block verification.

### Weaknesses
- Complexity — many moving parts (Tokio + Rayon + channels + priorities).
- Memory overhead from Tokio runtime and Rayon pools.
- Contention under extreme load (all work types compete for Tokio threads).

---

## 4. Comparison Table

| Dimension | lodestar-z (Zig) | TS Lodestar | Lighthouse |
|-----------|-------------------|-------------|------------|
| **Threading model** | Single-threaded + BLS pool | Single-threaded + BLS workers | Multi-threaded Tokio + Rayon |
| **Event loop** | std.Io (io_uring) cooperative fibers | Node.js libuv | Tokio (epoll/io_uring) |
| **Gossip processing** | Inline on main fiber | Inline on event loop | Priority-queued, dispatched to Tokio tasks |
| **BLS for gossip** | ❌ Single-threaded, one-at-a-time | ✅ Worker pool, batched (100ms window) | ✅ Rayon pool, batched |
| **BLS for blocks** | ✅ ThreadPool batch verify | ✅ Worker pool | ✅ Rayon pool |
| **Epoch transitions** | ❌ Blocks everything | ❌ Blocks event loop | ✅ spawn_blocking |
| **Block import pipeline** | Synchronous on main fiber | Sequential on event loop | Async pipeline |
| **Engine API** | Cooperative I/O (yields) | Async HTTP | Async HTTP |
| **HTTP API** | Fiber (blocks during chain ops) | Async (blocks during epoch) | Fully async |
| **Priority queues** | ❌ Defined but not wired | ❌ None | ✅ ~40 work types |
| **Sync-aware dropping** | ❌ Defined but not wired | Partial | ✅ Full |
| **Network I/O blocking** | Minimal (std.Io cooperative) | None (libuv async) | None (Tokio async) |
| **STFN parallelism** | None | None | `spawn_blocking` |
| **State regen offloading** | None (inline) | None (inline) | `spawn_blocking` |

---

## 5. Critical Gaps — Where lodestar-z Will Fail at Mainnet Scale

### Gap 1: Gossip BLS Not Batched or Offloaded (CRITICAL)

**Problem:** Every gossip attestation, aggregate, voluntary exit, sync committee message, and block proposer signature is verified individually on the main fiber via `verifySingleSignatureSet()`. On mainnet, ~15,000 attestations arrive per slot (every 12s). Each BLS verify takes ~1ms. That's **15 seconds of BLS work per 12-second slot** — the node cannot keep up.

**TS Lodestar fix:** Worker pool + 100ms batching window. Gossip BLS is always offloaded.
**Lighthouse fix:** Rayon pool + beacon_processor priority queue batching.

**Required fix:** Wire the BLS ThreadPool for gossip verification. The `GossipHandler` should collect signature sets and dispatch them in batches to `ThreadPool.verifyMultipleAggregateSignatures()`.

### Gap 2: Epoch Transitions Block Everything (CRITICAL)

**Problem:** `processSlots()` during epoch boundary blocks runs inline on the main fiber. On mainnet with 1M+ validators, this takes 200-800ms. During this time:
- No gossip messages are processed
- No API requests are served
- No network I/O progresses (QUIC keepalives may time out)
- No sync batches are dispatched

**TS Lodestar status:** Same problem — known issue, mitigated only by fast JS execution.
**Lighthouse fix:** `spawn_blocking` — epoch transition runs on a blocking thread pool.

**Required fix:** Run epoch transitions on a dedicated std.Thread or background fiber. The main loop must not be blocked by CPU-bound work.

### Gap 3: BeaconProcessor Not Wired (HIGH)

**Problem:** The entire `processor/` subsystem (`BeaconProcessor`, `WorkQueues`, `WorkItem`) is implemented but never instantiated. All gossip and sync work is processed inline without priority ordering or queue-full dropping.

**Impact:**
- During sync, low-priority gossip attestations compete with high-priority sync blocks.
- No backpressure — a burst of gossip can overwhelm processing.
- No batch formation for attestations (the WorkQueues have this logic ready).

**Required fix:** Instantiate `BeaconProcessor` in `BeaconNode`, route all gossip/sync/API work through it, and drain it from a fiber.

### Gap 4: Engine API Calls Are Latency-Sensitive (MEDIUM)

**Problem:** `verifyExecutionPayload()` and `notifyForkchoiceUpdate()` make HTTP calls to the EL inline during block import. While `std.Io` makes these cooperative (they yield), the block import pipeline is blocked until the EL responds (50-200ms typically, up to 12s under load).

**TS Lodestar status:** Same — EL calls are async but block the import pipeline.
**Lighthouse status:** Same pattern, but the async runtime allows other work to progress.

**Required fix:** Not critical for now (same as TS Lodestar), but consider optimistic import where EL verification runs in parallel with the next block's STFN.

### Gap 5: HTTP API Blocks During Chain Operations (MEDIUM)

**Problem:** The HTTP API server runs as a fiber, but handler functions (e.g., `getHeadState`, `importBlock` via API) execute synchronously. During epoch transitions or EL calls, the API is completely unresponsive.

**Lighthouse fix:** Axum handlers spawn async tasks; state access is through `Arc<RwLock<_>>`.

**Required fix:** Either dedicate a separate thread for the API server, or ensure all handler functions are non-blocking (return cached data, never call STFN inline).

### Gap 6: No Gossip Validation Parallelism (MEDIUM)

**Problem:** Gossip messages are processed sequentially in `processGossipEventsFromSlice()`. On mainnet, thousands of messages arrive per slot. Sequential processing creates a growing backlog.

**Lighthouse fix:** `BeaconProcessor` dispatches work items to Tokio tasks — multiple gossip messages can be validated concurrently across Tokio threads.

**Required fix:** Wire the processor queue, then process work items from multiple fibers or threads.

---

## 6. std.Io Roadmap — How Zig 0.16 Changes the Picture

Zig 0.16-dev (our current version) introduces `std.Io` — cooperative, evented I/O backed by io_uring on Linux and GCD on macOS. This fundamentally changes what's possible:

### What std.Io Gives Us
- **Cooperative fibers:** Multiple logical threads of execution on a single OS thread. Network I/O, timers, and file I/O yield automatically.
- **io_uring integration:** Zero-copy, kernel-level async I/O. HTTP server accept/read/write, EL HTTP calls, and DB reads can all be non-blocking without explicit async/await.
- **`Io.Group.async`:** Spawn concurrent fibers within a single thread. Already used for API + P2P + clock.

### What std.Io Does NOT Give Us
- **CPU parallelism:** Fibers share one thread. CPU-bound work (STFN, BLS, hashing) still blocks all fibers.
- **Work stealing:** No built-in multi-threaded runtime like Tokio. Each `Io.Group` runs on one thread.
- **Preemptive scheduling:** Fibers must yield cooperatively. A long computation stalls everything.

### Proposed std.Io Architecture for Production

```
┌────────────────────────────────────────────────────────────────────┐
│  Thread 1: Network + API I/O (std.Io event loop)                   │
│  - HTTP API accept + handlers                                      │
│  - QUIC P2P transport (gossipsub, req/resp)                        │
│  - Engine API HTTP calls                                           │
│  - Slot clock + timers                                             │
│  - Gossip Phase 1 validation (cheap, < 1ms)                        │
│  - Routes work items to BeaconProcessor channel                    │
└─────────────────────────┬──────────────────────────────────────────┘
                          │ mpsc channel (WorkItem)
┌─────────────────────────▼──────────────────────────────────────────┐
│  Thread 2: BeaconProcessor (drains priority queues)                 │
│  - Pops highest-priority item                                      │
│  - Dispatches to handlers                                          │
│  - Lightweight handlers: inline                                    │
│  - CPU-heavy handlers: dispatch to Thread 3                        │
│  - BLS handlers: dispatch to BLS ThreadPool                        │
└─────────────────────────┬──────────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────────┐
│  Thread 3: STFN Worker (dedicated)                                  │
│  - processSlots() + processBlock()                                  │
│  - Epoch transitions                                               │
│  - State root computation                                          │
│  - Runs on dedicated thread to never block I/O                     │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│  Threads 4..4+N: BLS ThreadPool (existing)                         │
│  - Batch BLS verification for gossip + blocks                      │
│  - N = num_cpus - 3 (reserve for I/O, processor, STFN)            │
└────────────────────────────────────────────────────────────────────┘
```

### Key Design Principle

**The I/O thread must NEVER do CPU work.** All CPU-bound operations (STFN, BLS, hashing) must be dispatched to dedicated threads. The I/O thread only does:
- Network packet handling (QUIC, HTTP)
- Gossip Phase 1 validation (< 1ms checks)
- Work item routing (push to channel)
- Timer/clock management

This is the same principle behind Lighthouse's Tokio + spawn_blocking design.

---

## 7. Thread Budget — Proposed Production Allocation

| Thread | Role | CPU Characteristics |
|--------|------|---------------------|
| **1** | I/O event loop (std.Io) | Mostly idle, burst on packet arrival |
| **2** | BeaconProcessor | Dispatch + lightweight handling |
| **3** | STFN worker | CPU-heavy during block import + epoch transitions |
| **4..N** | BLS ThreadPool | CPU-heavy during gossip + block verification |

**For a 4-core machine:** 1 I/O + 1 processor + 1 STFN + 1 BLS worker = 4 threads.
**For an 8-core machine:** 1 I/O + 1 processor + 1 STFN + 5 BLS workers = 8 threads.
**For a 16-core machine:** 1 I/O + 1 processor + 1 STFN + 13 BLS workers = 16 threads.

The BLS ThreadPool already supports up to 16 workers and uses the calling thread as worker 0, so it naturally adapts to available cores.

---

## 8. Prioritized Recommendations

### P0 — Must Fix Before Mainnet Testing

1. **Wire BLS ThreadPool for gossip BLS verification.**
   - Modify `GossipHandler` to collect signature sets into a buffer.
   - After Phase 1 validation, batch and dispatch to `ThreadPool.verifyMultipleAggregateSignatures()`.
   - This is the single highest-impact change — without it, the node can't validate mainnet gossip volume.

2. **Move epoch transitions off the main fiber.**
   - Option A: Run `processSlots()` on a `std.Thread` and wait for completion.
   - Option B: Use `Io.Group.async` with a background fiber and a completion event.
   - Either way, the main event loop must not stall for 200-800ms.

3. **Wire BeaconProcessor.**
   - Instantiate `BeaconProcessor` in `BeaconNode.init()`.
   - Route gossip messages through `processor.ingest()` instead of inline processing.
   - Call `processor.dispatchOne()` in the main loop (or a dedicated fiber).
   - This unlocks: priority ordering, sync-aware dropping, batch formation, backpressure.

### P1 — Required for Stable Mainnet Operation

4. **Add a thread-safe work channel between I/O and processor.**
   - The I/O fiber produces `WorkItem`s; the processor thread consumes them.
   - Use `std.Thread.ResetEvent` + atomic ring buffer (or `std.Thread.Channel` when available).

5. **Dedicate a STFN worker thread.**
   - Block import's `runStateTransition()` should be dispatched to a dedicated thread.
   - Use an event-based completion signal so the I/O fiber can continue.

6. **Non-blocking API handlers.**
   - `getHeadState` should return a cached snapshot, not access the live state.
   - `importBlock` via API should enqueue to the processor, not execute inline.

### P2 — Performance Optimization

7. **Gossip BLS batching with a time window.**
   - Like TS Lodestar's 100ms buffer: collect incoming attestation signature sets, verify in batch after 100ms or 32 sets (whichever comes first).
   - Batch BLS is ~2x faster than individual verification.

8. **Parallel gossip validation.**
   - Process multiple gossip work items concurrently from the processor queue.
   - Requires either multiple processor fibers or a small worker pool.

9. **Optimistic EL verification.**
   - Start processing the next block's STFN while the EL verifies the current block's execution payload.
   - Requires careful state management but reduces critical-path latency.

---

## Appendix: Source File Reference

| File | Role | Threading |
|------|------|-----------|
| `src/node/main.zig` | Entry point, CLI, Io.Group.async for services | Main thread |
| `src/node/beacon_node.zig` | Node orchestrator, block import, gossip routing | Main fiber |
| `src/node/gossip_handler.zig` | Two-phase gossip validation | Main fiber (inline) |
| `src/processor/processor.zig` | BeaconProcessor (priority dispatch) | **NOT WIRED** |
| `src/processor/work_queues.zig` | ~35 priority queues, batch formation | **NOT WIRED** |
| `src/processor/work_item.zig` | Work item types | **NOT WIRED** |
| `src/bls/ThreadPool.zig` | Multi-threaded BLS verification | Separate threads |
| `src/chain/chain.zig` | Chain coordinator | Main fiber |
| `src/chain/queued_regen.zig` | State regen with queue/dedup | Main fiber (sync) |
| `src/sync/sync_service.zig` | Sync state machine | Main fiber |
| `src/networking/p2p_service.zig` | QUIC + gossipsub + req/resp | Main fiber (std.Io) |
| `src/api/http_server.zig` | Beacon REST API | Fiber (std.Io) |
| `src/execution/http_engine.zig` | Engine API HTTP client | Main fiber (std.Io) |
| `src/validator/validator.zig` | Validator client | Separate process |
