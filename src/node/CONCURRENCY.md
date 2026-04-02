# Concurrency Model

This document is the concurrency design note for the beacon node.

It replaces the older comparison-heavy writeup. The goal here is not to
compare against other clients in the abstract. The goal is to state the
actual ownership rules this codebase should follow, based on the live code.

## Current Facts

The current code has these important properties:

- The main `std.Io` thread is both the I/O reactor and the single writer for
  node and chain state.
- `BeaconNode` and `Chain` are mutated synchronously on that thread.
- The P2P runtime loop is cooperative, but it still runs on the same thread as
  block import, fork choice updates, API callbacks, and sync orchestration.
- `BeaconProcessor` is a real queueing and prioritization layer, but it is not
  a separate executor. `dispatchItem()` runs handlers inline.
- BLS verification is already offloaded to dedicated worker pools:
  - block pool
  - gossip pool
- `QueuedStateRegen` exists, but its slow path is still effectively inline.

Those facts imply the current worst stall is not transport I/O. It is heavy
chain compute, especially state transition and regen work that still runs on
the main thread.

## Current Code Anchors

The main places that define the current shape are:

- `src/node/p2p_runtime.zig`
  - `runLoop()`
  - `runRealtimeP2pTick()`
- `src/node/beacon_node.zig`
  - `completeReadyIngress()`
  - `importReadyBlock()`
- `src/chain/blocks/execute_state_transition.zig`
  - `executeStateTransition()`
- `src/processor/processor.zig`
  - `dispatchItem()`
- `src/node/lifecycle.zig`
  - `initBlsThreadPools()`
- `src/chain/queued_regen.zig`
  - `QueuedStateRegen`

## Design Invariants

These are the rules the code should converge to.

1. There is exactly one owner of mutable node and chain state.
   Today that owner is the main `std.Io` thread. `BeaconNode`, `Chain`,
   fork choice, op pools, peer state, discovery policy, and the processor all
   live under that single-writer rule.

2. Worker threads do pure compute, not shared-state mutation.
   A worker may verify signatures, regenerate state, or run state transition on
   owned inputs. A worker must not directly mutate `BeaconNode`, `Chain`,
   fork choice, peer DB, or discovery state.

3. Heavy compute is queued and bounded.
   Expensive work must go through an explicit bounded service with backpressure.
   No unbounded background spawning.

4. Cache hits may stay inline on the main thread.
   If a gossip validation step can be answered from already-owned chain caches,
   it is correct to do that inline. The problem is uncontrolled heavy misses,
   not all chain-state access.

5. Cache misses must go through a compute service.
   If validation or import needs state regeneration, committee derivation, or
   other expensive cold-path work, it should request that through a queued
   worker service and resume when the result is ready.

6. The transport side must not perform heavyweight chain work directly.
   Network ingress may decode, route, and run cheap Phase 1 checks, but it must
   not run long state transition or regen compute inline just because a message
   arrived.

## Target Execution Shape

The intended near-term shape is:

### 1. Main Thread: I/O + Chain Single Writer

The main `std.Io` thread remains the owner of:

- `BeaconNode`
- `Chain`
- fork choice
- op pools
- peer manager and discovery policy
- API callbacks
- `BeaconProcessor`
- final import/commit side effects

This thread may:

- accept and decode network traffic
- run cheap gossip Phase 1 checks
- consult chain-owned hot caches
- enqueue heavy work
- apply completed results to chain state

This thread should not:

- run long regen or STFN compute inline on the hot path
- wait on heavyweight worker jobs longer than necessary

### 2. STFN / Regen Worker Service

There should be a dedicated queued service for:

- `processSlots()`
- `processBlock()` pre-commit compute
- pre-state regeneration
- other expensive state derivation needed by validation or import

This service should:

- take owned immutable inputs
- deduplicate equivalent requests where useful
- prioritize block import and fork-choice-critical work over background work
- return owned immutable results

This service should not:

- mutate `Chain` directly
- publish events directly
- update peer state or discovery state

The main thread remains responsible for committing the returned effects into
chain state and for publishing any follow-on notifications.

### 3. BLS Worker Pools

BLS stays off the main thread.

The current split is the right direction:

- block BLS pool
- gossip BLS pool

The gossip pool should continue to avoid caller-thread participation on the hot
ingress path. The block pool may use caller participation if that remains the
best tradeoff for block import.

### 4. Processor

`BeaconProcessor` should be treated as:

- the main-thread scheduling and backpressure layer
- not a second state owner

It may remain inline as a scheduler while the main thread is still the single
chain owner. If later profiling shows that processor dispatch itself needs to
move, that should happen only after the STFN/regen boundary is clean.

## Gossip Validation Rule

The important clarification is this:

Gossip validation is allowed to consult chain-owned state when it is running on
the chain-owning thread.

What is not allowed is for some other worker thread to reach into mutable chain
state directly.

So the correct split is:

- hot-path cache hit: validate inline on the main thread
- cold-path cache miss: enqueue regen/STFN work and resume later

This is closer to Lodestar's `NetworkProcessor` + queued regen model than to a
pure "transport thread never touches chain state" model.

## What Not To Do

These are explicit anti-goals:

- Do not turn every subsystem into its own thread pool.
- Do not let worker threads mutate chain state directly.
- Do not split I/O and chain ownership into separate threads before the STFN
  and regen boundary is explicit.
- Do not push Phase 1 gossip validation into a detached worker model just to
  make the architecture look more parallel.
- Do not rely on undocumented implicit ordering between fibers and worker
  callbacks.

## Migration Order

The next steps should happen in this order:

1. Keep the main thread as the single writer for `BeaconNode` and `Chain`.
2. Introduce a real queued STFN/regen worker service.
3. Route the current synchronous block-import compute path through that worker.
4. Route cold-path validation misses through the same service.
5. Re-evaluate whether any further thread split is still necessary.

## Why This Document Is Short

The previous document tried to be a survey. That made it noisy and stale.

This document is intentionally narrower:

- state ownership
- executor boundaries
- allowed cross-thread interactions
- migration order

If code disagrees with this document, the code wins until the document is
updated. The value of this note is in making those disagreements obvious.
