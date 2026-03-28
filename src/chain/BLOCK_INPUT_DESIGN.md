# Async Block Input Design — Data Waiting with std.Io

## Problem

On gossip, blocks and their associated data (blobs in Deneb, columns in Fulu/PeerDAS) arrive
independently. A block may arrive BEFORE all its blobs/columns. The node must:

1. Receive block → check if blobs/columns are needed → wait for them with timeout
2. Receive blob/column → check if it completes a pending block → if yes, make available
3. After timeout → mark block as data-unavailable for rejection

TS Lodestar solves this with `blockInput.ts` (~1,005 LOC) using JavaScript Promises.
We need the Zig equivalent using `std.Io`.

## std.Io Analysis

Zig 0.16's `std.Io` provides:

| Primitive       | Description                                          | Our use?         |
|-----------------|------------------------------------------------------|------------------|
| `Io.Event`      | One-shot futex-based signal (set/wait/waitTimeout)   | **YES — chosen** |
| `Io.Future(T)`  | Async task result (async/await/cancel)               | No — task-scoped |
| `Io.Group`      | Spawn multiple async tasks, await all                | No — task-scoped |
| `Io.Queue(T)`   | MPMC concurrent queue with blocking get/put          | No — overkill    |
| `Io.Semaphore`  | Counting semaphore                                   | No               |
| `Io.Mutex`      | Futex-based mutex                                    | YES — for state  |
| `Io.Timeout`    | Duration or deadline                                 | YES — for wait   |
| `futexWait/Wake`| Raw futex operations                                 | Via Event        |

### Why `Io.Event`?

`Io.Event` is exactly what we need:
- **One-shot boolean** — transitions from `unset` → `is_set`
- **`waitTimeout(io, timeout)`** — blocks fiber until set or timeout (returns `error.Timeout`)
- **`set(io)`** — wakes all waiters, stays set forever (subsequent waits return immediately)
- **`reset()`** — resets to unset (for reuse, but we don't reuse)
- **Lightweight** — single `u32` atomic word, futex-based
- **Thread-safe** — designed for cross-fiber/cross-thread signaling

The pattern maps directly to our need:

```
Block arrives → create Event (unset) → fiber calls event.waitTimeout(io, 6s)
Blob arrives  → if completes block → event.set(io) → fiber wakes up
Timeout       → waitTimeout returns error.Timeout → block marked data-unavailable
```

### Alternatives Considered

**`Io.Future`**: Requires spawning an async task that produces the result. Our case is
different — the "producer" (blob arriving on gossip) isn't a spawned task, it's an
external event. Event is a better fit.

**`Io.Queue`**: Too heavyweight. We don't need a producer/consumer channel — we need
a simple "signal when done" primitive.

**`std.Thread.Condition + Mutex`**: Would work but doesn't integrate with the Io
event loop. `Io.Event` uses the same futex mechanism but participates in cancelation.

## State Machine

```
                    ┌─────────────┐
   block arrives →  │  PreData     │  (block received, waiting for blobs/columns)
                    └──────┬──────┘
                           │
              blobs/columns arrive one by one
                           │
                    ┌──────▼──────┐
                    │  Partial     │  (some data received, more needed)
                    └──────┬──────┘
                           │
              last required piece arrives OR timeout
                    ┌──────▼──────┐         ┌───────────┐
                    │  Available   │ ───OR──▶│ TimedOut   │
                    └──────┬──────┘         └─────┬─────┘
                           │                      │
                    import block           reject / retry
```

In code, this collapses to two states: **pending** (PreData + Partial) and **available**.
Timeout is detected by the caller via `error.Timeout` from `Event.waitTimeout`.

## Data Model

### GossipBlockInput (the manager)

The `GossipBlockInput` manager sits between gossip handlers and the block import pipeline.
It does NOT own blocks or blobs (they come from gossip message pools). It tracks:

- Which blocks are pending (waiting for data)
- Which blobs/columns have been received for each pending block
- Completion events for waiters

### Integration with existing modules

```
                    ┌──────────────────────┐
  gossip blob  ────▶│  GossipBlockInput     │──── AvailableBlockInput ────▶ Block Import
  gossip col   ────▶│  (this module)        │                               Pipeline
  gossip block ────▶│                       │
                    │  Uses:                │
                    │  - BlobTracker        │
                    │  - ColumnTracker      │
                    │  - DataAvailability   │
                    └──────────────────────┘
```

### PendingBlock

```zig
pub const PendingBlock = struct {
    block: AnySignedBeaconBlock,
    block_root: Root,
    source: BlockSource,
    slot: u64,
    expected_blobs: u32,
    received_blobs: std.StaticBitSet(MAX_BLOBS_PER_BLOCK),
    received_columns: std.StaticBitSet(NUMBER_OF_COLUMNS),
    blob_sidecars: [MAX_BLOBS_PER_BLOCK]?BlobSidecarHeader,
    custody_columns: []const u64,  // which columns we need
    created_at_ns: i128,
    completion: std.Io.Event,
};
```

### Completion Flow

**Synchronous path** (no waiting needed):
1. Block arrives → `onBlock()` checks if 0 blobs expected → returns `AvailableBlockInput`
2. Blob arrives → `onBlobSidecar()` checks if block is now complete → returns available

**Async path** (waiting with timeout):
1. Block arrives → `onBlock()` returns null (pending)
2. Caller calls `waitForBlock(io, root, timeout)` which calls `event.waitTimeout(io, timeout)`
3. Eventually blob arrives → `onBlobSidecar()` finds pending, marks bit, if complete → `event.set(io)`
4. Caller's `waitForBlock` returns → calls `getAvailable(root)` to get the assembled input

**Timeout path**:
1. Same as async, but `event.waitTimeout` returns `error.Timeout`
2. Caller handles timeout (marks block as data-unavailable, signals REJECT)

## Timeout Strategy

- Default: **6 seconds** (half a slot = 12s/2)
- Matches TS Lodestar `BLOCK_INPUT_TIMEOUT_MS = 6000`
- If too long: attestation is late (missed reward)
- If too short: valid blocks with slow data rejected

## Range Sync

Range sync fetches blocks AND blobs together via req/resp, so data is always available:

```zig
pub fn assembleFromRangeSync(
    block: AnySignedBeaconBlock,
    blobs: []const BlobSidecarHeader,
    source: BlockSource,
) AvailableBlockInput;
```

No waiting, no timeout, no pending state.

## File: `src/chain/block_input.zig`

New module in the chain package. Re-exported via `src/chain/root.zig`.
