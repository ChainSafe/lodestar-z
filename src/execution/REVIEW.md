# Execution + DB + Sync Subsystem Review

**Reviewer:** lodekeeper-z  
**Date:** 2026-03-28  
**Branch:** feat/beacon-node  
**Scope:** `src/execution/`, `src/db/`, `src/sync/`

---

## Executive Summary

These three subsystems form the backbone of the beacon node's interaction with the execution layer, persistent storage, and chain synchronization. The code is structurally sound — the vtable patterns are idiomatic Zig, the DB layer is clean, and the sync state machines are well-modeled. Test coverage is strong for the happy paths.

However, there are **critical correctness issues** in the execution engine's JSON serialization, **missing functionality** in response decoding (withdrawals, blobs, deposit requests are all stubbed out), and the sync subsystem has a **no-op block import path** that means range sync won't actually import anything yet.

**Verdict: Good scaffolding, not production-ready. The architecture is right; the plumbing needs finishing.**

---

## 1. Execution Engine (`src/execution/`)

### 1.1 Correctness

#### 🔴 CRITICAL: QUANTITY vs DATA encoding mismatch

The Engine API spec distinguishes between:
- **QUANTITY** — variable-length hex, no leading zeros (`"0x1"`, `"0x64"`)
- **DATA** — fixed-length hex, zero-padded (`"0x0000000000000001"`)

`http_engine.zig` uses `hexEncodeU64()` (fixed-width DATA encoding) for fields that should be QUANTITY:

```
blockNumber, gasLimit, gasUsed, timestamp
```

These are QUANTITY fields per the spec. The code uses `hexEncodeU64()` which produces `"0x0000000000000001"` instead of `"0x1"`. While most EL clients are lenient and accept both, this is **spec-non-compliant** and some clients (particularly Besu in strict mode) may reject these.

The `hexEncodeQuantity()` function exists and is used correctly for `hexEncodeQuantityU256()` in the builder, but the execution payload encoding functions don't use it.

**Fix:** Replace `hexEncodeU64` with `hexEncodeQuantity` for all QUANTITY fields in `encodeExecutionPayloadV1/V2/V3/V4`, `encodeWithdrawal`, `encodeDepositRequest`, `encodeWithdrawalRequest`, and `encodePayloadAttributesV1/V2`.

#### 🔴 CRITICAL: Withdrawal index/amount are DATA-encoded but spec says QUANTITY

In `encodeWithdrawal()`:
```zig
const index_hex = try hexEncodeU64(allocator, w.index);
const vi_hex = try hexEncodeU64(allocator, w.validator_index);
const amt_hex = try hexEncodeU64(allocator, w.amount);
```

Per the Engine API spec, `index`, `validatorIndex`, and `amount` in `WithdrawalV1` are all QUANTITY. These should use `hexEncodeQuantity`.

#### 🔴 CRITICAL: `base_fee_per_gas` encoding is wrong

The encoding uses `hexEncodeU256` (fixed 64-char DATA encoding) for `base_fee_per_gas`. The Engine API spec says `baseFeePerGas` is a **QUANTITY** (variable-length, no leading zeros). This should use `hexEncodeQuantityU256`.

#### 🟡 MEDIUM: Response decoding drops withdrawals and blobs

`decodeGetPayloadResponse()` (V3) ignores the `withdrawals` array:
```zig
.withdrawals = &.{},  // ← silently dropped
```

`decodeGetPayloadResponseV4()` drops withdrawals, deposit_requests, withdrawal_requests, and consolidation_requests:
```zig
.withdrawals = &.{},
.deposit_requests = &.{},
.withdrawal_requests = &.{},
.consolidation_requests = &.{},
```

`decodeGetPayloadResponseV2()` has the same issue.

The BlobsBundle is also stubbed to empty in V3 and V4 decoders:
```zig
.blobs_bundle = .{ .commitments = &.{}, .proofs = &.{}, .blobs = &.{} },
```

The `decodeWithdrawals()` function literally returns `[0]Withdrawal{}`:
```zig
fn decodeWithdrawals(withdrawals: []const WithdrawalJson) ![0]Withdrawal {
    _ = withdrawals;
    return .{};
}
```

**Impact:** The node will fail to produce valid blocks (getPayload returns incomplete data) and will fail to process blocks with withdrawals correctly (newPayload sends correct data but getPayload response is broken).

#### 🟡 MEDIUM: `extra_data` and `transactions` lifetime issues

In the response decoders, `extra_data` and `transactions` reference the JSON arena:
```zig
.extra_data = ep.extraData,        // points into arena
.transactions = ep.transactions,    // points into arena
```

But `ParsedResponse.deinit()` frees the arena. Any code that captures the decoded response and then frees the parsed response will have dangling pointers.

The V1/V2 decoders note "arena-backed, caller must copy if needed" for withdrawals but don't apply the same discipline to `extra_data` and `transactions`. In `getPayloadForFork()`, the `HttpEngine` returns the response directly — the caller would need to know they must deep-copy before the arena dies. **This is a use-after-free waiting to happen.**

#### 🟢 MINOR: `forkchoiceUpdatedForFork` takes `attrs_json: ?[]const u8` (pre-encoded)

This is an asymmetry — `newPayloadForFork` and `getPayloadForFork` take typed parameters, but `forkchoiceUpdatedForFork` takes a pre-encoded JSON string. This means the caller must handle JSON encoding, which breaks the abstraction.

### 1.2 Completeness

#### Missing: `engine_getPayloadBodiesByHashV1` / `engine_getPayloadBodiesByRangeV1`

These methods are needed for historical backfill (EIP-4444). TS Lodestar implements them. Not blocking for initial sync but needed for a full node.

#### Missing: `engine_newPayloadV5` / `forkchoiceUpdatedV4` (Fulu/PeerDAS)

The types use V4 for Electra and route Fulu to the same V4 methods. This is correct for now (Fulu reuses Electra Engine API methods), but the Fork enum includes `fulu` — document that it maps to V4.

#### Good: `exchangeCapabilities`, `exchangeTransitionConfiguration`, `getClientVersion`, `checkHealth`

These are implemented and tested. Nice work.

#### Good: `IoHttpTransport` for production use

Clean separation of transport from encoding. The production HTTP transport using `std.http.Client` is properly abstracted.

### 1.3 Coherence

#### vtable pattern: ✅ Good

The `EngineApi` vtable with `*anyopaque` + `*const VTable` is idiomatic Zig. The `@ptrCast` in vtable construction is the standard pattern. Both `HttpEngine` and `MockEngine` implement the full vtable.

#### Naming inconsistency: `newPayload` vs `newPayloadV3`

The "default" methods (`newPayload`, `forkchoiceUpdated`, `getPayload`) map to V3 (Deneb). This is fine for a Deneb+ node but confusing — they should be either always versioned or clearly documented as "current fork" aliases.

#### `Fork` enum in `HttpEngine` vs fork types elsewhere

`HttpEngine.Fork` is its own enum independent of any global fork type. This will cause translation issues when the beacon chain's fork enum is used to dispatch.

### 1.4 Taste

#### 🟡 Hand-rolled JSON encoding is fragile

The entire `encodeExecutionPayloadV3()` function is ~40 lines of manual `allocPrint` with hex encoding. This is extremely fragile:
- Each new field requires updating 4 separate encode functions (V1, V2, V3, V4)
- The multiline format strings use `\\` line continuations which are hard to diff
- No round-trip test verifies that encode → decode produces the original values

A better approach would be to define a JSON intermediate struct and use `std.json.stringify()`, then have a single encode function that takes the intermediate. TS Lodestar uses a similar approach with `jsonSerialize` on each type.

#### 🟢 Good: MockTransport records requests for assertion

The test infrastructure with `MockTransport` recording `last_body`, `last_url`, and `last_had_auth` is well-designed for asserting encoding correctness.

#### 🟢 Good: JWT implementation is correct and tested

HMAC-SHA256, base64url, proper header. Determinism test ensures no randomness leaks.

#### 🟢 Good: Retry with exponential backoff

`sendRequest` handles retry with configurable backoff. Fresh JWT is generated per retry attempt (required since `iat` must be recent).

#### 🟢 Good: `EngineState` machine for connection tracking

Online/offline/syncing/auth_failed with logged transitions. Clean.

#### Builder API (`builder.zig`)

Well-structured REST client mirroring the Engine API pattern. The vtable approach is consistent. `StubBuilder` for when no relay is configured is a nice touch. One concern: `parseExecutionPayload()` for `submitBlindedBlock` response drops transactions (`transactions = &.{}`), which is the **entire point** of unblinding.

---

## 2. Database (`src/db/`)

### 2.1 Correctness

#### ✅ Named databases work correctly

The design replaces TS Lodestar's key-prefix scheme with LMDB named databases (DBIs). This is a genuine improvement:
- No prefix collision risk
- Native LMDB optimization per-DBI (separate B-trees)
- Cleaner keys (just the actual key bytes)

The `DatabaseId` enum has 27 named databases, all with unique names (compile-time verified). LMDB supports up to 128. All DBIs are opened in a single write transaction at init — correct per LMDB requirements.

#### ✅ Transaction discipline is correct

- Read operations use `MDB_RDONLY` transactions
- Write operations use read-write transactions with `errdefer txn.abort()`
- `writeBatch` wraps all ops in a single transaction — atomic cross-database writes

#### 🟡 MEDIUM: `getLatestStateArchiveSlot()` is O(n) — iterates all keys

```zig
pub fn getLatestStateArchiveSlot(self: *BeaconDB) !?u64 {
    const keys = try self.state_archive_db.allKeys();
    // ... iterate to find max
}
```

This loads ALL keys from the state archive into memory, then finds the max. On mainnet with 100k+ finalized epochs, this allocates and iterates 100k+ byte slices. LMDB cursors support `MDB_LAST` which gives O(1) access to the last key (since LMDB stores keys sorted). The KVStore interface should expose a `lastKey()` method.

#### 🟡 MEDIUM: `allKeys()` / `allEntries()` don't scale

These methods load the entire database into memory. For production use on mainnet:
- `block_archive` has millions of entries
- `state_archive` has hundreds of thousands of entries

Need cursor-based iteration or at minimum a `count()` method.

#### 🟡 MEDIUM: `std.mem.asBytes(&slot)` endianness

```zig
try self.validator_index_db.put(&pubkey, std.mem.asBytes(&index));
```

`std.mem.asBytes` gives the native byte representation. On x86_64 this is little-endian, which matches `slotKey()` (also little-endian). But this is an implicit contract — if the code ever runs on big-endian, the DB format changes silently. Consider using explicit `std.mem.toBytes()` (which is always native) or `writeInt(.little)` for consistency.

Actually, `slotKey()` uses `std.mem.toBytes()` which IS `@bitCast`, which IS native endian. So the slot keys are LE on x86 but would be BE on a BE platform. This means the DB is **not portable across architectures**. For a beacon node this probably doesn't matter (you'd resync anyway), but it's worth documenting.

### 2.2 Completeness

#### Good: Full schema coverage

The `DatabaseId` enum covers:
- Core: blocks (hot + archive), states (archive), indices
- Blobs: hot + archive (Deneb)
- Data columns: hot + archive + per-column (Fulu/PeerDAS)
- Light client: sync witnesses, committees, updates
- Op pool: exits, proposer slashings, attester slashings, BLS changes
- ePBS: payloads (Gloas, forward-looking)
- Internal: fork choice, validator index, chain info, backfill ranges

This is comprehensive and mirrors TS Lodestar's bucket scheme.

#### Missing: `checkpoint_state` database not used in `BeaconDB`

`DatabaseId.checkpoint_state` exists but `BeaconDB` doesn't have methods for it. Checkpoint states are used by fork choice for justification/finalization.

#### Missing: `backfill_ranges` not used

`DatabaseId.backfill_ranges` exists but no methods in `BeaconDB`.

#### Missing: Light client databases not used

`lc_sync_witness`, `lc_sync_committee`, `lc_checkpoint_header`, `lc_best_update` are defined but unused. OK for now but track it.

#### Missing: `bls_change` database not used

`DatabaseId.bls_change` has no methods.

#### Missing: `idx_block_parent_root` not used

Defined in `DatabaseId` but no methods in `BeaconDB`. TS Lodestar uses this for parent lookups.

### 2.3 Coherence

#### ✅ Clean layering: lmdb.zig → kv_store.zig → lmdb_kv_store.zig → beacon_db.zig

Each layer adds exactly one thing:
- `lmdb.zig`: Raw C API wrapper
- `kv_store.zig`: Abstract vtable interface
- `lmdb_kv_store.zig`: LMDB implementation of vtable
- `beacon_db.zig`: Typed beacon chain accessors

#### ✅ Memory model is clear

All `get` methods return **owned** slices. Caller must free. Consistent across both implementations. The `EntryList` has a proper `deinit()` method.

#### `Database` convenience type is nice

Getting a scoped handle via `kv.getDatabase(.block)` eliminates repeating the `DatabaseId` on every call.

### 2.4 Taste

#### 🟢 Good: LMDB error mapping is complete

Every `MDB_*` error code maps to a Zig error. No silent failures.

#### 🟢 Good: MDB_NOTLS flag

Using `MDB_NOTLS` avoids thread-local storage issues with Zig's async/fiber model. Correct choice.

#### 🟢 Good: Test coverage

- MemoryKVStore: 12 tests covering CRUD, batch, isolation, binary keys, close behavior
- LmdbKVStore: 10 tests including persistence across reopen, large values, many keys
- BeaconDB: 16 tests covering all typed accessors
- Named database isolation explicitly tested

#### 🟡 Map size default is generous but undocumented

`256 * 1024 * 1024 * 1024` (256 GB) is the default LMDB map size. This is correct (LMDB uses sparse files so it costs nothing until written), but should be documented in case someone runs on a filesystem without sparse file support.

---

## 3. Sync (`src/sync/`)

### 3.1 Correctness

#### 🔴 CRITICAL: `processChainSegmentImpl` is a no-op

In `sync_service.zig`:
```zig
fn processChainSegmentImpl(ptr: *anyopaque, blocks: []const BatchBlock, _: RangeSyncType) anyerror!void {
    _ = ptr;
    _ = blocks;
    // Block import is handled by the chain segment processor...
}
```

This means the range sync pipeline downloads blocks but **never imports them**. The comment says "handled by the chain segment processor at the SyncChain level" but `SyncChain.processNextBatch()` calls `self.callbacks.processChainSegment(front.blocks, self.sync_type)` which chains back to this no-op.

**Impact:** Range sync will appear to work (batches will cycle through downloading → processing → validation) but no blocks will actually be imported. The chain will never advance.

#### 🟡 MEDIUM: `SyncChain` uses a global mutable static for chain IDs

```zig
var next_chain_id: u32 = 0;
```

This is a `var` at file scope — it's effectively a global mutable static. In multi-threaded contexts this is a data race. Zig doesn't protect file-scope `var` from concurrent access. For a beacon node that runs sync on one thread this is fine, but it's a footgun.

#### 🟡 MEDIUM: `SyncChain.peers` uses `StringArrayHashMap` with non-owned keys

```zig
peers: std.StringArrayHashMap(ChainTarget),
```

The keys in this map are `[]const u8` peer IDs. These are **not** owned — they're whatever slice was passed to `addPeer()`. If the caller's buffer is freed, the map has dangling pointers. Compare with `PeerSyncInfo` which correctly owns its peer_id with `allocator.dupe()`.

`BackwardsChain.PeerSet` solves this correctly by copying into a fixed buffer.

#### 🟡 MEDIUM: `SyncChain.batches` uses `orderedRemove` in a hot path

`drainValidated()` calls `self.batches.orderedRemove(0)` in a loop. For an `ArrayListUnmanaged`, `orderedRemove(0)` is O(n) because it shifts all remaining elements. With `MAX_PENDING_BATCHES = 8` this is fine, but if the window grows, consider a ring buffer or `std.fifo.LinearFifo`.

#### 🟢 Batch generation counter correctly rejects stale responses

The `Batch.generation` counter increments on each download attempt. `onDownloadSuccess` and `onDownloadError` verify the generation matches before applying. This correctly handles the case where a slow peer responds after a batch has been re-assigned to a new peer.

#### 🟢 CheckpointSync correctly validates state root

SHA-256 hash of state bytes is compared against the trusted root before persisting. The comment correctly notes that production would use SSZ hash-tree-root.

### 3.2 Completeness

#### Missing: Backfill sync

TS Lodestar has backfill sync (downloading historical blocks after checkpoint sync). No equivalent here. The `backfill_ranges` database is defined but unused.

#### Missing: Optimistic sync integration

`SyncStatus.is_optimistic` is always `false`. There's no integration with the execution engine's SYNCING status to track optimistic blocks.

#### Missing: Block processing pipeline

Blocks arrive as `[]const u8` (raw bytes) but there's no deserialization, no fork choice integration, no state transition. This is expected for the current stage but the interface boundary should be documented — what format are `block_bytes`? SSZ? What fork version?

#### Present and well-designed: Unknown chain sync (backwards headers)

The `unknown_chain/` module is a clean port of TS Lodestar's PR #8221. The `BackwardsChain` state machine (unknown_head → unknown_ancestor → linked) is correct. The coordinator properly handles multiple chains, eviction, finalization pruning, and block-import-triggered linking.

This is the most architecturally mature part of the sync subsystem.

#### Present: UnknownBlockSync (active parent fetch)

The orphan block resolution with parent chain walking, recursive child import, bad root tracking, and capacity eviction is solid. The `tick()` driven active fetch loop is cleaner than the TS event-driven approach.

### 3.3 Coherence

#### ✅ Clean two-layer architecture

```
BeaconNode → SyncService → RangeSync (finalized + head chains)
                         → UnknownBlockSync (active parent fetch)
                         → CheckpointSync (bootstrap)
```

No `SyncController` intermediary (TS Lodestar has one). This is simpler and correct for the scope.

#### ✅ Consistent callback vtable pattern

`SyncServiceCallbacks`, `RangeSyncCallbacks`, `SyncChainCallbacks`, `UnknownBlockCallbacks`, `UnknownChainSync.Callbacks` — all follow the same `ptr: *anyopaque + fn pointer` pattern. Testable with stub implementations.

#### 🟡 Two separate unknown-block mechanisms

There are TWO orphan block sync systems:
1. `unknown_block.zig` — `UnknownBlockSync` — stores full block bytes, fetches parents by root, imports recursively
2. `unknown_chain/` — `UnknownChainSync` — stores minimal headers, builds backwards chains, links to fork choice

These overlap significantly. TS Lodestar originally had (1) and is migrating to (2) via PR #8221. The codebase has both without clear documentation of which to use when.

**Recommendation:** `UnknownBlockSync` handles orphan gossip blocks (has full block bytes, needs parent). `UnknownChainSync` handles unknown roots from attestations/status (no block bytes, just roots). Document this split.

### 3.4 Taste

#### 🟢 Good: Sync types are well-defined

`sync_types.zig` has clear constants, a clean state machine (`SyncState`), and owned `PeerSyncInfo`. The constants match TS Lodestar's values.

#### 🟢 Good: Batch state machine is clean

The `Batch` lifecycle is well-defined:
```
AwaitingDownload → Downloading → AwaitingProcessing → Processing → AwaitingValidation
```
With retry counters and generation-based stale response rejection.

#### 🟢 Good: Test coverage for state machines

- `SyncChain`: batch pipeline, peer management, completion
- `RangeSync`: finalized/head chain creation, priority
- `SyncService`: mode transitions, gossip gating, status reporting
- `UnknownBlockSync`: add/retrieve, bad roots, eviction
- `BackwardsChain`: advance, link, relevance
- `UnknownChainSync`: root tracking, linking, finalization pruning

#### 🟡 `BatchBlock.block_bytes` is `[]const u8` — no ownership semantics

When blocks arrive from the network and are stored in `Batch.blocks`, who owns the memory? The batch doesn't allocate or free — it just stores the slice. If the network layer frees the response buffer, the batch has dangling pointers.

---

## Cross-Cutting Concerns

### Memory Management

1. **Execution:** Arena-backed JSON parsing has lifetime hazards (extra_data, transactions reference freed arena)
2. **DB:** Clean ownership model (all gets return owned slices)
3. **Sync:** Block bytes ownership is unclear throughout the pipeline

### Error Handling

1. **Execution:** JSON-RPC errors are well-mapped to specific Zig errors. `anyerror!` in vtable signatures is correct (allows implementation-specific errors).
2. **DB:** LMDB errors are comprehensively mapped. `StoreClosed` sentinel is clean.
3. **Sync:** Error handling is mostly via retry with counters. Missing: error propagation from batch processing to chain health.

### Testing Philosophy

All three subsystems have strong unit tests. The mock/stub pattern (MockTransport, MemoryKVStore, TestCallbacks) enables testing without external dependencies. What's missing:

1. **No integration tests** across subsystems (e.g., sync → import → db persistence)
2. **No round-trip tests** for Engine API (encode → decode should be identity)
3. **No concurrency tests** (important for LMDB reads + writes)
4. **No fuzzing** for JSON parsing or hex encoding

---

## Priority Action Items

| # | Severity | Area | Issue |
|---|----------|------|-------|
| 1 | 🔴 | Execution | Fix QUANTITY vs DATA encoding for all Engine API fields |
| 2 | 🔴 | Execution | Implement withdrawal, blob, and request array decoding |
| 3 | 🔴 | Sync | Implement `processChainSegmentImpl` (blocks must actually import) |
| 4 | 🔴 | Execution | Fix `extra_data`/`transactions` lifetime (deep copy from arena) |
| 5 | 🟡 | Execution | Fix `base_fee_per_gas` to use QUANTITY encoding |
| 6 | 🟡 | Execution | Builder: `submitBlindedBlock` must decode transactions |
| 7 | 🟡 | Sync | Own peer_id strings in `SyncChain.peers` |
| 8 | 🟡 | Sync | Document `UnknownBlockSync` vs `UnknownChainSync` split |
| 9 | 🟡 | DB | Add `lastKey()` to KVStore for O(1) latest slot lookup |
| 10 | 🟢 | All | Add encode↔decode round-trip tests for Engine API |
