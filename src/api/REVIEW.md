# API + Node + Processor Subsystem Review

**Reviewer:** lodekeeper-z  
**Date:** 2026-03-28  
**Branch:** `feat/beacon-node`  
**Scope:** `src/api/`, `src/node/`, `src/processor/`

---

## Executive Summary

The three subsystems collectively form a working beacon node skeleton with a real HTTP API, a priority-based work scheduler, and a monolithic-but-functional node orchestrator. The code is surprisingly complete for the state of the project — 55 routes are defined, the processor has clean FIFO/LIFO queues with batching, and `beacon_node.zig` successfully wires dozens of components together.

That said, there are correctness bugs, significant design debts, and some choices that will create pain at scale. Below is the full breakdown.

---

## 1. API Subsystem (`src/api/`)

### 1.1 Correctness

#### 🔴 CRITICAL: `dispatchHandler` is a ~400-line string-matching if-chain

The dispatch in `http_server.zig` compares `operation_id` strings using sequential `std.mem.eql`. This is **O(n)** per request (55 routes × string compare). More critically, if an operation_id is misspelled in the route table vs. the dispatch function, it silently falls through to `error.NotImplemented` — no compile-time safety.

**Fix:** Use a comptime `std.StaticStringMap` keyed by operation_id that maps to handler function pointers. Or better: make routes carry typed handler function pointers directly (the TS Lodestar approach — each route definition includes its handler).

#### 🔴 CRITICAL: Route count test is self-contradictory

`routes.zig` line 574:
```zig
test "route count" {
    try std.testing.expectEqual(@as(usize, 54), routes.len);
    try std.testing.expectEqual(@as(usize, 41), routes.len);
}
```
Both assertions will fail (actual count is 55), and they contradict each other. This test has never passed.

#### 🟡 SSZ responses are never actually returned

Content negotiation parses `Accept: application/octet-stream` correctly, and `supports_ssz` flags are set on routes, but the dispatch handler **always returns JSON**. There's no code path that calls `encodeSSZ` or returns raw SSZ bytes based on the negotiated format. The `format` variable from content negotiation is computed but never used in dispatch.

#### 🟡 `getBlockV2` and `getBlindedBlock` inline hex encoding manually

Both duplicate a manual hex-encoding loop (`hi_nibble`/`lo_nibble`) instead of using `std.fmt.bytesToHex`. This is both wrong (doesn't use the same code path as the rest of the API) and error-prone.

#### 🟡 `getBlockV2` sets `ssz_bytes = block_result.data`

The `handler_res` is constructed with `ssz_bytes = block_result.data`, but `data` is also `block_result.data` (the raw SSZ). This stores the same pointer twice. If SSZ response was actually implemented, it would serialize the JSON envelope with the raw bytes as the "data" field *and* also think it has SSZ bytes — conflating two concerns.

#### 🟡 POST body reading uses `request.readerExpectNone()`

The function name suggests it expects *no body*, but then tries to read up to 1MB. This seems like it should be `request.reader()` — need to verify the `std.http.Server` API. If `readerExpectNone` actually returns an empty reader, all POST endpoints receive empty bodies.

#### 🟡 `getValidators` frees result before `makeJsonResult` serializes it

```zig
const handler_res = try handlers.beacon.getValidators(ctx, state_id, .{});
defer alloc.free(handler_res.data);
return self.makeJsonResult([]const types.ValidatorData, handler_res);
```

`makeJsonResult` serializes `handler_res.data` — but if it triggers an error path, `defer` runs and frees the data. More importantly, the JSON encoder holds a pointer to `handler_res.data` during serialization. If `encodeHandlerResultJson` were to yield or realloc, this could UAF. Currently safe because encoding is synchronous, but fragile.

#### 🟡 `getEvents` SSE endpoint always returns `NotImplemented`

The SSE handler reads from EventBus but unconditionally returns `error.NotImplemented`. The dispatch path catches this error and returns a 501, but the dispatch code also handles `getEvents` by catching the error and returning a 200 with `{}` — so the actual response is 200 OK with an empty JSON object, which is wrong per the SSE spec. SSE should hold the connection open with `Content-Type: text/event-stream`.

#### 🟡 Rewards endpoints return hardcoded zeros/empty arrays

`getBlockRewards`, `getAttestationRewards`, `getSyncCommitteeRewards` all return zero/empty stub data. This is fine as scaffolding but validators relying on these will get incorrect data.

#### 🟡 `handleRequest` (test path) doesn't free response body on error paths

Several error returns from `handleRequest` return stack-allocated string literals as `.body`, but the test code does `defer if (resp.status == 200) std.testing.allocator.free(resp.body)`. Non-200 responses with heap-allocated bodies would leak.

### 1.2 Completeness

#### Missing endpoints (compared to Beacon API spec)

- `GET /eth/v1/beacon/states/{state_id}/validator_balances` — not defined
- `POST /eth/v1/beacon/states/{state_id}/validators` — POST variant for filtered queries
- `GET /eth/v2/beacon/blocks/{block_id}/attestations` — block attestations
- `GET /eth/v1/beacon/deposit_snapshot` — deposit tree snapshot
- `GET /eth/v1/beacon/light_client/*` — all light client endpoints
- `POST /eth/v1/beacon/blocks` (v1) — only v2 is defined
- `POST /eth/v2/beacon/blinded_blocks` — blinded block submission
- `GET /eth/v3/validator/blocks/{slot}` — v3 block production (replaces v1)
- `GET /eth/v1/config/deposit_contract` — deposit contract info
- Keymanager routes are not in the route table (only in `handlers/keymanager.zig`)

#### Missing API behaviors

- No request body content-type checking (POST endpoints accept anything)
- No rate limiting
- No authentication (except keymanager which has its own bearer check)
- No request ID / correlation headers
- No gzip response compression
- No streaming for large responses (validator list can be 100MB+)
- `Eth-Consensus-Version` header from `meta_flags` is declared but not enforced — handlers can return metadata that contradicts the route's flags

### 1.3 Coherence

#### The HandlerResult pattern works but dispatch doesn't use it uniformly

Some handlers (node, beacon simple queries) go through `makeJsonResult` cleanly. Others (getProposerDuties, getBlockHeaders, getDebugHeads, getForkChoice) build JSON manually with `std.ArrayListUnmanaged(u8)` and `allocPrint`. This means:
- The JSON envelope format (data + metadata) is duplicated in 10+ places
- Some responses include metadata inside the envelope, others emit it only as headers
- Error handling is inconsistent between the two paths

This is the biggest taste issue. The pattern *should* be: every handler returns `HandlerResult(T)`, and `encodeHandlerResultJson` handles all serialization. The 300+ lines of manual JSON construction in `dispatchHandler` should not exist.

#### `context.zig` callback proliferation

The `ApiContext` has **14 optional callback fields** (block_import, head_state, peer_db, op_pool, pool_submit, produce_block, attestation_data, aggregate_attestation, sync_committee_contribution, state_regen_callback, keymanager, validator_monitor, event_bus + allocator). Each callback is a separate `struct { ptr: *anyopaque, fn: *const fn }`.

This is workable for now but will become a maintenance burden:
- Adding a new feature requires: (1) new callback type in context.zig, (2) new field in ApiContext, (3) new wiring in beacon_node.zig init, (4) new cleanup in beacon_node.zig deinit
- No way to tell at compile time if a required callback is missing

**Suggestion:** Consider a `ChainInterface` vtable with all chain operations, wired once. Or at minimum, group related callbacks (pool_submit's 8 sub-function pointers are a good example of over-granularity).

#### `response.zig` has two encoding paths

`encodeJsonResponse` (legacy) and `encodeHandlerResultJson` (new). Both do the same thing with slightly different signatures. The legacy path should be removed.

### 1.4 Taste

#### Good

- Content negotiation is clean and well-tested
- `response_meta.zig` is a nice self-contained module
- Error response format correctly follows the Beacon API spec
- Test coverage for routes, types, and handlers is solid
- `EventBus` ring buffer is simple and correct

#### Bad

- `http_server.zig` is 700+ lines with a single `dispatchHandler` method that's 400+ lines of unmaintainable string matching
- Manual hex encoding (`hi_nibble`/`lo_nibble`) appears 3 times
- `routes.zig` defines `MetaFlags` per route but dispatch ignores them entirely
- `test_helpers.zig` uses `var` for mutable test fixtures that should be `const` where possible
- No `handleRequest` equivalent for SSZ responses
- The `handleConnection` → `handleHttpRequest` → `dispatchHandler` call chain is single-threaded and blocking — one slow handler stalls all connections
- Pool GET endpoints return counts (not actual objects) which doesn't match the Beacon API spec

---

## 2. Node Subsystem (`src/node/`)

### 2.1 Correctness

#### 🟡 `beacon_node.zig` is ~2800 lines — the god object problem

This single file contains:
- `BlockImporter` (300+ lines) with full STFN pipeline
- `SyncCallbackCtx` (100+ lines) bridging sync→P2P
- `BeaconNode` struct (100+ fields) with init/deinit, importBlock, block production, gossip handling, P2P wiring, sync pipeline, EL communication, builder API, KZG
- All gossip callback functions (300+ lines)
- All req/resp callback functions (200+ lines)
- All BLS verification callbacks (200+ lines)
- API callback glue (100+ lines)
- 20+ tests

This is not a correctness bug per se, but it makes reasoning about correctness extremely difficult. A subtle ordering issue (e.g., `fork_choice` being null during a code path that assumes it's non-null) would be nearly impossible to catch by reading this file.

#### 🟡 `gossip_node` module-level mutable pointer

```zig
var gossip_node: ?*BeaconNode = null;
```

Used by gossip callbacks that don't take a context pointer. This is explicitly a "we know there's only one BeaconNode per process" hack. Safe in practice but violates the vtable pattern used everywhere else.

#### 🟡 `startP2p` never returns — the main loop is embedded in it

`startP2p` calls `dialBootnodeEnr` which enters an infinite `while(true)` loop at the bottom. This means `startP2p` is essentially the main event loop, not just "start the P2P service". The function name is misleading, and the `while(true)` loop with 6-second sleeps is the entire node lifecycle.

#### 🟡 API head tracker is a separate copy, not a reference

`api_head_tracker` and `api_sync_status` are heap-allocated separate structs that get manually updated after each `importBlock`. If any import path forgets to update them, the API returns stale data. In TS Lodestar, the API reads directly from the chain object — no synchronization needed.

#### 🟡 `resolveBlockSlotAndRoot` for `BlockId.root` uses head slot for fork inference

When looking up a block by root, the code does:
```zig
const fork_seq = ctx.beacon_config.forkSeq(ctx.head_tracker.head_slot);
```
This is wrong for archived blocks from older forks. A block at slot 100 (phase0) would be deserialized with the electra fork if head is in electra range. This will fail or produce garbage.

#### 🟢 `initFromGenesis` and `initFromCheckpoint` are well-structured

Both correctly compute genesis/anchor block roots, register them in `block_to_state`, initialize fork choice, and wire API context. The checkpoint init properly handles non-zero anchor slots.

### 2.2 Completeness

#### Missing node lifecycle steps

- No graceful API server shutdown (serves forever)
- No P2P service shutdown/cleanup on signal
- No periodic state archiving (only at epoch boundaries during import)
- No EL payload preparation ahead of proposal slot
- No attestation production loop
- No aggregate production loop
- No sync committee message production
- No slashing protection DB
- No finalized state pruning
- No deposit processing
- No eth1 data voting

These are expected gaps for the current speedrun phase, but worth tracking.

#### `clock.zig` has no slot subscription mechanism

TS Lodestar's clock emits events at slot boundaries. Here, `SlotClock` is a pure query object — the slot clock loop in `main.zig` manually sleeps. This works but means no reactive architecture.

### 2.3 Coherence

#### `options.zig` has VC-mode fields that don't belong

`NodeOptions` contains validator client fields (`validator_keys_dir`, `beacon_node_url`, `doppelganger_detection`, `web3signer_url`). These should be in a separate `ValidatorOptions` struct. The beacon node should not know about validator key management.

#### `main.zig` is well-organized

The CLI spec, config loading, state initialization priority chain, and concurrent service startup are all clearly structured. The RC config resolver is a nice touch. The signal handler is correctly async-signal-safe.

### 2.4 Taste

#### Good

- `data_dir.zig` path resolution is clean
- `jwt.zig` load-or-generate pattern is correct
- `identity.zig` secp256k1 key persistence is right
- `shutdown.zig` is minimal and correct
- Test coverage in `beacon_node.zig` is excellent (FCU, req/resp, blob import, state archival)

#### Bad

- `beacon_node.zig` should be split into at least: `block_import.zig`, `gossip_callbacks.zig` (exists but not used for all callbacks), `reqresp_callbacks.zig`, `api_glue.zig`, `sync_bridge.zig`
- The `startP2p` function does 10 different things and is 200+ lines
- The inline `while(true)` loop should be in `runNodeLoop` or similar
- `convertEnginePayload` is a 60-line function that should live in `execution_mod`
- Several `// TODO: timing for 0.16` comments — these should be tracked

---

## 3. Processor Subsystem (`src/processor/`)

### 3.1 Correctness

#### 🟢 The processor is clean and correct

This is the best-designed subsystem of the three. The priority queue system, FIFO/LIFO queues, batching, sync-aware dropping, and tick-based cooperative scheduling are all correct and well-tested.

#### 🟢 Batch formation is correct

`formAttestationBatch` and `formAggregateBatch` correctly handle the single-item (no batch) vs. multi-item (batch) case. The batch uses pre-allocated scratch buffers owned by `WorkQueues`, avoiding per-tick allocation.

#### 🟡 `WorkQueues.totalQueued()` doesn't include batch buffers

If items are popped into `attestation_batch_buf` but the handler hasn't processed them yet (which can't happen in the current inline model), `totalQueued()` would undercount. Not a bug today but would be if a worker pool is added.

### 3.2 Completeness

#### Missing processor features

- No worker pool (documented as Phase 2)
- No per-queue metrics export
- No queue depth alerting/backpressure signaling
- No timing data (all `elapsed_ns` are 0 — requires `std.Io` clock)
- `slot_tick` and `reprocess` items have no queues and are silently dropped

### 3.3 Coherence

#### 🟢 Clean separation of concerns

- `work_item.zig`: type definitions only, no logic
- `queues.zig`: generic queue implementations, no beacon-chain knowledge
- `work_queues.zig`: routing table, queue config, priority order
- `processor.zig`: scheduling loop, metrics

This is exactly how it should be decomposed.

#### 🟡 Priority numbers are encoded as enum ordinals

```zig
pub const WorkType = enum(u8) {
    chain_segment = 0,
    rpc_block = 1,
    ...
```

This means adding a new work type in the middle requires renumbering everything. TS Lodestar uses separate priority numbers. Consider:
```zig
pub fn priority(self: WorkType) u8 { return switch(self) { ... }; }
```

### 3.4 Taste

#### Good

- Ring buffer queues are textbook clean
- `popBatch` on LIFO queues is elegant
- `QueueConfig.fromValidatorCount` scaling is well-considered
- Tests cover priority ordering, batching, sync dropping, queue depths

#### Minor nits

- `QueueConfig.totalCapacity()` uses `inline for` over struct fields — fragile if non-u32 fields are added
- The `unreachable` in `routeToQueue` for batch items is correct but could use a comment explaining why

---

## 4. Cross-Cutting Concerns

### Allocation discipline

The API subsystem has inconsistent allocation ownership:
- Some handlers allocate and expect the caller to free
- Some handlers allocate and free themselves
- `dispatchHandler` does `defer self.allocator.free(result.body)` which is correct for the HTTP path but means `handleRequest` (test path) gets a freed body on the stack

The processor subsystem has excellent allocation discipline — pre-allocated buffers, no per-item allocation.

### Error propagation

API errors are well-typed (`ApiError` → JSON). But the mapping in `fromZigError` catches `anyerror`, which means new error types silently become 500s. Consider explicit error sets for handler return types.

### Compared to TS Lodestar

| Aspect | TS Lodestar | lodestar-z | Gap |
|--------|-------------|------------|-----|
| Route dispatch | Typed function refs per route | String matching | Major |
| Response encoding | Generic per-type serializers | Mix of generic + manual | Moderate |
| SSE events | Real streaming | Stub | Blocking for validators |
| API context | Direct chain reference | 14 optional callbacks | Different approach, works |
| Processor | Worker pool + batch BLS | Inline + batch stubs | Expected |
| Node lifecycle | Service manager | Monolithic struct | Should improve |

---

## 5. Top Recommendations (Priority Order)

1. **Fix the route count test** — it's broken and contradictory
2. **Wire SSZ response path** — content negotiation is done, just needs dispatch integration
3. **Replace string dispatch with typed handler pointers** — this is the single biggest quality improvement available
4. **Split beacon_node.zig** — extract BlockImporter, gossip callbacks, reqresp callbacks, API glue into separate files
5. **Remove manual JSON construction from dispatchHandler** — all handlers should go through `encodeHandlerResultJson`
6. **Fix fork inference in `resolveBlockSlotAndRoot`** — use the block's actual slot, not head slot
7. **Add `POST /eth/v1/beacon/pool/attestations` GET variant** that returns actual attestations (not just counts)
8. **Verify `request.readerExpectNone` actually reads POST bodies**

---

*This review covers correctness, completeness, coherence, and taste across ~15,000 lines of code in the three subsystems. The codebase is in surprisingly good shape for its development stage — the bones are right, the test coverage is real, and the design decisions are defensible. The main risk is the monolithic `beacon_node.zig` becoming unmaintainable as more features land.*
