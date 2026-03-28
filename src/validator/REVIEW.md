# Validator Client Code Review

**Date:** 2026-03-28  
**Scope:** `src/validator/` — 23 files, ~8000 LOC  
**Branch:** `feat/beacon-node`  
**Reviewer:** lodekeeper-z (automated review)

---

## 1. Executive Summary

| Dimension | Score (1-10) | Notes |
|---|---|---|
| **Correctness** | 5/10 | Signing roots correctly computed via real `state_transition` module. Major bugs in aggregate JSON construction, block signing body_root, timing logic, and pointer aliasing. |
| **Completeness** | 7/10 | All major TS Lodestar services implemented. Missing: emitter, validator registration (builder API), builder/blinded block flow, validator effectiveness metrics push. |
| **Coherence** | 6/10 | Generally consistent types and patterns. Duplicate domain constants. Dangling pointer hazard in init. Clock has no shutdown mechanism. |
| **Taste** | 6/10 | Generally clean Zig. Some files excellent (keystore, slashing_protection_db). Others have hand-rolled JSON, dead code paths, and missing errdefer. |

**Overall:** Impressive scaffolding — the architecture is sound, all major flows exist, signing root computation delegates to the real `state_transition` module (not hand-rolled), and slashing protection is properly implemented with thorough tests. But there are **several critical correctness bugs** that would cause incorrect behavior at runtime, primarily in aggregate construction, block signing, sub-slot timing, and pointer stability. The code needs a focused correctness pass before it can be tested against a real beacon node.

---

## 2. Critical Bugs

### BUG-1: Dangling pointers from `init()` — services store pointers to stack locals (validator.zig:163-191) ⚠️ **SEVERITY: CRITICAL**

```zig
// validator.zig init():
var api = ...;                    // local variable on stack frame of init()
var validator_store = ...;        // local variable on stack frame of init()
const block_service = BlockService.init(allocator, &api, &validator_store, signing_ctx);
//                                                  ^^^ pointer to local!
```

`BlockService`, `AttestationService`, `SyncCommitteeService`, `PrepareBeaconProposerService`, `ChainHeaderTracker`, `SyncingTracker`, and `IndexTracker` all store `*BeaconApiClient` and/or `*ValidatorStore` by pointer. These pointers point to `api` and `validator_store` **locals inside `init()`**. When `init()` returns a `ValidatorClient` struct by value, those locals are gone — the services now hold dangling pointers.

The comment on line 160 says "Pointers are stable because ValidatorClient is heap-allocated by the caller" — but this is only true if the caller does `var vc = try allocator.create(ValidatorClient); vc.* = try ValidatorClient.init(...)`, which moves `api` and `validator_store` into their final resting place. But the pointers were captured BEFORE the move. After the move, the `api` and `validator_store` are in the `ValidatorClient` struct at a new address, but the services still point to the old stack address.

**Fix:** Either:
1. Two-phase init: `init()` creates the ValidatorClient, then a separate `wire()` method takes `*ValidatorClient` and initializes services with stable pointers.
2. Store services as pointers that are heap-allocated and initialized after the parent.
3. Have services take the pointers in `start()` (where `self` is stable), not `init()`.

### BUG-2: Aggregate JSON uses zeroed aggregate data (attestation_service.zig:380-413)

```zig
const aggregate_and_proof = consensus_types.phase0.AggregateAndProof.Type{
    .aggregator_index = dp.duty.validator_index,
    // For now we use a zeroed aggregate since we don't decode the SSZ response.
    .aggregate = std.mem.zeroes(consensus_types.phase0.Attestation.Type),
    .selection_proof = sel_proof,
};
```

The `AggregateAndProof.aggregate` is zeroed. The signing root is computed over this zeroed struct, not the actual aggregate attestation fetched from the BN. Then the published JSON also has zeroed attestation data. **The BN will reject this**, and even if it didn't, the signature would be over the wrong data.

The `agg.attestation_ssz` is fetched from the BN but never decoded and used. The aggregate response needs to be SSZ/JSON decoded and placed into `aggregate_and_proof.aggregate`.

### BUG-3: Block body_root not computed — signing a header with zero body_root (block_service.zig:242-258)

```zig
// body_root — if absent, we'd need to compute it via SSZ hash of body.
// The BN often doesn't include body_root in the block response; it must be computed.
if (msg_obj.get("body_root")) |br_val| { ... }
```

The BN's `GET /eth/v3/validator/blocks/{slot}` returns the full block, **not** a `BeaconBlockHeader`. There is no `body_root` field in the response — it must be computed as `hash_tree_root(block.body)`. But the code falls through to a zero body_root. This means the signed `BeaconBlockHeader` has `body_root = 0x00...00`, which:
1. Produces the wrong signing root → wrong signature → BN rejects the block.
2. Even if accepted, it would be a different block than what was proposed.

**Fix:** Either:
- SSZ-decode the full block, compute `hash_tree_root(body)`, and build the header.
- Or: the `v3` response may include the block in JSON — compute the SSZ hash tree root of the body from the deserialized data.

### BUG-4: Block JSON injection is fragile and likely wrong (block_service.zig:270-280)

```zig
if (std.mem.endsWith(u8, std.mem.trimRight(u8, raw, " \t\r\n"), "}")) {
    try signed_json.appendSlice(trimmed_raw[0 .. trimmed_raw.len - 1]);
    try signed_json.writer().print(",\"signature\":\"0x{s}\"}}", .{sig_hex});
}
```

The v3 block response has structure `{"version":"...","data":{...}}`. Injecting `signature` before the closing `}` puts it inside `data`, but `POST /eth/v2/beacon/blocks` expects a `SignedBeaconBlock` which wraps `{message: ..., signature: ...}`. The injection puts `signature` at the wrong nesting level.

### BUG-5: Sub-slot timing uses nanoTimestamp mod slot_duration (attestation_service.zig:286-290)

```zig
const elapsed_in_slot_ns = now_ns % slot_duration_ns;
```

`std.time.nanoTimestamp()` returns nanoseconds since an unspecified epoch (typically boot time, not Unix time). This modulo trick only works if the timestamp epoch is aligned with genesis. It is not. The correct approach is: `elapsed = now - (genesis_time + slot * seconds_per_slot)`, using Unix time. Same bug in `sync_committee_service.zig:219-227`.

### BUG-6: `SigningContext` uses a single static `fork_version` (signing.zig:39-42)

```zig
pub const SigningContext = struct {
    fork_version: [4]u8,
    genesis_validators_root: [32]u8,
};
```

The Ethereum spec requires using the fork version **for the epoch of the message being signed**, not a static fork version. When a fork boundary is crossed (e.g., Altair → Bellatrix), the fork version changes. The current code uses whichever fork version was set at startup and never updates it. This means **all signatures after a fork boundary will use the wrong domain and be invalid**.

TS Lodestar: `config.getDomain(signingSlot, domainType)` computes the fork version dynamically based on the slot's epoch.

**Fix:** `SigningContext` needs access to the fork schedule and must compute `fork_version` per-slot/per-epoch, or the services need to pass the correct fork version for each signing operation.

### BUG-7: Clock `run()` has no shutdown check (clock.zig:129-155)

```zig
while (true) {
    // ... sleep until next slot ...
}
```

The loop runs forever. `ValidatorClient` has `shutdown_requested: std.atomic.Value(bool)` and `requestShutdown()`, but the clock loop never checks it. `requestShutdown()` sets the flag, but nothing reads it in the hot path. The validator client cannot be gracefully stopped.

**Fix:** Pass a shutdown check to the clock, or have `run()` check a cancellation token each iteration.

### BUG-8: Sync committee selection proofs computed for epoch start slot, not per-slot (sync_committee_service.zig:240-244)

```zig
const slot = epoch * self.slots_per_epoch;  // ← epoch start slot
signing_mod.syncCommitteeSelectionProofSigningRoot(
    self.signing_ctx, slot, subcommittee_index, &sel_root,
) catch { ... };
```

Selection proofs should be computed for each slot within the sync period (each slot the validator needs to produce a message). Using the epoch start slot means all proofs are identical, and aggregator selection may be wrong for non-first slots.

---

## 3. Completeness Gaps

### Missing Features

| TS Service | Zig File | Status | Notes |
|---|---|---|---|
| `validatorStore.ts` | `validator_store.zig` | ✅ Implemented | Missing: remote signer delegation (signs locally only) |
| `attestation.ts` + `attestationDuties.ts` | `attestation_service.zig` | ⚠️ Partial | Aggregate construction broken (BUG-2). Missing: distributed validator (DVT) support |
| `block.ts` + `blockDuties.ts` | `block_service.zig` | ⚠️ Partial | Block signing broken (BUG-3, BUG-4). Missing: blinded blocks, builder API flow |
| `syncCommittee.ts` + `syncCommitteeDuties.ts` | `sync_committee_service.zig` | ⚠️ Partial | Selection proof timing wrong (BUG-8). Contribution JSON hardcodes `aggregation_bits: "0x00"` |
| `doppelgangerService.ts` | `doppelganger.zig` | ✅ Complete | Full detection + shutdown callback |
| `chainHeaderTracker.ts` | `chain_header_tracker.zig` | ✅ Complete | SSE parsing, reorg detection, callbacks |
| `indices.ts` | `index_tracker.zig` | ✅ Complete | Resolution, epoch refresh |
| `prepareBeaconProposer.ts` | `prepare_beacon_proposer.zig` | ✅ Complete | Fee recipient registration |
| `externalSignerSync.ts` | `remote_signer.zig` | ⚠️ Partial | Lists keys, has sign(), but never wired into `ValidatorStore.sign*()` — all signing is local |
| `emitter.ts` | — | ❌ Missing | No event emitter for duty outcomes |
| `syncingStatusTracker.ts` | `syncing_tracker.zig` | ✅ Complete | Pause/resume on sync distance |
| `utils.ts` | — | ⚠️ Partial | Some utils exist in services directly |
| Builder API / MEV | — | ❌ Missing | No `registerValidator`, no blinded block proposal flow |
| Validator effectiveness API | — | ⚠️ Partial | `liveness.zig` tracks locally, but no BN `/eth/v1/validator/liveness` push |

### Missing Non-Service Components

1. **No Keymanager HTTP server** — `keymanager_auth.zig` has token auth, but no HTTP server wiring. `ValidatorStore` has add/remove/list, but there's no route handler for `GET/POST/DELETE /eth/v1/keystores`.
2. **No voluntary exit flow** — `signing.zig` has `voluntaryExitSigningRoot()` but no service calls it.
3. **No builder/MEV flow** — no `registerValidator()`, no blinded block request/signing.
4. **No metrics** — `liveness.zig` tracks duty outcomes but there's no Prometheus endpoint or metrics registry.
5. **No CLI** — no entry point to configure and start the validator from command line.

---

## 4. Coherence Issues

### COH-1: Duplicate domain type constants (types.zig + signing.zig)

`types.zig` defines `DOMAIN_BEACON_PROPOSER`, `DOMAIN_BEACON_ATTESTER`, etc. (lines 83-97).
`signing.zig` imports domain types from `constants` module (lines 24-32), and also **re-defines** `DOMAIN_SELECTION_PROOF` inline (line 190) instead of importing it from `constants`.

The `types.zig` domain constants are **never used** by any other file. They're dead code. All actual signing goes through `signing.zig` which uses `constants.*`.

### COH-2: `ValidatorStore.pubkeys()` returns empty slice (always)

```zig
pub fn pubkeys(self: *const ValidatorStore) []const [48]u8 {
    _ = self;
    return &[_][48]u8{};
}
```

This is documented as a stub but exists as a public API. It will silently return empty for any caller, which is a trap. Either implement it or remove it.

### COH-3: `ValidatorIndexAndStatus.status` dangling pointer (api_client.zig:492-495)

```zig
dst.status = src.status; // NOTE: arena-owned, valid only within this scope.
// TODO: copy status string to owned memory if needed beyond this call.
```

The status field points into the JSON arena which is freed at the end of `getValidatorIndices()`. Any caller that accesses `.status` after the function returns gets undefined behavior. The `TODO` acknowledges this but it's a live bug.

### COH-4: `api_client.zig` creates a new `std.http.Client` per request

Every `get()` and `post()` call creates a new `std.http.Client`, makes one request, and destroys it. This means:
- No connection reuse (TCP setup + TLS handshake every call)
- No keep-alive
- Poor performance for the ~15+ API calls per slot

TS Lodestar maintains a persistent HTTP client with connection pooling.

### COH-5: `fee_recipient` type mismatch

`PrepareBeaconProposerService.default_fee_recipient` is `[42]u8` (fixed-size array holding "0x" + 40 hex chars). But `ValidatorClient` passes:

```zig
const ZERO_FEE_RECIPIENT = "0x0000000000000000000000000000000000000000".*;
```

This is `*const [42]u8` (string literal type). The type works here by coincidence (string literal decomposes to array), but the semantic type is wrong — a fee recipient should be `[20]u8` (raw bytes) serialized to hex at the JSON boundary, not carried as a hex string everywhere.

### COH-6: Clock fires epoch callbacks only on slot 0 of epoch

```zig
if (slot % self.slots_per_epoch == 0) {
    const epoch = slot / self.slots_per_epoch;
    for (self.epoch_callbacks...) { cb.call(epoch); }
}
```

If the validator starts mid-epoch, the first epoch callback won't fire until the next epoch boundary. Services that depend on epoch callbacks to fetch initial duties (block, attestation, sync committee) will have no duties until then. TS Lodestar fires an initial epoch callback at startup.

---

## 5. Taste Improvements

### TASTE-1: Hand-rolled JSON everywhere

`attestation_service.zig`, `block_service.zig`, `sync_committee_service.zig`, `prepare_beacon_proposer.zig` all construct JSON via `std.fmt.allocPrint` or manual string concatenation. This is:
- Error-prone (easy to miss quotes, escaping)
- Hard to maintain
- Impossible to validate at compile time

**Recommendation:** Define SSZ/JSON types and use `std.json.stringify` or a builder pattern.

### TASTE-2: `getDutiesAtSlot` returns ALL duties, not filtered (attestation_service.zig:312-317)

```zig
fn getDutiesAtSlot(self: *const AttestationService, slot: u64) []const AttesterDutyWithProof {
    _ = slot;
    return self.duties.items;
}
```

The function name says "at slot" but ignores the `slot` parameter and returns everything. Callers then filter inside their loops. This is confusing API design.

### TASTE-3: No `errdefer` on complex init sequences

`ValidatorClient.init()` has `errdefer validator_store.deinit()` but doesn't errdefer anything else. If `KeyDiscovery.loadAllKeys()` or subsequent operations fail, `api`, `block_service`, etc., leak.

### TASTE-4: `ArrayList(ValidatorRecord)` vs HashMap for validator lookup

`ValidatorStore.findValidator()` does a linear scan on every signing operation. With many validators (100+), this becomes measurable. A `HashMap([48]u8, *ValidatorRecord)` would be O(1).

### TASTE-5: Contribution JSON hardcodes `"aggregation_bits":"0x00"` (sync_committee_service.zig:389)

Even though the code correctly computes `agg_bits` with the right bit set (lines 370-374), the actual JSON serialization ignores this computed value and sends `"0x00"`:

```zig
"aggregation_bits\":\"0x00\""
```

The computed `agg_bits` array is never serialized into the JSON.

### TASTE-6: Unused `BlockService.deinit()` (block_service.zig:109-111)

```zig
pub fn deinit(self: *BlockService) void {
    _ = self;
}
```

Empty deinit is fine for now but indicates the fixed-size arrays strategy avoids heap — good taste. However, the `_ = self` pattern should use `_ = &self` for pointers per Zig convention (though this is a minor style point).

### TASTE-7: Magic number 32 for slots_per_epoch (attestation_service.zig:136)

```zig
const epoch = info.slot / 32; // approximate; slots_per_epoch not stored
```

The service stores `seconds_per_slot` but not `slots_per_epoch`. Hard-coding 32 breaks for test configs (e.g., minimal preset with 8 slots/epoch).

### TASTE-8: `createKeystore` retry logic has `unreachable` (keystore_create.zig:55)

```zig
const secret_key = SecretKey.fromBytes(sk_bytes) catch {
    sk_bytes[31] +%= 1;
    try SecretKey.fromBytes(sk_bytes);  // error is propagated
    unreachable;                         // never reached if try propagates
};
```

The `try` on the second attempt already propagates the error, so `unreachable` is correct, but the code reads awkwardly. A clearer pattern would be a `while` loop with `break`.

---

## 6. File-by-File Notes

### `validator.zig` (517 lines)
- **Line 80:** `ZERO_FEE_RECIPIENT` defined as `"0x0...".*` — works but fragile. Should be `[42]u8` literal or const.
- **Lines 163-191:** BUG-1 — dangling pointers from init locals.
- **Lines 260-262:** `requestShutdown()` sets flag but clock never checks it (BUG-7).
- **Line 291:** SSE header tracker not started — documented limitation, fine for MVP.
- **Line 330:** `onSlotBlockService` etc. — lots of trampoline functions. Acceptable pattern for type-erased callbacks.
- **Line 369:** `isSafeToSign` on `ValidatorClient` is unused by services (they each have their own copy).

### `types.zig` (154 lines)
- **Lines 83-97:** Dead domain constants (COH-1).
- Clean struct definitions, good documentation.

### `signing.zig` (193 lines)
- **BUG-6:** Static fork_version (lines 39-42).
- **Line 190:** Re-defines `DOMAIN_SELECTION_PROOF` locally instead of importing from `constants`.
- Otherwise: well-structured, delegates to real `state_transition` module, correct domain types.

### `validator_store.zig` (482 lines)
- **Line 177:** `pubkeys()` stub returns empty slice (COH-2).
- **Line 208:** `signBlock()` — slashing protection called before signing. Correct order. ✅
- **Line 244:** `signAttestation()` — slashing protection before signing. Correct. ✅
- **Line 322:** `findValidator()` is O(n). Fine for < 100 validators.
- Good test coverage for slashing protection.

### `slashing_protection_db.zig` (587 lines)
- **Best file in the codebase.** Thorough surround vote detection, sorted history, crash-safe append-only format, duplicate detection on replay, excellent test coverage.
- **Minor:** No file locking. If two processes open the same DB file, they'll corrupt it. Standard for single-process validator clients though.
- **TOCTOU:** `checkAndInsert*` methods are not atomic: between the check and the file append, another thread could interleave. The `SlashingProtectionDb` is only accessed via `ValidatorStore` which holds a mutex, so this is safe as long as `SlashingProtectionDb` is never used directly from multiple threads.

### `attestation_service.zig` (496 lines)
- **BUG-2:** Aggregate uses zeroed attestation (line 380).
- **BUG-5:** Sub-slot timing broken (line 286).
- **TASTE-2:** `getDutiesAtSlot` ignores `slot` parameter.
- **TASTE-7:** Hard-coded `32` for slots_per_epoch (line 136).
- **Line 340:** Good pattern — computes attestation signing root once for all validators in the slot.
- **Line 414:** Aggregate JSON is malformed — `agg_pk_hex[0..2]` sliced as selection_proof (bug in format string).

### `block_service.zig` (372 lines)
- **BUG-3:** Zero body_root in BeaconBlockHeader.
- **BUG-4:** JSON injection fragile.
- **Line 200:** `MAX_DUTIES_PER_EPOCH = 32` used as both array size and `slots_per_epoch` — conflation will break if slots_per_epoch changes.
- **Line 249:** JSON parsing for block header fields — fragile but reasonable as a first pass.
- **Line 303-317:** `checkMissedSlots` — good monitoring feature.

### `sync_committee_service.zig` (455 lines)
- **BUG-8:** Selection proofs use epoch start slot instead of per-slot.
- **TASTE-5:** `aggregation_bits` hardcoded as `"0x00"` in JSON despite being computed.
- **Line 120:** `SYNC_COMMITTEE_SIZE = 512` hardcoded — should come from config (minimal preset uses 32).
- **Line 270:** `produceAndPublishContributions` — no aggregator eligibility check! The code iterates all selection proofs but doesn't check `is_aggregator = SHA256(proof)[0:8] % modulo == 0`. Every validator with a non-null proof attempts to aggregate.

### `api_client.zig` (969 lines)
- **COH-3:** `ValidatorIndexAndStatus.status` dangling pointer.
- **COH-4:** New HTTP client per request.
- Good fallback URL rotation logic.
- SSE parsing is correct and well-implemented.
- `produceBlock` response named `block_ssz` but contains JSON — misleading.

### `clock.zig` (193 lines)
- **BUG-7:** No shutdown mechanism.
- **COH-6:** No initial epoch callback at startup.
- Clean implementation otherwise. Good use of `Io.Timeout.sleep`.

### `doppelganger.zig` (262 lines)
- Complete and correct implementation.
- Good state machine: `unverified → verified_safe` or `→ doppelganger_detected`.
- Shutdown callback wired. Error returned to halt epoch processing.
- `DEFAULT_REMAINING_DETECTION_EPOCHS = 1` — matches TS. ✅

### `chain_header_tracker.zig` (254 lines)
- Clean SSE parsing, mutex-protected head info, callbacks.
- Properly handles `previous_duty_dependent_root` and `current_duty_dependent_root` for reorg detection.

### `index_tracker.zig` (268 lines)
- Complete implementation with mutex, resolution, and epoch refresh.
- Good tests.

### `prepare_beacon_proposer.zig` (143 lines)
- Clean and complete.
- `[42]u8` for fee recipient is awkward (COH-5) but functional.

### `keystore.zig` (616 lines)
- **Excellent implementation.** Correct scrypt and PBKDF2 flows. Proper AES-128-CTR. HMAC-SHA256 checksum verification.
- EIP-2335 test vectors pass. ✅
- Good error handling for wrong password.

### `keystore_create.zig` (335 lines)
- Complete encrypt + write flow.
- Proper UUID v4 generation.
- Round-trip test verifies encrypt → decrypt.

### `key_discovery.zig` (283 lines)
- Correct directory layout scanning.
- Graceful handling of missing directories, bad hex, missing passwords.
- Password trimming of trailing whitespace. ✅

### `interchange.zig` (400 lines)
- Complete EIP-3076 v5 import/export.
- Genesis validators root verification (critical safety check). ✅
- Only tracks max slot/epoch ("fast import" strategy) — documented and correct.

### `keymanager_auth.zig` (174 lines)
- Proper bearer token auth with constant-time comparison. ✅
- Generate/load/persist flow correct.

### `remote_signer.zig` (273 lines)
- Lists keys and signs via Web3Signer API.
- **Gap:** Uses `"type": "UNKNOWN"` for all sign requests — Web3Signer expects type-specific payloads (BLOCK_V2, ATTESTATION, etc.).
- **Gap:** Never wired into `ValidatorStore` — all signing is local.

### `liveness.zig` (360 lines)
- Clean rolling window tracker.
- Good warning thresholds.
- Epoch summary logging.

### `syncing_tracker.zig` (140 lines)
- Complete with atomic state, threshold logic, state transition logging.
- Starts optimistic (synced=true) — reasonable default.

### `root.zig` (83 lines)
- Clean re-export file. All modules exposed.

---

## 7. Prioritized Action Items

### P0 — Must Fix (Would cause incorrect behavior)

1. **BUG-1:** Fix dangling pointers in `ValidatorClient.init()` — two-phase init or pointer capture in `start()`.
2. **BUG-3 + BUG-4:** Fix block signing — compute body_root via SSZ hash_tree_root, build proper `SignedBeaconBlock` JSON/SSZ.
3. **BUG-6:** Make `SigningContext` fork-aware — look up fork version per signing epoch/slot.
4. **BUG-2:** Decode aggregate attestation from BN response and use in `AggregateAndProof`.
5. **BUG-5:** Fix sub-slot timing — use `genesis_time + slot * seconds_per_slot` as reference, not `nanoTimestamp() % slot_duration`.
6. **BUG-7:** Add shutdown check to clock `run()` loop.
7. **BUG-8:** Compute sync committee selection proofs per-slot, not per-epoch.
8. **Missing aggregator check in sync committee contributions** — add `is_aggregator` check.

### P1 — Should Fix (Functional gaps)

9. **COH-3:** Fix `ValidatorIndexAndStatus.status` dangling pointer — copy string to owned memory.
10. **COH-6:** Fire initial epoch callback on startup.
11. **TASTE-5:** Serialize computed `agg_bits` into contribution JSON.
12. **Line 414 in attestation_service.zig:** Fix aggregate JSON format string (selection_proof field uses wrong hex slice).
13. Wire `RemoteSigner` into `ValidatorStore` for remote signing support.
14. Remove dead domain constants from `types.zig`.

### P2 — Nice to Have (Quality improvements)

15. **COH-4:** Reuse HTTP client across requests (connection pooling).
16. **TASTE-1:** Replace hand-rolled JSON with proper serialization.
17. **TASTE-4:** Use HashMap for validator lookup in `ValidatorStore`.
18. **COH-2:** Implement or remove `ValidatorStore.pubkeys()`.
19. Add Keymanager HTTP server wiring.
20. Add builder/blinded block flow.
21. Pass `slots_per_epoch` to services that currently hardcode 32.
22. Add proper metrics/Prometheus endpoint.

---

## Summary

The validator client is a solid architectural foundation — the service decomposition mirrors TS Lodestar well, the slashing protection is properly implemented with full surround vote detection, and the signing root computation correctly delegates to the real `state_transition` module rather than being hand-rolled. The keystore, interchange, and key discovery implementations are production-quality.

However, there are ~8 correctness bugs that would prevent the client from successfully performing any validator duties against a real beacon node. The most critical are the dangling pointer issue (BUG-1), the static fork version (BUG-6), and the broken block/aggregate construction (BUG-2, BUG-3, BUG-4). These need to be fixed before integration testing.

The code was clearly written by multiple agents at different times — some files are excellent (keystore, slashing_protection_db), while others have obvious placeholders and TODO comments (block_service JSON handling, sync committee contribution JSON). A focused correctness pass addressing the P0 items would bring this to a testable state.
