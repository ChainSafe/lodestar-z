# Aggregate Gossip + Direct-Peer Resilience Implementation Plan

> For Hermes: Use subagent-driven-development skill to implement this plan task-by-task.

Date: 2026-04-21

Goal: eliminate the false-invalid aggregate gossip penalties that disconnect real peers, and make configured direct peers reconnect boundedly instead of being consumed once at startup.

Architecture: split the work into two production-real patches. First, bring aggregate gossip validation to Lodestar-TS parity by fixing phase-1 semantics, moving aggregate dedup writes behind successful verification, and routing signing-root/signature-set construction through canonical helpers instead of callback-local reconstruction. Second, replace the startup-only direct-peer cursor with a steady-state runtime tracker that respects peer-manager eligibility and bounded backoff.

Tech stack: Zig, Lodestar-Z beacon node, `src/chain/gossip_validation.zig`, `src/node/gossip_node_callbacks.zig`, `src/networking/peer_manager.zig`, `src/networking/peer_db.zig`, Lodestar-TS reference validation/signature-set behavior.

---

## Why this plan exists

Current local evidence points to two independent but compounding problems:

1. Aggregate gossip correctness is still too bespoke.
- `src/node/gossip_node_callbacks.zig:722-803` (`resolveAggregate`) hand-builds selection-proof and wrapper signing roots.
- `src/node/gossip_node_callbacks.zig:1210-1249` (`verifyResolvedAggregateSignature`) hand-builds the inner aggregate signature set.
- `src/node/gossip_node_callbacks.zig:1295-1385` (`verifySyncContributionSignature`) hand-builds all three sync contribution signature legs.
- `src/fork_types/any_attestation.zig:76-89` silently maps Electra `committee_bits` to the first set bit or `0`, which is too implicit for gossip validation.

2. Direct-peer reconnect behavior is still startup-only.
- `src/node/beacon_node.zig:824-825` stores only `next_direct_peer_index`.
- `src/node/p2p_runtime.zig:1158-1166` just resets that cursor.
- `src/node/p2p_runtime.zig:1230-1257` consumes each direct peer once and stops permanently once the cursor reaches the end.
- `src/node/p2p_runtime.zig:2722-2729` dials a direct peer without any persistent retry state or peer-manager dialing bookkeeping.
- The peer layer already has the primitives we should use instead of inventing a second policy:
  - `src/networking/peer_info.zig:395-396` says trusted/direct peers should always be reconnected.
  - `src/networking/peer_manager.zig:517-536` already exposes `dialEligibility()`.
  - `src/networking/peer_db.zig:410-414` already exposes `setTrusted()`.

Reference behavior to preserve:
- Lodestar-TS aggregate validation and signature sets:
  - `../lodestar/packages/beacon-node/src/chain/validation/aggregateAndProof.ts`
  - `../lodestar/packages/beacon-node/src/chain/validation/syncCommitteeContributionAndProof.ts`
  - `../lodestar/packages/beacon-node/src/chain/validation/signatureSets/{selectionProof,aggregateAndProof,syncCommitteeSelectionProof,contributionAndProof}.ts`
- Existing local sync-contribution dedup pattern that is already good enough to copy for aggregate superset tracking:
  - `src/chain/seen_cache.zig:260-315`

---

## Patch order

1. Aggregate phase-1 parity and dedup staging
2. Canonical aggregate/signature-set helper refactor
3. Direct-peer steady-state reconnect state machine
4. Kurtosis validation rerun after aggregate patch lands

Do not combine all of this into one giant patch.

---

## Task 1: Fix aggregate phase-1 gossip semantics

**Objective:** make phase-1 aggregate gossip behavior match Lodestar-TS before touching the expensive BLS path.

**Files:**
- Modify: `src/chain/gossip_validation.zig:299-337`
- Modify: `src/chain/gossip_validation.zig:631-677`
- Test: `src/chain/gossip_validation.zig:544-611`
- Test: `src/chain/gossip_validation.zig:1280-1337`

**Required code changes:**
1. Change stale aggregate handling from `reject` to `ignore` for both:
   - `validateGossipAggregate()`
   - `validateGossipElectraAggregate()`
2. Keep `attestation_epoch != target_epoch` as `reject`.
3. Stop calling `state.seen_cache.markAggregatorSeen(...)` in phase-1.
4. Keep only the early duplicate read check (`hasSeenAggregator(...)`) in phase-1.

**Why:**
- Lodestar-TS `aggregateAndProof.ts` treats out-of-window aggregate propagation failures as IGNORE, not REJECT.
- Current Zig phase-1 code marks the aggregator as seen before signature verification, so an invalid aggregate can poison dedup state.

**Step 1: Update the existing tests to express the intended behavior**
- Rename or replace:
  - `test "gossip aggregate: reject stale epoch"`
  - add Electra stale-slot coverage mirroring the pre-Electra case
- Expected behavior after the patch:
  - stale aggregate -> `AttestationGossipAction.ignore`
  - invalid-but-first aggregate must not permanently poison later valid aggregate handling

**Step 2: Add a regression test for dedup poisoning**
Add a new focused test in `src/chain/gossip_validation.zig` or `src/node/gossip_handler_test.zig` that proves:
- first aggregate passes phase-1 but is intentionally invalid later
- second aggregate with the same `(aggregator_index, epoch)` is still allowed to continue to phase-2 because phase-1 did not mark it seen yet

**Step 3: Run targeted tests**
Run:
```bash
zig build test:chain -Dchain.filters='gossip aggregate|gossip electra aggregate'
```
Expected: all aggregate phase-1 tests pass with stale-slot IGNORE semantics.

**Step 4: Commit**
```bash
git add src/chain/gossip_validation.zig
git commit -m "fix: align aggregate gossip phase-1 semantics with lodestar-ts"
```

---

## Task 2: Add aggregate participant-superset dedup parity

**Objective:** give aggregate gossip the same kind of participant-superset dedup that sync contributions already have.

**Files:**
- Create: `src/chain/seen_aggregated_attestations.zig`
- Modify: `src/chain/root.zig`
- Modify: `src/chain/chain.zig`
- Modify: `src/chain/runtime.zig`
- Modify: `src/node/gossip_handler.zig`
- Test: `src/node/gossip_handler_test.zig`
- Reference pattern: `src/chain/seen_cache.zig:260-315`

**Required data model:**
Key aggregate dedup by:
- target epoch
- committee index
- attestation data root
- aggregation bitfield entries sorted by descending true-bit-count

**Required behavior:**
1. Early phase check: if an already-seen superset exists, ignore the aggregate.
2. Post-BLS success path: re-check the same condition to avoid races.
3. Only after successful verification/import:
   - mark aggregator seen
   - mark aggregate participant bitfield seen

**Design constraints:**
- Do not overload the existing sync contribution cache with aggregate-specific semantics.
- Prefer a dedicated file over growing `SeenCache` into a grab bag.
- Add explicit pruning by epoch/slot so this cache cannot grow forever.

**Step 1: Write failing tests first**
Add tests in `src/node/gossip_handler_test.zig` for:
- subset aggregate ignored after valid superset
- invalid aggregate does not poison later valid aggregate from same aggregator
- race-safe double-check behavior if two aggregates with same aggregator land close together

**Step 2: Implement the dedicated aggregate dedup cache**
Create `src/chain/seen_aggregated_attestations.zig` with:
- insert ordered by true-bit-count descending
- `isBitSupersetOrEqual(...)` semantics matching sync contributions
- prune helpers

**Step 3: Wire it into gossip handling**
Use the new aggregate dedup cache from the aggregate gossip success path in `src/node/gossip_handler.zig`.

**Step 4: Run targeted tests**
Run:
```bash
zig build test:node -Dnode.filters='onAggregateAndProof|sync contribution ignores seen aggregator and participant superset'
```
Expected: aggregate dedup tests and existing sync-contribution dedup tests pass together.

**Step 5: Commit**
```bash
git add src/chain/seen_aggregated_attestations.zig src/chain/root.zig src/chain/chain.zig src/chain/runtime.zig src/node/gossip_handler.zig src/node/gossip_handler_test.zig
git commit -m "fix: add aggregate gossip superset dedup parity"
```

---

## Task 3: Canonicalize aggregate signature-set construction

**Objective:** stop open-coding aggregate signing roots and signature sets inside gossip callbacks.

**Files:**
- Create: `src/state_transition/signature_sets/aggregate_and_proof.zig`
- Create: `src/state_transition/signature_sets/sync_contribution_and_proof.zig`
- Modify: `src/state_transition/root.zig`
- Modify: `src/node/gossip_node_callbacks.zig`
- Modify: `src/fork_types/any_attestation.zig`
- Test: `src/node/gossip_node_callbacks.zig`

**Required helper surface:**
Mirror Lodestar-TS naming/behavior closely:
- `getSelectionProofSigningRoot`
- `getAggregateAndProofSigningRoot`
- `getAggregateAndProofSignatureSet`
- `getSyncCommitteeSelectionProofSignatureSet`
- `getContributionAndProofSignatureSet`
- `getSyncCommitteeContributionSignatureSet`

**Rules the helpers must encode:**
1. Selection proof root uses the fork of the message slot, not a state-epoch fallback.
2. Aggregate-and-proof wrapper root uses the fork of `computeStartSlotAtEpoch(target_epoch)`.
3. Sync contribution wrapper and selection helpers use the contribution slot fork.
4. Electra aggregate wrapper signing uses the Electra SSZ type; pre-Electra uses phase0.
5. Electra committee extraction in gossip paths must require exactly one set committee bit; no silent `0` fallback.

**Step 1: Add failing unit tests in `src/node/gossip_node_callbacks.zig`**
Keep or extend fork-boundary tests that prove:
- `gossipDomainAtSlot` uses message-slot fork selection
- attestation signing roots follow target-epoch fork semantics
- sync contribution signing roots follow contribution-slot fork semantics
- Electra committee extraction rejects zero/multiple committee bits in gossip-only paths

**Step 2: Implement new canonical helper modules**
Put the domain/signing-root/signature-set logic in `src/state_transition/signature_sets/*` and export it from `src/state_transition/root.zig`.

**Step 3: Refactor the callback code to consume those helpers**
Replace inline signing-root assembly in:
- `resolveAggregate()`
- `verifyResolvedAggregateSignature()`
- `verifySyncContributionSignature()`

**Step 4: Make Electra committee extraction explicit**
Do not rely on `AnyAttestation.committeeIndex()` for gossip validation unless it is upgraded to return an error for zero/multiple committee bits.

**Step 5: Run targeted tests**
Run:
```bash
zig build test:node -Dnode.filters='gossipDomainAtSlot|gossip attestation signing root|gossip sync contribution roots|onAggregateAndProof validates electra aggregates'
```
Expected: all targeted signing-root/fork-boundary tests pass.

**Step 6: Commit**
```bash
git add src/state_transition/signature_sets/aggregate_and_proof.zig src/state_transition/signature_sets/sync_contribution_and_proof.zig src/state_transition/root.zig src/node/gossip_node_callbacks.zig src/fork_types/any_attestation.zig
git commit -m "refactor: canonicalize aggregate gossip signature-set construction"
```

---

## Task 4: Move aggregate seen-marking behind successful verification/import

**Objective:** finalize aggregate dedup state only after the message has actually cleared the expensive/canonical validation path.

**Files:**
- Modify: `src/node/gossip_handler.zig`
- Modify: `src/node/gossip_node_callbacks.zig`
- Test: `src/node/gossip_handler_test.zig`

**Required behavior:**
1. Phase-1 only checks for known duplicates.
2. Phase-2 verify/import path re-checks duplicate state.
3. Only on success:
   - mark aggregator seen
   - mark aggregate participant superset seen
4. Unknown-block/deferred aggregate replay must still work; do not mark dedup state for items that are being deferred for later replay.

**Step 1: Add a replay-safe regression test**
Add a test proving an aggregate returning `unknown_beacon_block` or deferral is not permanently dropped as “already seen” when replayed later.

**Step 2: Wire success-path marking**
Put the marking exactly after successful verify/import completion in the aggregate handler path.

**Step 3: Run targeted tests**
Run:
```bash
zig build test:node -Dnode.filters='onAggregateAndProof|queues unknown beacon_block_root for replay'
```
Expected: accepted aggregates are deduped only after success, deferred aggregates still replay.

**Step 4: Commit**
```bash
git add src/node/gossip_handler.zig src/node/gossip_node_callbacks.zig src/node/gossip_handler_test.zig
git commit -m "fix: mark aggregate gossip seen only after successful verification"
```

---

## Task 5: Replace the startup-only direct-peer cursor with steady-state runtime state

**Objective:** make `--direct-peers` a maintained set of operator-curated peers rather than a one-shot startup bootstrap list.

**Files:**
- Modify: `src/node/beacon_node.zig`
- Modify: `src/node/p2p_runtime.zig`
- Modify: `src/networking/peer_manager.zig`
- Test: `src/node/p2p_runtime.zig`
- Test: `src/networking/peer_manager.zig`

**Required structural changes:**
1. Replace:
- `src/node/beacon_node.zig:824-825`
  - `next_direct_peer_index: usize = 0`
2. With BeaconNode-owned runtime state, for example:
- `direct_peer_states: []DirectPeerState = &.{}`
- `next_direct_peer_rr_index: usize = 0`

**Recommended `DirectPeerState` contents:**
- configured address string
- optional known peer id
- dialing flag
- consecutive failure count
- next attempt deadline in ms

**Step 1: Write pure helper tests first**
Add small scheduler tests in `src/node/p2p_runtime.zig` for:
- retries after disconnect when backoff expires
- no redial while peer is connected/dialing/disconnecting
- round-robin across multiple direct peers with a per-tick budget of 1
- reset of backoff after successful connect

**Step 2: Rewrite bootstrapDirectPeers()**
Make it initialize direct-peer runtime state once instead of resetting a cursor.

**Step 3: Replace `bootstrapNextDirectPeer()` with `maintainDirectPeers()`**
New rules:
- scan configured direct peers every maintenance pass
- skip entries that are already connected, dialing, disconnecting, banned, or cooling down
- use `pm.dialEligibility(peer_id, now_ms)` when a peer id is known
- obey bounded backoff
- attempt at most one direct dial per maintenance tick
- do not gate direct-peer maintenance on `MIN_PEERS_TO_SYNC`

**Step 4: Reorder connectivity maintenance**
In `runConnectivityMaintenance()`, reconcile transport-derived peer state before choosing direct-peer redials, so the dial decision uses fresh state.

**Step 5: Add a small peer-manager wrapper**
Expose a public helper on `PeerManager` that marks a peer trusted via the existing DB primitive. Do not reach around the peer manager from runtime code.

**Step 6: Run targeted tests**
Run:
```bash
zig build test:node -Dnode.filters='direct peer|runtime'
zig build test:networking -Dnetworking.filters='trusted peers not pruned'
```
Expected: scheduler tests pass and trusted peers still are not pruned.

**Step 7: Commit**
```bash
git add src/node/beacon_node.zig src/node/p2p_runtime.zig src/networking/peer_manager.zig
git commit -m "fix: keep configured direct peers on bounded steady-state redial"
```

---

## Task 6: Tie direct-peer state into connect and disconnect completions

**Objective:** make the new direct-peer state machine observe real dial success/failure and transport disconnects.

**Files:**
- Modify: `src/node/p2p_runtime.zig`
- Modify: `src/networking/peer_manager.zig`
- Test: `src/node/p2p_runtime.zig`

**Required behavior:**
1. On successful direct dial:
- clear dialing state
- reset backoff
- capture peer id if available
- mark the peer trusted through `PeerManager`
2. On direct dial failure:
- clear dialing state
- increment bounded backoff
3. On later transport disconnect of a known direct peer:
- schedule a bounded retry instead of leaving the harness stranded
4. Do not bypass peer-manager bans or reconnection cooldowns.

**Step 1: Add direct-dial failure/success tests**
Cover:
- success resets backoff and records peer id
- failure schedules a later retry
- disconnect schedules retry for tracked direct peer
- cooldown/banned state suppresses retry

**Step 2: Wire completion hooks**
Hook the new direct-peer state transitions into the existing dial success/failure and disconnect paths in `p2p_runtime.zig`.

**Step 3: Run targeted tests**
Run:
```bash
zig build test:node -Dnode.filters='direct peer|disconnect|redial'
```
Expected: reconnect logic is bounded and stable under disconnects.

**Step 4: Commit**
```bash
git add src/node/p2p_runtime.zig src/networking/peer_manager.zig
git commit -m "fix: reconnect direct peers after disconnect with bounded backoff"
```

---

## Task 7: Run broad verification before Kurtosis rerun

**Objective:** ensure the tree is coherent before spending time on the sidecar harness.

**Files:**
- No source-file requirement beyond whatever changed above.

**Step 1: Run focused test targets**
```bash
zig build test:chain -Dchain.filters='gossip aggregate|gossip electra aggregate'
zig build test:node -Dnode.filters='gossipDomainAtSlot|gossip attestation signing root|gossip sync contribution roots|onAggregateAndProof|sync contribution ignores seen aggregator and participant superset|direct peer'
zig build test:networking -Dnetworking.filters='trusted peers not pruned'
```

**Step 2: Run broader suites**
```bash
zig build test:node
zig build test:networking
zig build
```

**Expected result:**
- all targeted tests pass
- no regressions in node/networking suites
- release/dev build completes cleanly

---

## Task 8: Re-run the Kurtosis sidecar and verify real peer retention

**Objective:** prove the aggregate fix removes the false-invalid disconnects, and the direct-peer fix prevents permanent stranding after a disconnect.

**Files:**
- Modify only if additional debug logging is temporarily needed.
- Reference harness notes:
  - `docs/design/KURTOSIS_SIDECAR_DEBUG_FINDINGS.md`
  - `docs/design/KURTOSIS_AGGREGATE_GOSSIP_VALIDATION_PLAN.md`

**Step 1: Rebuild the image**
```bash
docker build -f docker/kurtosis/Dockerfile -t lodestar-z:kurtosis .
```

**Step 2: Restart the sidecar from a fresh data dir**
Use the existing reference-only enclave and keep Lighthouse as the meaningful QUIC target.

**Step 3: Verify live behavior**
Run:
```bash
curl -fsS http://127.0.0.1:33952/eth/v1/node/syncing
curl -fsS http://127.0.0.1:33808/metrics | grep -E '^(libp2p_peers|p2p_peer_connection_state_count|beacon_gossipsub_mesh_peers|beacon_gossipsub_topic_peers|beacon_gossipsub_outbound_streams|p2p_peer_reports_total|beacon_head_slot|beacon_sync_distance)'
docker logs --since 5m lodestar-z-sidecar-ref 2>&1 | perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' | grep -E 'aggregate|contribution|InvalidSignature|low_tolerance|direct peer|Connected to direct peer|Peer disconnected'
curl -fsS http://127.0.0.1:33008/eth/v1/node/peers
```

**Success criteria:**
- sidecar reaches head again
- false-invalid aggregate/contribution signature rejections disappear
- `p2p_peer_reports_total{source="gossipsub",action="low_tolerance"}` no longer climbs because of these messages
- the Lighthouse peer remains connected after gossip becomes active
- if the direct peer disconnects once, the sidecar later attempts a bounded redial instead of staying at `peers=0`

---

## Readiness signoff

This work is implementation-ready.

Highest-confidence first moves:
1. `src/chain/gossip_validation.zig`: change stale aggregate handling to IGNORE and stop phase-1 `markAggregatorSeen()`.
2. Add aggregate participant-superset dedup using the sync contribution cache pattern as the model.
3. Move aggregate/signature-root construction into canonical `src/state_transition/signature_sets/*` helpers and consume them from `src/node/gossip_node_callbacks.zig`.
4. Replace the startup-only `next_direct_peer_index` cursor with persistent direct-peer runtime state plus bounded redial.

Do not ship temporary workaround logic here. The correct direction is Lodestar-TS parity for aggregate validation semantics and a production-real runtime state machine for curated direct peers.