# Gossipsub async-validation review

Date: 2026-04-22

## Scope

Review whether Lodestar-Z's current Zig gossipsub async-validation model should move closer to the Lodestar-TS / js-libp2p-gossipsub model.

Reviewed code:
- Zig:
  - `zig-pkg/libp2p-0.1.0-Sj0LiOefCQANndzyK8XV66ut86LacMn088voDlrKi7I4/src/protocol/gossipsub/router.zig`
  - `zig-pkg/libp2p-0.1.0-Sj0LiOefCQANndzyK8XV66ut86LacMn088voDlrKi7I4/src/protocol/gossipsub/mcache.zig`
  - `zig-pkg/libp2p-0.1.0-Sj0LiOefCQANndzyK8XV66ut86LacMn088voDlrKi7I4/src/protocol/gossipsub/config.zig`
  - `src/networking/p2p_service.zig`
  - `src/processor/processor.zig`
  - `src/node/beacon_node.zig`
- Lodestar-TS / js-libp2p:
  - `packages/beacon-node/src/network/gossip/gossipsub.ts`
  - `packages/beacon-node/src/network/processor/index.ts`
  - `node_modules/.pnpm/@libp2p+gossipsub@15.0.15/node_modules/@libp2p/gossipsub/dist/src/gossipsub.js`
  - `node_modules/.pnpm/@libp2p+gossipsub@15.0.15/node_modules/@libp2p/gossipsub/dist/src/message-cache.js`

## Short verdict

Yes: Lodestar-Z should move closer to the js-libp2p model, but not by blindly porting everything.

The current Zig design is not wrong simply because it has a pending-validation tracker. Async validation requires retained state in both implementations.

The real issue is that Zig currently uses a weaker and more duplication-heavy shape than js-libp2p:
- a separate `pending_validations` map clones full messages before validation
- accepted messages are then cloned again into `mcache`
- duplicate propagators are not tracked while validation is pending
- reject handling is therefore less informed than js-libp2p
- saturation can drop messages at the router boundary before the application pipeline catches up

Recommendation:
- move toward a js-libp2p-style `mcache` that can hold unvalidated messages
- remove the separate router-level full-message `pending_validations` map
- keep the application/processor-side deferred-result bookkeeping, but make the router retain pending message state inside `mcache`

## What both systems actually need

Both implementations use async validation.

### Lodestar-TS / js-libp2p
- Lodestar-TS enables `asyncValidation: true`
- js-libp2p stores inbound messages in `mcache` immediately with `validated=false`
- later `reportMessageValidationResult()` either:
  - marks the cache entry validated and forwards it, or
  - removes it and applies reject scoring
- `mcache` also tracks:
  - `originatingPeers`
  - `notValidatedCount`
  - first-seen/validation-delay metrics

### Lodestar-Z / Zig
- Zig router emits subscribed messages for manual validation
- before that, it stores a full cloned copy in `pending_validations`
- later `reportValidationResult()` removes that pending entry and:
  - on accept, clones again into `mcache` and forwards
  - on ignore/reject, drops it
- application-level completion bookkeeping is separate again in `BeaconProcessor.pending_gossip_validations`

So the difference is not:
- "TS has async validation but Zig does not"

The difference is:
- TS stores pending/unvalidated state in `mcache`
- Zig stores pending/unvalidated state in a separate router map and only later inserts into `mcache`

## Why the current Zig shape is weaker

### 1. Extra message copying and memory churn

Current Zig path for a manually validated inbound message:
1. parse inbound message
2. clone into `pending_validations`
3. emit event to app
4. on accept, clone again into `mcache`

By contrast, js-libp2p stores once in cache and flips a validated bit later.

Consequence:
- higher copy/allocation churn under heavy gossip load
- worse saturation behavior exactly in the path we are currently hitting on nogroup

### 2. No tracking of duplicate propagators while pending

js-libp2p `MessageCache` tracks `originatingPeers` for unvalidated messages.
That matters because:
- on reject, all known propagators can be penalized
- on accept, forwarding can avoid resending to peers that already propagated the message

Current Zig `pending_validations` stores only one `source_peer`.

Consequence:
- reject/ignore handling is less informative than the js-libp2p model
- forwarding/reject behavior is less faithful to mature gossipsub behavior

### 3. Router-level saturation happens before the application pipeline can absorb work

Current Zig router has:
- `max_pending_validations = 4096`
- if full, it logs:
  - `dropping inbound message because pending validation limits were reached`

This is exactly the live warning currently appearing on nogroup.

Current live behavior suggests the router's pending-validation boundary is becoming the hot drop point before our own processor queues report being full.

Consequence:
- router-level backpressure is firing earlier than the downstream scheduler metrics make obvious
- the failure signal is opaque and coarse

### 4. Two disjoint pending-validation subsystems exist today

Current Zig has:
- router-level pending message retention:
  - `pending_validations`
- processor-level deferred completion tracking:
  - `pending_gossip_validations`

These two layers store different aspects of the same logical "waiting for validation result" state.

Consequence:
- more moving parts than necessary
- harder reasoning about where the bottleneck actually is
- easier for hurried code to accidentally duplicate ownership or lose information

## What should move closer to js-libp2p

### Recommended convergence

#### A. Make `mcache` capable of holding unvalidated entries
Add support in Zig `mcache` for:
- `validated: bool`
- `originating_peers`
- maybe `first_seen_ns` / `first_seen_ms`
- `not_validated_count`

This is the most valuable structural convergence.

#### B. Remove router-level full-message `pending_validations`
Instead of:
- cloning full messages into `pending_validations`
- then later cloning again into `mcache`

Use:
- `mcache.putWithId(..., validated=false)` on inbound accepted-for-manual-validation messages
- `reportValidationResult(accept)` to mark validated and forward
- `reportValidationResult(ignore/reject)` to remove from mcache

#### C. Track duplicate propagators while validation is pending
Mirror js-libp2p behavior by recording duplicate senders against unvalidated cached messages.

That gives Zig:
- better reject scoring behavior
- better forwarding hygiene on accept
- better parity with mature gossipsub semantics

### Keep separate app-side completion context if needed
I do **not** recommend forcing the entire application/processor side into js-libp2p's exact shape.

Zig still benefits from an application-side deferred-validation context map because our app pipeline needs:
- fork digest
- topic type
- subnet id
- peer id handle
- integration with `BeaconProcessor`

So the target is not:
- "collapse everything into one structure"

It is:
- keep processor-side completion bookkeeping
- remove the router-side extra full-message pending clone map
- let `mcache` be the single retained-message store during async validation

## What should not be copied blindly

### Do not simply delete all bounds
js-libp2p's model does not mean "unbounded pending validation is fine".

Zig should still keep explicit bounds/metrics for:
- count of unvalidated cached messages
- total bytes held by unvalidated entries
- oldest validation age
- per-topic pending-unvalidated counts

The difference should be:
- bound/cache one retained-message store
not
- bound one store and duplicate into another

### Do not copy TS network-processor architecture wholesale
Lodestar-TS also has application-side queueing/backpressure in the beacon-node layer.
Zig should take behavioral guidance, not architectural copy-paste.

## Immediate low-risk improvements even before a full convergence refactor

1. Add metrics for current Zig router pending validation pressure
- pending validation count
- oldest pending age
- total retained bytes if easy to compute

2. Confirm whether seen-cache poisoning on pending-limit drop is acceptable
Current Zig path does:
- dedup miss
- `rememberSeen(mid)`
- then checks pending-validation limit
- then may drop the message

If a message is marked seen before it is admitted to retained pending state, saturation may suppress useful duplicates later.
This deserves targeted review before refactoring.

3. Record duplicate sources for still-pending messages
Even before a full mcache convergence, enriching pending entries with duplicate propagators would bring Zig closer to js-libp2p's semantics.

## Recommended phased implementation order

### Phase 1: observability and semantic cleanup
- add pending-validation metrics on the Zig router side
- review and fix seen-before-admission behavior if needed
- record duplicate propagators for pending messages
- keep current architecture otherwise

### Phase 2: mcache convergence
- extend Zig `mcache` with:
  - `validated`
  - `originating_peers`
  - unvalidated counters/metrics
- route manual-validation messages into `mcache` directly
- remove router `pending_validations`
- update `reportValidationResult()` accordingly

### Phase 3: throughput tuning after convergence
- measure whether the hot drop point moves from router pending-validation limits into application queues
- only then decide whether queue sizes, batching policy, or scheduler priority need retuning

## Final signoff

Recommendation: yes, Zig should move closer to the js-libp2p async-validation model.

But the correct interpretation is:
- the existence of pending-validation state is not bot-slop by itself
- the current Zig split between `pending_validations` and later `mcache` insertion is the weaker part

The best target is:
- one retained-message store in `mcache`
- application-side completion bookkeeping kept separate
- better duplicate-propagator tracking
- better pending-validation observability

That would be a real structural improvement, not just a parameter tweak.
