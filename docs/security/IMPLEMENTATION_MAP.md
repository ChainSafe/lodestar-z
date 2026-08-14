# Lodestar-z security implementation map

This is the volatile companion to the stable [threat model](../../THREAT_MODEL.md). It records only
implementation facts needed to establish a trust boundary or precondition.

- **Owner:** `@ChainSafe/lodestar`
- **Last reviewed:** 2026-08-14

## Integration status

The following status is maintainer-confirmed as of the review date:

| Surface | Lodestar-z status | Lodestar production status |
| --- | --- | --- |
| BLS and pubkey cache | Exported through N-API | Lodestar-ts still uses `@chainsafe/blst` and its TypeScript pubkey cache |
| State transition | Exported as `BeaconStateView.stateTransition` | Integration is in progress |
| Fork choice | Implemented in Zig but not exported through N-API | Lodestar-ts owns production fork choice |
| Networking and P2P validation | Not implemented here | Lodestar-ts owns gossip, req/resp, framing, peer scoring, and import orchestration |

A report against an unintegrated surface should be classified as security readiness unless another
supported caller supplies a current hostile path.

## Boundary map

| Boundary or invariant | Current implementation evidence |
| --- | --- |
| N-API exports and shared addon lifecycle | [`bindings/napi/root.zig`](../../bindings/napi/root.zig) registers exports and initializes or tears down process-wide configuration, pools, metrics, and the pubkey cache on first or last environment. |
| Beacon-state construction | [`BeaconStateView.createFromBytes`](../../bindings/napi/BeaconStateView.zig) reads the slot and SSZ-deserializes bytes without authenticating a root. Its contract therefore requires trusted state bytes. |
| State-transition candidate isolation | [`stateTransition`](../../src/state_transition/state_transition.zig) clones the cached state and destroys the clone on error before returning a post-state. Verification options are caller policy. |
| Serialized block boundary | [`BeaconStateView.stateTransition`](../../bindings/napi/BeaconStateView.zig) accepts serialized signed-block bytes and passes the decoded block to the transition. This is a hostile-input boundary for integrated callers. |
| Pubkey cache | [`pubkey_cache.zig`](../../src/state_transition/cache/pubkey_cache.zig) defines an application-wide, append-only cache with locked access and no escaping pointers into movable storage. [`bindings/napi/pubkeys.zig`](../../bindings/napi/pubkeys.zig) owns its process-wide instance. |
| Reused epoch cache | [`epoch_transition_cache.zig`](../../src/state_transition/cache/epoch_transition_cache.zig) stores process-global arrays borrowed by an `EpochTransitionCache`. The lock covers acquisition and resize, not the full borrowed lifetime. Current safe use requires non-overlapping transitions and no concurrent teardown. |
| PKIX persistence | [`pkix.zig`](../../src/state_transition/cache/pkix.zig) checks framing, bounds, ABI compatibility, and corruption checksums. It does not authenticate the file or semantically revalidate affine entries, so file provenance remains trusted. |

## Host integration contracts

These are Lodestar-ts preconditions supplied by maintainers. They are recorded here because they
change reachability and classification, but they are not enforced by this repository.

- Lodestar-ts owns initial checkpoint decoding and root authentication. Without a user-provided
  checkpoint root, trust is delegated to the checkpoint provider.
- Gossip objects receive their specification-defined validation. Range sync and unknown-parent
  recovery instead establish a parent-root hash chain before processing blocks forward.
- A full state transition is required before a block enters the live chain or fork choice. Archive
  backfill is separate and may persist hash-chain and signature-checked blocks without establishing
  trusted state.
- Signature, transition, execution, and data-availability work may run concurrently, but required
  results join before live-chain and fork-choice admission.
- Execution `syncing` is conditionally valid. Lodestar suppresses validator duties while optimistic,
  and a later invalid result removes the affected fork-choice branch.
- Data availability is required inside its validation window and treated as satisfied outside it.

If code or a supported integration conflicts with any item above, use the code to assess the finding
and update this map.
