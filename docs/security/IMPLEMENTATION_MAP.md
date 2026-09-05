# Lodestar-z security implementation map

This is the volatile companion to the stable [threat model](../../THREAT_MODEL.md). It records only
implementation facts needed to establish a trust boundary or precondition.

- **Owner:** `@ChainSafe/lodestar`
- **Last reviewed:** 2026-09-04

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
| N-API exports and shared addon lifecycle | [`build.zig`](../../build.zig) and [`bindings/napi/root.zig`](../../bindings/napi/root.zig) give zapi class exports a Zig package and addon-specific identity. The identity's version component comes from `build.zig.zon`, which intentionally remains `0.0.0` independently of the npm bindings version. The root module registers exports and initializes or tears down the process-wide BLS pool and pubkey cache on first or last environment. Each environment initializes and releases its own tree pool, default configuration snapshot, metrics, and epoch scratch cache. |
| Beacon-state construction | [`StateTransition`](../../bindings/napi/state_transition_context.zig) owns an immutable configuration snapshot and constructs states that retain it. The legacy `config.set` selects the snapshot for subsequent static construction without changing live state families. [`BeaconStateView.createFromBytes`](../../bindings/napi/BeaconStateView.zig) checks the slot byte range and supported fork, then SSZ-deserializes bytes without authenticating a root. Its contract therefore requires trusted state bytes. |
| State-transition candidate isolation | [`stateTransition`](../../src/state_transition/state_transition.zig) clones the cached state and destroys the clone on error before returning a post-state. Verification options are caller policy. |
| Serialized block boundary | [`BeaconStateView.stateTransition`](../../bindings/napi/BeaconStateView.zig) checks the signed-message offset and supported fork, then decodes full or blinded signed-block bytes and passes the decoded block to the transition. This is a hostile-input boundary for integrated callers. |
| BLS verifier validation | [`bls_verifier.zig`](../../bindings/napi/bls_verifier.zig) validates every signature for infinity and G2 membership before pairing. It also validates raw public keys for infinity and G1 membership. Indexed and aggregate sets trust cached affine keys. Direct append callers must supply a validated public key. State-transition appends follow successful deposit proof-of-possession checks. Bulk sync requires a trusted validator list. PKIX load requires trusted file provenance. |
| Pubkey cache | [`pubkey_cache.zig`](../../src/state_transition/cache/pubkey_cache.zig) defines an application-wide, append-only cache with locked access and no escaping pointers into movable storage. [`bindings/napi/pubkeys.zig`](../../bindings/napi/pubkeys.zig) owns its process-wide instance. |
| Persistent Merkle tree pool | [`Node.Pool`](../../src/persistent_merkle_tree/Node.zig) allocates a fixed number of user slots and returns `PoolExhausted` without resizing. Each N-API environment has a separate pool because node refcounts, free-list mutations, and hashing scratch are not synchronized. It reads `LODESTAR_Z_NODE_POOL_CAPACITY` during initialization, defaults to 10,000,000 slots per environment, and rejects invalid values. View-held pool references keep late finalizers safe after environment cleanup. Chunked-leaf and container payloads use a separate dynamic allocator. |
| Reused epoch cache | [`epoch_transition_cache.zig`](../../src/state_transition/cache/epoch_transition_cache.zig) stores thread-local arrays borrowed by an `EpochTransitionCache`. Synchronous transitions within one thread must not overlap. Separate N-API workers use independent arrays; each environment releases its scratch during cleanup. |
| State-transition metrics | [`metrics.zig`](../../src/state_transition/metrics.zig) keeps registries thread-local. Each N-API environment initializes and releases its own registry; historical workers select the `lodestar_historical_state_` prefix at initialization. |
| PKIX persistence | [`pkix.zig`](../../src/state_transition/cache/pkix.zig) checks framing, bounds, ABI compatibility, and corruption checksums. It does not authenticate the file or semantically revalidate affine entries, so file provenance remains trusted. |
| Build and release provenance | [`build.zig.zon`](../../build.zig.zon) and [`pnpm-lock.yaml`](../../pnpm-lock.yaml) pin dependency inputs. [`publish-bindings.yml`](../../.github/workflows/publish-bindings.yml) pins actions, builds ReleaseSafe artifacts, and publishes them with npm provenance. |

## Host integration contracts

These are Lodestar-ts preconditions supplied by maintainers. They are recorded here because they
change reachability and classification, but they are not enforced by this repository.

- Lodestar-ts owns initial checkpoint decoding and root authentication. Without a user-provided
  checkpoint root, trust is delegated to the checkpoint provider.
- Native state construction, slot processing, state loading, and block transition reject Gloas and later forks until supported.
- Configuration snapshots isolate state families, but the validator pubkey cache remains application-wide. The host must use one consistent validator-index mapping across environments and setup handles.
- Lodestar loads one version of `@chainsafe/lodestar-z` per Node.js process. Passing zapi class
  instances between different addon versions is unsupported.
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
