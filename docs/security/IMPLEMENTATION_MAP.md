# Lodestar-z security implementation map

This is the volatile companion to the stable [threat model](../../THREAT_MODEL.md). It records only
implementation facts needed to establish a trust boundary or precondition.

- **Owner:** `@ChainSafe/lodestar`
- **Last reviewed:** 2026-08-21

## Integration status

Production statuses reflect the maintainer-confirmed baseline. Branch networking changes are noted
separately.

| Surface | Lodestar-z status | Lodestar production status |
| --- | --- | --- |
| BLS and pubkey cache | Exported through N-API | Lodestar-ts still uses `@chainsafe/blst` and its TypeScript pubkey cache |
| State transition | Exported as `BeaconStateView.stateTransition` | Integration is in progress |
| Fork choice | Implemented in Zig but not exported through N-API | Lodestar-ts owns production fork choice |
| Networking and P2P validation | Native QUIC, discovery, req/resp and gossipsub exported through `./network` on this branch | The experimental native adapter is deployed on the Cayman Hoodi beacon node and consumes public peer traffic. Host validators and import orchestration remain responsible for consensus acceptance. This does not establish adoption in upstream Lodestar releases. |

A report against an unintegrated surface should be classified as security readiness unless another
supported caller supplies a current hostile path.

## Boundary map

| Boundary or invariant | Current implementation evidence |
| --- | --- |
| Native networking lifecycle | [`network.js`](../../bindings/src/network.js) wraps one native runtime per instance. `ready` resolves after preparation; application `applyIntent` activates it. The `closed` promise reports terminal owner shutdown, independently of lossy diagnostic observations. |
| Native network metrics | [`metrics.zig`](../../src/network/metrics.zig) collects bounded, pointer-free snapshots on the network owner, at most once per second. `getMetrics()` copies under the runtime mutex and formats outside it into at most 256 KiB. Client, method and topic labels use fixed vocabularies; fork labels use configured digests. Scraping does not consume events or mutate peer scores. Score evaluation shares policy arithmetic without changing its cache or decay. Latency histograms and transport byte counters use fixed storage; UDP accounting includes partial send successes and excludes truncated receive payloads. |
| Native identity snapshots | [`network_runtime.zig`](../../bindings/napi/network_runtime.zig) copies local metadata and the signed ENR on the owner thread into each identity result. Later intent updates cannot alter that result. |
| Native network logging | [`logging.zig`](../../src/network/logging.zig) hooks scoped `std.log` through a thread-local runtime sink, restored before runtime release. Each sink has an independent mutex and a fixed 128-record queue with 768-byte sanitized messages, severity reserves and per-scope/level rate limits. No logging callback enters JavaScript or retains network input pointers. [`network_logs.zig`](../../bindings/napi/network_logs.zig) validates level and batch size, copies at most 32 records and commits only after all N-API allocations succeed. Draining is confined to the owning JavaScript environment and remains available after close. Public peer and correlation identifiers are logged; payloads, private keys, JWTs and raw ENRs are excluded. Loss counters are included in metrics. |
| Native network dependencies and validation | [`build.zig.zon`](../../build.zig.zon) pins quiche-zig and Snappy. Native QUIC authentication, framing, req/resp decoding and gossip admission consume hostile network bytes. Host consensus validators still decide gossip acceptance. Local Lodestar integration bounds host serving and gossip retention across cancelled instances; uint64 peer Status fields require per-peer range checks before conversion to its number-based API. |
| Gossip score arithmetic | [`score.zig`](../../src/network/gossipsub/score.zig) bounds counters and caps at 1e6 and weights at 1e12, including configuration updates. Across 512 topics the resulting score remains below 1e40 in magnitude. Remote deliveries cannot increase counters beyond their caps. |
| N-API exports and shared addon lifecycle | [`build.zig`](../../build.zig) and [`bindings/napi/root.zig`](../../bindings/napi/root.zig) give zapi class exports a Zig package and addon-specific identity. The identity's version component comes from `build.zig.zon`, which intentionally remains `0.0.0` independently of the npm bindings version. The root module registers exports and initializes or tears down process-wide configuration, pools, metrics, and the pubkey cache on first or last environment. |
| Beacon-state construction | [`BeaconStateView.createFromBytes`](../../bindings/napi/BeaconStateView.zig) reads the slot and SSZ-deserializes bytes without authenticating a root. Its contract therefore requires trusted state bytes. |
| State-transition candidate isolation | [`stateTransition`](../../src/state_transition/state_transition.zig) clones the cached state and destroys the clone on error before returning a post-state. Verification options are caller policy. |
| Serialized block boundary | [`BeaconStateView.stateTransition`](../../bindings/napi/BeaconStateView.zig) accepts serialized signed-block bytes and passes the decoded block to the transition. This is a hostile-input boundary for integrated callers. |
| BLS verifier validation | [`bls_verifier.zig`](../../bindings/napi/bls_verifier.zig) validates every signature for infinity and G2 membership before pairing. It also validates raw public keys for infinity and G1 membership. Indexed and aggregate sets trust cached affine keys. Direct append callers must supply a validated public key. State-transition appends follow successful deposit proof-of-possession checks. Bulk sync requires a trusted validator list. PKIX load requires trusted file provenance. |
| Pubkey cache | [`pubkey_cache.zig`](../../src/state_transition/cache/pubkey_cache.zig) defines an application-wide, append-only cache with locked access and no escaping pointers into movable storage. [`bindings/napi/pubkeys.zig`](../../bindings/napi/pubkeys.zig) owns its process-wide instance. |
| Reused epoch cache | [`epoch_transition_cache.zig`](../../src/state_transition/cache/epoch_transition_cache.zig) stores process-global arrays borrowed by an `EpochTransitionCache`. The lock covers acquisition and resize, not the full borrowed lifetime. Current safe use requires non-overlapping transitions and no concurrent teardown. |
| PKIX persistence | [`pkix.zig`](../../src/state_transition/cache/pkix.zig) checks framing, bounds, ABI compatibility, and corruption checksums. It does not authenticate the file or semantically revalidate affine entries, so file provenance remains trusted. |
| Build and release provenance | [`build.zig.zon`](../../build.zig.zon) and [`pnpm-lock.yaml`](../../pnpm-lock.yaml) pin dependency inputs. [`publish-bindings.yml`](../../.github/workflows/publish-bindings.yml) pins actions, builds ReleaseSafe artifacts, and publishes them with npm provenance. |

## Host integration contracts

These are Lodestar-ts preconditions supplied by maintainers. They are recorded here because they
change reachability and classification, but they are not enforced by this repository.

- Lodestar-ts owns initial checkpoint decoding and root authentication. Without a user-provided
  checkpoint root, trust is delegated to the checkpoint provider.
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
