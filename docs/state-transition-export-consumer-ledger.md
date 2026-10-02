# State-transition export and consumer migration ledger

This ledger records which `@lodestar/state-transition` exports are covered by the native state-view rollout and which remain TypeScript-owned. It is an integration map, not a promise to reimplement every TypeScript export in Zig.

The audit covers Lodestar `unstable` and Lodestar-z `main` as of 2026-10-02. A native implementation is counted only when the production path has a host adapter, a public binding declaration, an N-API registration, and a reachable caller or an explicit test contract.

## Migration status

| Area | Production entry points | Owner during native rollout | Status and evidence |
| --- | --- | --- | --- |
| State-view construction | `createBeaconStateView`, `createBeaconStateViewForHistoricalRegen` | Native adapter when `nativeStateView` is enabled; TypeScript otherwise | Open Lodestar [#9632](https://github.com/ChainSafe/lodestar/pull/9632) implements both factory paths from native SSZ bytes. Keep item 32 open until merged and validated on `unstable`. |
| State-view methods and getters | `IBeaconStateView*`, `NativeBeaconStateView` | Native binding plus TS adapter | #9632 covers the adapter boundary. The method-level declaration/registration audit remains a merge-validation step: every native method must exist in `bindings/src/index.d.ts` and be registered from `bindings/napi/root.zig`. |
| State transition and state-root production | `IBeaconStateView.stateTransition`, `computeNewStateRoot` | Native adapter for native state views | #9632 serializes full/blinded blocks for the native byte API and covers import, production, replay, and regeneration paths. |
| Electra queue values | `pendingDeposits`, `pendingPartialWithdrawals`, `pendingConsolidations` | Native bytes decoded by the TS adapter | #9632 decodes native SSZ bytes into Lodestar SSZ values. Do not expose the raw `Uint8Array` to beacon-node consumers. |
| Attestation and sync-committee rewards | `computeAttestationsRewards`, `computeSyncCommitteeRewards` | Native binding and adapter | Open Lodestar-z [#731](https://github.com/ChainSafe/lodestar-z/pull/731); not complete on `main`. |
| Transition external-data options | `TransitionOpts`, execution/DA status, `preMerge` | TS/native adapter contract | Open Lodestar-z [#701](https://github.com/ChainSafe/lodestar-z/pull/701). |
| Signature sets and signing roots | `signatureSets/*`, `computeSigningRoot`, `computeDomain` | TypeScript | These are pure helpers and are consumed directly by beacon-node and validator code. They do not become native merely because the state view is native. |
| Block and operation validation | voluntary-exit, proposer-slashing, attester-slashing, BLS-to-execution-change helpers | TypeScript | Production validation imports these helpers directly from the state-transition package. Keep them TS-owned unless a separate native API and caller contract is introduced. |
| Genesis and state initialization | genesis helpers, `createCachedBeaconState`, `loadCachedBeaconState`, state upgrade helpers | TypeScript | Startup and cache construction still use Lodestar's cached-state and config abstractions. Native factory setup is an adapter boundary, not a replacement of these helpers. |
| Shuffling and attestation utilities | shuffling, committee, participation, withdrawal helpers | TypeScript | Validator duties, beacon-node validation, block production, and pool code import these helpers directly. Preserve the existing exports. |
| Rewards and reporting helpers | reward calculation and proposer-reward reporting helpers | Mixed | Native state-view reward queries are tracked separately in item 36/#731. Existing pure reward utilities remain TypeScript-owned. |
| Weak subjectivity and light-client helpers | checkpoint/proof utilities and the `./light-client` subpath | Mixed | The current beacon-node consumer calls `postState.getFinalizedRootProof()` from `packages/beacon-node/src/chain/lightClient/index.ts`. Keep light-client-specific helpers in their existing subpath; do not infer a native blocker from an unused raw-state helper. |
| Gloas/Heze-only APIs | payload bids, PTC, builder payments, parent-payload methods | Explicitly gated | Native Gloas transition support is not available. Keep these APIs gated and track scheduled pre-Gloas builder-deposit work under items 43 and 47. |

## Consumer inventory

The production consumers that determine the migration boundary are under:

- `packages/beacon-node/src/chain`: state views, block import, regeneration, production, fork choice, light client, caches, and validation.
- `packages/beacon-node/src/api`: state, block, validator, and Lodestar API handlers.
- `packages/validator/src`: duties, proposer preparation, signing roots, and clock helpers.
- `packages/state-transition/src/index.ts`: the public barrel and its `light-client` subpath.

A public export is in scope for migration only when a production consumer reaches it. Test-only imports and unused barrel exports must be recorded as such instead of driving native API work.

## Package subpath scope

The Lodestar state-transition package exposes these subpaths. They are separate audit units even when they share the root package:

| Subpath | Role | Native migration status |
| --- | --- | --- |
| `@lodestar/state-transition` | Public barrel: state views, transition helpers, caches, rewards, signatures, constants, and utilities | Mixed; use the area rows above and the method-level checks below. |
| `@lodestar/state-transition/block` | Block-processing and validation helpers | TypeScript-owned production helpers unless a native API is explicitly added. |
| `@lodestar/state-transition/epoch` | Epoch-processing helpers and types | TypeScript-owned production helpers; native state-view calls are an adapter boundary. |
| `@lodestar/state-transition/slot` | Slot-processing helpers and types | TypeScript-owned production helpers; native state-view calls are an adapter boundary. |
| `@lodestar/state-transition/light-client` | Light-client spec and proof helpers | TypeScript-owned subpath; its current production consumer is recorded above. |
| `@lodestar/state-transition/test-utils` | Fixtures and test runners | Test-only; it is not a production replacement target. |

The Lodestar-z binding package has a separate surface: `.`, `./state-transition`, `./shuffle`, `./blst`, `./bls-verifier`, `./pubkeys`, and `./metrics`. #9632 consumes the state-transition binding and the native metrics path; the BLS, shuffle, pubkey, and verifier entry points remain standalone integrations and are not implied by state-view parity.

## Boundary checks for every native export

For each entry classified as native, review these layers together:

```text
state-transition public export
  -> NativeBeaconStateView or host adapter
  -> bindings/src/index.d.ts
  -> bindings/napi/root.zig registration
  -> Zig implementation
  -> production caller or integration test
```

A Zig `pub fn` without the binding declaration and registration is not a public native export. A TypeScript helper retained intentionally is not a migration failure.

## Completion criteria

Item 40 can close when:

1. Every production import from the state-transition public barrel or subpath has an owner recorded above.
2. Every native-owned entry has matching adapter, declaration, N-API registration, implementation, and caller evidence.
3. Native and TypeScript behavior is exercised through the package public entry points with the native toggle both disabled and enabled where supported.
4. Open dependencies are linked instead of being counted as complete: #9632 for item 32, #731 for rewards, #701 for transition options, and items 43/47 for rollout and Gloas boundaries.
5. No pure TypeScript helper is removed solely to make the native surface appear complete.
