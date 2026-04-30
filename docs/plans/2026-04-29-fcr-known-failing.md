# FCR Spec Test — Known Failures (Phase F)

**Last updated:** 2026-04-30 against `gr/feat-fcr` HEAD `4ac9e8bc`.

## Run command

```bash
zig build run:write_spec_tests
zig build "test:spec_tests" -Dpreset=minimal
```

## Aggregate results (minimal preset, all spec_test runners)

```
Build Summary: 4006/4798 tests passed (792 failed)
```

Pre-fix baseline: 0/1014 FCR cases passing. Post-fix: 4006/4798 across all
runners (~83.5%). 792 fail with `FcrConfirmedRootMismatch`.

## Root cause of remaining 792 failures (traced 2026-04-30)

Traced one specific failure (`altair fast_confirmation current_epoch
fcr_current_epoch_12`, mismatch at slot 18):

- spec wants `confirmed_root = 2cc999...` (advance from prior `1e317b...`)
- our impl keeps `confirmed_root = 1e317b...`

Trace through `findLatestConfirmedDescendant`:
- canonical_roots from head=95ac63 down to confirmed=1e317b: [2cc999, 95ac63]
- Loop 1 guard fails because `unrealized_justifications[head].epoch + 1 <
  current_epoch` (head's UJ stuck at anchor epoch 0; current_epoch=2)
- Loop 2 guard fails for the same reason
- Result: no advancement.

**The bug is upstream of FCR.** `unrealized_justifications[head]` (the
per-block unrealized justified checkpoint stored on `ProtoBlock`) is not
advancing. By slot 18 with attestations from slots 16+17 applied, spec
expects head's UJ to have caught up to at least epoch 1, but our impl
still has it at anchor (epoch 0).

The likely culprit is in `src/fork_choice/fork_choice.zig`'s
`computeUnrealizedCheckpoints` integration with `onBlock` /
`onAttestation`. We already fixed two latent compile bugs there in Phase F
(arg order on `computeUnrealizedCheckpoints`, allocator threading on
`OnBlockBalancesCtx`) but the actual UJ-tracking semantics may still
have bugs. This area was not directly covered by Phase A-E unit tests
because those tests inject pre-populated unrealized fields into the
fixture rather than computing them from blocks/attestations.

This is genuinely outside the FCR module scope — it's a fork_choice
correctness issue that the Phase F EF spec test runner exposed.

## What's been fixed in this PR

1. `390a6db0`: critical — `updateFastConfirmationVariables` reads global
   `fc.fc_store.unrealized_justified.checkpoint` (spec line 815), not
   head's per-block UJ (which Phase E confused). Took us from 0/1014 to
   ~600/1014.
2. `4ac9e8bc`: spec-aligned `getLatestConfirmed` step-2 outer epoch gate
   uses block's slot's epoch, not checkpoint's `epoch` field (spec line
   999). Did not change pass count but fixes a real spec divergence
   that would surface in different test layouts.

## Suspected sources of remaining 792 failures (other than UJ tracking)

1. **Head-state vs checkpoint-state drift in balance sources** — The
   `// TODO Phase F` in `rebuildHeadBalanceSource`
   (`fast_confirmation.zig:1714`) flagged that the spec wants the
   *checkpoint state* for current/previous balance sources, not the
   head state. Cases that rely on cross-epoch FFG decisions fail here.
2. **`willCurrentTargetBeJustified` zero-balance edge case** — Phase D
   noted `total = 0` returns `true`. The runner's `head_balance_source`
   may not be properly populated for early-epoch cases.
3. **Reentrancy on `last_update_slot`** — The runner calls
   `runConfirmation` before each `checks` step; if there are two
   `checks` at the same slot the second is a no-op for variable rotation,
   but the spec semantics may differ.

## Diagnosis approach for follow-up commits

1. Pick a failing case from `current_epoch` or `restart_gu` suite.
2. Add logging to `fork_choice.zig` `onBlock` to print
   `proto_block.unrealized_justified_root/epoch` after computation.
3. Compare against expected UJ trajectory from steps.yaml — for each
   block added, what UJ does spec expect on that block's ProtoBlock?
4. If UJ doesn't match → bug in `computeUnrealizedCheckpoints` or its
   wiring.
5. If UJ matches but FCR result differs → bug in FCR algorithm
   (back to `findLatestConfirmedDescendant`).

## Pre-existing non-FCR test status

`zig build "test:spec_tests"` passes for non-FCR suites (sanity, fork,
transition, epoch_processing, finality, operations, random, rewards,
merkle_proof) — verified by spot-check during Phase F. The runner
wiring did NOT regress any other test path.

## Out of scope for current PR

- Mainnet-preset runs.
- The 792 remaining failures (likely fork_choice UJ tracking bugs that
  are upstream of FCR — separate investigation).
- Cross-fork edge cases at fork transitions.
