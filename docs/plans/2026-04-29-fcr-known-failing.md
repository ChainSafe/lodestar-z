# FCR Spec Test — Known Failures (Phase F)

Generated 2026-04-29 against `gr/feat-fcr` HEAD `1d2d2740` (Phase E) plus
runner wiring.

## Run command

```bash
zig build run:write_spec_tests
zig build "test:spec_tests" -Dpreset=minimal -Dspec_tests.filters="fast_confirmation"
```

## Aggregate results (minimal preset, all 6 forks)

| Fork      | Total | Pass | Fail |
|-----------|-------|------|------|
| altair    | 169   | 0    | 169  |
| bellatrix | 169   | 0    | 169  |
| capella   | 169   | 0    | 169  |
| deneb     | 169   | 0    | 169  |
| electra   | 169   | 0    | 169  |
| fulu      | 169   | 0    | 169  |
| **total** | 1014  | 0    | 1014 |

## Failure categories

| Error                                  | Count |
|----------------------------------------|-------|
| `error.FcrPrevUnrealizedRootMismatch`  | 1002  |
| `error.HeadRootMismatch`               |   12  |

## Top diagnosis

### 1. `previous_epoch_greatest_unrealized_checkpoint` zeroed at epoch boundary
   (1002/1014)

`updateFastConfirmationVariables` at `src/fork_choice/fast_confirmation/fast_confirmation.zig:1397`
unconditionally writes the head's `unrealized_justified_checkpoint` into
`previous_epoch_greatest_unrealized_checkpoint` whenever `current_slot+1` is
the start of an epoch. For the early test cases, the head is the anchor /
genesis block and its proto-array node carries `unrealized_justified_root =
ZERO_HASH`, so the FCR field gets stomped to zero. The spec implies a
"greatest" semantic — it should keep the maximum across the epoch and not
regress to zero. Likely fix: only overwrite when the new checkpoint has a
strictly higher epoch than the current value, or fall back to
`finalized_checkpoint` when the head's unrealized is zero.

This is a real Phase E bug that does not surface in the unit tests because
they construct the linear fixture with the genesis block's unrealized fields
already set to non-zero values (see `initLinearForkChoice` in
`fast_confirmation.zig:2001`).

Fix: follow-up commit on `gr/feat-fcr`.

### 2. `head_root` mismatch — 12 cases

Concentrated in cases that ingest reorg-prone block sequences before FCR
state has been updated. Likely a downstream consequence of (1) — once
confirmed_root drifts, subsequent reorg checks in `getLatestConfirmed` walk
the wrong branch.

Fix: re-evaluate after (1) is patched.

## Pre-existing fork_choice.zig fixes (in this commit)

The runner triggered two latent compile errors in `src/fork_choice/fork_choice.zig`
that no existing unit test exercised:

1. `computeUnrealizedCheckpoints(state, allocator)` — the call passed the
   wrong number of args. Patched to pass `(allocator, std.testing.io, state)`
   matching the helper's actual signature.
2. `EffectiveBalanceIncrementsRc.init(balances.allocator, balances)` —
   `std.ArrayListUnmanaged(u16)` has no `.allocator` field in Zig 0.16. Added
   an explicit `allocator` field to `OnBlockBalancesCtx` and threaded it
   through the three call sites.

Both fixes are minimal and additive; they do not alter existing FCR /
fork-choice semantics.

## Out of scope for Phase F

- Mainnet-preset runs (`-Dpreset=mainnet`) — same runner, larger states.
- `revert_finality` suite cases that re-finalize previously orphaned chains.
- Resolving `FcrPrevUnrealizedRootMismatch` in the FCR algorithm.
- Cross-fork edge cases at fork transitions.
