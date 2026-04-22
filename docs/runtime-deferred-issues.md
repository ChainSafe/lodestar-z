# Runtime Deferred Issues

Operational issues discovered during live Hoodi sync work that should stay
visible, but are not the immediate implementation target.

**Date:** 2026-04-15
**Status:** Deferred

## 1. Queued Range-Sync Pre-State Clone OOM

### Evidence

Live logs on `nogroup-rs2000-0` showed repeated queue-stage failures:

```text
Apr 16 02:15:07 ... [warn ] [pipeline] failed to clone queued pre-state parent_slot=2840929 block_slot=2840930: error.OutOfMemory
Apr 16 02:15:07 ... [warn ] [node] failed to start pending sync segment block chain_id=0 batch_id=0 generation=2 index=2: error.InternalError
```

The same pattern repeated for both `head` and `finalized` range-sync segments.

### Current understanding

- The failure is not `QueuedStateRegen` queue saturation.
- It happens in queued state-work capture, when `captureStateTransitionJob()`
  clones the `CachedBeaconState` for background execution.
- The concrete failing path is [pipeline.zig](/home/cayman/Code/lodestar-z-beacon-node-3/src/chain/blocks/pipeline.zig)
  inside `captureStateTransitionJob()`.

### Why this is deferred

- Falling back to synchronous import from this path was rejected as not
  production-real enough without Lodestar-TS-aligned justification.
- The correct fix likely requires reducing clone pressure or restructuring
  queued state-work ownership, not masking OOM with an ad hoc fallback.

## 2. Shutdown Segfault in `CachedBeaconState.deinit`

### Evidence

During a service restart on `nogroup-rs2000-0`, shutdown crashed before systemd
restarted the process:

```text
Apr 16 02:11:11 ... Segmentation fault at address 0x7f9e1c868518
/src/state_transition/cache/state_cache.zig:110:32: in deinit
/src/chain/regen/state_disposer.zig:7:17: in destroyCachedBeaconState
/src/chain/regen/block_state_cache.zig:201:36: in disposeState
```

A later restart captured a more precise teardown failure in the same path:

```text
Apr 16 04:36:58 ... thread 4188300 panic: integer overflow
/src/state_transition/utils/reference_count.zig:44:29: in release
/src/state_transition/cache/epoch_cache.zig:451:40: in deinit
/src/state_transition/cache/state_cache.zig:110:32: in deinit
/src/chain/regen/state_disposer.zig:7:17: in destroyCachedBeaconState
/src/chain/regen/block_state_cache.zig:201:36: in disposeState
```

### Current understanding

- The crash happened during teardown, not steady-state sync.
- The top frame is [state_cache.zig](/home/cayman/Code/lodestar-z-beacon-node-3/src/state_transition/cache/state_cache.zig#L110),
  reached via block-state-cache disposal.
- The later overflow shows the failure is specifically tied to reference-count
  release during cache teardown, not just an opaque segfault.
- This still points to a state ownership / double-free / invalid-lifetime bug
  in cache disposal, not a networking issue.

### Why this is deferred

- It does not explain the immediate live failure to reach stable gossip-based
  block and data-column import.
- It still needs a proper ownership audit before more operational restarts.

## 3. Shutdown Abort During Restart

### Evidence

Another restart on `nogroup-rs2000-0` ended the previous main process with an
abort instead of a clean stop:

```text
Apr 16 04:19:11 ... systemd[1]: beacon.service: Main process exited, code=dumped, status=6/ABRT
Apr 16 04:19:11 ... systemd[1]: beacon.service: Failed with result 'core-dump'.
```

`coredumpctl` is not installed on the host, so the systemd/journal record is
currently the only retained evidence from that crash.

### Current understanding

- This abort is no longer an isolated unknown crash: a later restart tied the
  abort to `reference_count.release()` flowing into
  `state_cache.zig:deinit()`.
- The failure occurred while stopping PID `4182166`, after extended live sync
  activity and before the replacement process was started.
- The exact abort site for the earlier PID is still unknown, but the restart
  path now has a reproducible teardown signature.

### Why this is deferred

- The active implementation target is still head/range/unknown-block sync
  correctness rather than shutdown-path hardening.
- The abort should be revisited together with the existing teardown segfaults,
  since both point to restart-time ownership or lifecycle bugs.

## Immediate priority

The active goal remains production-real alignment with Lodestar TS so the node
can sustain:

1. stable peering
2. range sync that advances the head
3. unknown-block sync
4. gossip block and data-column import
