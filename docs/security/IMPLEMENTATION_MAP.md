# Lodestar-z security implementation map

This document maps the stable [threat model](../../THREAT_MODEL.md) to the current implementation.
It is an audit aid, not a normative security contract. Implementation details may change without
changing the threat model.

- **Owner:** `@ChainSafe/lodestar`
- **Last reviewed:** 2026-08-14
- **Review baseline:** PR #557

Update this map when a change adds or alters a trust boundary, native dependency, persistence path
or format, shared mutable cache or pool, externally influenced native input, or supported
integration. Update the threat model only when the security contract or finding classification also
changes.

## Integration maturity

| Component | Current status | Review treatment |
| --- | --- | --- |
| BLS bindings | Implemented and exported by the addon; not wired into Lodestar-ts production | Direct library surface and planned-integration security readiness |
| Process-wide pubkey cache | Implemented and exported by the addon; not wired into Lodestar-ts production | Direct library surface and planned-integration security readiness |
| State transition | Next integration stage | Consensus correctness and security readiness; planned input is a trusted pre-state plus a serialized hostile signed block |
| Zig fork choice | Future integration stage | Parity and security readiness; planned inputs are STF-valid blocks and validated attestations |
| Generic P2P deserialization | Planned as integrations expand | Hostile-input boundary only where a current or identified planned path exists |
| Beacon-state and ERA loading | Library surface using trusted input | Reliability and hardening unless another attacker path is demonstrated |

Lodestar-ts production currently uses `@chainsafe/blst` and its TypeScript pubkey cache rather than
these addon surfaces.

A planned-component bug can block integration without being described as a currently exploitable
Lodestar vulnerability.

## Component map

| Area | Current security concern | Inherited contract |
| --- | --- | --- |
| `src/ssz`, `src/persistent_merkle_tree`, `src/hashing` | Canonical decoding, offsets, generalized indexes, ownership, proof correctness, and bounded merkleization | Serialized bytes may be hostile; typed callers obey lifetime contracts |
| `src/consensus_types`, `src/fork_types`, `src/config`, `src/preset` | Fork schema, preset values, dispatch, and safe cross-fork access | Configuration identifies the intended network |
| `src/state_transition` | Spec equivalence, signature checks, candidate isolation, cache consistency, and bounded per-block work | Eligible trusted pre-state and accurate external statuses |
| `src/bls` | Point validation, aggregation cardinality, randomness, thread-pool cleanup, and false acceptance | Validation flags and proof-of-possession requirements are caller policy |
| `src/fork_choice` | Head correctness, invalidation, votes, finalized ancestry, equivocation, queues, and arithmetic | STF-valid blocks, validated attestations, and trusted time |
| `src/beacon_node`, `src/clock` | Cache ownership, event ordering, time calculations, and integration invariants | Production reachability must be established |
| `src/era` | Framing, offsets, decompression, allocation bounds, and optional semantic validation | ERA provenance is trusted |
| `bindings/napi`, `bindings/src` | Runtime checks, native lifetime, worker isolation, errors, and JS/native agreement | Same-process caller owns policy and has ambient process privileges |
| `scripts`, `test`, `bench`, `examples` | Developer, CI, generation, or supply-chain impact | No runtime peer-facing path without additional evidence |

## Current boundary mappings

### JavaScript and N-API

Native exports are registered from `bindings/napi/root.zig`; public wrappers and declarations live
in `bindings/src`.

All JavaScript-controlled types, lengths, indexes, encodings, object shapes, and buffer ranges need
runtime checks before native memory access. TypeScript declarations do not provide those checks.
Assertions are acceptable for internal invariants only after hostile lengths and offsets have been
validated.

Explicit local APIs remain caller-controlled policy. For example, allowing the caller of a cache
save API to choose its output path is not independently path traversal.

### Beacon-state loading

`BeaconStateView.createFromBytes` and ERA state loading currently accept state bytes under the
trusted-state contract. SSZ deserialization checks structure but does not authenticate provenance.

Lodestar-ts currently owns raw checkpoint decoding and authentication. `initBeaconState` downloads
or loads checkpoint bytes and `readWSState` decodes them. When the user supplies a weak-subjectivity
checkpoint, `ensureWithinWeakSubjectivityPeriod` compares both the checkpoint root and epoch after
decoding. Without a supplied checkpoint, trust in checkpoint selection is delegated to the source.

If Lodestar-z becomes the first decoder of raw checkpoint responses, its slot extraction and state
decoding must become checked hostile-input parsing before root comparison.

### Live P2P block processing

Lodestar-ts currently owns networking, framing, decompression limits, peer scoring, and import
orchestration.

- Gossip blocks receive the consensus-spec gossip validation applicable to that object.
- Forward range sync and unknown-parent recovery establish ancestry through the parent-root hash
  chain. Unknown-parent recovery fetches ancestors until reaching a block already known to fork
  choice, then processes descendants forward.
- Hash-chain membership does not establish consensus validity. Full STF is required before a block
  enters the live chain or fork choice or establishes a trusted post-state.
- Proposer and operation signatures are checked by STF or batch-verified beforehand. Prior batch
  results must join the same all-or-none import result.
- Serialized P2P objects are expected to cross the binding as integrations expand.

The Lodestar-ts import path may run STF, signature checks, execution verification, and DA
verification concurrently. STF may receive a provisional available DA status, but the real DA
result or satisfied sync policy joins before publication.

### Historical archive backfill

Archive backfill is distinct from unknown-parent recovery. It verifies reverse hash-chain continuity
and proposer signatures, then writes blocks directly to `blockArchive` without full STF. These blocks
do not enter the live chain or fork choice and do not establish trusted post-states. Any later use in
a live consensus path must first satisfy the full acceptance contract.

### Execution, DA, and fork choice

Lodestar-z does not contact the execution layer or DA subsystem. The host supplies their results.
The execution layer is assumed nonmalicious but may be fallible or syncing.

Each block carries its execution status. A `syncing` status remains conditionally valid until the
execution layer returns `valid` or `invalid`; latest-valid-hash processing propagates invalidity
through the affected branch. Lodestar-ts currently prevents validator duties while execution
optimistic.

Inside the DA window, availability is joined before acceptance. A super-node that custodies every
column may treat DA as satisfied after enough columns are observed to reconstruct the remainder.
Outside the window during sync, DA is treated as satisfied.

The production fork-choice implementation remains in Lodestar-ts. The Zig implementation is
intended to replace it and must preserve:

- full-STF prerequisites for blocks;
- applicable gossip and indexed-attestation prerequisites;
- known-parent, time, finalized-ancestry, and target checks;
- execution-status and latest-valid-hash propagation;
- vote, equivocation, and internal-bound behavior.

Gloas payload resolution (`EMPTY` versus `FULL`) is distinct from execution validity
(`valid`, `syncing`, or `invalid`). The current Zig `ExecutionStatus.payload_separated` model
should be reviewed before fork-choice integration rather than treated as a threat-model trust state.

### Shared configuration, pools, and caches

The addon currently shares configuration, metrics, the BLS worker pool, persistent Merkle node pool,
pubkey cache, and reused epoch-transition cache across Node.js environments.

- Worker and environment teardown must not destroy state still in use elsewhere.
- Movable pubkey-cache storage is locked, and borrowed references must not survive a resize.
- PKIX save, load, and reset are restricted to the control environment.
- Configuration is startup state and must not be replaced while borrowed.
- Explicit capacity APIs reject overflow and impossible capacities. Large valid reservations remain
  local caller policy unless a remote path controls them.

State-transition clones share the process-wide pubkey cache. Candidate processing can append a
future validator pubkey before later operations or state-root verification fail; that append is not
rolled back. Safety depends on the stable branch-independent cache invariant:

- an index at or beyond the current state's validator count is treated as absent;
- later valid processing must reproduce the same pubkey at that index; and
- conflicting, duplicate, or sparse appends fail.

Former Eth1 bridge deposits can register validators and append during block processing. In Electra,
the new validator initially has zero balance while its amount remains pending. Execution-layer
deposit requests remain pending and register a new validator only after their source slot is
finalized.

Apart from the process-wide pubkey and reused epoch-transition caches, state-transition caches are
generally epoch-scoped and candidate-specific. A failed STF may leave metrics, completed signature
computations, and a permitted pubkey-cache append, but no other candidate-derived mutation that
influences later validity.

The reused epoch-transition cache in `epoch_transition_cache.zig` is process-global and survives
until explicit deinitialization. Its lock covers lookup and resize, but `EpochTransitionCache.init`
mutates the shared arrays after that lock is released, and returned candidate caches borrow those
arrays. Correctness therefore currently requires non-overlapping epoch-transition cache use and no
concurrent teardown across environments. Concurrent integrations must serialize the full borrowed
lifetime or replace this sharing model.

## Persistence paths

### PKIX

PKIX is a cache snapshot, not a trust anchor. Its loader currently checks framing, exact size, format
version, ABI compatibility, caller-supplied capacity, and corruption checksums. The checksum is not
authentication, and affine entries are not semantically revalidated on load.

A report needs one of these paths to cross the trusted-file assumption:

- a supported remote workflow can replace or select the file;
- the loader violates its documented size, framing, ABI, checksum, ownership, or cleanup contract;
  or
- a failed or concurrent load corrupts the previously live cache.

### ERA and E2S

ERA/E2S data is trusted local input. Sizes, counts, arithmetic, offsets, decompression, and SSZ
decoding are still checked for bounded reliability. `Reader.validate` additionally checks network
and block/state consistency; lower-level reads rely on provenance.

Download scripts, test generation, benchmarks, and fuzz harnesses are development surfaces unless a
build, CI, workstation, or release path is shown.

## Current controls to verify

Reviewers should test these controls rather than assume they are complete:

- consensus, SSZ, and BLS vectors pinned through `build.zig.zon`;
- minimal and mainnet preset tests plus SSZ and BLS fuzz targets;
- full STF, signatures, and state-root verification before live-chain or fork-choice admission;
- copy-on-write candidate state and cleanup on rejection;
- gossip validation or sync hash-chain validation before forward STF;
- genesis or checkpoint-root trust bootstrapping;
- protocol bounds and checked arithmetic in parsers;
- pubkey-cache locking, state-length guards, staged PKIX installation, and capacity limits;
- reference-counted pools and last-environment cleanup;
- ReleaseSafe native artifacts; and
- pinned workflows and dependencies, lockfile installation, npm trusted publishing, and provenance.

## Open integration questions

- Which N-API methods are stable public APIs versus Lodestar compatibility surfaces?
- Which serialized P2P objects will cross the binding as STF and fork choice integrate?
- Which layer will compare a downloaded state root with a user-provided checkpoint root?
- Which errors will distinguish invalid peer data, consensus failure, external invalidity, and
  internal failure for scoring and operations?
- Which production limits apply to proof descriptors, aggregate lists, pool preheating, and pubkey
  cache growth?
- Is configuration guaranteed to be set once before workers and state views exist?
- How will reused epoch-transition cache use and teardown be serialized across environments?
- How are PKIX files provisioned and invalidated across network or binary upgrades?
- Is the exported `SecretKey` intended for production validator keys or compatibility and testing?
