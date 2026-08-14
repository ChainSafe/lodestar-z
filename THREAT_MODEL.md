# Lodestar-z threat model

This document is the stable security contract for Lodestar-z. It defines the assets, actors, trust
boundaries, invariants, and classification rules that determine whether a finding is a security
issue, security-readiness issue, correctness bug, or hardening opportunity.

Current integration status, call paths, cache mechanics, file references, and implemented controls
belong in the [security implementation map](docs/security/IMPLEMENTATION_MAP.md). Those details may
change without changing this contract.

This model applies to the `main` branch. Review consensus claims against the specification version
pinned in `build.zig.zon`, the active fork, and the active preset.

## Scope

Lodestar-z is a Zig library and Node.js native addon used by Lodestar. It is not itself a network
service, P2P stack, execution client, key manager, or slashing-protection database.

Security classification depends on the least-privileged attacker, the supported or identified
planned path to the affected code, the trusted preconditions on that path, and the resulting impact.
A bug in a planned integration may be release-blocking security-readiness work without being a
currently exploitable Lodestar vulnerability. Direct downstream users must establish their own
reachable boundaries.

## Assets

The protected assets are:

- Ethereum consensus safety and liveness;
- beacon-state, state-root, validator-accounting, fork-choice, and head correctness;
- BLS verification and aggregation correctness;
- availability, integrity, and confidentiality of the hosting Node.js process, including unrelated
  validator material, JWTs, API credentials, and other resident secrets;
- integrity of shared native pools, caches, configuration, and worker state;
- confidentiality of BLS secret-key material intentionally passed to the library; and
- integrity of source dependencies, npm packages, and native release artifacts.

The library does not claim to provide an HSM, hardened secret memory, a JavaScript sandbox, or
protection from arbitrary code that already has the Node.js process's privileges.

## Security objectives

1. **Consensus correctness.** Given the correct preset and configuration, an eligible trusted
   pre-state, all required validation, and accurate execution and data-availability results, state
   transition and fork choice agree with the pinned consensus specification.
2. **Cryptographic correctness.** BLS operations do not accept invalid signatures or points when
   the API contract requests the relevant checks. Batch operations preserve cardinality and use
   unpredictable nonzero coefficients where required.
3. **Memory safety.** Malformed externally influenced values do not cause out-of-bounds access,
   use-after-free, double free, uninitialized-memory use, allocator mismatch, or native-memory
   disclosure.
4. **Process availability.** Attacker-controlled inputs and bounded sequences fail safely. They do
   not cause panics, deadlocks, infinite loops, cumulative leaks, or unbounded queue or cache growth.
   CPU and memory amplification remain within explicit protocol, transport, and application bounds.
5. **State integrity.** Rejected candidates do not modify their trusted pre-state, publish
   branch-specific derived state, enter fork choice, or corrupt shared state.
6. **Lifecycle safety.** Supported workers, concurrent operations, environment teardown, and
   finalization do not race or access freed shared state.
7. **Artifact integrity.** Published native artifacts are built from reviewed source and pinned
   dependencies through the repository release process.

## Actors and trusted inputs

| Actor or source | Capability and trust |
| --- | --- |
| Remote consensus participant | Controls protocol-shaped and malformed P2P objects. It does not directly control native options, configuration, local files, or capacity APIs without a demonstrated Lodestar path. |
| Remote API user | Controls only values forwarded by Lodestar's API layer after its validation and limits. Reports must trace that path. |
| Operator and host application | Trusted to choose the preset, configuration, initial state, local files, verification policy, external statuses, capacities, and wall-clock time. Accidental misuse should fail clearly, but a malicious operator is out of scope. |
| Same-process JavaScript | Has ambient application privileges and may intentionally provide malformed or coercing values. It is not an authorization or OS-isolation boundary, but it does not thereby possess arbitrary native-memory or cross-worker access. |
| Same-process Zig code | Executes native code with process privileges and can construct or dereference arbitrary pointers. It is trusted to honor Zig API preconditions and is not a native-memory isolation boundary. |
| Checkpoint state provider | Semitrusted. A user-provided checkpoint root is authoritative; without one, checkpoint selection is explicitly delegated to the provider. |
| Trusted local storage | Database state, ERA/E2S data, and PKIX files are application-owned. This model assumes bytes written are the bytes later read. Malicious local replacement and host compromise are out of scope. |
| Contributor or supply-chain attacker | May attempt to introduce malicious source, workflow, dependency, or release changes. |

Raw checkpoint bytes are hostile to whichever component first decodes them before authentication.
Lodestar-z state-loading entry points are defined to accept trusted state bytes. If a supported
integration assigns initial checkpoint decoding to Lodestar-z, that entry point becomes a
hostile-input boundary.

## Trust boundaries

| Boundary | Lodestar-z contract |
| --- | --- |
| Remote source to Lodestar-z | Remotely derived bytes remain hostile unless the exact required validation has already completed and is bound to the operation's result. |
| JavaScript to N-API | Runtime types, lengths, indexes, encodings, arrays, object shapes, and buffer ranges must be validated before unsafe native access. Caller-selected policy remains trusted. |
| Serialized input to SSZ | Decoding enforces canonical encoding, offsets, list limits, bitfields, arithmetic bounds, and safe ownership. |
| Beacon-state construction | Input state bytes already have trusted provenance. SSZ decoding establishes structure only, not ancestry, canonicality, finality, or consensus validity. |
| State transition | The pre-state is an eligible trusted pre-state; the signed candidate block is hostile. Required consensus checks and state-root verification must complete before publication. |
| Fork choice | Blocks have passed full state transition, attestations have passed the applicable upstream validation, external statuses are accurate, and local time is trusted. Fork choice still owns its specified ancestry, timing, vote, status-propagation, and bound checks. |
| BLS API | Serialized points, messages, collections, and cardinality may be hostile. Caller-controlled validation flags and proof-of-possession preconditions are explicit policy. |
| Zig to native dependencies | Lodestar-z owns representation, initialization, cardinality, pointer lifetime, requested validation, and ABI compatibility. Pinned dependencies are trusted to honor documented contracts. |
| Shared native state | Synchronization, ownership, worker visibility, and teardown order must be defined. |
| Local persistence | Provenance is trusted. Parsers still enforce documented framing, size, format, checksum, ownership, and cleanup contracts for reliability and memory safety. |
| Build and release | Maintainer review, pinned inputs, protected repository settings, and release credentials establish artifact trust. |

A `std.debug.assert` is not a parser guard for externally influenced data in ReleaseSafe. TypeScript
declarations are not runtime validation.

## Consensus trust invariants

### Beacon-state provenance and eligibility

A beacon state is not an arbitrary network object. Trusted provenance originates from:

- genesis, treated as the checkpoint at epoch zero;
- a state whose hash-tree-root matches a user-provided checkpoint root; or
- explicit delegation of checkpoint selection to a checkpoint state provider.

A state read from trusted storage retains the provenance and validity status it had when written.
Subsequent states inherit authenticated provenance through successful consensus-layer state
transitions.

An **authenticated beacon state** is structurally valid SSZ and is either a trusted anchor or the
result of a successful consensus-layer transition from an eligible trusted pre-state. It carries the
execution and DA status applicable when it was accepted.

An **eligible trusted pre-state** is an authenticated beacon state whose branch remains eligible
for fork choice under its current execution and DA status. Eligibility is a current-use property,
not part of historical provenance.

| Property | Authenticated beacon state |
| --- | --- |
| Structural SSZ validity | Always |
| Trusted origin | Authenticated anchor or successful CL transition from an eligible trusted pre-state |
| Canonical, finalized, or persisted | Not necessarily |
| Execution status | Where applicable, valid or conditionally valid while execution validity is unresolved |
| DA status | Where applicable, valid within the DA window; treated as satisfied by the defined sync policy outside it |
| Fork-choice eligibility | Required only when used as an eligible trusted pre-state |

A noncanonical branch may retain valid eligible pre-states while it remains viable. Finalization
makes conflicting branches ineligible but does not erase their provenance or historical CL
validity. Execution invalidation instead revokes conditional validity and eligibility for the
affected branch.

### Candidate-block acceptance

- A full consensus-layer state transition is required before a block enters the live chain or fork
  choice, or establishes a trusted post-state. Gossip, sync, hash-chain, and ancestry checks may
  establish prerequisites but do not replace it.
- All proposer and operation signatures are checked by the state transition or by an equivalent
  prior batch whose all-or-none result gates the same import.
- A candidate may publish its post-state and enter fork choice only after state transition,
  state-root verification, signatures, execution handling, and DA handling have jointly succeeded.
  Independent checks may run concurrently.
- A state with unresolved execution validity is authenticated but conditionally valid. It may remain
  fork-choice eligible, but validators must not perform duties while the node is execution
  optimistic. A later invalid result invalidates the affected branch.
- Within the DA window, DA must be satisfied before acceptance and publication. Outside the window,
  the defined sync policy treats DA as satisfied rather than retaining a DA-optimistic branch.
- Verification flags are trusted application policy. A required check may be disabled only when the
  same accepted operation is gated on equivalent prior verification.

Blocks stored only as historical archive data need not run STF when they cannot affect consensus
decisions or establish trusted state. Any later promotion into the live chain must satisfy the full
acceptance contract.

Lodestar-z consumes execution and DA results rather than establishing them. A false result supplied
by a trusted external system is not an independent Lodestar-z bypass. Mishandling an accurate result
is in scope.

### Candidate isolation and shared facts

Candidate processing must isolate branch-specific mutations until acceptance. A rejected candidate
may leave only work products or cache facts that cannot affect later validity based on the rejected
branch.

Shared caches may retain only branch-independent facts. In particular, an append-only
validator-pubkey cache may advance during a failed candidate only if:

- cached indexes beyond a state's validator count are treated as absent for that state;
- later valid processing at an index must reproduce the same pubkey; and
- conflicting, duplicate, or sparse appends fail.

Any new mutable global state must define its synchronization, ownership, worker visibility, bounds,
and teardown order.

## Finding classification

### Required evidence

A security report must identify:

1. the least-privileged attacker and controlled value;
2. the current supported path or identified planned integration path to the operation;
3. the integration maturity and every trusted precondition on that path;
4. the validation, ownership, lifecycle, fork, preset, and external-status contracts involved;
5. the violated security objective and concrete effect;
6. whether the effect survives candidate cleanup, cache isolation, fork-choice invalidation, or
   worker teardown; and
7. a reproducible input or sequence with relevant size, work, and allocation bounds.

Severity follows demonstrated reachability, defaults, reproducibility, and impact. A
dangerous-looking line is not sufficient evidence.

### Categories

| Classification | Meaning |
| --- | --- |
| Security vulnerability | An in-scope attacker crosses a current supported boundary and violates a security objective. |
| Security-readiness issue | A planned integration would expose the violation at a hostile boundary, but that path is not yet production-reachable. |
| Consensus correctness bug | Behavior differs from the pinned specification under valid inputs without established attacker reachability. |
| Boundary hardening | Validation or robustness is weak where the caller already has equivalent impact and no less-privileged hostile path is established. |
| Trusted-input reliability bug | Trusted state, storage, or local-file use causes a leak, panic, race, cleanup failure, or bad error. |
| Operator misuse or unsupported use | The trigger violates an explicit trusted precondition or supported lifecycle. |
| Test or documentation gap | No current behavior violates this model. |

### Resource exhaustion

Every denial-of-service report must quantify the input bound, work or allocation amplification,
repeatability, and attacker-controlled path.

- One malformed remote input must fail safely before peer scoring can help.
- Sustained attacks must account for supported transport limits, scoring, and disconnection, but
  those controls do not excuse cumulative leaks or unbounded queues.
- Protocol-bounded transition and cryptographic costs are expected unless amplification materially
  exceeds the protocol work.
- A large allocation requested only by a trusted same-process caller is hardening unless remote
  influence is demonstrated.
- Host-wide out-of-memory is not itself a vulnerability; attacker-controlled amplification before
  it can be.

### Common non-findings

Without evidence crossing a boundary above, these are not security vulnerabilities:

- missing authentication on an in-process API, deliberate use of caller-owned policy flags, or
  effects already available through the caller's ambient privileges without additional
  native-memory or cross-worker impact;
- an operator selecting malicious configuration, an untrusted initial state, a wrong-network file,
  or an attacker-controlled output path;
- treating trusted database, ERA/E2S, or PKIX bytes as remotely controlled;
- expecting state SSZ decoding to establish trusted ancestry, canonicality, or finality;
- fork choice relying on documented state-transition or attestation-validation prerequisites;
- mutation of a disposable candidate or a permitted branch-independent cache append;
- retention of a viable noncanonical state or eviction of a finalized-away state;
- a checksum that detects corruption but is not an authentication mechanism;
- intended secret-key serialization to the owning caller;
- failures confined to tests, generators, fuzzers, examples, benchmarks, or explicit stubs; and
- timing or memory-forensic attacks absent a separately adopted side-channel guarantee.

These may still be correctness, reliability, API-design, or defense-in-depth issues.

## Maintenance rule

Keep this file normative and short. A statement belongs here only if changing it can change a
finding's trust analysis, classification, reachability, severity, or required security property.
Descriptions of where or how the current implementation enforces a rule belong in the
[implementation map](docs/security/IMPLEMENTATION_MAP.md).

Review both documents when a change adds or alters a trust boundary, native dependency, persistence
path or format, shared mutable cache or pool, externally influenced native input, or supported
integration.
