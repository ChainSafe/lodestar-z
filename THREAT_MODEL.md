# Lodestar-z threat model

This document defines the security assumptions that materially affect how findings in Lodestar-z
are classified.

This model is not an allowlist. Reviewers should first surface candidate violations, then use these
assumptions to determine reachability and severity. A finding may be downgraded only when the
applicable call path establishes the cited assumption. If the code contradicts this document, report
the code issue and the documentation gap.

## Scope

Lodestar-z is a Zig consensus library, native QUIC/DiscV5 networking stack, and Node.js native addon.
The native networking surface receives public peer traffic and owns transport authentication,
protocol framing, resource admission, and peer lifecycle. Its host owns API exposure, checkpoint
acquisition, consensus validation of received objects, execution-layer communication, and validator
duties. Native networking does not make received consensus objects trusted.

The supported Node.js integration loads one version of `@chainsafe/lodestar-z` per process. Passing
native class instances between addon versions is unsupported.

The beacon node initializes one native network runtime per process, from its owning Node.js thread.
Initialization installs complete configuration and initial protocol state before starting network
work. Every configured hard fork whose activation epoch is not `FAR_FUTURE_EPOCH` must be supported,
including forks that are not active yet. The host applies subscriptions and peer demand through
ordinary runtime updates.
The application owns the network and explicitly closes it; dropping JavaScript references does not
request shutdown. Once close begins, the binding retains its pump through delivery of outstanding
completions and the close result, without waiting for host serving or validation tasks to retire.
An initialization failure or shutdown is terminal for that runtime. While one runtime is live,
another initialization, including from another Node.js environment, is rejected; after it is fully
released, a new runtime may initialize. The owning thread coordinates shutdown and joins the network
thread. Environment cleanup also stops the owner and retires outstanding native obligations, even
when JavaScript can no longer run. Admission failures are reported before the operation commits.
Once an exchange applies actions and selects delivery, building and publishing its result are bridge
obligations. A result-build or result-finish failure while JavaScript remains runnable is a bridge
contract failure and terminates the process unsuccessfully through a native fatal error. If the
JavaScript environment has stopped, teardown reclaims the outstanding native obligations. If the runtime otherwise cannot safely continue, the
host shuts down the beacon node and preserves the terminal failure as an unsuccessful process exit.

The assets protected here are:

- Ethereum consensus safety and liveness;
- state-transition, fork-choice, and BLS correctness;
- native memory safety and availability of the hosting process; and
- integrity of shared native state across calls and Node.js environments; and
- integrity of source dependencies and published native artifacts.

The relevant attackers are remote peers or API users whose values reach Lodestar-z. Attackers may
also target dependencies, build workflows, release credentials, or the package registry. The
operator and host application are trusted to select configuration, verification policy, initial
state, local files, wall-clock time, and execution or data-availability status. Lodestar is the only
JavaScript consumer of the bindings and, like same-process Zig code, is trusted to honor native API
preconditions. Host compromise, hostile host code, and malicious replacement of trusted local
storage are out of scope.

## Security objectives

1. Given the correct preset and configuration, an eligible trusted pre-state, and accurate external
   statuses, consensus behavior agrees with the pinned Ethereum consensus specification.
2. BLS operations do not falsely accept invalid signatures or points when their API contract
   requires validation.
3. Externally influenced values cannot cause native-memory corruption or disclosure.
4. Attacker-controlled inputs fail without panics, deadlocks, cumulative leaks, or unbounded work or
   allocation.
5. Rejected candidates cannot publish branch-specific state or corrupt shared state.
6. Supported concurrent operations and environment teardown cannot race with borrowed native state.
7. Build and release preserve the integrity and provenance of reviewed source, dependency inputs,
   and published native artifacts.

## Trust boundaries

| Boundary | Contract |
| --- | --- |
| Remote UDP, QUIC and TLS | Datagrams, source addresses, negotiation bytes, certificates, and authenticated streams remain hostile. Source addresses may be spoofed before return-path validation. Authentication establishes identity, not permission to exhaust shared native resources or consensus validity. |
| DiscV5 and peer discovery | Packets and signed ENRs remain hostile. A valid signature does not prove endpoint reachability, advertised utility, or membership in an honest peer population. Discovery bounds both authenticated and unauthenticated packet work with source and aggregate quotas. Matching an outstanding request's endpoint grants bounded receive admission, not identity or guaranteed session retention. Discovery and inbound peers must not indefinitely lock retained admission capacity. Automatic ENR endpoint learning uses expiring, bounded observations from authenticated PONGs matched to local requests, with distinct node IDs and IPv4 /24 or IPv6 /64 sources. A quorum is an address estimate, not proof of reachability or independent operators. Explicit startup endpoints remain pinned; cached endpoints do not disable learning. |
| Peer coverage | Connected gossip coverage requires an eligible route on the requested fork and topic. Subscription announcements do not establish custody service or prove delivery. Custody coverage uses separate assignments and fresh compatible metadata; request consumers still check slot availability. Coverage maintenance uses bounded storage, finite newcomer grace, and paced replacement when demand remains unmet. |
| Network owner to host | The owner copies or explicitly lends bounded data across documented lifetimes. Host backpressure and teardown must release borrows and terminate pending work without blaming peers for local resource refusal. The owner starts graceful close or shutdown between turns, after consuming borrowed events. Shutdown is terminal: the owner does not advance the core again or wait for individual terminal events or host tasks. Deinitialization ends remaining native payload borrows before the host completes outstanding operations. Explicit detach, shutdown or deinitialization ends the host wake descriptor borrow before the host closes or reuses it. Retryable publication admission refusal must precede publication side effects and retaining caller payloads. A locally refused gossip admission leaves retained messages and history intact; any replacement commits with candidate admission. Gossip validation retains execution capacity until the host task retires, including after its protocol deadline. Host request handlers retain serving capacity until their asynchronous operations retire, including after stream cancellation; a stream terminal event alone does not acknowledge host retirement. Destroying the network releases its native capacity without waiting for host work; surviving host work retains its own resource charges until it retires. The transport obtains cryptographically secure startup entropy through its I/O provider. The host supplies consensus verdicts, configuration, and clock policy. Local state must supply all fields required by advertised receive protocols, including custody for early Metadata v3 support. Invalid state or capability updates must fail before publishing ENR, Identify, or serving state. |
| Remote input through Lodestar | Values remain hostile until the validation required by the consuming operation has completed. Reports must trace the supported or planned path into Lodestar-z. |
| JavaScript to N-API | The caller is Lodestar, trusted to follow the documented API contract; hostile host code such as prototype pollution, hostile accessors, or replaced globals is out of scope. Bindings still check runtime types, lengths, indexes, encodings, and buffer ranges where a mistake would violate memory safety or native state, and report violations as programming errors. TypeScript declarations are not runtime checks. |
| LevelDB storage | The host selects trusted local database directories and limits the number of open handles. Opted-in handles in the same addon share one engine and cache for a resolved directory; the registry resolves paths before sharing or refusing an exclusive open. The host prevents concurrent access through independent engine copies or filesystem aliases not resolved by realpath, because POSIX process-scoped engine locks do not enforce that same-process obligation. Each runtime bounds admitted operations, copied inputs and job metadata. Up to two point/multi-get reads overlap its serialized write/cursor/maintenance work; callers await writes before issuing dependent reads. Different runtimes may execute concurrently. Each active operation allocates actual read results under separate per-value and aggregate output bounds after checking borrowed value lengths. These operating limits can reject oversized host requests; atomic write batches are never silently split. These are materialization bounds, not limits on LevelDB's internal block reads, decompression, snapshots, compaction, or total process memory. Storage does not validate consensus objects. Manual iterators retain their snapshot after exhaustion to support seek, so callers close them when finished; for-await iteration, explicit close, read errors and handle/environment teardown retire their cursors. The shared engine and cache remain alive until every handle releases its reference after outstanding work and cursors retire, including during Node.js environment teardown. |
| Serialized input to SSZ | Decoders must enforce canonical encoding, bounds, offsets, and safe ownership. Beacon-state construction is the exception described below: its bytes have trusted provenance, but still require structural SSZ validation. |
| State transition | The pre-state is an eligible trusted state. The signed block is hostile. Processing must not mutate the pre-state, and the result becomes trusted only after the required checks succeed. |
| Fork choice | Blocks have passed full state transition, attestations have passed their applicable validation, external statuses are accurate, and local time is trusted. Fork choice still owns its specified ancestry, timing, vote, invalidation, and bound checks. |
| Zig to native dependencies | Lodestar-z owns representation, cardinality, validation flags, pointer lifetime, and ABI compatibility. Pinned dependencies are trusted only within their documented contracts. |
| Shared native state | Ownership, synchronization, bounds, worker visibility, and teardown must be defined for every shared pool or cache. |
| Build and release | Dependency resolution, automation credentials, and artifact publication must preserve provenance from reviewed source to the published native addon. Release jobs build and publish from one checkout using pinned inputs. Package assembly relies on the release runner, toolchains, and zapi honoring their contracts. |

## BeaconState trust

Beacon states accepted by Lodestar-z are trusted inputs. SSZ deserialization establishes structural
validity only. It does not establish provenance, canonicality, finality, execution validity, or data
availability.

Trusted provenance begins at one of these anchors:

- genesis;
- a state matching a user-provided checkpoint root; or
- a checkpoint selected by a provider to which the user has delegated trust.

A successfully transitioned descendant inherits that provenance. A state loaded from trusted local
storage retains the status it had when written.

A **trusted state** is structurally valid SSZ and is either an anchor or the result of a successful
consensus-layer transition from an eligible trusted pre-state. It need not be canonical, finalized,
or persisted. An **eligible trusted pre-state** additionally belongs to a branch that remains
fork-choice eligible under its current execution and data-availability status.

A viable noncanonical branch can therefore contain trusted states. Finalization can make the branch
ineligible without changing its historical consensus validity. An execution-optimistic state is
conditionally trusted: it may remain in fork choice while execution is unresolved, but validators
must not perform duties from an optimistic node. An invalid execution result revokes eligibility for
the affected branch.

Raw checkpoint bytes are hostile to whichever component first decodes them before authentication.
Lodestar-z does not currently own that boundary. If it does in a supported integration, the new
entry point must treat those bytes as hostile.

## Block acceptance

- A full consensus-layer state transition is required before a block enters the live chain or fork
  choice, or establishes a trusted post-state. Gossip, ancestry, and hash-chain checks do not replace
  the transition.
- Signatures are checked by the transition or by an equivalent prior batch whose all-or-none result
  gates the same import.
- State transition, signature checks, execution verification, and data-availability verification may
  run concurrently, but all required results must gate live-chain and fork-choice admission.
- Within the data-availability window, availability must be satisfied before acceptance. Outside the
  window, the sync policy treats availability as satisfied.
- Verification flags are trusted host policy. Disabling a required check is safe only when equivalent
  prior verification gates the same operation.
- Historical archive backfill may omit the full transition only while its blocks cannot enter live
  consensus or establish trusted state. Later promotion must satisfy the normal acceptance contract.

Lodestar-z consumes execution and data-availability results rather than establishing them. A false
result from a trusted external component is outside this boundary; mishandling an accurate result is
in scope.

## Candidate and cache isolation

Candidate processing must isolate branch-specific mutations until acceptance. A rejected candidate
may leave only branch-independent facts or completed work that cannot affect later validity.

An append-only validator-pubkey cache may advance during a failed candidate when entries beyond the
current state's validator count are treated as absent, later valid processing must reproduce the
same pubkey at an index, and conflicting or sparse appends fail. This is permitted cache population,
not publication of the rejected state.

## Classifying findings

A report should identify the least-privileged attacker, the supported or planned call path, the
trusted precondition under review, the violated objective, and the concrete effect. Verify
integration status against the current or planned call path. State uncertain reachability explicitly.

| Classification | Meaning |
| --- | --- |
| Security vulnerability | An in-scope attacker crosses a current supported boundary and violates a security objective. |
| Security-readiness issue | An identified planned integration would expose the violation, but the path is not production-reachable. |
| Consensus correctness bug | Consensus behavior violates the pinned specification without established hostile reachability. |
| Reliability bug | The implementation violates another contract without established hostile reachability. |
| Boundary hardening | Validation or failure handling is weak, but the caller already has equivalent impact or violates a trusted precondition. |
| Unsupported use | The trigger is outside the documented caller, lifecycle, or provenance contract. |

For denial-of-service findings, quantify the attacker-controlled input, amplification, repetition,
and applicable transport or peer-scoring limits. Peer scoring can limit sustained abuse but does not
excuse a crash, cumulative leak, or unbounded queue.

## Maintenance

Change this file only when a security objective, trust assumption, trust boundary, or supported
caller obligation changes. Keep enduring API preconditions beside the owning declaration or module.
Routine fixes, optimizations, and file moves that preserve these contracts require no
security-documentation update.
