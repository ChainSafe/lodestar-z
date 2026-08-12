# Lodestar-z threat model

This document defines the security boundaries and review assumptions for Lodestar-z. It is written
for maintainers and automated reviewers. Read it before reporting a security issue.

It applies to the `main` branch and was last reviewed on 2026-08-12.

This is a living model. A code path that violates an assumption may still contain a bug, but the
report must explain why the violation is reachable in a supported Lodestar deployment.

## System and deployment context

Lodestar-z is a Zig library and a Node.js native addon. It is not a network service, an HTTP server,
an Ethereum peer-to-peer stack, an execution client, a key manager, or a slashing-protection
database.

The production data flow is generally:

```text
remote consensus peer or external subsystem
                    |
                    v
       Lodestar networking and orchestration       outside this repository
                    |
                    v
       JavaScript wrappers and N-API boundary      bindings/src, bindings/napi
                    |
                    v
   SSZ, state transition, BLS, caches, fork choice src
                    |
                    v
        post-state, roots, proofs, or errors
```

P2P objects are the principal hostile data source. Lodestar-ts currently owns networking, message
size and decompression limits, peer scoring, and orchestration. P2P objects that will cross into
Lodestar-z may still contain adversarial SSZ bytes. Beacon states, ERA data, database contents,
configuration, wall-clock time, and application policy have different trust contracts described
below. Reviews must not treat every serialized object or JavaScript argument as remotely controlled.

The package also supports direct use by JavaScript and Zig callers. Those callers are in the same
process and privilege domain as Lodestar-z. The addon is not a sandbox around hostile JavaScript.

### Integration maturity

Threat reports must distinguish current production reachability from the required security posture
of components planned to replace Lodestar-ts implementations:

| Component | Integration status | Review classification |
| --- | --- | --- |
| BLS bindings | Integrated | Production-reachable |
| Process-wide pubkey cache | Integrated | Production-reachable |
| State transition | Next integration stage | Consensus correctness and security readiness; planned input is a trusted pre-state plus serialized hostile signed block |
| Zig fork choice | Future integration stage | Parity and security readiness; planned inputs include STF-valid blocks and validated attestations |
| Generic P2P-object deserialization | Planned as integrations expand | Hostile-input boundary where actually wired |
| Beacon-state and ERA loading | Library surface using trusted input | Reliability and defense in depth unless another attacker path is demonstrated |

A bug in a planned component can be important and release-blocking without being described as a
currently exploitable Lodestar vulnerability. Direct downstream users must establish their own
reachable boundary.

## Security objectives

Lodestar-z aims to preserve the following properties in supported builds and deployments:

1. **Consensus correctness.** With the correct preset and chain configuration, a trusted pre-state,
   all required checks completed locally or equivalently beforehand, and accurate external execution
   and data-availability results, state transition and fork choice agree with the consensus
   specification version pinned in `build.zig.zon`.
2. **Cryptographic correctness.** BLS operations do not accept invalid signatures or points when the
   relevant validation is requested by their API contract. Randomized batch operations use
   unpredictable, nonzero coefficients and preserve the required cardinality.
3. **Memory safety.** Malformed externally sourced bytes, points, indices, offsets, and collection
   lengths do not cause out-of-bounds access, use-after-free, double free, uninitialized-memory use,
   or allocator mismatch.
4. **Process availability.** A single malformed or protocol-bounded remote input fails with an error
   rather than a panic, deadlock, infinite loop, or unreasonable amplification of CPU or memory.
5. **State integrity.** Rejected candidate blocks do not partially modify the trusted pre-state,
   publish derived epoch-cache entries, enter fork choice, or corrupt process-wide caches.
6. **Lifecycle safety.** Supported Node.js worker creation, concurrent cache access, environment
   teardown, and finalization do not race or access freed global state.
7. **Artifact integrity.** Published native artifacts are built from reviewed sources and pinned
   dependencies through the repository release workflow.

Secret keys are sensitive when callers use the exported BLS `SecretKey` API. The library must not
leak them through unrelated output, logs, memory-safety errors, or other objects. It does not claim
to provide process isolation, an HSM, hardened memory, or protection from arbitrary code already
executing in the Node.js process.

## Assets and impact

The main assets are:

- the correctness of beacon states, state roots, fork selection, validator accounting, and head
  selection;
- Ethereum consensus safety and liveness for a Lodestar node using this implementation;
- availability and memory integrity of the hosting Node.js process;
- correctness of BLS signature verification and aggregation;
- integrity of process-wide node pools, pubkey caches, configuration, and worker-pool state;
- confidentiality of BLS secret-key material intentionally passed to this package;
- integrity of npm packages and native release artifacts.

A consensus mismatch, invalid signature acceptance, remotely reachable native memory corruption, or
deterministic process crash can be security-significant. A wrong exception message, an unsupported
API call, or bad output caused only by an operator supplying inconsistent trusted configuration is
normally a correctness or usability issue instead.

## Actors and capabilities

### Remote consensus participant

A peer can send adversarial but protocol-shaped blocks, attestations, signatures, public keys, and
SSZ payloads to Lodestar. It may also send malformed network payloads. It cannot directly choose
native method options, mutate the local chain configuration, select local files, reserve arbitrary
cache capacity, or call addon methods unless a concrete Lodestar path exposes that control.

### Remote API user

An API user has only the capabilities granted by Lodestar's HTTP or RPC layer, which is outside this
repository. A report relying on this actor must trace the value through that layer to a Lodestar-z
entry point and account for upstream validation and limits.

### Operator and host application

The operator and the Lodestar application choose the network preset, chain configuration, trusted
checkpoint or initial state, file paths, cache sizing, execution status, data-availability status,
verification policy, and wall-clock time. These are trusted control-plane inputs. Accidental
mistakes should fail clearly where practical, but a malicious operator is not an attacker this
library can contain.

### Same-process JavaScript or Zig code

Code loaded into the same process can invoke exported functions, allocate memory, read and write
files using its own runtime privileges, terminate the process, and serialize a `SecretKey` by design.
It is not a security boundary. N-API still validates types, lengths, indexes, and encodings to prevent
accidental misuse from becoming native undefined behavior or a process crash.

### Checkpoint state provider

A checkpoint state provider is usually semitrusted. If the user supplies a checkpoint root, matching
the downloaded state's hash-tree-root to that root is a mandatory part of establishing the trust
chain. The exact Lodestar-ts or Lodestar-z integration point that performs this check is not yet
fixed. If the user supplies no root, trust in checkpoint selection is explicitly delegated to the
provider. A malicious provider under delegated trust is outside this threat model, while safely
handling malformed responses remains worthwhile boundary hardening.

### Trusted local storage

Beacon states read from the database, ERA/E2S data, and PKIX snapshots are application-owned trusted
inputs. The current model assumes bytes written are the bytes later read. Host or database compromise,
silent storage corruption, and an operator selecting a file from the wrong network are outside the
adversarial model. Framing checks and graceful failures remain reliability and defense-in-depth
requirements, not evidence that these inputs are ordinarily hostile.

### Contributor or supply-chain attacker

A contributor may propose malicious source or workflow changes. A dependency or build service may
be compromised. Code review, pinned Zig dependencies and GitHub Actions, tests, npm trusted
publishing, and provenance are the relevant controls.

## Trust boundaries and contracts

| Boundary | Untrusted or fallible data | Trusted decision or precondition |
| --- | --- | --- |
| Network to Lodestar | P2P gossip and req/resp objects | Message framing, size/decompression limits, peer scoring, and orchestration are currently owned by Lodestar-ts |
| JavaScript to N-API | Runtime types, byte contents, lengths, indices, offsets, arrays, and object shapes | Same-process caller chooses which method to call and owns policy options |
| P2P object to SSZ | Bytes, offsets, list lengths, bitfields, and encodings are hostile | Lodestar-ts applies transport bounds; native decoding still enforces canonical SSZ and consensus limits |
| Beacon-state deserialization | Bytes come from a trusted anchor, trusted database, or trusted ERA source | Deserialization establishes structural SSZ validity only; provenance establishes state trust |
| State transition | Serialized signed block contents are hostile | Pre-state is trusted; full STF or equivalent prior checks are required; execution and DA statuses are accurate |
| Fork choice | Valid blocks and validated attestations still represent competing branches | Only STF-valid blocks enter; attestations passed the applicable upstream validation; local time is trusted |
| BLS API | Serialized points, messages, list contents, and cardinality | Boolean validation options are caller policy; proof-of-possession preconditions apply where documented |
| Shared native state | Worker scheduling and teardown are asynchronous | Configuration and administrative cache operations follow their lifecycle contract |
| Checkpoint provider | Response may be malformed; provider is semitrusted | User-provided checkpoint root is authoritative, or checkpoint selection is explicitly delegated |
| Database, PKIX, and ERA/E2S | Fallible local I/O, format compatibility, and accidental corruption | Contents and provenance are trusted; malicious local replacement is out of scope |
| Build and release | Source contributions and downloaded dependencies | Maintainer review, pinned versions/hashes, protected repository settings, and release credentials |

### Component review map

| Area | Primary security concern | Important inherited contract |
| --- | --- | --- |
| `src/ssz`, `src/persistent_merkle_tree`, `src/hashing` | Canonical decoding, offset and generalized-index bounds, ownership, proof correctness, and bounded merkleization | Generic typed callers obey allocator and lifetime contracts; serialized bytes can be hostile |
| `src/consensus_types`, `src/fork_types`, `src/config`, `src/preset` | Correct fork schema, preset values, fork dispatch, and type-safe cross-fork access | Active preset and runtime chain configuration identify the intended network |
| `src/state_transition` | Consensus equivalence, signature checks, rejected-state isolation, cache consistency, and bounded per-block work | Trusted anchored pre-state and accurate external execution/DA results |
| `src/bls` | Point decoding, subgroup and infinity checks, aggregation cardinality, randomness, thread-pool cleanup, and false acceptance | Per-call validation flags and proof-of-possession requirements are explicit API policy |
| `src/fork_choice` | Head correctness, optimistic invalidation, vote accounting, finalized ancestry, equivocation handling, queue bounds, and arithmetic | Blocks passed full state transition; indexed attestations passed upstream validation; time is advanced by the trusted caller |
| `src/beacon_node`, `src/clock` | Cache ownership, event ordering, time/slot calculations, and integration invariants | A report must establish whether the component is wired into a production Lodestar path |
| `src/era` | Format correctness, offsets, decompression, allocation bounds, SSZ parsing, and optional semantic validation | ERA data and its provenance are trusted; failures are ordinarily reliability issues |
| `bindings/napi`, `bindings/src` | Runtime type and range checks, native lifetime, worker isolation, error stability, and JS/native API agreement | Same-process caller owns control-plane policy and has ambient process privileges |
| `scripts`, `test`, `bench`, `examples` | Developer, CI, generation, or supply-chain impact | These are not runtime peer-facing surfaces without a demonstrated invocation path |

### N-API boundary

The native exports are registered from `bindings/napi/root.zig`: configuration, node-pool sizing,
shuffle, metrics, state transition helpers, `BeaconStateView`, BLS, and the pubkey cache. Public
JavaScript declarations and wrappers live in `bindings/src`.

Every JavaScript-controlled length, index, byte encoding, buffer range, class instance, and numeric
conversion that reaches native memory must be checked or passed to an API that returns a bounded
error. JavaScript type declarations are not runtime validation. A `std.debug.assert` is not an
acceptable parser guard in ReleaseSafe when malformed external data can reach it.

This robustness requirement does not turn the addon into an authorization boundary. For example,
`pubkeyCache.save(path)` is explicitly a local file-writing API. Letting its caller choose `path` is
not path traversal by itself.

### Beacon-state trust and provenance

A beacon state is not an arbitrary network object in the Lodestar architecture. Every state-loading
or construction entry point requires trusted state bytes. Trust originates at one of these anchors:

- genesis, which can be viewed as the trusted checkpoint at epoch zero;
- a user-provided checkpoint root, after the downloaded state's hash-tree-root is matched to it; or
- explicit delegation of checkpoint selection to a checkpoint state provider.

Subsequent states inherit trust through successful state transitions. A state written to trusted
storage retains the trust it had when written. SSZ deserialization checks structural validity; it
does not establish provenance, consensus validity, canonicality, or finality.

```text
genesis or authenticated checkpoint
                 |
                 v
       trusted beacon pre-state
                 |
        hostile candidate block
                 |
       isolated full state transition
          |                    |
       reject                accept
          |                    |
 discard candidate       trusted post-state
                               |
                    fork choice or trusted storage
```

For this model, a trusted beacon state is:

- structurally valid SSZ;
- consensus-layer valid, conditional on the execution and DA assertions supplied by the application;
- descended from a trusted anchor; and
- associated with a block branch that is eligible for fork choice at the time it is accepted.

These properties must not be conflated:

| Property | Guarantee for a trusted beacon state |
| --- | --- |
| Structural SSZ validity | Always |
| Consensus-layer validity | Always, conditional on correct external execution and DA assertions |
| Descent from trusted anchor | Always |
| Canonical | Not necessarily |
| Finalized | Not necessarily |
| Persisted | Not necessarily |
| Execution status | Valid or conditionally trusted while `syncing` |
| DA status | Valid within the DA window; treated as satisfied outside the window |

A noncanonical block and its implied post-state remain valid and trusted while their branch remains
viable. Finalization makes conflicting branches ineligible and their states are evicted. This does
not mean those states were invalid before finalization, but they are no longer eligible trusted
pre-states afterward.

An execution-optimistic state is conditionally trusted. Each block carries its own execution status.
While the EL is syncing, optimistic blocks and their descendants remain `syncing`. When the EL later
reports valid or invalid, fork choice propagates that result through the affected branch. Latest
valid hash processing makes an invalid block and all descendants immediately ineligible, revokes
their conditional trust, and prevents their use as trusted pre-states. Lodestar-ts is responsible for
preventing validator duties while the node is execution optimistic.

DA must be satisfied before STF. Inside the DA window this means DA validation has completed. A
super-node that custodies all columns may start STF after observing half because it can reconstruct
the remainder. Outside the window during sync, DA is treated as satisfied rather than retained as an
optimistic branch status.

`BeaconStateView.stateTransition` clones the trusted cached pre-state. Work before a late failure
mutates only the disposable candidate clone, which is destroyed on error. Only a successful full STF
may publish the post-state or enter fork choice. A finding that claims accepted-state corruption must
demonstrate an alias or cache mutation crossing this isolation boundary.

Malicious database or ERA state bytes are outside the adversarial model. Checkpoint-provider bytes
are the one state-loading surface where malformed input is plausible because the provider is only
semitrusted. Robust decoding there is defense in depth, and matching a user-provided checkpoint root
is the critical authentication step.

### P2P block validation paths

Gossip and sync establish different preliminary facts, but full STF is required before every block
import:

```text
hostile P2P bytes
        |
        v
canonical SSZ decoding
        |
        +-- gossip: consensus-spec gossip validation
        |
        +-- range, unknown-block, or backward sync: hash-chain validation
                                                       |
                                                       v
                         proposer and operation signatures checked
                         individually by STF or batch-verified beforehand
                                                       |
                                                       v
                                      full STF and state-root verification
                                                       |
                                                       v
                                  valid block and trusted post-state
                                                       |
                                                       v
                                                 fork choice
```

Backward sync starts when a block, attestation, or another P2P object references an unknown block. It
fetches parents until reaching a block already known to fork choice, checks `parentRoot` against the
parent block's hash-tree-root, and then processes the chain forward through full STF before import.
Hash-chain membership proves ancestry, not consensus validity.

Lodestar-ts may batch-verify signatures in parallel before STF. In practice, all required
verification pathways are joined with all-or-none `Promise.all` behavior. Disabling a corresponding
STF check is valid only when that exact import operation is gated on all prior verification promises.
Successful signature computations may remain after a later STF failure, but they are useless and
must not imply block validity.

### Verification flags and external statuses

The following values are trusted application policy, not remote authorization controls:

- `verifyStateRoot`, `verifyProposer`, and `verifySignatures`;
- execution-payload status;
- data-availability status;
- BLS public-key, signature, group, and infinity-check options.

Disabling a check is supported for call paths that already performed equivalent validation, tests,
and controlled workloads. Production import still requires proposer verification, all operation
signature checks, consensus processing, and post-state-root verification. A report is
security-relevant only if an untrusted actor can cause a supported production path to omit a
required check, prior verification is not bound into the all-or-none import result, a check marked
enabled is ineffective, or the API contract falsely claims validation that does not occur.

Lodestar-z does not contact the execution layer or a data-availability subsystem. It consumes their
results. The EL is trusted to be nonmalicious but may be fallible or still syncing. An incorrect
`valid` response from a faulty EL is an external-system failure. Incorrect handling of a correct EL
response is a Lodestar-z consensus bug. The `syncing` execution status becomes branch metadata in
the planned fork-choice integration rather than weakening CL state-transition checks.

DA orchestration currently belongs to Lodestar-ts. Supplying the correct DA status before STF is an
integration precondition. Incorrect handling of that status in Lodestar-z is in scope; a trusted
caller falsely claiming availability is not an independent native validation bypass.

### Fork choice

Fork choice intentionally does not repeat every expensive consensus check:

- `ForkChoice.onBlock` requires the supplied block to have passed state transition upstream.
- `ForkChoice.onAttestation` requires the indexed attestation to have passed
  `is_valid_indexed_attestation` upstream.
- `onAttesterSlashing` relies on state-transition validation, including sorted attesting indices.

On the gossip path, attestation prerequisites are the applicable consensus-spec gossip and indexed
attestation validations. They include structural constraints, timing, shuffling and committee
membership, sorted and unique indices, and BLS verification as applicable. Sync paths may establish
their prerequisites differently, but may not put an invalid block into fork choice.

Fork choice remains responsible for its documented checks, including known parents, time, finalized
ancestry, target consistency, execution and payload status propagation, latest-valid-hash branch
invalidation, vote application, and internal bounds. Missing an upstream-owned signature check
inside fork choice is not a vulnerability unless a production caller can bypass the prerequisite.

The current production Lodestar fork-choice implementation remains in Lodestar-ts. The Zig module is
intended to replace it, so parity of optimistic handling, invalidation, and validation prerequisites
is a required integration invariant even before current remote reachability exists.

### Process-wide configuration, pools, and caches

The addon shares BLS worker-pool state, the persistent Merkle node pool, configuration, metrics, and
the pubkey cache across Node.js environments. Sharing is intentional.

- Loading and unloading supported workers must not tear down state still used by another
  environment.
- Pubkey-cache movable storage is protected by its lock, and references into it must not escape a
  resize.
- PKIX save, load, and reset are restricted to the control environment. Reads and supported append
  operations may be shared.
- The pubkey cache contains finalized validator-registry history. Pending deposits are processed into
  this global append-only history only at finalization, so an orphaned or execution-invalid branch
  cannot poison it.
- Other state-transition caches are short-lived, generally epoch-scoped, and derived from a trusted
  state. Candidate-block processing must isolate their mutations until acceptance. A failed STF may
  leave metrics or completed signature computations, but nothing that can influence later validity
  decisions.
- Chain configuration is application startup state. The application must not concurrently replace
  it while states or transitions are using borrowed configuration data.
- Explicit capacity APIs are controlled by the local application. They must reject arithmetic
  overflow and impossible capacities, but a same-process caller deliberately requesting a large
  valid reservation is not a remote memory-exhaustion attack.

Any code change that adds mutable global state must define its synchronization, ownership, worker
visibility, and teardown order.

### PKIX cache files

PKIX is a fast native cache snapshot, not a trust anchor. Its loader checks framing, exact file size,
format version, ABI compatibility, caller-supplied capacity, and corruption checksums. The checksum
is not intended to authenticate a maliciously modified file, and affine entries are not
semantically revalidated on load. Callers must load only an application-owned file from the intended
network while cache administration is safe.

Reports about forged PKIX checksums or semantically invalid but well-framed local files are out of
scope unless they show one of the following:

- a normal Lodestar workflow allows a remote actor to replace or select the file;
- the loader accepts a file contrary to its documented ABI, size, or checksum contract;
- a failed or concurrent load corrupts the previously live cache.

### ERA and E2S files

ERA/E2S data is trusted local input, not a hostile runtime surface. Entry sizes, index counts,
arithmetic, file offsets, decompression, and SSZ decoding should still be bounded and checked for
reliability. `Reader.validate` additionally checks network and block/state consistency. Lower-level
`read*` methods do not establish trust because trust already comes from provenance.

Download scripts, test-vector generation, benchmarks, and fuzz harnesses are development tooling,
not runtime network endpoints. Findings in them need a build, CI, developer-workstation, or release
impact rather than a claimed beacon-node remote exploit.

## Threat scenarios in scope

| ID | Scenario | Security condition |
| --- | --- | --- |
| TM-01 | Malformed P2P SSZ, proof descriptors, BLS encodings, or remotely influenced N-API values trigger native memory corruption or a panic | Reachable through a current or identified planned P2P integration without first violating a trusted-caller precondition |
| TM-02 | An adversarial block or attestation produces a state root, validator result, fork upgrade, or head different from the pinned specification | Correct preset/configuration, trusted pre-state, full required validation, and accurate external statuses are used |
| TM-03 | An invalid BLS signature, public key, or aggregate is accepted when the requested checks and documented preconditions hold | Report identifies the exact API flags, point validation state, and proof-of-possession assumption |
| TM-04 | Attacker-controlled work or memory grows beyond protocol or documented application bounds | Report traces attacker control and quantifies amplification, not merely a theoretical maximum local call |
| TM-05 | Node.js workers race on a cache, pool, configuration, async job, finalizer, or cleanup hook | Sequence uses the supported worker/lifecycle model |
| TM-06 | Failed STF leaks candidate-derived caches into trusted state, enters fork choice, leaks, double-frees, or deadlocks | Report accounts for cloning, epoch-cache ownership, `defer`, `errdefer`, reference counts, locks, and rollback |
| TM-07 | Checkpoint bootstrap accepts a downloaded state whose hash-tree-root does not equal the user-provided checkpoint root | Report identifies the integration layer responsible for the mandatory root comparison |
| TM-08 | A build or release workflow executes untrusted code with secrets or publishes a substituted native artifact | Report demonstrates the relevant CI event, permissions, pinning, and artifact path |
| TM-09 | Secret-key material escapes through an unrelated API or memory-safety flaw | Calling documented `SecretKey.toBytes` or `toHex` is not an escape |
| TM-10 | Correct EL or DA status causes wrong optimistic eligibility, validator-safety signal, or branch invalidation | A false status supplied by an external system is distinguished from mishandling a correct status |

## Resource-exhaustion standard

This project requires bounded loops and allocations even when an immediate exploit is not proven.
Security severity still depends on reachability:

- A protocol-valid peer input that causes superlinear or grossly amplified work in the normal node
  path is a security concern.
- A malformed remote input that allocates before checking its encoded bound is a security concern.
- A single malformed P2P object must fail safely before peer scoring can help. Scoring does not
  mitigate a panic, memory corruption, deadlock, or large one-shot amplification.
- A remote API input is relevant only when the Lodestar API actually forwards it and does not
  impose an effective bound.
- An arbitrary JavaScript array or explicit `ensureCapacity` value supplied by trusted same-process
  code is boundary hardening unless a remote path is demonstrated.
- Normal state-transition cost, cryptographic verification cost, and allocations bounded by
  consensus constants are expected. A report should compare the cost with the protocol maximum and
  the surrounding Lodestar rate controls.
- Sustained invalid-input attacks must account for Lodestar-ts peer scoring and disconnection. A
  report should show meaningful damage before scoring takes effect or an integration path that is
  not scored appropriately. Scoring policy itself is currently a Lodestar-ts concern.
- Unavoidable process behavior after genuine host-wide out-of-memory is not by itself a
  vulnerability. Attacker-controlled allocation amplification before OOM can be one.

Every denial-of-service report should provide an input-size bound, work or allocation estimate,
repeatability, and the attacker-controlled call path.

## Out of scope and common false positives

The following are not security findings without additional evidence that crosses a boundary above:

- lack of authentication or authorization on an in-process Zig or N-API function;
- arbitrary code already executing inside the Lodestar Node.js process;
- an operator choosing a malicious configuration, wrong preset, untrusted initial state, wrong
  network file, or attacker-controlled output path;
- treating trusted database beacon states or ERA/E2S data as attacker-controlled inputs without a
  demonstrated boundary that can replace them;
- expecting beacon-state SSZ deserialization to establish trusted ancestry, canonicality, finality,
  or long-range-attack resistance;
- bypassing validation by explicitly setting a verification option to `false` from trusted code;
- inaccurate execution or data-availability results supplied by the trusted application;
- fork choice not repeating state transition, signature, or indexed-attestation validation;
- mutation of the disposable post-state clone before a transition is rejected;
- a noncanonical but still viable branch retaining a valid trusted post-state;
- states from a finalized-away branch being evicted as no longer useful;
- the PKIX checksum not being a MAC or PKIX affine entries not being revalidated;
- path traversal based solely on the caller-controlled path of an explicit local load/save API;
- disclosure of a secret through the documented `SecretKey.toBytes` or `toHex` method to its owning
  caller;
- crashes or hangs only in tests, generated spec-test runners, fuzz harnesses, examples, or
  benchmarks, absent a production or supply-chain path;
- missing implementation of an API that is explicitly stubbed and throws `NOT_IMPLEMENTED`;
- a large allocation requested only by a malicious same-process caller, with no remote influence;
- timing or memory-forensic attacks against secret keys, unless maintainers separately adopt a
  hardened-memory or side-channel-resistance guarantee.

These cases can still justify a correctness, reliability, API-design, or defense-in-depth issue.
Label them accurately rather than presenting them as remote vulnerabilities.

## Security-review procedure

Before filing a security finding, answer all of the following:

1. **Attacker:** Who is the least-privileged actor that controls the trigger?
2. **Maturity:** Is the component production-integrated, planned for integration, or only a direct
   library surface?
3. **Provenance:** Is the input hostile P2P data, a semitrusted checkpoint response, trusted state or
   ERA data, trusted application policy, or same-process caller data?
4. **Entry point:** Which exported Zig function, N-API method, parser, file workflow, or CI event is
   reached?
5. **Call path:** How does attacker-controlled data reach the exact operation through gossip, sync,
   req/resp, a binding, or another supported or identified planned deployment path?
6. **Validation route:** Did gossip validation, hash-chain validation, individual STF checks, or
   all-or-none prior batch verification establish a prerequisite?
7. **Contract:** Which trust-anchor, execution/DA, lifecycle, ownership, fork, preset, and upstream
   preconditions apply?
8. **Violated objective:** Which numbered security objective or threat scenario is broken?
9. **Reproduction:** Can the issue be reproduced on the target branch with the supported Zig version
   and, for bindings, a ReleaseSafe native build?
10. **Impact:** Does it cause consensus divergence, false cryptographic acceptance, memory
    corruption, branch misclassification, persistent integrity loss, process unavailability, secret
    exposure, or only a handled error?
11. **Rollback and ownership:** Does the effect survive candidate-clone destruction, epoch-cache
    cleanup, lock release, worker teardown, cache staging, or fork-choice invalidation?
12. **Bound:** For denial of service, what are the maximum input, allocation, loop count, and
   amplification?
13. **Reference:** For consensus behavior, does the claim match the exact spec version pinned in
    `build.zig.zon`, the active fork, and the active preset rather than upstream `master`?

A useful report includes a minimal test or input and states whether the classification is:

- **security vulnerability:** crosses an in-scope boundary and violates a security objective;
- **consensus correctness bug:** wrong behavior under valid inputs, with deployment reachability not
  yet established;
- **security-readiness or integration invariant:** required before a planned component becomes a
  hostile-input production boundary, but not currently remotely reachable;
- **boundary hardening:** unsafe or weak validation at an in-process boundary without a remote path;
- **trusted-input reliability bug:** leak, panic, format failure, race, or bad cleanup under
  non-adversarial state, database, ERA, or local-file use;
- **operator misuse or unsupported use:** violates an explicit trusted precondition;
- **test or documentation gap:** no current behavior violating the model.

Do not assign a high severity from a dangerous-looking line alone. Severity follows the demonstrated
attacker, defaults, call path, reproducibility, and effect.

## Existing controls to verify, not assume

The repository has controls that reduce risk, but a review may show that an implementation is
incomplete:

- consensus, SSZ, and BLS vectors pinned through `build.zig.zon`;
- minimal and mainnet preset testing;
- SSZ and BLS fuzz targets;
- full STF before import, including proposer and operation signatures checked by STF or an
  all-or-none prior batch, plus post-state-root verification;
- copy-on-write state cloning and cleanup on rejected transitions;
- gossip validation or sync hash-chain validation before full forward STF;
- trusted-anchor bootstrapping through genesis or checkpoint-root authentication;
- explicit protocol bounds, bounded stack buffers, and checked arithmetic in parsers;
- keyed pubkey-cache hashing, locking around movable storage, staged PKIX installation, capacity
  limits, and control-environment administration;
- reference-counted native pools and last-environment cleanup;
- fork-choice execution-status propagation and latest-valid-hash invalidation as required parity
  behavior for the future integration;
- ReleaseSafe native artifacts;
- pinned GitHub Actions, hashed Zig dependencies, lockfile installation, npm trusted publishing, and
  provenance.

Security reports should test whether the relevant control actually covers the claimed path.

## Open deployment questions

Maintainers should update this model as the integration matures. Until then, reviewers should state
their assumption for these questions rather than silently choosing the most alarming one:

- Which N-API methods are stable end-user APIs versus Lodestar-internal compatibility surfaces?
- Which additional serialized P2P object types are connected to Lodestar-z as STF and fork-choice
  integration proceeds?
- Which layer will own the mandatory comparison between a downloaded checkpoint state root and a
  user-provided checkpoint root?
- What stable error taxonomy will let Lodestar-ts distinguish invalid peer data, consensus failure,
  execution invalidity, and internal failure for scoring and operations?
- What production limits should apply to proof descriptors, aggregate lists, pool preheating, and
  pubkey-cache growth?
- Is chain configuration guaranteed to be set once before workers and state views are created?
- How are PKIX files provisioned, permissioned, and invalidated across network or binary upgrades?
- Is the exported `SecretKey` API intended for production validator key material, or only API
  compatibility and testing?
