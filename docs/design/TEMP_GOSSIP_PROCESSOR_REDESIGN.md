## Temporary Design Note: Gossip Processor Redesign

Status: working design note, not committed.

Date: 2026-04-17

### Goal

Move to a durable, production-real gossip architecture where one subsystem owns:

- gossip admission
- per-topic prioritization
- deferred unknown-parent / missing-block-data handling
- async BLS batch lifecycle
- final validation completion back to gossipsub

The preferred outcome is to extend the existing `BeaconProcessor` upward so it becomes that owner, instead of adding a second processor-like subsystem.

This note does not redesign inbound req/resp serving.

Req/resp should follow the same architectural thesis, but it is a sibling serving-domain
problem. If current code still shares queue machinery with req/resp work, treat that as
legacy coupling, not as the target `BeaconProcessor` boundary.

### Grounded Observations

#### Lodestar-TS boundary

Lodestar's ownership seam is:

- gossipsub emits raw pending messages to the network processor
- the network processor owns queueing and scheduling
- gossip handlers are validation/handling logic, not queue owners
- final validation results are emitted back to gossipsub over the same network event boundary

Relevant source:

- `../lodestar/packages/beacon-node/src/network/gossip/gossipsub.ts`
- `../lodestar/packages/beacon-node/src/network/events.ts`
- `../lodestar/packages/beacon-node/src/network/processor/index.ts`
- `../lodestar/packages/beacon-node/src/network/processor/gossipHandlers.ts`
- `../lodestar/packages/beacon-node/src/network/processor/gossipQueues/index.ts`

Important Lodestar properties:

- `beacon_block`, `blob_sidecar`, `data_column_sidecar`, and `execution_payload` are fast-lane topics
- `beacon_attestation` is the explicit overload queue
- the network processor owns pending unknown-block / missing-block-data waiting state
- the network processor owns final validation result emission

Important Lighthouse property:

- the router classifies gossip by topic before it reaches the processor
- the processor still owns the first bounded typed queues and the scheduling policy
- the queue payload may still be raw bytes at that stage

This is an important proof point. Early topic classification does not conflict with
processor-owned scheduling.

#### Current Zig boundary

Today the responsibility is split too late:

- `P2pService` drains gossip events and reports validation results
- `gossip_ingress` parses topic and fork, then directly calls `gossip_handler`
- `gossip_handler` performs phase-1 work and sometimes phase-2 scheduling itself
- only then do typed items get enqueued into `BeaconProcessor`
- `BeaconNode` owns several gossip lifecycle structures that should be scheduler-owned

Current ownership leaks:

- `pending_gossip_validations`
- `completed_gossip_validations`
- `pending_unknown_block_gossip`
- `pending_gossip_bls_batches`

This means the current system has processor priority, but not processor-owned admission control.

### Core Design Decision

Do not add another processor-like ingress stage.

Instead, make the real boundary explicit:

- the first bounded, policy-bearing gossip queues must already be typed

Everything before that may classify, but it must remain a thin adapter:

- no queue ownership
- no drop policy
- no deferred-state ownership
- no hidden transport-side side effects

This is the sharper version of the earlier slogan.

Do not say:

- one subsystem should own gossip admission and scheduling together

Say:

- one subsystem must own the first bounded typed gossip queues and the full validation lifecycle

That preserves architectural coherence while still allowing a thin classifier at the
transport edge.

### Architectural Thesis Applied

This refactor must follow the architectural thesis directly, not just borrow its
vocabulary.

That means the processor redesign must satisfy all of these constraints:

- single-writer consensus truth, not single-writer everything
- explicit truth domains with explicit command boundaries
- deadline-aware scheduling, not just priority ordering
- one-way, acyclic hot-path command flow between authoritative domains
- one idempotent decision record for every network object with a terminal outcome
- explicit protocol-boundary outcomes under overload or refusal
- explicit egress ownership, not just ingress ownership
- artifact-aware admission where message-level scheduling is the wrong unit
- provenance-preserving artifact dedup with hard caps
- immutable snapshot handles plus retention budgets
- explicit durability boundary and replay rules
- first-class node modes with an owning state machine and hysteresis
- explicit object lifecycle ownership from admission to retirement

If a later section in this note conflicts with those rules, that section is wrong.

### Authoritative Domain Command Model

The refactor may rely on multiple authoritative domains, but it must not turn the node
into a distributed system inside one process.

For a given network object:

- there is one hot-path owner from admission until its terminal decision record is written
- cross-domain commands are one-way and acyclic
- hot-path protocol-visible outcomes must not wait on synchronous cross-domain
  acknowledgments
- other authoritative domains consume decision records asynchronously and idempotently

In this refactor, the intended hot-path owner for admitted gossip objects is
`BeaconProcessor`, unless an object lifecycle explicitly says otherwise.

### Decision Record Model

The redesign should distinguish between:

- an authoritative decision record
- protocol-boundary outcomes derived from that record

The authoritative record is the cross-domain truth for a terminal object decision.

It should be rich enough to drive, as applicable:

- gossip `accept` / `ignore` / `reject`
- seen-set or anti-equivocation mutation
- forwarding permission
- peer scoring consequences
- persistence obligations
- gossip publication consequences

This is stricter than a transport-facing validation completion item. Transport completion is
derived from the decision record, not vice versa.

For shared artifacts, the rule is:

- expensive validation may resolve once at the artifact core
- protocol-visible outcomes still resolve per contributing message or stream item

So the processor may keep:

- one shared artifact resolution state
- many message-scoped decision records derived from that shared result plus provenance

That preserves deduplicated validation without erasing protocol accountability.

### Protocol-Boundary Outcomes

The processor boundary is not complete unless overload and refusal are visible at the
protocol edge.

This redesign therefore needs explicit outcome classes for:

- gossip:
  `accept` / `ignore` / `reject`
- liveness:
  answer / drop / disconnect

Internal queue overflow or refusal must not hide inside libp2p transport state or stalled
streams.

Req/resp response semantics matter too, but they belong to the sibling serving-domain
design rather than this gossip-processor refactor note.

### Egress Ownership

Outbound publication is part of the architecture.

This redesign must treat egress as processor-adjacent and decision-driven:

- outbound gossip publication must be triggered by authoritative decision records

Transport must not become a hidden outbound workflow engine.

### Durability And Replay Boundary

The processor redesign must name the durability boundary now.

For each object or artifact class, it must define:

- what must be durably committed before the decision is final
- what may be indexed asynchronously later
- what retention window must be preserved for serving obligations
- how replay reconstructs processor-visible state after restart
- whether replay resumes parked work, discards it, or reconstructs it from durable state

This applies at minimum to:

- recent blocks needed for retained serving obligations
- recent blob / sidecar / data-column artifacts needed for retained serving obligations
- canonical decision-relevant records
- any processor state that is not safe to reconstruct as empty

### Snapshot And Lifecycle Contract

Every cold-path or deferred job must run against an explicit snapshot handle, not an
ambient "current view".

This redesign must therefore define:

- immutable snapshot handles
- read barriers for acquiring them
- generation tags used for stale-result invalidation
- a snapshot retention budget
- eviction / recompute policy when the budget is exhausted

It must also define a lifecycle per object or artifact class:

- admitted
- parked
- waiting on snapshot or dependency
- ready on snapshot `S`
- importing / transforming
- persisted
- peer-effects applied
- retired

For each state: one owner, one legal handoff path, one cancellation rule.

### Operating Modes

The processor scheduler must be mode-aware.

At minimum:

- steady-state near head
- catch-up / head sync
- weak-subjectivity recovery and recent-data backfill
- degraded dependency mode

This redesign must not treat mode as a cosmetic flag. A separate owner must define:

- entry thresholds
- exit thresholds
- hysteresis
- degraded-mode service guarantees

Mode must affect budgets, expiry, persistence priority, and serving guarantees.

### Control Plane vs Data Plane

The refactor should be read through a strict control-plane / data-plane split.

#### Control plane

The control plane is the set of authoritative domains.

It owns:

- `BeaconProcessor`
- `BeaconNode`
- `Chain`
- fork choice
- peer / req-resp liveness policy
- discovery policy
- op pools
- queue admission
- queue priority
- deferred wait maps
- authoritative decision records
- final completion and import side effects

Responsibilities:

- decide what work is admitted
- decide what work is dropped
- decide what work waits
- decide what work resumes
- decide what work expires at each stage
- decide what protocol-visible outcome is emitted
- decide what must be persisted before a decision is final
- commit final results into mutable node / chain state

The control plane is policy and ownership.

#### Data plane

The data plane is the bounded execution domain.

It owns no mutable node or chain state.

It includes:

- shared BLS worker service
- queued regen worker
- state-work / STFN worker
- execution-runtime worker(s)

Responsibilities:

- verify signatures
- derive pre-states / checkpoint states
- run expensive state-transition compute
- perform external execution-side fetch / verify compute
- obey snapshot and ownership contracts attached to jobs

The data plane is execution only, not policy or result interpretation.

#### Completion path

All data-plane work must complete back into the control plane.

That means:

- workers never mutate `BeaconNode` directly
- workers never mutate `Chain` directly
- workers never emit gossip outcomes directly
- workers return owned results
- the control plane applies those results

This is the key durability rule. The system stays coherent if ownership and
mutation always return to the same single-writer boundary.

### Target Ownership

#### `P2pService`

Owns only transport concerns:

- drain gossipsub events
- report final validation results
- record invalid message penalties

Must not own gossip policy.

#### `gossip_ingress`

Becomes a thin adapter only:

- drain `GossipEvent.message`
- parse topic
- resolve fork sequence if cheap and stable
- build a typed gossip work item
- enqueue into `BeaconProcessor`

Must not:

- call `gossip_handler` directly
- decide `accept` / `ignore` / `reject`
- own deferred validation bookkeeping

#### `gossip_egress`

Should be treated as the symmetric transport adapter for outbound obligations:

- consume processor-owned decision records or egress actions
- publish outbound gossip only when the decision record allows it

Must not:

- invent publication policy
- publish without an authoritative decision record
- hide long-lived outbound workflow outside the processor / chain contracts

#### `BeaconProcessor`

Becomes the sole owner of gossip scheduling:

- typed gossip-ingress admission
- per-topic queueing
- per-topic drop policy
- phase-1 dispatch
- typed work dispatch
- deferred unknown-parent / missing-block-data state
- async BLS batch state
- final validation completion records

#### `GossipHandler`

Becomes pure topic logic:

- decode and parse
- cheap validation
- transformation from typed gossip-ingress work into prepared work or deferred action
- topic-specific import helpers

Must not:

- reference `BeaconProcessor`
- enqueue work directly
- own pending validation state
- own final validation outcome delivery

#### `BeaconNode`

Provides services and callbacks:

- chain access
- fork choice access
- execution access
- pool import callbacks
- peer-scoring callback helpers

Must stop owning gossip scheduling state.

### Processor-Owned Gossip State

The following state should move from `BeaconNode` into `BeaconProcessor` or a processor-owned helper:

- pending validation records
- completed validation records
- pending unknown-block gossip queue
- pending missing-block-data gossip queue
- pending async BLS batch list

This creates a single place where the lifecycle of a gossip message is visible end-to-end.

### Lifecycle Ownership

This redesign is not complete unless each object or artifact class has an explicit owner per
state.

For gossip objects and shared DA artifacts, define states such as:

- admitted
- parked
- waiting on snapshot or dependency
- ready on snapshot `S`
- importing / transforming
- persisted
- peer-effects applied
- retired

For each state, the design must name:

- current owner
- legal handoff target
- cancellation behavior
- durable representation, if any
- terminal decision record

Without this, "processor owns workflow, chain owns transformation" is only a slogan.

### Work Item Taxonomy

The processor should own two gossip stages.

#### Stage A: typed ingress

The first bounded gossip queues must be typed by topic class.

That does not require a fully decoded consensus object. It only requires enough information
to choose the correct queue and overload policy.

So the queue item may still carry owned raw bytes, but the lane itself must be typed.

Note on naming:

- current source code still contains transitional names such as `RawGossipWork`
- this note is stating the target model
- the target model should use `GossipWork` and typed ingress lane names because that is the clearer design

Proposed shape:

```zig
pub const GossipWork = union(enum) {
    block: BlockGossipWork,
    blob: BlobGossipWork,
    data_column: DataColumnGossipWork,
    attestation: AttestationGossipWork,
    aggregate: AggregateGossipWork,
    sync_message: SyncMessageGossipWork,
    sync_contribution: SyncContributionGossipWork,
    pool_object: PoolObjectGossipWork,
};

pub const BlockGossipWork = struct {
    source: GossipSource,
    message_id: MessageId,
    peer_id: PeerIdHandle,
    fork_seq: ForkSeq,
    fork_digest: [4]u8,
    seen_timestamp_ns: i64,
    block_bytes: GossipDataHandle,
};

pub const AttestationGossipWork = struct {
    source: GossipSource,
    message_id: MessageId,
    peer_id: PeerIdHandle,
    fork_seq: ForkSeq,
    fork_digest: [4]u8,
    subnet_id: u8,
    seen_timestamp_ns: i64,
    attestation_bytes: GossipDataHandle,
};
```

The key property is not "raw" versus "decoded".

The key property is:

- the queue identity is typed
- the payload bytes may remain raw until the topic handler runs

That is the correct protection boundary.

The thin transport adapter should only attach what transport actually knows:

- who sent the message
- which gossip topic it arrived on
- which fork/subnet it claims
- the owned wire bytes
- when the node saw it

It should not try to carry processor lifecycle state yet.

In particular:

- attempt ids are not an adapter field
- artifact identities are not an adapter field
- provenance fan-in is not an adapter field

Those belong to processor-owned objects created after typed admission.

#### Processor-owned admitted objects

After typed admission, the processor should materialize one of two concrete scheduler-owned
shapes:

- a message object for ordinary message-shaped gossip
- a shared artifact accumulator for DA-style reusable work

Ordinary message-shaped topics:

- blocks
- aggregates
- sync committee gossip
- slashings
- exits

These remain one admitted object per inbound message.

DA-style topics:

- blob sidecars
- data-column sidecars
- future partial DA fragment traffic

These should not stay "one message == one long-lived work item" once phase-1 parsing has
identified the reusable object boundary.

Suggested end-state shapes:

```zig
pub const AdmittedGossipObject = struct {
    object_id: GossipObjectId,
    admitted: GossipWork,
    deadlines: StageDeadlines,
    attempt_id: ?WorkAttemptId,
};

pub const DaArtifactAccumulator = struct {
    artifact_id: ArtifactId,
    kind: enum { blob_sidecar, data_column_sidecar },
    block_root: Root,
    shared_header: ?ArtifactHeader,
    fragments: BoundedFragmentSet,
    provenance: BoundedPeerFanIn,
    waiting: WaitingSet,
    deadlines: StageDeadlines,
};
```

The architectural point is concrete:

- `GossipWork` is the typed admitted message object
- `AdmittedGossipObject` is the ordinary scheduler object
- `DaArtifactAccumulator` is the reusable DA scheduler object

That is where attempt identity, provenance, and dependency state belong.

#### Attempt identity in this design

`WorkAttemptId` should be minted by the processor when an admitted object crosses into a
cold-path or deferred lifecycle, for example:

- parked on missing block
- parked on missing block-associated data
- submitted to chain compute
- submitted to async BLS

It should identify which admitted object or artifact attempt a later completion is allowed
to resume.

It is not part of the typed ingress object.

The conceptual split is:

- `ValidationSnapshotHandle`: what exact view did this work read?
- `WorkAttemptId`: which parked or admitted object attempt may this completion resume?

#### Provenance in this design

Per-peer provenance should live only on shared reusable artifacts.

For ordinary message-shaped gossip, peer accountability remains on the message object and
its terminal decision record.

For DA artifacts, provenance must be:

- keyed by contributing peer and fragment kind
- hard-capped per artifact
- compressible after the cap
- sufficient to drive peer scoring even when expensive validation is deduplicated

#### Stage B: typed gossip work

Reuse the current typed processor items where possible:

- `gossip_block`
- `gossip_execution_payload`
- `gossip_blob`
- `gossip_data_column`
- `attestation`
- `aggregate`
- `sync_message`
- `sync_contribution`
- pool objects

The current typed layer in `src/processor/work_item.zig` is still useful. The issue is not the typed queue model; it is where the boundary currently starts.

### Queue Classes

#### Typed fast-lane ingress queues

These must be admitted and serviced before attestation pressure:

- beacon block ingress
- execution payload ingress
- blob sidecar ingress
- data column sidecar ingress

#### Typed ingress control and overload queues

Typed attestation ingress is the explicit overload queue, matching Lodestar's
network-processor shape.

- beacon attestation ingress: indexed or grouped overload queue

Other typed gossip control topics stay separate from the explicit overload band:

- aggregate and proof ingress: LIFO
- sync committee message ingress: LIFO
- sync contribution and proof ingress: LIFO

Important:

- the first overload boundary for attestations belongs at the typed ingress boundary
- duplicate-aware grouping and batch formation may happen in the next attestation-preparation step
- the later attestation queues must not repeat first-stage overload policy in the end state

#### Deferred wait maps

Processor-owned maps:

- awaiting block by root
- awaiting block data by root

Block-data waiting is still keyed by beacon block root.

Both bounded and expiring.

### Handler Contract Redesign

Current `GossipProcessResult` is transport-shaped:

- `accepted`
- `deferred`
- `ignored`
- `rejected`
- `failed`

That contract is not ideal once the processor owns scheduling.

Replace it with a processor-facing action contract:

```zig
pub const GossipPhase1Action = union(enum) {
    ignore,
    reject: GossipRejectReason,
    park_on_block: [32]u8,
    park_on_block_data: [32]u8,
    update_artifact: ArtifactUpdate,
    request_chain_compute: ChainComputeRequest,
    enqueue_typed: WorkItem,
};
```

Properties:

- no transport result language
- no direct acceptance reporting
- `gossip_handler` only returns what the processor should do next

`update_artifact` is how DA-style reusable work stops pretending it is just another queued
message.

It means:

- phase-1 parsing found a shared artifact boundary
- the processor should merge this contribution into a bounded accumulator
- expensive validation, dependency waiting, and eventual publication now hang off that
  artifact lifecycle instead of one admitted message directly

Then the processor decides when a message becomes:

- final accept
- final ignore
- final reject

`park_on_block_data` is keyed by the beacon block root whose associated data is
missing, not by a separate invented identity.

### Decision Record And Validation Completion Model

The processor should own an authoritative decision record, then derive transport-facing
validation completion from it.

Suggested processor-owned decision record:

```zig
pub const GossipDecisionRecord = struct {
    object_id: GossipObjectId,
    message_id: MessageId,
    peer_id: PeerIdHandle,
    topic_type: GossipTopicType,
    verdict: enum { accept, ignore, reject },
    reject_reason: ?GossipRejectReason = null,
    should_forward: bool,
    persistence: enum { none, best_effort, required },
    peer_effect: enum { none, penalize_invalid, penalize_liveness },
    seen_effect: SeenEffect,
};
```

Transport-facing completion remains:

```zig
pub const GossipValidationCompletion = struct {
    message_id: MessageId,
    peer_id: PeerIdHandle,
    topic_type: GossipTopicType,
    outcome: enum { accept, ignore, reject },
    reject_reason: ?GossipRejectReason = null,
};
```

Rules:

- `GossipDecisionRecord` is the authoritative hot-path outcome for the object
- `GossipValidationCompletion` is derived from that record for gossip transport
- seen-set / anti-equivocation updates, forwarding permission, and peer effects are driven
  from the same record
- other authoritative domains may consume the record asynchronously, but the hot path does
  not wait on acknowledgments

`p2p_runtime` should only drain processor-owned completions and forward them to
`P2pService.reportGossipValidationResult()`.

This mirrors Lodestar's `pendingGossipsubMessage -> gossipMessageValidationResult` seam.

### Async BLS Ownership

Current async BLS batch state is owned by `BeaconNode`.

That should move under the processor boundary too.

Rationale:

- batch readiness is already coupled to queue dispatch policy
- batch completion directly determines gossip accept/ignore/reject outcomes
- this is scheduler state, not node-global state

Preferred shape:

- processor forms attestation/aggregate/sync-message batches
- processor submits async verification jobs
- processor marks in-flight batches
- processor consumes completed batches and emits final typed import or final rejection

### Processor-To-Chain Compute Contract

The processor owns scheduling, but it must not own regen or STFN execution.

So cold-path validation needs an explicit processor-to-chain-compute contract.

Suggested minimal shape:

```zig
pub const ChainComputeRequest = union(enum) {
    gossip_phase2: struct {
        work: WorkItem,
        snapshot: SnapshotHandle,
        attempt_id: WorkAttemptId,
    },
};

pub const ChainComputeCompletion = union(enum) {
    ignore,
    reject: GossipRejectReason,
    park_on_block: Root,
    park_on_block_data: Root,
    enqueue_typed: WorkItem,
};
```

`ChainComputeRequest`, `ValidationSnapshotHandle`, and `WorkAttemptId` need a real meaning
here.

Concrete rule:

- the processor mints an attempt id only when it submits cold-path or deferred work
- that attempt id identifies the admitted object or artifact attempt to resume
- the snapshot handle identifies the exact read view used to derive the request
- completions are valid only if both the snapshot handle and the attempt id still match

That is the actual contract. The pair exists to prevent a late cold-path result from being
applied to the wrong parked object or the wrong fork-choice view.

Processor-side rules:

- `request_chain_compute` means "this admitted object or artifact needs chain-owned cold-path work"
- `BeaconProcessor` may only submit that request if chain compute can accept work
- the request must name the exact snapshot handle it was derived from
- late completions must be dropped if snapshot or attempt id no longer match
- `BeaconProcessor` owns waiting for completion
- `ChainRuntime` owns actual execution
- completion comes back to the processor before any transport result is finalized
- snapshot handles must obey a bounded retention budget and recompute policy

### Resulting Runtime Flow

Target flow:

1. `P2pService` drains gossip events.
2. `gossip_ingress` classifies by topic and builds typed `GossipWork`.
3. `BeaconProcessor` enqueues typed ingress work by topic class.
4. `BeaconProcessor` schedules typed ingress work with block/blob/data-column priority.
5. `gossip_handler` performs phase-1 decode and classification on the typed ingress item.
6. The handler returns a `GossipPhase1Action`.
7. The processor either:
   - rejects immediately
   - ignores immediately
   - parks on missing block or missing block-associated data
   - merges a contribution into a shared artifact accumulator
   - submits cold-path chain compute
   - enqueues typed work
8. Chain compute completions, BLS completions, and artifact-resolution events return to the
   processor.
9. Typed work runs through existing priority queues and BLS/import stages.
10. The processor writes one authoritative decision record for any terminal outcome.
11. Transport-facing validation completion and any egress publication are derived from that
    record.
12. `p2p_runtime` drains completions and egress actions into transport adapters.

No cross-domain synchronous acknowledgment is on the hot path between steps 10 and 12.

### Metrics To Require

The processor boundary should expose:

- typed ingress queue depth by topic class
- typed ingress drops by topic class
- typed gossip queue depth by topic class
- deferred parked count by topic class and reason
- decision-record counts by topic and verdict
- time spent waiting in typed ingress queue
- time spent waiting in prepared typed queue
- async BLS in-flight batch counts
- final validation results by topic class
- stale-completion drops
- snapshot handles retained and evicted
- protocol-boundary overload outcomes
- per-artifact provenance cap hits
- mode transitions and time spent per mode

This replaces opaque generic pressure with observable per-topic pressure.

### Migration Plan

#### Phase 1

- Add typed `GossipWork`
- Add typed gossip-ingress queues to `BeaconProcessor`
- Change `gossip_ingress` to enqueue typed gossip work only

#### Phase 2

- Introduce `GossipPhase1Action`
- Make `gossip_handler` return processor-facing actions instead of transport-facing outcomes

#### Phase 3

- Move pending validation completion state into processor
- Move unknown-block / missing-block-data parked state into processor

#### Phase 4

- Move pending async BLS batch state into processor
- Remove gossip lifecycle ownership from `BeaconNode`

#### Phase 5

- Delete processor coupling from `gossip_handler`
- make `gossip_handler` pure enough for isolated topic tests

#### Phase 6

- Introduce processor-owned egress actions derived from decision records
- Introduce processor-owned mode input and expiry ownership
- Make shared-artifact resolution emit per-message outcomes without losing provenance

### Acceptance Criteria

The redesign is successful when:

- under attestation flood, block/blob/data-column gossip is still serviced promptly
- attestation shedding happens before block shedding
- there is one clear owner for gossip admission and completion
- shared DA validation is deduplicated at the artifact boundary without losing per-peer
  accountability
- protocol-boundary overload is explicit rather than hidden in transport backpressure
- one decision record drives verdict, seen/anti-equivocation effects, forwarding
  permission, peer effects, and persistence obligations
- stale cold-path completions are dropped by attempt-id/snapshot mismatch instead of being
  applied late
- restart/replay can reconstruct required recent-serving state without blocking the hot
  path on ad hoc recovery
- the processor consumes an explicit scheduler mode with hysteresis rather than inferring
  contradictory local policies
- `BeaconNode` no longer owns gossip queue lifecycle state
- `gossip_handler` no longer owns queueing policy
- metrics show per-topic pressure, not just generic pending-validation saturation

### Next Grounded Step

Produce a migration-oriented API sketch:

- new typed gossip-ingress work item types and queue placement
- new processor methods for gossip admission and completion draining
- new `GossipPhase1Action` contract
- list of exact `BeaconNode` fields and functions to move or delete

### API Sketch

This section is the next grounded step: concrete API shape, tied to the existing codebase.

#### New work item families

Add a typed gossip-ingress family ahead of the current prepared/import family.

Suggested `WorkType` additions:

- `gossip_block_ingress`
- `gossip_execution_payload_ingress`
- `gossip_blob_ingress`
- `gossip_data_column_ingress`
- `gossip_attestation_ingress`
- `gossip_aggregate_ingress`
- `gossip_sync_contribution_ingress`
- `gossip_sync_message_ingress`
- `gossip_voluntary_exit_ingress`
- `gossip_proposer_slashing_ingress`
- `gossip_attester_slashing_ingress`
- `gossip_bls_to_exec_ingress`
- `gossip_payload_attestation_ingress`
- `gossip_execution_payload_bid_ingress`
- `gossip_proposer_preferences_ingress`

These should sit ahead of the current typed gossip items in priority order.

The existing typed items remain:

- `gossip_block`
- `gossip_execution_payload`
- `gossip_blob`
- `gossip_data_column`
- `attestation`
- `aggregate`
- `sync_message`
- `sync_contribution`
- pool objects

This preserves the current phase-2 queue model while moving the first protected queue
earlier.

#### Typed ingress work structs

Do not use one common raw shape as the target model.

Use a typed `GossipWork` family instead. The bytes inside each variant may stay raw until
the corresponding topic handler runs.

```zig
pub const GossipWork = union(enum) {
    block: BlockGossipWork,
    blob: BlobGossipWork,
    data_column: DataColumnGossipWork,
    attestation: AttestationGossipWork,
    aggregate: AggregateGossipWork,
    sync_message: SyncMessageGossipWork,
    sync_contribution: SyncContributionGossipWork,
    pool_object: PoolObjectGossipWork,
};
```

Do not push lifecycle concepts into these structs. They are typed ingress work objects.

The point is not to decode early.

The point is to ensure the first bounded queue is already topic-aware.

Within each typed work object:

- message bytes may still be raw
- transport metadata may stay minimal
- overload policy is now correct at the first queue boundary

This is better than an untyped raw queue because:

- blocks, blobs, and data columns can be protected immediately
- attestations can enter an overload lane immediately
- later topic-specific restructuring can still happen inside the same scheduler

Examples of later restructuring:

- attestation ingress lane:
  owned bytes first, then decode-and-index into batch groups
- DA ingress lane:
  per-message admission first, then collapse into a shared artifact accumulator

#### Shared-artifact objects

Artifact-aware admission must be explicit in the API sketch too.

For DA-style reusable work, the processor should own an artifact accumulator separate from
`GossipWork`.

Suggested shape:

```zig
pub const ArtifactUpdate = union(enum) {
    blob_sidecar: BlobArtifactFragment,
    data_column_sidecar: DataColumnArtifactFragment,
};

pub const DaArtifactAccumulator = struct {
    artifact_id: ArtifactId,
    block_root: Root,
    header: ?ArtifactHeader,
    fragments: BoundedFragmentSet,
    provenance: BoundedPeerFanIn,
    deadlines: StageDeadlines,
};
```

The important part is not the exact field names. The important part is the boundary:

- typed ingress owns admitted message work
- the processor owns shared reusable artifacts
- peer provenance stays attached to the artifact accumulator rather than vanishing into
  deduplication

#### Processor public API

Existing processor entry points:

- `ingest()`
- `dispatchOne()`
- `tick()`

Add processor-owned gossip APIs:

```zig
pub fn ingestGossipWork(self: *BeaconProcessor, work: GossipWork) void
pub fn onImportedBlock(self: *BeaconProcessor, block_root: Root) void
pub fn onImportedBlockData(self: *BeaconProcessor, block_root: Root) void
pub fn onChainComputeCompletion(self: *BeaconProcessor, completion: ChainComputeCompletion) void
pub fn onGossipClockSlot(self: *BeaconProcessor, slot: u64) void
pub fn popValidationCompletion(self: *BeaconProcessor) ?GossipValidationCompletion
```

Properties:

- `ingestGossipWork()` is the only typed gossip admission entry point
- `onImportedBlock()` and `onImportedBlockData()` replace node-owned release logic for
  missing block roots and missing block-associated data
- `onChainComputeCompletion()` is the only cold-path completion entry point
- `onGossipClockSlot()` owns expiry for parked messages
- `popValidationCompletion()` is the only transport-result drain point

#### Handler contract

Replace transport-shaped phase-1 output with processor-shaped actions.

```zig
pub const GossipPhase1Action = union(enum) {
    ignore,
    reject: GossipRejectReason,
    park_on_block: Root,
    park_on_block_data: Root,
    update_artifact: ArtifactUpdate,
    request_chain_compute: ChainComputeRequest,
    enqueue_typed: WorkItem,
};
```

And add a handler entry point shaped for typed ingress work:

```zig
pub const GossipValidationContext = struct {
    snapshot: ValidationSnapshotHandle,
    slot: u64,
    epoch: u64,
    finalized_slot: u64,
    fork_seq: ForkSeq,
};

pub fn classifyGossipWork(
    self: *const GossipHandler,
    ctx: GossipValidationContext,
    work: *const GossipWork,
) GossipPhase1Action
```

Important:

- this function does not enqueue
- this function does not report gossipsub results
- this function does not mutate processor-owned deferred state

It only answers: what should the scheduler do next for this typed ingress item?

For DA topics, the important non-message-shaped answer is `update_artifact`.
That is the concrete place where the design stops pretending that one inbound message is
the real durable unit of work.

#### Completion records

Processor-owned completion item:

```zig
pub const GossipValidationCompletion = struct {
    message_id: MessageId,
    peer_id: PeerIdHandle,
    topic_type: GossipTopicType,
    outcome: enum {
        accept,
        ignore,
        reject,
    },
    reject_reason: ?GossipRejectReason = null,
};
```

This replaces the current node-owned:

- `pending_gossip_validations`
- `completed_gossip_validations`

#### Gossip publish actions

Processor-owned gossip publication should be explicit too.

Suggested shape:

```zig
pub const GossipPublishAction = union(enum) {
    publish_gossip: struct {
        topic_type: GossipTopicType,
        payload: GossipDataHandle,
    },
};
```

The exact payload wrappers may change. The contract should not:

- gossip publication is derived from authoritative decision records
- gossip publication is bounded and drainable
- transport adapters execute it, but do not invent it

#### Deferred state

Processor-owned parked message state should replace the current node-owned unknown-block gossip queue.

Suggested processor-owned helpers:

```zig
const AwaitingBlockGossip = struct { ... };
const AwaitingBlockDataGossip = struct { ... };
```

The processor should own:

- bounded parking by root
- retry / release policy
- expiry by slot
- completion as `ignore` on expiry/drop

This mirrors Lodestar's processor-owned awaiting maps instead of our current `BeaconNode` ownership.

#### Chain compute service contract

The processor must not reach into regen / STFN internals directly.

Use one explicit chain-compute service boundary:

```zig
pub fn chainComputeCanAcceptValidationWork(self: *const ChainCompute) bool
pub fn submitChainCompute(self: *ChainCompute, req: ChainComputeRequest) !void
pub fn popChainComputeCompletion(self: *ChainCompute) ?ChainComputeCompletion
```

The processor should consult both:

- BLS capacity
- chain-compute capacity

before dispatching cold-path validation work.

### Exact Move / Delete Inventory

#### Fields to move out of `BeaconNode`

Move these fields into `BeaconProcessor`:

- `pending_gossip_validations`
- `completed_gossip_validations`
- `pending_unknown_block_gossip`
- `pending_gossip_bls_batches`

Current locations:

- `src/node/beacon_node.zig`
- `src/node/lifecycle.zig`

#### Functions whose logic should move into processor-owned helpers

Move or delete the logic behind:

- `beginPendingGossipValidation`
- `finishPendingGossipValidation`
- `drainCompletedGossipValidations`
- `releasePendingUnknownBlockGossip`
- `requeuePendingUnknownBlockGossipItem`
- `drainDroppedPendingUnknownBlockGossip`
- `processPendingGossipBlsBatch`
- `flushPendingGossipBlsBatch`

These are currently `BeaconNode` responsibilities but are scheduler responsibilities.

#### Callback wiring to re-evaluate

Current `gossip_handler` wiring in `p2p_runtime`:

- `queueUnknownBlockFn`
- `queueUnknownBlockAttestationFn`
- `queueUnknownBlockAggregateFn`
- `importResolvedAttestationFn`
- `importResolvedAggregateFn`
- `importSyncCommitteeMessageFn`
- verification callbacks

Target direction:

- keep import and verification callbacks
- remove queue-ownership callbacks from `gossip_handler`

Specifically, the following queue callbacks should disappear from the handler contract:

- `queueUnknownBlockFn`
- `queueUnknownBlockAttestationFn`
- `queueUnknownBlockAggregateFn`

They should be replaced by `GossipPhase1Action.park_on_block` or `.park_on_block_data`.

### Immediate Design Constraints

To keep the migration coherent:

- do not create a second processor
- do not let `gossip_handler` own queue transitions in the end state
- do not leave completion state split between processor and node
- do not keep async BLS ownership in `BeaconNode` once typed gossip-ingress admission moves into the processor

### Implementation Sequence

The least-thrashy implementation order is:

1. Introduce typed `GossipWork` items and typed ingress queues.
2. Change ingress to enqueue typed gossip work instead of invoking `gossip_handler`.
3. Teach the processor to invoke `gossip_handler.classifyGossipWork()`.
4. Move completion state into the processor.
5. Move unknown-block / missing-block-data parked state into the processor.
6. Move async gossip BLS batch state into the processor.
7. Delete old node-owned gossip lifecycle code.

### Scheduler Table

This section locks the intended dispatch order for the redesigned single processor.

The key design rule is:

- typed fast-lane gossip ingress must be prioritized early so blocks / DA objects enter the system promptly
- prepared fast-lane imports must run before overload classes
- attestation-style overload must be the first class that gets shed under pressure

#### Priority bands

| Band | Work family | Examples | Queue class | Drop policy | Rationale |
| --- | --- | --- | --- | --- | --- |
| 0 | Sync / RPC | `chain_segment`, `rpc_block`, `rpc_blob`, `rpc_custody_column` | FIFO | bounded FIFO | existing highest-priority sync work |
| 1 | Typed fast-lane gossip ingress | `gossip_block_ingress`, `gossip_execution_payload_ingress`, `gossip_blob_ingress`, `gossip_data_column_ingress` | FIFO | bounded FIFO, newest dropped on overflow only after full queue | keep block / DA admission ahead of overload |
| 2 | Prepared fast-lane gossip | `delayed_block`, `gossip_block`, `gossip_execution_payload`, `gossip_blob`, `gossip_data_column` | FIFO | bounded FIFO | preserve current production block / DA import priority |
| 3 | Typed control gossip ingress | `gossip_aggregate_ingress`, `gossip_sync_contribution_ingress`, `gossip_sync_message_ingress`, `gossip_voluntary_exit_ingress`, `gossip_proposer_slashing_ingress`, `gossip_attester_slashing_ingress`, `gossip_bls_to_exec_ingress`, `gossip_payload_attestation_ingress`, `gossip_execution_payload_bid_ingress`, `gossip_proposer_preferences_ingress` | FIFO or LIFO by topic | bounded, topic-specific | low-volume or control-path gossip should not starve behind attestation flood |
| 4 | Prepared control gossip | `aggregate`, `sync_contribution`, `sync_message`, `gossip_payload_attestation`, `gossip_execution_payload_bid`, `gossip_proposer_preferences`, pool objects | FIFO or LIFO by topic | bounded, topic-specific | preserves current aggregate / sync / pool ordering |
| 5 | Typed overload gossip ingress | `gossip_attestation_ingress` | LIFO or grouped overload queue | explicit overload queue | first class allowed to absorb / shed load |
| 6 | Prepared overload gossip | `attestation` | simple typed queue | bounded, should stay small after attestation preparation | later stage no longer owns first-stage overload policy |
| 7 | Deferred reprocessing | parked-on-block / parked-on-block-data releases | LIFO | bounded, expiring | reprocess only after fast-lane and control work |
| 8 | Low priority | `api_request_p1`, `backfill_segment`, light client | FIFO | bounded FIFO | dead-last work |

#### Notes on the table

- Band 5 is the explicit overload band. If we need to drop production-valid traffic under pressure, this is the first place it should happen.
- `aggregate` stays above `attestation`, matching current processor intent and Lodestar's practical ordering.
- Low-volume pool objects are deliberately not lumped into the attestation overload band.
- The table is about scheduling ownership, not about who ultimately imports the object.

### Dispatch Policy

The processor should not simply sort all typed ingress work above all prepared typed work.
That would create a new starvation failure mode.

Use a staged dispatch policy inside one processor tick:

1. Finish ready async BLS batch completions.
2. Release parked gossip made runnable by imported block / block-data notifications.
3. Drain fast-lane typed gossip ingress up to a bounded fast-lane budget.
4. Drain prepared fast-lane gossip up to a bounded fast-lane budget.
5. Alternate between control bands and overload bands until `max_items` is reached.

Recommended invariants:

- typed fast-lane ingress may run ahead of prepared overload
- prepared fast-lane may run ahead of ingress overload
- ingress overload must never monopolize the whole tick
- prepared overload must not starve control-path ingress forever

This means the processor needs small per-band budgets, not just one global `max_items`.

Suggested initial shape:

```zig
const TickBudgets = struct {
    fast_lane_raw: u32 = 16,
    fast_lane_typed: u32 = 16,
    control: u32 = 32,
    overload: u32 = 32,
    reprocess: u32 = 8,
};
```

These are design defaults, not locked constants. They exist to make the scheduling model explicit and measurable.

### Stage Deadlines

The scheduler must not treat "expiry" as one timestamp per object.

For relevant classes, it should track at least:

- forward-by
- validate-by
- persist-by
- serve-by
- accounting-by

Missing the forward deadline may still permit persistence, anti-equivocation, or future
serving side effects. Terminal handling must follow stage deadlines, not one naive
"stale therefore dead" rule.

### Mode Ownership And Hysteresis

The processor scheduler must be parameterized by an explicit mode owner, not a loose set of
signals.

That owner should define:

- steady-state near head
- catch-up / head sync
- weak-subjectivity recovery and recent-data backfill
- degraded dependency mode

And must own:

- entry thresholds
- exit thresholds
- hysteresis
- degraded-mode service guarantees
- mode-specific queue budgets and reservations

The processor should consume mode as authoritative input. It should not infer mode
independently from ad hoc local symptoms.

### Protocol Refusal / Overload Outcomes

Scheduler refusal must map to explicit protocol-boundary behavior:

- gossip:
  final `accept` / `ignore` / `reject`
- liveness:
  answer, drop, or disconnect behavior

If a queue is full or a class budget is exhausted, the redesign must still specify the
wire-visible result instead of silently relying on transport backpressure.

Req/resp overload semantics should be handled by the sibling serving-domain design, not by
gossip `BeaconProcessor` ownership.

### `p2p_runtime` After Redesign

Once the processor owns gossip lifecycle state, `p2p_runtime` should shrink to orchestration only.

#### Responsibilities to keep

- drain completed discovery dials
- run sync services
- run execution / block-state side work
- ingest typed gossip work into processor
- tick processor
- drain processor-owned validation completions into `P2pService`
- drain processor-owned gossip publication actions into transport adapters

#### Responsibilities to remove from `p2p_runtime`

These should no longer be direct runtime-owned gossip lifecycle steps:

- `processPendingGossipBlsBatch()`
- hidden outbound publication decisions
- `drainCompletedGossipValidations()`
- `drivePendingUnknownBlockGossip()`
- direct `gossip_ingress -> gossip_handler` invocation

Current runtime tick has these responsibilities split across:

- `processPendingGossipBlsBatch()`
- `bp.tick(128)`
- `drainCompletedGossipValidations()`
- `drivePendingUnknownBlockGossip()`
- `gossip_ingress_mod.processEvents(...)`

The end-state should reduce that to:

```zig
did_work = ingestTypedGossipEventsIntoProcessor(self, io, svc) or did_work;
did_work = bp.tick(processor_tick_budget) > 0 or did_work;
did_work = drainProcessorGossipCompletions(self, io, svc) or did_work;
did_work = drainProcessorGossipPublishes(self, io, svc) or did_work;
```

#### Imported block / block-data notifications

Do not keep imported-block release logic as a runtime polling concern.

Prefer direct notifications from import paths into the processor:

- `bp.onImportedBlock(root)`
- `bp.onImportedBlockData(root)`

This removes the need for runtime-owned `drivePendingUnknownBlockGossip()`.

### Deletion Candidates In End State

These pieces should disappear or become thin wrappers once the redesign is complete:

- `gossip_ingress.processValidatedMessage()` as a direct handler caller
- `GossipHandler.beacon_processor`
- handler queue-ownership callbacks for unknown block parking
- node-owned pending validation completion storage
- node-owned pending gossip BLS batch storage

### Final Design Test

The design is coherent if all of the following are true:

- a typed gossip-ingress message has exactly one scheduler owner from admission to completion
- a DA-sidecar contribution can transition from admitted-message ownership into a shared
  artifact accumulator without losing peer provenance
- a shared artifact resolution can emit per-message outcomes without redoing expensive
  validation per peer
- `gossip_handler` cannot enqueue or complete transport results on its own
- gossip-visible overload outcomes and outbound publication both flow only from
  processor-owned decisions
- `BeaconNode` can be reasoned about without knowing gossip queue internals
- `p2p_runtime` can be read as orchestration rather than gossip policy
- attestation overload can be isolated without risking block starvation
- mode changes, stale completion drops, and replay obligations are explicit rather than
  ambient behavior

### Implementation Contract

This section locks the concrete contract that implementation should target.

The goal is to make the migration mechanical:

- exact new work families
- exact processor entrypoints
- exact handler contract
- exact queue ownership
- explicit test migration

#### `WorkType` end state

`WorkType` is an internal scheduler enum. Its ordinal values are not part of any external protocol, so contiguous renumbering is acceptable if it makes the new boundary clear.

The end-state order should be:

1. Sync / RPC
   - `chain_segment`
   - `rpc_block`
   - `rpc_blob`
   - `rpc_custody_column`
2. Typed fast-lane gossip ingress
   - `gossip_block_ingress`
   - `gossip_execution_payload_ingress`
   - `gossip_blob_ingress`
   - `gossip_data_column_ingress`
3. Prepared fast-lane gossip
   - `delayed_block`
   - `gossip_block`
   - `gossip_execution_payload`
   - `gossip_blob`
   - `gossip_data_column`
   - `column_reconstruction`
4. High-priority API
   - `api_request_p0`
5. Typed control gossip ingress
   - `gossip_aggregate_ingress`
   - `gossip_sync_contribution_ingress`
   - `gossip_sync_message_ingress`
   - `gossip_payload_attestation_ingress`
   - `gossip_execution_payload_bid_ingress`
   - `gossip_proposer_preferences_ingress`
   - `gossip_voluntary_exit_ingress`
   - `gossip_proposer_slashing_ingress`
   - `gossip_attester_slashing_ingress`
   - `gossip_bls_to_exec_ingress`
6. Prepared control gossip
   - `aggregate`
   - `aggregate_batch`
   - `gossip_payload_attestation`
   - `sync_contribution`
   - `sync_message`
   - `sync_message_batch`
   - `gossip_execution_payload_bid`
   - `gossip_proposer_preferences`
   - `gossip_attester_slashing`
   - `gossip_proposer_slashing`
   - `gossip_voluntary_exit`
   - `gossip_bls_to_exec`
7. Typed overload gossip ingress
   - `gossip_attestation_ingress`
8. Prepared overload gossip
   - `attestation`
9. Low priority
   - `api_request_p1`
   - `backfill_segment`
   - light client work
10. Internal
   - `artifact_ready`
   - `slot_tick`
   - `reprocess`

Two current `WorkType`s should disappear:

- `unknown_block_aggregate`
- `unknown_block_attestation`

Those are artifacts of node-owned deferred queues. In the redesigned boundary, parked gossip lives in processor-owned wait maps and is re-enqueued internally when a block or block-data notification arrives.

`artifact_ready` is the corresponding internal trigger for shared DA artifacts. It is how
an artifact accumulator re-enters scheduling once enough fragments, validation results, or
dependencies make it runnable.

#### Typed ingress queue classes

The typed ingress queue types should be explicit and mirror Lodestar where that fits the new boundary:

- `gossip_block_ingress`: FIFO
- `gossip_execution_payload_ingress`: FIFO
- `gossip_blob_ingress`: FIFO
- `gossip_data_column_ingress`: FIFO
- `gossip_aggregate_ingress`: LIFO
- `gossip_sync_contribution_ingress`: LIFO
- `gossip_sync_message_ingress`: LIFO
- `gossip_payload_attestation_ingress`: FIFO
- `gossip_execution_payload_bid_ingress`: FIFO
- `gossip_proposer_preferences_ingress`: FIFO
- `gossip_voluntary_exit_ingress`: FIFO
- `gossip_proposer_slashing_ingress`: FIFO
- `gossip_attester_slashing_ingress`: FIFO
- `gossip_bls_to_exec_ingress`: FIFO
- `gossip_attestation_ingress`: LIFO overload queue

Important constraint:

- do not duplicate attestation batching in both ingress and prepared stages

Lodestar's attestation ingress queue is indexed because its network processor performs
attestation batch validation there.

So the end-state rule is:

- typed attestation-ingress queue owns the first overload boundary
- later attestation preparation owns duplicate-aware grouping and batch validation
- the post-prepare attestation queue no longer owns first-stage overload policy

The current `WorkQueues.attestation_group_counts` logic is transitional and
should disappear once typed attestation-ingress grouping is in place.

#### Processor API

The processor should expose an explicit gossip boundary instead of a generic `ingest()` call being the only admission seam.

Proposed entrypoints:

```zig
pub fn ingestGossipWork(self: *BeaconProcessor, work: GossipWork) void;

pub fn onImportedBlock(self: *BeaconProcessor, block_root: Root) void;

pub fn onImportedBlockData(self: *BeaconProcessor, block_root: Root) void;

pub fn onChainComputeCompletion(self: *BeaconProcessor, completion: ChainComputeCompletion) void;

pub fn updateSchedulerMode(self: *BeaconProcessor, mode: SchedulerMode) void;

pub fn popValidationCompletion(self: *BeaconProcessor) ?GossipValidationCompletion;

pub fn popGossipPublishAction(self: *BeaconProcessor) ?GossipPublishAction;
```

Design notes:

- `ingestGossipWork()` must own queue-full drop behavior and any immediate completion records caused by that drop
- `onImportedBlock()` releases processor-owned waiters parked on `beacon_block_root`
- `onImportedBlockData()` releases processor-owned waiters keyed by the block root whose associated block data became available
- `onChainComputeCompletion()` is the only cold-path completion entry point
- `updateSchedulerMode()` makes mode an explicit input owned elsewhere, not an inferred
  local heuristic
- `popValidationCompletion()` keeps completion draining allocation-free and runtime-simple
- `popGossipPublishAction()` is how outbound gossip publication stays decision-driven
  instead of becoming hidden transport workflow

The generic typed `ingest()` path can remain, but only for non-gossip producers such as sync / RPC / API / slot-tick work.

#### Handler contract

The current `GossipHandler` setter-style contract is too stateful:

- `updateClock(...)`
- `updateForkSeq(...)`
- `processGossipMessageWithSubnetAndMetadata(...)`

The redesigned contract should pass an explicit validation snapshot into a pure-ish phase-1 classifier:

```zig
pub const GossipValidationContext = struct {
    snapshot: ValidationSnapshotHandle,
    slot: u64,
    epoch: u64,
    finalized_slot: u64,
    fork_seq: ForkSeq,
};

pub fn classifyGossipWork(
    self: *const GossipHandler,
    ctx: GossipValidationContext,
    work: *const GossipWork,
) GossipPhase1Action;
```

This is a better boundary for three reasons:

- the scheduler does not need mutable handler-global clock state
- `gossip_handler` can be unit-tested without runtime orchestration
- it makes the phase-1 inputs explicit instead of ambient

And one further reason:

- it gives phase-1 one coherent read handle instead of encouraging mixed ambient reads

The existing `GossipPhase1Action` shape still holds:

```zig
pub const GossipPhase1Action = union(enum) {
    ignore,
    reject: GossipRejectReason,
    park_on_block: Root,
    park_on_block_data: Root,
    update_artifact: ArtifactUpdate,
    request_chain_compute: ChainComputeRequest,
    enqueue_typed: WorkItem,
};
```

`ValidationSnapshotHandle` is the read-consistency anchor for phase-1 classification.
It should represent one coherent control-plane view, not a bag of copied fields.

#### `gossip_ingress` contract

`gossip_ingress` should stop being a validation-result boundary and become a thin typed-work builder.

End-state responsibility:

- drain `P2pService` gossip events
- parse topic
- resolve fork sequence
- build `GossipWork`
- call `bp.ingestGossipWork(work)`

It should no longer:

- call `gossip_handler`
- begin pending validation tracking
- report `accept` / `ignore` / `reject` directly to `P2pService`

For DA-heavy topics, `gossip_ingress` is still only a typed-work builder. It does not own
artifact accumulation. That happens only after processor-owned phase-1 classification
returns `update_artifact`.

#### `processorHandlerCallback` contract

`processorHandlerCallback(item, context)` can remain, but its scope becomes narrower and cleaner:

- it handles typed processor items only
- it does not own unknown-block release
- it does not own validation completion bookkeeping
- it does not own typed gossip-ingress admission

That means the existing typed-import integration tests remain useful.

#### Test migration

The current tests split cleanly into three groups.

##### Tests that should survive with minor updates

These still describe real invariants after the redesign:

- `BeaconProcessor: ingest and dispatch priority order`
- `BeaconProcessor: tick processes limited items`
- `BeaconProcessor: blocks dispatched before attestations`
- `WorkQueues: route and pop priority order`
- `WorkQueues: gossip bls dispatch gate defers attestation and aggregate work`
- `WorkQueues: sync message batching holds briefly for a fuller batch`

These tests need only enough updates to account for the inserted typed gossip-ingress
bands and the reserved peer-service budget.

##### Tests that should remain, but with tightened meaning

These should continue to exist because typed import dispatch still matters:

- `processorHandlerCallback imports queued voluntary exits`
- `processorHandlerCallback imports queued aggregates`
- `processorHandlerCallback imports queued aggregate batches`
- `processorHandlerCallback imports queued attestations`
- `processorHandlerCallback imports queued sync committee messages`
- `processorHandlerCallback imports queued blob sidecars`
- `processorHandlerCallback imports queued data column sidecars`

Their meaning changes slightly:

- they are typed dispatch integration tests
- they are no longer implicit tests for gossip lifecycle ownership

##### Tests that should be deleted and replaced

These are tied to the current split ownership model and should not survive unchanged:

- `GossipHandler: onAttestation queues unknown beacon_block_root for replay`
- `GossipHandler: onAggregateAndProof queues unknown beacon_block_root for replay`
- `releasePendingUnknownBlockGossip transfers queued attestations without double cleanup`
- `Queue exposes expired items through takeDropped`

They should be replaced by processor-owned tests:

- `BeaconProcessor: attestation ingress parks on missing block root`
- `BeaconProcessor: aggregate ingress parks on missing block root`
- `BeaconProcessor: attestation ingress queue batches same attestation data`
- `BeaconProcessor: attestation ingress queue releases partial batch on age threshold`
- `BeaconProcessor: onImportedBlock releases parked gossip exactly once`
- `BeaconProcessor: onImportedBlockData releases block-data waiters keyed by block root`
- `BeaconProcessor: expired parked gossip emits ignore completion and frees owned data`
- `BeaconProcessor: block ingress is dispatched before attestation ingress under mixed load`
- `BeaconProcessor: reserved peer-service budget drains status under attestation load`
- `BeaconProcessor: popValidationCompletion reports accept / ignore / reject`
- `BeaconProcessor: shared artifact resolution emits per-message outcomes without duplicate expensive validation`
- `BeaconProcessor: shared artifact provenance caps and compresses past the fan-in limit`

#### Migration stop conditions

Implementation is not complete until all of the following are true:

- `BeaconNode` no longer has `pending_gossip_validations`
- `BeaconNode` no longer has `completed_gossip_validations`
- `BeaconNode` no longer has `pending_unknown_block_gossip`
- `BeaconNode` no longer has `pending_gossip_bls_batches`
- `gossip_ingress.processValidatedMessage()` is gone
- `GossipHandler.beacon_processor` is gone
- `queueUnknownBlock*` gossip callbacks are gone

That is the point where the ownership boundary has actually moved, not just been wrapped.

### BLS Pool Model

This section answers whether the refactored design should keep separate gossip
and block BLS pools or collapse to one shared pool.

#### Current fact pattern

Today Zig has two pools initialized in `src/node/lifecycle.zig`:

- block pool
- gossip pool

That split is not purely architectural. It is also influenced by the current
`src/bls/ThreadPool.zig` API:

- async verify-set submission requires `use_caller_thread = false`
- the current block pool uses caller-thread participation
- the current gossip pool disables caller-thread participation and exposes a
  bounded async queue

So the current two-pool setup is partly an implementation artifact.

Lodestar-TS uses one shared BLS worker pool exposed off `chain.bls`, with one
global backpressure signal:

- `chain.blsThreadPoolCanAcceptWork()`
- network processor checks that before admitting more work
- block validation and gossip validation both submit into the same underlying
  verifier with per-call options and priorities

That is a better architectural target.

#### Preferred end state

Post-refactor, prefer one shared BLS compute service.

Ownership stays separate even if execution is shared:

- `BeaconProcessor` owns gossip batching, submission, waiting, and completion
- `ChainRuntime` / block-state services own block-signature submission and
  waiting
- the shared BLS service owns only worker execution and queueing

This is more coherent than separate physical pools because:

- it gives one global CPU budget for BLS work instead of static partitioning
- it gives one backpressure signal for the network scheduler to consult
- it avoids idle capacity on one side while the other side is saturated
- it matches Lodestar's behavioral model more closely

#### Required BLS service features

One shared pool is only production-real if the pool contract can represent the
different kinds of work cleanly.

It needs:

- multiple admission lanes inside one shared service
  - `block_critical`
  - `reqresp_liveness`
  - `gossip_fast`
  - `gossip_normal`
  - `background`
- per-lane reservation or minimum progress guarantees
- per-lane bounded queue capacity
- preemption or strict ordering rules between lanes
- bounded queue capacity with `canAcceptWork()`
- async future-returning submission for gossip batching
- synchronous / cooperative submission for block-path use where useful
- no direct ownership of node or chain state

Current Zig already has one important piece:

- `ThreadPool.VerifySetsPriority` with `high` and `normal`

But it does not yet cleanly support both:

- async background gossip submission
- optional caller-thread participation for block-path verification

using one pool instance.

That means the design target should be:

- one logical BLS service
- either:
  - extend `ThreadPool` so caller participation is per job, not per pool, or
  - standardize on background-worker-only execution for both block and gossip

The first option is the better end state. The second is acceptable as a
transitional simplification if profiling does not show regressions.

#### Recommendation

For the post-`BeaconProcessor` refactor design:

- prefer one shared BLS service, not two separate pools
- treat the current two-pool split as transitional, not architectural
- keep ownership separate by subsystem even when execution is shared
- make block-path jobs higher priority than gossip-path jobs
- do not allow one global FIFO or one undifferentiated priority heap
- require multiple lanes with explicit reservation so attestation or DA volume cannot starve
  block-critical verification
- expose one global `blsCanAcceptWork()` signal that the processor can consult

One pool is fine. One starvation domain is not.
