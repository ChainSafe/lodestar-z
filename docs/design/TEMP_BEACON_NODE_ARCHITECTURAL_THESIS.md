# Beacon Node Architectural Thesis

## Purpose

This note states the architectural thesis for the beacon node as a standalone design
document. It is intentionally broader than any one refactor. It should anchor later
design decisions and provide a simple test for whether a change moves the node toward
or away from a production-real design.

This is a temporary working document. It is not yet a committed project contract.

## The Super Idea

The beacon node should be:

- a deadline-aware control plane
- with a single writer for consensus truth, not a single writer for the entire node
- using explicit causal work, bounded queues, and dependency-driven promotion
- while data-plane services perform compute and transport work without owning the meaning of results

This is the central simplification.

The node is not a pile of handlers reacting directly to the network.

The node is a control system. The network provides inputs. Time provides deadlines.
External dependencies provide completions. Peer requests provide liveness obligations. All
of them are admitted into a bounded scheduler. The control plane decides what must happen
before expiry, what can wait, what must be promoted because it unblocks more important
work, and what is already stale and must be dropped.

Nothing outside the single writer for consensus truth mutates canonical consensus state.

## Why This Is The Right Simplification

This unifies the design goals that otherwise fight each other:

- safety:
  one owner of mutable consensus state, bounded queues, explicit ownership, explicit
  transitions
- performance:
  batching, predictable work admission, backpressure, data-plane isolation
- developer experience:
  clear responsibilities, clear invariants, less ambient state, fewer hidden couplings

This is the kind of simplicity that comes from mastery rather than omission. The design
is not simpler because it has fewer nouns. It is simpler because its nouns have cleaner
jobs and stronger boundaries.

## Architectural Thesis

The beacon node must distinguish clearly between:

- control plane:
  the authoritative domains that own truth, admission, deadlines, causality, mutation,
  and final decisions
- data plane:
  bounded execution services that perform compute or transport work without owning the
  meaning of results

The control plane may contain more than one authoritative domain. What must stay singular
is ownership of each mutable truth domain. Consensus truth itself remains single-writer.

The control plane should run the node by deadlines and causal validity, not by arrival
order. The data plane should serve the control plane. The network must not directly drive
consensus mutation.

## Primary Invariant: Single-Writer Consensus Truth

Nothing mutates canonical consensus truth except its single authoritative domain.

This includes:

- chain head and fork choice
- canonical pool membership
- sync and finality state
- canonical caches whose mutation affects consensus results

If a worker thread, callback, or helper service can mutate these directly, the design has
already drifted.

## Secondary Invariant: Explicit Truth Domains

The single-writer rule does not mean one writer for the entire node.

Other mutable truth domains may exist, for example:

- peer and req/resp liveness state
- discovery policy state
- dependency health state
- processor-owned deferred-work state
- peer-impacting validation outcomes

Each such domain must still have one explicit owner and explicit command boundaries to
other domains.

## Consequences Of The Primary Invariant

If the primary invariant holds, several secondary design rules follow naturally.

### All External Inputs Become Work

External events are not permission to run arbitrary logic inline.

Examples:

- gossip message arrival
- req/resp message arrival
- timer tick
- imported block notification
- execution layer response
- BLS completion
- regen completion

Each must become an explicit work item, notification, artifact update, or completion
delivered into the control plane.

The unit of scheduled work does not have to be the inbound message. For high-fanout data
availability traffic, the right unit may be a shared artifact keyed by block root, header,
column group, or similar reuse boundary.

### Admission Must Be Artifact-Aware Where Needed

The scheduler should not assume that one inbound message equals one durable unit of work.

For PeerDAS-style traffic, multiple inbound messages may contribute to one reusable data
availability artifact. In those cases:

- admission should deduplicate by artifact key
- deferred state should be keyed by the shared artifact
- validation reuse should happen at the artifact boundary
- scheduler cost should reflect shared work, not raw message count

### Artifact Reuse Must Preserve Provenance

Artifact-aware admission must not erase accountability.

When multiple peers contribute fragments to one reusable artifact, the architecture must
retain:

- which peer supplied which fragment
- which peer first supplied a valid reusable fragment
- which peer supplied invalid or conflicting fragments
- per-peer quota and scoring information even when expensive validation is deduplicated

The right model is a shared artifact core plus a provenance fan-in table. Deduplicate the
expensive work, not the accountability.

Per-artifact provenance must itself be bounded.

That means:

- each artifact has a hard fan-in cap
- provenance beyond the cap is compressed into bounded summary form
- unbounded per-peer fragment retention is forbidden
- authoritative peer accounting remains primarily in the peer truth domain, not in the
  artifact accumulator

### Cold Or Blocking Work Becomes Causal Request/Completion

Hot cache hits and cheap checks may stay inline inside the authoritative owner.

Cold state derivation, batch signature verification, state transition work, and blocking
dependency work must not be hidden behind ordinary helper calls. They are causal requests
to the data plane, followed later by completions returned to the control plane.

### All Work Is Deadline-Bearing

Every work class must define:

- an admit deadline
- an expiry rule
- a minimum service guarantee
- the peer or consensus consequence of missing that deadline

Priority without deadlines is not enough for beacon-node work. Many obligations are
deadline-bound, not merely importance-bound.

### All Jobs And Completions Are Causal

Every job and completion must carry enough causal identity to prove it still belongs to
the current decision context.

At minimum this means:

- work id
- source peer or source subsystem
- slot or epoch
- fork digest or equivalent fork identity
- head generation
- finalized generation
- cancellation semantics

Late completions must be dropped if their causal ticket no longer matches the live view.

### All Queues Are Bounded And Admission Is Cost-Aware

Every queue must have:

- an owner
- an upper bound
- a drop or parking policy
- a consensus rationale for its priority
- per-peer or per-source quota where relevant
- per-topic or per-class budget where relevant
- cheap prefilters before expensive admission

Bounds alone are not enough. Without cost-aware admission, a bounded queue is just a
fixed-size victim cache for honest traffic.

If a queue cannot be bounded, the design is incomplete.

### Admission Must Produce Protocol Results

Backpressure is not only an internal concern. Each protocol boundary needs an explicit
external outcome when admission or service cannot proceed.

At minimum:

- gossip must resolve to a protocol-visible verdict
- req/resp must resolve to a response, stream error, or explicit resource-unavailable
  outcome
- liveness traffic must resolve to answer, drop, or disconnect behavior

Internal queue overflow must not be allowed to hide inside transport state or indefinite
stream stalling.

### Parked Work Must Promote Its Unblockers

Parked work is not a terminal state. It creates dependency edges.

If a piece of work is parked waiting for a block, envelope, state, or artifact, then the
traffic that can unblock it must inherit enough priority to drain the parked set.

Bounded parking without priority inheritance is a recipe for permanent gridlock.

### Ownership Must Be Single And Explicit

There should be one owner for each of:

- gossip admission and priority
- deferred gossip lifecycle
- validation completion records
- chain-state derivation services
- consensus-state mutation

If two subsystems both partly own a thing, neither actually owns it.

### Canonical And Advisory State Must Be Separated

Not every cache deserves the same ownership rules.

There are two valid classes:

- canonical state:
  single-writer state whose mutation can change consensus or peer outcomes
- advisory state:
  concurrent best-effort dedup or hint structures that may reduce work but must never be
  the sole source of truth

If a cache can change consensus meaning, it is canonical. If it exists only to avoid
duplicated effort, it may be advisory.

### Memory Ownership Must Be Explicit

Queue boundaries are also ownership-transfer boundaries.

Every job class must define:

- who owns wire buffers
- whether buffers are immutable and pooled
- how snapshots are referenced
- when arenas are created and destroyed
- who owns completion payloads
- how cancellation frees queued or parked state

Without an explicit memory model, Zig performance gains turn into lifetime hazards.

### Durability And Replay Must Be Explicit

Durability is part of the architecture, not an implementation afterthought.

For each truth domain and each durable artifact class, the design must define:

- what must be durably committed before a decision is final
- what may be indexed or derived asynchronously later
- what retention window must be preserved for serving obligations
- how replay reconstructs the live domain after crash or restart
- which domains replay as empty and which must be reconstructed before service

At minimum this applies to:

- recent block records needed for req/resp service
- recent sidecar and data-column records needed for req/resp service
- canonical chain records needed to reconstruct consensus truth
- pool and scheduler state if not safely reconstructable from durable chain data

Weak-subjectivity startup and recovery are part of this contract. If a node begins
participating before it can serve the required retained ranges, that is an operating mode
with explicit limitations, not an accidental transient.

### Cross-Domain Outcomes Must Commit Atomically

Multiple truth domains are only safe if coupled outcomes have an atomic story.

For any network object that reaches a terminal decision, the design must define one
idempotent decision record that drives, as applicable:

- acceptance / rejection / ignore outcome
- seen-set or anti-equivocation mutation
- forwarding permission
- peer scoring or peer consequence
- persistence obligation

Those effects may be executed by different owners, but they must be derived from one
authoritative decision record and applied idempotently. Otherwise the node will drift into
split-brain outcomes such as forwarded-but-not-scored or scored-but-not-deduped.

### Cross-Domain Commands Must Be One-Way And Acyclic

For any network object, there must be one hot-path owner from admission until the terminal
decision record is written.

If other authoritative domains need to react, they must consume that decision record
asynchronously and idempotently. The hot path must not wait on cross-domain acknowledgments
to complete a protocol-visible outcome.

This implies:

- command flow between authoritative domains is one-way for a given object lifecycle
- synchronous cross-domain round-trips on the hot path are forbidden
- command graphs between authoritative domains must be acyclic

If coupled outcomes require synchronous coordination, they belong under one hot-path owner
instead of multiple domains.

### Causality Requires Snapshot Handles, Not Just Generations

Generation tags are necessary for stale-result invalidation, but they are not a complete
read-consistency model.

Every job that reads mutable truth must name the exact snapshot it was derived from.

That means the architecture must define:

- immutable snapshot handles or owned snapshots
- read barriers for acquiring those handles
- the relationship between snapshot handles and generation invalidation
- when a response stream or deferred job must stop because its snapshot is no longer valid

Jobs must not read against mixed snapshots and then rely on late invalidation to repair
the damage.

### Snapshot Handles Must Have Budgets

Snapshot handles are not free.

The architecture must define:

- bounded snapshot retention per generation or view
- shared handles rather than unbounded per-job copies
- refcount or lease rules
- eviction and recompute policy when the budget is exhausted
- which jobs may pin snapshots and for how long

Correctness without a budget is just deferred memory failure.

## The Top-Level Shape

In the end-state design, the node should be understood as three domains.

### 1. Transport Ingress And Egress Adapters

Examples:

- libp2p / gossipsub transport
- req/resp transport
- execution transport
- clock / timer adapters

Responsibilities:

- decode transport framing
- identify the input kind
- create control-plane work items
- submit them into the control plane
- consume authoritative decision records
- drive bounded outbound publication and response streams
- translate internal admission and service outcomes into protocol-visible wire outcomes

Non-responsibilities:

- no consensus mutation
- no hidden cold-path validation
- no ambient scheduling policy
- no ownership of deferred consensus work
- no hidden outbound workflow that bypasses authoritative decisions

### 2. Control Plane

Examples:

- `BeaconNode`
- `BeaconProcessor`
- `ChainRuntime`
- chain-facing orchestration

Responsibilities:

- admit work
- prioritize work
- track deadlines, expiry, and minimum service guarantees
- park, cancel, and resume work
- issue causal jobs and invalidate stale completions
- promote work that unblocks more important parked work
- drive authoritative decision records across coupled domains
- decide what must be durably committed before a decision is final
- drive replay and recovery policy for owned truth domains
- submit data-plane jobs
- consume completions
- mutate consensus state
- produce final outcomes

This is the heart of the node.

`ChainRuntime` is not a peer layer next to the control plane. It is part of the control
plane. It is the control plane's consensus runtime.

### 3. Data Plane Services

Examples:

- shared BLS compute service
- regen execution service
- state-transition execution service
- execution engine runtime
- builder runtime
- other bounded transport or dependency executors

Responsibilities:

- perform bounded expensive work
- perform bounded blocking or async dependency work
- obey the causal and ownership contracts of submitted jobs
- return results back to the control plane

Non-responsibilities:

- no consensus ownership
- no direct state mutation
- no queue-priority authority

## The Intended Role Of `BeaconProcessor`

`BeaconProcessor` should not be a sidecar or a downstream work queue.

It should be the control-plane scheduler for beacon-node work, especially network-facing
work. In particular, it should become the sole owner of:

- gossip admission
- per-topic priority and overload policy
- deadline-aware service guarantees and expiry policy
- deferred gossip parking and release
- dependency promotion for parked-work unblockers
- gossip-related validation completions
- causal job issuance and stale-completion dropping
- scheduling of typed consensus work after admission
- submission of processor-owned compute jobs
- resumption after compute completions

This does not mean `BeaconProcessor` owns all consensus logic. It means it owns the
control-plane workflow around that logic.

`BeaconProcessor` should also be the hot-path owner for peer-visible outcomes of admitted
network objects unless the lifecycle contract explicitly assigns that outcome elsewhere.

## The Intended Role Of `ChainRuntime`

The chain side should own:

- fork choice
- import sequencing
- state derivation and regen orchestration
- caches and mutation gates
- pool mutation
- consensus invariants on imported objects

`ChainRuntime` is not a second owner beside the control plane. It executes inside the
control plane and applies consensus-state transformation on the control plane's behalf.

This is not in conflict with the `BeaconProcessor` design. The processor owns workflow.
The chain owns consensus-state transformation.

The processor may decide that a piece of work needs cold state derivation. The chain side
must own how that derivation happens.

## Lifecycle Ownership Must Be Explicit

Every network object or shared artifact class must define an explicit lifecycle.

For each state, the design must define:

- current owner
- durable representation, if any
- legal handoff targets
- cancellation behavior
- terminal decision record

At minimum, lifecycles usually include states such as:

- admitted
- parked
- waiting on snapshot or dependency
- ready on snapshot `S`
- transforming or importing
- persisted
- peer-effects applied
- retired

The exact states may differ by object class. The invariant does not: one owner per state,
one handoff at a time, one terminal decision record.

## The Intended Role Of Data-Plane Services

Data-plane services must be boring.

They should:

- accept bounded requests
- perform pure compute or isolated transport execution
- produce completions

They should not:

- call back into arbitrary node logic
- mutate shared consensus state
- interpret the consensus meaning of results
- decide scheduling priority
- hide retries, parking, or deferred admission policy

If a data-plane service starts owning workflow, the design is decaying.

## Control Plane Versus Data Plane

This distinction is important enough to restate plainly.

### Control Plane

The control plane is:

- the set of authoritative domains and schedulers
- the owner of mutable truth domains
- the owner of queue admission and priority
- the owner of deferred-work lifecycle
- the owner of final validation and peer-impact decisions

The control plane does not have to be one executor for the entire node.

What must be singular is the writer for each truth domain, especially consensus truth.
Separate authoritative domains are valid only when their ownership and command boundaries
are explicit.

The control plane should be able to stop, inspect, and explain every outstanding unit of
work in the node.

### Data Plane

The data plane is:

- bounded worker capacity
- no truth ownership
- no mutation authority
- no authority to interpret the consensus meaning of results

The data plane may perform:

- pure compute
- blocking or async transport work
- bounded interaction with external dependencies

What makes it the data plane is not that it is CPU-only. What makes it the data plane is
that it executes work without owning the meaning of that work.

The data plane exists to amortize cost and isolate latency, not to own decisions.

### Dependency Semantics

External dependencies such as the execution engine and builder still fit inside the
control-plane / data-plane model.

The split is:

- control plane owns when to call the dependency
- control plane owns in-flight request lifecycle
- control plane owns dependency liveness interpretation
- control plane owns the consensus meaning of dependency results
- data plane performs the actual transport/auth/session work and returns completions

This keeps the architecture honest without inventing a third plane.

### Completion Path

Every data-plane completion returns to the control plane before any
shared-state mutation or final gossip / peer outcome is emitted.

If a completion causes direct mutation from a worker context, the split has failed.

## Top-Level Executors

The durable executor model should stay small.

### Consensus Control Executor

There must be one authoritative executor for consensus truth.

It owns:

- `BeaconProcessor`
- `BeaconNode`
- `ChainRuntime`
- chain mutation
- fork choice
- canonical pool mutation
- canonical caches
- final consensus outcomes

### Other Authoritative Executors

Other authoritative executors may exist for disjoint truth domains, for example:

- peer and req/resp liveness state
- discovery policy state
- dependency health state

They are valid only if:

- ownership is explicit
- commands between domains are explicit
- they cannot directly mutate consensus truth

### Shared Data-Plane Executors

Bounded services for:

- BLS verification
- regen execution
- state-transition execution
- execution engine interaction
- builder interaction
- other remote dependency protocols

These are helpers, not owners.

Some data-plane services are compute-heavy. Some are transport-heavy. That difference does
not justify a separate architectural plane.

The architectural mistake would be to give each area an independent control-plane-shaped
runtime. That would produce competing schedulers instead of one coherent node.

## BLS In This Model

The end-state preference is one shared BLS compute service, not multiple permanent BLS
subsystems.

Why:

- one global CPU budget
- one global backpressure signal
- less static partitioning
- better alignment with Lodestar's behavior

Ownership still remains explicit:

- the control plane owns which jobs to submit, when, and why
- the BLS service owns execution only

One shared implementation does not imply one undifferentiated queue.

The shared service must support:

- multiple admission lanes or classes
- per-class reservations
- backpressure by class as well as globally
- explicit starvation prevention for liveness-critical classes

The shared service should expose explicit admission/backpressure so the control plane can
make correct priority decisions without letting one hot workload consume the entire budget.

## Regen In This Model

Regen is not processor-owned. It is chain-owned compute requested by the control plane.

This is the clean split:

- control plane decides that work is blocked on cold chain state
- chain-owned compute services derive that state
- completion returns to the control plane
- control plane resumes the parked work

The processor owns waiting. The chain side owns derivation.

## External Dependencies In This Model

Execution-engine and builder interaction are not pure compute, but they still fit inside
the two-plane model.

The correct distinction is not "compute versus dependency". The correct distinction is
"decision versus execution".

So the clean split is:

- control plane decides when dependency work is needed
- control plane owns in-flight request state and liveness interpretation
- data plane performs protocol/session execution
- completion returns to the control plane
- control plane decides the consensus consequence

This preserves simplicity by keeping the categories honest and minimal.

## Scheduling Principle

The scheduler should reflect deadlines and consensus criticality, not convenience.

Every work class must define:

- admit deadline
- expiry
- minimum service guarantee
- causal ticket requirements
- whether it can park
- what inherits its priority if it parks

### Deadlines Are Stage-Specific

Work rarely has one deadline. It usually has several.

Examples:

- forward-by
- validate-by
- persist-by
- serve-by
- accounting-by

Missing one stage deadline must not automatically kill all later stages. Work may be stale
for forwarding but still required for persistence, replay completeness, anti-equivocation,
or future req/resp service.

### Node Modes Are First-Class

The scheduler must have explicit operating modes. At minimum:

- steady-state near head
- catch-up / head sync
- weak-subjectivity recovery and recent-data backfill
- degraded dependency mode

These modes are not just different queue contents. They carry different compliance
obligations, queue bounds, and minimum service guarantees.

Mode must influence:

- admission budgets
- per-class reservations
- expiry policy
- serving guarantees
- persistence and backfill priorities

### Modes Need An Owner And Hysteresis

Mode changes must be owned by a dedicated control-plane state machine.

That owner must define:

- entry signals
- exit signals
- entry thresholds
- exit thresholds
- hysteresis rules to prevent flapping
- degraded-mode service objectives

Mode is not a derived convenience flag. It is an authoritative operating contract.

A production-real priority order will favor:

- block-like control traffic
- data availability control traffic
- req/resp liveness
- deferred work that unblocks parked consensus progress
- high-volume overload traffic such as attestations after the above

Forward-or-serve-now traffic must be treated accordingly. If a work class becomes useless
after its freshness window, stale instances should die early instead of consuming scarce
service.

The right question is not "what is easiest to process next?"

The right question is "what best preserves chain progress, forwarding correctness, and
peer liveness before deadlines expire?"

## What This Design Rejects

This thesis rules out several patterns.

### Inline Reaction To The Network

The node should not perform unbounded or consensus-significant work directly in reaction
to transport callbacks.

### Ambient Mutable Handler State

Handlers should not secretly own workflow state or scheduling state through setter-style
dependencies and nullable runtime fields.

### Maybe-Owner Designs

Patterns like:

- maybe this subsystem owns deferred state
- maybe the node owns it
- maybe the handler owns it

are not acceptable. Ownership must be singular.

### Fallback Shims Over Missing Design

Tolerance shims, hidden fallbacks, and recovery paths that exist because the real
ownership model is missing are not production-real.

### Extra Control Planes

Adding another processor-like ingress stage on top of a weak processor boundary is the
wrong move. If the scheduling boundary is wrong, the answer is to move the boundary, not
to stack a new scheduler on top of the old one.

## Decision And Measurement Test For Future Changes

Every meaningful design change should be tested against these questions:

1. Does it preserve single-writer consensus truth and explicit truth-domain ownership?
2. Does it strengthen or weaken the control-plane / data-plane split?
3. Are deadlines, expiry rules, and minimum service guarantees explicit?
4. Are jobs and completions causal, cancelable, and stale-result safe?
5. Is admission bounded, cost-aware, and quota-aware?
6. Does parked work promote the unblocker paths it depends on?
7. Does the protocol boundary have an explicit external outcome under overload or refusal?
8. Is egress driven only by authoritative decision records?
9. Are snapshot handles, read barriers, and snapshot budgets explicit?
10. Is the durability and replay contract explicit?
11. Does one idempotent decision record drive all coupled cross-domain outcomes?
12. Are cross-domain commands one-way and acyclic on the hot path?
13. Is lifecycle ownership explicit for each object or artifact class?
14. Is memory ownership explicit across every queue boundary it introduces?
15. Does this remove hidden coupling, or add it?
16. Is this a real simplification, or just a local patch?

If the answer is unclear, the design is not yet ready.

The thesis should also be falsifiable with metrics. At minimum:

- p95 and p99 validation latency by topic
- p95 and p99 req/resp service latency by request type
- max control-plane critical section duration
- max parked-work cardinality by class
- stale-completion drop rate
- max per-peer queued work and memory footprint
- sync catch-up throughput under load
- data-availability serving latency after successful validation

## What This Means For Current Refactors

This thesis implies the following direction for the current beacon-node work:

- move gossip admission upward into `BeaconProcessor`
- make `gossip_ingress` a thin adapter
- make `gossip_handler` pure-ish topic logic rather than workflow owner
- make admission artifact-aware where message-level scheduling is the wrong unit
- preserve peer provenance and cap per-artifact fan-in
- move deferred gossip lifecycle into the processor boundary
- move gossip validation completion ownership into the processor boundary
- introduce causal tickets and stale-completion invalidation
- define one-way command flow between authoritative domains
- define explicit protocol-boundary outcomes for gossip, req/resp, and liveness
- make egress a first-class adapter driven by decision records
- introduce immutable snapshot handles and read barriers for cold or deferred work
- add snapshot budgets and recompute rules
- add deadline, expiry, and minimum-service policy per work class
- split stage deadlines into forward / validate / persist / serve where needed
- make node operating modes first-class in scheduling and budgets
- give mode changes an explicit owner with hysteresis
- split canonical caches from concurrent advisory dedup structures
- define the durability boundary and replay path for each truth domain and artifact class
- make coupled outcomes flow through one idempotent decision record
- define explicit lifecycle ownership and handoff states for each object class
- add an explicit memory-ownership model for queues, parks, and completions
- keep chain-state derivation chain-owned
- keep data-plane services execution-only
- keep shared services lane-isolated even when their implementation is shared
- preserve one consensus control domain rather than introducing competing schedulers

## Relationship To Lodestar

Lodestar is a strong grounding reference for production-real behavioral shape. It is not
the architecture contract.

The point is not to copy every file shape. The point is to preserve the behavioral
discipline:

- explicit network admission boundary
- central scheduling ownership
- batching where the overload really is
- backpressure tied to real compute capacity
- handlers that are logic, not hidden workflow engines

Where our implementation differs, it should do so because the local design is clearly
better by the project's priorities and measured behavior, not because the boundary is
still unclear.

Spec correctness and measured production behavior are the contract. Lodestar parity is a
useful guardrail, not the floor.

## Final Statement

The beacon node should feel like one mind, not many.

It should admit work explicitly, schedule it by deadlines and causality, execute it in
bounded data-plane services, and mutate consensus truth only in its authoritative domain.

That is the simplest design because it makes the hard things obvious:

- who owns truth
- who owns deadlines
- who owns priority
- who is allowed to mutate state
- who is only allowed to execute
- who owns memory at every boundary

Everything else should be made to serve that idea.
