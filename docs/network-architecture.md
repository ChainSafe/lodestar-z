# Native networking architecture

The `network` module implements QUIC/libp2p transport, Ethereum req/resp, gossipsub,
Identify, and managed peer policy. `discv5` supplies discovery, while `udp` owns shared
socket mechanics. The Node.js addon exposes `createNativeNetworkApplicationRuntime`.
The host supplies chain configuration and consensus validation. Transport authentication,
valid SSZ framing, and a positive gossip verdict are separate decisions.

## Layers and owners

| Owner | Responsibility | Lifetime and dependencies |
| --- | --- | --- |
| `udp.Sockets` | One socket per configured family, bounded datagram I/O and provider cleanup | Owned by a QUIC or discovery Transport; input borrows its receive buffer |
| `quic.Engine` | TLS authentication, cryptographic random generation, connection admission, protocol timers and flow control | Owns its TLS context after successful initialization and all QUIC connections/streams; consumes bytes and explicit time without socket I/O |
| `Transport` | Engine and socket lifetime, OS clock sampling, pacing queues, buffers and bounded I/O turns | Owns startup entropy and teardown; completed progress can accompany a later local or keylog failure |
| `Router` / `Negotiator` | Multistream selection and handler dispatch | Owns negotiation buffers until completion; handlers consume or copy leftovers before the next pump |
| `Service` | Protocol composition and separate control/application output capacity | Owns req/resp, gossip sessions and optional Identify; does not decide consensus validity |
| `PeerManager` | Authenticated peer catalog, Status/Metadata, reputation, demand and dial selection | Borrows Service and Engine per operation; identity generations differ from physical connection generations |
| `NetworkCore` | Managed composition, discovery, local intent and I/O turns | Owns Transport, PeerManager and Service as siblings, plus optional discovery; consumes a resolved construction plan and composes deadlines |
| `GossipProcessor` | Ethereum gossip work admission, dependency waiting, batching and execution credits | Owned by the application runtime above Gossipsub; uses fixed startup storage and borrows authoritative chain answers from the host |
| `discv5.Transport` | Discovery Engine, sockets, packet workspaces and bounded I/O | Takes ownership of bound sockets after the host derives its signed advertisement; returns progress alongside later failures |
| `peers.Discovery` | Ethereum fork, subnet and custody lookup demand and candidate selection | Seeds configured bootnodes as known routing contacts, owns one demand-driven walk and liveness maintenance, and borrows discovery Transport |
| Binding owner thread | Drives NetworkCore and copies native events into bounded bridge tables | Owns all protocol mutation; JavaScript never drives a native protocol object concurrently |

Shared `types.zig` defines addresses, time, connection handles and stream handles without
importing either owner. Engine counters are plain data; network metrics renders snapshots
outside the engine. Transport iterates physical slots internally and tags queued datagrams
with their connection generation before carrying them across turns.

Raw Zig callers may compose `Transport` and `Service` for protocol-specific tools.
Managed callers use `NetworkCore`; the binding uses the managed configuration path.
These paths share parsers and lifecycle rules. Raw application req/resp callers must
supply `Options.policy` or `Options.admission.policy`; `Config.fromBeaconConfig` builds
that policy from a chain configuration and copies its schedule during initialization.
Control-only callers do not need an application request policy.

The addon host initializes the shared `BeaconConfig` before constructing a network runtime.
`network/chain.zig` reads that configuration once and owns the derived network plan: effective
named-fork and BPO boundaries, request contexts, topic namespace and SSZ bounds, Phase0 message
IDs, request policy, custody parameters, and ENR fork hints. The application constructor accepts
resource budgets and optional light-client serving policy; it does not accept separate fork
digests, capability tables, topic rules, or request limits. Shared-config initialization and
immutability remain the responsibility of the existing addon configuration integration. Network
owners retain no pointers into its mutable backing storage.

Each intent selects the plan using the supplied clock slot, then stages local Status, protocol
capabilities, discovery and subscriptions in one transaction. A narrow Status update carries
head/finality/availability observations and preserves the current digest. Response contexts still
identify the historical object's boundary, including distinct BPO digests within Fulu. Future
unsupported named forks remain visible in ENR hints; activation refuses them explicitly.

Request receive buffers are allocated once for the maximum configured request across supported
forks. Admission captures the active fork and installs its exact byte bounds in the length-prefix
decoder, so later activation cannot reinterpret a partly received request. The same policy owns
structural limits and response chunk ceilings. The 4096 blob-identifier implementation capacity
is separate from configured Deneb/Electra limits and from the per-block BPO schedule. Blob RPCs
serve pre-Fulu history; Fulu/BPO blob counts do not enlarge their lists or buffer reservations.

Shared protocol definitions are independent of the router and protocol owners. Each new
stream negotiates once, then passes to its selected handler. Inbound proposals use the
current receive capabilities when parsed. Opening a stream does not freeze an offer set.
After acceptance, the selected numeric protocol identity survives capability changes,
blocked acknowledgment writes and delayed completion delivery. Established streams do not
renegotiate; a replacement stream negotiates anew. Outbound negotiations retain their
ordered candidates until they succeed or terminate.

The application runtime activates through a complete `applyIntent`. Once active,
`updateStatus` copies and validates Status against the active fork through the same ordered
command queue. It updates future Status exchanges and invalidates peer selection without
changing subscriptions, Metadata, ENR, demand expiry, or the native clock. The host refreshes
slot and fork state with a complete intent before using this narrow path in a new slot;
`headSlot` may decrease during a reorganization and never supplies the clock.

## A managed turn

1. Apply bounded host commands, cancellation flags, validation results, and peer penalties.
2. Sample time, receive a bounded UDP batch, route or authenticate it, and advance transport timers.
3. Negotiate newly opened streams, advance protocol owners, and capture completions into the
   supplied output slices. Full outputs retain outstanding borrows until a later turn.
4. Process control responses, reconcile peer demand, and schedule bounded discovery/dial work.
5. Flush bounded sends and publish copied host events and diagnostics. Combine the next native
   deadline with host work and socket readiness before waiting.

`managed.process` borrows PeerManager, Service and Engine for one socket-independent turn.
Production and managed tests call this same function. It admits authenticated connections to
peer policy before gossip admission, then calls Service exactly once. Status relevance remains
independent of gossip admission. Control completions, custody work and reconciliation follow;
discovery and physical dials do not start another protocol pump.

Service owns one heap-allocated Gossipsub. Its public `pump` and `nextWakeup` cover both protocol
maintenance and stream work. Internal `session_io.zig` functions borrow that same owner;
stream opening cursors, sessions, retries and delivery revision belong to Gossipsub itself.

Gossip receive storage is fixed at startup. Each session owns a small contiguous prefix and one
chain of 4 KiB overflow pages from a dedicated arena. Declared frame size does not reserve pages;
only received bytes do. The outer RPC reader retains cursors and item ranges across turns, and
materializes one segmented item at a time into a shared maximum-frame workspace. Decoded item
borrows end before the owner yields. Copy work has its own bounded credits alongside decode work.
The default receive arena is 32 MiB; the small profile reserves enough pages for one maximum
frame. Both profiles also reserve one maximum-frame workspace. Capacity refusal resets the
requesting inbound stream and releases its pages without a peer penalty. Native validation or
payload-store refusal drops that publication; temporary turn/event limits defer processing.

Peer inputs mark policy selection dirty. `PeerManager.reconcile(service, now)` evaluates those changes and
publishes coverage deficits and discovery need together. Their const getters return that last
completed evaluation, including its peer counts and demand, without refreshing reputation,
selecting or removing peers, publishing events, or consulting a remembered clock. Callers that
need pending changes immediately must reconcile with explicit time first. Dirty inputs wake
the owner immediately; reputation, metadata and admission-evaluation deadlines schedule later evaluations.
Demand expires only when `process` receives the host's next slot. Both observations are empty
before the first evaluation and are cleared on quiescence or shutdown; reconciliation does no
further policy work in either closing state.

Ordinary settled peers are pruned to `targetPeers`; the space up to `maxPeers` permits evaluation
of newcomers. Initial Status, Metadata, gossip readiness and custody derivation share a bounded
evaluation grace. Pending newcomers do not displace the settled set during that grace. Gossip
scores are normalized to the RPC reputation scale. Pruning first removes unusable or meaningfully
penalized peers, then favors removals that preserve demanded coverage. Each removal updates subnet
counts; unmet coverage remains a preference and cannot permanently protect an ordinary peer above
the target. At an equal target and ceiling, unmet coverage or outbound demand permits one replacement.
Direct peers and the outbound floor retain their protections below the hard ceiling; operator
reservations that occupy every slot can prevent replacement. Selection uses fixed scratch and at
most 256 removal rounds, each scanning at most 256 inputs and 196 subnet counters.

Local count/capacity pruning defers automatic redial for five minutes without reducing reputation
or rejecting healthy incoming connections. Explicit connect and direct intent bypass that timer.
Remote Goodbye backoff and misconduct bans remain admission restrictions. Peer snapshots expose
`redialUntilMs`, `goodbyeUntilMs` and `banUntilMs` independently. These identity records retain their
existing bounded eviction policy.

The Lodestar host supplies gossip demand for its sampling groups and publication routes to other
column groups. Sampling groups use the configured target; other configured groups use a baseline
of four peers, bounded by peer capacity. Groups outside the chain configuration remain zero.
Gossip coverage uses peers' sampling sets; downloads use their actual custody sets.

The bridge has a mutex around shared command, result, and cancellation state. Protocol
objects belong exclusively to the owner thread. A bounded thread-safe notification wakes
JavaScript; the callback copies data without borrowing growable native buffers. Wake writes
and notifications are different channels. Polling, including the prepared state, is bounded
so a failed wake write cannot strand shutdown.

ReqResp owns request tables, scheduling, output fairness and completion accounting. Client
and Server keep their distinct protocol phases and deadlines. A common request record owns
handles, generation, notifications, terminal result and borrowed buffers. Its terminal
transition accepts one outcome and schedules cleanup; accounting happens at that transition.
Closing the stream, delivering the terminal event and recycling the slot are separate steps.
A pending response chunk survives termination, and the slot recycles only on the following
pump. RequestIO is private state for partial frame reads and writes, with no independent
allocation or lifecycle policy.

`service_test_support.ServicePair` constructs real Services over the in-memory QUIC pair.
Each step accepts ordinary Service output slices and processes each side once; transport
transfer and time advancement remain independently available. Protocol fixtures supply only
their defaults and scenario helpers. Managed fixtures live in `managed_test_support.zig`,
while policy, quota and topic fixtures live beside their subsystems. The shared UDP test I/O
adapter scopes basic socket, clock and entropy faults and forwards unaffected operations
through the supplied provider. Scenario-specific ordering faults remain local to their tests.

## Resource admission

Startup configuration fixes connection, negotiation, request, payload, validation, delivery,
and retained-identity capacity. Managed configuration derives request peer capacity from
transport capacity and gossip capacities from peer policy. The admitted-peer limit also sizes
outbound maintenance operations and protected req/resp and negotiation capacity. Application
request capacity remains separate. Socket send, receive and total-work budgets belong to Transport and are
validated independently of engine admission limits. Independent overrides preserve profile defaults; raw module options retain
their explicit controls. Composition validates shared limits before allocating native owners.
The binding parses into stable owned storage, obtains its policy seed and resolves one
`configuration.Resolved`. Bridge capacities and budgets, native construction and reported
capacities consume that same result. Admission defaults use the final inbound capacity;
Identify overrides preserve the selected profile. `NetworkCore.init` takes the resolved plan
and explicit startup inputs. `initManaged` resolves once for native convenience callers;
`initRaw` validates explicit module options before using the same construction path. Socket
binding and signed advertisement construction still depend on the actual allocated resources.
Allocation ledgers count requested native storage and bridge
storage. QUIC receive-window limits and native dependency overhead are separate from the
Zig allocation ledger, and host payload copies have their own byte budget. Engine reports its
configured windows; Transport adds its pacing queue and ready-batch storage. Nonblocking
receives skip deadline scans; a receive that may wait includes both engine and pacing deadlines.
Host diagnostics expose aggregate, connection and stream QUIC receive-window ceilings as
`quicReceiveWindowBytes`, `quicConnectionWindowBytes` and `quicStreamWindowBytes`. These are
flow-control ceilings, not measurements of allocated quiche memory. Profile regression tests
cap total and major-owner requested storage separately from the exact allocation reconciliation.

The engine reserves capacity for outbound recovery, groups IPv6 handshake sources by /64,
and requires stateless Retry for every new inbound connection. Tokenless Initials receive Retry
before QUIC or TLS allocation; a valid unexpired token binds the source endpoint and connection
IDs. Existing connections retain their routes, and handshake capacity limits still apply.
Retry authenticates the return path, not peer identity or consensus data.
Negotiation has a per-connection bound and preserves global outbound and control capacity.
A timed-out live gossip stream to a direct peer gets one retry after 30 seconds. Failed initial
or recovery negotiation has no timer retry; new inbound-stream evidence can reopen it. The
normal per-pump opening limit also bounds recovery, and removing direct membership cancels it.

Req/resp enforces two concurrent requests per protocol and connection. One policy validates
request structure and determines response chunk ceilings. Request transfer and each inbound
response chunk have absolute deadlines. The outbound API additionally has a whole-response
deadline, including host-held response chunks. Local host or quota pressure has distinct failure
reasons. Managed peer scoring observes incomplete inbound request timeouts even before a
request is delivered to the application.

Inbound admission refusals increment fixed method/reason counters exactly once where the
decision occurs. Reasons distinguish server capacity, peer capacity, protocol concurrency,
and decoded peer/global work quotas or identity capacity. Pre-admission refusals reset the
stream; decoded quota refusals use response code 139. Local capacity refusal does not penalize
the peer or evict admitted work. Bounded native debug logging records the refusal, and inbound
occupancy gauges distinguish request transfer, host waiting, response writing, withheld output,
and terminal owners awaiting recycling.

Managed maintenance keeps one outbound request per admitted peer. Pending Status and Metadata
coalesce and retain their first due times; a Metadata request replaces Ping work. A rotating
cursor bounds control and Identify starts per turn without limiting the number of peers that
can await responses. Cancelled requests retain their operation storage through terminal delivery,
including across catalog-slot and connection replacement. Local retirement yields to the next
protocol turn without a peer penalty or timer retry. Goodbye retains its independent close deadline.
Reserved control slots use startup-allocated scratch sized for control payloads and the maximum
error response, plus a read buffer that accommodates negotiation leftovers. The shared codec checks
declared frame lengths against the remaining compressed-byte allowance before copying payloads.

Gossip payloads are immutable after admission. Validation, history, and transmit descriptors
hold independent retains. Validation attribution pins retained identities and topic generations.
Per-peer validation limits, expiring unsent IWANT batches, and absolute large-frame transfer deadlines
prevent one session from keeping those resources indefinitely. Peer-caused large-frame expiry
also sets an identity cooldown; local host pressure does not blame the sender. Disconnected,
unpinned negative identities can be reclaimed under pressure while preserving outbound reserves.

### Ethereum gossip processing

The native Lodestar host enables `gossipPolicy.processor`, with item and byte allowances for
each of the 13 supported pre-Gloas message kinds. Subnets and fork digests share their kind's
allowance. The plan fixes validation slots, compressed pending storage, decoded processor storage,
and a separate compressed history/transmit allowance. Payloads of up to 512 bytes live inline
in startup-allocated descriptors; larger payloads use fixed 4 KiB pages. Retained descriptors
and pages stay charged until the final transmit or history retain ends. If retained capacity
is unavailable, a host Accept still resolves validation but does not retain or forward that payload.
Full admission drops the incoming message neutrally; it does not evict live pending work.

`GossipProcessor` extracts bounded slot/root fields as scheduling hints. These are unvalidated
claims and never establish consensus validity. `drainGossipChecks` lends copied metadata to the
host, which answers from fork choice through a generation-checked `classifyGossip`. Unknown-block
attestations and aggregates remain native. Waiting uses at most half a kind's slots and at most
a quarter per source, capped at 64 per source. Native validation separately caps each source at
half a kind's slots, capped at 128. A block notification retries authoritative checks, including
checks in progress, without extending the original receipt deadline. Recovery deduplication holds
96 roots with eight candidate peers each for at most 30 seconds measured by local monotonic time.
The host still owns fetching missing blocks, chain import and consensus validation.

The host advertises remaining per-kind execution credits before any JavaScript payload copy.
Each drain copies at most 64 messages and 16 MiB. Blocks, blobs and columns have independent
capacity and bypass the ordinary BLS/regen readiness gate. Attestations with identical attestation
data and fork digest form batches; a partial group waits at most 50 ms from receipt before becoming
eligible. The drain bound does not cap total concurrency: running work may occupy at most half a
kind's slots, subject to its byte allowance and the host's smaller execution budget. Attestations,
aggregates and sync work use newest-first service; other kinds use oldest-first service.

The companion host adapter in `lodestar-native-dual-stack` executes the existing handlers through
`NativeGossipExecutor`. The native path does not instantiate the TypeScript `NetworkProcessor`
or maintain a second pending queue. Queued expiry discards native payloads; expiry of an executing
job keeps its execution credit until the host reports completion. The environment-wide host
budget survives runtime shutdown while jobs remain active. Late reports cannot revive a protocol
verdict or a replacement cell. Startup decoded storage is deducted before shared request and
publication bridge credit is available, so pending gossip cannot consume recovery's remaining allowance.

Host defaults reserve 512 MiB each for the native and bridge ceilings and 64 MiB/4,096 items for
executing host gossip. These are independent ceilings, not measured RSS. The pending attestation
count derives from active validators per slot with 10% headroom; byte allowances also accommodate
the largest configured object across supported fork boundaries. Invalid or undersized plans fail
at startup. Without a processor plan the public binding retains its raw validation handoff.
The native host's legacy payload queue dump is unavailable; processor counts and refusal reasons
are available through runtime diagnostics and host metrics. Gloas remains unsupported by this host.

Discovery seeds the routing table with every compatible configured bootnode, subject to bucket
capacity and the existing address-prefix quotas. These known contacts can seed lookups without
claiming reachability. Application peer demand starts one bounded random walk at a time; its
authenticated responses populate and refresh routing while yielding peer candidates. Maintenance
owns liveness, newer-ENR and replacement probes. Failed liveness probes retain the contact for
future walks, clear its responsive status and make it a preferred replacement incumbent. FINDNODE
replies include only responsive contacts. There is no separate bootstrap retry policy or
background discovery walk, and all candidate storage is allocated at construction.

Discovery sessions and routing entries are separate. Authenticated NODES responses may supply
signed referrals without proving each advertised endpoint reachable. QUIC verifies the expected
peer identity before managed admission. Matching an outstanding coverage need grants one discovery
preference regardless of advertised breadth; the dial cursor rotates among matching candidates.
Failed candidates eventually lose eviction protection; manual intent outranks discovery preference.
Routing buckets limit unsolicited inbound membership,
maintenance retries cannot monopolize one probe indefinitely, and empty lookups back off.

Each live WHOAREYOU challenge permits one incoming handshake verification attempt. Channel
consumes it before ENR or identity-proof verification; any failure leaves established session
keys intact. New challenge creation and incoming handshake verification have separate admission
budgets, each allowing a burst of four per source and twenty globally, replenishing at four and
twenty per second. A source is an IPv4 host or IPv6 /64, independent of port and claimed NodeID.
The 256 source rows are allocated at startup; active quota debt cannot be evicted or extended by
refused packets. A full table fails closed until a row has fully replenished both budgets.
Verification refused by admission leaves the challenge's original deadline unchanged. Established
encrypted messages and responses to challenges for locally initiated requests bypass these gates.
Throttling does not penalize authenticated peer reputation. Fixed stage/outcome counters expose
admissions and refusals through `lodestar_native_discovery_admission_total`. Sustained traffic can
still exhaust the global allowance and temporarily delay new discovery sessions.

## Host handles and teardown

Connection, stream, request, validation and peer handles carry generation checks. Their widths
and lifetimes differ because they identify different owners. A stale handle cannot mutate a
replacement object. Exhausted connection generations retire rather than wrap.

An outbound request owns its native response sink until terminal completion is copied to the
host. An incoming request lends request data and may own a response buffer until serving ends.
Gossip deliveries copy into the bridge before native receive storage is reused; a validation token
remains separate from the JavaScript payload copy. The host must resolve or cancel these handles
through their documented APIs. Pool exhaustion returns a bounded refusal rather than growing
queues without limit.

Shutdown stops new work, cancels negotiations and protocol owners, releases transmit and
validation retains, and joins the owner before destroying its network objects. JavaScript handles
may keep lightweight terminal bridge cells alive after the heavy owner is gone. Per-environment
cleanup uses the same ownership rules. Test-only fault injection is excluded from release addons.

Peer reports use generation-bound counters separate from the command table. Repeated reports
accumulate up to the score floor, unknown identities are counted and ignored, and each owner turn
drains bounded work. Host-supplied reports remain trusted scoring policy.

## Validation and security references

The [threat model](../THREAT_MODEL.md) defines the security contract. The
[implementation map](security/IMPLEMENTATION_MAP.md) ties that contract to current code and
supported call paths. [Logging](network-logging.md) documents observable transitions and loss.
`AGENTS.md` lists native, binding, interoperability and fuzz checks. `test/fuzz/network-targets.tsv`
is the source of truth for network fuzz targets; smoke runs establish harness viability, not the
absence of vulnerabilities.

## Metrics

The network owner collects one bounded, pointer-free snapshot each second. Counters remain
with their subsystem owners. The snapshot separates cumulative totals and historical high-water
marks, live observations, and configured capacities. Shutdown clears the live group and retains
the final totals and configuration, including gossip capacities and queue high-water marks.

`metrics/collectors.zig` registers a fixed set of subsystem collectors. Each scrape supplies the
same copied snapshot to every collector; collection and rendering do not drive network policy,
refresh score caches, or retain owner pointers. Log metrics join the same encoder from their
separately synchronized log snapshot. Values belong to each runtime, with no global registry state.

`metrics/registry.zig` gives metric families fixed names, help, kinds, units, label schemas and
histogram bounds. Names, labels and bounds are checked at compile time; gathering rejects duplicate
family names and collisions with histogram-generated sample names. The encoder admits at most
512 families and writes into the existing 512 KiB output limit. Shared encoding owns family grouping,
label escaping, enum labels and histogram exposition. No registry work occurs on packet processing.

`metrics/histogram.zig` provides one bounded bucket accumulator for durations, population
distributions and score-cache deltas. Durations accumulate exact integer milliseconds and convert
only when exported. Population distributions reset each snapshot and accept negative scores.
Min/max/average score ranges remain a separate aggregate. Client attribution classifies each
connected catalog row once, builds a snapshot-local connection lookup with generation checks,
and derives client and direction marginals from the joint population table.

Existing metric names, labels and bucket boundaries remain available. Compatibility aliases share
the underlying observations; removing an exported alias requires an explicit metrics API change.
