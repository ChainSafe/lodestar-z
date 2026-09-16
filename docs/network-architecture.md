# Native networking architecture

The `network` module implements QUIC/libp2p transport, Ethereum req/resp, gossipsub,
Identify, and managed peer policy. `discv5` supplies discovery, while `udp` owns shared
socket mechanics. The Node.js addon exposes `createNativeNetworkApplicationRuntime`.
The host supplies chain configuration and consensus validation. Transport authentication,
valid SSZ framing, and a positive gossip verdict are separate decisions.

## Layers and owners

| Owner | Responsibility | Lifetime and dependencies |
| --- | --- | --- |
| `udp.Sockets` | One socket per configured family, bounded datagram I/O and provider cleanup | Owned by Transport or the discovery driver; input borrows its receive buffer |
| `quic.Engine` | TLS authentication, cryptographic random generation, connection admission, protocol timers and flow control | Owns its TLS context after successful initialization and all QUIC connections/streams; consumes bytes and explicit time without socket I/O |
| `Transport` | Engine and socket lifetime, OS clock sampling, pacing queues, buffers and bounded I/O turns | Owns startup entropy and teardown; completed progress can accompany a later local or keylog failure |
| `Router` / `Negotiator` | Multistream selection and handler dispatch | Owns negotiation buffers until completion; handlers consume or copy leftovers before the next pump |
| `Service` | Protocol composition and separate control/application output capacity | Owns req/resp, gossip sessions and optional Identify; does not decide consensus validity |
| `Core` | Authenticated peer catalog, Status/Metadata, reputation, demand and dial selection | Uses Service plus the engine; identity generations differ from physical connection generations |
| `NetworkCore` | Managed composition, discovery, local intent and I/O turns | Owns transport and Core; validates resource profiles and composes their deadlines |
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

Peer inputs mark policy selection dirty. `Core.reconcile(now)` evaluates those changes and
publishes coverage deficits and discovery need together. Their const getters return that last
completed evaluation, including its peer counts and demand, without refreshing reputation,
selecting or removing peers, publishing events, or consulting a remembered clock. Callers that
need pending changes immediately must reconcile with explicit time first. Dirty inputs wake
the owner immediately; reputation and metadata deadlines still schedule later evaluations.
Demand expires only when `process` receives the host's next slot. Both observations are empty
before the first evaluation and are cleared on quiescence or shutdown; reconciliation does no
further policy work in either closing state.

The bridge has a mutex around shared command, result, and cancellation state. Protocol
objects belong exclusively to the owner thread. A bounded thread-safe notification wakes
JavaScript; the callback copies data without borrowing growable native buffers. Wake writes
and notifications are different channels. Polling, including the prepared state, is bounded
so a failed wake write cannot strand shutdown.

## Resource admission

Startup configuration fixes connection, negotiation, request, payload, validation, delivery,
and retained-identity capacity. Managed configuration derives request peer capacity from
transport capacity, gossip capacities from peer policy, and router control reservation from
the request owner. Socket send, receive and total-work budgets belong to Transport and are
validated independently of engine admission limits. Independent overrides preserve profile defaults; raw module options retain
their explicit controls. Composition validates shared limits before allocating native owners.
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
and sends stateless Retry under handshake pressure. Retry authenticates the return path
before allocating another handshake. It does not authenticate peer identity or consensus data.
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

Gossip payloads are immutable after admission. Validation, history, and transmit descriptors
hold independent retains. Validation attribution pins retained identities and topic generations.
Per-peer validation limits, expiring unsent IWANT batches, and absolute large-frame leases
prevent one session from keeping those resources indefinitely. Peer-caused large-frame expiry
also sets an identity cooldown; local host pressure does not blame the sender. Disconnected,
unpinned negative identities can be reclaimed under pressure while preserving outbound reserves.

Discovery sessions and routing entries are separate. Authenticated NODES responses may supply
signed referrals without proving each advertised endpoint reachable. QUIC verifies the expected
peer identity before managed admission. Failed candidates eventually lose eviction protection;
manual intent outranks discovered utility. Routing buckets limit unsolicited inbound membership,
maintenance retries cannot monopolize one probe indefinitely, and empty lookups back off.
A fixed challenge table still has finite tolerance for spoofed discovery traffic.

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
