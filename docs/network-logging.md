# Native network logging

The binding root installs `std_options.logFn` and debug scope levels for network
modules. This keeps network debug calls available in ReleaseSafe builds while
preserving the normal settings for other Zig code. The hook follows Zig's
[standard library options](https://ziglang.org/documentation/0.16.0/#Standard-Library-Options).

Each runtime owns its log queue. A thread-local binding selects that queue during
initialization and on the network owner thread, and is restored before runtime
release. The hook never calls JavaScript. Unbound calls use Zig's default logger.

## Host integration

Both runtime APIs expose `setLogLevel("error" | "warn" | "info" | "debug" | "off")`
and `drainLogs(maxRecords = 32)`. The default capture level is info. Draining returns
owned records plus cumulative dropped, suppressed and truncated counts. It does
not consume protocol events and remains available after `close()`. An allocation
failure leaves the batch queued for retry. Use one consumer per runtime.

Lodestar's native adapter captures debug, drains up to 32 records every 250 ms
through the standard `network/native` child logger, and flushes up to 128 records
after native shutdown. The existing console and file filters decide delivery.
Enable detailed console records with:

```sh
--logLevelModule network/native=debug
```

This also makes them available through an existing systemd journal scrape. Debug
file logging needs no separate native sink. The host attaches `nativeScope`,
`nativeSession`, `nativeSequence`, `nativeTimestampMs`, `nativeMonotonicMs` and
`nativeTruncated` as structured context. Native timestamps describe capture time;
the outer logger timestamp describes host delivery. IDs and timestamps remain
lossless decimal strings in host context.

## Instrumentation conventions

Use `std.log.scoped(.network_reqresp).debug("request_started ...", .{...})` with a
scope below. Start messages with a stable event name and use `key=value` fields.
Record transitions, outcomes and refusal reasons where the decision is made.
Pair operations with their completion or failure, including generation-bearing
handles and elapsed milliseconds. Avoid per-byte, per-packet and per-chunk logs.
Do not call policy functions that mutate state merely to compute a log field.

| Scope | Recorded behavior |
| --- | --- |
| `network_runtime` | Initialization, preparation, activation, shutdown, terminal errors, 30-second health summaries |
| `network_core` | Intent changes, dial starts and refusals |
| `network_quic` | Authenticated connections, close reasons and codes, oversized datagram refusals |
| `network_peers` | Admission, Identify outcomes, Goodbye wire reason, disconnect client and lifetime, one-shot dial completion/expiry, retry backoff |
| `network_reqresp` | Request start/completion, method, direction, stream, chunk count and duration |
| `network_reqresp_errors` | Request failure phase/reason, response code, admission and rate-limit refusals |
| `network_gossip` | Non-accept validation verdicts, expiry, stale verdicts, malformed RPCs, pressure and stream resets |
| `network_gossip_errors` | Send queue refusal resource, occupancy, oldest age and transport write failures |
| `network_mesh` | Graft/prune transitions, topic, connection and backoff |
| `network_discovery` | Lookup starts/completion, authenticated and published candidates, query counts, elapsed time and discovery failures |
| `network_bridge` | Command failures, host/native request mapping, publication pressure |

Info covers lifecycle and periodic health; errors cover terminal owner failures.
Expected network churn and peer failures use debug. Logs contain public peer IDs,
message IDs and protocol metadata. Never log payloads, private keys, JWTs or raw
ENRs. Add a regression test when instrumenting an important failure path.

## Bounds and loss

Each runtime has 128 records with at most 768 ASCII bytes per message. Formatting
truncates at this bound and replaces control/non-ASCII bytes with `?`. Debug can
occupy 96 slots and info 112, leaving room for more severe records. New records
are dropped when their queue allowance is exhausted; queued records are never
evicted. Sequences advance for enabled attempts, so gaps can indicate loss.

Fixed one-second windows permit eight records per scope and severity, subject to
global limits of 8 errors, 16 warnings, 16 info and 64 debug records per second.
These limits bound hostile peer amplification. Repeated events can be suppressed;
the log is diagnostic evidence, not a complete audit trail. Request failures and
mesh transitions have separate scopes to reduce contention with routine traffic.

`getMetrics()` includes `lodestar_native_logs_{emitted,dropped,suppressed,truncated}_total`
by scope and level, plus queue occupancy, capacity and high-water gauges. Emitted
means enqueued, not acknowledged by the host logger. Lodestar also exports
`lodestar_native_log_delivery_errors_total` and reports accumulated native loss at
most once per 30 seconds. Check these before interpreting an absent event.

## Runtime investigation

Start with health and loss metrics, then narrow by capture interval, session and
scope. Connection/request handles include generations; combine the native session
with host identity and process lifetime when correlating across restarts. Follow
`host_request_submitted` to its native request handle, then `request_started` and
`request_completed` or `request_failed`. Gossip verdicts carry message IDs and
peer identities; mesh transitions carry topic and connection handles.

The Lodestar adapter's peer REST endpoints expose the bounded native peer snapshot,
including client agent, QUIC address, Status and metadata. Remote uint64 fields
remain decimal strings in diagnostic JSON. Wall-clock peer timestamp fields are
zero when unavailable; use the native log timestamps for connection timing.

`request_write_stopped` records QUIC request half-closure while response processing
continues. Its `detail` distinguishes STOP_SENDING from a stream already retired
after buffered response EOF. The per-method counter
`lodestar_native_reqresp_request_write_stops_total` counts these transitions even
when debug records are suppressed. A later `request_failed` remains authoritative
for response decoding, reset, or timeout failures and includes the native I/O error
in `detail`. Scheduled disconnects include peer identity and the reported agent.
`health_timeout` means an RPC deadline expired; `health_error` covers other failed
or empty health responses. Neither label implies a consensus validation failure.

`peer_goodbye_received` records the remote uint64 code, its bounded reason label,
the reported agent and the resulting retry cooldown. `peer_disconnected` identifies
the client even for a transport close without Goodbye. Compare
`lodestar_native_peer_closes_by_client_total{client,reason}` with the connected-client
gauges, and use `lodestar_native_peer_goodbyes_total{reason}` for received reasons.
An absent Goodbye is not evidence of a particular remote policy decision.
`during_close=true` means the Goodbye was recovered from retained authenticated
stream bytes before connection cancellation. The counters
`lodestar_native_reqresp_goodbyes_{recovered,incomplete}_on_close_total` distinguish
successful recovery from unavailable or incomplete data. Incomplete cases log
the buffered and decoded byte counts, decoder phase, FIN state and native error.
An already selected local disconnect reason retains precedence.

`response_finish_stopped` records a peer stopping only the final response FIN
after complete chunks were written. This completes the local serving operation;
it does not claim the peer validated the response. The per-method counter is
`lodestar_native_reqresp_response_finish_stops_total`. Stops before any chunk or
while response bytes remain pending still fail.

`dial_backoff` includes consecutive failures, connection lifetime and retry delay.
Successful one-shot `connect()` calls retire their dial intent. Expiry and explicit
disconnect also retire it; direct membership remains independently persistent.
The `lodestar_native_dial_` counters distinguish these outcomes. Periodic Status
requests follow the peer timer; local head and metadata updates do not restart it.
Unreachable dial destinations rotate to the next advertised address and use
failure backoff. Local resource refusals remain deferred without penalizing the
peer. `dial_failed` and `dial_deferred` identify the endpoint and native error.

Peer age, app/gossip score, attnet and custody-count histograms describe the current
connected population and are rebuilt each snapshot. Read their buckets directly,
without `rate()`. Metadata availability gauges distinguish unknown coverage from
an advertised zero. `lodestar_native_peers_by_client_direction` separates the
client mix by connection direction. QUIC close counters include failures before
peer admission, and Identify failures have fixed reason labels.

`lodestar_discovery_dial_time_seconds{status="success"|"error"}` and
`lodestar_discovery_find_node_query_time_seconds` are cumulative duration
histograms. Local dial deferrals and cancelled operations are excluded. Native
dial/QUIC occupancy gauges, pending routing revalidations, foreground queries and
candidate idle time distinguish pressure from stalled discovery. Candidate idle
time is absent before the first publication and after close.

Foreground discovery prioritizes current-network QUIC records and counts only
matching successes toward convergence. Each walk permits at most 128 queries
with three in flight. `lodestar_native_discovery_` counters show query progress,
authenticated candidates and publications. Candidate rejection labels distinguish
missing `eth2`, incompatible fork, malformed ENR, absent QUIC, endpoint scope,
unwanted subnet/custody coverage and output capacity. A signed advertisement alone
does not prove its QUIC endpoint is reachable.

`gossip_send_pressure` distinguishes descriptor, payload-byte and control-queue
limits. Each peer has 128 data descriptors to accommodate a 64-verdict host burst;
configured byte and age limits still apply. Its counters are
`lodestar_native_gossip_queue_drops_total{reason}` and survive connection-slot reuse.
These count queue admission refusals, not packets lost on the wire. Sampled logs
include queue occupancy and oldest age at logging time, after any intervening drain.

For the Cayman Hoodi deployment, existing Loki labels can select these records:

```logql
{job="beacon",instance="cayman-ax41x",network="hoodi"} |= "nativeScope="
{job="beacon",instance="cayman-ax41x",network="hoodi"} |= "nativeScope=network_reqresp_errors"
{job="beacon",instance="cayman-ax41x",network="hoodi"} |= "network_health"
```

With JSON output, parse context according to the configured Lodestar logger
format. Peer IDs, request handles and message IDs belong in log content, never
Prometheus or Loki index labels. Logging does not capture quiche internals,
packet traces, successful gossip validation for every message, or payload bytes.

Discovery failures include `stage=coordinator|clock|maintenance|receive|process`.
`discovery_send_failed` records the destination and packet length without payload
bytes. `revalidation_deferred` records the local retry interval. A failed routing
revalidation does not stop receive processing or evict its incumbent, and cannot
retry within one second. The `lodestar_native_discovery_` counters
`maintenance_failures_total`, `receive_failures_total`,
`processing_failures_total`, and `coordinator_failures_total` distinguish failures
from ordinary query timeouts.

`lodestar_native_discovery_authenticated_not_retained_total` counts authenticated
responders that were not retained at their exact endpoint in the routing table.
They still pass through the ordinary ENR, fork, demand and endpoint-scope checks
before publication to the dialer. Routing-table occupancy does not establish
whether a peer is authenticated or usable.
