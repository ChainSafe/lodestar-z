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
| `network_peers` | Admission, scheduled disconnection, disconnection reason and connection lifetime |
| `network_reqresp` | Request start/completion, method, direction, stream, chunk count and duration |
| `network_reqresp_errors` | Request failure phase/reason, response code, admission and rate-limit refusals |
| `network_gossip` | Non-accept validation verdicts, expiry, stale verdicts, malformed RPCs, pressure and stream resets |
| `network_mesh` | Graft/prune transitions, topic, connection and backoff |
| `network_discovery` | Lookup starts/completion, candidate counts and discovery failures |
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
