# Discv5 discovery ingress fix plan

> For Hermes: use subagent-driven-development if/when implementing this plan.

Goal
- Stop discv5 UDP receive saturation on nogroup so discovery packets are serviced promptly, peer acquisition recovers, and the node can advance past checkpoint head.

Architecture
- Treat discovery ingress as a first-class workload, not opportunistic maintenance.
- Follow the behavioral direction of:
  - Lodestar-TS: dedicated discv5 worker + event-driven UDP servicing.
  - Lighthouse/discv5: dedicated recv task, bounded internal channels, unsolicited packet filtering, and reduced event-pressure.
- Keep the Zig design idiomatic rather than copying JS/Rust structure literally.

Tech stack
- Zig std.Io / current src/discv5/* stack
- src/networking/discovery_service.zig bridge
- src/node/p2p_runtime.zig orchestration

---

## Current diagnosis

Nogroup evidence says packets are reaching the host but discovery is not keeping up:
- UDP 9001/9002 receive queues pinned near rb ceiling
- rising UdpRcvbufErrors
- very low discovery lookups/dials over long periods
- peer demand remains high while head stays stuck at checkpoint head

The current local code path explains that behavior:
- discovery socket servicing is piggybacked on broader runtime maintenance:
  - src/node/p2p_runtime.zig:1170-1178
  - src/node/p2p_runtime.zig:1211-1227
  - src/node/p2p_runtime.zig:1661-1700
- service.poll() drains UDP packets inline and sequentially:
  - src/discv5/service.zig:587-594
  - src/discv5/service.zig:740-744
  - src/discv5/service.zig:1120-1147
- the per-packet hot path is expensive and repeats global maintenance:
  - src/discv5/protocol.zig:413-419
  - src/discv5/protocol.zig:635-655
  - src/discv5/protocol.zig:1193-1227
- ENRs are decoded/copied multiple times on the same response path:
  - src/discv5/protocol.zig:1244-1271
  - src/discv5/protocol.zig:1399-1463
  - src/discv5/service.zig:791-815
  - src/discv5/service.zig:817-839
  - src/networking/discovery_service.zig:596-610
- event queues use orderedRemove(0), which becomes costly under backlog:
  - src/discv5/protocol.zig:383-386
  - src/discv5/service.zig:574-577

Net: the current path mixes socket IO, decode/session work, event queuing, and maintenance in one place. Under load, it burns too much CPU/allocator time per packet and cannot drain ingress fast enough.

---

## Behavioral references

### Lodestar-TS

Key behaviors worth matching:
- discv5 runs in a dedicated worker thread:
  - /home/cayman/Code/lodestar/packages/beacon-node/src/network/discv5/index.ts:41-65
- UDP sockets are serviced on message callbacks, not a coarse timer poll:
  - /home/cayman/Code/lodestar/packages/beacon-node/node_modules/@chainsafe/discv5/src/transport/udp.ts:81-94
  - /home/cayman/Code/lodestar/packages/beacon-node/node_modules/@chainsafe/discv5/src/transport/udp.ts:131-158
- beacon-node guards random lookup overlap rather than stacking them:
  - /home/cayman/Code/lodestar/packages/beacon-node/src/network/peers/discover.ts:346-374

What to borrow:
- dedicated discovery servicing
- event-driven / immediate packet handling
- single-active random lookup guard

What not to cargo-cult:
- exact JS worker API surface
- exact Node buffer sizes

### Lighthouse / upstream Rust discv5

Key behaviors worth matching:
- dedicated recv task reads UDP sockets continuously with tokio::select:
  - /home/cayman/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/discv5-0.4.1/src/socket/recv.rs:61-129
- recv path does early unsolicited packet filtering before full processing:
  - /home/cayman/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/discv5-0.4.1/src/socket/recv.rs:174-219
- internal handoff is bounded with channels:
  - recv -> handler: channel(30)
  - handler -> service: channel(50)
  - service request: channel(30)
- Lighthouse enables packet filter and rate limiter and suppresses discovered-peer report spam:
  - /home/cayman/Code/lighthouse/beacon_node/lighthouse_network/src/config.rs:277-315

What to borrow:
- dedicated recv stage
- bounded handoff / backpressure
- early packet filtering
- lower event pressure

What not to cargo-cult:
- exact Rust async/task decomposition
- exact rate-limit constants without measuring Zig behavior first

---

## Recommended fix strategy

Use a staged approach.

Phase 1 is the minimum production-real fix to ship first.
Phase 2 is the architectural cleanup that gets us closer to Lodestar/Lighthouse behavior.

### Phase 1: hot-path relief and ingress fairness

Ship these together first.

1. Remove global pruning from the per-packet path.
2. Increase kernel socket receive buffer capacity.
3. Stop discovery ingress from monopolizing a poll pass.
4. Stop launching overlapping random lookups while demand is already being serviced.
5. Add ingress metrics so we can prove the fix on nogroup.

Why Phase 1 first:
- smallest architectural jump that directly attacks the observed bottleneck
- can be validated quickly on nogroup
- reduces risk before the larger worker/task split

### Phase 2: dedicated discovery ingress worker

Once Phase 1 is in and measured, move to a first-class ingress pipeline:
- dedicated discovery recv loop/task
- bounded handoff queue
- decode/session work separated from raw socket reads
- reduced event churn and FIFO queues instead of orderedRemove(0)

Why Phase 2:
- this is the cleanest parity direction versus Lodestar/Lighthouse
- it makes discovery robust even when the rest of the node is busy

---

## Implementation tasks

### Task 1: Add ingress saturation observability

Objective
- Expose enough metrics to prove whether we are draining sockets fast enough and where time is being spent.

Files
- Modify: src/discv5/service.zig
- Modify: src/discv5/udp_socket.zig
- Modify: src/node/metrics.zig
- Modify: src/node/p2p_runtime.zig

Add metrics/log state for:
- packets received per socket
- packets processed per poll pass
- times ingress budget is exhausted
- times drain exits on timeout vs budget
- effective SO_RCVBUF / SO_SNDBUF values after bind
- counts of dropped internal discovery events / queue full incidents

Verification
- metrics endpoint exports the new gauges/counters
- on nogroup, we can compare:
  - kernel UdpRcvbufErrors
  - socket Recv-Q
  - discovery packets processed
  - discovery budget hits

### Task 2: Tune socket buffers explicitly

Objective
- Give the process more headroom so short bursts do not immediately overflow kernel receive queues.

Files
- Modify: src/discv5/udp_socket.zig
- Modify: src/networking/discovery_service.zig
- Modify: src/node/options.zig
- Modify: src/cli/commands/beacon/spec.zig
- Modify: src/cli/commands/beacon/command.zig

Changes
- Add configurable discovery UDP socket buffer sizes.
- Set SO_RCVBUF and SO_SNDBUF in Socket.bind().
- Log the effective accepted values after setsockopt/getsockopt.
- Provide sane defaults biased toward production hosts (MiB scale, not tens of KiB).

Notes
- This is not the whole fix.
- It is guardrail capacity, not substitute for better servicing.

Verification
- unit test for option plumbing if appropriate
- host log shows configured/effective socket buffer sizes
- nogroup no longer sits at the tiny default rb values

### Task 3: Remove pruneExpiredState() from the per-packet path

Objective
- Stop paying global maintenance cost on every inbound datagram.

Files
- Modify: src/discv5/protocol.zig
- Modify: src/discv5/service.zig

Changes
- Delete the call to pruneExpiredState() from Protocol.handlePacket().
- Keep pruning in Service.poll() / maintenance, but run it once per maintenance pass instead of once per packet.
- If needed, split protocol maintenance into cheaper cadence-based functions.

Why
- Current code scans active requests, pending requests, bucket pending entries, and WHOAREYOU rate state per packet.
- That is exactly the wrong place to spend CPU when ingress is overloaded.

Verification
- existing discv5 protocol tests still pass
- add regression test ensuring timed-out requests still produce request_timeout events via periodic maintenance

### Task 4: Make ingress polling budgeted and fair

Objective
- Prevent a hot discovery socket from monopolizing the runtime forever.

Files
- Modify: src/discv5/service.zig
- Modify: src/networking/discovery_service.zig
- Modify: src/node/p2p_runtime.zig

Changes
- Split current Service.poll() into something like:
  - pollIngressBudgeted(max_packets_per_socket)
  - runMaintenance()
- Drain IPv4 and IPv6 fairly with a fixed packet budget per call.
- Do not loop until timeout forever on a hot socket.
- Service ingress every active runtime tick, not only during coarse connectivity maintenance.

Important design point
- Budgeting must preserve fairness between sockets and between discovery and the rest of the node.
- We want steady draining, not “drain until silence”.

Verification
- add tests for:
  - budget stops a drain pass
  - both ip4/ip6 sockets get serviced fairly
- on nogroup:
  - socket Recv-Q should stop pinning at ceiling
  - UdpRcvbufErrors should flatten or drop sharply

### Task 5: Enforce one active random lookup and actually honor lookup_interval_ms

Objective
- Stop lookup traffic from amplifying ingress pressure while the node is already behind.

Files
- Modify: src/networking/discovery_service.zig

Changes
- Track active random lookup id/state.
- Refuse to start a second random lookup while one is active.
- Clear the guard on lookup_finished / timeout.
- Replace the dead lookup_interval_ms config field with real scheduling logic.

Why
- Lodestar-TS explicitly does not stack random lookups.
- Current Zig code defines lookup_interval_ms but does not actually use it.

Verification
- regression tests for:
  - active random lookup blocks overlap
  - interval gate works
  - lookup restarts after finish/timeout

### Task 6: Collapse repeated ENR decode/copy work

Objective
- Stop re-decoding the same ENRs several times on the same response path.

Files
- Modify: src/discv5/protocol.zig
- Modify: src/discv5/service.zig
- Modify: src/networking/discovery_service.zig

Changes
- Move toward a single parse of each ENR on the NODES path.
- Carry forward extracted fields instead of repeatedly duplicating raw ENR bytes and decoding again.
- Prefer direct cache insertion or a richer discovered-node event payload over raw ENR ping-pong.

Why
- Current path decodes/copies the same ENR multiple times before it becomes a candidate.
- Under bursty NODES responses that is wasted allocator and CPU time.

Verification
- existing discovery tests still pass
- add focused test around NODES response handling and emitted/cache state

### Task 7: Replace orderedRemove(0) event queues with FIFO/ring queues

Objective
- Remove O(n^2) queue-drain behavior under backlog.

Files
- Modify: src/discv5/protocol.zig
- Modify: src/discv5/service.zig
- Modify: src/networking/discovery_service.zig

Changes
- Replace ArrayList + orderedRemove(0) event queues with proper FIFO ring/deque structures.
- Add bounded capacity where low-value events can be dropped/coalesced safely.

Why
- Once backlog builds, orderedRemove(0) makes recovery worse.
- Lighthouse’s bounded-channel approach is the right behavioral model here.

Verification
- queue behavior tests
- no event leaks / ownership regressions

### Task 8: Add early unsolicited packet filtering

Objective
- Reject clearly low-value inbound traffic before expensive decode/session work.

Files
- Modify: src/discv5/service.zig and/or src/discv5/protocol.zig
- Possibly add: src/discv5/filter.zig

Changes
- Introduce a lightweight ingress filter/rate limiter.
- Allow expected responses to bypass the unsolicited filter.
- Bound per-IP and total unsolicited packet rates.

Why
- Lighthouse explicitly does this before deeper handling.
- It protects the CPU path, not just the routing table.

Verification
- unit tests around expected-response bypass and per-IP limiting
- on nogroup under real traffic, lower packet decode load for junk traffic

### Task 9: Phase-2 workerization

Objective
- Give discovery ingress its own execution context so socket reads are not delayed by sync/gossip/processor work.

Files
- Modify: src/discv5/udp_socket.zig
- Modify: src/discv5/service.zig
- Modify: src/networking/discovery_service.zig
- Modify: src/node/p2p_runtime.zig

Target design
- dedicated recv loop/task/thread for discovery sockets
- bounded handoff queue into protocol/service stage
- maintenance stays periodic, but socket servicing is continuous

Notes
- This is the strongest parity move toward Lodestar worker + Lighthouse recv-handler behavior.
- Do this after Phase 1 if we still see ingress pressure, or do it directly if implementation cost is acceptable.

Verification
- dedicated tests for shutdown, queue full behavior, and event ordering
- long-run nogroup validation with sustained live traffic

---

## Acceptance criteria

Nogroup should satisfy all of these after the fix:
- discovery UDP sockets no longer pin at receive-buffer ceiling during normal operation
- UdpRcvbufErrors stop increasing materially during steady-state observation
- beacon_discovery_lookups_total continues to move while peer demand exists
- beacon_discovery_dials_total continues to move while peer demand exists
- connected peers rise above the current 1-peer stranded state
- head_slot advances beyond checkpoint-sync slot
- sync_distance trends down instead of up

Secondary acceptance criteria
- no discovery event queue explosion
- no reintroduction of discovery-demand starvation semantics
- no new retry storms or overlapping random-lookup churn

---

## Recommended execution order

Recommended first shipping sequence:
1. Task 1
2. Task 2
3. Task 3
4. Task 4
5. Task 5
6. Verify on nogroup
7. If still needed under load, do Tasks 6-9

Rationale
- Tasks 2-5 directly target the observed primary issue.
- Tasks 6-9 make the system more scalable and parity-real, but the first wave should tell us how much of the live failure was coarse servicing plus hot-path waste.

---

## Practical verification commands

After deployment, check:

```bash
ssh devops@nogroup-rs2000-0 'curl -fsS http://127.0.0.1:9596/eth/v1/node/syncing'
ssh devops@nogroup-rs2000-0 'curl -fsS http://127.0.0.1:8008/metrics | grep -E "^(beacon_head_slot|beacon_sync_distance|libp2p_peers|beacon_discovery_lookups_total|beacon_discovery_dials_total|lodestar_discovery_peers_to_connect|beacon_discovery_pending_dials)"'
ssh devops@nogroup-rs2000-0 'sudo ss -u -n -m -p state all | egrep "9001|9002|skmem"'
ssh devops@nogroup-rs2000-0 'nstat -az UdpInDatagrams UdpRcvbufErrors Udp6InDatagrams Udp6RcvbufErrors 2>/dev/null || true'
ssh devops@nogroup-rs2000-0 'sleep 20; nstat -az UdpInDatagrams UdpRcvbufErrors Udp6InDatagrams Udp6RcvbufErrors 2>/dev/null || true'
```

Success pattern
- Recv-Q materially below rb ceiling
- UdpRcvbufErrors flat or nearly flat over the sample window
- discovery lookups/dials continue increasing
- peers no longer stranded at 1
- head slot begins advancing
