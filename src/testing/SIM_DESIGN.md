# Simulation Framework V2 — Design

## Vision

Run the ENTIRE beacon node state machine in a single process with deterministic control. Same seed = identical execution.

### Use Cases
1. **Integration testing**: multi-node simulations that reach finality
2. **Fuzzing**: random events → verify invariants hold
3. **Regression testing**: replay specific scenarios (reorgs, missed slots, late attestations)
4. **Performance testing**: measure block processing time under simulated load

## Architecture

```
SimController (canonical orchestrator)
├── SimClock (deterministic time)
├── SimTopology (peer graph, req/resp, partitions, gossip delivery)
│   └── SimNetwork (deterministic message delivery)
├── SimValidator[] (duty tracking, block/attestation production)
├── SimNodeHarness[] (each wrapping a BeaconNode)
├── ClusterInvariantChecker (multi-node observations and safety checks)
└── Scenario / Fuzzer (step generators)
```

## New Components

### SimValidator

Simulated validator client that:
- Holds N validator keys (interop keys from epoch cache)
- Computes duties from the sim node's state (proposer + attester)
- Produces blocks when assigned as proposer
- Produces attestations for assigned committees
- Uses stub signatures (verify_signatures: false)

Key design: validators are distributed across nodes. Each node has a
`SimValidator` holding a range of validator indices. The controller
calls `onSlot()` which produces blocks/attestations, then gossips them.

### SimController

Canonical deterministic event orchestrator:
- Manages clock, nodes, validators, network
- `advanceSlot()`: tick clock → proposer produces block → attesters produce → gossip → nodes process → check invariants
- `advanceToEpoch()`: advance slot-by-slot until target epoch
- `runUntilFinality()`: advance until finalized_epoch > 0
- `runScenario()`: execute a scripted sequence of Steps

### SimTopology

Shared topology and transport layer that:
- Owns peer wiring and reconnection across reachable nodes
- Applies partitions and node disconnect/reconnect semantics
- Runs status maintenance and req/resp routing
- Delivers gossip blocks/attestations into the simulated nodes

Key design: slot progression and validator behavior stay in `SimController`,
while transport and peer-graph behavior stay in `SimTopology`.

### Scenario System

Scriptable test cases via a Step union:
- `advance_slot` / `advance_to_epoch` — time progression
- `advance_until` — semantic progress until a condition is satisfied
- `skip_slot` — proposer misses their slot
- `inject_fault` — fault injection (see below)
- `check_invariant` — verify a specific invariant holds
- `network_partition` / `heal_partition` — split/heal network
- `disconnect_node` / `reconnect_node` — node isolation

Built-in scenarios:
- `happy_path`: 4 nodes, 64 slots, reach finality
- `missed_proposals`: some proposers skip
- `network_partition`: split then heal, verify convergence
- `late_attestations`: delayed attestations

### Fault Injection

Extended from existing SimStorage/SimNetwork faults:
- Block: missed_proposal, invalid_state_root
- Attestation: missed_attestation, wrong_head
- Network: message_delay, message_drop_rate, partition
- Node: node_crash, node_restart

### Invariant Checker Enhancement

Multi-node invariants:
- `finality_agreement` — all nodes agree on finalized checkpoint
- `head_freshness` — head slot within N of clock
- `safety` — no two conflicting finalized blocks
- `liveness` — finalized epoch advances within N epochs
- `head_agreement` — fork choice heads consistent across nodes

### Fuzzer

Random step generation with:
- Configurable weights per step type
- Invariant checking after each step
- Reproducer dump on failure (step sequence for replay)

## Implementation Priority

1. SimValidator → sim_validator.zig
2. SimController → sim_controller.zig
3. Scenario system → scenario.zig
4. Enhanced invariants → update cluster_invariant_checker.zig
5. Fuzzer → sim_fuzzer.zig
6. Tests for each component

## Relationship to Existing Code

- SimNodeHarness: used by SimController for each node
- SimController: canonical multi-node harness
- SimTopology: canonical peer-graph and transport layer
- SimNetwork: reused directly
- BlockGenerator / AttestationGenerator: reused by SimValidator
- InvariantChecker / ClusterInvariantChecker: enhanced with new types
