# Aggregate gossip validation follow-up plan

> For Hermes: after the self-dial fix, use this plan to drive the next local Kurtosis interoperability fix.

Date: 2026-04-21
Context: in the working reference-only Kurtosis sidecar harness, Lodestar-Z now connects to Lighthouse over QUIC and range-syncs to head, but then disconnects the Lighthouse peer after false-invalid aggregate gossip penalties.

## Goal

Fix the post-sync Lighthouse disconnect so the sidecar can retain a real gossip-capable QUIC peer after catch-up.

## Current evidence summary

What is already proven:
- self-dial filtering fixed a real bug
- sidecar now forms a real QUIC connection to Lighthouse
- sidecar range-syncs successfully from genesis anchor to head
- once gossip becomes active, the sidecar penalizes the Lighthouse peer with 5 `low_tolerance` gossipsub reports and disconnects it

Current live evidence from the successful rerun:
- `libp2p_peers 1` during sync, then `0` after catch-up
- `beacon_gossipsub_outbound_streams 1`, `beacon_gossipsub_topic_peers 1` during the good window
- `p2p_peer_reports_total{source="gossipsub",action="low_tolerance"} 5`
- logs show:
  - `Gossip sync contribution rejected ... err=error.InvalidSignature`
  - `single aggregate BLS failed for aggregator ...`
  - `Peer action ... low_tolerance from gossipsub`
  - `Peer disconnected ... total=0`
- Lighthouse peer REST shows the current sidecar peer becomes `disconnected`

High-confidence conclusion:
- the next primary bug is false-invalid same-message aggregate gossip validation for:
  - `beacon_aggregate_and_proof`
  - `sync_committee_contribution_and_proof`
- a secondary local issue is that direct-peer dialing is startup-only, so a single disconnect can strand the node with `peers=0`

## Most likely root-cause area

Strongest local suspect files:
- `src/node/gossip_node_callbacks.zig`
  - `resolveAggregate()`
  - `getSingleCommitteeAttestingIndices()`
  - `verifyResolvedAggregateSignature()`
  - `syncContributionParticipantIndices()`
  - `verifySyncContributionAggregateSignature()`
  - `verifySyncContributionSignature()`
- `src/state_transition/utils/signature_sets.zig`
- `src/state_transition/utils/bls.zig`

Rationale:
- both failing topics are same-message aggregate gossip paths
- single-signature paths are healthy enough
- the local code hand-reconstructs participant/pubkey sets and signing roots in gossip callbacks instead of routing through one canonical signature-set construction path

## Reference behavior to preserve

- Lodestar-TS:
  - `packages/beacon-node/src/chain/validation/aggregateAndProof.ts`
  - `packages/beacon-node/src/chain/validation/syncCommitteeContributionAndProof.ts`
  - `packages/beacon-node/src/chain/validation/signatureSets/*.ts`
- Lighthouse:
  - `consensus/state_processing/src/per_block_processing/signature_sets.rs`

Behavioral takeaway:
- reference clients centralize signature-set construction for wrapper signatures and inner aggregate signatures
- local gossip validation should move toward shared canonical construction instead of bespoke callback-local reconstruction

## Plan

### Task 1: Prove exactly which signature leg is failing

Files:
- Modify: `src/node/gossip_node_callbacks.zig`
- Verify with local Kurtosis sidecar logs only; no deploy yet

Add temporary debug instrumentation in the two aggregate paths to distinguish which leg fails:
- aggregate gossip:
  - selection proof
  - aggregate-and-proof wrapper signature
  - inner aggregate attestation signature
- sync contribution gossip:
  - selection proof
  - contribution-and-proof wrapper signature
  - inner aggregate sync contribution signature

Success criterion:
- one rerun clearly identifies whether failures are concentrated in the inner aggregate leg, wrapper leg, or both

### Task 2: Add parity-style regression tests for signature-set construction

Files:
- Modify: `src/node/gossip_node_callbacks.zig`
- Test: existing node/gossip tests or a new focused test file if necessary

Add tests that build representative:
- `SignedAggregateAndProof`
- `SignedContributionAndProof`

For each object, compare:
- locally reconstructed participant indices
- locally reconstructed signing roots
against the canonical/reference construction expected for the same object

Priority assertions:
- attestation aggregate signing root matches reference construction
- contribution-and-proof signing root matches reference construction
- sync contribution participant index selection matches the expected subcommittee slice
- sync contribution aggregate signing root matches reference construction

Success criterion:
- a failing regression test reproduces the current mismatch before code changes

### Task 3: Collapse gossip aggregate verification onto one canonical signature-set path

Files:
- Modify: `src/node/gossip_node_callbacks.zig`
- Possibly add small helper(s) under:
  - `src/state_transition/utils/signature_sets.zig`
  - or a new focused helper file under `src/node/` if that is cleaner

Implementation direction:
- stop open-coding same-message aggregate signature inputs separately in the gossip callback path where possible
- reuse a single canonical constructor for:
  - aggregate-and-proof wrapper signature set
  - contribution-and-proof wrapper signature set
  - inner aggregate signature set
- keep the early gossip IGNORE/REJECT semantics unchanged; only change how the signature inputs are assembled

Success criterion:
- regression tests from Task 2 pass
- the code path for both failing topics shares as much signature-set construction as practical

### Task 4: Re-run the Kurtosis sidecar and verify peer retention after catch-up

Files:
- none required unless extra logging is needed

Rerun procedure:
1. `zig build`
2. rebuild `lodestar-z:kurtosis`
3. restart `lodestar-z-sidecar-ref` from a fresh data dir
4. monitor:
   - sidecar sync endpoint
   - sidecar metrics
   - Lighthouse peer endpoint
   - sidecar logs around gossip validation and peer actions

Success criterion:
- sidecar again reaches head
- the Lighthouse peer remains connected after gossip becomes active
- `p2p_peer_reports_total{source="gossipsub",action="low_tolerance"}` no longer climbs from these false-invalid messages

### Task 5: Fix direct-peer redial semantics after disconnect

Files:
- Modify: `src/node/p2p_runtime.zig`
- Test: add or update runtime/peer-manager tests if feasible

Current problem:
- `bootstrapNextDirectPeer()` is startup-only and consumes each configured direct peer once by incrementing `next_direct_peer_index`
- after a disconnect, no redial occurs for a one-peer harness

Implementation direction:
- treat direct peers as persistent curated targets, not one-shot startup bootstrap entries
- redial boundedly when the direct peer is disconnected and not already dialing/cooling down
- do not create reconnect storms; keep cooldown / dial timeout semantics intact

Success criterion:
- if the only direct Lighthouse peer disconnects, the sidecar attempts a later redial instead of staying stranded at `peers=0`

## Verification commands

Local build/tests:
```bash
zig build test:node
zig build test:networking
zig build
```

Image rebuild:
```bash
docker build -f docker/kurtosis/Dockerfile -t lodestar-z:kurtosis .
```

Sidecar rerun:
- use the existing reference-only enclave
- restart the sidecar with a fresh `/tmp/lodestar-z-peer-trace-ref/sidecar-data-*` dir
- keep the existing Lighthouse direct-peer argument unless the reference harness is changed

Runtime checks:
```bash
curl -fsS http://127.0.0.1:33952/eth/v1/node/syncing
curl -fsS http://127.0.0.1:33808/metrics | grep -E '^(libp2p_peers|p2p_peer_connection_state_count|beacon_gossipsub_mesh_peers|beacon_gossipsub_topic_peers|beacon_gossipsub_outbound_streams|p2p_peer_reports_total|beacon_reqresp_outbound_requests_total|beacon_head_slot|beacon_sync_distance)'
docker logs --since 5m lodestar-z-sidecar-ref 2>&1 | perl -pe 's/\e\[[0-9;]*[A-Za-z]//g'
curl -fsS http://127.0.0.1:33008/eth/v1/node/peers
```

## Exit criteria

This follow-up is done when all of the following are true:
- self-dial loop remains absent
- sidecar reaches head again
- Lighthouse stays connected after gossip activation
- false-invalid aggregate gossip rejections disappear or are reduced to clearly legitimate cases
- a direct-peer disconnect no longer strands the sidecar permanently at zero peers
