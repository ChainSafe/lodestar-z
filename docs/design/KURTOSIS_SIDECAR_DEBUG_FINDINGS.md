# Kurtosis sidecar debug findings

Goal: debug Lodestar-Z against reference peers in Kurtosis without forcing it through ethereum-package's Lodestar launcher assumptions.

Date: 2026-04-21

## Setup that worked

1. Launch a reference-only enclave:

```bash
kurtosis run github.com/ethpandaops/ethereum-package@5.0.1 \
  --enclave lodestar-z-peer-trace-ref \
  --args-file kurtosis-peer-trace-reference.yaml \
  --image-download missing \
  --verbosity brief
```

2. Reference services in the successful run:
- `cl-1-lodestar-reth`
  - REST `http://127.0.0.1:33001`
  - metrics `http://127.0.0.1:33002`
  - internal IP `172.16.8.13`
- `cl-2-lighthouse-geth`
  - REST `http://127.0.0.1:33008`
  - metrics `http://127.0.0.1:33009`
  - internal IP `172.16.8.14`
- Docker network:
  - `kt-lodestar-z-peer-trace-ref`
  - subnet `172.16.8.0/22`

3. Download enclave files for the sidecar:

```bash
mkdir -p /tmp/lodestar-z-peer-trace-ref
kurtosis files download lodestar-z-peer-trace-ref el_cl_genesis_data /tmp/lodestar-z-peer-trace-ref/genesis
kurtosis files download lodestar-z-peer-trace-ref jwt_file /tmp/lodestar-z-peer-trace-ref/jwt
```

4. Start Lodestar-Z as a separate container on the Kurtosis network:

```bash
docker run -d \
  --name lodestar-z-sidecar-ref \
  --network kt-lodestar-z-peer-trace-ref \
  --ip 172.16.8.20 \
  -p 33952:4000 \
  -p 33808:8008 \
  -v /tmp/lodestar-z-peer-trace-ref/genesis:/network-configs:ro \
  -v /tmp/lodestar-z-peer-trace-ref/jwt:/jwt:ro \
  -v /tmp/lodestar-z-peer-trace-ref/sidecar-data:/data \
  --entrypoint /usr/local/bin/lodestar-z \
  lodestar-z:kurtosis \
  beacon \
  --logLevel debug \
  --port 9000 \
  --discoveryPort 9001 \
  --dataDir /data \
  --discv5 \
  --execution.urls http://el-1-reth-lodestar:8551 \
  --rest \
  --rest.address 0.0.0.0 \
  --rest.port 4000 \
  --nat \
  --jwt-secret /jwt/jwtsecret \
  --enr.ip 172.16.8.20 \
  --enr.tcp 9000 \
  --enr.udp 9001 \
  --metrics \
  --metrics.address 0.0.0.0 \
  --metrics.port 8008 \
  --supernode \
  --paramsFile /network-configs/config.yaml \
  --checkpointState /network-configs/genesis.ssz \
  --bootnodes '<lodestar ENR>,<lighthouse ENR>' \
  --direct-peers '/ip4/172.16.8.14/udp/33010/quic-v1/p2p/<lighthouse peer id>'
```

This avoids ethereum-package's direct Lodestar launcher assumptions:
- TCP readiness on the CL port
- `--port == --discoveryPort`

## What the sidecar proved

### 1. QUIC connectivity to Lighthouse works and is retained

Sidecar metrics/logs showed:
- `libp2p_peers 1`
- `beacon_gossipsub_mesh_peers 1`
- `beacon_gossipsub_topic_peers 1`
- outbound `status` success = 1
- outbound `beacon_blocks_by_range` success = 4
- repeated ping success in both directions
- identify + gossipsub stream activity on the Zig side

Lighthouse REST showed the sidecar as a connected peer:

```json
{
  "peer_id": "16Uiu2HAmG1kv9d9M8KNvVuArngpALFUy71N7eMaoyH17BZRoLqsc",
  "last_seen_p2p_address": "/ip4/172.16.8.20/udp/51658/quic-v1",
  "state": "connected",
  "direction": "inbound"
}
```

Conclusion:
- the sidecar path successfully established and retained a QUIC peer relationship with Lighthouse
- this is enough to move past the earlier "cannot even launch Lodestar-Z in Kurtosis" blocker

### 2. The sidecar did not connect to the reference Lodestar-TS node

Reference Lodestar peer list still only showed Lighthouse as connected.

Conclusion:
- in this Kurtosis setup, the productive peer relationship was Lighthouse <-> Lodestar-Z
- this reproduction does not yet prove TS-on-Kurtosis is QUIC-usable for our sidecar

### 3. The node is not failing because of churn in this reproduction

Despite only one peer, the connection remained up long enough for:
- repeated pings
- repeated gossipsub heartbeats
- repeated blocks-by-range requests and responses

This is not the same immediate churn pattern seen on the public host.

## New root cause exposed by the sidecar reproduction

The sidecar stayed connected but did not advance head.

Observed state:
- reference nodes were synced at head slot `55`
- sidecar stayed at head slot `0`
- sidecar sync distance kept rising

Sidecar metrics:
- `beacon_block_import_results_total{source="range_sync",outcome="genesis_block"} 3`
- `beacon_block_import_results_total{source="range_sync",outcome="parent_unknown"} 93`
- `beacon_range_sync_download_requests_total{sync_type="head"} 4`
- `beacon_range_sync_download_success_total{sync_type="head"} 4`
- `beacon_range_sync_processing_error_total{sync_type="head"} 3`
- `beacon_range_sync_segment_results_total{sync_type="head",result="failed"} 3`

Zig logs:

```text
range sync segment completed sync_type=head result=failed chain_id=0 batch_id=0 generation=1 blocks=32 imported=0 skipped=1 failed=31 optimistic=0 epoch_transitions=0 elapsed_ms=28 errors=genesis_block=1,parent_unknown=31 head_slot=0 finalized_epoch=0
range sync segment completed sync_type=head result=failed chain_id=0 batch_id=0 generation=2 blocks=32 imported=0 skipped=1 failed=31 optimistic=0 epoch_transitions=0 elapsed_ms=1 errors=genesis_block=1,parent_unknown=31 head_slot=0 finalized_epoch=0
range sync segment completed sync_type=head result=failed chain_id=0 batch_id=0 generation=3 blocks=32 imported=0 skipped=1 failed=31 optimistic=0 epoch_transitions=0 elapsed_ms=1 errors=genesis_block=1,parent_unknown=31 head_slot=0 finalized_epoch=0
```

Interpretation:
- range sync is downloading blocks successfully
- each segment starts at slot `0`
- slot `0` is skipped as `GenesisBlock`
- slots `1..31` then fail as `ParentUnknown`
- this causes range sync to collapse back to idle with head still at slot `0`

## Strongest evidence: our genesis anchor root does not match the canonical peer genesis block root

Sidecar head root after bootstrap from `genesis.ssz`:
- `0xdde847e4dde10b0f163439c1ea65491d2bf8d317a78c38e95c244c6fce594f2e`

Canonical slot-0 block root from both reference nodes:
- `0xdbae0441632c829bfce09619dacfeeeab539c5bec83061b59e9d0d72a6db48b5`

Therefore:
- the sidecar is anchored to a different slot-0 root than the network's canonical genesis block root
- when range sync downloads the canonical genesis block and skips it as `GenesisBlock`, the next block's parent is still unknown to our chain view
- this exactly matches the `genesis_block=1,parent_unknown=31` segment failures

## Most likely local code-path explanation

Relevant code:
- `src/cli/commands/beacon/command.zig`
  - checkpoint-state file at slot `0` correctly goes through `finishGenesis(...)`
- `src/chain/chain.zig`
  - `bootstrapFromGenesis()` computes `genesis_block_root` as `hashTreeRoot(latestBlockHeader())`
- `src/sync/sync_chain.zig`
  - range sync starts batches from `start_epoch * SLOTS_PER_EPOCH`
  - for a genesis anchor this means start slot `0`
- `src/chain/blocks/verify_sanity.zig`
  - slot `0` is skipped as `GenesisBlock` when `ignore_if_known = true`
  - block import then requires later parents to be known in fork choice or `block_to_state`

Current hypothesis:
- bootstrapping from the Kurtosis `genesis.ssz` produces an anchor root derived from the state's latest block header that does not equal the canonical genesis block root served by peers
- then range sync re-requests slot `0`, skips it, and every later block in the segment sees an unknown parent

## Why this matters for the broader peering investigation

This sidecar reproduction successfully separates two concerns:

1. Peer connectivity / retention
- QUIC connection to Lighthouse can be established and retained in the devnet

2. Sync/import correctness after connection
- even with a retained QUIC peer, Lodestar-Z still fails to make sync progress here because of a genesis-anchor / range-sync import problem

So this local Kurtosis path has already exposed a non-peering correctness bug that would have been easy to misdiagnose as mere peer churn.

## Recommended next debug step

Do not change the peer logic first.

First fix or prove the genesis-anchor mismatch:
- compare how Lodestar-TS derives / persists the canonical genesis block root when starting from a genesis state file
- verify whether Lodestar-Z should seed the canonical slot-0 block root differently during `finishGenesis(...)`
- alternatively verify whether range sync should start from slot `anchor_slot + 1` when bootstrapping from genesis-state-only input that does not yet prove a canonical genesis block root match

A good regression target:
- boot from the Kurtosis `genesis.ssz`
- connect to a reference peer
- confirm `block 0 root == peer canonical slot-0 root`
- confirm first head-range segment imports slots `1..N` without `parent_unknown`

## Additional finding after the bootstrap and fork-resolution fixes

After the genesis-anchor and gossip-fork fixes, the sidecar could sync deep into the devnet, but a later stall exposed a new local issue.

Observed state from the running sidecar:
- current node identity endpoint reported:
  - peer id `16Uiu2HAmUt6awTS83t8RKYyX5Fw8HXY8tB4EoYRLNruzntEwQhpt`
  - p2p address `/ip4/172.16.8.20/udp/9000/quic-v1/p2p/16Uiu2HAmUt6awTS83t8RKYyX5Fw8HXY8tB4EoYRLNruzntEwQhpt`
- metrics at stall showed:
  - `libp2p_peers 0`
  - `beacon_gossipsub_mesh_peers 0`
  - `beacon_gossipsub_topic_peers 0`
  - `beacon_gossipsub_outbound_streams 0`
  - `beacon_head_slot 539`
  - `beacon_sync_distance` continuing to grow

Zig logs repeatedly showed discovery surfacing our own sidecar address as a dial candidate:

```text
queued discovered peer has_quic=true source=custody_query addr4=.{ .ip4 = .{ .bytes = { 172, 16, 8, 20 }, .port = 9000 } } addr6=null
Connected to discovered peer ...
Discovered ENR identity did not match connected peer ...; dropping connection
```

This sequence repeated over and over while peer count stayed at zero.

## Current root-cause hypothesis: stale self-address ENRs bypass self filtering

The current discovery self-filter in `src/networking/discovery_service.zig` rejects candidates only when:
- `candidate.node_id == local_node_id`

That is sufficient for a current self ENR, but not for stale ENRs that still advertise our fixed sidecar address (`172.16.8.20:9000`) with an older node identity.

Why this is plausible in this harness:
- the sidecar is repeatedly restarted on the same fixed Kurtosis IP
- prior runs used fresh sidecar data dirs / identities
- reference peers can retain or rediscover old ENRs for that same address
- when Lodestar-Z later rediscovers one of those stale ENRs, the candidate address still points back to the current sidecar container
- dialing that address reaches the current node, but the connected libp2p peer ID does not match the stale ENR pubkey/node identity
- `registerConnectedPeer()` in `src/node/p2p_runtime.zig` then logs:
  - `Discovered ENR identity did not match connected peer ...; dropping connection`

So the node is not just suffering generic churn here; it is repeatedly self-dialing through stale discovery records for its own address.

## Most likely fix direction

Treat "our advertised address" as self, not only "our current node ID".

The clean production-real direction is:
1. add a discovery candidate filter that rejects peers whose dial address matches the node's own advertised QUIC endpoint(s)
   - IPv4: advertised IP + QUIC/P2P port
   - IPv6: advertised IP + QUIC/P2P port
2. apply that filter before caching and/or before queueing cached ENRs for dial
3. optionally prune cached ENRs whose address collides with the local advertised address, even if their node ID differs
4. add a regression test covering:
   - local advertised address `172.16.8.20:9000`
   - stale cached ENR with different node ID/pubkey but same dial address
   - expected result: candidate is filtered and never dialed

This issue is specific to the sidecar devnet harness because the node is intentionally reused at a fixed private IP across restarts, but the fix is still production-real: a node should never try to dial its own advertised transport endpoint even if discovery learns a stale identity for that endpoint.

## Reference-client peering reality in the current Kurtosis harness

The current reference-only enclave is not symmetric from a QUIC-interop perspective.

### Kurtosis Lodestar-TS is TCP-only in this setup

Evidence:
- `GET /eth/v1/node/identity` on `cl-1-lodestar-reth` reports only TCP P2P addresses:
  - `/ip4/172.16.8.13/tcp/33000/p2p/...`
- no `/udp/.../quic-v1` P2P address is advertised by Lodestar-TS here
- `kurtosis service inspect` for `cl-1-lodestar-reth` shows:
  - `--port=33000`
  - `--discoveryPort=33000`
  - no separate QUIC listen/ENR port
- Lodestar's peer REST API has never shown any of the sidecar peer IDs; querying the current sidecar peer ID returned `404`

Conclusion:
- in this exact Kurtosis configuration, the reference Lodestar-TS node is not a meaningful QUIC libp2p peering target for a QUIC-only Lodestar-Z sidecar
- discovery PONG/NODES responses from `172.16.8.13:33000` only prove discv5 reachability, not transport compatibility

### Lighthouse is the real bilateral peer target here

Evidence:
- `kurtosis service inspect` for `cl-2-lighthouse-geth` shows explicit QUIC configuration:
  - `--quic-port=33010`
  - `--enr-quic-port=33010`
- the sidecar is configured with a direct peer to Lighthouse QUIC:
  - `/ip4/172.16.8.14/udp/33010/quic-v1/p2p/<lighthouse peer id>`
- Lighthouse peer REST shows multiple disconnected sidecar identities from `172.16.8.20` over QUIC, including the current sidecar identity:
  - `/ip4/172.16.8.20/udp/.../quic-v1`
- earlier sidecar metrics showed successful:
  - `status`
  - `ping`
  - `metadata`
  - `beacon_blocks_by_range`
  against that peer path

Conclusion:
- after the self-dial loop is removed, Lighthouse remains the correct local reference client for the next bilateral retention/debugging loop
- Lodestar-TS can still contribute discovery-side evidence in this harness, but not a fair QUIC peer-retention comparison unless its Kurtosis launch is changed to actually expose QUIC transport

## Post-self-dial-filter rerun: what actually happens now

After rebuilding `lodestar-z:kurtosis` with the self-address discovery filter and restarting the sidecar from a fresh data dir:
- the sidecar no longer got trapped in the old self-dial loop
- it formed a real QUIC connection to Lighthouse
- Lighthouse reported the current sidecar peer as:
  - `state = connected`
  - `direction = inbound`
  - address `/ip4/172.16.8.20/udp/<ephemeral>/quic-v1`
- sidecar metrics during the good window showed:
  - `libp2p_peers 1`
  - `beacon_gossipsub_outbound_streams 1`
  - `beacon_gossipsub_topic_peers 1`
  - `beacon_gossipsub_mesh_peers` briefly reached `1`
  - `status` success
  - `ping` success
  - `beacon_blocks_by_range` success

Most importantly, range sync made real progress again:
- `head_slot` advanced from `0` to `671`, then to `1319`
- `beacon_block_import_results_total{source="range_sync",outcome="imported"}` rose to hundreds of imported blocks
- range-sync segment logs showed repeated `result=complete`

This confirms the self-dial filter fix is real and effective.

## New primary failure after self-dial is removed

Once the sidecar reached head and gossip became active, the Lighthouse connection still did not stay up.

Observed sequence:
1. sidecar reaches near-head with `peers=1`
2. gossipsub is active and inbound gossip starts flowing
3. Lodestar-Z rejects several gossip messages from the Lighthouse peer as invalid
4. those rejections are mapped to peer-manager `low_tolerance` reports from gossipsub
5. after 5 such reports, the peer is disconnected
6. the node falls back to `peers=0` and starts drifting behind again

Concrete sidecar evidence around the disconnect:
- `p2p_peer_reports_total{source="gossipsub",action="low_tolerance"} 5`
- sidecar logs showed:
  - `Gossip sync contribution rejected ... err=error.InvalidSignature`
  - `single aggregate BLS failed for aggregator ...`
  - `Peer action ... low_tolerance from gossipsub`
  - `Peer disconnected ... total=0`
- immediately after disconnect:
  - `libp2p_peers 0`
  - `beacon_gossipsub_mesh_peers 0`
  - `beacon_gossipsub_topic_peers 0`
  - `beacon_sync_distance` starts growing again
- Lighthouse peer REST for the current sidecar peer then changes to:
  - `state = disconnected`

Important detail:
- single-signature maintenance paths still looked healthy enough:
  - repeated `status` success
  - repeated `ping` success
- the messages being rejected are same-message aggregate gossip paths:
  - sync committee contribution and proof
  - aggregate and proof

This strongly narrows the next issue to aggregate gossip signature validation or the data used to build those aggregate signature sets, not generic QUIC transport failure.

## Additional sidecar-specific issue exposed after the disconnect

The direct-peer redial path is also too weak for this harness.

Code evidence in `src/node/p2p_runtime.zig`:
- `bootstrapDirectPeers()` sets `next_direct_peer_index = 0` once at startup
- `bootstrapNextDirectPeer()` increments that index and dials each direct peer once
- after `next_direct_peer_index >= direct_peers.len`, it returns `false`

Practical consequence in this one-direct-peer devnet:
- after the Lighthouse peer disconnects, the sidecar does not keep re-dialing the curated direct peer
- so a single disconnect can strand the node at `peers=0`

## Current best root-cause framing after the successful rerun

The sidecar harness is now good enough to make two evidence-backed conclusions:

1. Self-dialing was a real bug, and fixing it materially improved behavior.
- without the fix, the node dialed its own fixed Kurtosis address and never made real progress
- with the fix, it connected to Lighthouse and range-synced hundreds of blocks successfully

2. The next real interoperability problem is false-invalid aggregate gossip handling.
- after catch-up, the node penalizes Lighthouse for aggregate gossip that it believes has invalid signatures
- those `low_tolerance` reports disconnect the only peer
- then the node does not reliably redial the direct Lighthouse peer afterward

So the next debugging target is not discovery anymore. It is:
- aggregate gossip signature validation correctness for:
  - `beacon_aggregate_and_proof`
  - `sync_committee_contribution_and_proof`
- plus secondarily the direct-peer redial policy after disconnect

## Strongest code-level hypothesis from source comparison

Static comparison against Lodestar-TS and Lighthouse points to the local gossip-side aggregate signature reconstruction as the most likely bug, not generic QUIC transport and not `BeaconConfig.getDomain()` by itself.

The strongest suspect files/functions are in `src/node/gossip_node_callbacks.zig`:
- `resolveAggregate()`
- `getSingleCommitteeAttestingIndices()`
- `verifyResolvedAggregateSignature()`
- `syncContributionParticipantIndices()`
- `verifySyncContributionAggregateSignature()`
- `verifySyncContributionSignature()`

These functions hand-build the participant/pubkey sets and signing roots for same-message aggregate gossip validation using `node.headState()` / `cached.epoch_cache`.

Why this is the best fit:
- the failing topics are exactly the two same-message aggregate gossip paths
- single-signature paths still work (`status`, `ping`, direct QUIC connect)
- range sync succeeds, so generic req/resp and base transport are healthy enough
- both failing topics ultimately depend on the same local aggregate-signature verification helper path:
  - `state_transition.signature_sets.verifyAggregatedSignatureSet()`
  - via custom pubkey/signing-root assembly in `gossip_node_callbacks.zig`

Reference behavior differs in an important way:
- Lodestar-TS uses shared signature-set helpers for these gossip objects instead of reconstructing the aggregate validation inputs ad hoc inside the gossip callback path
- Lighthouse likewise routes these through canonical signature-set construction for wrapper signatures and inner aggregate signatures

So the next focused verification target should be:
- compare the locally reconstructed participant index/pubkey sets and signing roots in `gossip_node_callbacks.zig` against the canonical/reference signature-set construction for the exact same aggregate and contribution objects
- if they differ, that should explain both the false `invalid_sync_contribution` rejects and the aggregate BLS failures that currently disconnect Lighthouse

## Post-aggregate/direct-peer rerun: the disconnect is gone, but the node still falls behind

After rebuilding `lodestar-z:kurtosis` from the current tree that includes the aggregate gossip fixes and runtime direct-peer maintenance, a fresh sidecar run showed a different failure mode.

Evidence that the new image actually included the current code:
- startup log now says:
  - `tracking 1 direct peer(s) for runtime maintenance`
- the old stale sidecar image had instead logged:
  - `queuing 1 direct peer(s) for runtime bootstrap`

The new run also no longer reproduced the previous aggregate-gossip disconnect signature:
- no `low_tolerance` gossipsub peer reports
- no `Gossip sync contribution rejected ... InvalidSignature`
- no `single aggregate BLS failed`
- peer stayed connected throughout the observation window

### What the fresh rerun did prove

The updated sidecar still connects and syncs successfully at first:
- sidecar peer id:
  - `16Uiu2HAmComRZ5Li1XKgDfewLjj1ajdC95ZSv4rVj8gkKX9PRqEY`
- Lighthouse peer REST shows it as:
  - `state = connected`
  - `direction = inbound`
  - `last_seen_p2p_address = /ip4/172.16.8.20/udp/<ephemeral>/quic-v1`
- sidecar metrics during sync showed:
  - `libp2p_peers 1`
  - `beacon_gossipsub_outbound_streams 1`
  - `beacon_gossipsub_mesh_peers 1`
  - `beacon_gossipsub_topic_peers 1`
- sidecar range sync imported through head normally:
  - `beacon_block_import_results_total{source="range_sync",outcome="imported"} 3327`
- Lighthouse logs showed repeated successful `BlocksByRange` requests from the sidecar and eventually:
  - `Peer transitioned sync state ... new_state: "Synced"`

### New observed failure mode

After catch-up, the sidecar remained connected but stopped receiving actual gossip payloads and slowly drifted behind head again.

Observed state after sync completion:
- sidecar sync endpoint later reported:
  - `head_slot = 3379`
  - `sync_distance = 26`
  - `is_syncing = false`
- reference Lighthouse and Lodestar were both at:
  - `head_slot = 3405` during the first lag sample
  - later `3392+` / advancing while the sidecar remained behind
- sidecar still showed:
  - `libp2p_peers 1`
  - `beacon_gossipsub_outbound_streams 1`
  - `beacon_gossipsub_mesh_peers 1`
  - `beacon_gossipsub_topic_peers 1`
  - `beacon_gossipsub_tracked_topics_with_peers 8`

But critically:
- `beacon_gossip_messages_received_total 0`
- no per-topic `beacon_gossip_messages_received_by_topic_total{...}` counters appeared at all
- sidecar logs repeatedly showed only gossipsub control traffic:

```text
gossipsub: decoded frame of 53 bytes
drainEvents: 1 events (0 messages)
drainEvents: 2 events (0 messages)
```

So the node has a connected gossip-capable peer and a live meshsub stream, but is not receiving any publish messages.

### Strongest live evidence for the stall mechanism

At the end of the last successful head-sync burst, the sidecar did queue and perform a re-status:

```text
SyncCallbackCtx: queued peer STATUS refresh ...
Opening req/resp stream: method=status ...
Sending Status ... head_slot=3379 finalized_epoch=103 ...
Peer Status ... head_slot=3380 finalized_epoch=103 ...
SyncService peer status: ... local_head=3379 ... peer_head=3380 ... distance=1 sync_type=fully_synced
```

Immediately after that, the node switched to synced mode and stopped making sync progress from the peer:

```text
Synced slot=3380 head_slot=3379 head_lag_slots=1 ... peers=1 wall_sync_distance=1 peer_sync_distance=0 sync_mode=synced gossip_state=enabled
```

Later samples showed the same pattern drifting wider:

```text
Synced slot=3405 head_slot=3379 head_lag_slots=26 ... peers=1 wall_sync_distance=26 peer_sync_distance=0 sync_mode=synced gossip_state=enabled
```

At the same time, peer-manager maintenance was only scheduling ping, not status refresh:

```text
Peer maintenance scheduled: restatus=0 ping=1
```

This matters because the current peer DB updates `sync_info.head_slot` only on Status exchange (`src/networking/peer_db.zig` `updatePeerStatus(...)`), not from ping or gossip control frames.

So once the post-sync re-status captured `peer_head=3380`, the local node had no further way to learn that Lighthouse had advanced unless either:
1. actual gossip payloads started arriving, or
2. another explicit Status refresh happened.

Neither occurred during the observation window.

### Current best root-cause framing

The aggregate/direct-peer fixes appear to have removed the previous false-invalid disconnect loop in this local harness.

The new primary issue is different:
- the sidecar can now keep the Lighthouse peer connected
- it can range-sync to near-head
- but after catch-up it receives zero gossip publish messages
- and after the one completion-triggered re-status, it does not refresh peer head information again soon enough to keep head sync moving in a one-peer harness

The result is:
- `sync_mode = synced`
- `gossip_state = enabled`
- `peers = 1`
- but `head_slot` stops advancing while `wall_sync_distance` grows

### Relation to Lodestar-TS behavior

Lodestar-TS explicitly re-statuses peers when a successful sync chain is removed:
- `packages/beacon-node/src/sync/range/range.ts:313-316`

Zig now does have the analogous callback plumbing:
- `src/sync/range_sync.zig:497-523`
- `src/node/sync_bridge.zig:489-523`
- `src/node/p2p_runtime.zig:1821-1841`

That callback is working in the fresh rerun — the sidecar did perform the one post-chain-completion status exchange.

So the new gap is not "missing range-sync re-status entirely" anymore.
It is more specifically:
- no actual gossip payload delivery after sync, and
- no follow-up mechanism that re-statuses again when wall lag grows but peer-sync lag still appears `0` from stale status data.

### Most likely next debugging targets

1. Prove why the connected Lighthouse peer is sending only gossipsub control traffic to Lodestar-Z and no publish messages.
- The sidecar sees meshsub frames and heartbeats, but zero messages.
- This is now the most direct explanation for why the node cannot stay at head after sync completion.

2. Add or compare a lag-triggered peer-head refresh policy.
- In the one-peer harness, if `wall_sync_distance` grows while `peer_sync_distance == 0`, the node should probably force a re-status of connected sync peers rather than waiting for the normal 5-minute status interval.
- Current logs show only `ping=1` maintenance scheduling during this drift.

3. Add a bilateral regression target for the Kurtosis sidecar harness.
- Fresh sidecar data dir
- one direct Lighthouse QUIC peer
- assert that after reaching synced mode, either:
  - `beacon_gossip_messages_received_total > 0`, or
  - `head_slot` stays within a very small lag window over time
- current behavior fails that expectation even though the peer stays connected

### Source-level diagnosis after the retained-peer rerun

A follow-up source inspection narrowed this newer failure further.

What is ruled out:
- the zero-receive problem is not in `src/node/gossip_handler.zig`
- `beacon_gossip_messages_received_total` is incremented only after a decoded gossip message reaches the handler
- in the failing rerun, that counter stays `0` and logs show only:
  - `drainEvents: ... (0 messages)`

So the failure is upstream of the node gossip handler: no gossipsub publish message is being surfaced as an inbound `.message` event at all.

#### Most likely source-level explanation

The strongest current code-path gap is that Zig direct peers are transport-maintained peers, but not gossipsub direct peers.

Evidence:
- runtime direct-peer support in `src/node/p2p_runtime.zig` maintains connection/trust/backoff state, but does not register those peers with gossipsub as permanent direct peers
- the current local gossipsub metrics (`mesh_peers`, `topic_peers`, `tracked_topics_with_peers`) are derived from the local router's topic/subscription maps, which prove local subscription state and control-plane visibility, but do not prove that Lighthouse is actually forwarding publish traffic to us
- Lodestar-TS explicitly configures gossipsub direct peers for its curated direct-peer set, which is a stronger guarantee in a one-peer harness than merely keeping the transport connection alive

Practical interpretation:
- in the current Zig sidecar, Lighthouse can remain transport-connected, respond to req/resp, and exchange meshsub control traffic
- but still not act as a guaranteed publish path for gossip payloads
- that exactly matches the observed pattern:
  - `peers = 1`
  - `gossip_state = enabled`
  - `beacon_gossip_messages_received_total = 0`
  - widening `wall_sync_distance`

#### Secondary source-level gap that amplifies the issue

There is also evidence that Zig's gossipsub wrapper is weaker than TS around live subscription updates.

Current local code path:
- runtime sync state toggles core-topic subscribe/unsubscribe through:
  - `src/node/p2p_runtime.zig` `setSyncGossipCoreTopicsEnabled(...)`
- local `gossipsub.subscribe()` / `unsubscribe()` updates local router state
- but the wrapper's explicit subscription announcement path is centered on stream establishment, not obviously on later sync-state flips for already-connected peers

That means a sync->gossip transition can plausibly leave the peer transport-connected with a meshsub stream, but without the remote side having a strong up-to-date reason to forward publish traffic immediately.

#### Separate sync-side consequence

Once gossip payloads are absent, the sync side has no fast recovery path in the one-peer harness.

Why:
- peer head knowledge is updated from Status, not from ping
- Zig does perform the one completion-triggered range-sync re-status
- after that, maintenance only schedules ping (`restatus=0 ping=1`) for the observed period
- therefore the node can sit in:
  - `sync_mode = synced`
  - `peer_sync_distance = 0`
  - while `wall_sync_distance` continues to widen from stale peer-status data

#### Best current next-step hypothesis

The most likely next local fix target is not aggregate gossip anymore.
It is the combination of:
1. no guaranteed gossipsub publish path for the single connected direct peer, and
2. no lag-triggered follow-up status refresh when wall lag grows after the one post-range-sync re-status

Those two gaps together explain the current retained-peer / zero-gossip / drifting-head failure mode better than generic QUIC churn.

### Stronger reproduction: forced reconnect after gossip is enabled

A follow-up local experiment made the post-sync gossip issue much clearer.

Experiment:
- keep the sidecar running until it is near-head with:
  - `peers=1`
  - `gossip_state=enabled`
  - `beacon_gossip_messages_received_total=0`
- then force a peer reconnect without restarting the process by pausing/unpausing the sidecar container

What happened immediately after the forced reconnect:
- direct-peer runtime maintenance redialed Lighthouse successfully
- the reconnected gossipsub stream logged:
  - `gossipsub: announced 137 subscriptions to inbound peer`
- right after that, the sidecar finally started receiving real gossip payloads:
  - `drainEvents: 3 events (1 messages)`
  - `drainEvents: 5 events (5 messages)`
- `beacon_gossip_messages_received_total` jumped from `0` to `12`

This is much stronger evidence that the earlier zero-gossip state was not just "Lighthouse happened not to send us anything".
It strongly suggests the existing peer had never learned our full post-sync subscription set.

### Why the reconnect matters

Compare behavior:

Before reconnect:
- existing peer connection from pre-sync phase
- sidecar logs showed:
  - `gossip core topics enabled`
- but no new subscription announcement was logged
- sidecar continued to decode only meshsub control frames with `0 messages`

After reconnect:
- a fresh gossipsub stream was attached
- current subscriptions were re-announced in bulk:
  - `announced 137 subscriptions`
- gossip payloads immediately began arriving

This lines up exactly with the source-level difference from Lodestar-TS:
- Lodestar-TS / js-libp2p-gossipsub sends subscription updates to all already-connected peers whenever `subscribe()` / `unsubscribe()` is called
- the local Zig gossipsub wrapper currently announces subscriptions only when a new gossipsub stream is attached to a peer

So the strongest current local bug is:
- runtime `subscribeEthTopics()` / `unsubscribeEthTopics()` changes are not propagated to already-connected peers

### The reconnect also exposed the next still-live bug

Once real gossip payloads finally started arriving after the 137-subscription announcement, the sidecar immediately reproduced the same-message gossip validation failures again.

Observed logs after reconnect:
- sync contributions:
  - `Gossip sync contribution rejected ... err=error.InvalidSignature`
- aggregate gossip:
  - `single aggregate BLS failed for aggregator ...`
- peer scoring:
  - repeated `Peer action ... low_tolerance from gossipsub`
- then disconnect / goodbye followed again

So the earlier "no invalid signatures in the fresh rerun" result was misleading: the node was simply not receiving the relevant gossip payloads at all.
Once the subscription-announcement problem was bypassed via reconnect, the old aggregate/sync-contribution validation failure came back immediately.

### Updated root-cause stack

The current Kurtosis sidecar evidence now points to two stacked bugs, in order:

1. Gossipsub subscription update propagation bug
- post-sync core-topic subscriptions are not announced to already-connected peers
- this suppresses real gossip delivery after catch-up
- reconnecting the peer causes a bulk subscription announcement and real message delivery resumes immediately

2. Remaining same-message aggregate gossip validation bug
- once messages do arrive, the sidecar still rejects valid Lighthouse gossip on:
  - `sync_committee_contribution_and_proof`
  - and at least some `beacon_aggregate_and_proof`
- those rejections still trigger `low_tolerance` peer penalties and disconnect the only peer

### Exact failing signature leg from the instrumented rerun

After rebuilding with finer-grained validation logs in `src/node/gossip_node_callbacks.zig`, the reconnect reproduction identified the exact failing leg.

Observed repeatedly in live sidecar logs:
- sync contribution path:
  - `sync contribution selection proof invalid: aggregator=... slot=... subcommittee=...`
  - followed by:
    - `Gossip sync contribution rejected ... err=error.InvalidSignature`
- aggregate path:
  - `aggregate selection proof invalid: aggregator=... slot=...`
  - followed by:
    - `single aggregate BLS failed for aggregator ...`

Important implication:
- the current remaining failure is not in the final aggregate pubkey/signature check for these messages
- it is failing earlier, at the selection-proof verification leg for both message families

That rules out several earlier broad suspects as the primary current cause, especially:
- aggregate attestation participant-set reconstruction as the first failure point in the currently reproduced path
- sync contribution aggregate signature-set assembly as the first failure point in the currently reproduced path

### Best current root-cause hypothesis after TS comparison

Lodestar-TS behaviorally points to two layered issues:

1. Subscription propagation bug in the local gossipsub wrapper
- Zig only announces subscriptions on stream attachment
- Lodestar-TS / js-libp2p-gossipsub pushes subscription updates to already-connected peers on live subscribe/unsubscribe
- this suppresses payload delivery until reconnect

2. Remaining selection-proof verification bug once payloads arrive
- both failing message families now point to selection-proof verification specifically
- the strongest remaining common suspects are therefore selection-proof specific inputs, not the later aggregate-signature legs:
  - selection-proof signing root construction
  - selection-proof domain choice
  - or deserialization/access of the embedded `selection_proof` field itself

Behaviorally, the TS guidance is now:
- first fix live subscription propagation so connected peers learn post-sync topic changes without a reconnect
- then continue narrowing the selection-proof path, since that is the exact remaining signature leg now failing in the Kurtosis sidecar harness

So the earlier retained-peer / zero-gossip state was masking, not replacing, the aggregate-validation problem.

## Updated 2026-04-22 checkpoint-sync rerun status

A fresh sidecar container built from the current local binary was started at:
- `2026-04-22T15:12:33Z`

The running container binary SHA matches the local `zig-out/bin/lodestar-z` exactly:
- `7d5733b0e0d8519636f53ceb92b9867cd553c792292c2d91f41efaeaac8fabcb`

This matters because it rules out the possibility that the latest live checks were still running an older pre-fix image.

### Current live status of the fresh run

The fresh checkpoint-sync run is healthy:
- bootstrap source:
  - `checkpoint sync URL: http://172.16.8.14:4000`
- checkpoint slot at startup:
  - `11904`
- later live sample:
  - `head_slot=12185`
  - `sync_distance=0`
  - `libp2p_peers=1`
  - `beacon_gossipsub_outbound_streams=1`
  - `beacon_gossipsub_mesh_peers=1`
  - `beacon_gossipsub_topic_peers=1`
  - `beacon_gossip_messages_received_total=1265`
  - `beacon_block_import_results_total{source="gossip",outcome="imported"}=200`

So in this fresh run Lodestar-Z is:
- staying connected to the Lighthouse direct peer
- receiving live gossip payloads without a manual reconnect / pause-unpause cycle
- importing gossip blocks
- and staying at sync head

### Most important correction to the previous findings

The fresh 2026-04-22 run does **not** reproduce the earlier selection-proof rejection loop.

Explicit grep across the current sidecar container logs found no matches for:
- `selection proof invalid`
- `aggregate selection proof invalid`
- `sync contribution selection proof invalid`
- `InvalidSignature`
- `single aggregate BLS failed`
- `low_tolerance`

Lighthouse-side log grep for the current sidecar peer ID also found no matching disconnect / penalty evidence during this healthy run.

Therefore the strongest evidence now is:
- the current local code does appear to have fixed the earlier live selection-proof failure in the fresh sidecar reproduction
- the earlier alert that still showed a `selection proof invalid` line was very likely from an older sidecar run before the current container restart/build

This does **not** prove the bug can never recur under any other runtime shape, but it does change the working conclusion from:
- "still definitely live in the current reproduction"

to:
- "not reproduced in the current fresh checkpoint-sync sidecar run"

### Separate issue found while re-checking the stateful path

While reconciling the old alert against the new healthy run, another spec-divergent behavior became clear in the Zig fast gossip validator:

- `validateGossipSyncContributionAndProof()` currently only checks:
  - aggregator index in range
  - contribution slot is not from the future
  - contribution slot is not already finalized
- Lodestar-TS's gossip validation is stricter and treats sync contribution gossip as current-slot work

This looser Zig acceptance window means stale-but-not-finalized sync contributions can survive deep enough into later validation and confuse debugging.

This is a separate issue from the earlier selection-proof failure:
- it does not explain the old invalid-selection-proof logs by itself
- but it is still a real behavior gap worth tightening in follow-up work so future repros stay cleaner and closer to production reference-client behavior
