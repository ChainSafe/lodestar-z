# Validator Client Design

Zig scaffolding for the lodestar-z Ethereum consensus validator client.

## Current Production Gaps

This document is also the canonical place to record validator-client
simplifications relative to Lodestar TS so they are not hidden behind
compatibility flags or launcher shortcuts.

Current gaps:

1. Remote validator monitoring is now implemented, but it is still Linux-only.
   The validator launcher now supports Lodestar-style `--monitoring.endpoint`,
   `--monitoring.interval`, `--monitoring.initialDelay`,
   `--monitoring.requestTimeout`, and `--monitoring.collectSystemStats`.
   The remaining gap is narrower: process and host stats currently rely on
   Linux `/proc` plus `statvfs("/")`, so non-Linux validator hosts are not
   supported yet.

2. Startup keystore import is now implemented, but it is still narrower than
   Lodestar TS.
   `--importKeystores` now recursively imports external EIP-2335 keystore files
   into the managed `keystores/` + `secrets/` layout before normal startup, but
   it currently assumes a single shared password file via
   `--importKeystoresPassword` and does not implement Lodestar's prompt /
   threaded-decrypt UX.

3. External signer support is still narrower than Lodestar TS, but no longer
   in the basic startup path.
   The validator now supports Lodestar's three startup sources for remote
   signers: persisted `remoteKeys/` definitions, explicit
   `--externalSigner.pubkeys`, and dynamic `--externalSigner.fetch`.
   The runtime keymanager server can now also add and remove remote keys while
   the client is running. The remaining external-signer gap is broader
   keymanager/key-discovery polish, not the core signer path.

4. The validator keymanager server now covers keystores, remote keys,
   fee-recipient updates, graffiti updates, gas-limit updates, builder-boost
   updates, proposer-config reads, voluntary-exit signing, typed HTTP error
   stacktraces, and dedicated request/latency monitoring. The remaining
   keymanager gap is narrower: there is still no separate remote monitoring
   pipeline for the keymanager surface beyond the local Prometheus metrics.

5. Distributed-validator flags and mnemonic / interop signer sources are still
   not implemented.
   The validator launcher now supports Lodestar-style proposer settings files,
   enforces strict fee-recipient checks before signing/publishing produced
   blocks, resolves Lodestar-style `cache/`, `remoteKeys/`, and
   `proposerConfigs/` paths, and loads/persists `proposerConfigs/` instead of
   ignoring them. The local lodestar-z beacon-node proposal path now honors
   `prepare_beacon_proposer` fee-recipient data, explicit `fee_recipient`
   request overrides, request-level `builder_boost_factor`,
   `builder.selection`, validator-provided `randao_reveal`, `blindedLocal`,
   and `broadcastValidation` for local block production/publish.
   The local beacon node can now also produce builder-sourced blinded
   proposals for builder-aware selections instead of silently degrading them
   to an engine block. The remaining production gap in that area is narrower:
   the local BN now evaluates the engine payload and builder bid with
   parallel fetches plus a Lodestar-style cutoff/overall-timeout race, and it
   now overlaps stable proposal-template assembly with those external fetches
   so the hot proposal path is no longer serialized on local body-building.
   On the beacon CLI side, `--builder`, `--builder.url`, and the default
   builder boost now wire through to a real local builder client, and the
   circuit-breaker tuning flags now control slot-based builder health checks.
   Builder and execution timeout overrides now apply to the local HTTP
   clients, with the builder proposal path still using a tighter capped
   proposal timeout inside that broader client budget. The local beacon node
   also now enforces a process-local equivocation guard on
   `broadcastValidation=consensus_and_equivocation`, though the validator's
   persistent slashing-protection DB remains the primary defense across restarts.

6. Beacon-node config verification now checks a much wider consensus-critical
   subset of `/eth/v1/config/spec`, including genesis, fork versions/epochs,
   slot timing, proposer/attestation/aggregate/sync timing cutoffs, churn,
   deposit contract, blob-sidecar limits, and core preset values. It still
   does not reach full Lodestar-TS-style parity for every critical parameter,
   especially where different clients omit fields or expose less structured
   values.

7. Validator persistence is intentionally simpler than Lodestar TS.
   Slashing protection uses an append-only file, and validator metadata
   (`genesis_time`, `genesis_validators_root`) is stored in a small sidecar file
   under `validator-db/`.

8. Beacon-node client failover is now request-scoped, deadline-bounded, and
   parallel on the validator hot path, but it is still simpler than
   Lodestar TS overall.
   The validator now retries non-streaming requests across configured beacon
   node URLs within one shared timeout budget, and it races degraded URLs in
   parallel through the next healthy URL instead of serializing every fallback
   attempt. The head-tracker SSE path also walks configured URLs within one
   reconnect cycle before backing off. The first URL that succeeds is promoted
   for later requests, so failover is no longer gated on a sticky failure
   threshold or a single-URL SSE retry. The client now also maintains
   Lodestar-style per-URL health scores, exports fallback/error/request-time
   metrics, and warns when the primary beacon node has bottomed out and the
   validator is riding fallbacks.
   The remaining gap is narrower: the client still does not run fully parallel
   multi-round fallback races once it has moved past one degraded URL window.

9. Sync committee duty handling is closer to Lodestar TS on the hot path, but
   it is still narrower on reorg semantics.
   The validator now re-polls sync duties every epoch, repairs missing duties
   from the slot path, and refreshes the first slot that uses a new sync
   period against a fresh beacon-node view. The remaining gap is that the BN
   sync-duty API still does not expose attester-style `dependent_root`
   metadata, so sync-duty churn is detected only by observed duty-set changes
   when a period is refreshed.

Non-gap note:

1. Local keystores are now locked at startup and held for the process lifetime.
   `--force` bypasses those ownership locks intentionally and should be treated
   as an operator escape hatch, not the default mode.

2. When `--proposerSettingsFile` is used, proposer policy writes are
   intentionally disabled through the keymanager API. The file is treated as the
   source of truth for proposer policy.

3. Chain-head tracking and remote-signer refresh now run as cancellable
   `std.Io` tasks owned by the validator runtime, not detached OS threads.

4. Beacon-node readiness is now fail-closed.
   The validator treats the beacon node as ready only when
   `!is_syncing && !is_optimistic && !el_offline`, exports `vc_beacon_health`,
   and pauses duties on sync-status poll failures instead of reusing stale
   readiness state.

5. Doppelganger protection now exports dedicated status and epochs-checked
   metrics.
   The validator now mirrors Lodestar TS's `vc_doppelganger_validator_status_count`
   and `vc_doppelganger_epochs_checked_total` surfaces instead of leaving
   doppelganger state observable only through logs.

## Architecture Overview

```
ValidatorClient
  │
  ├─ SlotClock          — wall-clock slot/epoch boundary notifications
  ├─ BeaconApiClient    — HTTP + SSE client for BN REST API
  ├─ ValidatorStore     — BLS keys, validator indices, slashing protection
  │
  ├─ BlockService       — proposer duties → block proposal
  ├─ AttestationService — attester duties → attestation + aggregation
  ├─ SyncCommitteeService — sync duties → sync messages + contributions
  └─ DoppelgangerService — liveness checks before allowing signing
```

## Data Flow

### 1. BN Connection

```
validator command bootstrap
  │
  ├─ waitForGenesis() → genesis_time, validators_root
  ├─ getConfigSpec() → startup config compatibility checks
  ├─ persist/verify validator metadata
  │
  └─ ValidatorClient.start()
       │
       └─ BeaconApiClient.subscribeToEvents(["head","block"])
       │
       └─ SSE stream (GET /eth/v1/events?topics=head,block)
            │
            └─ HeadEvent { slot, block_root, ... }
                 │
                 └─ ChainHeaderTracker.onHead() → notify attestation/sync services
```

### 2. Duty Cycle (Epoch Boundary)

```
SlotClock fires epoch callback
  │
  ├─ BlockService.onEpoch(epoch)
  │    └─ BeaconApiClient.getProposerDuties(epoch) → []ProposerDuty
  │
  ├─ AttestationService.onEpoch(epoch)
  │    ├─ ValidatorStore.allIndices()
  │    └─ BeaconApiClient.getAttesterDuties(epoch, indices) → []AttesterDuty
  │         └─ compute selection proofs (sign slot → aggregator eligibility)
  │
  └─ SyncCommitteeService.onEpoch(epoch)
       ├─ (only if sync period changed)
       └─ BeaconApiClient.getSyncCommitteeDuties(epoch, indices) → []SyncCommitteeDuty
```

### 3. Block Proposal (Slot Start)

```
SlotClock fires slot callback
  │
  └─ BlockService.onSlot(slot)
       │
       ├─ getDutyAtSlot(slot) → ProposerDuty (or none)
       │
       ├─ ValidatorStore.signRandao(pubkey, sign_root) → RANDAO reveal
       │
       ├─ BeaconApiClient.produceBlock(slot, randao_reveal, graffiti)
       │    └─ GET /eth/v3/validator/blocks/{slot}?randao_reveal=...
       │
       ├─ ValidatorStore.signBlock(pubkey, sign_root, slot) → signature
       │    └─ checks slashing: slot > last_signed_block_slot
       │
       └─ BeaconApiClient.publishBlock(signed_block_ssz)
            └─ POST /eth/v2/beacon/blocks
```

### 4. Attestation (1/3 + 2/3 Slot)

```
SlotClock fires slot callback
  │
  └─ AttestationService.onSlot(slot)
       │
       ├─ [at 1/3 slot or head block, whichever first]
       │   ├─ BeaconApiClient.produceAttestationData(slot, committee_index=0)
       │   │    └─ GET /eth/v1/validator/attestation_data?slot=...
       │   │
       │   ├─ for each duty at this slot:
       │   │    └─ ValidatorStore.signAttestation(pubkey, sign_root, src_epoch, tgt_epoch)
       │   │         └─ checks slashing: target_epoch > last_signed_target
       │   │
       │   └─ BeaconApiClient.publishAttestations(batch)
       │        └─ POST /eth/v2/beacon/pool/attestations
       │
       └─ [at 2/3 slot]
           ├─ for each aggregator duty:
           │    ├─ BeaconApiClient.getAggregatedAttestation(slot, data_root)
           │    ├─ ValidatorStore.signAggregateAndProof(pubkey, sign_root)
           │    └─ BeaconApiClient.publishAggregateAndProofs(batch)
           └─    POST /eth/v2/validator/aggregate_and_proofs
```

### 5. Sync Committee (Altair+, 1/3 + 2/3 Slot)

```
SlotClock fires slot callback
  │
  └─ SyncCommitteeService.onSlot(slot)
       │
       ├─ [at ~1/3 slot]
       │   ├─ for each validator in sync committee:
       │   │    └─ ValidatorStore.signSyncCommitteeMessage(pubkey, sign_root)
       │   └─ BeaconApiClient.publishSyncCommitteeMessages(batch)
       │        └─ POST /eth/v1/beacon/pool/sync_committees
       │
       └─ [at ~2/3 slot]
           ├─ for each aggregator in each subcommittee:
           │    ├─ BeaconApiClient.produceSyncCommitteeContribution(slot, subnet, root)
           │    ├─ ValidatorStore.signContributionAndProof(pubkey, sign_root)
           │    └─ BeaconApiClient.publishContributionAndProofs(batch)
           └─    POST /eth/v1/validator/contribution_and_proofs
```

## TypeScript → Zig Type Mapping

| TypeScript (lodestar)       | Zig (lodestar-z)                          |
|-----------------------------|-------------------------------------------|
| `Validator` class           | `validator.ValidatorClient` struct        |
| `IClock` / `Clock`          | `clock.SlotClock`                         |
| `ApiClient`                 | `api_client.BeaconApiClient`              |
| `ValidatorStore` class      | `validator_store.ValidatorStore` struct   |
| `BlockProposingService`     | `block_service.BlockService`              |
| `BlockDutiesService`        | (merged into `BlockService`)              |
| `AttestationService`        | `attestation_service.AttestationService`  |
| `AttestationDutiesService`  | (merged into `AttestationService`)        |
| `SyncCommitteeService`      | `sync_committee_service.SyncCommitteeService` |
| `SyncCommitteeDutiesService`| (merged into `SyncCommitteeService`)      |
| `DoppelgangerService`       | `doppelganger.DoppelgangerService`        |
| `IndicesService`            | (merged into `ValidatorStore.allIndices`) |
| `ChainHeaderTracker`        | `chain_header_tracker.ChainHeaderTracker` |
| `ISlashingProtection`       | `SlashingProtectionRecord` (in-process)   |
| `BLSSecretKey` / `SignerLocal` | `bls.SecretKey`                        |
| `PubkeyHex`                 | `[48]u8` (raw bytes)                      |
| `ProposerDuty`              | `types.ProposerDuty`                      |
| `AttDutyAndProof`           | `types.AttesterDutyWithProof`             |
| `SyncDutyAndProofs`         | `types.SyncCommitteeDutyWithProofs`       |
| `ValidatorStatus`           | `types.ValidatorStatus` (enum)            |
| `AbortSignal`               | (Zig 0.16: cancellation via error return) |
| `Promise<void>`             | `!void` + std.Io                          |

## Key Design Decisions

### 1. std.Io for All I/O

All blocking operations use Zig 0.16's `std.Io` (evented I/O):
- `Io.Timeout.sleep(io)` for timed delays (slot clock).
- `std.Io.net.Stream` for HTTP connections (see `api_client.zig`).
- Pattern borrowed from `src/api/http_server.zig` and `src/networking/p2p_service.zig`.

The TypeScript equivalent uses `Promise` + `AbortSignal`. In Zig we use error returns and a run loop.

### 2. No Class Hierarchy

TypeScript uses class inheritance and interfaces (IClock, ISlashingProtection).
Zig uses:
- **Structs** with explicit `init()` / `deinit()`.
- **Callback vtables** (SlotCallback, EpochCallback) instead of interface dispatch.
- **Explicit allocator** passed to every init (no hidden GC).

### 3. Callbacks vs Async Loops

TypeScript: `clock.runEverySlot(fn)` registers async slot/epoch work that fans out into service tasks.

Zig: Same concept — `SlotClock.onSlot(cb)` / `onEpoch(cb)` registers coherent runtime phases. The validator runtime then fans those phases out through `std.Io.Group.concurrent`, so sync-status gating, index resolution, and long-running duty work are ordered explicitly instead of hiding behind detached threads.

For sub-slot timing, attestation and sync duties now wait until either the configured due instant or the slot head block arrives, whichever happens first. `ChainHeaderTracker` provides the head cache plus event-driven wakeups for those waits.

### 4. Signing API

All signing goes through `ValidatorStore` which:
1. Looks up the `SecretKey` for the given pubkey.
2. Checks slashing protection before signing.
3. Updates the protection record.
4. Returns `bls.Signature`.

The caller is responsible for computing the `signing_root` via `compute_signing_root(object, domain)` (not yet implemented — stubs use zeroed root).

### 5. Duty Scheduling

TypeScript uses separate `DutiesService` classes that maintain rolling maps.
Zig merges duties into the service structs to keep the module count manageable. Both current and next epoch duties should be pre-fetched at epoch N-1 to avoid latency spikes — this is stubbed for now.

### 6. Doppelganger Protection

Checks liveness via `/eth/v1/validator/liveness/{epoch}` for DEFAULT_REMAINING_DETECTION_EPOCHS (1) clean epochs before allowing signing. Validators start as `unverified` and become `verified_safe` after passing detection. If any are found `is_live`, all signing is halted and a shutdown is triggered.

## What's Different from TypeScript

1. **No class hierarchy** — flat structs, no `extends` / `implements`.
2. **Explicit memory management** — `allocator` everywhere, `deinit()` / `destroy()` required.
3. **No closures** — callbacks use `*anyopaque` context pointers.
4. **Explicit runtime phases** — slot and epoch work run through explicit `std.Io` task groups rather than detached promise chains or per-tick OS threads.
5. **BLS API** — `SecretKey.sign(msg, dst, aug)` vs `secretKey.sign(msg)`.
6. **Pubkeys as raw bytes** — `[48]u8` vs hex strings (PubkeyHex in TS).
7. **Remote signer support is present but narrower** — current Web3Signer support fetches keys from one signer and signs by duty type; TS supports a broader signer-loading matrix.
8. **Validator persistence is file-based** — append-only slashing protection file + metadata sidecar instead of LevelDB buckets.
9. **Merged duty services** — AttestationDutiesService + AttestationService → single `AttestationService`.

## Files

| File                         | TS Equivalent                              | Status  |
|------------------------------|---------------------------------------------|---------|
| `validator.zig`              | `validator.ts` Validator class              | Stub    |
| `clock.zig`                  | `util/clock.ts` Clock / IClock              | Stub    |
| `api_client.zig`             | `@lodestar/api` ApiClient                   | Stub    |
| `validator_store.zig`        | `services/validatorStore.ts`                | Stub    |
| `block_service.zig`          | `services/block.ts` + `blockDuties.ts`      | Stub    |
| `attestation_service.zig`    | `services/attestation.ts` + `attestationDuties.ts` | Stub |
| `sync_committee_service.zig` | `services/syncCommittee.ts` + `syncCommitteeDuties.ts` | Stub |
| `doppelganger.zig`           | `services/doppelgangerService.ts`           | Stub    |
| `types.zig`                  | `types.ts` + duty types from services       | Stub    |
| `root.zig`                   | `index.ts`                                  | Done    |

## Next Steps (Not Scaffolded)

1. **Distributed-validator mode** — `--distributed` is still rejected because the validator does not yet implement the distributed aggregation-selection / duty-coordination semantics Lodestar expects there.
2. **Portable remote monitoring** — validator host/process stats still assume Linux `/proc` and `statvfs("/")`.
3. **Broader beacon config verification parity** — the `/eth/v1/config/spec` comparison is much wider now, but still not exhaustive across every consensus-critical field and client-specific response shape.
4. **Beacon API failover polish** — request-scoped failover is deadline-bounded and parallel on the validator hot path, but the client still does not run fully general multi-round races with Lodestar-style route-scoped metrics.
5. **Keymanager monitoring split** — the keymanager surface has dedicated auth/metrics/error handling now, but still does not have a separate remote monitoring pipeline beyond local Prometheus metrics.
