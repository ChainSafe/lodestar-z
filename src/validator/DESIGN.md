# Validator Client Design

Zig scaffolding for the lodestar-z Ethereum consensus validator client.

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
ValidatorClient.start(io)
  │
  ├─ BeaconApiClient.getGenesis() → genesis_time, validators_root
  │
  └─ BeaconApiClient.subscribeToEvents(["head","block"])
       │
       └─ SSE stream (GET /eth/v1/events?topics=head,block)
            │
            └─ HeadEvent { slot, block_root, ... }
                 │
                 └─ (TODO) ChainHeaderTracker.onHead() → notify AttestationService
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
| `ChainHeaderTracker`        | (TODO: chain_header_tracker.zig)          |
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

TypeScript: `clock.runEverySlot(fn)` registers an async function that runs in a separate Promise chain.

Zig: Same concept — `SlotClock.onSlot(cb)` / `onEpoch(cb)` registers callbacks. The `run()` loop fires them synchronously at each boundary.

For sub-slot timing (1/3, 2/3), services will need to spawn background tasks using `io.background.async()` — not yet wired (stub uses synchronous calls).

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
2. **Explicit memory management** — `allocator` everywhere, `deinit()` required.
3. **No closures** — callbacks use `*anyopaque` context pointers.
4. **Synchronous-first clock** — no concurrent promise chains; sub-slot timing needs `io.background.async()`.
5. **BLS API** — `SecretKey.sign(msg, dst, aug)` vs `secretKey.sign(msg)`.
6. **Pubkeys as raw bytes** — `[48]u8` vs hex strings (PubkeyHex in TS).
7. **No metrics layer** — metrics hooks removed from scaffolding for clarity.
8. **No remote signer** — web3signer support (SignerRemote in TS) deferred.
9. **In-process slashing protection** — no SQLite backend yet (TS uses slashingProtection DB).
10. **Merged duty services** — AttestationDutiesService + AttestationService → single `AttestationService`.

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

1. **chain_header_tracker.zig** — SSE head event subscription + head root cache.
2. **compute_signing_root()** — domain computation for all signing operations.
3. **HTTP client implementation** — wire BeaconApiClient to real HTTP requests using std.Io.net.
4. **Sub-slot timing** — use `io.background.async()` for 1/3 and 2/3 slot waits.
5. **Slashing protection DB** — persistent store (SQLite or custom) for cross-restart protection.
6. **Validator key loading** — keystore decryption (EIP-2335).
7. **prepare_beacon_proposer.zig** — fee recipient registration polling.
