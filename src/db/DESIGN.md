# Database Schema Design: LMDB Named Databases

## Problem

TS Lodestar uses LevelDB (a flat KV store) and simulates namespaces by prepending a
single-byte bucket ID to every key. lodestar-z inherited this pattern despite using LMDB,
which natively supports **named databases** (equivalent to column families). This wastes:

- 1 byte per key for the bucket prefix
- Range scans must filter out unrelated prefixes
- No per-bucket tuning (compaction, flags, statistics)
- No native namespace isolation

## Solution

Map each logical bucket to its own LMDB named database (DBI). LMDB supports up to 128
named databases per environment, sharing a single memory map with zero extra overhead.

## Schema

### Named Databases

| DBI Name | Key | Value | Access Pattern | Hot/Cold | LMDB Flags |
|---|---|---|---|---|---|
| `state_archive` | Slot (8B BE) | SSZ BeaconState | Range scan (ascending) | Cold | — |
| `block` | Root (32B) | SSZ SignedBeaconBlock | Point lookup | Hot | — |
| `block_archive` | Slot (8B BE) | SSZ SignedBeaconBlock | Range scan (ascending) | Cold | — |
| `idx_block_parent_root` | Root (32B) | Slot (8B BE) | Point lookup | Cold | — |
| `idx_block_root` | Root (32B) | Slot (8B BE) | Point lookup | Cold | — |
| `idx_main_chain` | Slot (8B BE) | Root (32B) | Point lookup, range | Cold | — |
| `chain_info` | Short string | Variable | Point lookup | Hot | — |
| `exit` | ValidatorIndex (8B BE) | SSZ VoluntaryExit | Point lookup, iteration | Hot | — |
| `proposer_slashing` | ValidatorIndex (8B BE) | SSZ ProposerSlashing | Point lookup | Hot | — |
| `attester_slashing` | Root (32B) | SSZ AttesterSlashing | Point lookup, iteration | Hot | — |
| `bls_change` | ValidatorIndex (8B BE) | SSZ SignedBLSToExecChange | Point lookup | Hot | — |
| `checkpoint_state` | Root (32B) | SSZ BeaconState | Point lookup | Hot | — |
| `idx_state_root` | Root (32B) | Slot (8B BE) | Point lookup | Cold | — |
| `blob_sidecar` | Root (32B) | SSZ BlobSidecars | Point lookup | Hot | — |
| `blob_sidecar_archive` | Slot (8B BE) | SSZ BlobSidecars | Range scan | Cold | — |
| `backfill_ranges` | From (8B BE) | To (8B BE) | Range scan | Cold | — |
| `lc_sync_witness` | Root (32B) | SyncCommitteeWitness | Point lookup | Warm | — |
| `lc_sync_committee` | Root (32B) | SSZ SyncCommittee | Point lookup | Warm | — |
| `lc_checkpoint_header` | Root (32B) | SSZ BeaconBlockHeader | Point lookup | Warm | — |
| `lc_best_update` | SyncPeriod (8B BE) | [Slot, LightClientUpdate] | Point lookup | Warm | — |
| `data_column` | Root (32B) | SSZ DataColumnSidecars | Point lookup | Hot | — |
| `data_column_archive` | Slot (8B BE) | SSZ DataColumnSidecars | Range scan | Cold | — |
| `data_column_single` | Root(32B) ++ ColIdx(8B BE) | Single DataColumnSidecar | Point lookup | Hot | — |
| `epbs_payload` | Root (32B) | SSZ SignedExecPayloadEnvelope | Point lookup | Hot | — |
| `epbs_payload_archive` | Slot (8B BE) | SSZ SignedExecPayloadEnvelope | Range scan | Cold | — |
| `fork_choice` | Short string | Serialized fork choice | Point lookup (single entry) | Hot | — |
| `validator_index` | Pubkey (48B) | ValidatorIndex (8B BE) | Point lookup | Hot | — |

**Total: 26 named databases** (well within LMDB's 128 limit).

### Key Encoding Changes

With named databases, keys no longer need the bucket prefix byte:

| Before (bucket prefix) | After (named DBI) |
|---|---|
| `[0x01] ++ root(32)` | `root(32)` in DBI `block` |
| `[0x02] ++ slot(8 LE)` | `slot(8 LE)` in DBI `block_archive` |
| `[0x07] ++ "fs"` | `"fs"` in DBI `chain_info` |

Keys are shorter by 1 byte each. More importantly, range scans within a DBI are native
B-tree scans — no prefix filtering needed.

## Hot/Cold Architecture

Future work: separate LMDB environments for hot vs cold data.

- **Hot env**: `block`, `chain_info`, `checkpoint_state`, `blob_sidecar`, `data_column*`,
  `fork_choice`, `validator_index`, op pool buckets
- **Cold env**: `*_archive`, `idx_*`, `state_archive`, `backfill_ranges`, light client

Benefits: different map sizes, sync settings, and backup strategies. The hot DB stays
small and fast; the cold DB can grow to terabytes.

This redesign keeps everything in one environment but structures the code to make the
split easy later: each `DatabaseId` knows which environment it belongs to.

## Comparison

| Aspect | TS Lodestar (LevelDB) | Old Zig (LMDB) | New Zig (LMDB) |
|---|---|---|---|
| Namespace | Prefix byte in key | Prefix byte in key | Named DBI |
| Range scan | Skip prefixes | Skip prefixes | Native per-DBI |
| Key overhead | +1 byte per key | +1 byte per key | Zero |
| Hot/cold | Same DB | Same DB | Same env (split-ready) |
| Tuning | Global | Global | Per-DBI flags possible |
| Stats | Global only | Global only | Per-DBI via `mdb_stat` |

## Migration Path

Since lodestar-z has no production databases yet, no migration is needed. The old
bucket-prefix format is simply replaced. If migration were needed, a one-time scan
of all entries in the unnamed DB, stripping the prefix byte and writing to the
corresponding named DBI, would suffice.

## Performance Notes

- Named DBs share the single mmap — no extra memory overhead per DBI
- Read transactions are lock-free (MVCC) regardless of DBI count
- MDB_INTEGERKEY is intentionally NOT used: it requires native-endian fixed-size keys,
  which conflicts with our LE encoding and variable-length keys (roots, pubkeys)
- MDB_DUPSORT is not used initially — each key maps to exactly one value in all buckets
- Copy-on-write B+tree means reads never block writes and vice versa

## Implementation

1. `buckets.zig` → `DatabaseId` enum with DBI name strings (replaces `Bucket` enum)
2. `kv_store.zig` → `KVStore` gains `database(name)` to get a `Database` handle
3. `lmdb_kv_store.zig` → Opens all named DBIs at init, routes ops by DBI
4. `memory_kv_store.zig` → Separate HashMap per database name
5. `beacon_db.zig` → Uses `Database` handles directly, no prefix construction
