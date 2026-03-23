# BeaconDB Storage Research

## 1. What other CL clients use

| Client | Language | Storage Engine | Notes |
|--------|----------|---------------|-------|
| **Lodestar** | TypeScript | LevelDB (classic-level) | Simple KV store with prefix-based buckets (single-byte prefix per bucket type) |
| **Lighthouse** | Rust | RocksDB | Column families for different data types (blocks, states, etc.) |
| **Nimbus** | Nim | RocksDB | KVStore abstraction with RocksDB backend |
| **Prysm** | Go | BoltDB (bbolt) | Embedded KV, uses buckets. Single-writer, B+tree based |
| **Teku** | Java | RocksDB (JNI) | Separate databases for hot/archive storage |
| **Grandine** | Rust | RocksDB | Standard RocksDB usage |

**Summary:** 4/6 clients use RocksDB. Lodestar uses LevelDB. Prysm uses BoltDB (B+tree, single-writer — similar trade-offs to LMDB).

## 2. Available Zig bindings

### RocksDB

| Package | Stars | Min Zig | Notes |
|---------|-------|---------|-------|
| **ChainSafe/rocksdb.zig** | 0 | 0.14.1 | Our own! Builds RocksDB v10.5.1 from source via Zig build system. Clean API: Database (open/close/get/put/delete), WriteBatch, Iterator. No column family support yet. |
| **Syndica/rocksdb-zig** | 23 | 0.15.0 | More mature. Has column families, WriteBatch, Iterator. Targets Zig 0.15+. |
| **jiacai2050/zig-rocksdb** | 6 | ? | Basic bindings |

### LevelDB

| Package | Stars | Min Zig | Notes |
|---------|-------|---------|-------|
| **ChainSafe/leveldb.zig** | 1 | 0.14.1 | Our own! Builds LevelDB from source. Uses snappy.zig (also ours). Simple API. |

### LMDB

| Package | Stars | Min Zig | Notes |
|---------|-------|---------|-------|
| **lithdew/lmdb-zig** | 86 | old (pre-zon) | Most popular but uses old build system (deps.zig), would need porting |
| **nDimensional/zig-lmdb** | 36 | 0.15.1 | Modern build.zig.zon, actively maintained |
| **allyourcodebase/lmdb** | 6 | ? | Just the build system integration |

## 3. Trade-off analysis

### RocksDB
**Pros:**
- Industry standard for blockchain nodes (4/6 CL clients use it)
- Excellent write throughput (LSM-tree based)
- Good compaction, handles large datasets well
- Column families for logical separation
- We have our own Zig bindings (ChainSafe/rocksdb.zig)

**Cons:**
- Large dependency (~400K lines of C++, compiles from source)
- Write amplification from compaction
- Memory tuning required for optimal performance
- Build time impact significant

### LevelDB
**Pros:**
- Same approach as TS Lodestar (easiest to port 1:1)
- Simpler than RocksDB (it's the ancestor)
- We have our own Zig bindings (ChainSafe/leveldb.zig)
- Smaller codebase to compile

**Cons:**
- No column families
- Worse compaction behavior than RocksDB under sustained write load
- Single compaction thread
- Less actively maintained upstream

### LMDB
**Pros:**
- Extremely simple C API (~20 functions we'd need)
- Outstanding read performance (memory-mapped, zero-copy reads)
- No background threads, no compaction
- ACID transactions, crash-safe (copy-on-write B+tree)
- Tiny footprint (~32KB compiled)

**Cons:**
- Single writer at a time (fine for beacon chain — we process blocks sequentially)
- Map size must be configured upfront (but can be set to TB+)
- No prefix iteration built-in (we handle it with key design)
- Best Zig binding (nDimensional/zig-lmdb) targets 0.15.1, needs 0.16 compat check

## 4. Recommendation

**Phase 1 (now): MemoryKVStore + abstraction layer**
- Implement the BeaconDB interface with vtable-based KVStore
- MemoryKVStore for testing, DST simulation, and development
- Design the key format to match Lodestar's bucket prefix scheme

**Phase 2 (later): LMDB backend**

Rationale:
- Read-heavy workload (block lookups, state archive retrieval) favors LMDB
- Single-writer model matches beacon chain block processing (one block at a time)
- Tiny dependency footprint — LMDB is ~10K lines of C vs RocksDB's ~400K C++
- Zero-copy reads via mmap — block data goes straight to network buffers
- No compaction overhead — deterministic performance, good for validators
- Clean C API maps well to Zig's C interop

If LMDB proves insufficient at scale (unlikely for CL data sizes), migration to RocksDB via the same KVStore interface is straightforward.

**Phase 3 (future): RocksDB backend (optional)**
- If write amplification or concurrent access becomes an issue
- ChainSafe/rocksdb.zig or Syndica/rocksdb-zig as starting point

## 5. Lodestar bucket structure (reference)

From `packages/beacon-node/src/db/buckets.ts`:

```
Bucket 0:  allForks_stateArchive           Root -> BeaconState
Bucket 1:  allForks_block                  Root -> SignedBeaconBlock (unfinalized)
Bucket 2:  allForks_blockArchive           Slot -> SignedBeaconBlock (finalized)
Bucket 3:  index_blockArchiveParentRootIndex   parent Root -> Slot
Bucket 4:  index_blockArchiveRootIndex     Root -> Slot
Bucket 6:  index_mainChain                 Slot -> Root<BeaconBlock>
Bucket 7:  index_chainInfo                 Key -> Number64 | stateHash | blockHash
Bucket 13: phase0_exit                     ValidatorIndex -> VoluntaryExit
Bucket 14: phase0_proposerSlashing         ValidatorIndex -> ProposerSlashing
Bucket 15: allForks_attesterSlashing       Root -> AttesterSlashing
Bucket 16: capella_blsToExecutionChange    ValidatorIndex -> SignedBLSToExecutionChange
Bucket 17: allForks_checkpointState        Root -> BeaconState
Bucket 26: index_stateArchiveRootIndex     State Root -> slot
Bucket 27: deneb_blobSidecars              Root -> BlobSidecars
Bucket 28: deneb_blobSidecarsArchive       Slot -> BlobSidecars
Bucket 42: backfilled_ranges               From -> To
Bucket 51-56: lightClient_*               Various lightclient data
Bucket 57: fulu_dataColumnSidecars         Root -> DataColumnSidecars
Bucket 58: fulu_dataColumnSidecarsArchive  Slot -> DataColumnSidecars
```

Key format: `[1-byte bucket prefix][key bytes]`

## 6. Key design for lodestar-z

We adopt the same single-byte prefix scheme:

```
Key = [bucket: u8] ++ [key_bytes...]

For root-keyed:  [bucket][32-byte root]         = 33 bytes
For slot-keyed:  [bucket][8-byte slot LE]        = 9 bytes
For blob/column: [bucket][32-byte root][1-byte index] = 34 bytes
For compound:    [bucket][custom encoding]
```

This gives us O(1) key construction and natural prefix iteration.
