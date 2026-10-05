# Progressive basic list view

`FixedProgressiveListType(Element).TreeView` supports basic elements using the existing
progressive tree representation. The implementation reuses `TreeViewState` for borrowed
chunk caching, staged node ownership, clone transfer, and batched publication.

For chunk index `c`, its subtree index is `floor(log2(3*c + 1) / 2)` and its subtree starts
at `(4^i - 1) / 3`. This computes the native generalized index without a subtree scan.
The path from the list root has `3*i + 2` edges; the native depth limit bounds growth.

Committed leaves remain immutable. The first packed write copies 32 bytes, and subsequent
writes to that pending chunk reuse its unreferenced leaf. A single chunk cache avoids repeated
hash-map probes during consecutive reads and writes. Successful commit, cache clearing, and
source cache transfer invalidate that entry. Failed commit preserves the old root and writes.

Append and zero growth are deferred. Commit builds only missing progressive spine branches,
then batches changed leaves using the existing grouped update implementation. Bulk reads walk
subtrees with `DepthIterator`, decode each chunk directly, and overlay pending writes.
`sliceTo` shares complete prefix subtrees and trims only the boundary path and chunk, so work
is logarithmic in chunk count. It clears truncated data before later growth.

The TS reference is the local optimized `ProgressiveListBasicTreeViewDU` implementation in a
ChainSafe/ssz checkout on `codex/progressive-basic-cache`. Its source SHA-256 was
`ba92620f6c24a677e06fdeb66be0a69db723f77b956ca902c0f81898dc2f4bd5`.
It provides separate committed/dirty caches and subtree batching. Native ownership and
cache-transfer behavior follow existing Zig views; TS commits before each push and rebuilds
all prefix leaves when slicing.

## Measurements

Apple M5, Zig 0.16.0 ReleaseFast, Node v25.2.1. Input has 1,048,576 elements, each `i % 127`.
Two warmups precede nine samples; the table reports median milliseconds. Mutation samples
include clone initialization, get/set, commit, root hashing, and native teardown. Base tree
construction and hashing are excluded. All measured roots are checked against value hashing.
Bulk output is checked outside timing; native uses a caller buffer, while TS allocates its result.
These are SSZ microbenchmarks, not complete STF measurements.

| Work | Progressive Zig | Fixed plain Zig | Fixed chunked Zig | Progressive TS |
| --- | ---: | ---: | ---: | ---: |
| u8, 512 scattered updates | 0.456 | 0.480 | 1.350 | 6.766 |
| u8, 4096 updates across 128 elements | 0.018 | 0.139 | 0.068 | 0.397 |
| u8, update every element | 17.322 | 62.433 | 25.109 | 128.705 |
| u8, bulk read | 0.562 | 3.625 | 0.541 | 9.478 |
| u64, 512 scattered updates | 0.676 | 0.801 | 2.259 | 8.933 |
| u64, update every element | 125.476 | 201.682 | 41.815 | 657.520 |
| u64, bulk read | 2.599 | 24.002 | 0.420 | 16.248 |

Ordinary lists have different Merkle layouts; they compare native implementation costs rather
than interchangeable roots. Chunked leaves retain advantages for cold reads, bulk u64 reads,
and dense u64 writes. The progressive view preserves the current plain-leaf layout, favoring
sparse copy-on-write and packed participation updates. This does not establish a universal
fastest representation. The immediate progressive baseline measured 0.577 ms for u8 and
0.910 ms for u64 scattered updates, with the same mutations and final roots.

Run native measurements with `zig build run:bench_progressive_list_basic -Doptimize=ReleaseFast`.
Run the reference script with `node bench/ssz/progressive_list_basic_reference.mjs` followed by
the built ChainSafe SSZ `lib/index.js` path. The native benchmark also covers cold/warm probes,
append, and slice/regrowth. Warm probes exclude clone and cache preparation from timing.

Validation includes all basic integer widths and bool, subtree boundaries, zero growth,
clone and parent-child isolation, pool exhaustion/retry, allocation-failure cleanup,
original deserialization errors, and official progressive SSZ vectors through the view API.
