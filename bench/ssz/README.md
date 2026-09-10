# SSZ hashing comparisons

Run the existing `run:bench_ssz_attestation`, `run:bench_ssz_block`, and
`run:bench_ssz_state` steps with `-Doptimize=ReleaseSafe`. These use the configured ERA
fixtures and the mainnet preset.

Each prints an untimed heap-workspace report before the benchmark table:

- **managed cold** includes `Hasher.init` and the first hash. The timing row also
  includes `deinit`, so repeated measurements release their workspace.
- **managed warm** hashes the same value again with initialized buffers. Allocation,
  resize, and allocated-byte counts cover only that second hash; retained bytes
  include the workspace kept from initialization and the first hash.
- **value** calls the type's ordinary `hashTreeRoot` directly.

The report uses `std.testing.FailingAllocator` with failure injection disabled to
count successful allocations and resizes/remaps. Allocated bytes include successful
growth and are cumulative, not peak usage. Retained bytes are requested bytes still
owned after the operation, not allocator residency. Input values, allocator
metadata, and stack workspace are excluded. All three roots must agree.

The timing measurements use the ordinary benchmark allocator without this counting
wrapper. Warm results describe repeated hashing at one input size; they do not
measure growth after warming, shrink behavior, or incremental Merkle updates.

Compare these results again after migrating the remaining type hashers to bounded
workspace. Removing `Hasher` also requires checking downstream users and total stack
usage across nested type hashing.
