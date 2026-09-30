# LevelDB storage

`@chainsafe/lodestar-z/leveldb` exposes asynchronous binary storage backed by
Google LevelDB through the Zig module in `src/leveldb`. It uses the same native
addon as the consensus and network bindings. The public JavaScript import remains
`@chainsafe/lodestar-z/leveldb`.

```js
import {LevelDb} from "@chainsafe/lodestar-z/leveldb";

const db = await LevelDb.open("./beacon-db");
try {
  const key = new Uint8Array([1, 2, 3]);
  await db.put(key, new Uint8Array([4, 5]), {sync: true});
  const value = await db.get(key, {maxValueBytes: 1024});

  for await (const {key, value} of db.iterator({
    gte: new Uint8Array([1]),
    lt: new Uint8Array([2]),
    maxValueBytes: 1024,
    maxTotalBytes: 64 * 1024,
    maxEntries: 128,
  })) {
    console.log(key, value);
  }
} finally {
  await db.close();
}
```

Keys and values are `Uint8Array` instances, including Node.js `Buffer`. Missing
keys return `null`; empty stored values return an empty buffer. Inputs are copied
before the operation is queued, so callers may reuse their buffers immediately.
Results are ordinary `Uint8Array` instances and own their bytes. Shared or detached
input buffers are rejected.

## Workload and limits

Point reads seek an iterator to the exact key, inspect its borrowed value length,
and then copy into a bounded result buffer. `getMany(keys, {maxValueBytes,
maxTotalBytes})` reuses a single iterator for up to 16,777,216 keys, preserves input
order and duplicates, and returns a consistent view. It avoids a C `leveldb_get`
allocation of the full value before enforcing the caller's limit. Reads and cursors
expose `fillCache`. Point reads default to filling the cache; native cursors default
to bypassing it. The Lodestar controller preserves its existing cache defaults.

`batch(operations, {sync})` applies an atomic ordered batch of puts and deletes.
Every operation and the aggregate payload are checked before constructing the
native write batch. Operations have the form `{type: "put", key, value}` or
`{type: "del", key}`. `sync: true` requests LevelDB's synchronous write policy.

| Resource | Limit |
| --- | --- |
| Key | 4 KiB |
| Individual value | 1 GiB |
| Atomic write batch | 16,777,216 operations and 4 GiB of keys plus values |
| Multi-get | 16,777,216 keys; 1 GiB default per-value and aggregate result limits |
| Cursor page | 1,024 entries; 1 GiB default selected key-plus-value byte limit |
| Diagnostic property copy | 1 MiB |
| Live cursors per database | 64 |
| Admitted operations per database | 4,096 by default, configurable up to 65,536 |
| Admitted copied input and job metadata per database | 8 GiB by default, configurable up to 16 GiB |

Configure admission with `maxPendingOperations` and `maxPendingBytes` at open.
These are finite operating limits, not consensus maxima. A request must fit its
payload and metadata budget; batches are never split into separate commits.
Queue saturation rejects before copying payloads. Read results allocate their
actual sizes on the worker after checking the requested bounds, rather than
allocating each read's maximum in advance. Only one worker result is active per
handle. Each handle's output bound is separate from its queued input admission. Engine memory,
write-batch backing and JavaScript results retained by callers are outside this
accounting. An archive state therefore uses one ordinary value without a special
controller-side encoding or chunking scheme.

Each handle runs one storage job at a time on Node's worker pool. Handles opened
with `multithreading: true` share the engine and cache while retaining independent
queues and admission limits; their jobs may execute concurrently. Closing stops
that handle's admissions, drains its accepted operations and retires its cursors.
The last handle releases the engine, cache and directory lock. Environment teardown
retains ownership until active work finishes. Applications should close handles
explicitly. The 64-cursor limit applies across handles sharing one database.

Cursors use a stable snapshot, `gt`/`gte` and `lt`/`lte` bounds, `reverse`, and an
optional total row `limit`. Inclusive bounds take precedence when both forms are
provided. `keys()` and `values()` project inside the native iterator, so a key-only
scan never copies stored values. A row that fits an empty page but not its remaining
space stays pending for the next page. A row exceeding the per-value or whole-page
limit fails the iteration; it is never silently skipped. Snapshots retain old
versions until exhausted or closed. Close an iterator when abandoning it outside
a `for await` loop.

These limits bound application result materialization and admission. They do
**not** bound LevelDB's internal block reads, decompression, compaction, snapshot
retention, total RSS, or storage latency. Open only trusted local database
files, and bound the number of databases at the host. The cache defaults to
8 MiB and the write buffer to 4 MiB; neither is a whole-engine memory cap.

## Lodestar integration

Lodestar's database controller and peer datastore use this binding instead of
`classic-level` and `datastore-level`. The controller preserves missing-value,
range, cache, batch, metrics and lifecycle behavior. The binding supplies
`clear`, `approximateSize`, `compactRange`, `getProperty` and `destroy` directly;
maintenance runs on the calling handle's serialized queue alongside reads and writes.
`clear` uses bounded deletion chunks and is not atomic across those chunks.

The controller opts into `multithreading`, preserving same-directory access from
its historical-state worker. Every sharing handle must opt in; engine options
come from the first opener. The binding resolves directory paths before sharing
or refusing an exclusive open, and rejects destruction while a handle remains open.
The host must still prevent concurrent access through independent engine copies
or filesystem aliases not resolved by `realpath`: POSIX process-scoped locks do
not reliably enforce that requirement. Existing databases keep their binary key
and value encodings. Block certification and the network serving policy retain
their existing responsibilities.

Storage bounds do not certify a block's consensus validity, canonicality,
execution status, or provenance. Any later removal of block certification must
preserve those obligations and distinguish bounded returned values from engine
workspace.

## Zig use and validation

`src/leveldb/root.zig` owns the bounded API. Zig callers provide destination
buffers to `getInto`, `getManyInto`, and `Cursor.readInto`, or use
`getManyOwned` and `Cursor.readOwned` for exact-sized allocated results. Callers
free each owned result with the database allocator. Database operations may run
concurrently with a thread-safe allocator; each cursor requires serialized access.
Callers keep the database address stable and retire all operations and cursors
before closing it. No iterator-owned pointer escapes into a returned result.

The sibling suites are `src/leveldb/root_test.zig` for the bounded API and
`src/leveldb/raw_test.zig` for the raw handles. Run validation from the repository
root:

```sh
zig build test:leveldb
zig build test:leveldb -Doptimize=ReleaseSafe
zig build build-lib:bindings -Doptimize=ReleaseSafe -Dpreset=mainnet -Dtarget=x86_64-linux-gnu.2.35 -Dcpu=znver1
pnpm typecheck:leveldb
NODE_OPTIONS=--expose-gc pnpm exec vitest run bindings/test/leveldb*.test.ts
```

## Native dependencies and attribution

The root `build.zig.zon` pins the `leveldb_c` dependency to
[ChainSafe/leveldb.zig commit e44b7544178a7fdcf12f41e15b5d043cf2ac3be9](https://github.com/ChainSafe/leveldb.zig/tree/e44b7544178a7fdcf12f41e15b5d043cf2ac3be9)
from the `chore/zig-0.16` branch. The local `leveldb` module's
`.link_libraries = .{"leveldb_c:leveldb"}` consumes only the upstream C library
artifact. `src/leveldb/raw.zig` uses `@cImport` for the C API; the upstream Zig
wrapper is not imported. Lodestar-z owns the bounded API in `src/leveldb/root.zig`.
There is no separate package manifest.

The root `build.zig` uses public build APIs to enable position-independent code
for LevelDB and Snappy so they can link into the Node addon. It also defines
`HAVE_O_CLOEXEC` on non-Windows targets to correct the pinned upstream build's
macro spelling and keep database descriptors out of child processes. The upstream
and root Snappy dependencies use commit
`713942410426051da6107a955b29f3f152815622` with the same content hash. These root
build settings allow consumption of the published artifact on Zig 0.16 without
an upstream patch.

The raw handles in `src/leveldb/raw.zig` are adapted
from [ChainSafe/leveldb.zig revision 186c4ddb4d4569a54103cd00749ca5d81623d6aa](https://github.com/ChainSafe/leveldb.zig/tree/186c4ddb4d4569a54103cd00749ca5d81623d6aa).
Lodestar-z maintains these adaptations for Zig 0.16. The original ChainSafe MIT
license is retained in [src/leveldb/LICENSE](../src/leveldb/LICENSE). Google LevelDB
and Snappy retain their own licenses.

## Raw handle ownership

`src/leveldb/raw.zig` exposes low-level handles for the Google LevelDB C API.
`Options.create`, `ReadOptions.create`, `WriteOptions.create`, `WriteBatch.create`,
`Cache.createLru`, `DB.createIterator`, and `DB.createSnapshot` return error unions;
callers must handle `OutOfMemory` when the C API returns a null handle. C++ allocation
failures inside LevelDB or Snappy can still terminate the process.

Core method names follow ChainSafe's wrapper, including `Options.setCache`,
`Options.setParanoidChecks`, `ReadOptions.setVerifyChecksums`,
`ReadOptions.setSnapshot`, `WriteOptions.setSync`, `Iterator.getError`, and
`DB.releaseSnapshot`. The adaptation omits custom comparator, filter policy,
environment, logger, batch callback, and repair wrappers.

`DB.get` checks and frees the C error before interpreting a null result as a missing
key. Successful results are C-owned and require the raw module's `free(value.ptr)`,
including empty values. `DB.propertyValue` results require the same cleanup.
`DB.get` allocates the complete value; the bounded API's `getInto` uses an iterator
to inspect the value length before copying it.

Iterator `key()` and `value()` return borrowed bytes valid only until that iterator
moves or is destroyed. Inspect lengths and copy into caller-owned memory before
advancing. Never pass these borrowed slices directly to JavaScript or retain them
across asynchronous work. `next`, `prev`, `key`, and `value` require a valid iterator.
Always check `getError` after positioning or traversal; an invalid iterator can
indicate an I/O or corruption error instead of the end of the range.

A snapshot belongs to its creating database. Keep it alive while reads or iterators
use it. Destroy iterators and release snapshots before closing their database.
A configured cache must outlive all databases that use it. Handles have one owner;
close, destroy, or release each exactly once. Callers serialize use of mutable
handles and enforce input sizes, batch limits, and traversal budgets before entering
the raw API. Cache capacity and read output limits do not bound engine scratch
space or process RSS.
