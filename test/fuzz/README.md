# AFL++ Fuzzer for lodestar-z

This directory contains [AFL++](https://aflplus.plus/) fuzzing harnesses
for SSZ deserialization in lodestar-z.

## Fuzz Targets

### SSZ

| Target | Binary | Description |
|--------|--------|-------------|
| `ssz_basic` | `fuzz-ssz_basic` | Bool, Uint8/16/32/64/128/256 |
| `ssz_bitlist` | `fuzz-ssz_bitlist` | BitList(8/64/2048) |
| `ssz_bitvector` | `fuzz-ssz_bitvector` | BitVector(4/32/64/512) |
| `ssz_bytelist` | `fuzz-ssz_bytelist` | ByteList(32/256/1024) |
| `ssz_containers` | `fuzz-ssz_containers` | Fork, Checkpoint, Eth1Data, Attestation, etc. |
| `ssz_lists` | `fuzz-ssz_lists` | FixedList(Uint64/32/Bool), VariableList(ByteList) |
| `ssz_chunked_leaf_set` | `fuzz-ssz_chunked_leaf_set` | FixedList(Uint64, chunked_leaf=true): replay set/commit/get op stream, assert root equivalence against fromValue(reference) |

Each SSZ input is `[selector_byte][ssz_data...]`. The first byte selects
which SSZ type to test within the target. See source files for the mapping.

### Network (stateful)

Single-shot decoders cover the wire formats; these harnesses drive the state machines. Each
input is an opcode stream: one byte selects the operation and the following bytes supply
its parameters, so AFL mutations become session histories. Every step ends with the owner's
own invariant checks (`checkInvariants`, `checkScheduling`, the reqresp route invariant) and
the harness's whole-table accounting.

| Target | Drives | Invariants |
|--------|--------|------------|
| `network_gossip_sessions` | One `Gossipsub` without a transport: SUBSCRIBE, GRAFT, PRUNE, IHAVE, IWANT, IDONTWANT and messages from several sessions, clock advances, heartbeats, verdicts, outbox drains, disconnects and reconnects | store pages and entries, validation pins, promise balance, delivery pool reserves, finite scores, ready-list scheduling |
| `network_gossip_recovery` | IHAVE floods, announced-then-delivered ids, IWANT, promise expiry and cancellation, reconnects with the same identity, penalties and decay | as above, with promise reserves exercised at capacity |
| `network_processor_admission` | `Gossipsub` feeding a `GossipProcessor`: mixed kinds, sources and sizes, newest-first eviction, dependency checks and waits, claim, finish, report, verdict pumping, expiry, slot changes, `dropQueued` and `dropPeer` | per-kind items and bytes, per-source charges, state counts, execution credits, store entries, empty table at close |
| `network_reqresp_session` | Two `ReqResp` instances per side over an in-process QUIC pair: requests, responses, error responses, finish, cancel, serving retain and release, raw request and response bytes with arbitrary splits and FIN placement, stream resets, clock advances for every timeout | route invariant, slot and event accounting, no pending request after `cancelAll` |
| `network_quic_session` | Two engines through a real handshake, then stream opens, writes, reads, capacity polls, shutdowns, closes, route binds, hostile datagrams on the established path, time jumps and connection close | engine invariants after every step, route and connection counts, clean teardown |

These harnesses link both snappy and quiche where needed (`all` in `network-targets.tsv`).
Use ReleaseSafe for campaigns. Each input starts with fresh protocol state; gossip uses
an input-driven clock and reuses allocation capacity between inputs.

```sh
zig build -Doptimize=ReleaseSafe build-network
zig build -Doptimize=ReleaseSafe test-harnesses
./smoke-network.sh network_gossip_sessions network_processor_admission
```

### BLS

| Target | Binary | Description |
|--------|--------|-------------|
| `bls_public_key` | `fuzz-bls_public_key` | Deserialize → validate → serialize roundtrip for `PublicKey` |
| `bls_signature` | `fuzz-bls_signature` | Deserialize → validate → serialize roundtrip for `Signature` |
| `bls_aggregate_pk` | `fuzz-bls_aggregate_pk` | Aggregate multiple `PublicKey`s, with and without randomness |
| `bls_aggregate_sig` | `fuzz-bls_aggregate_sig` | Aggregate multiple `Signature`s, with and without randomness |

BLS inputs are raw bytes interpreted directly as compressed point encodings.

## Prerequisites

Install AFL++ so that `afl-cc` and `afl-fuzz` are on your `PATH`.

- **macOS (Homebrew):** `brew install afl++`
- **Linux:** build from source or use your distro's package (e.g.
  `apt install afl++` on Debian/Ubuntu).

## Building

From this directory (`test/fuzz`):

```sh
zig build
```

This compiles Zig static libraries for each fuzz target, emits LLVM bitcode,
then links each with `afl.c` using `afl-cc` to produce instrumented binaries
at `zig-out/bin/fuzz-*`.

## Running the Fuzzer

Each target has its own run step:

```sh
zig build run-ssz_basic
zig build run-ssz_containers
```

Or invoke `afl-fuzz` directly:

```sh
AFL_CRASH_EXITCODE=99 afl-fuzz -i corpus/ssz_basic-cmin -o afl-out/ssz_basic \
  -- zig-out/bin/fuzz-ssz_basic
```

Harness panics exit with code 99. The launch scripts and build steps configure
`AFL_CRASH_EXITCODE` so AFL records these as crashes.

The fuzzer runs indefinitely. Let it run for as long as you like; meaningful
coverage is usually reached within a few hours, but longer runs can find
deeper bugs. Press `ctrl+c` to stop the fuzzer when you're done.

On Linux containers, AFL++ may abort if `/proc/sys/kernel/core_pattern` is
configured to pipe core dumps. If you cannot change sysctl as root, run with:

```sh
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 zig build run-ssz_basic
```

BLS targets work the same way:

```sh
zig build run-bls_public_key
zig build run-bls_signature
zig build run-bls_aggregate_pk
zig build run-bls_aggregate_sig
```

### Running targets in a loop

`fuzz-loop.sh` runs fuzzers in parallel, [minimizes the corpus]()
with `afl-cmin` after each round, and repeats indefinitely:

```sh
./fuzz-loop.sh --help
Usage: ./fuzz-loop.sh [targets...]

Groups:  all, ssz, bls
Targets: ssz_basic ssz_bitlist ssz_bitvector ssz_bytelist ssz_containers ssz_lists bls_public_key bls_signature bls_aggregate_pk bls_aggregate_sig

Examples:
  ./fuzz-loop.sh                    # fuzz all targets
  ./fuzz-loop.sh ssz                # fuzz all SSZ targets
  ./fuzz-loop.sh bls                # fuzz all BLS targets
  ./fuzz-loop.sh ssz bls_signature  # mix groups and individual targets

Environment:
  ROUND_DURATION=3600               # seconds per round (default: 3600)
```

Logs are written to `logs/<target>.log`. Crashes are reported at the end of
each round; run `./replay-crashes.sh` to inspect them.

## Finding Crashes and Hangs

After (or during) a run, results are written to `afl-out/<target>/default/`:

```
afl-out/ssz_basic/default/
├── crashes/ # Inputs that triggered crashes
├── hangs/   # Inputs that triggered hangs/timeouts
└── queue/   # All interesting inputs (the evolved corpus)
```

Each file in `crashes/` or `hangs/` is a raw byte file that triggered the
issue. The filename encodes metadata about how it was found (e.g.
`id:000000,sig:06,...`).

## Reproducing a Crash

Replay any crashing input by piping it into the harness:

```sh
cat afl-out/ssz_basic/default/crashes/<filename> | zig-out/bin/fuzz-ssz_basic
```

## Corpus Management

After a fuzzing run, the queue in `afl-out/<target>/default/queue/` typically
contains many redundant inputs. Use `afl-cmin` to find the smallest
subset that preserves full edge coverage, and `afl-tmin` to shrink
individual test cases.

> **Important:** The instrumented binary reads input from **stdin**, not
> from file arguments. Do **not** use `@@` with `afl-cmin`, `afl-tmin`,
> or `afl-showmap` — it will cause them to see only the C harness
> coverage (~4 tuples) instead of the Zig SSZ coverage.

### Populating seeds from spec tests

```sh
# Download spec tests first (from project root)
cd ../.. && zig build run:download_spec_tests

# Extract to corpus/-initial directories
cd test/fuzz && zig build extract-corpus
```

### Corpus minimization (`afl-cmin`)

Reduce the evolved queue to a minimal set covering all discovered edges:

```sh
AFL_NO_FORKSRV=1 afl-cmin.bash \
  -i afl-out/ssz_basic/default/queue \
  -o corpus/ssz_basic-cmin \
  -- zig-out/bin/fuzz-ssz_basic
```

`AFL_NO_FORKSRV=1` is required because the Python `afl-cmin` wrapper has
a bug in some AFL++ versions. Use the `afl-cmin.bash` script instead.

### Windows/macOS compatibility

AFL++ output filenames contain colons (e.g., `id:000024,time:0,...`), which
are invalid on Windows (NTFS). After running `afl-cmin`,
rename the output files to replace colons with underscores before committing:

```sh
./corpus/sanitize-filenames.sh
```

### Corpus directories

| Directory | Contents |
|-----------|----------|
| `corpus/<target>-initial/` | Hand-crafted seeds + spec test vectors |
| `corpus/<target>-cmin/` | Output of `afl-cmin` (edge-deduplicated corpus) |

## Adding a New Target

1. Create `src/fuzz_<name>.zig` exporting `zig_fuzz_init` and
   `zig_fuzz_test` with `callconv(.c)`.
2. Add the name to the `fuzzers` array in `build.zig`. If the target links
   against blst (i.e. it uses BLS operations), set extra_libs if you're facing similar situation that bls has: e.g., `.extra_libs = &.{dep_blst.artifact("blst")}`.
3. Create `corpus/<name>-initial/` with hand-crafted seed files.
4. Add the target to `replay-crashes.sh` target list.

## On MacOs

If you are on macOS, you could temporarily comment these two lines in `pkg/afl++/afl.c`:

```c
__sanitizer_cov_trace_pc_guard_init(&__start___sancov_guards,
                                      &__stop___sancov_guards);
```

On Linux (ELF), the linker automatically synthesizes `__start___sancov_guards`
and `__stop___sancov_guards` symbols for any custom section. On macOS (Mach-O),
these symbols are not automatic — they only exist if the section is present and
non-empty in the final binary. If the Zig-compiled bitcode does not produce the
`__sancov_guards` section in the expected Mach-O layout, the symbols are absent
and calling `__sanitizer_cov_trace_pc_guard_init` crashes at startup.

AFL++ has its own coverage tracking that does not depend on this call, so
commenting it out is safe.

