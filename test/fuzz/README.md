# AFL++ Fuzzer for lodestar-z

This directory contains [AFL++](https://aflplus.plus/) fuzzing harnesses
for SSZ deserialization in lodestar-z.

## Fuzz Targets

| Target | Binary | Description |
|--------|--------|-------------|
| `ssz_basic` | `fuzz-ssz_basic` | Bool, Uint8/16/32/64/128/256 |
| `ssz_bitlist` | `fuzz-ssz_bitlist` | BitList(8/64/2048) |
| `ssz_bitvector` | `fuzz-ssz_bitvector` | BitVector(4/32/64/512) |
| `ssz_bytelist` | `fuzz-ssz_bytelist` | ByteList(32/256/1024) |
| `ssz_containers` | `fuzz-ssz_containers` | Fork, Checkpoint, Eth1Data, Attestation, etc. |
| `ssz_lists` | `fuzz-ssz_lists` | FixedList(Uint64/32/Bool), VariableList(ByteList) |

Each input is `[selector_byte][ssz_data...]`. The first byte selects
which SSZ type to test within the target. See source files for the
mapping.

## Prerequisites

Install AFL++ so that `afl-cc` and `afl-fuzz` are on your `PATH`.

- **macOS (Homebrew):** `brew install aflplusplus`
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
afl-fuzz -i corpus/ssz_basic-cmin -o afl-out/ssz_basic \
  -- zig-out/bin/fuzz-ssz_basic @@
```

The fuzzer runs indefinitely. Let it run for as long as you like; meaningful
coverage is usually reached within a few hours, but longer runs can find
deeper bugs. Press `ctrl+c` to stop the fuzzer when you're done.

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
2. Add the name to the `fuzzers` array in `build.zig`.
3. Create `corpus/<name>-initial/` with hand-crafted seed files.
4. Add the target to `replay-crashes.sh` target list.
