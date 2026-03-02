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

- **Linux:** build from source or `apt install afl++`
- **macOS:** not directly supported — use
  [OrbStack](https://orbstack.dev/) or similar Linux VM

## Building

From this directory (`test/fuzz`):

```sh
zig build
```

This compiles instrumented binaries at `zig-out/bin/fuzz-*`.

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

Press `Ctrl-C` to stop. Resume later with `-i-` (resume mode).

## Finding Crashes and Hangs

Results are written to `afl-out/<target>/default/`:

```
afl-out/ssz_basic/default/
├── crashes/     Inputs that triggered crashes
├── hangs/       Inputs that caused timeouts
└── queue/       All interesting inputs (evolved corpus)
```

## Reproducing a Crash

Replay any crashing input by piping it into the harness via stdin:

```sh
./replay-crashes.sh                     # all targets
./replay-crashes.sh ssz_lists           # one target

# single file
__AFL_DEFER_FORKSRV=1 ./zig-out/bin/fuzz-ssz_lists \
  < afl-out/ssz_lists/default/crashes/<filename>
```

After fixing a crash, add the input as a regression seed:

```sh
cp afl-out/ssz_lists/default/crashes/<filename> \
   corpus/ssz_lists-initial/06-regression-description
```

## Corpus Management

> **Important:** The instrumented binary reads input from **stdin**,
> not from file arguments. Do **not** use `@@` with `afl-cmin`,
> `afl-tmin`, or `afl-showmap` — it will produce useless results.

### Corpus directories

| Directory | Contents |
|-----------|----------|
| `corpus/<target>-initial/` | Hand-crafted seeds + spec test vectors |
| `corpus/<target>-cmin/` | Output of `afl-cmin` (edge-deduplicated) |

### Populating seeds from spec tests

```sh
# Download spec tests first (from project root)
cd ../.. && zig build run:download_spec_tests

# Extract to corpus/-initial directories
cd test/fuzz && zig build extract-corpus
```

### Corpus minimization (`afl-cmin`)

After a fuzzing run, reduce the evolved queue to a minimal set:

```sh
./minimize-corpus.sh              # all targets
./minimize-corpus.sh ssz_lists    # one target
```

This merges `-initial` seeds with the evolved queue, runs
`afl-cmin.bash` to keep only edge-unique inputs, and writes
the result to `corpus/<target>-cmin/`.

The script uses `afl-cmin.bash` (not the Python `afl-cmin`) to
avoid wrapper bugs in some AFL++ versions. It requires two
environment variables for correct coverage:

```sh
__AFL_DEFER_FORKSRV=1 AFL_NO_FORKSRV=1 afl-cmin.bash \
  -i INPUT -o OUTPUT -- ./zig-out/bin/fuzz-ssz_basic
```

`__AFL_DEFER_FORKSRV=1` is needed because `afl-showmap` (used
internally by `afl-cmin.bash`) does not auto-detect the deferred
fork server marker — without it the binary aborts with SIGABRT.
`afl-fuzz` does not need this variable.

### Windows/macOS compatibility

AFL++ output filenames contain colons (`id:000001,...`), which are
invalid on NTFS/macOS. The minimize script automatically replaces
colons with underscores.

### Workflow

```
1. Start with -initial seeds (hand-crafted + spec tests)
2. Run AFL++ for hours/days
3. ./minimize-corpus.sh → corpus/<target>-cmin/
4. Commit -cmin to the repo
5. Future runs use -cmin as input (faster startup)
```

## Adding a New Target

1. Create `src/fuzz_<name>.zig` exporting `zig_fuzz_init` and
   `zig_fuzz_test` with `callconv(.c)`.
2. Add the name to the `fuzzers` array in `build.zig`.
3. Create `corpus/<name>-initial/` with hand-crafted seed files.
4. Add the target to `replay-crashes.sh` and
   `minimize-corpus.sh` target lists.
