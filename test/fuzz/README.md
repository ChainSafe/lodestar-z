# AFL++ correctness and reliability fuzzing

This directory contains AFL++ harnesses for correctness and reliability testing of lodestar-z SSZ,
persistent Merkle tree, and BLS code. This v1 covers the native Zig harnesses only.

## Targets

`build.zig` is the single target registry. A build generates and installs
`zig-out/share/lodestar-z-fuzz/targets.tsv`, with one row per target containing its schema, group,
target name, executable, committed minimized corpus, and maximum input length. The controller
validates the manifest and requires exactly these 13 targets:

| Group | Target | Maximum bytes | Coverage |
| --- | --- | ---: | --- |
| SSZ | `ssz_basic` | 33 | Canonical deserialize/serialize round trips for `Bool` and unsigned integers from 8 to 256 bits |
| SSZ | `ssz_bitlist` | 258 | Sentinel, padding, limit, and round-trip behavior for bitlists of 8, 64, and 2048 bits |
| SSZ | `ssz_bitvector` | 65 | Fixed size, trailing-bit, and round-trip behavior for bitvectors of 4, 32, 64, and 512 bits |
| SSZ | `ssz_bytelist` | 1,025 | Length limits and round trips for byte lists with limits 32, 256, and 1024 |
| SSZ | `ssz_containers` | 16,613 | Fixed and variable phase0 containers, including attestations and indexed attestations |
| SSZ | `ssz_lists` | 4,161 | Fixed lists of integers and booleans, plus variable lists of byte lists |
| SSZ | `ssz_chunked_leaf_set` | 4,097 | Bounded `TreeView` operation streams over chunked-leaf lists, checked against a value reference and pool ownership invariants |
| SSZ | `ssz_nested_opaque_proof` | 8,191 | Single-proof creation and reconstruction through nested `container_struct` and `chunked_leaf` nodes |
| SSZ | `ssz_opaque_roundtrip` | 1,048,576 | Byte, value, root, and ownership round trips for opaque chunked-leaf lists, vectors, and struct containers |
| BLS | `bls_public_key` | 96 | Public-key decode, validation, serialization, and stable round trips |
| BLS | `bls_signature` | 192 | Signature decode, validation, serialization, and stable round trips |
| BLS | `bls_aggregate_pk` | 10,240 | Bounded public-key aggregation with and without randomness |
| BLS | `bls_aggregate_sig` | 16,384 | Bounded signature aggregation with and without randomness |

SSZ inputs generally start with a target-specific selector byte. BLS inputs are interpreted as raw
compressed encodings or bounded sequences of encodings and randomness. See `src/fuzz_*.zig` for the
exact input formats.

Operation-stream targets use maximum lengths derived from their bounded step counts. Exact and
protocol targets use limits derived from their serialized sizes or bounded element cardinalities.

## Prerequisites and deterministic fixtures

The foreground controller requires Linux, Bash 5 or newer, Git, Zig, and AFL++ with `afl-cc` and
`afl-fuzz` on `PATH`. It also uses standard Linux utilities including `realpath`, `sha256sum`,
`setsid`, and `stat`.

The verified continuous-runner toolchain is AFL++ 5.02c at commit
`011cd189801830253c66ecd3cd6919ec01b46c34` with LLVM 18. After changing the AFL++ version, rebuild
the persistent harnesses and use a new state directory instead of resuming existing state.

Generate fixtures from the consensus-spec version pinned by the repository:

```sh
# From the repository root.
zig build run:download_spec_tests

# From test/fuzz.
zig build extract-corpus
```

The extractor reads `test/spec/version.txt`, not an independently chosen upstream version. It
extracts matching generic and minimal phase0 vectors for `ssz_basic`, `ssz_bitlist`,
`ssz_bitvector`, and `ssz_containers`, and writes fixed fixtures for the two opaque-node targets.
Targets without matching vectors retain their committed hand-written fixtures. Review any resulting
corpus diff before committing it.

## Building

From `test/fuzz`:

```sh
zig build -Doptimize=ReleaseSafe
```

This produces the instrumented `zig-out/bin/fuzz-*` executables and the installed manifest.
`ReleaseSafe` keeps runtime safety checks and harness assertions enabled while applying
optimizations needed for sustained fuzzing throughput. The controller always performs this build
itself and refuses to run unless the complete Git checkout is clean both before and after it.

## Foreground controller

`fuzz-loop.sh` starts one AFL++ worker for each selected target and remains in the foreground. All
named options must precede selectors:

```sh
./fuzz-loop.sh \
  --state-dir "$STATE_DIR" \
  --timeout-ms "$TIMEOUT_MS" \
  --memory-mb "$MEMORY_MB" \
  --min-input-len "$MIN_INPUT_LEN" \
  [all|ssz|bls|TARGET ...]
```

Selectors default to `all`. Groups and individual target names may be combined; duplicates keep
their first occurrence in selector-expansion order, while each group expands in manifest order. All
numeric values must be positive decimals. The minimum input length must not exceed any selected
target's manifest maximum. Manifest maximums must be positive canonical decimals no greater than
1 MiB.

`STATE_DIR` is required and must resolve outside the Git checkout. The controller does not write
campaign output, logs, or mutable state into the repository. Before workers start, it verifies the
selected binaries and requires each selected `corpus/<target>-cmin` directory to be non-empty,
committed, and free of untracked files.

### First start and resume

On first start, `STATE_DIR` must not already exist. The controller creates it atomically, starts each
worker from the selected committed `-cmin` corpus, and stores:

```text
STATE_DIR/
├── .initialized
├── metadata
├── targets.tsv
└── output/
```

The state is published atomically after creating the output directory, marker, metadata, and
manifest. The marker, metadata, and manifest are mode `0444`. Metadata records the Git commit,
repository and state paths, manifest hash, `ReleaseSafe` build command, tool paths and versions,
global resource policy, selected targets, and exact per-target first-start and resume worker
arguments. AFL++ populates `output/<target>/default/` after each worker starts.

Passing an existing state directory requests a resume. Resume succeeds only when those immutable
files are present and byte-for-byte metadata matches the current invocation, and every selected
target has a non-empty `fuzzer_stats`. The same commit, checkout path, manifest, tools, policy,
selectors, and state path are therefore required. A successful resume uses AFL++ `-i -` to continue
the existing campaign. Use a new state directory when any recorded value changes.

### Worker lifecycle and status

Each worker runs in its own process group with stdout and stderr discarded to `/dev/null`. Raw AFL++
output is not a campaign result: in non-TTY mode it emits per-test status indefinitely and would
cause unbounded disk writes. The controller's own stdout and stderr remain available to its caller,
including the systemd journal. If any worker exits, the controller treats it as unexpected, reports
the status, terminates all remaining worker groups, and exits nonzero. It does not restart workers.

On `SIGINT` or `SIGTERM`, the controller sends `SIGTERM` to every worker group, waits for bounded
shutdown, sends `SIGKILL` to survivors, and reaps them. The controller exits with status 130 for
`SIGINT` and 143 for `SIGTERM`.

Inspect AFL++ statistics and obtain a quiet aggregate status while the campaign runs:

```sh
sed -n '1,120p' "$STATE_DIR/output/ssz_basic/default/fuzzer_stats"
sed -n '$p' "$STATE_DIR/output/ssz_basic/default/plot_data"
afl-whatsup -s "$STATE_DIR/output/ssz_basic"
```

Campaign results are the `fuzzer_stats` and `plot_data` files, aggregate `afl-whatsup` output, saved
`queue`, `crashes`, and `hangs` entries under `STATE_DIR/output/<target>/default/`, and the
controller's exit status.

## Bounded saved-input replay

Replay saved crash and hang inputs from external state with a positive per-input timeout:

```sh
./replay-crashes.sh \
  --state-dir "$STATE_DIR" \
  --timeout-ms "$REPLAY_TIMEOUT_MS" \
  [all|ssz|bls|TARGET ...]
```

Selectors default to all targets recorded in that state. Replay processes every enumerable saved
input for the selected targets and preserves harness diagnostics. It exits zero only when state and
infrastructure validation succeeds and every replayed input exits zero. It still processes the full
enumerable set before returning an aggregate nonzero status for any timeout, signal, nonzero harness
exit, oversized target input, or validation failure.

## Offline corpus minimization

Minimization is a deliberate offline maintenance operation. Stop the controller first. Never use a
live queue as `afl-cmin` input, and never point `afl-cmin` output at a committed corpus directory.
Copy one saved queue into a temporary input directory and use a distinct temporary output path:

```sh
TARGET=ssz_basic
MIN_WORK="$(mktemp -d)"
MIN_INPUT="$MIN_WORK/input"
MIN_OUTPUT="$MIN_WORK/output"

mkdir "$MIN_INPUT"
cp -a "$STATE_DIR/output/$TARGET/default/queue/." "$MIN_INPUT/"

afl-cmin \
  -i "$MIN_INPUT" \
  -o "$MIN_OUTPUT" \
  -- "zig-out/bin/fuzz-$TARGET"
```

Use AFL++ 5.02c's `afl-cmin` exactly as shown. The harness reads test cases from standard input, so
do not add `@@`, do not substitute `afl-cmin.bash`, and do not set `AFL_NO_FORKSRV`. Review the
minimized files, their coverage, and the relevant harness behavior in `MIN_OUTPUT`. Only after that
review should a separate, intentional repository change update `corpus/<target>-cmin`; sanitize
filenames when needed and review the final Git diff. The controller never minimizes or updates
committed corpora.

## Scope

Host service files, concrete numeric resource choices, host/tool/repository updates, and zapi or
Lodestar runners are outside this v1.
