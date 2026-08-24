# AFL++ correctness and reliability fuzzing

This directory contains the repository-owned AFL++ target semantics, committed corpora, repro
executables, and bounded corpus replay for lodestar-z SSZ, persistent Merkle tree, and BLS code.

## Targets

`build.zig` is the single registry for all 13 targets and their maximum input lengths.

| Target | Maximum bytes | Input and oracle semantics |
| --- | ---: | --- |
| `ssz_basic` | 33 | Selector-prefixed canonical deserialize/serialize round trips for `Bool` and unsigned integers from 8 to 256 bits |
| `ssz_bitlist` | 258 | Selector-prefixed sentinel, padding, limit, and round-trip behavior for bitlists of 8, 64, and 2048 bits |
| `ssz_bitvector` | 65 | Selector-prefixed fixed size, trailing-bit, and round-trip behavior for bitvectors of 4, 32, 64, and 512 bits |
| `ssz_bytelist` | 1,025 | Selector-prefixed length limits and round trips for byte lists with limits 32, 256, and 1024 |
| `ssz_containers` | 16,613 | Selector-prefixed fixed and variable phase0 containers, including attestations and indexed attestations |
| `ssz_lists` | 4,161 | Selector-prefixed fixed lists of integers and booleans, plus variable lists of byte lists |
| `ssz_chunked_leaf_set` | 4,097 | Bounded selector-prefixed `TreeView` operation streams over chunked-leaf lists, checked against a value reference and pool ownership invariants |
| `ssz_nested_opaque_proof` | 8,191 | Selector-prefixed single-proof creation and reconstruction through nested `container_struct` and `chunked_leaf` nodes |
| `ssz_opaque_roundtrip` | 1,048,576 | Selector-prefixed byte, value, root, and ownership round trips for opaque chunked-leaf lists, vectors, and struct containers |
| `bls_public_key` | 96 | Compressed (48-byte) or serialized (96-byte) public-key decode, validation, serialization, and stable round trips |
| `bls_signature` | 192 | Compressed (96-byte) or serialized (192-byte) signature decode, validation, serialization, and stable round trips |
| `bls_aggregate_pk` | 6,144 | Bounded sequences of compressed public keys with aggregation oracles |
| `bls_aggregate_sig` | 12,288 | Bounded sequences of compressed signatures with aggregation oracles |

See `src/fuzz_*.zig` for the exact input formats and target-specific oracles. The registry injects
each maximum input length into both the AFL++ target and its matching repro executable.

## Prerequisites and build

Use Zig 0.16.0 and AFL++ with `afl-cc` and `afl-fuzz` on `PATH`. From `test/fuzz`, build and
install every instrumented target and repro executable in `ReleaseSafe` mode:

```sh
zig build -Doptimize=ReleaseSafe
```

The standard paths are `zig-out/bin/fuzz-<target>` and `zig-out/bin/repro-<target>`.

Build and install only one matching fuzz and repro executable:

```sh
zig build -Doptimize=ReleaseSafe -Dfuzz-target=ssz_basic
```

An unknown `-Dfuzz-target` value fails during build configuration. Omitting the option selects all
13 targets.

Generate the compact GitHub matrix without compiling fuzzers:

```sh
zig build fuzz-metadata
```

This writes `zig-out/share/lodestar-z-fuzz/targets.json` in registry order with this shape:

```json
{"include":[{"target":"ssz_basic","max_input_len":33}]}
```

The real file contains all 13 entries.

Run one target under AFL++ with its committed bootstrap corpus:

```sh
zig build run-ssz_basic -Doptimize=ReleaseSafe
```

## Committed corpus extraction

Generate fixtures from the consensus-spec version pinned by the repository:

```sh
# From the repository root.
zig build run:download_spec_tests

# From test/fuzz.
zig build extract-corpus
```

The extractor reads `test/spec/version.txt` and writes spec-derived `-initial` fixtures for
`ssz_basic`, `ssz_bitlist`, `ssz_bitvector`, and `ssz_containers`. It does not run minimization or
write the committed bootstrap corpus. Targets without matching vectors retain their committed
hand-written fixtures. Review every resulting corpus diff before committing it.

`corpus/<target>-cmin` is the current compatibility path for committed bootstrap inputs. Evolving
campaign corpora and `afl-cmin` or `afl-tmin` output remain external to this repository.

## Reproduction and bounded replay

Replay one input file or every regular file in one directory without AFL++:

```sh
zig-out/bin/repro-ssz_basic path/to/input
zig-out/bin/repro-ssz_basic corpus/ssz_basic-cmin
```

The repro executable calls `zig_fuzz_init` once, rejects inputs beyond the registry limit, and
bounds directory enumeration and per-file allocation.

Replay every committed bootstrap corpus with its matching repro executable:

```sh
zig build replay-corpus -Doptimize=ReleaseSafe
```

Replay only one committed corpus by selecting the target at build configuration:

```sh
zig build replay-corpus -Doptimize=ReleaseSafe -Dfuzz-target=ssz_basic
```

## Continuous campaigns

Long-running campaigns, `afl-cmin`, result retention, and campaign reporting belong to the external
[lodestar-fuzzer](https://github.com/ChainSafe/lodestar-fuzzer) repository. Lodestar-z CI only
builds the `ReleaseSafe` fuzz harnesses.
