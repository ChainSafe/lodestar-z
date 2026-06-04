# CLAUDE.md

Lodestar-z is a Zig library providing consensus modules for [Lodestar](https://github.com/ChainSafe/lodestar) — the TypeScript Ethereum consensus client. It implements performance-critical paths (SSZ, hashing, state transition) in Zig for use via NAPI bindings.

## Quick Reference

### Zig (core library)

```bash
# Build
zig build

# Run all unit tests
zig build test

# Run specific test
zig build test -- --test-filter "test name"

# Run specific module test with filter
zig build test:ssz -Dtest:ssz.filters="your filter"
```

### Spec Tests

```bash
# 1. Download spec test vectors
zig build run:download_spec_tests

# 2. Generate spec test code
zig build run:write_spec_tests
zig build run:write_ssz_generic_spec_tests
zig build run:write_ssz_static_spec_tests

# 3. Run spec tests (use -Dpreset=minimal for faster runs)
zig build test:spec_tests -Dpreset=minimal
zig build test:ssz_generic_spec_tests -Dpreset=minimal
zig build test:ssz_static_spec_tests -Dpreset=minimal

# Run with filter
zig build test:spec_tests -Dtest:spec_tests.filters="your filter"
```

### Benchmarks

```bash
# Download ERA files first (required for some benchmarks)
zig build run:download_era_files

# Run specific benchmarks
zig build run:bench_ssz_attestation
zig build run:bench_ssz_block
zig build run:bench_ssz_state
zig build run:bench_hashing
zig build run:bench_merkle_node
zig build run:bench_merkle_gindex
```

### JS/TS Bindings

```bash
# Install JS dependencies
pnpm i

# Build NAPI bindings
zig build build-lib:bindings                          # debug
zig build build-lib:bindings -Doptimize=ReleaseSafe   # release

# Run JS/TS tests
pnpm test

# Lint JS/TS
pnpm biome check
```

## Project Structure

```
src/
├── config/              # Network configuration
├── consensus_types/     # Ethereum consensus types (phase0 → electra)
├── constants/           # Protocol constants
├── era/                 # ERA file handling
├── fork_types/          # Per-fork type definitions
├── hashing/             # SHA-256, zero-hash tree, Merkleization
├── persistent_merkle_tree/  # Structural sharing, lazy hashing
├── preset/              # Consensus presets (mainnet, minimal)
├── ssz/                 # SSZ serialization, views, containers
└── state_transition/    # Beacon state transition functions

bindings/                # NAPI bindings for Node.js integration
bench/                   # Performance benchmarks
test/                    # Integration and spec tests
```

## Key Conventions

- **Style:** Follow the project style guide at `.gemini/styleguide.md` (modified [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md))
- **Safety first:** No recursion, limits on everything, fail-fast, zero technical debt
- **Fork order:** phase0 → altair → bellatrix → capella → deneb → electra → fulu → gloas → heze
- **SSZ types:** Defined as compile-time type definitions returning namespaces of operations
- **Testing:** Ethereum consensus spec tests are the source of truth
