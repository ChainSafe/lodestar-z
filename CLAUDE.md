# CLAUDE.md

Lodestar-z is a Zig library providing consensus modules for [Lodestar](https://github.com/ChainSafe/lodestar) — the TypeScript Ethereum consensus client. It implements performance-critical paths (SSZ, hashing, state transition) in Zig for use via NAPI bindings.

## Quick Reference

```bash
# Build
zig build

# Run all tests
zig build test

# Run specific test
zig build test -- --test-filter "test name"

# Run spec tests (download first)
cd test/spec && pnpm install && node download_tests.mjs
zig build spec-test

# Run benchmarks
zig build bench

# Lint (JS/TS parts)
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

- **Style:** Follow [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) — see `README.md` for the full guide
- **Safety first:** No recursion, limits on everything, fail-fast, zero technical debt
- **Fork order:** phase0 → altair → bellatrix → capella → deneb → electra → fulu
- **SSZ types:** Defined as compile-time type definitions returning namespaces of operations
- **Testing:** Ethereum consensus spec tests are the source of truth
