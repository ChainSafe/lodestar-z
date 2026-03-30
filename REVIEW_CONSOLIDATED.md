# feat/beacon-node — Consolidated Cross-Codebase Review

**Branch:** `feat/beacon-node` (389 files, +117K / -2.4K lines vs main)
**Reviewers:** 4 parallel opus agents (correctness, completeness, coherence, taste)
**Date:** 2026-03-28

---

## Executive Summary

The branch is a remarkable speedrun — a functional beacon node skeleton with block import pipeline, fork choice, networking, sync, REST API, validator client, execution engine, DB, metrics, and simulation framework. The bones are right and the test coverage is real. However, the review surfaces **3 categories of debt**:

1. **Wiring gaps** — Components exist but aren't connected (EventBus, produce_block, attestation_data, slot clock ticks, onFinalized)
2. **Duplication** — Same concepts implemented 2-5× (gossip validation, HeadInfo, ImportResult, SlotClock, block import pipeline)
3. **TigerStyle compliance** — Near-zero assertions, 70-line function limit blown 11×, pervasive `usize`, hand-rolled JSON

The most critical finding: **`chain.onFinalized()` is never called**, meaning unbounded memory growth → OOM within hours on mainnet.

---

## 🔴 CRITICAL / BLOCKING

### Correctness

| # | Issue | File | Impact |
|---|-------|------|--------|
| C1 | `processAttestationQueue` assumes sorted order but `AutoArrayHashMap` is insertion-ordered — `break` skips past-slot attestations queued after future-slot ones | `fork_choice.zig:1488` | Silent vote loss → wrong head |
| C2 | `getStatus` returns wrong `finalized_root` — looks up `slot_roots[epoch*32]` instead of fork choice checkpoint | `chain.zig:462` | Peers disconnect us |
| C3 | `makeGossipState` callback signatures missing `*anyopaque` param — compile error when wired | `chain.zig:495` | Dead code, will break |

### Completeness

| # | Issue | Impact | Effort |
|---|-------|--------|--------|
| W1 | No slot clock tick in main loop — fork choice time never advances between imports | Wrong head selection | Small |
| W2 | `chain.onFinalized()` never called — states/FC nodes/seen entries accumulate forever | **OOM within hours** | Trivial |
| W3 | Context bytes ignored during range sync — blocks deserialized with head fork, not actual fork | Corruption across fork boundaries | Small |
| W4 | EventBus never wired — SSE events emitted but go nowhere | VC can't track head | Medium |
| W5 | `produce_block` callback not wired to API | Validators can't produce blocks | Small |
| W6 | `attestation_data` returns wrong target root (head root instead of checkpoint) | Attestations rejected by network | Medium |
| W7 | `preparePayload` never called — EL never starts building | Empty execution payloads | Medium |
| W8 | No Eth1 data voting | Fine for Electra-only devnets | N/A for now |

### Coherence

| # | Issue | Modules |
|---|-------|---------|
| A1 | Dual block import pipelines — `node/block_import.zig` (455 lines, dead) vs `chain/blocks/pipeline.zig` (live) | node, chain |
| A2 | HeadInfo defined 5× with different fields | chain, node, api, validator, networking |
| A3 | ImportResult/ImportError defined 3× with semantic drift | chain, chain/blocks, testing |
| A4 | Two gossip validation modules (930 + 1024 lines) with overlapping logic | chain, networking |

---

## 🟡 IMPORTANT

### Correctness
- `handleBeaconBlocksByRange` uses index-based slot for fork digest instead of actual block slot (skip slots → wrong context bytes)
- Weak CSPRNG fallback for batch BLS — ASLR-seeded ChaCha (~40 bits entropy vs ~128 needed)
- `verifySanity` uses `<=` for finalized slot check — blocks AT finalized slot are rejected
- Every block gets proposer boost (hardcoded `block_delay_sec: 0`)
- `voluntaryExitSigningRoot` ignores EIP-7044 post-Deneb (should use CAPELLA_FORK_VERSION)

### Completeness
- Pool POST endpoints don't propagate to gossip
- State endpoints only support `head` state_id (others return 500)
- Block production hardcoded to Electra fork
- No fork digest update on fork activation
- `syncRequestBlockByRoot` is a no-op → can't resolve orphan blocks
- `syncGetConnectedPeers` returns empty
- discv5 WHOAREYOU not implemented → discovery limited to bootnodes
- No peer scoring integration — misbehaving peers never penalized

### Coherence
- Dead file: `gossip_callbacks.zig` duplicates `gossip_node_callbacks.zig`
- Three SlotClock implementations (node, validator, testing)
- API context defines parallel stub types instead of importing from chain
- Inconsistent callback patterns (vtable vs struct-of-fn-ptrs vs static const)
- `Root` type: some modules use SSZ wrapper, others raw `[32]u8`
- Custom logger exists but only 4 files use it (rest use `std.log`)

### Taste
- Near-zero assertions (~82 across ~2,700 functions, TigerStyle wants ≥2/fn)
- `dispatchHandler` is 795 lines of sequential string comparison with inline JSON
- Pervasive `usize` instead of explicit `u32`/`u64`
- Hand-rolled JSON serialization across 30+ endpoints
- Duplicate gossip validation (networking vs chain)
- 40+ TODOs hiding real bugs (e.g., discarded `state_id` parameter)
- Tests are shallow "init and read back" — no error paths or multi-step workflows
- Excessive `*anyopaque` + `@ptrCast` for callbacks

---

## 🟢 MINOR / NICE-TO-HAVE

- `work_queues.zig` init/route are 128+ line switches with identical arms (use comptime iteration)
- `http_engine.zig` has 91-line copy-paste struct promotion (use comptime)
- `SeenSet` in networking has no eviction (unbounded growth)
- `while (true)` loops without TigerStyle termination assertions
- `beacon_node.zig` still 4208 lines (further splitting possible)
- No rate limiting, auth, gzip, or streaming for API
- No block/state archiving on finalization

---

## Recommended Priority Order

**Phase 1 — Devnet blockers (do first):**
1. W2: Wire `chain.onFinalized()` (trivial)
2. W1: Add slot clock tick to main loop (small)
3. C1: Fix `processAttestationQueue` ordering (small)
4. C2: Fix `getStatus` finalized_root (small)
5. W3: Parse context bytes in range sync (small)
6. W5: Wire `produce_block` to API (small)
7. W6: Fix attestation_data target root (medium)
8. W7: Wire `preparePayload` at 2/3 slot (medium)

**Phase 2 — Coherence cleanup:**
1. A1: Delete dead `node/block_import.zig` BlockImporter
2. A4: Unify gossip validation into single module
3. A2: Single canonical HeadInfo type
4. A3: Single ImportResult/ImportError

**Phase 3 — Taste / hardening:**
1. Add assertions to all public API entry points
2. Replace `dispatchHandler` string chain with StaticStringMap
3. Centralize JSON serialization
4. Unify callback patterns to vtable
