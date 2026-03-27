# Logging Framework Design

## Overview

Structured logging for lodestar-z, modeled on the TypeScript Lodestar logger
(`@lodestar/logger`) but implemented as a zero-allocation, comptime-optimized
Zig library.

Key design decisions:
- **6 log levels** matching TS Lodestar: error, warn, info, verbose, debug, trace
- **Per-module level control** via runtime configuration
- **Two output formats**: human-readable and JSON
- **Zero overhead when disabled**: level check is a single branch; format strings are comptime
- **No allocations on the log path**: everything is stack-formatted via `std.fmt`
- **Built on `std.io.GenericWriter`**: output goes to any writer (stderr, file, etc.)

## Log Level Policy

| Level   | Use for | Examples |
|---------|---------|----------|
| error   | Unrecoverable failures — node is broken | DB corruption, port bind failure, state transition bug, BLS internal error |
| warn    | Recoverable issues needing operator attention | Peer banned, attestation missed, reorg detected, EL comm failure, sync stalled |
| info    | High-level operational events (≤1 line/slot) | Slot processed, epoch transition, new head, sync status, finality update |
| verbose | Detailed operational events | Block imported (with root/slot), attestation pool size, peer connect/disconnect, API requests |
| debug   | Development-level detail | Gossip message received, BLS verify timing, state cache hit/miss |
| trace   | Extreme detail for targeted debugging | SSZ decode bytes, raw network bytes, individual field accesses |

## Module Tags

Each subsystem gets a tag used in log output and per-module level control:

| Tag       | Subsystem |
|-----------|-----------|
| chain     | Block import, fork choice, state management |
| sync      | Range sync, checkpoint sync, unknown block |
| network   | P2P, gossip, req/resp, peer management |
| api       | REST HTTP API requests/responses |
| execution | Engine API communication |
| db        | Database operations |
| validator | Duty tracking, signing, submission |
| bls       | Signature verification (batching, timing) |
| node      | Top-level lifecycle |
| backfill  | Historical block backfill |
| rest      | REST server transport |
| metrics   | Metrics collection/serving |

## Structured Logging

Log messages carry typed context as Zig anonymous structs:

```zig
logger.info("block imported", .{
    .slot = block.slot,
    .root = block.root,
    .parent = block.parent_root,
    .proposer = block.proposer_index,
    .duration_ms = timer.elapsed_ms,
});
```

Context fields are formatted as `key=value` pairs in human mode, and as JSON
fields in JSON mode. Special formatting:
- `[N]u8` arrays → hex with `0x` prefix, truncated to 8 hex chars + `..`
- Integers → decimal
- Enums → tag name string
- Optionals → value or `null`

## Output Formats

### Human-readable (default)
```
Mar-27 20:30:00.123 [info ] [chain    ] block imported  slot=12345, root=0xab12cd34.., duration_ms=34
```

### JSON
```json
{"ts":"2026-03-27T20:30:00.123Z","level":"info","module":"chain","msg":"block imported","slot":12345,"root":"0xab12cd34..","duration_ms":34}
```

## Per-Module Level Control

CLI options:
```
--log-level info              # global default
--log-level-chain verbose     # override for chain module
--log-level-bls debug         # override for bls module
```

Runtime: `GlobalLogger` stores a per-module level array indexed by `Module` enum.

## Performance

1. Level check is a single integer comparison at the call site
2. Format strings are `comptime` — no runtime string construction when disabled
3. No heap allocations — `std.fmt.format` writes directly to the output writer
4. Context struct fields are iterated at comptime via `@typeInfo`
5. Writer is buffered (8KB) to minimize syscalls
