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
- **No allocations on the log path**: everything is stack-formatted via `std.fmt.bufPrint`
- **Dual output**: stderr (console) + optional file transport with rotation
- **std.log integration**: Custom `logFn` routes all `std.log.*` calls through the same output

## Architecture

### std.log Integration

The framework provides a custom `stdLogFn` that replaces Zig's default log handler.
This is wired in `src/node/main.zig` via:

```zig
pub const std_options: std.Options = .{
    .logFn = log_mod.stdLogFn,
    .log_level = .debug, // Let our runtime filtering handle levels
};
```

This means:
- All 271+ existing `std.log.*` / `std.log.scoped()` calls go through our formatter
- Scoped loggers (e.g. `std.log.scoped(.validator_client)`) are mapped to our Module enum
- Timestamps, level tags, and module tags are added uniformly
- Both console and file output receive these messages

### Why not build directly on std.log?

`std.log` only has 4 levels (err, warn, info, debug). Lodestar needs 6 (adding
verbose and trace). We extend beyond what std.log provides while still integrating
with it for existing code.

`std.log`'s comptime level elimination is retained for the 4 standard levels via
`std.options.log_level = .debug` — all std.log calls up to debug compile in, and
our runtime filtering handles the rest.

### Transport Architecture

```
GlobalLogger
├── Console transport (stderr, always active)
│   └── Uses std.debug.lockStderr for thread-safe output
└── File transport (optional, enabled via --log-file)
    └── Uses raw Linux syscalls for I/O (no std.Io dependency)
    └── SpinLock for thread safety
    └── Size-based and daily rotation
```

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
| default   | Catch-all for unrecognized std.log scopes |

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
Mar-27 20:30:00 [info ] [chain    ] block imported  slot=12345, root=0xab12cd34.., duration_ms=34
```

### JSON
```json
{"ts":"2026-03-27T20:30:00Z","level":"info","module":"chain","msg":"block imported","slot":12345,"root":"0xab12cd34..","duration_ms":34}
```

## File Transport + Rotation

Modeled on TS Lodestar's Winston daily-rotate-file transport.

### CLI Options
```
--log-file <path>              Enable file logging
--log-file-level <level>       Level for file output (default: debug)
--log-file-daily-rotate <n>    Number of rotated files to keep (default: 5, 0 to disable)
```

### Rotation Behavior
- **Size-based**: When file exceeds configured max (default 100MB), rotate
- **Daily**: At midnight UTC, rotate to `<path>.YYYY-MM-DD`
- **Retention**: Keep last N rotated files, delete older ones
- Rotation = close current → rename to dated → open new
- File format is always human-readable (timestamps + structured context)

### Implementation
- Uses raw Linux syscalls (`write`, `openat`, `close`, `renameat`, `getdents64`) for
  file I/O, avoiding dependency on `std.Io` instance which requires threading context
- SpinLock (not `std.Io.Mutex`) for thread safety without Io dependency
- Stack-allocated BufWriter (8KB) for formatting lines without heap allocation

## Per-Module Level Control

CLI options:
```
--log-level info              # global default
--log-level-chain verbose     # override for chain module (TODO)
--log-level-bls debug         # override for bls module (TODO)
```

Runtime: `GlobalLogger` stores a per-module level array indexed by `Module` enum.

## Performance

1. Level check is a single integer comparison at the call site
2. Format strings are `comptime` — no runtime string construction when disabled
3. No heap allocations — `std.fmt.bufPrint` writes to stack buffers
4. Context struct fields are iterated at comptime via `@typeInfo`
5. stderr output is buffered via `lockStderr` (8KB buffer)
6. File output uses raw `write()` syscall (no buffering — each log line is one write)
