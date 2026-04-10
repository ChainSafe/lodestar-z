# Logging Backend Design

## Overview

lodestar-z uses Zig's native logging frontend:

```zig
const log = std.log.scoped(.chain);

log.info("epoch transition slot={d} finalized_epoch={d}", .{ slot, finalized_epoch });
log.warn("fork choice update failed: {}", .{err});
```

Application code should not import `src/log` for normal logging. The `log`
package is only the runtime backend configured through `std.options.logFn`.

Key design decisions:
- **Idiomatic frontend**: application callsites use local scoped loggers from `std.log.scoped`.
- **Open scopes**: scopes are enum literals, not a central module registry.
- **Runtime filtering**: the backend applies CLI log-level filtering.
- **Two output formats**: human-readable and JSON.
- **Dual output**: stderr plus optional rotated file transport.
- **No structured frontend**: fields are rendered into the message string at the callsite.

## Architecture

The CLI wires the backend through `std.options`:

```zig
pub const std_options: std.Options = .{
    .logFn = log_mod.stdLogFn,
    .log_level = .debug,
};
```

This means every scoped log event flows through `src/log/logger.zig`, where the
backend:

- filters by the configured runtime level,
- adds timestamp, level, and scope,
- renders either human text or JSON,
- mirrors accepted lines to the optional file transport.

The backend intentionally does not expose an app-facing `Logger` type.

## Levels

The active Zig frontend has the four standard `std.log` levels:

| Level | Use for |
|-------|---------|
| error | Unrecoverable or operator-actionable failures |
| warn  | Recoverable issues needing attention |
| info  | High-level operational events |
| debug | Development and high-volume detail |

CLI compatibility still accepts `verbose` and `trace`, but both currently map to `debug`.
If a subsystem needs more selectivity, prefer a narrower scope such as
`.chain_import`, `.validator_store`, or `.reqresp`.

## Scopes

Scopes are open-ended `std.log.scoped(.name)` literals. The backend writes the
literal scope name directly:

```text
Apr-10 12:34:56 [info ] [chain             ] epoch transition slot=123
```

There is no `Module` enum and no scope-to-module mapping. This keeps logging
local to the subsystem that emits it and avoids central registry churn.

## Output Formats

### Human-readable

```text
Apr-10 12:34:56 [info ] [chain             ] block imported slot=123 root=abcd1234...
```

### JSON

```json
{"ts":"2026-04-10T12:34:56Z","level":"info","scope":"chain","msg":"block imported slot=123 root=abcd1234..."}
```

JSON output is intentionally message-oriented. If we later need indexed
structured fields, that should be driven by a concrete ingestion requirement,
not by a parallel logging API.

## File Transport

`--log-file` enables asynchronous file output with rotation.

```text
--log-file <path>              Enable file logging
--log-file-level <level>       Level for file output, default debug
--log-file-daily-rotate <n>    Number of daily rotated files to keep; 0 disables daily rotation
```

The file transport:

- formats accepted lines before enqueueing,
- uses a bounded MPSC queue,
- writes from a single background thread,
- performs size-based and daily rotation,
- drops newest lines under sustained backpressure and emits a dropped-line summary.

File output is currently human-readable regardless of console format.

## Performance

- `std.options.log_level = .debug` keeps standard levels compiled in for the main CLI executable.
- Runtime filtering is one integer comparison in `stdLogFn`.
- Formatting uses stack buffers and comptime format strings.
- stderr writes use `std.debug.lockStderr`.
- File writes are serialized by the file worker thread.
