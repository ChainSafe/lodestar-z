//! Logging framework for lodestar-z.
//!
//! Provides structured, per-module logging with level filtering, human-readable
//! and JSON output formats, and zero overhead when disabled.
//!
//! Integrates with `std.log` — all existing `std.log.*` and `std.log.scoped()`
//! calls are routed through the same output path via a custom `logFn`.
//!
//! ## Quick Start
//!
//! ```zig
//! const log = @import("log");
//! // In your module init, get a scoped logger:
//! const logger = log.logger(.chain);
//! logger.info("block imported", .{ .slot = slot, .root = root });
//! ```

pub const logger_mod = @import("logger.zig");

pub const Level = logger_mod.Level;
pub const Module = logger_mod.Module;
pub const Logger = logger_mod.Logger;
pub const GlobalLogger = logger_mod.GlobalLogger;
pub const FileTransport = logger_mod.FileTransport;
pub const RotationConfig = logger_mod.RotationConfig;
pub const stdLogFn = logger_mod.stdLogFn;

/// Process-wide logger instance. Initialized by the beacon node at startup.
pub var global: GlobalLogger = GlobalLogger.init(.info, .human);

/// Convenience: get a module-scoped logger from the global instance.
pub fn logger(module: Module) Logger {
    return global.logger(module);
}

test {
    _ = logger_mod;
}
