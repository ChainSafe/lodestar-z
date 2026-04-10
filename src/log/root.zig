//! Runtime backend for lodestar-z logging.
//!
//! Application code should use `std.log` or `std.log.scoped(.scope)`.
//! This package is intentionally only the backend configured by
//! `std.options.logFn`.

pub const logger_mod = @import("logger.zig");

pub const Level = logger_mod.Level;
pub const Format = logger_mod.Format;
pub const Backend = logger_mod.Backend;
pub const FileTransport = logger_mod.FileTransport;
pub const RotationConfig = logger_mod.RotationConfig;
pub const stdLogFn = logger_mod.stdLogFn;

/// Process-wide logging backend. Initialized by CLI startup before normal node work.
pub var global: Backend = Backend.init(.info, .human);

pub fn configure(level: Level, format: Format) void {
    global = Backend.init(level, format);
}

pub fn setFileTransport(transport: *FileTransport) !void {
    try global.setFileTransport(transport);
}

test {
    _ = logger_mod;
}
