//! Runtime log-level filtering over `std.log`.
//!
//! Per the discussion in #446, lodestar-z deliberately does NOT ship a custom
//! logger: modules log through the standard `std.log` API and the root module
//! decides formatting and destination. The one gap `std.log` leaves is that
//! its level is compile-time, while Lodestar configures the level at runtime
//! (and will pass it in when creating the BeaconEngine, #413).
//!
//! This module closes that gap the same way Tigerbeetle does: the root module
//! compiles all levels in and installs a `logFn` that consults a runtime
//! level before delegating to `std.log.defaultLog`:
//!
//! ```zig
//! const logger = @import("logger");
//!
//! pub const std_options: std.Options = .{
//!     // Compile every level in; `logger.logFn` gates at runtime.
//!     .log_level = .debug,
//!     .logFn = logger.logFn,
//! };
//! ```
//!
//! Consumers then call `logger.setLevel(...)` (e.g. from the BeaconEngine
//! constructor with the level configured in the BeaconChain).

const std = @import("std");

/// Runtime log level. Atomic so the JS binding thread can adjust it while
/// worker threads log. Defaults mirror `std.log.default_level`.
var runtime_level: std.atomic.Value(u8) = std.atomic.Value(u8).init(
    @intFromEnum(std.log.default_level),
);

pub fn setLevel(level: std.log.Level) void {
    runtime_level.store(@intFromEnum(level), .monotonic);
}

pub fn getLevel() std.log.Level {
    return @enumFromInt(runtime_level.load(.monotonic));
}

/// Parse a Lodestar log-level string into a `std.log.Level`.
/// Lodestar's `verbose` and `trace` levels are finer than `debug`; `std.log`
/// has no finer level, so both map to `.debug`.
pub fn levelFromString(s: []const u8) ?std.log.Level {
    const map = .{
        .{ "error", std.log.Level.err },
        .{ "warn", std.log.Level.warn },
        .{ "info", std.log.Level.info },
        .{ "verbose", std.log.Level.debug },
        .{ "debug", std.log.Level.debug },
        .{ "trace", std.log.Level.debug },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, s, entry[0])) return entry[1];
    }
    return null;
}

/// Drop-in `std.Options.logFn` that gates on the runtime level, then
/// delegates to `std.log.defaultLog` for formatting and output.
pub fn logFn(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) > runtime_level.load(.monotonic)) return;
    std.log.defaultLog(message_level, scope, format, args);
}

test "setLevel gates messages" {
    const initial = getLevel();
    defer setLevel(initial);

    setLevel(.warn);
    try std.testing.expectEqual(std.log.Level.warn, getLevel());

    // err (0) and warn (1) pass a .warn threshold; info (2) and debug (3) do not.
    try std.testing.expect(@intFromEnum(std.log.Level.err) <= @intFromEnum(getLevel()));
    try std.testing.expect(@intFromEnum(std.log.Level.warn) <= @intFromEnum(getLevel()));
    try std.testing.expect(@intFromEnum(std.log.Level.info) > @intFromEnum(getLevel()));
    try std.testing.expect(@intFromEnum(std.log.Level.debug) > @intFromEnum(getLevel()));
}

test "levelFromString maps Lodestar levels" {
    try std.testing.expectEqual(std.log.Level.err, levelFromString("error").?);
    try std.testing.expectEqual(std.log.Level.warn, levelFromString("warn").?);
    try std.testing.expectEqual(std.log.Level.info, levelFromString("info").?);
    try std.testing.expectEqual(std.log.Level.debug, levelFromString("verbose").?);
    try std.testing.expectEqual(std.log.Level.debug, levelFromString("debug").?);
    try std.testing.expectEqual(std.log.Level.debug, levelFromString("trace").?);
    try std.testing.expectEqual(@as(?std.log.Level, null), levelFromString("bogus"));
}
